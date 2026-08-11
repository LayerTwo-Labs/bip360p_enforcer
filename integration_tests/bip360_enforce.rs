//! Hand-built-block helpers for BIP 360 enforcement trials.
//!
//! The wallet only ever produces *valid* P2MR spends, so to prove the enforcer
//! *rejects* an invalid one we must assemble a block containing a tampered spend
//! and submit it straight to bitcoind (which accepts it — P2MR outputs are
//! anyone-can-spend to Core), then check the enforcer `invalidateblock`s it.

use std::time::Duration;

use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Witness,
    block::Header,
    consensus::encode::{deserialize_hex, serialize_hex},
    hashes::Hash as _,
    merkle_tree,
    opcodes::OP_0,
    script::{Builder as ScriptBuilder, PushBytesBuf},
    transaction::Version,
};
use cusf_enforcer_lib::{bins::CommandExt as _, proto::mainchain::GetChainTipRequest};
use serde::Deserialize;
use tokio::time::sleep;

use crate::setup::PostSetup;

const WITNESS_RESERVED_VALUE: [u8; 32] = [0; 32];

pub struct BlockTemplate {
    pub prev_hash: BlockHash,
    pub height: u32,
    pub coinbasevalue: u64,
    pub bits: bitcoin::pow::CompactTarget,
    pub curtime: u32,
    pub version: i32,
}

/// Fetch bitcoind's current `getblocktemplate` (used only for header fields and
/// the coinbase value; the tx set is chosen by the caller).
pub async fn fetch_block_template(post_setup: &mut PostSetup) -> anyhow::Result<BlockTemplate> {
    let template_json = post_setup
        .bitcoin_cli
        .command::<String, _, String, _, _>(
            [],
            "getblocktemplate",
            ["{\"rules\":[\"segwit\"]}"].map(String::from),
        )
        .run_utf8()
        .await?;
    let template: serde_json::Value = serde_json::from_str(&template_json)?;
    let prev_hash: BlockHash = template["previousblockhash"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing previousblockhash"))?
        .parse()?;
    let height = template["height"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing height"))? as u32;
    let coinbasevalue = template["coinbasevalue"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing coinbasevalue"))?;
    let bits = template["bits"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing bits"))?;
    let bits = bitcoin::pow::CompactTarget::from_consensus(u32::from_str_radix(bits, 16)?);
    let curtime = template["curtime"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing curtime"))? as u32;
    let version = template["version"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("missing version"))? as i32;
    Ok(BlockTemplate {
        prev_hash,
        height,
        coinbasevalue,
        bits,
        curtime,
        version,
    })
}

#[must_use]
pub fn build_coinbase(post_setup: &PostSetup, template: &BlockTemplate) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            // Height-only scriptSig can be 1 byte and fails Core's
            // `bad-cb-length` check; append OP_0 like the wallet miner does.
            script_sig: ScriptBuilder::new()
                .push_int(template.height as i64)
                .push_opcode(OP_0)
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[WITNESS_RESERVED_VALUE]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(template.coinbasevalue),
            script_pubkey: post_setup.mining_address.script_pubkey(),
        }],
    }
}

/// Fetch the current template once and return `(template, coinbase)`.
pub async fn prepare_coinbase(
    post_setup: &mut PostSetup,
) -> anyhow::Result<(BlockTemplate, Transaction)> {
    let template = fetch_block_template(post_setup).await?;
    let coinbase = build_coinbase(post_setup, &template);
    Ok((template, coinbase))
}

/// Assemble a block from a template and coinbase already tied to that template,
/// adding the witness commitment, computing the merkle root, and grinding the
/// header to a valid PoW via `bitcoin-util grind`.
pub async fn build_block_with_coinbase(
    post_setup: &PostSetup,
    template: &BlockTemplate,
    coinbase: Transaction,
    non_coinbase_txs: Vec<Transaction>,
) -> anyhow::Result<Block> {
    let mut txdata = Vec::with_capacity(1 + non_coinbase_txs.len());
    txdata.push(coinbase);
    txdata.extend(non_coinbase_txs);

    let header = Header {
        version: bitcoin::block::Version::from_consensus(template.version),
        prev_blockhash: template.prev_hash,
        merkle_root: TxMerkleNode::all_zeros(),
        time: template.curtime,
        bits: template.bits,
        nonce: 0,
    };
    let mut block = Block { header, txdata };

    let witness_root = block
        .witness_root()
        .ok_or_else(|| anyhow::anyhow!("failed to compute witness merkle root"))?;
    let witness_commitment =
        Block::compute_witness_commitment(&witness_root, &WITNESS_RESERVED_VALUE);
    const WITNESS_COMMITMENT_HEADER: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];
    let witness_commitment_spk = {
        let mut push_bytes = PushBytesBuf::from(WITNESS_COMMITMENT_HEADER);
        push_bytes.extend_from_slice(witness_commitment.as_byte_array())?;
        ScriptBuf::new_op_return(push_bytes)
    };
    block.txdata[0].output.push(TxOut {
        script_pubkey: witness_commitment_spk,
        value: Amount::ZERO,
    });

    let mut tx_hashes: Vec<_> = block.txdata.iter().map(Transaction::compute_txid).collect();
    block.header.merkle_root = merkle_tree::calculate_root_inline(&mut tx_hashes)
        .ok_or_else(|| anyhow::anyhow!("failed to compute tx merkle root"))?
        .to_raw_hash()
        .into();

    let header_hex = post_setup
        .bitcoin_util()?
        .command::<String, _, _, _, _>([], "grind", [serialize_hex(&block.header)])
        .run_utf8()
        .await?;
    block.header = deserialize_hex(header_hex.trim())?;
    Ok(block)
}

/// Submit a hand-built block to bitcoind and return its hash. bitcoind accepts
/// P2MR spends (anyone-can-spend to Core); the enforcer is what may reject.
pub async fn submit_block(post_setup: &mut PostSetup, block: &Block) -> anyhow::Result<BlockHash> {
    let block_hash = block.block_hash();
    let submit_resp = post_setup
        .bitcoin_cli
        .command::<String, _, _, _, _>([], "submitblock", [serialize_hex(block)])
        .run_utf8()
        .await?;
    anyhow::ensure!(
        submit_resp.is_empty(),
        "submitblock unexpectedly rejected: `{submit_resp}`"
    );
    Ok(block_hash)
}

fn witness_stack_element<'a>(
    witness: &'a Witness,
    index: usize,
    label: &'static str,
) -> anyhow::Result<&'a [u8]> {
    witness
        .nth(index)
        .ok_or_else(|| anyhow::anyhow!("P2MR witness stack missing {label} (element {index})"))
}

/// Flip the first byte of the signature element (stack item 0) of a single-sig
/// (Schnorr / ML-DSA / SLH) P2MR witness `[sig, leaf, control]`.
pub fn tamper_witness_signature(spend_tx: &mut Transaction) -> anyhow::Result<()> {
    let witness = &spend_tx.input[0].witness;
    let mut bad_sig = witness_stack_element(witness, 0, "signature")?.to_vec();
    bad_sig[0] ^= 0x01;
    let mut bad_witness = Witness::new();
    bad_witness.push(bad_sig);
    bad_witness.push(witness_stack_element(witness, 1, "leaf script")?);
    bad_witness.push(witness_stack_element(witness, 2, "control block")?);
    spend_tx.input[0].witness = bad_witness;
    Ok(())
}

/// Flip the first byte of the EC (Schnorr) signature (stack item 0) of a hybrid
/// EC+SLH P2MR witness `[ec_sig, slh_sig, leaf, control]`.
pub fn tamper_hybrid_witness_ec_signature(spend_tx: &mut Transaction) -> anyhow::Result<()> {
    let witness = &spend_tx.input[0].witness;
    let mut bad_sig = witness_stack_element(witness, 0, "EC signature")?.to_vec();
    bad_sig[0] ^= 0x01;
    let mut bad_witness = Witness::new();
    bad_witness.push(bad_sig);
    bad_witness.push(witness_stack_element(witness, 1, "SLH signature")?);
    bad_witness.push(witness_stack_element(witness, 2, "leaf script")?);
    bad_witness.push(witness_stack_element(witness, 3, "control block")?);
    spend_tx.input[0].witness = bad_witness;
    Ok(())
}

#[derive(Deserialize)]
struct SignResult {
    hex: String,
    complete: bool,
}

/// Sign a transaction with bitcoind's wallet (`signrawtransactionwithwallet`).
/// Used to sign the coinbase-funded input of a P2MR funding tx.
pub async fn wallet_sign_transaction(
    post_setup: &PostSetup,
    tx: Transaction,
) -> anyhow::Result<Transaction> {
    let json = post_setup
        .bitcoin_cli
        .command::<String, _, _, _, _>([], "signrawtransactionwithwallet", [serialize_hex(&tx)])
        .run_utf8()
        .await?;
    let signed: SignResult = serde_json::from_str(&json)?;
    anyhow::ensure!(signed.complete, "signrawtransactionwithwallet incomplete");
    Ok(deserialize_hex(&signed.hex)?)
}

/// The coinbase outpoint of the block at `height` (mature enough to spend when
/// `height <= tip - 100`). Validator-only setup mines 101 blocks to the bitcoind
/// wallet, so heights 1..=101 are spendable coinbases.
pub async fn funding_prevout_at_height(
    post_setup: &PostSetup,
    height: u32,
) -> anyhow::Result<OutPoint> {
    let block_hash = post_setup
        .bitcoin_cli
        .command::<String, _, _, _, _>([], "getblockhash", [height.to_string()])
        .run_utf8()
        .await?;
    let block_hex = post_setup
        .bitcoin_cli
        .command::<String, _, _, _, _>([], "getblock", [block_hash.trim(), "0"])
        .run_utf8()
        .await?;
    let block: Block = deserialize_hex(block_hex.trim())?;
    Ok(OutPoint {
        txid: block.txdata[0].compute_txid(),
        vout: 0,
    })
}

/// Wait until the enforcer's validator has caught up to bitcoind's tip.
pub async fn wait_for_enforcer_synced(post_setup: &mut PostSetup) -> anyhow::Result<()> {
    const POLL_INTERVAL: Duration = Duration::from_millis(250);
    const TIMEOUT: Duration = Duration::from_secs(60);

    let target_height: u32 = post_setup
        .bitcoin_cli
        .command::<String, _, String, _, _>([], "getblockcount", [])
        .run_utf8()
        .await?
        .trim()
        .parse()?;

    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let tip_height = match post_setup
            .validator_service_client
            .get_chain_tip(GetChainTipRequest::default())
            .await
        {
            Ok(resp) => resp
                .into_owned()
                .block_header_info
                .into_option()
                .map(|info| info.height)
                .unwrap_or(0),
            Err(err) => {
                tracing::trace!("enforcer get_chain_tip not ready ({err:#}), waiting...");
                0
            }
        };
        if tip_height >= target_height {
            return Ok(());
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "enforcer did not sync to bitcoind height {target_height} within {TIMEOUT:?} \
             (stuck at {tip_height})"
        );
        sleep(POLL_INTERVAL).await;
    }
}
