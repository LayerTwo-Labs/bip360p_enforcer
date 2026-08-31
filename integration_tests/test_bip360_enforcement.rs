//! BIP 360 enforcement trial: per scheme, a block containing a P2MR spend with a
//! tampered signature must be **rejected** by the enforcer (`invalidateblock`).
//!
//! Runs the enforcer **validator-only** (`enforcer_wallet: Disabled`,
//! `Mode::NoMempool`). The wallet+mempool-enabled enforcer currently dies on the
//! `invalidateblock` reorg (mempool-sync disconnect timeout — a known Phase-3
//! bug), so the wallet lifecycle and the reject path are proven in separate
//! trials. Validator-only mode handles the reorg cleanly.
//!
//! Each leg builds a same-block funding tx (spends a mature coinbase → pays the
//! scheme's P2MR scriptPubKey) plus a valid spend of it whose signature is then
//! corrupted, assembles a block, submits it straight to bitcoind (which accepts
//! it — P2MR is anyone-can-spend to Core), and asserts the enforcer invalidates
//! it and logs the scheme's rejection reason.

use std::time::Duration;

use bip360p_enforcer_lib::{
    bins::CommandExt as _,
    validator::pqc::signer::{
        SignAlgorithm, build_hybrid_ec_slh_spend_from_prevout, build_p2mr_spend_from_prevout,
        p2mr_output_for_algorithm, p2mr_output_for_hybrid_ec_slh,
    },
};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    sighash::TapSighashType,
};
use futures::channel::mpsc;

use crate::{
    bip360_enforce,
    block_verdict::{Expect, assert_enforcer_verdict},
    setup::{BitcoindKind, EnforcerWallet, Mode, PostSetup, PreSetup, SetupOpts},
};

/// Sats paid into the P2MR funding output (rest of the coinbase becomes fee,
/// which returns to the hand-built block's own coinbase).
const FUNDING_VALUE: u64 = 50_000;
/// Sats the (tampered) spend pays to the recipient.
const SPEND_OUTPUT: u64 = 40_000;

// Test-controlled entropy — the test holds these so it can build a valid spend
// and then corrupt the signature.
const SCHNORR_ENTROPY: [u8; 32] = [0x11; 32];
const MLDSA_ENTROPY: [u8; 128] = [0x22; 128];
const SLH_ENTROPY: [u8; 128] = [0x88; 128];
const HYBRID_EC_ENTROPY: [u8; 32] = [0x33; 32];

enum Kind {
    Single {
        algo: SignAlgorithm,
        entropy: &'static [u8],
    },
    Hybrid {
        ec: &'static [u8; 32],
        slh: &'static [u8],
    },
}

pub async fn test_bip360_enforcement(pre_setup: PreSetup) -> anyhow::Result<()> {
    let opts: SetupOpts = SetupOpts {
        bitcoind_kind: BitcoindKind::Unpatched,
        enforcer_wallet: EnforcerWallet::Disabled,
        enforcer_args: vec![
            "--activation-height=0".to_string(),
            "--pqc-verify-budget-ms=5000".to_string(),
        ],
        ..SetupOpts::default()
    };
    let (res_tx, _res_rx) = mpsc::unbounded();
    let mut post_setup = pre_setup.setup(Mode::NoMempool, opts, res_tx).await?;
    bip360_enforce::wait_for_enforcer_synced(&mut post_setup).await?;

    // Validator-only setup mines 101 blocks; a coinbase matures after 100. Mine a
    // few more so the four low-height coinbases we fund from (heights 1..=4) are
    // all comfortably mature.
    generate_blocks(&mut post_setup, 4).await?;
    bip360_enforce::wait_for_enforcer_synced(&mut post_setup).await?;

    let cases: [(&str, u32, &str, Kind); 4] = [
        (
            "schnorr",
            1,
            "invalid Schnorr signature",
            Kind::Single {
                algo: SignAlgorithm::Schnorr,
                entropy: &SCHNORR_ENTROPY,
            },
        ),
        (
            "mldsa",
            2,
            "invalid ML-DSA-44 signature",
            Kind::Single {
                algo: SignAlgorithm::Mldsa,
                entropy: &MLDSA_ENTROPY,
            },
        ),
        (
            "slh",
            3,
            "invalid SLH-DSA-SHA2-128s signature",
            Kind::Single {
                algo: SignAlgorithm::Slh,
                entropy: &SLH_ENTROPY,
            },
        ),
        (
            // The hybrid leg corrupts the EC (Schnorr) leg of the two-sig leaf.
            "hybrid_ec_slh",
            4,
            "invalid Schnorr signature",
            Kind::Hybrid {
                ec: &HYBRID_EC_ENTROPY,
                slh: &SLH_ENTROPY,
            },
        ),
    ];

    for (label, funding_height, reject_log, kind) in cases {
        run_reject_case(&mut post_setup, label, funding_height, reject_log, kind).await?;
    }

    Ok(())
}

async fn run_reject_case(
    post_setup: &mut PostSetup,
    label: &str,
    funding_height: u32,
    reject_log: &'static str,
    kind: Kind,
) -> anyhow::Result<()> {
    // 1. The scheme's P2MR scriptPubKey from test-controlled entropy.
    let spk = match &kind {
        Kind::Single { algo, entropy } => p2mr_output_for_algorithm(*algo, entropy),
        Kind::Hybrid { ec, slh } => p2mr_output_for_hybrid_ec_slh(ec, slh),
    }
    .map_err(|e| anyhow::anyhow!("{label}: build P2MR output: {e}"))?
    .0;

    // 2. Funding tx: spend a mature coinbase, pay the P2MR spk. Sign via bitcoind.
    let funding_prevout =
        bip360_enforce::funding_prevout_at_height(post_setup, funding_height).await?;
    let unsigned_funding = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(FUNDING_VALUE),
            script_pubkey: spk.clone(),
        }],
    };
    let funding = bip360_enforce::wallet_sign_transaction(post_setup, unsigned_funding).await?;
    let outpoint = OutPoint {
        txid: funding.compute_txid(),
        vout: 0,
    };
    let prevout = TxOut {
        value: Amount::from_sat(FUNDING_VALUE),
        script_pubkey: spk,
    };
    let spend_outputs = vec![TxOut {
        value: Amount::from_sat(SPEND_OUTPUT),
        script_pubkey: post_setup.mining_address.script_pubkey(),
    }];

    // 3. Build a valid spend from that prevout, then corrupt the signature.
    let tampered = match &kind {
        Kind::Single { algo, entropy } => {
            let mut tx = build_p2mr_spend_from_prevout(
                *algo,
                entropy,
                TapSighashType::Default,
                outpoint,
                prevout,
                spend_outputs,
            )
            .map_err(|e| anyhow::anyhow!("{label}: build spend: {e}"))?;
            bip360_enforce::tamper_witness_signature(&mut tx)?;
            tx
        }
        Kind::Hybrid { ec, slh } => {
            let mut tx = build_hybrid_ec_slh_spend_from_prevout(
                ec,
                slh,
                TapSighashType::Default,
                outpoint,
                prevout,
                spend_outputs,
            )
            .map_err(|e| anyhow::anyhow!("{label}: build hybrid spend: {e}"))?;
            bip360_enforce::tamper_hybrid_witness_ec_signature(&mut tx)?;
            tx
        }
    };

    // 4. One block: same-block funding + tampered spend; submit straight to Core.
    let (template, coinbase) = bip360_enforce::prepare_coinbase(post_setup).await?;
    let block = bip360_enforce::build_block_with_coinbase(
        post_setup,
        &template,
        coinbase,
        vec![funding, tampered],
    )
    .await?;
    let block_hash = bip360_enforce::submit_block(post_setup, &block).await?;
    tracing::info!(%label, %block_hash, "submitted tampered-spend block; expecting rejection");

    // 5. The enforcer must invalidate it, logging the scheme's rejection reason.
    assert_enforcer_verdict(
        post_setup,
        block_hash,
        Expect::Rejected {
            log_contains: reject_log,
        },
        Duration::from_secs(20),
    )
    .await?;

    // 6. The reject reverts bitcoind's tip; wait for the enforcer to resettle
    //    before the next leg builds on the reverted chain.
    bip360_enforce::wait_for_enforcer_synced(post_setup).await?;

    tracing::info!(%label, "enforcement PASS: tampered spend invalidated");
    Ok(())
}

/// Mine `n` blocks directly via bitcoind to the harness mining address.
async fn generate_blocks(post_setup: &mut PostSetup, n: u32) -> anyhow::Result<()> {
    let address = post_setup.mining_address.to_string();
    post_setup
        .bitcoin_cli
        .command::<String, _, _, _, _>([], "generatetoaddress", [n.to_string(), address])
        .run_utf8()
        .await?;
    Ok(())
}
