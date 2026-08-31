//! BIP360+ OP_VAULT enforcement trial (live regtest).
//!
//! Proves the vault covenant end-to-end against a real bitcoind + enforcer — the
//! runtime path the unit tests can't reach: the `getblock` verbosity-3 prefetch
//! resolving a prior-block vault prevout, the async→sync boundary threading it in,
//! the taptree reconstruction / signature / value checks, and `invalidateblock`
//! actually reverting bitcoind's tip on a violation.
//!
//! Runs the enforcer **validator-only** (`EnforcerWallet::Disabled`,
//! `Mode::NoMempool`) to isolate covenant validation from the wallet/mempool
//! path. (The wallet+mempool invalidateblock reorg crash was fixed in `be10c74`;
//! it is simply not exercised by this trial.)
//!
//! Four vault UTXOs are funded in one prior block (so each spend's prevout is
//! resolved via getblock-v3, not from same-block outputs). Then: a correct signed
//! trigger must be accepted; a forged signature and a mismatching trigger-output
//! taptree must each be rejected; and an unauthorized recovery must be accepted.
//! The vault transactions are built by `vault_build` independently of the
//! interpreter, so acceptance cross-checks the enforcer's reconstruction.

use std::time::Duration;

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    locktime::absolute::LockTime, transaction::Version,
};
use futures::channel::mpsc;

use crate::{
    bip360_enforce,
    block_verdict::{Expect, assert_enforcer_verdict},
    setup::{BitcoindKind, EnforcerWallet, Mode, PostSetup, PreSetup, SetupOpts},
    vault_build::{self, TriggerKind},
};

/// Sats paid into each vault funding output (the rest of the spent coinbase
/// becomes fee, left unclaimed by the hand-built block's coinbase).
const FUNDING_VALUE: u64 = 50_000;
/// Per-case verdict timeout.
const VERDICT_TIMEOUT: Duration = Duration::from_secs(20);

pub async fn test_bip360_vault_enforcement(pre_setup: PreSetup) -> anyhow::Result<()> {
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

    // Validator-only setup mines 101 blocks; mine a few more so the low-height
    // coinbases we fund from (heights 1..=4) are comfortably mature.
    generate_blocks(&mut post_setup, 4).await?;
    bip360_enforce::wait_for_enforcer_synced(&mut post_setup).await?;

    // Fund four vault UTXOs in one prior block, so each spend's vault prevout must
    // be resolved via the enforcer's getblock-v3 prefetch (not same-block).
    let vaults = fund_vaults(&mut post_setup, &[1, 2, 3, 4]).await?;
    bip360_enforce::wait_for_enforcer_synced(&mut post_setup).await?;

    // 1. A correct signed trigger — accepted. Exercises prefetch + taptree
    //    reconstruction + signature + value preservation on a live chain.
    run_case(
        &mut post_setup,
        "valid-trigger",
        vault_build::build_trigger(vaults[0], FUNDING_VALUE, TriggerKind::Valid),
        Expect::Accepted,
    )
    .await?;

    // 2. A forged trigger-auth signature — rejected.
    run_case(
        &mut post_setup,
        "forged-sig",
        vault_build::build_trigger(vaults[1], FUNDING_VALUE, TriggerKind::ForgeSig),
        Expect::Rejected {
            log_contains: "schnorr signature verification failed",
        },
    )
    .await?;

    // 3. A trigger output whose taptree does not match the leaf-update
    //    reconstruction — rejected.
    run_case(
        &mut post_setup,
        "tampered-trigger-out",
        vault_build::build_trigger(vaults[2], FUNDING_VALUE, TriggerKind::TamperTriggerOut),
        Expect::Rejected {
            log_contains: "trigger output taptree does not match",
        },
    )
    .await?;

    // 4. A valid unauthorized recovery — accepted.
    run_case(
        &mut post_setup,
        "valid-recovery",
        vault_build::build_recovery(vaults[3], FUNDING_VALUE),
        Expect::Accepted,
    )
    .await?;

    Ok(())
}

/// Submit a single-spend block and assert the enforcer's verdict, then wait for
/// the enforcer to resettle (a reject reverts bitcoind's tip).
async fn run_case(
    post_setup: &mut PostSetup,
    label: &str,
    spend_tx: Transaction,
    expect: Expect,
) -> anyhow::Result<()> {
    let (template, coinbase) = bip360_enforce::prepare_coinbase(post_setup).await?;
    let block =
        bip360_enforce::build_block_with_coinbase(post_setup, &template, coinbase, vec![spend_tx])
            .await?;
    let block_hash = bip360_enforce::submit_block(post_setup, &block).await?;
    tracing::info!(%label, %block_hash, "submitted vault-spend block");

    assert_enforcer_verdict(post_setup, block_hash, expect, VERDICT_TIMEOUT).await?;
    bip360_enforce::wait_for_enforcer_synced(post_setup).await?;
    tracing::info!(%label, "vault enforcement PASS");
    Ok(())
}

/// Fund one vault UTXO per mature coinbase `height`, all in a single hand-built
/// block, and return their outpoints.
async fn fund_vaults(post_setup: &mut PostSetup, heights: &[u32]) -> anyhow::Result<Vec<OutPoint>> {
    let vault_spk = vault_build::vault_spk();
    let mut funding_txs = Vec::with_capacity(heights.len());
    let mut outpoints = Vec::with_capacity(heights.len());
    for &height in heights {
        let coinbase_prevout =
            bip360_enforce::funding_prevout_at_height(post_setup, height).await?;
        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: coinbase_prevout,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(FUNDING_VALUE),
                script_pubkey: vault_spk.clone(),
            }],
        };
        let funding = bip360_enforce::wallet_sign_transaction(post_setup, unsigned).await?;
        outpoints.push(OutPoint {
            txid: funding.compute_txid(),
            vout: 0,
        });
        funding_txs.push(funding);
    }

    let (template, coinbase) = bip360_enforce::prepare_coinbase(post_setup).await?;
    let block =
        bip360_enforce::build_block_with_coinbase(post_setup, &template, coinbase, funding_txs)
            .await?;
    let block_hash = bip360_enforce::submit_block(post_setup, &block).await?;
    tracing::info!(%block_hash, count = outpoints.len(), "funded vault UTXOs");
    Ok(outpoints)
}

/// Mine `n` blocks directly via bitcoind to the harness mining address.
async fn generate_blocks(post_setup: &mut PostSetup, n: u32) -> anyhow::Result<()> {
    use cusf_enforcer_lib::bins::CommandExt as _;
    let address = post_setup.mining_address.to_string();
    post_setup
        .bitcoin_cli
        .command::<String, _, _, _, _>([], "generatetoaddress", [n.to_string(), address])
        .run_utf8()
        .await?;
    Ok(())
}
