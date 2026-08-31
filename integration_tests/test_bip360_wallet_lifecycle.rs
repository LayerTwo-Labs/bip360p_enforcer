//! Full P2MR wallet-lifecycle trial, run against a **plain** (unpatched)
//! Bitcoin Core node.
//!
//! For every P2MR spend scheme this exercises the complete path the enforcer
//! exposes over its wallet gRPC service:
//!
//!   1. `CreateP2mrAddress` mints a witness-v2 P2MR address; the enforcer stores
//!      the key material.
//!   2. The enforcer wallet pays that address (`SendTransaction`); the standard
//!      funding tx is mined via the enforcer's own block template.
//!   3. `ListP2mrOutputs` surfaces the confirmed output, flagged `is_mine`.
//!   4. `SpendP2mr` builds the nonstandard witness-v2 spend and enqueues it in
//!      the block producer.
//!   5. Mining pulls the enforcer's block template, whose `finalize_block_template`
//!      injects the queued spend into the suffix; `submitblock` lands it on a
//!      node that would never have relayed it.
//!   6. The enforcer validates the spend on block-connect and keeps the block on
//!      its active chain; the spent output leaves the P2MR UTXO set.

use std::{collections::HashMap, time::Duration};

use bip360p_enforcer_lib::{
    bins::CommandExt as _,
    proto::{
        mainchain::{
            CreateP2mrAddressRequest, ListP2mrOutputsRequest, ListP2mrOutputsResponse, P2mrScheme,
            SendTransactionRequest, SendTransactionResponse, SpendP2mrRequest, SpendP2mrResponse,
            list_p2mr_outputs_response,
        },
        wrap_u64,
    },
};
use bitcoin::{BlockHash, Txid};

use crate::{
    block_verdict::{Expect, assert_enforcer_verdict},
    integration_test::{fund_enforcer, wait_for_wallet_sync},
    mine::mine,
    setup::{BitcoindKind, PostSetup, SetupOpts},
};

/// Sats paid into each freshly created P2MR address.
const FUNDING_VALUE: u64 = 100_000;
/// Absolute fee taken by the P2MR spend (well under relay minimums — the spend
/// is mined via the enforcer's template, not relayed, so only consensus applies).
const SPEND_FEE: u64 = 2_000;

/// Plain bitcoind + BIP 360 active from genesis + enforcer wallet enabled +
/// generous PQC budget so SLH-DSA verification never trips the watchdog.
#[must_use]
pub fn wallet_lifecycle_setup_opts() -> SetupOpts {
    SetupOpts {
        bitcoind_kind: BitcoindKind::Unpatched,
        // `enforcer_wallet` defaults to `Enabled`, which this trial requires.
        enforcer_args: vec![
            "--activation-height=0".to_string(),
            "--pqc-verify-budget-ms=5000".to_string(),
        ],
        ..SetupOpts::default()
    }
}

pub async fn test_bip360_wallet_lifecycle(mut post_setup: PostSetup) -> anyhow::Result<()> {
    // Give the enforcer wallet a spendable balance.
    fund_enforcer(&mut post_setup).await?;

    let destination = post_setup.receive_address.to_string();

    for (scheme, label) in [
        (P2mrScheme::P2MR_SCHEME_SCHNORR, "schnorr"),
        (P2mrScheme::P2MR_SCHEME_MLDSA, "mldsa"),
        (P2mrScheme::P2MR_SCHEME_SLH, "slh"),
        (P2mrScheme::P2MR_SCHEME_HYBRID_EC_SLH, "hybrid_ec_slh"),
    ] {
        run_scheme(&mut post_setup, scheme, label, &destination).await?;
    }

    // A partial spend must return the remainder as change to a new P2MR output.
    run_partial_spend_change(&mut post_setup, &destination).await?;

    Ok(())
}

/// Amount paid to the recipient in the partial-spend leg (well below the funded
/// value so the remainder is returned as change rather than burned as fee).
const PARTIAL_AMOUNT: u64 = 40_000;

async fn run_scheme(
    post_setup: &mut PostSetup,
    scheme: P2mrScheme,
    label: &str,
    destination: &str,
) -> anyhow::Result<()> {
    // 1. Create a P2MR address for this scheme.
    let created = post_setup
        .wallet_service_client
        .create_p2mr_address(CreateP2mrAddressRequest {
            scheme: scheme.into(),
        })
        .await?
        .into_owned();
    let p2mr_address = created.address.clone();
    anyhow::ensure!(
        !p2mr_address.is_empty(),
        "{label}: CreateP2mrAddress returned an empty address"
    );
    tracing::info!(%label, address = %p2mr_address, "created P2MR address");

    // 2. Fund it from the enforcer wallet, then mine via the enforcer template.
    let funding: SendTransactionResponse = post_setup
        .wallet_service_client
        .send_transaction(SendTransactionRequest {
            destinations: HashMap::from([(p2mr_address.clone(), FUNDING_VALUE)])
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .await?
        .into_owned();
    let funding_txid: Txid = funding
        .txid
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("{label}: SendTransaction returned no txid"))?
        .decode::<SendTransactionResponse, _>("txid")?;
    tracing::info!(%label, %funding_txid, "funded P2MR address; mining funding block");
    mine(post_setup, 1).await?;
    wait_for_wallet_sync(post_setup).await?;

    // 3. The confirmed output must appear in ListP2mrOutputs, flagged is_mine.
    let (spend_txid_field, vout) = {
        let outputs = post_setup
            .wallet_service_client
            .list_p2mr_outputs(ListP2mrOutputsRequest::default())
            .await?
            .into_owned()
            .outputs;
        let mut matched = None;
        for output in outputs {
            let out_txid: Txid = output
                .txid
                .clone()
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("{label}: ListP2mrOutputs entry missing txid"))?
                .decode::<ListP2mrOutputsResponse, _>("txid")?;
            if out_txid == funding_txid {
                anyhow::ensure!(
                    output.is_mine,
                    "{label}: our funded P2MR output is not flagged is_mine"
                );
                anyhow::ensure!(
                    output.value_sats == FUNDING_VALUE,
                    "{label}: funded value {} != expected {FUNDING_VALUE}",
                    output.value_sats
                );
                matched = Some((output.txid, output.vout));
                break;
            }
        }
        matched.ok_or_else(|| {
            anyhow::anyhow!(
                "{label}: funded P2MR output {funding_txid} absent from ListP2mrOutputs"
            )
        })?
    };

    // 4 + 5. Spend the output (enqueues the nonstandard spend), then mine — the
    // enforcer template injects it into the block suffix and submitblock lands it.
    let spend: SpendP2mrResponse = post_setup
        .wallet_service_client
        .spend_p2mr(SpendP2mrRequest {
            txid: spend_txid_field,
            vout,
            destination: destination.to_string(),
            amount_sats: FUNDING_VALUE - SPEND_FEE,
            fee_sats: wrap_u64(SPEND_FEE),
        })
        .await?
        .into_owned();
    let spend_txid: Txid = spend
        .txid
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("{label}: SpendP2mr returned no txid"))?
        .decode::<SpendP2mrResponse, _>("txid")?;
    tracing::info!(%label, %spend_txid, "enqueued P2MR spend; mining spend block");
    mine(post_setup, 1).await?;
    wait_for_wallet_sync(post_setup).await?;

    // 6a. The enforcer must keep the block containing the spend on its chain.
    let best_hash: BlockHash = post_setup
        .bitcoin_cli
        .command::<String, _, String, _, _>([], "getbestblockhash", [])
        .run_utf8()
        .await?
        .trim()
        .parse()?;
    assert_enforcer_verdict(
        post_setup,
        best_hash,
        Expect::Accepted,
        Duration::from_secs(20),
    )
    .await?;

    // 6b. The spend must be mined into that block.
    let raw = post_setup
        .bitcoin_cli
        .command::<String, _, _, _, _>(
            [],
            "getrawtransaction",
            [spend_txid.to_string(), "true".to_string()],
        )
        .run_utf8()
        .await?;
    anyhow::ensure!(
        raw.contains(&best_hash.to_string()),
        "{label}: spend {spend_txid} not confirmed in the enforcer-mined block"
    );

    // 6c. The spent output must leave the P2MR UTXO set.
    let still_present = post_setup
        .wallet_service_client
        .list_p2mr_outputs(ListP2mrOutputsRequest::default())
        .await?
        .into_owned()
        .outputs
        .into_iter()
        .filter_map(|o| {
            o.txid
                .into_option()
                .and_then(|t| t.decode::<ListP2mrOutputsResponse, Txid>("txid").ok())
        })
        .any(|t| t == funding_txid);
    anyhow::ensure!(
        !still_present,
        "{label}: spent P2MR output {funding_txid} still present after spend was mined"
    );

    tracing::info!(%label, "P2MR lifecycle PASS: create → fund → list → spend → mine → validate");
    Ok(())
}

/// Fund a fresh Schnorr P2MR output, spend only PART of it, and prove the
/// remainder comes back as a new `is_mine` P2MR change output that is itself
/// spendable — i.e. the change is not burned as fee.
async fn run_partial_spend_change(
    post_setup: &mut PostSetup,
    destination: &str,
) -> anyhow::Result<()> {
    let label = "partial_change";
    let expected_change = FUNDING_VALUE - PARTIAL_AMOUNT - SPEND_FEE;

    // Create + fund a Schnorr P2MR output, mined via the enforcer.
    let p2mr_address = post_setup
        .wallet_service_client
        .create_p2mr_address(CreateP2mrAddressRequest {
            scheme: P2mrScheme::P2MR_SCHEME_SCHNORR.into(),
        })
        .await?
        .into_owned()
        .address;
    let funding: SendTransactionResponse = post_setup
        .wallet_service_client
        .send_transaction(SendTransactionRequest {
            destinations: HashMap::from([(p2mr_address, FUNDING_VALUE)])
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .await?
        .into_owned();
    let funding_txid: Txid = funding
        .txid
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("{label}: SendTransaction returned no txid"))?
        .decode::<SendTransactionResponse, _>("txid")?;
    mine(post_setup, 1).await?;
    wait_for_wallet_sync(post_setup).await?;
    let funded = find_mine_output(post_setup, funding_txid, FUNDING_VALUE, label).await?;

    // Partial spend: pay PARTIAL_AMOUNT, keep the rest as change.
    let spend: SpendP2mrResponse = post_setup
        .wallet_service_client
        .spend_p2mr(SpendP2mrRequest {
            txid: funded.txid,
            vout: funded.vout,
            destination: destination.to_string(),
            amount_sats: PARTIAL_AMOUNT,
            fee_sats: wrap_u64(SPEND_FEE),
        })
        .await?
        .into_owned();
    anyhow::ensure!(
        spend.change_sats == expected_change,
        "{label}: change_sats {} != expected {expected_change}",
        spend.change_sats
    );
    anyhow::ensure!(
        !spend.change_address.is_empty(),
        "{label}: partial spend returned no change address"
    );
    let spend_txid: Txid = spend
        .txid
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("{label}: SpendP2mr returned no txid"))?
        .decode::<SpendP2mrResponse, _>("txid")?;
    mine(post_setup, 1).await?;
    wait_for_wallet_sync(post_setup).await?;

    // The change must appear as a new is_mine P2MR output worth expected_change.
    let change_output = find_mine_output(post_setup, spend_txid, expected_change, label).await?;

    // ...and it must itself be spendable (drain it).
    let change_spend: SpendP2mrResponse = post_setup
        .wallet_service_client
        .spend_p2mr(SpendP2mrRequest {
            txid: change_output.txid,
            vout: change_output.vout,
            destination: destination.to_string(),
            amount_sats: expected_change - SPEND_FEE,
            fee_sats: wrap_u64(SPEND_FEE),
        })
        .await?
        .into_owned();
    let change_spend_txid: Txid = change_spend
        .txid
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("{label}: change spend returned no txid"))?
        .decode::<SpendP2mrResponse, _>("txid")?;
    mine(post_setup, 1).await?;
    wait_for_wallet_sync(post_setup).await?;

    let best_hash: BlockHash = post_setup
        .bitcoin_cli
        .command::<String, _, String, _, _>([], "getbestblockhash", [])
        .run_utf8()
        .await?
        .trim()
        .parse()?;
    assert_enforcer_verdict(
        post_setup,
        best_hash,
        Expect::Accepted,
        Duration::from_secs(20),
    )
    .await?;

    // The change output is now spent and gone from the P2MR set.
    let still_present = list_p2mr_txids(post_setup).await?.contains(&spend_txid);
    anyhow::ensure!(
        !still_present,
        "{label}: change output {spend_txid} still present after being spent"
    );

    tracing::info!(%change_spend_txid, "partial-spend change leg PASS");
    Ok(())
}

/// Find the confirmed `is_mine` P2MR output at `txid` and assert its value.
async fn find_mine_output(
    post_setup: &mut PostSetup,
    txid: Txid,
    expected_value: u64,
    label: &str,
) -> anyhow::Result<list_p2mr_outputs_response::Output> {
    let outputs = post_setup
        .wallet_service_client
        .list_p2mr_outputs(ListP2mrOutputsRequest::default())
        .await?
        .into_owned()
        .outputs;
    for output in outputs {
        let out_txid: Txid = output
            .txid
            .clone()
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("{label}: ListP2mrOutputs entry missing txid"))?
            .decode::<ListP2mrOutputsResponse, _>("txid")?;
        if out_txid == txid {
            anyhow::ensure!(output.is_mine, "{label}: P2MR output {txid} is not is_mine");
            anyhow::ensure!(
                output.value_sats == expected_value,
                "{label}: P2MR output {txid} value {} != expected {expected_value}",
                output.value_sats
            );
            return Ok(output);
        }
    }
    anyhow::bail!("{label}: P2MR output {txid} absent from ListP2mrOutputs")
}

/// The txids of all P2MR outputs currently in the set.
async fn list_p2mr_txids(post_setup: &mut PostSetup) -> anyhow::Result<Vec<Txid>> {
    Ok(post_setup
        .wallet_service_client
        .list_p2mr_outputs(ListP2mrOutputsRequest::default())
        .await?
        .into_owned()
        .outputs
        .into_iter()
        .filter_map(|o| {
            o.txid
                .into_option()
                .and_then(|t| t.decode::<ListP2mrOutputsResponse, Txid>("txid").ok())
        })
        .collect())
}
