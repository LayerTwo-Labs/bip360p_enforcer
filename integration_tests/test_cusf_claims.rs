//! Behavioral test pinning a Bitcoin Core mempool invariant the enforcer relies
//! on: `testmempoolaccept` validates a transaction without inserting it into
//! `mapTx`. If this changes, the enforcer's mempool handling must be revisited.

use bip360p_enforcer_lib::bins::CommandExt as _;

use crate::setup::PostSetup;

// ─── Claim: testmempoolaccept does not admit ───────────────────────────────

/// After `testmempoolaccept`, the txid must be absent from `getrawmempool`.
/// Control: the same hex via `sendrawtransaction` appears in the mempool.
///
/// Uses bitcoind wallet only (validator-only enforcer / mature coinbases).
pub async fn test_cusf_claim_testmempoolaccept_no_insert(
    post_setup: PostSetup,
) -> anyhow::Result<()> {
    let dest = post_setup.receive_address.to_string();
    // outputs JSON object form required by createrawtransaction
    let outputs = format!(r#"{{"{dest}":0.001}}"#);
    let raw = post_setup
        .bitcoin_cli
        .command::<String, _, _, _, _>([], "createrawtransaction", ["[]".to_string(), outputs])
        .run_utf8()
        .await?;
    let funded = post_setup
        .bitcoin_cli
        .command::<String, _, _, _, _>([], "fundrawtransaction", [raw.trim().to_string()])
        .run_utf8()
        .await?;
    let funded_val: serde_json::Value = serde_json::from_str(&funded)?;
    let hex = funded_val
        .get("hex")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow::anyhow!("fundrawtransaction missing hex: {funded}"))?
        .to_string();
    let signed = post_setup
        .bitcoin_cli
        .command::<String, _, _, _, _>([], "signrawtransactionwithwallet", [hex])
        .run_utf8()
        .await?;
    let signed_val: serde_json::Value = serde_json::from_str(&signed)?;
    let signed_hex = signed_val
        .get("hex")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow::anyhow!("signrawtransactionwithwallet missing hex: {signed}"))?
        .to_string();
    anyhow::ensure!(
        signed_val.get("complete").and_then(|c| c.as_bool()) == Some(true),
        "wallet could not fully sign: {signed}"
    );

    let decoded = post_setup
        .bitcoin_cli
        .command::<String, _, _, _, _>([], "decoderawtransaction", [signed_hex.clone()])
        .run_utf8()
        .await?;
    let decoded_val: serde_json::Value = serde_json::from_str(&decoded)?;
    let txid = decoded_val
        .get("txid")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow::anyhow!("decoderawtransaction missing txid"))?
        .to_string();

    let accept = post_setup
        .bitcoin_cli
        .command::<String, _, _, _, _>([], "testmempoolaccept", [format!(r#"["{signed_hex}"]"#)])
        .run_utf8()
        .await?;
    tracing::info!(%accept, %txid, "testmempoolaccept result");

    let mempool = post_setup
        .bitcoin_cli
        .command::<String, _, String, _, _>([], "getrawmempool", [])
        .run_utf8()
        .await?;
    anyhow::ensure!(
        !mempool.contains(&txid),
        "CLAIM FAIL: testmempoolaccept left txid {txid} in getrawmempool: {mempool}\n\
         Claim: test_accept never inserts into mapTx (FINAL_REPORT §3.3)"
    );

    drop(
        post_setup
            .bitcoin_cli
            .command::<String, _, _, _, _>([], "sendrawtransaction", [signed_hex, "0".to_string()])
            .run_utf8()
            .await?,
    );
    let mempool_after = post_setup
        .bitcoin_cli
        .command::<String, _, String, _, _>([], "getrawmempool", [])
        .run_utf8()
        .await?;
    anyhow::ensure!(
        mempool_after.contains(&txid),
        "control failed: sendraw did not put {txid} in mempool: {mempool_after}"
    );

    tracing::info!(%txid, "PASS claim: testmempoolaccept no insert; sendraw inserts");
    Ok(())
}
