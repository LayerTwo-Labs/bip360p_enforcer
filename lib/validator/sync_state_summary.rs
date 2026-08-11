//! A deterministic snapshot of the enforcer's consensus state at a mainchain
//! tip, intended for cross-run consistency checks. See [`SyncStateSummary`]
//! and [`Validator::sync_state_summary`].

use bitcoin::{BlockHash, OutPoint};

use crate::validator::Validator;

impl Validator {
    /// Collect a deterministic snapshot of the enforcer's consensus state at
    /// the current tip. The result is ordered, so two validators synced to the
    /// same tip and in agreement produce byte-identical summaries (and
    /// digests). Intended for cross-run consistency checks.
    pub fn sync_state_summary(&self) -> Result<SyncStateSummary, miette::Report> {
        use miette::IntoDiagnostic as _;

        let tip_hash = self.get_mainchain_tip()?;
        let tip_height = self
            .try_get_block_height()?
            .ok_or_else(|| miette::miette!("cannot summarize state: validator is not synced"))?;

        let rotxn = self.dbs.read_txn().into_diagnostic()?;
        let utxos = self.dbs.p2mr_utxos.load_map(&rotxn).into_diagnostic()?;
        let mut p2mr_utxos: Vec<P2mrUtxoSummary> = utxos
            .into_iter()
            .map(|(outpoint, txout)| P2mrUtxoSummary {
                outpoint,
                value_sats: txout.value.to_sat(),
                script_pubkey_hex: hex::encode(txout.script_pubkey.as_bytes()),
            })
            .collect();
        // Canonical ordering: by outpoint.
        p2mr_utxos.sort_by_key(|utxo| (utxo.outpoint.txid, utxo.outpoint.vout));

        Ok(SyncStateSummary {
            tip_hash,
            tip_height,
            p2mr_utxos,
        })
    }
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SyncStateSummary {
    pub tip_hash: BlockHash,
    pub tip_height: u32,
    /// Every unspent P2MR output tracked at the tip, in canonical order.
    pub p2mr_utxos: Vec<P2mrUtxoSummary>,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct P2mrUtxoSummary {
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
}

impl SyncStateSummary {
    /// Deterministic JSON encoding of the summary.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("sync state summary serialization cannot fail")
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// SHA-256 digest of the canonical JSON encoding.
    pub fn digest(&self) -> String {
        use bitcoin::hashes::{Hash as _, sha256};
        let hash = sha256::Hash::hash(self.to_json_pretty().as_bytes());
        hash.to_string()
    }
}
