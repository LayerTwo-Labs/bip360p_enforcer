//! A deterministic snapshot of the enforcer's consensus state at a mainchain
//! tip, intended for cross-run consistency checks. See [`SyncStateSummary`]
//! and [`Validator::sync_state_summary`].

use bitcoin::BlockHash;

use crate::validator::Validator;

impl Validator {
    /// Collect a deterministic snapshot of the enforcer's consensus state at
    /// the current tip. The result is ordered, so two validators synced to the
    /// same tip and in agreement produce byte-identical summaries (and
    /// digests). Intended for cross-run consistency checks.
    ///
    /// Template: only the tip is summarized. Forks that track rule state
    /// (e.g. a UTXO subset) should add it here in canonical order so
    /// `--verify-consensus-state` catches divergence between runs.
    pub fn sync_state_summary(&self) -> Result<SyncStateSummary, miette::Report> {
        let tip_hash = self.get_mainchain_tip()?;
        let tip_height = self
            .try_get_block_height()?
            .ok_or_else(|| miette::miette!("cannot summarize state: validator is not synced"))?;

        Ok(SyncStateSummary {
            tip_hash,
            tip_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SyncStateSummary {
    pub tip_hash: BlockHash,
    pub tip_height: u32,
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
