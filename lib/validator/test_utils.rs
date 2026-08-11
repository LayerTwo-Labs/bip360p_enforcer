//! Shared test utilities for `crate::validator` tests.
//! This module is gated behind `#[cfg(test)]` in the parent module.

use bitcoin::{BlockHash, hashes::Hash as _};
use miette::IntoDiagnostic;

use super::dbs::Dbs;

pub fn create_test_dbs() -> miette::Result<(temp_dir::TempDir, Dbs)> {
    let dir = temp_dir::TempDir::new().into_diagnostic()?;
    let dbs = Dbs::new(dir.path(), bitcoin::Network::Regtest).into_diagnostic()?;
    Ok((dir, dbs))
}

/// Minimal block header for tests — only `prev_blockhash` is meaningful
pub fn test_block_header(prev_blockhash: BlockHash) -> bitcoin::block::Header {
    bitcoin::block::Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash,
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 0,
        bits: bitcoin::CompactTarget::from_consensus(0x2000_0000),
        nonce: 0,
    }
}
