use bitcoin_jsonrpsee::jsonrpsee;
use error_fatality::{Fatality, Split};
use sneed::{db, env, rwtxn};
use thiserror::Error;
use transitive::Transitive;

use crate::{
    errors::Splittable,
    validator::{dbs, main_rest_client::MainRestClientError, parse_block_files},
};

#[derive(Debug, Error, Transitive)]
#[expect(clippy::duplicated_attributes)]
#[transitive(from(db::error::Get, db::Error), from(db::error::TryGet, db::Error))]
pub(in crate::validator::task) enum ValidateTransactionInner {
    #[error(transparent)]
    Db(Box<db::Error>),
    #[error(transparent)]
    NestedWriteTxn(#[from] env::error::NestedWriteTxn),
    #[error("No chain tip")]
    NoChainTip,
}

impl From<db::Error> for ValidateTransactionInner {
    fn from(err: db::Error) -> Self {
        Self::Db(Box::new(err))
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct ValidateTransaction(ValidateTransactionInner);

impl<Err> From<Err> for ValidateTransaction
where
    ValidateTransactionInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error, Fatality, Split, Transitive)]
#[expect(clippy::duplicated_attributes)]
#[split(attrs(derive(Debug, Error)))]
#[transitive(
    from(db::error::Delete, db::Error),
    from(db::error::First, db::Error),
    from(db::error::Get, db::Error),
    from(db::error::Len, db::Error),
    from(db::error::Put, db::Error),
    from(db::error::TryGet, db::Error)
)]
pub(in crate::validator) enum ConnectBlock {
    #[error("Block parent `{parent}` does not match tip `{tip}` at height {tip_height}")]
    #[fatal(false)]
    BlockParent {
        parent: bitcoin::BlockHash,
        tip: bitcoin::BlockHash,
        tip_height: u32,
    },
    #[error(transparent)]
    #[fatal(true)]
    Db(Box<db::Error>),
    #[error("Block has no transactions (missing coinbase)")]
    #[fatal(false)]
    NoCoinbase,
    #[error(transparent)]
    #[fatal(true)]
    PutBlockInfo(#[from] dbs::block_hash_dbs_error::PutBlockInfo),
    #[error("BIP 360 validation failed for block `{block_hash}`")]
    #[fatal(false)]
    Bip360 {
        block_hash: bitcoin::BlockHash,
        #[source]
        source: crate::validator::pqc::PqcValidationError,
    },
    /// Aggregate rule consent rejected (remote Timeout/Failure/Reject, or
    /// composition Reject when local validation succeeded).
    #[error("rule consent rejected for block `{block_hash}`: {reason}")]
    #[fatal(false)]
    RulesReject {
        block_hash: bitcoin::BlockHash,
        reason: String,
    },
}

impl From<db::Error> for ConnectBlock {
    fn from(err: db::Error) -> Self {
        Self::Db(Box::new(err))
    }
}

#[derive(Debug, Error, Transitive)]
#[expect(clippy::duplicated_attributes)]
#[transitive(
    from(db::error::Delete, db::Error),
    from(db::error::Get, db::Error),
    from(db::error::Put, db::Error),
    from(db::error::TryGet, db::Error)
)]
pub(in crate::validator) enum DisconnectBlock {
    #[error(transparent)]
    Db(Box<db::Error>),
    #[error(transparent)]
    GetHeaderInfo(#[from] dbs::block_hash_dbs_error::GetHeaderInfo),
    #[error("Block hash `{block_hash}` does not match tip `{tip_hash}`")]
    TipHash {
        block_hash: bitcoin::BlockHash,
        tip_hash: bitcoin::BlockHash,
    },
    #[error(transparent)]
    Undo(#[from] dbs::diff::UndoError),
}

impl From<db::Error> for DisconnectBlock {
    fn from(err: db::Error) -> Self {
        Self::Db(Box::new(err))
    }
}

#[derive(Debug, Error, Fatality, Split, Transitive)]
#[expect(clippy::duplicated_attributes)]
#[split(attrs(derive(Debug, Error)))]
#[transitive(
    from(db::error::Get, db::Error),
    from(db::error::Put, db::Error),
    from(db::error::TryGet, db::Error),
    from(env::error::ReadTxn, env::Error),
    from(env::error::WriteTxn, env::Error)
)]
pub(in crate::validator) enum Sync {
    #[error("Batch JSON RPC error: {}", .errors.join(", "))]
    #[fatal(true)]
    BatchJsonRpc { errors: Vec<String> },
    #[error(transparent)]
    #[fatal(true)]
    BlockDirectoryParser(#[from] parse_block_files::BlockDirectoryParserError),
    #[error("failed to set byte offset in block file parser")]
    #[fatal(true)]
    BlockFileParserSetOffset(#[source] std::io::Error),
    #[error("Block not in active chain: `{block_hash}`")]
    #[fatal(true)]
    BlockNotInActiveChain { block_hash: bitcoin::BlockHash },
    #[error(transparent)]
    #[fatal(true)]
    CommitWriteTxn(#[from] rwtxn::error::Commit),
    #[error(transparent)]
    #[fatal(forward)]
    ConnectBlock(Box<Splittable<ConnectBlock>>),
    #[error(transparent)]
    #[fatal(true)]
    Db(#[from] db::Error),
    #[error(transparent)]
    #[fatal(false)]
    Decode(#[from] bitcoin::consensus::encode::Error),
    #[error(transparent)]
    #[fatal(true)]
    DisconnectBlock(#[from] DisconnectBlock),
    #[error(transparent)]
    #[fatal(true)]
    Env(#[from] env::Error),
    #[error(transparent)]
    #[fatal(true)]
    FetchBlockIndex(#[from] parse_block_files::FetchBlockIndexError),
    #[error(transparent)]
    #[fatal(true)]
    GetHeaderInfo(#[from] dbs::block_hash_dbs_error::GetHeaderInfo),
    #[error("Header sync already in progress")]
    #[fatal(false)]
    HeaderSyncInProgress,
    #[error(transparent)]
    #[fatal(false)]
    Hex(#[from] hex::FromHexError),
    #[error("JSON RPC error (`{method}`)")]
    #[fatal(true)]
    JsonRpc {
        method: String,
        source: jsonrpsee::core::ClientError,
    },
    #[error("JSON serialization error")]
    #[fatal(true)]
    JsonSerialize(#[source] serde_json::Error),
    #[error(transparent)]
    #[fatal(true)]
    LastCommonAncestor(#[from] dbs::block_hash_dbs_error::LastCommonAncestor),
    #[error(transparent)]
    #[fatal(true)]
    ParseBlockFiles(#[from] parse_block_files::ParseBlockFileError),
    #[error(transparent)]
    #[fatal(true)]
    Rest(#[from] MainRestClientError),
    #[error("Shutdown signal received")]
    #[fatal(true)]
    Shutdown,
}

impl From<ConnectBlock> for Sync {
    fn from(err: ConnectBlock) -> Self {
        Self::ConnectBlock(Box::new(Splittable(err)))
    }
}
