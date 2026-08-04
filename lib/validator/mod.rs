use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use async_broadcast::{InactiveReceiver, Sender as BroadcastSender, broadcast};
use bitcoin::{self, BlockHash};
use bitcoin_jsonrpsee::jsonrpsee;
use fallible_iterator::FallibleIterator;
use futures::{StreamExt, stream::FusedStream};
use miette::Diagnostic;
use nonempty::NonEmpty;
use sneed::{db, env};
use thiserror::Error;
use tokio::sync::watch::Receiver as WatchReceiver;

use crate::{
    proto::{StatusBuilder, ToStatus, mainchain::HeaderSyncProgress},
    types::{BlockInfo, Event, HeaderInfo, NetworkParams},
    validator::main_rest_client::MainRestClient,
};

pub mod cusf_enforcer;
mod dbs;
pub mod main_rest_client;
pub mod parse_block_files;
mod sync_state_summary;
mod task;
#[cfg(test)]
mod test_utils;

use self::dbs::Dbs;
pub use self::sync_state_summary::SyncStateSummary;

#[derive(Debug, Error)]
pub enum InitError {
    #[error(transparent)]
    CreateDbs(#[from] dbs::CreateDbsError),
    #[error("JSON RPC error (`{method}`)")]
    JsonRpc {
        method: String,
        source: jsonrpsee::core::ClientError,
    },
}

#[derive(Debug, Diagnostic, Error)]
enum GetHeaderInfoErrorInner {
    #[error(transparent)]
    GetHeaderInfo(#[from] dbs::block_hash_dbs_error::GetHeaderInfo),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

impl ToStatus for GetHeaderInfoErrorInner {
    fn builder(&self) -> StatusBuilder<'_> {
        match self {
            Self::GetHeaderInfo(err) => StatusBuilder::new(err),
            Self::ReadTxn(err) => StatusBuilder::new(err),
        }
    }
}

#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct GetHeaderInfoError(GetHeaderInfoErrorInner);

impl<T> From<T> for GetHeaderInfoError
where
    GetHeaderInfoErrorInner: From<T>,
{
    fn from(err: T) -> Self {
        Self(err.into())
    }
}

impl ToStatus for GetHeaderInfoError {
    fn builder(&self) -> StatusBuilder<'_> {
        self.0.builder()
    }
}

#[derive(Debug, Diagnostic, Error)]
enum TryGetHeaderInfosErrorInner {
    #[error(transparent)]
    Db(#[from] db::Error),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct TryGetHeaderInfosError(TryGetHeaderInfosErrorInner);

impl<T> From<T> for TryGetHeaderInfosError
where
    TryGetHeaderInfosErrorInner: From<T>,
{
    fn from(err: T) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
enum GetBlockInfoErrorInner {
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
    #[error(transparent)]
    GetBlockInfo(#[from] dbs::block_hash_dbs_error::GetBlockInfo),
}

#[derive(Debug, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct GetBlockInfoError(GetBlockInfoErrorInner);

impl<T> From<T> for GetBlockInfoError
where
    GetBlockInfoErrorInner: From<T>,
{
    fn from(err: T) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
enum TryGetBlockInfosErrorInner {
    #[error(transparent)]
    Db(#[from] db::Error),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

#[derive(Debug, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct TryGetBlockInfosError(TryGetBlockInfosErrorInner);

impl<T> From<T> for TryGetBlockInfosError
where
    TryGetBlockInfosErrorInner: From<T>,
{
    fn from(err: T) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
enum GetBlockInfosErrorInner {
    #[error("Missing header or block: {0}")]
    MissingHeaderBlock(BlockHash),
    #[error(transparent)]
    TryGetBlockInfos(#[from] TryGetBlockInfosError),
}

#[derive(Debug, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct GetBlockInfosError(GetBlockInfosErrorInner);

impl<T> From<T> for GetBlockInfosError
where
    GetBlockInfosErrorInner: From<T>,
{
    fn from(err: T) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Error)]
pub enum ListHeadersError {
    #[error(transparent)]
    Iter(#[from] db::error::Iter),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

#[derive(Debug, Diagnostic, Error)]
pub enum TryGetMainchainTipError {
    #[error(transparent)]
    DbTryGet(#[from] db::error::TryGet),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

impl ToStatus for TryGetMainchainTipError {
    fn builder(&self) -> StatusBuilder<'_> {
        match self {
            Self::DbTryGet(err) => StatusBuilder::new(err),
            Self::ReadTxn(err) => StatusBuilder::new(err),
        }
    }
}

#[derive(Debug, Diagnostic, Error)]
pub enum GetMainchainTipError {
    #[error(transparent)]
    DbGet(#[from] db::error::Get),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

impl ToStatus for GetMainchainTipError {
    fn builder(&self) -> StatusBuilder<'_> {
        match self {
            Self::DbGet(err) => StatusBuilder::new(err),
            Self::ReadTxn(err) => StatusBuilder::new(err),
        }
    }
}

#[derive(Debug, Diagnostic, Error)]
pub enum TryGetMainchainTipHeightError {
    #[error(transparent)]
    DbGet(#[from] db::error::Get),
    #[error(transparent)]
    DbTryGet(#[from] db::error::TryGet),
    #[error(transparent)]
    ReadTxn(#[from] env::error::ReadTxn),
}

impl ToStatus for TryGetMainchainTipHeightError {
    fn builder(&self) -> StatusBuilder<'_> {
        match self {
            Self::DbGet(err) => StatusBuilder::new(err),
            Self::DbTryGet(err) => StatusBuilder::new(err),
            Self::ReadTxn(err) => StatusBuilder::new(err),
        }
    }
}

#[derive(Debug, Diagnostic, Error)]
pub enum EventsStreamError {
    #[error("Events stream closed due to overflow")]
    Overflow,
}

impl ToStatus for EventsStreamError {
    fn builder(&self) -> StatusBuilder<'_> {
        match self {
            Self::Overflow => StatusBuilder::new(self),
        }
    }
}

#[derive(Clone)]
pub struct Validator {
    dbs: Dbs,
    events_rx: InactiveReceiver<Event>,
    events_tx: BroadcastSender<Event>,
    header_sync_progress_rx: Arc<parking_lot::RwLock<Option<WatchReceiver<HeaderSyncProgress>>>>,
    mainchain_client: jsonrpsee::http_client::HttpClient,
    mainchain_rest_client: MainRestClient,
    mainchain_blocks_dir: Option<PathBuf>,
    network: bitcoin::Network,
    network_params: NetworkParams,
    activation_height: u32,
}

impl Validator {
    pub fn new(
        mainchain_client: jsonrpsee::http_client::HttpClient,
        mainchain_rest_client: MainRestClient,
        mainchain_blocks_dir: Option<PathBuf>,
        data_dir: &Path,
        network: bitcoin::Network,
        network_params: NetworkParams,
        activation_height: u32,
    ) -> Result<Self, InitError> {
        // Note: this needs to be reasonably big. If set too small,
        // we're going to run into strange issues with the broadcast
        // channel overflowing. This again leads to subscribers not
        // not being able to receive events. What's the right number
        // here? Don't know! 256 was the last value, and that was
        // too small.
        const EVENTS_CHANNEL_CAPACITY: usize = 2_000;

        let (events_tx, mut events_rx) = broadcast(EVENTS_CHANNEL_CAPACITY);
        events_rx.set_await_active(false);
        events_rx.set_overflow(true);

        let dbs = Dbs::new(data_dir, network)?;
        Ok(Self {
            dbs,
            events_rx: events_rx.deactivate(),
            events_tx,
            header_sync_progress_rx: Arc::new(parking_lot::RwLock::new(None)),
            mainchain_client,
            mainchain_rest_client,
            mainchain_blocks_dir,
            network,
            network_params,
            activation_height,
        })
    }

    pub fn activation_height(&self) -> u32 {
        self.activation_height
    }

    pub fn network(&self) -> bitcoin::Network {
        self.network
    }

    pub fn network_params(&self) -> NetworkParams {
        self.network_params
    }

    pub fn subscribe_events(
        &self,
    ) -> impl FusedStream<Item = Result<Event, EventsStreamError>> + use<> {
        futures::stream::try_unfold(self.events_rx.activate_cloned(), |mut receiver| async {
            match receiver.recv_direct().await {
                Ok(event) => Ok(Some((event, receiver))),
                Err(async_broadcast::RecvError::Closed) => Ok(None),
                Err(async_broadcast::RecvError::Overflowed(_)) => Err(EventsStreamError::Overflow),
            }
        })
        .fuse()
    }

    /// Returns `None` if there is not a header sync in progress
    pub fn subscribe_header_sync_progress(&self) -> Option<WatchReceiver<HeaderSyncProgress>> {
        self.header_sync_progress_rx.read().clone()
    }

    pub fn get_header_info(
        &self,
        block_hash: &BlockHash,
    ) -> Result<HeaderInfo, GetHeaderInfoError> {
        let rotxn = self.dbs.read_txn()?;
        let res = self.dbs.block_hashes.get_header_info(&rotxn, block_hash)?;
        Ok(res)
    }

    /// Get header infos for the specified block hash, and up to max_ancestors
    /// ancestors.
    /// Returns header infos newest-first.
    pub fn try_get_header_infos(
        &self,
        block_hash: &BlockHash,
        max_ancestors: usize,
    ) -> Result<Option<NonEmpty<HeaderInfo>>, TryGetHeaderInfosError> {
        let rotxn = self.dbs.read_txn()?;
        let res = self
            .dbs
            .block_hashes
            .try_get_header_infos(&rotxn, block_hash, max_ancestors)?;
        Ok(res)
    }

    pub fn get_block_info(&self, block_hash: &BlockHash) -> Result<BlockInfo, GetBlockInfoError> {
        let rotxn = self.dbs.read_txn()?;
        let res = self.dbs.block_hashes.get_block_info(&rotxn, block_hash)?;
        Ok(res)
    }

    /// Get block infos for the specified block hash, and up to max_ancestors
    /// ancestors.
    /// Returns block infos newest-first.
    pub fn try_get_block_infos(
        &self,
        block_hash: &BlockHash,
        max_ancestors: usize,
    ) -> Result<Option<NonEmpty<(HeaderInfo, BlockInfo)>>, TryGetBlockInfosError> {
        let rotxn = self.dbs.read_txn()?;
        let Some(header_infos) =
            self.dbs
                .block_hashes
                .try_get_header_infos(&rotxn, block_hash, max_ancestors)?
        else {
            return Ok(None);
        };
        let Some(info) = self
            .dbs
            .block_hashes
            .try_get_block_info(&rotxn, block_hash)?
        else {
            return Ok(None);
        };
        let mut res = NonEmpty::new((header_infos.head, info));
        for header_info in header_infos.tail {
            if let Some(info) = self
                .dbs
                .block_hashes
                .try_get_block_info(&rotxn, &header_info.block_hash)?
            {
                res.push((header_info, info));
            } else {
                break;
            }
        }
        Ok(Some(res))
    }

    pub fn get_block_infos(
        &self,
        block_hash: &BlockHash,
        max_ancestors: usize,
    ) -> Result<NonEmpty<(HeaderInfo, BlockInfo)>, GetBlockInfosError> {
        match self.try_get_block_infos(block_hash, max_ancestors)? {
            Some(res) => Ok(res),
            None => Err(GetBlockInfosErrorInner::MissingHeaderBlock(*block_hash).into()),
        }
    }

    // Lists known block heights and their corresponding header hashes in ascending order.
    pub fn list_headers(
        &self,
        start_height: u32,
    ) -> Result<Vec<(u32, BlockHash)>, ListHeadersError> {
        let rotxn = self.dbs.read_txn()?;
        let mut res: Vec<(u32, BlockHash)> = self
            .dbs
            .block_hashes
            .height()
            .iter(&rotxn)
            .map_err(db::error::Iter::from)?
            .filter_map(|(block_hash, height)| {
                if height >= start_height {
                    Ok(Some((height, block_hash)))
                } else {
                    Ok(None)
                }
            })
            .collect()
            .map_err(db::error::Iter::from)?;

        res.sort_by_key(|(height, _)| *height);

        debug_assert!(
            res.clone()
                .is_sorted_by(|(first_height, _), (second_height, _)| {
                    first_height < second_height
                })
        );
        Ok(res)
    }

    /// Get the mainchain tip. Returns `None` if not synced
    pub fn try_get_mainchain_tip(&self) -> Result<Option<BlockHash>, TryGetMainchainTipError> {
        let rotxn = self.dbs.read_txn()?;
        let res = self.dbs.current_chain_tip.try_get(&rotxn, &())?;
        Ok(res)
    }

    /// Get the mainchain tip. Returns an error if not synced
    pub fn get_mainchain_tip(&self) -> Result<BlockHash, GetMainchainTipError> {
        let rotxn = self.dbs.read_txn()?;
        let res = self.dbs.current_chain_tip.get(&rotxn, &())?;
        Ok(res)
    }

    /// Get the mainchain tip height. Returns `None` if not synced
    pub fn try_get_block_height(&self) -> Result<Option<u32>, TryGetMainchainTipHeightError> {
        let rotxn = self.dbs.read_txn()?;
        let Some(tip) = self.dbs.current_chain_tip.try_get(&rotxn, &())? else {
            return Ok(None);
        };
        let height = self.dbs.block_hashes.height().get(&rotxn, &tip)?;
        Ok(Some(height))
    }
}
