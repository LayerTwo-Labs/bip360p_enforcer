use std::{collections::HashMap, path::PathBuf, time::Instant};

use async_broadcast::{Sender, TrySendError};
use bitcoin::{Block, BlockHash, Network, OutPoint, Transaction, TxOut, Work, hashes::Hash as _};
use error_fatality::Fatality as _;
use fallible_iterator::FallibleIterator;
use futures::FutureExt as _;
use jsonrpsee::core::{
    client::BatchResponse,
    params::{ArrayParams, BatchRequestBuilder},
};
use sneed::RwTxn;
use tokio_util::sync::CancellationToken;

use crate::{
    proto::mainchain::HeaderSyncProgress,
    types::{BlockInfo, Event, HeaderInfo},
    validator::{
        dbs::{
            Dbs,
            diff::{self, Diff},
        },
        main_rest_client::MainRestClient,
    },
};

mod block_files;
pub mod error;

/// Bundles the consensus inputs that every handler needs.
#[derive(Clone)]
pub(in crate::validator) struct BlockHandler<'a> {
    pub(super) dbs: &'a Dbs,
    pub(super) network: Network,
    /// Height at which BIP 360 (P2MR) validation activates. Blocks below it
    /// are plain Bitcoin history: still recorded (and their P2MR outputs still
    /// indexed), but spends are not validated.
    pub(super) activation_height: u32,
    /// Per-block wall-clock budget for PQC signature verification.
    pub(super) pqc_verify_budget_ms: u64,
    /// Prevouts resolved out-of-band from bitcoind before connect (e.g. a
    /// multi-input P2MR spend's non-P2MR co-input, or a Taproot-v1 vault
    /// input). Empty for the sync/disconnect paths, which need no such lookup.
    pub(super) extra_prevouts: HashMap<OutPoint, TxOut>,
}

impl<'a> BlockHandler<'a> {
    pub(in crate::validator) fn new(
        dbs: &'a Dbs,
        network: Network,
        activation_height: u32,
        pqc_verify_budget_ms: u64,
        extra_prevouts: HashMap<OutPoint, TxOut>,
    ) -> Self {
        Self {
            dbs,
            network,
            activation_height,
            pqc_verify_budget_ms,
            extra_prevouts,
        }
    }
}

impl BlockHandler<'_> {
    pub(in crate::validator) fn validate_tx(
        &self,
        parent_rwtxn: &mut RwTxn,
        transaction: &Transaction,
    ) -> Result<bool, error::ValidateTransaction> {
        use crate::validator::pqc::{self, activation::Bip360Activation};

        let dbs = self.dbs;
        let child_rwtxn = dbs.nested_write_txn(parent_rwtxn)?;
        let tip_hash = dbs
            .current_chain_tip
            .try_get(&child_rwtxn, &())?
            .ok_or(error::ValidateTransactionInner::NoChainTip)?;
        let tip_height = dbs.block_hashes.height().get(&child_rwtxn, &tip_hash)?;

        // BIP 360+ mempool admission. Since upstream dropped `tx_inputs` from
        // `accept_tx`, we no longer have parent prevouts here, so the P2MR
        // prevout check is a no-op — which is fine: P2MR/OP_CAT spends are
        // non-relay (they never reach mempool admission; they enter via the
        // block-producer suffix path), and block-connect remains authoritative.
        // The OP_CAT/tapscript checks need no prevouts and still run.
        match pqc::validate_mempool_transaction(
            transaction,
            tip_height,
            Bip360Activation(self.activation_height),
        ) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn connect_block_pass_through(
        &self,
        rwtxn: &mut RwTxn,
        block: &Block,
        height: u32,
        coinbase: &Transaction,
        block_hash: BlockHash,
        prev_mainchain_block_hash: BlockHash,
    ) -> Result<Event, error::ConnectBlock> {
        use crate::validator::pqc::{self, activation::Bip360Activation};

        let dbs = self.dbs;
        // BIP 360 block validation: verify every P2MR spend and compute the
        // resulting P2MR UTXO-set diff. Prevouts come from the indexed P2MR
        // UTXO set plus this block's own outputs. A validation failure is a
        // non-fatal rejection — the driver invalidateblocks it via Core RPC.
        // Below activation the diff is still computed (outputs are indexed)
        // but spends are not verified.
        let chain_utxos = dbs.p2mr_utxos.load_map(rwtxn)?;
        let p2mr_utxo = pqc::validate_and_diff_block_transactions(
            block,
            height,
            Bip360Activation(self.activation_height),
            &chain_utxos,
            &self.extra_prevouts,
            self.pqc_verify_budget_ms,
        )
        .map_err(|source| error::ConnectBlock::Bip360 { block_hash, source })?;

        let block_info = BlockInfo {
            coinbase_txid: coinbase.compute_txid(),
        };
        let block_diff = diff::Block { p2mr_utxo };
        let () = block_diff.apply(rwtxn, dbs, height)?;
        let () = dbs
            .block_hashes
            .put_block_info(rwtxn, &block_hash, &block_info, &block_diff)
            .map_err(error::ConnectBlock::PutBlockInfo)?;
        let current_tip_cumulative_work: Option<Work> = 'work: {
            let Some(current_tip) = dbs.current_chain_tip.try_get(rwtxn, &())? else {
                break 'work None;
            };
            Some(
                dbs.block_hashes
                    .cumulative_work()
                    .get(rwtxn, &current_tip)?,
            )
        };
        let cumulative_work = dbs.block_hashes.cumulative_work().get(rwtxn, &block_hash)?;
        if Some(cumulative_work) > current_tip_cumulative_work {
            dbs.current_chain_tip.put(rwtxn, &(), &block_hash)?;
            tracing::trace!("updated current chain tip: {}", height);
        }
        Ok(Event::ConnectBlock {
            header_info: HeaderInfo {
                block_hash,
                prev_block_hash: prev_mainchain_block_hash,
                height,
                work: block.header.work(),
                timestamp: block.header.time,
            },
            block_info,
        })
    }

    /// Block header should be stored before calling this. Runs BIP 360
    /// validation via [`Self::connect_block_pass_through`]; an invalid P2MR
    /// spend produces a non-fatal rejection.
    #[tracing::instrument(skip_all)]
    pub(in crate::validator) fn connect_block(
        &self,
        rwtxn: &mut RwTxn,
        block: &Block,
    ) -> Result<Event, error::ConnectBlock> {
        let dbs = self.dbs;
        let parent = block.header.prev_blockhash;

        tracing::trace!("verifying chain tip is block parent");
        // Check that current chain tip is block parent
        match dbs.current_chain_tip.try_get(rwtxn, &())? {
            Some(tip) if parent == tip => (),
            Some(tip) => {
                let tip_height = dbs
                    .block_hashes
                    .height()
                    .get(rwtxn, &tip)
                    .unwrap_or_default();
                tracing::error!(
                    chain_tip = %tip,
                    incoming_block_parent = %parent,
                    "unable to connect block: chain tip is not parent of incoming block"
                );
                return Err(error::ConnectBlock::BlockParent {
                    parent,
                    tip,
                    tip_height,
                });
            }
            None if block.header.prev_blockhash == BlockHash::all_zeros() => (),
            None => {
                return Err(error::ConnectBlock::BlockParent {
                    parent,
                    tip: BlockHash::all_zeros(),
                    tip_height: 0,
                });
            }
        }

        tracing::trace!("starting block processing");
        let height = dbs.block_hashes.height().get(rwtxn, &block.block_hash())?;
        let Some(coinbase) = block.txdata.first() else {
            return Err(error::ConnectBlock::NoCoinbase);
        };

        let block_hash = block.header.block_hash();
        let prev_mainchain_block_hash = block.header.prev_blockhash;

        self.connect_block_pass_through(
            rwtxn,
            block,
            height,
            coinbase,
            block_hash,
            prev_mainchain_block_hash,
        )
    }

    pub(in crate::validator) fn disconnect_block(
        &self,
        rwtxn: &mut RwTxn,
        event_tx: &Sender<Event>,
        block_hash: BlockHash,
    ) -> Result<(), error::DisconnectBlock> {
        let dbs = self.dbs;
        // Absence of a stored diff means we rejected the block. Nothing do to on our end!
        let Some(diff) = dbs.block_hashes.diff().try_get(rwtxn, &block_hash)? else {
            tracing::trace!(
                %block_hash,
                "disconnect_block: block was rejected, treating as no-op"
            );
            return Ok(());
        };

        if let Some(tip_hash) = dbs.current_chain_tip.try_get(rwtxn, &())?
            && tip_hash != block_hash
        {
            return Err(error::DisconnectBlock::TipHash {
                block_hash,
                tip_hash,
            });
        }
        let header_info = dbs.block_hashes.get_header_info(rwtxn, &block_hash)?;
        let () = diff.undo(rwtxn, dbs)?;
        if header_info.prev_block_hash != BlockHash::all_zeros() {
            dbs.current_chain_tip
                .put(rwtxn, &(), &header_info.prev_block_hash)?;
        } else {
            dbs.current_chain_tip.delete(rwtxn, &())?;
        }
        let event = Event::DisconnectBlock { block_hash };
        let _send_err: Result<Option<_>, TrySendError<_>> = event_tx.try_broadcast(event);
        Ok(())
    }
}

// Find the best ancestor of the node's tip that the enforcer has
// Returns hash and height of the best ancestor.
async fn fetch_best_ancestor<MainRpcClient>(
    dbs: &Dbs,
    mainchain: &MainRpcClient,
    node_tip: BlockHash,
    node_tip_height: u32,
) -> Result<Option<(BlockHash, u32)>, error::Sync>
where
    MainRpcClient: bitcoin_jsonrpsee::client::MainClient + Sync,
{
    if node_tip == BlockHash::all_zeros() {
        return Ok(None);
    }

    // Check if enforcer already has the node tip
    {
        let rotxn = dbs.read_txn()?;
        if dbs.block_hashes.contains_header(&rotxn, &node_tip)? {
            return Ok(Some((node_tip, node_tip_height)));
        }
    }

    // Find best ancestor via binary search
    let mut best_known_ancestor: Option<(BlockHash, u32)> = None;
    let mut oldest_known_missing_ancestor_height = node_tip_height;

    loop {
        let best_known_ancestor_height = best_known_ancestor.map(|(_, height)| height);
        let midpoint_height =
            oldest_known_missing_ancestor_height.midpoint(best_known_ancestor_height.unwrap_or(0));
        if Some(midpoint_height) == best_known_ancestor_height
            || midpoint_height == oldest_known_missing_ancestor_height
        {
            return Ok(best_known_ancestor);
        }

        let midpoint = mainchain
            .getblockhash(midpoint_height as usize)
            .await
            .map_err(|err| error::Sync::JsonRpc {
                method: "getblockhash".to_owned(),
                source: err,
            })?;
        let rotxn = dbs.read_txn()?;
        if dbs.block_hashes.contains_header(&rotxn, &midpoint)? {
            best_known_ancestor = Some((midpoint, midpoint_height));
        } else {
            oldest_known_missing_ancestor_height = midpoint_height;
        }
    }
}

#[tracing::instrument(skip_all)]
async fn sync_headers<MainRpcClient>(
    dbs: &Dbs,
    main_rest_client: &MainRestClient,
    main_rpc_client: &MainRpcClient,
    main_tip: BlockHash,
    progress_tx: &tokio::sync::watch::Sender<HeaderSyncProgress>,
    cancel: CancellationToken,
) -> Result<(), error::Sync>
where
    MainRpcClient: bitcoin_jsonrpsee::client::MainClient + Sync,
{
    let start = Instant::now();

    if main_tip == BlockHash::all_zeros() {
        return Ok(());
    }

    let main_tip_height = main_rpc_client
        .getblockheader(main_tip)
        .await
        .map_err(|err| error::Sync::JsonRpc {
            method: "getblockheader".to_owned(),
            source: err,
        })?
        .height;

    let best_ancestor: Option<(BlockHash, u32)> =
        fetch_best_ancestor(dbs, main_rpc_client, main_tip, main_tip_height).await?;

    // Return early if all headers are already available.
    let (mut current_block_hash, mut current_height, new_headers_needed) = match best_ancestor {
        Some((ancestor, height)) => {
            if ancestor == main_tip {
                return Ok(());
            } else {
                (ancestor, height, main_tip_height - height)
            }
        }
        None => {
            let genesis_block_hash =
                main_rpc_client
                    .getblockhash(0)
                    .await
                    .map_err(|err| error::Sync::JsonRpc {
                        method: "getblockhash".to_owned(),
                        source: err,
                    })?;
            (genesis_block_hash, 0, main_tip_height + 1)
        }
    };

    // Fetch headers in batches for efficiency
    // 2000 is max allowed by Bitcoin Core
    const HEADER_FETCH_BATCH_SIZE: usize = 2000;

    tracing::debug!(
        "Syncing headers starting from #{current_height} `{current_block_hash}` up to `{main_tip}`"
    );

    // The requested block header is the /first/ header in the batch. This means we
    // need to loop from our current tip, until we find the requested main tip.
    loop {
        if cancel.is_cancelled() {
            tracing::warn!("Header sync interrupted");
            return Err(error::Sync::Shutdown);
        }

        tracing::debug!(
            "Fetching batch of headers starting from #{current_height} `{current_block_hash}`"
        );

        // It is possible that the first header is not new
        let headers_needed = (main_tip_height - current_height) + 1;
        let batch_size = std::cmp::min(HEADER_FETCH_BATCH_SIZE, headers_needed as usize);
        // Fetch a batch of headers
        let headers = main_rest_client
            .get_block_headers(&current_block_hash, batch_size)
            .await?;

        match headers.last() {
            Some((_, last_block_hash, last_block_height)) => {
                // Update the block_hash to the latest header fetched in this
                // batch to continue the loop
                current_block_hash = *last_block_hash;
                current_height = *last_block_height;
            }
            None => {
                // This will be empty if the requested block hash is not in the
                // current active chain, i.e. if we're dealing with a reorg,
                // or the provided mainchain tip was invalid.

                // Syncing headers is a reasonably quick operation.
                // We therefore deal with it by erroring out here, and then
                // retrying the sync from further out in the call stack.
                //
                // This branch only hits if we're dealing with a reorg /while/
                // we're syncing headers.
                // If we've reorged before starting the sync, it is picked up
                // at the beginning. It is such an edge case that we don't
                // bother implementing it (for now, at least)
                return Err(error::Sync::BlockNotInActiveChain {
                    block_hash: current_block_hash,
                });
            }
        }

        // Store the fetched headers
        let mut rwtxn = dbs.write_txn()?;
        dbs.block_hashes.put_headers(
            &mut rwtxn,
            &headers
                .iter()
                .map(|(header, _, height)| (*header, *height))
                .collect::<Vec<_>>(),
        )?;
        let () = rwtxn.commit()?;

        // Send progress update
        let progress = HeaderSyncProgress {
            current_height: Some(current_height),
        };
        if let Err(err) = progress_tx.send(progress) {
            tracing::warn!("Failed to send header sync progress: {err:#}");
        }

        // Important: break out here /after/ storing the last header.
        if current_block_hash == main_tip {
            tracing::info!(main_tip = %main_tip, "Reached main tip at height {current_height}!");
            break;
        } else if current_height == main_tip_height {
            return Err(error::Sync::BlockNotInActiveChain {
                block_hash: main_tip,
            });
        }
    }

    tracing::info!(
        main_tip = ?main_tip,
        "Synced {new_headers_needed} headers in {}",
        jiff::SignedDuration::try_from(start.elapsed()).unwrap_or_default()
    );
    Ok(())
}

async fn fetch_blocks_batch<MainRpcClient>(
    main_rpc_client: &MainRpcClient,
    block_hashes: &[BlockHash],
) -> Result<Vec<Block>, error::Sync>
where
    MainRpcClient: bitcoin_jsonrpsee::client::MainClient + Sync,
{
    let mut get_block_batch = BatchRequestBuilder::new();
    for block_hash in block_hashes {
        // By default (1) a deserialized block is returned. We want to do this ourselves!
        let verbosity = 0;

        let mut params = ArrayParams::new();
        params
            .insert(block_hash.to_string())
            .expect("failed to insert block hash");

        params
            .insert(verbosity)
            .expect("failed to insert verbosity");

        get_block_batch
            .insert("getblock", params)
            .map_err(error::Sync::JsonSerialize)?;
    }

    let start = Instant::now();

    let batch_response: BatchResponse<String> = main_rpc_client
        .batch_request(get_block_batch)
        .boxed() // IMPORTANT: omitting this box leads to cryptic a lifetime error
        .await
        .map_err(|err| error::Sync::JsonRpc {
            method: "getblock (batched)".to_owned(),
            source: err,
        })?;

    let fetch_duration = start.elapsed();

    let blocks = match batch_response.ok() {
        Ok(blocks) => blocks
            .map(|block| {
                let bytes = hex::decode(block)?;
                let block: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)?;

                Ok::<_, error::Sync>(block)
            })
            .collect::<Result<Vec<_>, _>>()?,
        Err(errors) => {
            return Err(error::Sync::BatchJsonRpc {
                errors: errors.map(|e| e.message().to_string()).collect(),
            });
        }
    };

    let deserialization_duration = start.elapsed() - fetch_duration;

    tracing::debug!(
        "Fetched ({:?}) and deserialized ({:?}) batch of {} block(s) with {} total transactions",
        fetch_duration,
        deserialization_duration,
        blocks.len(),
        blocks.iter().map(|block| block.txdata.len()).sum::<usize>(),
    );

    Ok(blocks)
}

impl BlockHandler<'_> {
    /// Returns `Some(block_hash)` if a rejected block was encountered.
    //  Returns `None` if every block in the batch connected successfully.
    pub(in crate::validator) fn handle_block_batch<'a>(
        &self,
        rwtxn: &mut RwTxn<'a>,
        blocks: &[Block],
        event_tx: &Sender<Event>,
    ) -> Result<Option<(BlockHash, String)>, error::Sync> {
        let dbs = self.dbs;
        let start = Instant::now();

        let mut total_txs = 0;

        // Process blocks sequentially to maintain ordering and database consistency
        for block in blocks {
            let block_hash = block.block_hash();

            tracing::trace!("Syncing block #{} `{block_hash}`", {
                // Do the data fetch within the macro, to avoid the cost on higher
                // log levels
                dbs.block_hashes.height().get(rwtxn, &block_hash)?
            });

            let start_block = Instant::now();
            // We should not call out to `invalidateblock` in case of failures here,
            // as that is handled by the cusf-enforcer-mempool crate.
            // FIXME: handle disconnects
            let event = match self.connect_block(rwtxn, block) {
                Ok(event) => event,
                Err(err) if !err.is_fatal() => {
                    let reason = format!("{:#}", crate::errors::ErrorChain::new(&err));
                    tracing::info!(
                        %block_hash,
                        "encountered invalid block during batch sync: {reason}",
                    );
                    return Ok(Some((block_hash, reason)));
                }
                Err(err) => return Err(err.into()),
            };

            let connect_block_duration =
                jiff::SignedDuration::try_from(start_block.elapsed()).unwrap_or_default();

            // Create dynamic fields using a HashMap for structured logging
            match &event {
                Event::ConnectBlock {
                    header_info,
                    block_info: _,
                } => {
                    // Keep all the blocks at info level in the beginning,
                    // and then taper off into less log noise
                    let log_interval = match header_info.height {
                        0..=999 => 1,
                        1000..=9999 => 10,
                        10_000..=99_999 => 100,
                        100_000.. => 1000,
                    };

                    total_txs += block.txdata.len();

                    // Apparently it isn't possible to do dynamic levels? wtf
                    // https://github.com/tokio-rs/tracing/issues/2730
                    if header_info.height % log_interval == 0 {
                        tracing::info!(
                            total_txs = block.txdata.len(),
                            "Synced block #{}: `{}` in {connect_block_duration}",
                            header_info.height,
                            header_info.block_hash,
                        );
                    } else {
                        tracing::debug!(
                            total_txs = block.txdata.len(),
                            "Synced block #{}: `{}` in {connect_block_duration}",
                            header_info.height,
                            header_info.block_hash,
                        );
                    };
                }
                Event::DisconnectBlock { block_hash } => {
                    tracing::debug!(
                        "Disconnected block: `{block_hash}` in {connect_block_duration}",
                    );
                }
            }
            // Events should only ever be sent after committing DB txs, see
            // https://github.com/LayerTwo-Labs/bip360p_enforcer/pull/185
            let _send_err: Result<Option<_>, TrySendError<_>> = event_tx.try_broadcast(event);
        }

        tracing::info!(
            total_txs = total_txs,
            "Synced batch of {} blocks in {}",
            blocks.len(),
            jiff::SignedDuration::try_from(start.elapsed()).unwrap_or_default(),
        );
        Ok(None)
    }

    // MUST be called after `sync_headers`.
    #[tracing::instrument(skip_all)]
    async fn sync_blocks<MainRpcClient>(
        &self,
        event_tx: &Sender<Event>,
        main_rpc_client: &MainRpcClient,
        main_blocks_dir: Option<PathBuf>,
        main_tip: BlockHash,
        cancel: CancellationToken,
    ) -> Result<Option<(BlockHash, String)>, error::Sync>
    where
        MainRpcClient: bitcoin_jsonrpsee::client::MainClient + Sync,
    {
        // Batch size for concurrent block fetching
        // It's hard to know what a good size here is, without
        // further benchmarking.
        const BLOCK_FETCH_BATCH_SIZE: usize = 50;

        let dbs = self.dbs;
        let start = Instant::now();
        let mut missing_blocks = tokio::task::block_in_place(|| {
            let current_enforcer_tip = {
                let mut rwtxn = dbs.write_txn()?;
                let mut current_enforcer_tip = dbs
                    .current_chain_tip
                    .try_get(&rwtxn, &())?
                    .unwrap_or_else(BlockHash::all_zeros);
                let last_common_ancestor = dbs.block_hashes.last_common_ancestor(
                    &rwtxn,
                    current_enforcer_tip,
                    main_tip,
                )?;
                if current_enforcer_tip != last_common_ancestor {
                    tracing::info!(
                        "Disconnecting tip {current_enforcer_tip} -> {last_common_ancestor}"
                    );
                    while current_enforcer_tip != last_common_ancestor {
                        let () =
                            self.disconnect_block(&mut rwtxn, event_tx, current_enforcer_tip)?;
                        current_enforcer_tip = dbs
                            .current_chain_tip
                            .try_get(&rwtxn, &())?
                            .unwrap_or_else(BlockHash::all_zeros);
                    }
                    rwtxn.commit()?;
                } else {
                    rwtxn.abort();
                }
                current_enforcer_tip
            };
            let rotxn = dbs.read_txn()?;
            let missing_blocks = dbs
                .block_hashes
                .ancestor_headers(&rotxn, main_tip)
                .map(|(block_hash, _)| Ok(block_hash))
                .take_while(|block_hash| Ok(*block_hash != current_enforcer_tip))
                .collect::<Vec<_>>()
                .map_err(error::Sync::from)?;
            Ok::<_, error::Sync>(missing_blocks)
        })?;

        if missing_blocks.is_empty() {
            tracing::info!("No missing blocks, skipping sync");
            return Ok(None);
        }

        tracing::info!(
            "identified {} missing blocks in {:?}, starting batched sync",
            missing_blocks.len(),
            start.elapsed()
        );

        let mut total_blocks_fetched: usize = 0;

        if let Some(main_blocks_dir) = main_blocks_dir {
            let start = Instant::now();
            tracing::debug!(
                network = %self.network,
                "syncing blocks from blocks dir: {}",
                main_blocks_dir.display()
            );

            match block_files::sync_from_directory(
                self,
                event_tx,
                &mut missing_blocks,
                main_blocks_dir,
                cancel.clone(),
            ) {
                Ok(total_handled_blocks) => {
                    total_blocks_fetched += total_handled_blocks as usize;
                    tracing::info!(
                        "Synced {total_handled_blocks} blocks from blocks dir in {:?}",
                        start.elapsed()
                    );
                }
                Err(e) => {
                    tracing::error!("Error syncing blocks from blocks dir: {e:#}");
                }
            }
        }

        // Process blocks in batches for better network efficiency
        let missing_blocks_rev: Vec<_> = missing_blocks.into_iter().rev().collect();
        for chunk in missing_blocks_rev.chunks(BLOCK_FETCH_BATCH_SIZE) {
            if cancel.is_cancelled() {
                tracing::warn!("Block sync interrupted");
                return Err(error::Sync::Shutdown);
            }

            let blocks = fetch_blocks_batch(main_rpc_client, chunk).await?;
            total_blocks_fetched += blocks.len();

            let mut rwtxn = dbs.write_txn()?;
            let rejected = self.handle_block_batch(&mut rwtxn, &blocks, event_tx)?;
            rwtxn.commit()?;
            if let Some((rejected_block, reason)) = rejected {
                tracing::warn!(
                    %rejected_block,
                    "stopping batch sync early: a rejected block was encountered"
                );
                return Ok(Some((rejected_block, reason)));
            }
        }

        tracing::info!(
            "Synced {total_blocks_fetched} blocks in {:?}",
            start.elapsed()
        );
        Ok(None)
    }
}

// Is this a good name? "Signal" in this context means both
// signal receiver and signal sender
pub struct SyncSignals {
    pub cancel: CancellationToken,
    pub header_sync_progress_tx: tokio::sync::watch::Sender<HeaderSyncProgress>,
    pub event_tx: Sender<Event>,
}

impl BlockHandler<'_> {
    pub(in crate::validator) async fn sync_to_tip<MainClient>(
        &self,
        main_rpc_client: &MainClient,
        main_rest_client: &MainRestClient,
        main_blocks_dir: Option<PathBuf>,
        main_tip: BlockHash,
        signals: SyncSignals,
    ) -> Result<Option<(BlockHash, String)>, error::Sync>
    where
        MainClient: bitcoin_jsonrpsee::client::MainClient + Sync,
    {
        let () = sync_headers(
            self.dbs,
            main_rest_client,
            main_rpc_client,
            main_tip,
            &signals.header_sync_progress_tx,
            signals.cancel.clone(),
        )
        .await?;
        let rejected = self
            .sync_blocks(
                &signals.event_tx,
                main_rpc_client,
                main_blocks_dir,
                main_tip,
                signals.cancel.clone(),
            )
            .await?;
        Ok(rejected)
    }
}

#[cfg(test)]
mod connect_disconnect_tests {
    use bitcoin::{Block, BlockHash, Transaction, hashes::Hash as _};
    use miette::{IntoDiagnostic, Result};

    use super::BlockHandler;
    use crate::validator::test_utils::create_test_dbs;

    fn test_handler(dbs: &crate::validator::dbs::Dbs) -> BlockHandler<'_> {
        BlockHandler::new(
            dbs,
            bitcoin::Network::Regtest,
            0,
            crate::validator::pqc::limits::DEFAULT_PQC_VERIFY_BUDGET_MS,
            std::collections::HashMap::new(),
        )
    }

    fn coinbase_tx() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                ..Default::default()
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    fn block_with_coinbase(prev_hash: BlockHash) -> Block {
        let txdata = vec![coinbase_tx()];
        let merkle_root = bitcoin::merkle_tree::calculate_root(
            txdata
                .iter()
                .map(Transaction::compute_txid)
                .map(|txid| *txid.as_raw_hash()),
        )
        .map(bitcoin::TxMerkleNode::from_raw_hash)
        .unwrap();
        Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::TWO,
                prev_blockhash: prev_hash,
                merkle_root,
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata,
        }
    }

    /// Template smoke: a block connects (accepted, tip advances, event
    /// emitted) and disconnects (tip rewinds) with the empty rule set.
    #[test]
    fn connect_disconnect_roundtrip_through_handler() -> Result<()> {
        let (_dir, dbs) = create_test_dbs()?;
        let handler = test_handler(&dbs);
        let mut rwtxn = dbs.write_txn().into_diagnostic()?;

        let block = block_with_coinbase(BlockHash::all_zeros());
        let block_hash = block.header.block_hash();
        dbs.block_hashes
            .put_headers(&mut rwtxn, &[(block.header, 0)])
            .into_diagnostic()?;

        let event = handler
            .connect_block(&mut rwtxn, &block)
            .into_diagnostic()?;
        match event {
            super::Event::ConnectBlock { header_info, .. } => {
                assert_eq!(header_info.block_hash, block_hash);
            }
            other => panic!("expected ConnectBlock event, got {other:?}"),
        }
        assert_eq!(
            dbs.current_chain_tip
                .try_get(&rwtxn, &())
                .into_diagnostic()?,
            Some(block_hash)
        );

        let (event_tx, _event_rx) = async_broadcast::broadcast(8);
        handler
            .disconnect_block(&mut rwtxn, &event_tx, block_hash)
            .into_diagnostic()?;
        assert_eq!(
            dbs.current_chain_tip
                .try_get(&rwtxn, &())
                .into_diagnostic()?,
            None
        );
        Ok(())
    }
}
