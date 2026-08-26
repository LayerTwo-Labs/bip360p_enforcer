//! Implementation of [`cusf_enforcer_mempool::cusf_enforcer::CusfEnforcer`]

use std::{
    collections::{HashMap, HashSet},
    future::Future,
};

use async_broadcast::TrySendError;
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid, hashes::Hash as _,
};
use cusf_enforcer_mempool::cusf_enforcer::{
    ConnectBlockAction, CusfEnforcer, DisconnectBlockAction, TxAcceptAction,
};
use error_fatality::{Nested as _, Split};
use futures::TryFutureExt as _;
use miette::Diagnostic;
use ouroboros::self_referencing;
use sneed::{RwTxn, db, env, rwtxn};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    errors::ErrorChain,
    proto::mainchain::HeaderSyncProgress,
    types::Event,
    validator::{
        Validator,
        task::{self, BlockHandler, error::ValidateTransaction as ValidateTransactionError},
    },
};

#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct SyncError(#[from] task::error::Sync);

#[derive(Debug, Diagnostic, Error)]
enum ConnectBlockErrorInner {
    #[error(transparent)]
    CommitWriteTxn(#[from] rwtxn::error::Commit),
    #[error(transparent)]
    ConnectBlock(#[from] Box<<task::error::ConnectBlock as Split>::Fatal>),
    #[error(transparent)]
    DbPut(#[from] db::error::Put),
    #[error(transparent)]
    DbTryGet(#[from] db::error::TryGet),
    #[error(transparent)]
    DbRange(Box<db::error::Range>),
    #[error(transparent)]
    NestedWriteTxn(#[from] env::error::NestedWriteTxn),
    #[error(transparent)]
    WriteTxn(#[from] env::error::WriteTxn),
}

impl From<db::error::Range> for ConnectBlockErrorInner {
    fn from(err: db::error::Range) -> Self {
        Self::DbRange(Box::new(err))
    }
}

impl From<<task::error::ConnectBlock as Split>::Fatal> for ConnectBlockErrorInner {
    fn from(err: <task::error::ConnectBlock as Split>::Fatal) -> Self {
        Self::from(Box::new(err))
    }
}

#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct ConnectBlockError(ConnectBlockErrorInner);

impl<Err> From<Err> for ConnectBlockError
where
    ConnectBlockErrorInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Diagnostic, Error)]
enum DisconnectBlockErrorInner {
    #[error(transparent)]
    CommitWriteTxn(#[from] rwtxn::error::Commit),
    #[error(transparent)]
    DisconnectBlock(#[from] task::error::DisconnectBlock),
    #[error(transparent)]
    WriteTxn(#[from] env::error::WriteTxn),
}

#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct DisconnectBlockError(DisconnectBlockErrorInner);

impl<Err> From<Err> for DisconnectBlockError
where
    DisconnectBlockErrorInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Diagnostic, Error)]
enum AcceptTxErrorInner {
    #[error(transparent)]
    Commit(#[from] rwtxn::error::Commit),
    #[error(transparent)]
    Db(#[from] db::Error),
    #[error(transparent)]
    ValidateTransaction(#[from] ValidateTransactionError),
    #[error(transparent)]
    WriteTxn(#[from] env::error::WriteTxn),
}

#[derive(Debug, Diagnostic, Error)]
#[error(transparent)]
#[repr(transparent)]
pub struct AcceptTxError(AcceptTxErrorInner);

impl<Err> From<Err> for AcceptTxError
where
    AcceptTxErrorInner: From<Err>,
{
    fn from(err: Err) -> Self {
        Self(err.into())
    }
}

/// Parent and child rwtxn
#[self_referencing]
struct ParentChildRwTxn<'a> {
    parent: RwTxn<'a>,
    // Annotated not_covariant because covariance is not needed.
    // May be covariant
    #[borrows(mut parent)]
    #[not_covariant]
    child: RwTxn<'this>,
}

impl<'a> ParentChildRwTxn<'a> {
    /// Abort child rwtxn and return parent
    fn abort_child(self) -> RwTxn<'a> {
        let ((), heads) = self.destruct_into_heads(|tails| tails.child.abort());
        heads.parent
    }

    /// Commit child rwtxn and return parent
    fn commit_child(self) -> Result<RwTxn<'a>, rwtxn::error::Commit> {
        let (commit_res, heads) = self.destruct_into_heads(|tails| tails.child.commit());
        let () = commit_res?;
        Ok(heads.parent)
    }
}

#[derive(Debug, Error)]
enum RejectReason {
    #[error(transparent)]
    ConnectBlock(#[from] <task::error::ConnectBlock as Split>::Jfyi),
    #[error("Missing parent (`{parent}`) height for block hash `{block_hash}`")]
    MissingParentHeight {
        block_hash: BlockHash,
        parent: BlockHash,
    },
}

/// Connect block action, with rwtxns that can be committed or aborted
enum ConnectBlockRwTxnAction<'a> {
    Accept {
        event: Event,
        remove_mempool_txs: HashSet<Txid>,
        rwtxns: ParentChildRwTxn<'a>,
    },
    Reject {
        /// rwtxn to write header
        header_rwtxn: RwTxn<'a>,
        reason: RejectReason,
    },
}

/// Connect a block without commiting the rwtxn.
/// The rwtxn is returned and can be committed or aborted.
/// If connecting the block results in a header write, the header write is
/// always committed. The block connect is not committed.
fn connect_block_no_commit<'validator>(
    validator: &'validator Validator,
    block: &Block,
    extra_prevouts: HashMap<OutPoint, TxOut>,
) -> Result<ConnectBlockRwTxnAction<'validator>, ConnectBlockError> {
    let block_hash = block.block_hash();
    let parent = block.header.prev_blockhash;
    // Always commit, to store header if necessary
    let mut parent_rwtxn = validator.dbs.write_txn()?;
    if !validator
        .dbs
        .block_hashes
        .contains_header(&parent_rwtxn, &block_hash)?
    {
        let height = if parent == BlockHash::all_zeros() {
            0
        } else if let Some(parent_height) = validator
            .dbs
            .block_hashes
            .height()
            .try_get(&parent_rwtxn, &parent)?
        {
            parent_height + 1
        } else {
            let reject_reason = RejectReason::MissingParentHeight { block_hash, parent };
            return Ok(ConnectBlockRwTxnAction::Reject {
                header_rwtxn: parent_rwtxn,
                reason: reject_reason,
            });
        };
        tracing::trace!("Storing header");
        validator
            .dbs
            .block_hashes
            .put_headers(&mut parent_rwtxn, &[(block.header, height)])?;
    }
    // Commit on block accept, abort on block reject
    let mut parent_child_rwtxn = ParentChildRwTxnTryBuilder {
        parent: parent_rwtxn,
        child_builder: |parent: &mut RwTxn| validator.dbs.nested_write_txn(parent),
    }
    .try_build()?;
    let handler = BlockHandler::new(
        &validator.dbs,
        validator.network,
        validator.activation_height(),
        validator.pqc_verify_budget_ms(),
        extra_prevouts,
    );
    match parent_child_rwtxn
        .with_child_mut(|child_rwtxn| handler.connect_block(child_rwtxn, block))
        .into_nested()?
    {
        Ok(event) => Ok(ConnectBlockRwTxnAction::Accept {
            event,
            remove_mempool_txs: HashSet::new(),
            rwtxns: parent_child_rwtxn,
        }),
        Err(jfyi) => {
            let header_rwtxn = parent_child_rwtxn.abort_child();
            Ok(ConnectBlockRwTxnAction::Reject {
                header_rwtxn,
                reason: RejectReason::ConnectBlock(jfyi),
            })
        }
    }
}

/// Used to specify commit/dry-run modes
trait ConnectBlockMode<'validator> {
    type Output;

    fn connect_block(
        self,
        validator: &'validator Validator,
        block: &Block,
        extra_prevouts: HashMap<OutPoint, TxOut>,
    ) -> Result<Self::Output, ConnectBlockError>;
}

/// Used to implement `ConnectBlockMode`.
/// Connects and commits a block.
struct ConnectBlockCommit;

impl<'validator> ConnectBlockMode<'validator> for ConnectBlockCommit {
    type Output = ConnectBlockAction;

    fn connect_block(
        self,
        validator: &'validator Validator,
        block: &Block,
        extra_prevouts: HashMap<OutPoint, TxOut>,
    ) -> Result<Self::Output, ConnectBlockError> {
        match connect_block_no_commit(validator, block, extra_prevouts)? {
            ConnectBlockRwTxnAction::Accept {
                event,
                remove_mempool_txs,
                rwtxns,
            } => {
                tracing::info!("accepted block");
                let rwtxn = rwtxns.commit_child()?;
                rwtxn.commit()?;
                // Events should only ever be sent after committing DB txs, see
                // https://github.com/LayerTwo-Labs/cusf_enforcer/pull/185
                let _send_err: Result<Option<_>, TrySendError<_>> =
                    validator.events_tx.try_broadcast(event);
                Ok(ConnectBlockAction::Accept { remove_mempool_txs })
            }
            ConnectBlockRwTxnAction::Reject {
                header_rwtxn,
                reason,
            } => {
                tracing::info!("rejecting block: {:#}", ErrorChain::new(&reason));
                header_rwtxn.commit()?;
                Ok(ConnectBlockAction::Reject)
            }
        }
    }
}

impl Validator {
    /// Fetch, from bitcoind, prevouts that the synchronous block-connect path
    /// cannot resolve from the indexed P2MR UTXO set or this block's own
    /// outputs: a multi-input P2MR spend's non-P2MR co-input from a prior
    /// block, and (from Phase 6b) Taproot-v1 vault inputs whose amount the
    /// value-preservation checks require. Returns an empty map when the block
    /// contains no such spend, or best-effort partial results on RPC failure —
    /// the downstream checks fail closed on anything left unresolved.
    async fn prefetch_external_prevouts(&self, block: &Block) -> HashMap<OutPoint, TxOut> {
        // Identify prevouts the sync path cannot resolve. Today: a multi-input
        // P2MR spend's co-input whose prevout is neither a tracked P2MR output
        // nor created earlier in this block — required to build the committing
        // `Prevouts::All` sighash. (Phase 6b extends this to Taproot-v1 vault
        // inputs, whose amount the value-preservation checks need.)
        let chain_p2mr = match self.p2mr_utxos() {
            Ok(map) => map,
            // Can't classify without the P2MR set; downstream fails closed.
            Err(_) => return HashMap::new(),
        };
        let same_block: HashSet<OutPoint> = block
            .txdata
            .iter()
            .flat_map(|tx| {
                let txid = tx.compute_txid();
                (0..tx.output.len() as u32).map(move |vout| OutPoint { txid, vout })
            })
            .collect();

        let mut wanted: HashSet<OutPoint> = HashSet::new();
        for tx in block.txdata.iter().skip(1) {
            if tx.input.len() < 2 {
                continue; // single-input spends need only their own prevout
            }
            let spends_p2mr = tx
                .input
                .iter()
                .any(|input| chain_p2mr.contains_key(&input.previous_output));
            if !spends_p2mr {
                continue;
            }
            for input in &tx.input {
                let outpoint = input.previous_output;
                if chain_p2mr.contains_key(&outpoint) || same_block.contains(&outpoint) {
                    continue; // resolvable locally
                }
                wanted.insert(outpoint);
            }
        }

        if wanted.is_empty() {
            return HashMap::new();
        }
        self.fetch_prevouts_getblock_v3(block.block_hash(), &wanted)
            .await
    }

    /// Resolve `wanted` outpoints' prevouts via a single `getblock <hash> 3`
    /// call, which returns every input's `prevout` (value + scriptPubKey) with
    /// no txindex requirement. Best-effort: on any RPC/parse failure the entry
    /// is simply absent and the downstream check fails closed.
    async fn fetch_prevouts_getblock_v3(
        &self,
        block_hash: BlockHash,
        wanted: &HashSet<OutPoint>,
    ) -> HashMap<OutPoint, TxOut> {
        use jsonrpsee::core::client::ClientT as _;

        #[derive(serde::Deserialize)]
        struct GbBlock {
            tx: Vec<GbTx>,
        }
        #[derive(serde::Deserialize)]
        struct GbTx {
            vin: Vec<GbVin>,
        }
        #[derive(serde::Deserialize)]
        struct GbVin {
            txid: Option<Txid>,
            vout: Option<u32>,
            prevout: Option<GbPrevout>,
        }
        #[derive(serde::Deserialize)]
        struct GbPrevout {
            value: f64,
            #[serde(rename = "scriptPubKey")]
            script_pubkey: GbScriptPubKey,
        }
        #[derive(serde::Deserialize)]
        struct GbScriptPubKey {
            hex: String,
        }

        let params = jsonrpsee::rpc_params![block_hash, 3u8];
        let parsed: GbBlock = match self.mainchain_client.request("getblock", params).await {
            Ok(block) => block,
            Err(err) => {
                tracing::warn!(%block_hash, %err, "getblock verbosity=3 prevout fetch failed");
                return HashMap::new();
            }
        };

        let mut resolved = HashMap::new();
        for tx in parsed.tx {
            for vin in tx.vin {
                let (Some(txid), Some(vout), Some(prevout)) = (vin.txid, vin.vout, vin.prevout)
                else {
                    continue; // coinbase input has no prevout
                };
                let outpoint = OutPoint { txid, vout };
                if !wanted.contains(&outpoint) {
                    continue;
                }
                let (Ok(value), Ok(spk_bytes)) = (
                    Amount::from_btc(prevout.value),
                    hex::decode(&prevout.script_pubkey.hex),
                ) else {
                    continue;
                };
                resolved.insert(
                    outpoint,
                    TxOut {
                        value,
                        script_pubkey: ScriptBuf::from_bytes(spk_bytes),
                    },
                );
            }
        }
        resolved
    }
}

impl CusfEnforcer for Validator {
    type SyncError = SyncError;

    async fn sync_to_tip<Signal>(
        &mut self,
        shutdown_signal: Signal,
        tip: BlockHash,
    ) -> Result<(), Self::SyncError>
    where
        Signal: Future<Output = ()> + Send,
    {
        let cancel = CancellationToken::new();

        let header_sync_progress_tx = {
            let mut header_sync_progress_rx_write = self.header_sync_progress_rx.write();
            if header_sync_progress_rx_write.is_some() {
                return Err(task::error::Sync::HeaderSyncInProgress.into());
            }
            let (header_sync_progress_tx, header_sync_progress_rx) =
                tokio::sync::watch::channel(HeaderSyncProgress {
                    current_height: None,
                });
            *header_sync_progress_rx_write = Some(header_sync_progress_rx);
            header_sync_progress_tx
        };
        tracing::debug!(block_hash = %tip, "Syncing to tip");

        let handler = BlockHandler::new(
            &self.dbs,
            self.network,
            self.activation_height(),
            self.pqc_verify_budget_ms(),
            HashMap::new(),
        );
        let sync_future = handler
            .sync_to_tip(
                &self.mainchain_client,
                &self.mainchain_rest_client,
                self.mainchain_blocks_dir.clone(),
                tip,
                task::SyncSignals {
                    cancel: cancel.clone(),
                    header_sync_progress_tx,
                    event_tx: self.events_tx.clone(),
                },
            )
            .map_err(SyncError);

        tokio::select! {
            result = sync_future => {
                *self.header_sync_progress_rx.write() = None;
                result
            }
            _ = shutdown_signal => {
                cancel.cancel();
                *self.header_sync_progress_rx.write() = None;
                Err(SyncError(crate::validator::task::error::Sync::Shutdown))
            }
        }
    }

    type ConnectBlockError = ConnectBlockError;

    async fn connect_block(
        &mut self,
        block: &Block,
    ) -> Result<ConnectBlockAction, Self::ConnectBlockError> {
        // Resolve prevouts the synchronous connect path cannot see on its own —
        // a multi-input P2MR spend's non-P2MR co-input, or a Taproot-v1 vault
        // input — by fetching them from bitcoind before entering the write txn.
        let extra_prevouts = self.prefetch_external_prevouts(block).await;
        ConnectBlockCommit.connect_block(self, block, extra_prevouts)
    }

    type DisconnectBlockError = DisconnectBlockError;

    async fn disconnect_block(
        &mut self,
        block_hash: BlockHash,
    ) -> Result<DisconnectBlockAction, Self::DisconnectBlockError> {
        let mut rwtxn = self.dbs.write_txn()?;
        let handler = BlockHandler::new(
            &self.dbs,
            self.network,
            self.activation_height(),
            self.pqc_verify_budget_ms(),
            HashMap::new(),
        );
        let () = handler.disconnect_block(&mut rwtxn, &self.events_tx, block_hash)?;
        rwtxn.commit()?;
        Ok(DisconnectBlockAction::default())
    }

    type AcceptTxError = AcceptTxError;

    fn accept_tx(&mut self, tx: &Transaction) -> Result<TxAcceptAction, Self::AcceptTxError> {
        let mut rwtxn = self.dbs.write_txn()?;
        // A fatal error here isn't something that means we should
        // call out to the `invalidateblock` RPC. It simply means
        // the transaction will not be accepted into the mempool.
        let handler = BlockHandler::new(
            &self.dbs,
            self.network,
            self.activation_height(),
            self.pqc_verify_budget_ms(),
            HashMap::new(),
        );
        let res = if handler.validate_tx(&mut rwtxn, tx)? {
            TxAcceptAction::Accept {
                conflicts_with: HashSet::new(),
                weight_tweak: 0,
            }
        } else {
            TxAcceptAction::Reject
        };
        Ok(res)
    }
}
