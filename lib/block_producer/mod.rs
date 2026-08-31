use std::sync::Arc;

use bitcoin::{Amount, BlockHash, Transaction, Txid};
use cusf_enforcer_mempool::{
    cusf_block_producer::{
        CoinbaseTxn, CusfBlockProducer, FilledBlockTemplate, InitialBlockTemplate,
        initial_block_template::SuffixTxsItem,
        typewit::const_marker::{Bool, BoolWit},
    },
    cusf_enforcer::{
        ConnectBlockAction, CusfEnforcer, DisconnectBlockAction, SyncToTipError, TxAcceptAction,
    },
};
use tracing::instrument;

use crate::{errors::ErrorChain, validator::Validator};

/// Fully-signed P2MR spends awaiting block-template injection, keyed by txid;
/// the value carries the absolute fee.
type PendingP2mrSpends = ordermap::OrderMap<Txid, (Transaction, Amount)>;

pub mod error;
mod mine;

struct Inner {
    validator: Validator,
    main_client: bitcoin_jsonrpsee::jsonrpsee::http_client::HttpClient,
    gbt_client: bitcoin_jsonrpsee::jsonrpsee::http_client::HttpClient,
    config: crate::cli::Config,
    // Always Some(_) on signets
    signet_challenge: Option<bitcoin::ScriptBuf>,
    /// Error from the most recent failed block template build, cleared on
    /// success. The GBT server reports template failures to its JSON-RPC client
    /// in a field that `bitcoin-cli` (and thus the signet miner's stderr) drops,
    /// so `GenerateToAddress` attaches this to its own error to surface the
    /// root cause.
    last_gbt_error: parking_lot::RwLock<Option<String>>,
    /// Limits `GenerateToAddress` to one concurrent call at a time.
    generate_blocks_semaphore: Arc<tokio::sync::Semaphore>,
    /// Fully-signed P2MR spends awaiting inclusion in a block. Stock Core's
    /// mempool won't relay these (nonstandard witness v2), so they never reach
    /// the enforcer's shadow mempool; instead they are injected into the block
    /// template we build here (`finalize_block_template`) and mined via
    /// `submitblock`. Keyed by txid; the value carries the absolute fee.
    pending_p2mr_spends: parking_lot::Mutex<PendingP2mrSpends>,
}

#[derive(Clone)]
pub struct BlockProducer {
    inner: Arc<Inner>,
}

impl BlockProducer {
    pub fn new(
        validator: Validator,
        main_client: bitcoin_jsonrpsee::jsonrpsee::http_client::HttpClient,
        gbt_client: bitcoin_jsonrpsee::jsonrpsee::http_client::HttpClient,
        config: crate::cli::Config,
        signet_challenge: Option<bitcoin::ScriptBuf>,
    ) -> Result<Self, error::InitDbConnection> {
        Ok(Self {
            inner: Arc::new(Inner {
                validator,
                main_client,
                gbt_client,
                config,
                signet_challenge,
                last_gbt_error: parking_lot::RwLock::new(None),
                generate_blocks_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
                pending_p2mr_spends: parking_lot::Mutex::new(PendingP2mrSpends::new()),
            }),
        })
    }

    /// Queue a fully-signed P2MR spend for inclusion in the next block template.
    /// `fee` is the absolute fee (prevout value − sum of output values). The
    /// spend is injected via `finalize_block_template` and mined by
    /// `submitblock`; it is removed from the queue once seen in a connected
    /// block. Returns the spend txid.
    pub fn enqueue_p2mr_spend(&self, tx: Transaction, fee: Amount) -> Txid {
        let txid = tx.compute_txid();
        self.inner
            .pending_p2mr_spends
            .lock()
            .insert(txid, (tx, fee));
        txid
    }

    /// Drop any pending P2MR spends that appear in `block` (they've been mined).
    ///
    /// Called from every accepted-block path. In wallet mode the mempool sync
    /// drives [`Wallet::connect_block`](crate::wallet::Wallet), which connects
    /// the validator directly rather than through
    /// [`CusfEnforcer::connect_block`] here, so that path must reap explicitly —
    /// otherwise a mined spend lingers in the queue and is re-injected into the
    /// next template, colliding with its already-confirmed self (BIP30).
    pub(crate) fn reap_confirmed_p2mr_spends(&self, block: &bitcoin::Block) {
        let mut pending = self.inner.pending_p2mr_spends.lock();
        if pending.is_empty() {
            return;
        }
        for tx in &block.txdata {
            pending.swap_remove(&tx.compute_txid());
        }
    }

    pub fn validator(&self) -> &Validator {
        &self.inner.validator
    }

    /// JSON-RPC client for the Bitcoin Core node.
    pub(crate) fn main_client(&self) -> &bitcoin_jsonrpsee::jsonrpsee::http_client::HttpClient {
        &self.inner.main_client
    }

    pub(crate) fn gbt_client(&self) -> &bitcoin_jsonrpsee::jsonrpsee::http_client::HttpClient {
        &self.inner.gbt_client
    }

    pub(crate) fn config(&self) -> &crate::cli::Config {
        &self.inner.config
    }

    pub(crate) fn signet_challenge(&self) -> Option<&bitcoin::Script> {
        self.inner.signet_challenge.as_deref()
    }

    pub fn generate_blocks_semaphore(&self) -> &Arc<tokio::sync::Semaphore> {
        &self.inner.generate_blocks_semaphore
    }

    pub fn last_gbt_error(&self) -> Option<String> {
        self.inner.last_gbt_error.read().clone()
    }

    fn record_gbt_result<T, Err>(&self, res: &Result<T, Err>)
    where
        Err: std::error::Error,
    {
        *self.inner.last_gbt_error.write() = res
            .as_ref()
            .err()
            .map(|err| format!("{:#}", ErrorChain::new(err)));
    }

    /// Connect a block to the validator only, without touching policy state.
    ///
    /// Split out from [`CusfEnforcer::connect_block`] so the wallet can hold the
    /// BDK write lock across [`Self::apply_connected_block_policy`].
    pub(crate) async fn connect_block_validator(
        &mut self,
        block: &bitcoin::Block,
    ) -> Result<ConnectBlockAction, <Validator as CusfEnforcer>::ConnectBlockError> {
        self.inner.validator.clone().connect_block(block).await
    }
}

impl CusfEnforcer for BlockProducer {
    type SyncError = <Validator as CusfEnforcer>::SyncError;
    type InvalidBlockReason = <Validator as CusfEnforcer>::InvalidBlockReason;

    async fn sync_to_tip<Signal>(
        &mut self,
        shutdown_signal: Signal,
        tip_hash: BlockHash,
    ) -> Result<(), SyncToTipError<Self::InvalidBlockReason, Self::SyncError>>
    where
        Signal: std::future::Future<Output = ()> + Send,
    {
        self.inner
            .validator
            .clone()
            .sync_to_tip(shutdown_signal, tip_hash)
            .await
    }

    type ValidateBlockError = <Validator as CusfEnforcer>::ValidateBlockError;

    fn validate_block(
        &self,
        block: &bitcoin::Block,
    ) -> Result<Option<String>, Self::ValidateBlockError> {
        self.inner.validator.validate_block(block)
    }

    type ConnectBlockError = error::ConnectBlock;

    #[instrument(skip_all, fields(block_hash = %block.block_hash()))]
    async fn connect_block(
        &mut self,
        block: &bitcoin::Block,
    ) -> Result<ConnectBlockAction, Self::ConnectBlockError> {
        let res = self.connect_block_validator(block).await?;
        if matches!(res, ConnectBlockAction::Accept { .. }) {
            self.reap_confirmed_p2mr_spends(block);
        }
        Ok(res)
    }

    type DisconnectBlockError = <Validator as CusfEnforcer>::DisconnectBlockError;

    async fn disconnect_block(
        &mut self,
        block_hash: BlockHash,
    ) -> Result<DisconnectBlockAction, Self::DisconnectBlockError> {
        self.inner
            .validator
            .clone()
            .disconnect_block(block_hash)
            .await
    }

    type AcceptTxError = <Validator as CusfEnforcer>::AcceptTxError;

    fn accept_tx(&mut self, tx: &Transaction) -> Result<TxAcceptAction, Self::AcceptTxError> {
        self.inner.validator.clone().accept_tx(tx)
    }
}

impl CusfBlockProducer for BlockProducer {
    type InitialBlockTemplateError = error::InitialBlockTemplate;

    /// Called when the RPC server starts producing a block template:
    /// 1. the RPC server (in `cusf_enforcer_mempool`) receives the request,
    /// 2. it fetches the initial block template (this function),
    /// 3. it processes that further and returns it to the client.
    ///
    /// Reserves block weight for each pending P2MR spend so the mempool
    /// selection leaves room; the actual txs are appended in
    /// [`Self::finalize_block_template`].
    async fn initial_block_template<const COINBASE_TXN: bool>(
        &self,
        parent_block_hash: &BlockHash,
        coinbase_txn_wit: BoolWit<COINBASE_TXN>,
        template: &mut InitialBlockTemplate<COINBASE_TXN>,
    ) -> Result<(), Self::InitialBlockTemplateError>
    where
        Bool<COINBASE_TXN>: CoinbaseTxn,
    {
        let _ = (parent_block_hash, coinbase_txn_wit);
        let weights: Vec<bitcoin::Weight> = {
            let pending = self.inner.pending_p2mr_spends.lock();
            pending.values().map(|(tx, _fee)| tx.weight()).collect()
        };
        for weight in weights {
            template.suffix_txs.push(SuffixTxsItem::Reserved { weight });
        }
        let res = Ok(());
        self.record_gbt_result(&res);
        res
    }

    type FinalizeBlockTemplateError = error::FinalizeBlockTemplate;

    /// Appends each pending P2MR spend to the template's suffix txs, filling the
    /// weight reserved in [`Self::initial_block_template`]. These are mined via
    /// `submitblock` even though stock Core never relayed them.
    async fn finalize_block_template<const COINBASE_TXN: bool>(
        &self,
        parent_block_hash: &BlockHash,
        coinbase_txn_wit: BoolWit<COINBASE_TXN>,
        template: &mut FilledBlockTemplate<COINBASE_TXN>,
    ) -> Result<(), Self::FinalizeBlockTemplateError>
    where
        Bool<COINBASE_TXN>: CoinbaseTxn,
    {
        let _ = (parent_block_hash, coinbase_txn_wit);
        let spends: Vec<(Transaction, Amount)> = {
            let pending = self.inner.pending_p2mr_spends.lock();
            pending.values().cloned().collect()
        };
        let suffix = template.suffix_txs();
        for (tx, fee) in spends {
            suffix.push((tx, fee));
        }
        let res = Ok(());
        self.record_gbt_result(&res);
        res
    }
}
