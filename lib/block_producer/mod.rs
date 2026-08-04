use std::{collections::HashMap, sync::Arc};

use bitcoin::{BlockHash, Transaction, Txid};
use cusf_enforcer_mempool::{
    cusf_block_producer::{
        CoinbaseTxn, CusfBlockProducer, FilledBlockTemplate, InitialBlockTemplate,
        typewit::const_marker::{Bool, BoolWit},
    },
    cusf_enforcer::{ConnectBlockAction, CusfEnforcer, DisconnectBlockAction, TxAcceptAction},
};
use tracing::instrument;

use crate::{errors::ErrorChain, validator::Validator};

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
            }),
        })
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

    async fn sync_to_tip<Signal>(
        &mut self,
        shutdown_signal: Signal,
        tip_hash: BlockHash,
    ) -> Result<(), Self::SyncError>
    where
        Signal: std::future::Future<Output = ()> + Send,
    {
        self.inner
            .validator
            .clone()
            .sync_to_tip(shutdown_signal, tip_hash)
            .await
    }

    type ConnectBlockError = error::ConnectBlock;

    #[instrument(skip_all, fields(block_hash = %block.block_hash()))]
    async fn connect_block(
        &mut self,
        block: &bitcoin::Block,
    ) -> Result<ConnectBlockAction, Self::ConnectBlockError> {
        let res = self.connect_block_validator(block).await?;
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

    fn accept_tx<TxRef>(
        &mut self,
        tx: &Transaction,
        tx_inputs: &HashMap<Txid, TxRef>,
    ) -> Result<TxAcceptAction, Self::AcceptTxError>
    where
        TxRef: std::borrow::Borrow<Transaction>,
    {
        self.inner.validator.clone().accept_tx(tx, tx_inputs)
    }
}

impl CusfBlockProducer for BlockProducer {
    type InitialBlockTemplateError = error::InitialBlockTemplate;

    /// Called when the RPC server starts producing a block template:
    /// 1. the RPC server (in `cusf_enforcer_mempool`) receives the request,
    /// 2. it fetches the initial block template (this function),
    /// 3. it processes that further and returns it to the client.
    ///
    /// This is the hook for adding rule-set coinbase outputs to the
    /// about-to-be-generated block.
    async fn initial_block_template<const COINBASE_TXN: bool>(
        &self,
        parent_block_hash: &BlockHash,
        coinbase_txn_wit: BoolWit<COINBASE_TXN>,
        template: &mut InitialBlockTemplate<COINBASE_TXN>,
    ) -> Result<(), Self::InitialBlockTemplateError>
    where
        Bool<COINBASE_TXN>: CoinbaseTxn,
    {
        let _ = (parent_block_hash, coinbase_txn_wit, template);
        let res = Ok(());
        self.record_gbt_result(&res);
        res
    }

    type FinalizeBlockTemplateError = error::FinalizeBlockTemplate;

    async fn finalize_block_template<const COINBASE_TXN: bool>(
        &self,
        parent_block_hash: &BlockHash,
        coinbase_txn_wit: BoolWit<COINBASE_TXN>,
        template: &mut FilledBlockTemplate<COINBASE_TXN>,
    ) -> Result<(), Self::FinalizeBlockTemplateError>
    where
        Bool<COINBASE_TXN>: CoinbaseTxn,
    {
        let _ = (parent_block_hash, coinbase_txn_wit, template);
        let res = Ok(());
        self.record_gbt_result(&res);
        res
    }
}
