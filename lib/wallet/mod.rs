use std::{
    collections::HashMap,
    path::Path,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use bdk_chain::ChainPosition;
use bdk_electrum::{
    BdkElectrumClient,
    electrum_client::{self, ElectrumApi},
};
use bdk_esplora::esplora_client;
use bdk_wallet::{
    self, KeychainKind,
    keys::{DerivableKey as _, ExtendedKey, bip39::Mnemonic},
};
use bitcoin::{Amount, BlockHash, Network, Transaction, hashes::Hash as _, script::PushBytesBuf};
use bitcoin_jsonrpsee::{
    client::{GetRawTransactionClient, GetRawTransactionVerbose, MainClient as _},
    jsonrpsee::http_client::HttpClient,
};
use either::Either;
use futures::{FutureExt, TryFutureExt};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    block_producer::BlockProducer,
    cli::{Config, WalletConfig, WalletSyncSource},
    convert,
    errors::ErrorChain,
    types::BDKWalletTransaction,
    validator::Validator,
    wallet::{
        error::WalletInitialization,
        mnemonic::{EncryptedMnemonic, new_mnemonic},
        seed_store::{Seed, SeedStore},
        util::{RwLockReadGuardSome, RwLockUpgradableReadGuardSome, RwLockWriteGuardSome},
    },
};

mod cusf_block_producer;
pub mod error;
pub mod mnemonic;
pub mod p2mr_store;
mod seed_store;
mod sync;
mod thread_safe_connection;
mod util;

pub(crate) type Persistence = thread_safe_connection::ThreadSafeConnection;
type BdkWallet = bdk_wallet::PersistedWallet<Persistence>;

type ElectrumClient = BdkElectrumClient<bdk_electrum::electrum_client::Client>;
type EsploraClient = bdk_esplora::esplora_client::AsyncClient;

/// A confirmed P2MR UTXO known to the enforcer, with whether the wallet can
/// spend it. Returned by [`Wallet::list_p2mr_outputs`].
#[derive(Clone, Debug)]
pub struct P2mrOutput {
    pub outpoint: bitcoin::OutPoint,
    pub txout: bitcoin::TxOut,
    pub is_mine: bool,
}

/// Default absolute fee for a P2MR spend when the caller does not specify one.
/// These spends are mined into the enforcer's own block template rather than
/// relayed, so the fee is not economically required — it just needs to be small
/// so partial spends return almost all of the remainder as change.
pub const DEFAULT_P2MR_FEE_SATS: u64 = 1000;

/// Result of [`Wallet::spend_p2mr`]: the spend txid plus, when the spend did not
/// drain the whole output, the freshly minted P2MR change address and its value.
#[derive(Clone, Debug)]
pub struct P2mrSpendOutcome {
    pub txid: bitcoin::Txid,
    /// The change address (a new P2MR address of the input's scheme), if a
    /// change output was created; `None` when the spend was a full drain or the
    /// change was sub-dust and folded into the fee.
    pub change_address: Option<String>,
    /// The change amount in sats (0 when there is no change output).
    pub change_sats: u64,
}

#[non_exhaustive]
enum ChainSourceClient {
    Electrum(Box<ElectrumClient>),
    Esplora(EsploraClient),
}

const fn default_esplora_url(network: Network) -> Option<&'static str> {
    match network {
        // No public default beyond regtest: operators supply their own
        // Esplora endpoint via `--wallet-esplora-url`.
        Network::Regtest => Some("http://localhost:3003"),
        _ => None,
    }
}

const fn default_electrum_host_port(network: Network) -> Option<(&'static str, u16)> {
    match network {
        // No public default beyond regtest: operators supply their own
        // Electrum endpoint via `--wallet-electrum-host`/`--wallet-electrum-port`.
        Network::Regtest =>
        // Default for mempool/electrs
        {
            Some(("127.0.0.1", 60401))
        }
        _ => None,
    }
}

struct WalletInner {
    main_client: HttpClient,
    producer: BlockProducer,
    // Unlocked, ready-to-go wallet: Some
    // Locked wallet: None
    bitcoin_wallet: async_lock::RwLock<Option<BdkWallet>>,
    /// Persistence for the BDK wallet.
    ///
    /// Lock order: when both are needed, take `bitcoin_wallet` before
    /// `bdk_db`
    bdk_db: tokio::sync::Mutex<Persistence>,
    seed_store: SeedStore,
    p2mr_store: p2mr_store::P2mrStore,
    chain_source_client: Option<ChainSourceClient>,
    last_sync: async_lock::RwLock<Option<SystemTime>>,
}

impl WalletInner {
    fn validator(&self) -> &Validator {
        self.producer.validator()
    }
}

impl WalletInner {
    async fn init_esplora_client(
        config: &WalletConfig,
        network: Network,
    ) -> Result<EsploraClient, error::InitEsploraClient> {
        let esplora_url = match config.esplora_url.as_ref() {
            Some(url) => url,
            None => {
                let default_url = default_esplora_url(network)
                    .ok_or(error::InitEsploraClient::MissingUrl { network })?;
                &url::Url::parse(default_url)?
            }
        };

        tracing::info!(esplora_url = %esplora_url, "creating esplora client");

        // URLs with a port number at the end get a `/` when turned back into a string, for
        // some reason. The Esplora library doesn't like that! Remove it.
        let client = esplora_client::Builder::new(esplora_url.as_str().trim_end_matches("/"))
            .build_async()
            .map_err(error::InitEsploraClient::BuildEsploraClient)?;

        let height = client
            .get_height()
            .await
            .map_err(error::InitEsploraClient::EsploraClientHeight)?;

        tracing::info!(height = height, "esplora client initialized");
        Ok(client)
    }

    /// Initialize electrum client
    fn init_electrum_client(
        config: &WalletConfig,
        network: Network,
    ) -> Result<ElectrumClient, error::InitElectrumClient> {
        let (electrum_host, electrum_port) =
            match (config.electrum_host.as_deref(), config.electrum_port) {
                (Some(host), Some(port)) => (host, port),
                (host, port) => {
                    let (default_host, default_port) = default_electrum_host_port(network)
                        .ok_or(error::InitElectrumClient::MissingHostPort { network })?;
                    (host.unwrap_or(default_host), port.unwrap_or(default_port))
                }
            };
        let electrum_url = format!("{electrum_host}:{electrum_port}");

        tracing::debug!(%electrum_url, "creating electrum client");
        // Apply a reasonably short timeout to prevent the wallet from hanging
        let timeout = std::time::Duration::from_secs(5);
        let config = electrum_client::ConfigBuilder::new()
            .timeout(Some(timeout))
            .build();
        let electrum_client = electrum_client::Client::from_config(&electrum_url, config)
            .map_err(error::InitElectrumClient::CreateElectrumClient)?;
        let header = electrum_client
            .block_header(0)
            .map_err(error::InitElectrumClient::GetInitialBlockHeader)?;
        // Verify the Electrum server is on the same chain as we are.
        if header.block_hash().as_byte_array() != network.chain_hash().as_bytes() {
            return Err(error::InitElectrumClient::ChainMismatch {
                electrum_block_hash: header.block_hash(),
                wallet_chain_hash: network.chain_hash(),
            });
        }
        Ok(BdkElectrumClient::new(electrum_client))
    }

    async fn init_chain_source_client(
        config: &WalletConfig,
        network: Network,
    ) -> Result<Option<ChainSourceClient>, error::InitChainSourceClient> {
        if config.sync_source == WalletSyncSource::Disabled {
            return Ok(None);
        }
        // The sync backend (electrs / esplora) may not be reachable yet when the
        // enforcer starts -- e.g. a freshly bootstrapped network where electrs is
        // still coming up. Rather than aborting startup, retry transient
        // connection failures with capped backoff, mirroring how we wait for
        // Bitcoin Core to become ready. Config and chain-mismatch errors are not
        // transient and fail immediately.
        const INITIAL_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500);
        const MAX_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(10);
        let mut retry_delay = INITIAL_RETRY_DELAY;
        loop {
            let result = match config.sync_source {
                WalletSyncSource::Electrum => Self::init_electrum_client(config, network)
                    .map(|client| ChainSourceClient::Electrum(Box::new(client)))
                    .map_err(error::InitChainSourceClient::from),
                WalletSyncSource::Esplora => Self::init_esplora_client(config, network)
                    .await
                    .map(ChainSourceClient::Esplora)
                    .map_err(error::InitChainSourceClient::from),
                WalletSyncSource::Disabled => unreachable!("handled above"),
            };
            match result {
                Ok(client) => return Ok(Some(client)),
                Err(err) if err.is_transient() => {
                    tracing::warn!(
                        %err,
                        "wallet sync backend not ready, retrying in {retry_delay:?}",
                    );
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = (retry_delay * 2).min(MAX_RETRY_DELAY);
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn initialize_wallet_from_mnemonic(
        mnemonic: &Mnemonic,
        network: bdk_wallet::bitcoin::Network,
        wallet_database: &mut Persistence,
    ) -> Result<BdkWallet, error::InitWalletFromMnemonic> {
        let extended_key: ExtendedKey = mnemonic.clone().into_extended_key()?;

        let xpriv = extended_key
            .into_xprv(network.into())
            .ok_or(error::InitWalletFromMnemonic::DeriveXpriv)?;

        // Create a BDK wallet structure using BIP 84 descriptor ("m/84h/1h/0h/0" and "m/84h/1h/0h/1")
        let external_desc = format!("wpkh({xpriv}/84'/1'/0'/0/*)");
        let internal_desc = format!("wpkh({xpriv}/84'/1'/0'/1/*)");

        tracing::debug!("Attempting load of existing BDK wallet");
        let bitcoin_wallet = bdk_wallet::Wallet::load()
            .descriptor(KeychainKind::External, Some(external_desc.clone()))
            .descriptor(KeychainKind::Internal, Some(internal_desc.clone()))
            .extract_keys()
            .check_network(network)
            .load_wallet_async(wallet_database)
            .await?;

        let bitcoin_wallet = match bitcoin_wallet {
            Some(wallet) => {
                tracing::info!("Loaded existing BDK wallet");
                wallet
            }

            None => {
                tracing::info!("Creating new BDK wallet");

                bdk_wallet::Wallet::create(external_desc, internal_desc)
                    .network(network)
                    .create_wallet_async(wallet_database)
                    .await?
            }
        };

        Ok(bitcoin_wallet)
    }

    async fn new(
        data_dir: &Path,
        config: &Config,
        main_client: HttpClient,
        producer: BlockProducer,
    ) -> Result<Self, error::InitWallet> {
        let network = {
            let validator_network = producer.validator().network();
            bdk_wallet::bitcoin::Network::from_str(validator_network.to_string().as_str())?
        };
        if network == bdk_wallet::bitcoin::Network::Signet && producer.signet_challenge().is_none()
        {
            return Err(error::InitWallet::NoSignetChallengeFound);
        }

        let database_path = data_dir.join("wallet.sqlite.db");

        tracing::info!(
            data_dir = %data_dir.display(),
            database_path = %database_path.display(),
            "Instantiating {} wallet",
            network,
        );

        let mut wallet_database = thread_safe_connection::ThreadSafeConnection::open(database_path)
            .await
            .map_err(error::InitWallet::OpenConnection)?;

        let chain_source_client =
            Self::init_chain_source_client(&config.wallet_opts, network).await?;

        // If we:
        // 1. Already have an initialized wallet
        // 2. It's plaintext
        //
        // We can just go ahead and unlock the wallet right away.
        let seed_store = SeedStore::new(data_dir)?;
        let p2mr_store = p2mr_store::P2mrStore::new(data_dir);

        let bitcoin_wallet = match seed_store.read_mnemonic().await? {
            Some(Either::Left(mnemonic)) => {
                tracing::debug!("found plaintext mnemonic, going straight to initialization");
                let initialized = WalletInner::initialize_wallet_from_mnemonic(
                    &mnemonic,
                    network,
                    &mut wallet_database,
                )
                .await?;

                Some(initialized)
            }
            _ => None,
        };

        tracing::debug!(
            message = "wallet inner: wired together components",
            wallet_initialized = bitcoin_wallet.is_some()
        );

        Ok(Self {
            main_client,
            producer,
            bitcoin_wallet: async_lock::RwLock::new(bitcoin_wallet),
            bdk_db: tokio::sync::Mutex::new(wallet_database),
            seed_store,
            p2mr_store,
            chain_source_client,
            last_sync: async_lock::RwLock::new(None),
        })
    }

    /// Warn if lock takes this long to acquire
    const LOCK_WARN_DURATION: Duration = Duration::from_secs(1);

    async fn read_wallet(&self) -> Result<RwLockReadGuardSome<'_, BdkWallet>, error::NotUnlocked> {
        use futures::future::{Either, select};
        tracing::trace!("wallet: acquiring read lock");
        let read_guard = match select(
            self.bitcoin_wallet.read().boxed(),
            tokio::time::sleep(Self::LOCK_WARN_DURATION).boxed(),
        )
        .await
        {
            Either::Left((read_guard, _sleep)) => read_guard,
            Either::Right(((), acquiring_read_lock)) => {
                tracing::warn!(
                    "wallet: waiting over {} to acquire read lock",
                    jiff::SignedDuration::try_from(Self::LOCK_WARN_DURATION).unwrap(),
                );
                acquiring_read_lock.await
            }
        };
        RwLockReadGuardSome::new(read_guard).ok_or(error::NotUnlocked)
    }

    /// Obtain an upgradable read lock on the inner wallet
    async fn read_wallet_upgradable(
        &self,
    ) -> Result<RwLockUpgradableReadGuardSome<'_, BdkWallet>, error::NotUnlocked> {
        use futures::future::{Either, select};
        tracing::trace!("wallet: acquiring upgradable read lock");
        let read_guard = match select(
            self.bitcoin_wallet.upgradable_read().boxed(),
            tokio::time::sleep(Self::LOCK_WARN_DURATION).boxed(),
        )
        .await
        {
            Either::Left((read_guard, _sleep)) => read_guard,
            Either::Right(((), acquiring_read_lock)) => {
                tracing::warn!(
                    "waiting over {} to acquire read lock",
                    jiff::SignedDuration::try_from(Self::LOCK_WARN_DURATION).unwrap(),
                );
                acquiring_read_lock.await
            }
        };
        RwLockUpgradableReadGuardSome::new(read_guard).ok_or(error::NotUnlocked)
    }

    async fn write_wallet(
        &self,
    ) -> Result<RwLockWriteGuardSome<'_, BdkWallet>, error::NotUnlocked> {
        use futures::future::{Either, select};
        let start = SystemTime::now();
        let span = tracing::span!(tracing::Level::TRACE, "acquire_write_lock");
        let _guard = span.enter();
        tracing::trace!("acquiring write lock");
        let write_guard = match select(
            self.bitcoin_wallet.write().boxed(),
            tokio::time::sleep(Self::LOCK_WARN_DURATION).boxed(),
        )
        .await
        {
            Either::Left((write_guard, _sleep)) => write_guard,
            Either::Right(((), acquiring_write_lock)) => {
                tracing::warn!(
                    "waiting over {} to acquire write lock",
                    jiff::SignedDuration::try_from(Self::LOCK_WARN_DURATION).unwrap()
                );
                acquiring_write_lock.await
            }
        };
        tracing::trace!(
            "wallet: acquired write lock successfully in {:?}",
            start.elapsed().unwrap_or_default()
        );
        RwLockWriteGuardSome::new(write_guard).ok_or(error::NotUnlocked)
    }

    pub async fn create_new_wallet(
        &self,
        mnemonic: Option<Mnemonic>,
        password: Option<&str>,
    ) -> Result<(), error::CreateNewWallet> {
        let (mnemonic, generated) = match mnemonic {
            Some(mnemonic) => (mnemonic, false),
            None => {
                tracing::info!("create new wallet: no mnemonic provided, generating fresh");
                (new_mnemonic()?, true)
            }
        };

        let birthday_height = if generated {
            let info = self
                .main_client
                .get_blockchain_info()
                .await
                .map_err(|err| {
                    error::CreateNewWallet::FetchBirthdayHeight(error::BitcoinCoreRPC {
                        method: "getblockchaininfo".to_owned(),
                        error: err,
                    })
                })?;
            Some(info.blocks)
        } else {
            None
        };

        match password {
            Some(password) => {
                tracing::info!("create new wallet: persisting encrypted mnemonic");
                let encrypted = EncryptedMnemonic::encrypt(&mnemonic, password)?;
                self.seed_store
                    .insert_seed(Seed::Encrypted(&encrypted), birthday_height)
                    .await?;
            }
            None => {
                tracing::info!(
                    "create new wallet: no password provided, persisting plaintext mnemonic"
                );
                self.seed_store
                    .insert_seed(Seed::Plaintext(&mnemonic), birthday_height)
                    .await?;
            }
        }

        let mut database = self.bdk_db.lock().await;
        let network = self.validator().network();
        let wallet =
            WalletInner::initialize_wallet_from_mnemonic(&mnemonic, network, &mut database).await?;
        drop(database);

        let mut write_guard = self.bitcoin_wallet.write().await;
        *write_guard = Some(wallet);
        drop(write_guard);
        Ok(())
    }

    pub async fn unlock_existing_wallet(
        &self,
        password: &str,
    ) -> Result<(), error::UnlockExistingWallet> {
        if self.bitcoin_wallet.read().await.is_some() {
            return Err(WalletInitialization::AlreadyUnlocked.into());
        }

        // Read the mnemonic from the database.
        let read = self.seed_store.read_mnemonic().await?;

        tracing::debug!("unlock wallet: read from DB");

        // Verify that it is encrypted!
        let encrypted = match read {
            None => {
                return Err(WalletInitialization::NotFound.into());
            }
            // Plaintext!
            Some(Either::Left(_)) => {
                return Err(error::UnlockExistingWallet::NotEncrypted);
            }
            Some(Either::Right(encrypted)) => encrypted,
        };

        tracing::debug!("unlock wallet: decrypting mnemonic");

        let mnemonic = encrypted.decrypt(password).map_err(|err| {
            tracing::error!("failed to decrypt mnemonic: {:#}", ErrorChain::new(&err));
            WalletInitialization::InvalidPassword
        })?;

        let mut database = self.bdk_db.lock().await;
        let network = self.validator().network();

        tracing::debug!("unlock wallet: initializing BDK wallet struct");
        let wallet =
            WalletInner::initialize_wallet_from_mnemonic(&mnemonic, network, &mut database).await?;
        drop(database);

        let mut write_guard = self.bitcoin_wallet.write().await;
        *write_guard = Some(wallet);
        drop(write_guard);

        tracing::info!("unlock wallet: initialized wallet");
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct CreateTransactionParams {
    /// Optional fee policy to use for the transaction
    pub fee_policy: Option<crate::types::FeePolicy>,
    /// Optional OP_RETURN message to include in the transaction
    pub op_return_message: Option<Vec<u8>>,
    /// Optional UTXOs that must be included in the transaction
    pub required_utxos: Vec<bdk_wallet::bitcoin::OutPoint>,
    // If set, sends ALL UTXOs in the wallet to this address.
    // Incompatible with `required_utxos`.
    pub drain_wallet_to: Option<bdk_wallet::bitcoin::Address>,
}

pub struct WalletInfo {
    // Public (i.e. without private keys) descriptors for the wallet
    pub keychain_descriptors: std::collections::HashMap<
        bdk_wallet::KeychainKind,
        bdk_wallet::descriptor::ExtendedDescriptor,
    >,
    pub network: bdk_wallet::bitcoin::Network,
    pub transaction_count: usize,
    pub unspent_output_count: usize,
    pub tip: (BlockHash, u32),
}

/// Cheap to clone, since it uses Arc internally
#[derive(Clone)]
pub struct Wallet {
    inner: Arc<WalletInner>,
}

impl Wallet {
    pub async fn new(
        data_dir: &Path,
        config: &Config,
        main_client: HttpClient,
        producer: BlockProducer,
    ) -> Result<Self, error::InitWallet> {
        let inner = Arc::new(WalletInner::new(data_dir, config, main_client, producer).await?);
        Ok(Self { inner })
    }

    /// The keyless block producer underneath this wallet.
    pub fn producer(&self) -> &BlockProducer {
        &self.inner.producer
    }

    pub async fn sync_task(&self, cancel: CancellationToken) -> Result<(), miette::Report> {
        const SYNC_INTERVAL: Duration = Duration::from_secs(15);
        tracing::debug!(
            interval = %jiff::SignedDuration::try_from(SYNC_INTERVAL).unwrap(),
            "wallet sync task: starting"
        );

        // Needed so we can use `tokio::select!`
        let shutdown_signal = cancel.cancelled();
        futures::pin_mut!(shutdown_signal);

        let mut sleep = tokio::time::sleep(SYNC_INTERVAL).boxed();
        loop {
            tokio::select! {
                biased;  // Prioritize shutdown

                _ = &mut shutdown_signal => {
                    tracing::info!("shutting down sync task");
                    return Ok(());
                }
                _ = &mut sleep => {
                    let tick = Uuid::new_v4().simple();
                    let span = tracing::span!(tracing::Level::DEBUG,
                        "wallet_sync",
                        %tick,
                    );
                    let guard = span.enter();
                    if self.inner.last_sync.read().await.is_none() {
                        // Initial sync is incomplete, nothing to do
                        tracing::debug!(
                            "waiting for initial wallet sync to complete"
                        );
                    } else if let Err(err) = self.inner.sync().await {
                        tracing::error!("wallet sync error: {:#}", ErrorChain::new(&err));
                    }
                    drop(guard);
                    sleep = tokio::time::sleep(SYNC_INTERVAL).boxed();
                }
            }
        }
    }

    pub(crate) fn parse_checked_address(
        &self,
        address: &str,
    ) -> Result<bitcoin::Address, connectrpc::ConnectError> {
        let network = self.validator().network();
        let address = bdk_wallet::bitcoin::Address::from_str(address).map_err(|err| {
            connectrpc::ConnectError::invalid_argument(format!("invalid bitcoin address: {err:#}"))
        })?;

        let address = address.require_network(network).map_err(|_| {
            connectrpc::ConnectError::invalid_argument(format!(
                "bitcoin address is not valid for network `{network}`",
            ))
        })?;

        Ok(address)
    }

    pub async fn full_scan(&self) -> miette::Result<BlockHash, error::FullScan> {
        self.inner.full_scan().await
    }

    pub async fn is_initialized(&self) -> bool {
        self.inner.bitcoin_wallet.read().await.is_some()
    }

    pub fn validator(&self) -> &Validator {
        self.inner.validator()
    }

    fn create_op_return_output<Msg>(
        msg: Msg,
    ) -> Result<bdk_wallet::bitcoin::TxOut, <bitcoin::script::PushBytesBuf as TryFrom<Msg>>::Error>
    where
        PushBytesBuf: TryFrom<Msg>,
    {
        let op_return_txout = bitcoin::TxOut {
            script_pubkey: bitcoin::ScriptBuf::new_op_return(PushBytesBuf::try_from(msg)?),
            value: bitcoin::Amount::ZERO,
        };
        Ok(bdk_wallet::bitcoin::TxOut {
            script_pubkey: bdk_wallet::bitcoin::ScriptBuf::from_bytes(
                op_return_txout.script_pubkey.to_bytes(),
            ),
            value: op_return_txout.value,
        })
    }

    pub async fn get_wallet_balance(
        &self,
    ) -> Result<(bdk_wallet::Balance, bool), error::GetWalletBalance> {
        let has_synced = self.inner.last_sync.read().await.is_some();

        let balance = self.inner.read_wallet().await?.balance();

        Ok((balance, has_synced))
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "false positive for `bitcoin_wallet`"
    )]
    #[instrument(skip_all)]
    pub async fn list_wallet_transactions(
        &self,
    ) -> Result<Vec<BDKWalletTransaction>, error::ListWalletTransactions> {
        // Massage the wallet data into a format that we can use to calculate fees, etc.
        let wallet_data = {
            let wallet_read = self.inner.read_wallet().await?;
            let transactions = wallet_read.transactions();

            transactions
                .into_iter()
                .map(|tx| {
                    let txid = tx.tx_node.txid;
                    let chain_position = tx.chain_position;
                    let tx = tx.tx_node.tx.clone();

                    let output_ownership: Vec<_> = tx
                        .output
                        .iter()
                        .map(|output| {
                            (
                                output.value,
                                wallet_read.is_mine(output.script_pubkey.clone()),
                            )
                        })
                        .collect();

                    // Just collect the inputs - we'll get their values using getrawtransaction later
                    let inputs = tx.input.clone();

                    (txid, tx, chain_position, output_ownership, inputs)
                })
                .collect::<Vec<_>>()
        };

        // Calculate fees, received, and sent amounts
        let mut txs = Vec::new();
        for (txid, tx, chain_position, output_ownership, inputs) in wallet_data {
            let mut input_value = Amount::ZERO;
            let mut output_value = Amount::ZERO;
            let mut received = Amount::ZERO;
            let mut sent = Amount::ZERO;

            // Calculate output value and received amount
            for (value, is_mine) in output_ownership {
                output_value += value;
                if is_mine {
                    received += value;
                }
            }

            // Get input values using getrawtransaction
            for input in inputs {
                // Coinbase transactions have an empty prev output txid, which we'll be unable to fetch
                if input.previous_output.txid == bitcoin::Txid::all_zeros() {
                    continue;
                }

                let transaction_hex = self
                    .inner
                    .main_client
                    // TODO: get rid of this. It's kind of absurd that we're calling out to getrawtransaction for every input.
                    // Both from a performance point of view, as well as requiring txindex. Would be better to somehow
                    // persist the relevant values in the wallet DB
                    .get_raw_transaction(
                        input.previous_output.txid,
                        GetRawTransactionVerbose::<false>,
                        None,
                    )
                    .await
                    .map_err(|err| error::ListWalletTransactions::FetchTransaction {
                        txid: input.previous_output.txid,
                        source: error::BitcoinCoreRPC {
                            method: "getrawtransaction".to_string(),
                            error: err,
                        },
                    })?;

                let prev_output =
                    bitcoin::consensus::encode::deserialize_hex::<Transaction>(&transaction_hex)?;

                let value = prev_output.output[input.previous_output.vout as usize].value;
                if self.inner.read_wallet().await?.is_mine(
                    prev_output.output[input.previous_output.vout as usize]
                        .script_pubkey
                        .clone(),
                ) {
                    sent += value;
                }
                input_value += value;
            }

            let fee = input_value
                .checked_sub(output_value)
                .unwrap_or(Amount::ZERO);
            // Calculate net wallet change (excluding fee)
            // We need to handle received and sent separately since Amount can't be negative
            let (final_received, final_sent) = if received >= sent {
                (received - sent, Amount::from_sat(0)) // Net gain to wallet
            } else {
                (Amount::from_sat(0), sent - received - fee) // Net loss from wallet
            };

            txs.push(BDKWalletTransaction {
                txid,
                tx,
                chain_position,
                fee,
                received: final_received,
                sent: final_sent,
            });
        }

        // Make sure that the transaction list is in chronological order.
        txs.sort_by(|a, b| match (a.chain_position, b.chain_position) {
            (
                ChainPosition::Confirmed {
                    anchor: a_anchor, ..
                },
                ChainPosition::Confirmed {
                    anchor: b_anchor, ..
                },
            ) => a_anchor.confirmation_time.cmp(&b_anchor.confirmation_time),
            (
                ChainPosition::Confirmed { anchor, .. },
                ChainPosition::Unconfirmed {
                    last_seen: Some(last_seen),
                    first_seen: _,
                },
            ) => anchor.confirmation_time.cmp(&last_seen),
            (
                ChainPosition::Unconfirmed {
                    last_seen: Some(last_seen),
                    first_seen: _,
                },
                ChainPosition::Confirmed { anchor, .. },
            ) => last_seen.cmp(&anchor.confirmation_time),
            (
                ChainPosition::Unconfirmed {
                    last_seen: Some(a_last_seen),
                    first_seen: _,
                },
                ChainPosition::Unconfirmed {
                    last_seen: Some(b_last_seen),
                    first_seen: _,
                },
            ) => a_last_seen.cmp(&b_last_seen),

            // Fallback to comparing TXIDs
            (_, _) => a.txid.cmp(&b.txid),
        });
        Ok(txs)
    }

    async fn create_send_psbt(
        &self,
        destinations: HashMap<bitcoin::Address, Amount>,
        params: CreateTransactionParams,
    ) -> Result<bdk_wallet::bitcoin::psbt::Psbt, error::CreateSendPsbt> {
        let mut timestamp = Instant::now();
        let psbt = {
            let mut wallet_write = self.inner.write_wallet().await?;
            tokio::task::block_in_place(|| {
                wallet_write.with_mut(|wallet| {
                    let mut builder = wallet.build_tx();

                    if let Some(op_return_message) = params.op_return_message {
                        let op_return_output = Self::create_op_return_output(op_return_message)?;
                        builder
                            .add_recipient(op_return_output.script_pubkey, op_return_output.value);

                        tracing::debug!("Added OP_RETURN output in {:?}", timestamp.elapsed());
                        timestamp = Instant::now();
                    }

                    let destinations_len = destinations.len();

                    // Add outputs for each destination address
                    for (address, value) in destinations {
                        builder.add_recipient(address.script_pubkey(), value);
                    }

                    tracing::debug!(
                        "Added {} destinations in {:?}",
                        destinations_len,
                        timestamp.elapsed()
                    );
                    timestamp = Instant::now();

                    if let Some(drain_wallet_to) = params.drain_wallet_to {
                        tracing::debug!("Draining wallet to {}", drain_wallet_to);
                        builder
                            .drain_to(drain_wallet_to.script_pubkey())
                            .drain_wallet();
                    }

                    if !params.required_utxos.is_empty() {
                        builder
                            // TODO: this does not work at all for wallets past a certain scale....
                            // 25s pr. UTXO for a wallet with 40k UTXOs in total
                            .add_utxos(&params.required_utxos)
                            .map_err(|err| match err {
                                bdk_wallet::tx_builder::AddUtxoError::UnknownUtxo(outpoint) => {
                                    error::CreateSendPsbt::UnknownUTXO(outpoint)
                                }
                            })?;

                        builder.manually_selected_only();

                        tracing::debug!(
                            "Added {} required UTXOs in {:?}",
                            params.required_utxos.len(),
                            timestamp.elapsed()
                        );
                        timestamp = Instant::now();
                    }

                    match params.fee_policy {
                        Some(crate::types::FeePolicy::Absolute(fee)) => {
                            builder.fee_absolute(fee);
                        }
                        Some(crate::types::FeePolicy::Rate(rate)) => {
                            builder.fee_rate(rate);
                        }
                        None => (),
                    }

                    tracing::debug!("Set fee policy in {:?}", timestamp.elapsed());
                    timestamp = Instant::now();

                    builder
                        .finish()
                        .inspect(|_| {
                            tracing::debug!(
                                "Finished transaction builder in {:?}",
                                timestamp.elapsed()
                            );
                        })
                        .map_err(error::CreateSendPsbt::CreateTx)
                })
            })?
        };

        Ok(psbt)
    }

    /// Creates a transaction, sends it, and returns the TXID.
    pub async fn send_wallet_transaction(
        &self,
        destinations: HashMap<bdk_wallet::bitcoin::Address, Amount>,
        params: CreateTransactionParams,
    ) -> Result<bitcoin::Txid, error::SendWalletTransaction> {
        tracing::debug!(
            destinations = destinations.len(),
            required_utxos = params.required_utxos.len(),
            drain_wallet = params.drain_wallet_to.is_some(),
            "Sending wallet transaction",
        );
        let mut timestamp = Instant::now();
        let psbt = self.create_send_psbt(destinations, params).await?;

        tracing::debug!("Created send PSBT in {:?}", timestamp.elapsed());
        timestamp = Instant::now();

        let tx = self.sign_transaction(psbt).await?;
        let txid = tx.compute_txid();

        tracing::info!(
            %txid,
            "Signed send transaction in {:?}, {} bytes",
            timestamp.elapsed(),
            {
                let tx_bytes = bdk_wallet::bitcoin::consensus::serialize(&tx);
                tx_bytes.len()
            },
        );
        timestamp = Instant::now();

        if crate::rpc_client::broadcast_transaction(&self.inner.main_client, &tx)
            .await
            .map_err(error::SendWalletTransaction::BroadcastTx)?
            .is_none()
        {
            let err = error::SendWalletTransaction::NonstandardTxNotSupported;
            tracing::error!(%txid, "{:#}", ErrorChain::new(&err));
            return Err(err);
        }
        tracing::info!(%txid, "Broadcast send transaction in {:?}", timestamp.elapsed());

        // Apply the unconfirmed transaction to the wallet
        let last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();

        let applied_changes = {
            // Lock order: wallet before `bdk_db`, see the `bdk_db` field docs
            let mut wallet_write = self.inner.write_wallet().await?;
            let mut bdk_db_lock = self.inner.bdk_db.lock().await;
            wallet_write
                .with_mut(|wallet| {
                    wallet.apply_unconfirmed_txs(vec![(tx, last_seen.as_secs())]);
                    wallet.persist_async(&mut bdk_db_lock)
                })
                .await?
        };

        // We used to do a sanity check here that changes were applied. However,
        // `applied_changes` may be false if the transaction was already
        // applied to the wallet by the mempool `accept_tx` hook, which runs in
        // a background task once bitcoind accepts the broadcast.
        if applied_changes {
            tracing::debug!(%txid, "Applied unconfirmed transaction to wallet");
        } else {
            tracing::debug!(
                %txid,
                "Unconfirmed transaction already applied to wallet (likely by mempool accept_tx)"
            );
        }

        Ok(convert::bdk_txid_to_bitcoin_txid(txid))
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "false positive for `bitcoin_wallet`"
    )]
    #[instrument(skip_all)]
    pub async fn get_utxos(&self) -> Result<Vec<bdk_wallet::LocalOutput>, error::NotUnlocked> {
        let wallet_read = self.inner.read_wallet().await?;
        let utxos = wallet_read.list_unspent().collect::<Vec<_>>();

        Ok(utxos)
    }

    async fn sign_transaction(
        &self,
        mut psbt: bdk_wallet::bitcoin::psbt::Psbt,
    ) -> Result<bdk_wallet::bitcoin::Transaction, error::WalletSignTransaction> {
        let mut timestamp = Instant::now();

        if !self
            .inner
            .read_wallet()
            .await
            .map_err(error::WalletSignTransaction::NotUnlocked)?
            .sign(&mut psbt, bdk_wallet::SignOptions::default())
            .map_err(error::WalletSignTransaction::SignerError)?
        {
            return Err(error::WalletSignTransaction::UnableToSign);
        }

        tracing::debug!("Signed transaction in {:?}", timestamp.elapsed());
        timestamp = Instant::now();

        let tx = psbt
            .extract_tx()
            .map_err(error::WalletSignTransaction::ExtractTx)?;

        tracing::debug!("Extracted transaction in {:?}", timestamp.elapsed());
        Ok(tx)
    }

    pub async fn get_wallet_info(&self) -> Result<WalletInfo, error::NotUnlocked> {
        let w = self.inner.read_wallet().await?;
        let mut keychain_descriptors = std::collections::HashMap::new();
        for (kind, _) in w.keychains() {
            keychain_descriptors.insert(kind, w.public_descriptor(kind).clone());
        }

        let tip = w.local_chain().tip();

        Ok(WalletInfo {
            keychain_descriptors,
            network: w.network(),
            transaction_count: w.transactions().count(),
            unspent_output_count: w.list_unspent().count(),
            tip: (tip.hash(), tip.height()),
        })
    }

    #[expect(clippy::significant_drop_tightening)]
    pub async fn get_new_address(
        &self,
    ) -> Result<bdk_wallet::bitcoin::Address, error::GetNewAddress> {
        // Using next_unused_address here means that we get a new address
        // when funds are received. Without this we'd need to take care not
        // to cross the wallet scan gap.
        let mut wallet_write = self.inner.write_wallet().await?;

        let mut bdk_db_lock = self.inner.bdk_db.lock().await;
        let address = wallet_write
            .with_mut(|wallet| {
                let info = wallet.next_unused_address(bdk_wallet::KeychainKind::External);
                wallet
                    .persist_async(&mut bdk_db_lock)
                    .map_ok(|_: bool| info.address)
            })
            .await?;
        Ok(address)
    }

    // ─── BIP 360 (P2MR) wallet lifecycle ───────────────────────────────────

    /// Create a new P2MR address for `scheme`, persisting its key material.
    /// Returns the record (scriptPubKey + the bech32m address via
    /// [`p2mr_store::P2mrAddressRecord::address`]).
    pub async fn create_p2mr_address(
        &self,
        scheme: p2mr_store::P2mrScheme,
    ) -> Result<p2mr_store::P2mrAddressRecord, error::P2mrStore> {
        self.inner.p2mr_store.create(scheme).await
    }

    /// The confirmed P2MR UTXOs known to the enforcer, each flagged with whether
    /// this wallet holds the key to spend it.
    pub fn list_p2mr_outputs(&self) -> Result<Vec<P2mrOutput>, error::ListP2mrOutputs> {
        let utxos = self.inner.validator().p2mr_utxos()?;
        let mut out = Vec::with_capacity(utxos.len());
        for (outpoint, txout) in utxos {
            let is_mine = self
                .inner
                .p2mr_store
                .get_by_spk(txout.script_pubkey.as_script())?
                .is_some();
            out.push(P2mrOutput {
                outpoint,
                txout,
                is_mine,
            });
        }
        out.sort_by_key(|o| (o.outpoint.txid, o.outpoint.vout));
        Ok(out)
    }

    /// Spend a confirmed P2MR UTXO the wallet controls, paying `amount` to
    /// `destination`. Because stock Core will not relay the nonstandard spend,
    /// it is queued in the block producer and mined via the enforcer's own
    /// `getblocktemplate` + `submitblock`.
    ///
    /// `fee_sats` is the absolute fee; if `None`, [`DEFAULT_P2MR_FEE_SATS`] is
    /// used. The remainder (`prevout_value − amount − fee`) is returned as
    /// **change to a freshly minted P2MR address of the same scheme** — not
    /// burned as fee. Sub-dust change folds back into the fee. The funding UTXO
    /// must be confirmed (present in the enforcer's P2MR UTXO set).
    pub async fn spend_p2mr(
        &self,
        outpoint: bitcoin::OutPoint,
        destination: bitcoin::Address,
        amount: Amount,
        fee_sats: Option<Amount>,
    ) -> Result<P2mrSpendOutcome, error::SpendP2mr> {
        use bdk_wallet::IsDust as _;

        let prevout = self
            .inner
            .validator()
            .get_p2mr_utxo(&outpoint)?
            .ok_or(error::SpendP2mr::UnknownUtxo { outpoint })?;

        let record = self
            .inner
            .p2mr_store
            .get_by_spk(prevout.script_pubkey.as_script())?
            .ok_or_else(|| error::SpendP2mr::NotOurs {
                outpoint,
                script_pubkey: prevout.script_pubkey.clone(),
            })?;

        let prevout_value = prevout.value;
        let dest_spk = destination.script_pubkey();
        if amount.is_dust(&dest_spk) {
            return Err(error::SpendP2mr::AmountBelowDust {
                amount,
                script_pubkey: dest_spk,
            });
        }
        let fee = fee_sats.unwrap_or(Amount::from_sat(DEFAULT_P2MR_FEE_SATS));
        let total = amount
            .checked_add(fee)
            .filter(|total| *total <= prevout_value)
            .ok_or(error::SpendP2mr::FeeExceedsRemainder {
                amount,
                fee,
                prevout_value,
            })?;
        let change = prevout_value - total;

        let mut outputs = vec![bitcoin::TxOut {
            value: amount,
            script_pubkey: dest_spk,
        }];
        let mut change_address = None;
        let mut change_sats = 0;
        let mut actual_fee = fee;

        // A P2MR change output has the same scriptPubKey shape as the prevout we
        // are spending, so gauge the dust threshold against it without minting.
        if change > Amount::ZERO {
            if change.is_dust(&prevout.script_pubkey) {
                // Sub-dust change is not worth an output; fold it into the fee.
                actual_fee = prevout_value - amount;
            } else {
                let change_record = self.inner.p2mr_store.create(record.scheme).await?;
                let addr = change_record.address(self.inner.validator().network())?;
                outputs.push(bitcoin::TxOut {
                    value: change,
                    script_pubkey: change_record.script_pubkey(),
                });
                change_address = Some(addr.to_string());
                change_sats = change.to_sat();
            }
        }

        let tx = record.build_spend(
            outpoint,
            prevout,
            outputs,
            bitcoin::sighash::TapSighashType::Default,
        )?;

        let txid = self.inner.producer.enqueue_p2mr_spend(tx, actual_fee);
        tracing::info!(
            %txid, %outpoint, %actual_fee, %change_sats,
            "queued P2MR spend for block-template injection"
        );
        Ok(P2mrSpendOutcome {
            txid,
            change_address,
            change_sats,
        })
    }

    /// Connect missing blocks to the BDK chain. Retries if we get a 'nested'
    /// alert from BDK, about further missing ancestors.
    async fn connect_missing_block(
        &mut self,
        try_include_height: u32,
    ) -> std::result::Result<(), error::ConnectMissingBlock> {
        use bitcoin_jsonrpsee::{
            MainClient as _,
            client::{GetBlockClient as _, U8Witness},
        };

        struct TryInclude {
            block_height: u32,
            block: Option<bitcoin::Block>,
        }

        // stack of block heights / blocks to connect
        let mut try_includes = vec![TryInclude {
            block_height: try_include_height,
            block: None,
        }];

        while let Some(try_include) = try_includes.last_mut() {
            let TryInclude {
                block_height,
                block,
            } = try_include;
            let block = match block {
                Some(block) => block,
                None => {
                    let block_hash = self
                        .inner
                        .main_client
                        .getblockhash(*block_height as usize)
                        .await
                        .map_err(|err| {
                            error::ConnectMissingBlockInner::GetBlockHash(error::BitcoinCoreRPC {
                                method: "getblockhash".to_string(),
                                error: err,
                            })
                        })?;
                    block.insert(
                        self.inner
                            .main_client
                            .get_block(block_hash, U8Witness::<0>)
                            .await
                            .map_err(|err| {
                                error::ConnectMissingBlockInner::GetBlock(error::BitcoinCoreRPC {
                                    method: "getblock".to_string(),
                                    error: err,
                                })
                            })?
                            .0,
                    )
                }
            };
            let block_hash = block.block_hash();
            let infos = self.inner.validator().get_block_infos(&block_hash, 0)?;
            assert_eq!(infos.len(), 1);
            let (_header_info, block_info) = infos.head;
            tracing::debug!(
                "connecting missing block {} at height {}",
                block_hash,
                block_height,
            );
            match self
                .inner
                .handle_connect_block(block, *block_height, &block_info)
                .await?
            {
                Ok(()) => {
                    tracing::debug!(
                        "connected missing block {} at height {}",
                        block_hash,
                        block_height
                    );
                    try_includes.pop();
                }
                // We can receive 'nested' alerts from BDK, about further missing ancestors. We therefore
                // recurse, but make sure to only do so if the recommended try_include_height is /below/
                // what we just tried. Otherwise we'll just loop forever.
                Err(
                    err @ bdk_wallet::chain::local_chain::CannotConnectError { try_include_height },
                ) => {
                    if try_include_height < *block_height {
                        // BDK's `try_include_height` can skip past the block's
                        // immediate parent, and retrying at the skipped-to height
                        // connects as a no-op without fixing anything, looping
                        // forever. Step down one height at a time instead. The
                        // reported height is only used (above) to check that we're
                        // still making downward progress.
                        let next_height = *block_height - 1;
                        tracing::debug!("adding missing block at height {} to stack", next_height);
                        try_includes.push(TryInclude {
                            block_height: next_height,
                            block: None,
                        });
                    } else {
                        return Err(error::ConnectMissingBlockInner::BdkConnect {
                            block_height: *block_height,
                            source: err,
                        }
                        .into());
                    }
                }
            };
        }

        Ok(())
    }

    pub async fn unlock_existing_wallet(
        &self,
        password: &str,
    ) -> Result<(), error::UnlockExistingWallet> {
        self.inner.unlock_existing_wallet(password).await
    }

    // Creates a new wallet with a given mnemonic and encryption password.
    // Note that the password is NOT a BIP39 passphrase, but is only used to
    // encrypt the mnemonic in storage.
    pub async fn create_wallet(
        &self,
        mnemonic: Option<Mnemonic>,
        password: Option<&str>,
    ) -> Result<(), error::CreateNewWallet> {
        self.inner.create_new_wallet(mnemonic, password).await
    }
}
