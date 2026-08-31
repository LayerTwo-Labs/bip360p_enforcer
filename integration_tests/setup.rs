//! Setup for an integration test

use std::{
    borrow::Borrow,
    ffi::OsStr,
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, LazyLock},
};

use anyhow::anyhow;
use bip360p_enforcer_lib::{
    bins::{self, CommandExt as _},
    proto::{
        self,
        mainchain::GetChainTipRequest,
        mainchain_service::{MiningServiceClient, ValidatorServiceClient, WalletServiceClient},
    },
};
use bitcoin::Address;
use connectrpc::client::{ClientConfig, HttpClient};
use futures::channel::mpsc;
use reserve_port::ReservedPort;
use temp_dir::TempDir;
use tokio::{
    net::TcpStream,
    time::{Duration, sleep, timeout},
};

use crate::util::{AbortOnDrop, BinPaths, Bitcoind, Electrs, Enforcer, VarError};

#[derive(strum::Display, Clone, Copy, Debug)]
pub enum Network {
    Regtest,
    Signet,
}

impl From<Network> for bitcoin::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Regtest => Self::Regtest,
            Network::Signet => Self::Signet,
        }
    }
}

// Signet-specific setup
pub struct SignetSetup {
    secret_key: bitcoin::PrivateKey,
    signet_challenge: bitcoin::ScriptBuf,
    signet_challenge_addr: bitcoin::Address,
    signet_magic: bitcoin::p2p::Magic,
}

impl SignetSetup {
    fn new() -> anyhow::Result<Self> {
        let secret_key = bitcoin::PrivateKey::generate(bitcoin::NetworkKind::Test);
        let cpk = bitcoin::CompressedPublicKey::from_private_key(
            &bitcoin::secp256k1::Secp256k1::new(),
            &secret_key,
        )?;
        let signet_challenge = bitcoin::Script::builder()
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .push_slice(cpk.to_bytes())
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
            .into_script();
        let signet_challenge_addr =
            bitcoin::Address::from_script(&cpk.p2wpkh_script_code(), &bitcoin::params::SIGNET)?;
        let signet_magic = bip360p_enforcer_lib::p2p::compute_signet_magic(&signet_challenge);
        tracing::info!(
            signet_challenge = %hex::encode(signet_challenge.as_bytes()),
            %signet_magic,
            mining_address = %signet_challenge_addr,
        );
        Ok(Self {
            secret_key,
            signet_challenge,
            signet_challenge_addr,
            signet_magic,
        })
    }

    /// Initialize bitcoind wallet
    async fn init_bitcoind_wallet(&self, bitcoin_cli: &bins::BitcoinCli) -> anyhow::Result<()> {
        tracing::debug!("Importing secret key");
        let mining_descriptor = {
            use bdk_wallet::miniscript;
            let descriptor = bdk_wallet::descriptor!(wpkh(self.secret_key))?;
            descriptor.0.to_string_with_secret(&descriptor.1)
        };
        let multisig_descriptor = {
            let descriptor = bdk_wallet::descriptor!(bare(multi(1, self.secret_key)))?;
            descriptor.0.to_string_with_secret(&descriptor.1)
        };
        let import_descriptors_output = bitcoin_cli
            .command::<String, _, String, _, _>(
                [],
                "importdescriptors",
                [serde_json::json!([
                    {
                        "desc": mining_descriptor,
                        "timestamp": "now",
                        "active": false,
                    },
                    {
                        "desc": multisig_descriptor,
                        "timestamp": "now",
                        "active": false,
                    },
                ])
                .to_string()],
            )
            .run_utf8()
            .await?;
        let expected_import_descriptors_output = serde_json::json!([
            { "success": true }, { "success": true }
        ]);
        if serde_json::from_str::<serde_json::Value>(&import_descriptors_output)?
            != expected_import_descriptors_output
        {
            anyhow::bail!("Importing descriptors failed: `{import_descriptors_output}`")
        }
        tracing::debug!(
            signet_challenge_addr = %self.signet_challenge_addr,
            "Checking that the signet challenge addr is loaded"
        );
        let getaddressinfo_output = bitcoin_cli
            .command::<String, _, _, _, _>(
                [],
                "getaddressinfo",
                [self.signet_challenge_addr.to_string()],
            )
            .run_utf8()
            .await?;
        tracing::debug!(%getaddressinfo_output);
        Ok(())
    }

    /// Configure signet miner to use enforcer's GBT server
    fn configure_miner(
        signet_miner: &mut bins::SignetMiner,
        out_dir: &TempDir,
        enforcer: &Enforcer,
    ) -> anyhow::Result<()> {
        let gbt_script_file = out_dir.path().join("gbt-script.sh");
        tracing::info!("GBT script: {}", gbt_script_file.display());
        let gbt_script = format!(
            r#"#!/bin/sh
            REQUEST='{{"jsonrpc":"2.0","id":0,"method":"getblocktemplate","params":['$1']}}'
            RESPONSE=$(curl 127.0.0.1:{} --no-progress-meter -H "Content-Type: application/json" --data-binary "${{REQUEST}}")
            RESULT=$(echo "${{RESPONSE}}" | jq '.result')
            echo "${{RESULT}}""#,
            enforcer.serve_rpc_port
        );
        std::fs::write(&gbt_script_file, gbt_script)?;
        cfg_if::cfg_if! {
            if #[cfg(target_family = "unix")] {
                use std::os::unix::fs::PermissionsExt as _;
                let mut perms = std::fs::metadata(&gbt_script_file)?.permissions();
                // Add execute permission (equivalent to chmod +x)
                perms.set_mode(perms.mode() | 0o111);
                std::fs::set_permissions(&gbt_script_file, perms)?;
            }
        }
        signet_miner.coinbasetxn = true;
        signet_miner.getblocktemplate_command = Some(format!("{}", gbt_script_file.display()));
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum MiningMode {
    GenerateBlocks,
    GetBlockTemplate,
}

#[derive(strum::Display, Clone, Copy, Debug)]
pub enum Mode {
    GetBlockTemplate,
    Mempool,
    NoMempool,
}

impl Mode {
    pub fn enable_mempool(&self) -> bool {
        match self {
            Self::GetBlockTemplate | Self::Mempool => true,
            Self::NoMempool => false,
        }
    }

    pub fn mining_mode(&self) -> MiningMode {
        match self {
            Self::GetBlockTemplate => MiningMode::GetBlockTemplate,
            Self::Mempool | Self::NoMempool => MiningMode::GenerateBlocks,
        }
    }
}

#[derive(Debug)]
pub struct ReservedPorts {
    pub bitcoind_listen: ReservedPort,
    pub bitcoind_rpc: ReservedPort,
    pub bitcoind_zmq_sequence: ReservedPort,
    pub electrs_electrum_rpc: ReservedPort,
    pub electrs_electrum_http: ReservedPort,
    pub electrs_monitoring: ReservedPort,
    pub enforcer_serve_grpc: ReservedPort,
    pub enforcer_serve_rpc: ReservedPort,
}

impl ReservedPorts {
    pub fn new() -> Result<Self, reserve_port::Error> {
        Ok(Self {
            bitcoind_listen: ReservedPort::random()?,
            bitcoind_rpc: ReservedPort::random()?,
            bitcoind_zmq_sequence: ReservedPort::random()?,
            electrs_electrum_rpc: ReservedPort::random()?,
            electrs_electrum_http: ReservedPort::random()?,
            electrs_monitoring: ReservedPort::random()?,
            enforcer_serve_grpc: ReservedPort::random()?,
            enforcer_serve_rpc: ReservedPort::random()?,
        })
    }
}

pub fn new_bitcoind(
    bitcoind_path: PathBuf,
    data_dir: PathBuf,
    reserved_ports: &ReservedPorts,
    network: Network,
    signet_setup: Option<&SignetSetup>,
) -> Bitcoind {
    Bitcoind {
        path: bitcoind_path,
        data_dir,
        listen_port: reserved_ports.bitcoind_listen.port(),
        network: network.into(),
        onion_ports: None,
        rpc_user: "integrationtest".to_owned(),
        rpc_pass: "integrationtesting".to_owned(),
        rpc_port: reserved_ports.bitcoind_rpc.port(),
        rpc_host: "127.0.0.1".to_owned(),
        signet_challenge: signet_setup
            .as_ref()
            .map(|setup| setup.signet_challenge.clone()),
        txindex: true,
        zmq_sequence_port: reserved_ports.bitcoind_zmq_sequence.port(),
    }
}

/// Waits for a TCP port to become available by attempting to connect periodically.
pub async fn wait_for_port(
    host: &str,
    port: u16,
    timeout_duration: Duration,
) -> anyhow::Result<()> {
    let target_addr_str = format!("{host}:{port}");
    let target_addr: SocketAddr = target_addr_str
        .parse()
        .map_err(|_| anyhow!("Invalid address format {host}:{port}"))?;
    let check_interval = Duration::from_millis(100);

    let task = async {
        loop {
            match TcpStream::connect(target_addr).await {
                Ok(_) => {
                    tracing::debug!("Port {port} on {host} is open.");
                    return Ok(());
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::ConnectionRefused
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // Port not open yet, wait and retry
                    tracing::trace!("Port {port} on {host} not open yet ({e}), waiting...");
                    sleep(check_interval).await;
                }
                Err(e) => {
                    // Other IO error occurred
                    tracing::warn!(
                        "Error connecting to {host}:{port} while waiting: {e}. Retrying..."
                    );
                    // Still retry, maybe it's a transient issue
                    sleep(check_interval).await;
                }
            }
        }
    };

    match timeout(timeout_duration, task).await {
        Ok(Ok(())) => Ok(()), // Inner Ok(()) means success
        Ok(Err(e)) => Err(e), // Propagate inner error (though our loop logic makes this unlikely)
        Err(_) => Err(anyhow!(
            "Timeout waiting for port {host}:{port} to open after {timeout_duration:?}"
        )),
    }
}

/// Inverse of [`wait_for_port`]: wait until nothing is listening on a port
/// anymore. `AbortOnDrop`'s `Drop` impl only calls `JoinHandle::abort`, which
/// schedules cancellation but doesn't guarantee the underlying child process
/// (and the port it holds) is actually gone by the time `drop` returns -- so
/// a kill immediately followed by a respawn on the same port can race the
/// old process's teardown. Poll for the port to actually free up instead of
/// guessing at a fixed delay.
pub async fn wait_for_port_free(
    host: &str,
    port: u16,
    timeout_duration: Duration,
) -> anyhow::Result<()> {
    let target_addr_str = format!("{host}:{port}");
    let target_addr: SocketAddr = target_addr_str
        .parse()
        .map_err(|_| anyhow!("Invalid address format {host}:{port}"))?;
    let check_interval = Duration::from_millis(50);

    let task = async {
        loop {
            match TcpStream::connect(target_addr).await {
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return,
                _ => {
                    tracing::trace!(
                        "Port {port} on {host} still held, waiting for it to free up..."
                    );
                    sleep(check_interval).await;
                }
            }
        }
    };

    match timeout(timeout_duration, task).await {
        Ok(()) => {
            tracing::debug!("Port {port} on {host} is free.");
            Ok(())
        }
        Err(_) => Err(anyhow!(
            "Timeout waiting for port {host}:{port} to free up after {timeout_duration:?}"
        )),
    }
}

/// Polls bitcoind via `getblockchaininfo` until it responds successfully.
/// The RPC port opens before bitcoind is ready to serve commands, so a TCP
/// probe alone is not enough.
pub async fn wait_for_bitcoind_ready(bitcoin_cli: &bins::BitcoinCli) -> anyhow::Result<()> {
    // When the whole suite runs at once, many bitcoind/electrs/enforcer
    // processes cold-start together. Apply a generous limit here that
    // doesn't crash long running tests, but catches stuck ones.
    const TIMEOUT: Duration = Duration::from_secs(120);
    const CHECK_INTERVAL: Duration = Duration::from_millis(200);
    let task = async {
        loop {
            match bitcoin_cli
                .clone()
                .command::<String, _, String, _, _>([], "getblockchaininfo", [])
                .run_utf8()
                .await
            {
                Ok(_) => return,
                Err(e) => {
                    tracing::trace!("bitcoind not ready yet ({e}), waiting...");
                    sleep(CHECK_INTERVAL).await;
                }
            }
        }
    };
    timeout(TIMEOUT, task)
        .await
        .map_err(|_| anyhow!("Timeout waiting for bitcoind to become ready after {TIMEOUT:?}"))
}

/// Polls the validator via `get_chain_tip` until it reports a tip, and returns
/// it. The enforcer starts serving gRPC before the validator has finished its
/// initial sync, and RPCs that need the mainchain tip fail with `Unavailable`
/// (or `ValidatorNotSynced`) until then, so waiting for the port alone is not
/// enough.
pub async fn wait_for_validator_synced(
    client: &ValidatorServiceClient<Transport>,
) -> anyhow::Result<proto::mainchain::BlockHeaderInfo> {
    const TIMEOUT: Duration = Duration::from_secs(120);
    const CHECK_INTERVAL: Duration = Duration::from_millis(100);
    /// Budget for a single attempt. Connect RPCs carry no client-side deadline
    /// by default, so a request to a peer that accepts the connection and then
    /// never answers -- a foreign listener shadowing the port, an enforcer
    /// still binding it -- would otherwise spend the whole `TIMEOUT` inside one
    /// call and never reach the retry below. Bounding each attempt turns that
    /// into one lost interval, and the retry opens a fresh connection.
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
    let task = async {
        loop {
            let attempt = timeout(
                ATTEMPT_TIMEOUT,
                client.get_chain_tip(GetChainTipRequest::default()),
            );
            match attempt.await {
                Ok(Ok(resp)) => {
                    return resp
                        .into_owned()
                        .block_header_info
                        .into_option()
                        .ok_or_else(|| anyhow!("no block header info in chain tip"));
                }
                // Not ready yet. `Unavailable` means the validator is still
                // syncing; a transport error means the gRPC server isn't
                // actually serving yet, even though the port accepted a TCP
                // connection. With the whole suite starting processes at once
                // both are routine, so retry either until the timeout rather
                // than failing a test on a startup hiccup.
                Ok(Err(err)) => {
                    tracing::trace!("Validator not ready yet ({err}), waiting...");
                    sleep(CHECK_INTERVAL).await;
                }
                Err(_elapsed) => {
                    tracing::warn!(
                        "chain tip request got no response within {ATTEMPT_TIMEOUT:?}; \
                         retrying on a fresh connection"
                    );
                }
            }
        }
    };
    timeout(TIMEOUT, task)
        .await
        .map_err(|_| anyhow!("Timeout waiting for validator to sync after {TIMEOUT:?}"))?
}

/// Default budget for the `wait_for_*` helpers below. Generous, because the
/// whole suite runs in parallel and the machine is saturated; these are
/// deadlines that catch a genuinely stuck test, not expected wait times.
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval between polls for conditions checked in-process or over an already
/// open connection (gRPC, a file read). Short, because these are cheap and the
/// conditions are normally already true on the first check.
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Interval between polls for conditions checked by shelling out to
/// `bitcoin-cli`. Each check forks a process and opens a fresh RPC connection,
/// so polling these as fast as the in-process checks would put more load on an
/// already-saturated machine than it saves in latency.
pub const WAIT_POLL_INTERVAL_SUBPROCESS: Duration = Duration::from_millis(250);

/// Poll `check` until it reports the condition has been reached, erroring out
/// with `what` in the message if it hasn't happened within `WAIT_TIMEOUT`.
///
/// Prefer this over sleeping a fixed duration: it returns as soon as the state
/// is actually observable (normally on the first poll) instead of paying a
/// worst-case guess every run, and it fails loudly rather than silently
/// continuing against state that was never reached.
///
/// A failing `check` counts as "not yet", not as a test failure: processes are
/// still coming up while the suite runs in parallel, so an RPC can legitimately
/// be refused or time out on the first attempts. Whatever it failed with last
/// is reported if the deadline runs out.
pub async fn wait_until<Check, Fut>(what: &str, check: Check) -> anyhow::Result<()>
where
    Check: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<bool>>,
{
    wait_until_every(what, WAIT_POLL_INTERVAL, check).await
}

/// [`wait_until`], with an explicit poll interval. Use
/// [`WAIT_POLL_INTERVAL_SUBPROCESS`] for checks that shell out.
pub async fn wait_until_every<Check, Fut>(
    what: &str,
    poll_interval: Duration,
    mut check: Check,
) -> anyhow::Result<()>
where
    Check: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<bool>>,
{
    let deadline = tokio::time::Instant::now() + WAIT_TIMEOUT;
    let mut last_err: Option<anyhow::Error> = None;
    loop {
        // Bound each individual check by whatever budget is left, so a single
        // hung RPC can't outlive the deadline.
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, check()).await {
            Ok(Ok(true)) => return Ok(()),
            Ok(Ok(false)) => tracing::trace!("still waiting for {what}..."),
            Ok(Err(err)) => {
                tracing::trace!("still waiting for {what} (check failed: {err:#})");
                last_err = Some(err);
            }
            Err(_elapsed) => break,
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        sleep(poll_interval.min(remaining)).await;
    }
    Err(match last_err {
        Some(err) => err.context(format!(
            "Timed out after {WAIT_TIMEOUT:?} waiting for {what}; last check failed"
        )),
        None => anyhow!("Timeout waiting for {what} after {WAIT_TIMEOUT:?}"),
    })
}

/// Wait until `txid` is in `bitcoin_cli`'s node's mempool.
///
/// The wallet broadcasts asynchronously, so a tx is not necessarily in the
/// node's mempool by the time the RPC that created it returns.
pub async fn wait_for_tx_in_mempool(
    bitcoin_cli: &bins::BitcoinCli,
    txid: &bitcoin::Txid,
) -> anyhow::Result<()> {
    let txid = txid.to_string();
    wait_until_every(
        &format!("tx `{txid}` to enter the mempool"),
        WAIT_POLL_INTERVAL_SUBPROCESS,
        || async {
            Ok(bitcoin_cli
                .command::<String, _, _, _, _>([], "getmempoolentry", [txid.clone()])
                .run_utf8()
                .await
                .is_ok())
        },
    )
    .await
}

/// Reported by the enforcer's `getblocktemplate` while its mempool syncs.
const RPC_CLIENT_IN_INITIAL_DOWNLOAD: i32 = -10;

/// Block until the enforcer's `getblocktemplate` endpoint serves templates,
/// rather than reporting that it is still syncing. Any other answer counts as
/// ready; a transport error is not an answer, and is retried.
pub async fn wait_for_block_templates(
    gbt_client: &jsonrpsee::http_client::HttpClient,
) -> anyhow::Result<()> {
    use cusf_enforcer_mempool::server::RpcClient as _;

    wait_until("the enforcer to serve block templates", || async {
        let request = bitcoin_jsonrpsee::client::BlockTemplateRequest::default();
        match gbt_client.get_block_template(request).await {
            Ok(_) => Ok(true),
            Err(jsonrpsee::core::client::Error::Call(err)) => {
                Ok(err.code() != RPC_CLIENT_IN_INITIAL_DOWNLOAD)
            }
            Err(err) => Err(err.into()),
        }
    })
    .await
}

/// Running tasks, aborted on drop
pub struct Tasks {
    // MUST be dropped before electrs and bitcoind. `Option` (rather than the
    // task unconditionally present) so `kill_enforcer`/`restart_enforcer` can
    // explicitly drop the old process before spawning a replacement bound to
    // the same ports.
    _enforcer: Option<AbortOnDrop<()>>,
    // MUST be dropped before bitcoind. Also `Option`, for the same reason as
    // `_enforcer` -- electrs sometimes needs restarting independently (it's
    // known to panic on some reorgs; an unrelated, pre-existing limitation
    // of the pinned binary, not the enforcer).
    _electrs: Option<AbortOnDrop<()>>,
    _bitcoind: AbortOnDrop<()>,
}

type Transport = HttpClient;

/// Construct a connectrpc transport/config pair for a plaintext gRPC endpoint
/// served by our enforcer.
fn make_client(port: u16) -> anyhow::Result<(HttpClient, ClientConfig)> {
    let uri: http::Uri = format!("http://127.0.0.1:{port}")
        .parse()
        .map_err(|err| anyhow!("invalid client URI: {err}"))?;
    let http = HttpClient::plaintext();
    let config = ClientConfig::new(uri);
    Ok((http, config))
}

#[derive(Clone, Debug)]
pub struct Directories {
    pub base_dir: TempDir,
    pub bitcoin_dir: PathBuf,
    pub electrs_dir: PathBuf,
    pub enforcer_dir: PathBuf,
}

impl Directories {
    fn new() -> anyhow::Result<Self> {
        let base_dir = TempDir::new()?;
        // leak unless explicitly allowed to cleanup
        base_dir.leak();

        let bitcoin_dir = base_dir.path().join("bitcoind");

        let electrs_dir = base_dir.path().join("electrs");

        let enforcer_dir = base_dir.path().join("enforcer");

        for dir in [&bitcoin_dir, &electrs_dir, &enforcer_dir] {
            std::fs::create_dir(dir)?;
        }

        Ok(Directories {
            base_dir,
            bitcoin_dir,
            electrs_dir,
            enforcer_dir,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum BitcoindKind {
    #[default]
    Patched,
    Unpatched,
}

fn bitcoind_path(
    bin_paths: &BinPaths,
    bitcoind_kind: BitcoindKind,
) -> Result<&PathBuf, crate::util::VarError> {
    match bitcoind_kind {
        BitcoindKind::Patched => bin_paths.bitcoind(),
        BitcoindKind::Unpatched => bin_paths.bitcoind_unpatched(),
    }
}

/// Whether the enforcer runs with a wallet. Is an enum instead of a
/// bool to make `Default` derivable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnforcerWallet {
    #[default]
    Enabled,
    /// Skip electrs and run the enforcer as validator-only.
    Disabled,
}

#[derive(Default)]
pub struct SetupOpts<
    BitcoindArg = String,
    EnforcerArg = String,
    BitcoindArgs = Vec<BitcoindArg>,
    EnforcerArgs = Vec<EnforcerArg>,
> where
    BitcoindArg: AsRef<OsStr>,
    EnforcerArg: AsRef<OsStr>,
    BitcoindArgs: IntoIterator<Item = BitcoindArg>,
    EnforcerArgs: IntoIterator<Item = EnforcerArg>,
{
    pub bitcoind_args: BitcoindArgs,
    pub bitcoind_kind: BitcoindKind,
    pub enforcer_args: EnforcerArgs,
    pub enforcer_wallet: EnforcerWallet,
}

type LazyLockBoxedSend<T> = LazyLock<T, Box<dyn FnOnce() -> T + Send>>;

pub struct PostSetup {
    pub network: Network,
    pub mode: Mode,
    pub bitcoin_cli: bins::BitcoinCli,
    bitcoin_util: LazyLockBoxedSend<Result<bins::BitcoinUtil, Arc<VarError>>>,
    // MUST occur before temp dirs and reserved ports in order to ensure that processes are dropped
    // before reserved ports are freed and temp dirs are cleared
    pub tasks: Tasks,
    /// Always `Some(_)` if `network == Network::Signet`, `None` otherwise
    pub signet_miner: Option<bins::SignetMiner>,
    pub gbt_client: jsonrpsee::http_client::HttpClient,
    pub validator_service_client: ValidatorServiceClient<Transport>,
    pub wallet_service_client: WalletServiceClient<Transport>,
    pub mining_service_client: MiningServiceClient<Transport>,
    pub mining_address: Address,
    pub receive_address: Address,
    // MUST occur after tasks in order to ensure that tasks are dropped
    // before temp dirs are cleared
    pub directories: Directories,
    // MUST occur after tasks in order to ensure that tasks are dropped
    // before reserved ports are freed
    pub reserved_ports: ReservedPorts,
}

impl PostSetup {
    pub fn bitcoin_util(&self) -> Result<&bins::BitcoinUtil, Arc<VarError>> {
        self.bitcoin_util.as_ref().map_err(|err| err.clone())
    }

    pub async fn setup<BitcoindArg, EnforcerArg, BitcoindArgs, EnforcerArgs>(
        bin_paths: &BinPaths,
        mode: Mode,
        network: Network,
        reserved_ports: ReservedPorts,
        dirs: Directories,
        opts: SetupOpts<BitcoindArg, EnforcerArg, BitcoindArgs, EnforcerArgs>,
        res_tx: mpsc::UnboundedSender<anyhow::Result<()>>,
    ) -> anyhow::Result<Self>
    where
        BitcoindArg: AsRef<OsStr>,
        EnforcerArg: AsRef<OsStr>,
        BitcoindArgs: IntoIterator<Item = BitcoindArg>,
        EnforcerArgs: IntoIterator<Item = EnforcerArg>,
    {
        tracing::info!("Running setup");
        let signet_setup = if let Network::Signet = network {
            Some(SignetSetup::new()?)
        } else {
            None
        };

        let enable_wallet = opts.enforcer_wallet == EnforcerWallet::Enabled;
        // No wallet/mempool constraint to assert: `MiningService` is served on
        // regtest and signet regardless of either, and the one mode that does
        // need a mempool (`GetBlockTemplate`) enables it by construction.

        tracing::debug!("Starting bitcoin node");
        let mut bitcoind = new_bitcoind(
            bitcoind_path(bin_paths, opts.bitcoind_kind)?.clone(),
            dirs.bitcoin_dir.clone(),
            &reserved_ports,
            network,
            signet_setup.as_ref(),
        );
        bitcoind.txindex = enable_wallet;
        let bitcoind_task =
            bitcoind.spawn_command_with_args::<String, _, _, _, _>([], opts.bitcoind_args, {
                let res_tx = res_tx.clone();
                move |err| {
                    let _err: Result<(), _> = res_tx.unbounded_send(Err(err));
                }
            });
        // wait for startup
        let mut bitcoin_cli = bitcoind.new_bitcoin_cli(bin_paths.bitcoin_cli()?.clone());
        wait_for_bitcoind_ready(&bitcoin_cli).await?;

        // Create a wallet and initialize it
        tracing::debug!("Creating wallet");
        let _create_wallet_output = bitcoin_cli
            .command::<String, _, _, _, _>([], "createwallet", ["integration-test"])
            .run_utf8()
            .await?;
        bitcoin_cli.rpc_wallet = Some("integration-test".to_owned());
        let mining_address = match signet_setup.as_ref() {
            Some(signet_setup) => {
                let () = signet_setup.init_bitcoind_wallet(&bitcoin_cli).await?;
                signet_setup.signet_challenge_addr.clone()
            }
            None => {
                tracing::debug!("Generating mining address");
                let mining_addr_str = bitcoin_cli
                    .command::<String, _, String, _, _>([], "getnewaddress", [])
                    .run_utf8()
                    .await?;
                mining_addr_str
                    .parse::<bitcoin::Address<_>>()?
                    .require_network(network.into())?
            }
        };
        tracing::debug!("Mining address: {mining_address}");
        tracing::debug!("Generating receiving address");
        let receive_address = {
            let receive_address_str = bitcoin_cli
                .command::<String, _, String, _, _>([], "getnewaddress", [])
                .run_utf8()
                .await?;
            tracing::debug!("Receiving address: {receive_address_str}");
            receive_address_str
                .parse::<Address<_>>()?
                .require_network(bitcoind.network)?
        };
        let mut signet_miner = if signet_setup.is_some() {
            Some(bins::SignetMiner {
                path: bin_paths.signet_miner()?.clone(),
                bitcoin_cli: bitcoin_cli.clone(),
                bitcoin_util: bin_paths.bitcoin_util()?.clone(),
                block_interval: None,
                coinbase_recipient: Some(mining_address.clone()),
                debug: false,
                // `None` makes the miner pass `--min-nbits`, grinding at
                // signet's floor difficulty. Calibrating for ~1s/block here
                // instead adds ~1s of pure grinding per mined block, which
                // dominates signet test runtime.
                nbits: None,
                getblocktemplate_command: None,
                coinbasetxn: false,
            })
        } else {
            None
        };
        // Validator-only harnesses fund spends from a mature coinbase
        // (COINBASE_MATURITY is 100), so they mine 101 blocks up front.
        let initial_blocks = if enable_wallet { 1 } else { 101 };
        tracing::debug!(%mining_address, initial_blocks, "Mining initial blocks");
        if let Some(signet_miner) = signet_miner.as_ref() {
            let mine_output = signet_miner
                .command("generate", vec!["--address", &mining_address.to_string()])
                .run_utf8()
                .await?;
            tracing::debug!("Checking that block was mined successfully");
            let blocks: u32 = bitcoin_cli
                .command::<String, _, String, _, _>([], "getblockcount", [])
                .run_utf8()
                .await?
                .parse()?;
            anyhow::ensure!(blocks == 1);
            tracing::debug!("Mined 1 block: `{mine_output}`");
        } else {
            let n_blocks = initial_blocks.to_string();
            let mining_addr = mining_address.to_string();
            let _output = bitcoin_cli
                .command::<String, _, _, _, _>([], "generatetoaddress", [&n_blocks, &mining_addr])
                .run_utf8()
                .await?;
        }
        let (wallet_electrum_rpc_port, wallet_electrum_http_port, electrs_task) = if enable_wallet {
            tracing::debug!("Starting electrs");
            let electrs = Electrs {
                path: bin_paths.electrs()?.clone(),
                db_dir: dirs.electrs_dir.clone(),
                auth: (
                    "integrationtest".to_owned(),
                    "integrationtesting".to_owned(),
                ),
                daemon_dir: bitcoind.data_dir.join("path"),
                daemon_rpc_port: bitcoind.rpc_port,
                electrum_rpc_port: reserved_ports.electrs_electrum_rpc.port(),
                electrum_http_port: reserved_ports.electrs_electrum_http.port(),
                monitoring_port: reserved_ports.electrs_monitoring.port(),
                network: bitcoind.network,
                signet_magic: signet_setup.as_ref().map(|setup| setup.signet_magic),
            };
            let electrs_task =
                electrs.spawn_command_with_args::<String, String, _, _, _>([], [], {
                    let res_tx = res_tx.clone();
                    move |err| {
                        let _err: Result<(), _> = res_tx.unbounded_send(Err(err));
                    }
                });
            sleep(std::time::Duration::from_secs(1)).await;
            (
                electrs.electrum_rpc_port,
                electrs.electrum_http_port,
                electrs_task,
            )
        } else {
            tracing::debug!("Skipping electrs (validator-only enforcer)");
            (0, 0, tokio::spawn(async {}).into())
        };
        tracing::debug!("Starting bip360p_enforcer");
        let enforcer = Enforcer {
            path: bin_paths.bip360p_enforcer()?.clone(),
            data_dir: dirs.enforcer_dir.clone(),
            enable_mempool: mode.enable_mempool(),
            enable_wallet,
            enable_block_template_server: matches!(mode, Mode::GetBlockTemplate),
            coinbase_recipient: (!enable_wallet).then(|| mining_address.to_string()),
            node_blocks_dir: None,
            node_rpc_user: bitcoind.rpc_user,
            node_rpc_pass: bitcoind.rpc_pass,
            node_rpc_port: bitcoind.rpc_port,
            node_zmq_sequence_port: bitcoind.zmq_sequence_port,
            serve_grpc_port: reserved_ports.enforcer_serve_grpc.port(),
            serve_rpc_port: reserved_ports.enforcer_serve_rpc.port(),
            wallet_electrum_rpc_port,
            wallet_electrum_http_port,
        };
        let enforcer_task = enforcer.spawn_command_with_args(
            [(
                "RUST_LOG",
                "h2=info,hyper_util=info,jsonrpsee-client=debug,jsonrpsee-http=debug,connectrpc=debug,trace",
            )],
            opts.enforcer_args,
            move |err| {
                let _err: Result<(), _> = res_tx.unbounded_send(Err(err));
            },
        );
        let tasks = Tasks {
            _enforcer: Some(enforcer_task),
            _electrs: Some(electrs_task),
            _bitcoind: bitcoind_task,
        };
        // Wait for enforcer gRPC port to open
        wait_for_port(
            "127.0.0.1",
            enforcer.serve_grpc_port,
            Duration::from_secs(10),
        )
        .await
        .map_err(|e| anyhow!("Failed waiting for enforcer gRPC port: {e}"))?;

        let gbt_client = jsonrpsee::http_client::HttpClient::builder()
            .build(format!("http://127.0.0.1:{}", enforcer.serve_rpc_port))
            .map_err(|err| anyhow!("failed to create gbt client: {err:#}"))?;

        // The JSON-RPC (`getblocktemplate`) server only runs in the mode that
        // serves block templates, and it binds before the enforcer has synced.
        // Both the `gbt_client` above and the signet miner's GBT script talk to
        // it, so wait for it to serve a template rather than racing the first
        // request against startup.
        if enforcer.enable_block_template_server {
            wait_for_port(
                "127.0.0.1",
                enforcer.serve_rpc_port,
                Duration::from_secs(60),
            )
            .await
            .map_err(|e| anyhow!("Failed waiting for enforcer JSON-RPC port: {e}"))?;
            wait_for_block_templates(&gbt_client).await?;
        }
        if let Some(signet_miner) = signet_miner.as_mut() {
            let () = SignetSetup::configure_miner(signet_miner, &dirs.base_dir, &enforcer)?;
        }
        let (http, config) = make_client(enforcer.serve_grpc_port)?;
        let validator_service_client = ValidatorServiceClient::new(http.clone(), config.clone());
        let mining_service_client = MiningServiceClient::new(http.clone(), config.clone());
        let wallet_service_client = WalletServiceClient::new(http, config);
        // The gRPC port opens before the validator has synced the blocks that
        // this setup generated. Wait for it, so that tests don't race the
        // initial sync.
        let _chain_tip = wait_for_validator_synced(&validator_service_client).await?;
        let bitcoin_util = {
            let path = match bin_paths.bitcoin_util() {
                Ok(path) => Ok(path.clone()),
                Err(err) => Err(Arc::new(err)),
            };
            let network = bitcoind.network;
            let closure = move || path.map(|path| bins::BitcoinUtil { path, network });
            LazyLock::new(Box::new(closure) as Box<_>)
        };
        Ok(PostSetup {
            network,
            mode,
            bitcoin_cli,
            bitcoin_util,
            tasks,
            signet_miner,
            gbt_client,
            validator_service_client,
            wallet_service_client,
            mining_service_client,
            mining_address,
            receive_address,
            directories: dirs.clone(),
            reserved_ports,
        })
    }

    /// Kill the running enforcer process (simulating a crash) without
    /// respawning it, and wait until its gRPC port is confirmed free. Used
    /// together with [`Self::restart_enforcer`] so a reorg can be driven
    /// entirely on bitcoind while the enforcer is down, forcing it to catch
    /// up over more than one block on the next restart rather than observing
    /// the reorg live via its ZMQ-fed background sync task.
    pub async fn kill_enforcer(&mut self) -> anyhow::Result<()> {
        if let Some(old) = self.tasks._enforcer.take() {
            drop(old);
        }
        wait_for_port_free(
            "127.0.0.1",
            self.reserved_ports.enforcer_serve_grpc.port(),
            Duration::from_secs(10),
        )
        .await
    }

    /// Respawn the enforcer from the same data-dir and ports (killing it
    /// first, if not already killed via [`Self::kill_enforcer`]).
    /// bitcoind/electrs are left running throughout. Existing gRPC clients
    /// reconnect automatically once the new process is listening.
    pub async fn restart_enforcer<EnforcerArg, EnforcerArgs>(
        &mut self,
        bin_paths: &BinPaths,
        enforcer_args: EnforcerArgs,
        res_tx: mpsc::UnboundedSender<anyhow::Result<()>>,
    ) -> anyhow::Result<()>
    where
        EnforcerArg: AsRef<OsStr>,
        EnforcerArgs: IntoIterator<Item = EnforcerArg>,
    {
        self.kill_enforcer().await?;

        let enforcer = Enforcer {
            path: bin_paths.bip360p_enforcer()?.clone(),
            data_dir: self.directories.enforcer_dir.clone(),
            enable_mempool: self.mode.enable_mempool(),
            enable_wallet: true,
            enable_block_template_server: matches!(self.mode, Mode::GetBlockTemplate),
            coinbase_recipient: None,
            node_blocks_dir: None,
            node_rpc_user: self
                .bitcoin_cli
                .rpc_user
                .clone()
                .ok_or_else(|| anyhow!("bitcoin_cli has no rpc_user"))?,
            node_rpc_pass: self
                .bitcoin_cli
                .rpc_pass
                .as_ref()
                .ok_or_else(|| anyhow!("bitcoin_cli has no rpc_pass"))?
                .expose()
                .to_owned(),
            node_rpc_port: self.bitcoin_cli.rpc_port,
            node_zmq_sequence_port: self.reserved_ports.bitcoind_zmq_sequence.port(),
            serve_grpc_port: self.reserved_ports.enforcer_serve_grpc.port(),
            serve_rpc_port: self.reserved_ports.enforcer_serve_rpc.port(),
            wallet_electrum_rpc_port: self.reserved_ports.electrs_electrum_rpc.port(),
            wallet_electrum_http_port: self.reserved_ports.electrs_electrum_http.port(),
        };
        let enforcer_task = enforcer.spawn_command_with_args(
            [(
                "RUST_LOG",
                "h2=info,hyper_util=info,jsonrpsee-client=debug,jsonrpsee-http=debug,connectrpc=debug,trace",
            )],
            enforcer_args,
            move |err| {
                let _err: Result<(), _> = res_tx.unbounded_send(Err(err));
            },
        );
        self.tasks._enforcer = Some(enforcer_task);

        wait_for_port(
            "127.0.0.1",
            enforcer.serve_grpc_port,
            Duration::from_secs(10),
        )
        .await
        .map_err(|e| anyhow!("Failed waiting for restarted enforcer gRPC port: {e}"))?;

        Ok(())
    }

    /// Kill electrs without respawning it, and wait until its ports are
    /// confirmed free.
    pub async fn kill_electrs(&mut self) -> anyhow::Result<()> {
        if let Some(old) = self.tasks._electrs.take() {
            drop(old);
        }
        wait_for_port_free(
            "127.0.0.1",
            self.reserved_ports.electrs_electrum_http.port(),
            Duration::from_secs(10),
        )
        .await
    }

    /// Kill electrs (if not already killed via [`Self::kill_electrs`]) and
    /// respawn it from a freshly wiped db-dir. electrs (the pinned v3.2.0
    /// binary) is known to panic mid-index on some reorgs -- an unrelated,
    /// pre-existing limitation, not the enforcer -- and can't resume
    /// cleanly from a state it panicked while indexing.
    pub async fn restart_electrs(
        &mut self,
        bin_paths: &BinPaths,
        res_tx: mpsc::UnboundedSender<anyhow::Result<()>>,
    ) -> anyhow::Result<()> {
        self.kill_electrs().await?;

        std::fs::remove_dir_all(&self.directories.electrs_dir).ok();
        std::fs::create_dir_all(&self.directories.electrs_dir)?;

        let electrs = Electrs {
            path: bin_paths.electrs()?.clone(),
            db_dir: self.directories.electrs_dir.clone(),
            auth: (
                self.bitcoin_cli
                    .rpc_user
                    .clone()
                    .ok_or_else(|| anyhow!("bitcoin_cli has no rpc_user"))?,
                self.bitcoin_cli
                    .rpc_pass
                    .as_ref()
                    .ok_or_else(|| anyhow!("bitcoin_cli has no rpc_pass"))?
                    .expose()
                    .to_owned(),
            ),
            daemon_dir: self.directories.bitcoin_dir.join("path"),
            daemon_rpc_port: self.bitcoin_cli.rpc_port,
            electrum_rpc_port: self.reserved_ports.electrs_electrum_rpc.port(),
            electrum_http_port: self.reserved_ports.electrs_electrum_http.port(),
            monitoring_port: self.reserved_ports.electrs_monitoring.port(),
            network: self.network.into(),
            // Only relevant for signet, which this helper isn't used by yet.
            signet_magic: None,
        };
        let electrs_task = electrs.spawn_command_with_args::<String, String, _, _, _>([], [], {
            let res_tx = res_tx.clone();
            move |err| {
                let _err: Result<(), _> = res_tx.unbounded_send(Err(err));
            }
        });
        self.tasks._electrs = Some(electrs_task);

        wait_for_port(
            "127.0.0.1",
            electrs.electrum_http_port,
            Duration::from_secs(60),
        )
        .await
        .map_err(|e| anyhow!("Failed waiting for restarted electrs http port: {e}"))?;

        Ok(())
    }
}

pub struct PreSetup<B = BinPaths> {
    pub bin_paths: B,
    pub network: Network,
    pub reserved_ports: ReservedPorts,
    pub directories: Directories,
}

impl<B> PreSetup<B> {
    pub fn new(bin_paths: B, network: Network) -> anyhow::Result<Self> {
        Ok(PreSetup {
            bin_paths,
            network,
            reserved_ports: ReservedPorts::new()?,
            directories: Directories::new()?,
        })
    }

    pub async fn setup<BitcoindArg, EnforcerArg, BitcoindArgs, EnforcerArgs>(
        self,
        mode: Mode,
        opts: SetupOpts<BitcoindArg, EnforcerArg, BitcoindArgs, EnforcerArgs>,
        res_tx: mpsc::UnboundedSender<anyhow::Result<()>>,
    ) -> anyhow::Result<PostSetup>
    where
        B: Borrow<BinPaths>,
        BitcoindArg: AsRef<OsStr>,
        EnforcerArg: AsRef<OsStr>,
        BitcoindArgs: IntoIterator<Item = BitcoindArg>,
        EnforcerArgs: IntoIterator<Item = EnforcerArg>,
    {
        PostSetup::setup(
            self.bin_paths.borrow(),
            mode,
            self.network,
            self.reserved_ports,
            self.directories,
            opts,
            res_tx,
        )
        .await
    }
}
