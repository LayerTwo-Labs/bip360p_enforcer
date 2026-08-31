use std::{future::Future, panic::AssertUnwindSafe, time::Duration};

use bip360p_enforcer_lib::{
    bins::CommandExt as _,
    proto::mainchain::{CreateNewAddressRequest, GetInfoRequest},
};
use futures::{FutureExt as _, channel::mpsc};
use tokio::time::sleep;
use tracing::Instrument as _;

use crate::{
    mine::mine_signet_check,
    setup::{Directories, Mode, Network, PostSetup, PreSetup},
    test_unconfirmed_transactions,
    util::{AsyncTrial, BinPaths, FileDumpConfig, TestFailureCollector, TestFileRegistry},
};

type TestFuture = std::pin::Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;
type TestTrial = AsyncTrial<TestFuture>;

struct TestSetupComponents {
    bin_paths: BinPaths,
    network: Network,
    mode: Mode,
    file_registry: TestFileRegistry,
    failure_collector: TestFailureCollector,
}

fn register_files(file_registry: &TestFileRegistry, name: &str, directories: &Directories) {
    // Register specific files with their own configurations
    file_registry.register_file(
        name,
        directories.bitcoin_dir.join("stdout.txt"),
        FileDumpConfig::new().with_label("Bitcoin Core stdout"),
    );

    file_registry.register_file(
        name,
        directories.bitcoin_dir.join("stderr.txt"),
        FileDumpConfig::new().with_label("Bitcoin Core stderr"),
    );

    file_registry.register_file(
        name,
        directories.enforcer_dir.join("stdout.txt"),
        FileDumpConfig::new().with_label("Enforcer stdout"),
    );

    file_registry.register_file(
        name,
        directories.enforcer_dir.join("stderr.txt"),
        FileDumpConfig::new().with_label("Enforcer stderr"),
    );
}

async fn catch_unwind<Fut>(test_future: Fut) -> anyhow::Result<()>
where
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    match AssertUnwindSafe(test_future).catch_unwind().await {
        Ok(result) => result,
        Err(panic_payload) => {
            // Convert panic to an error
            let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            Err(anyhow::anyhow!("Test panicked: {panic_msg}"))
        }
    }
}

fn new_trial<F, Fut>(name: String, comps: TestSetupComponents, test_fn: F) -> TestTrial
where
    F: FnOnce(PreSetup) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let file_registry = comps.file_registry.clone();
    AsyncTrial::new(
        name.clone(),
        Box::pin(async move {
            let pre_setup = PreSetup::new(comps.bin_paths.clone(), comps.network)?;

            register_files(&file_registry, &name, &pre_setup.directories);

            let test_future =
                test_fn(pre_setup).instrument(tracing::info_span!("test", name = %name));

            catch_unwind(test_future).await
        }),
        comps.file_registry,
        comps.failure_collector,
    )
}

fn new_trial_with_setup<F, Fut>(name: String, comps: TestSetupComponents, test_fn: F) -> TestTrial
where
    F: FnOnce(PostSetup) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    new_trial_with_setup_opts(name, comps, Default::default(), test_fn)
}

/// Like [`new_trial_with_setup`], for tests that need non-default
/// [`SetupOpts`] (e.g. extra enforcer CLI flags).
fn new_trial_with_setup_opts<F, Fut>(
    name: String,
    comps: TestSetupComponents,
    setup_opts: crate::setup::SetupOpts,
    test_fn: F,
) -> TestTrial
where
    F: FnOnce(PostSetup) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let file_registry = comps.file_registry.clone();
    AsyncTrial::new(
        name.clone(),
        Box::pin(async move {
            let (res_tx, _) = mpsc::unbounded();
            let pre_setup = PreSetup::new(comps.bin_paths.clone(), comps.network)?;
            register_files(&file_registry, &name, &pre_setup.directories);
            let post_setup = pre_setup.setup(comps.mode, setup_opts, res_tx).await?;

            let test_future =
                test_fn(post_setup).instrument(tracing::info_span!("test", name = %name));

            catch_unwind(test_future).await
        }) as TestFuture,
        comps.file_registry,
        comps.failure_collector,
    )
}

/// Wait until the enforcer wallet has applied every block Bitcoin Core has
/// mined. The wallet connects blocks as the node advances, so poll its tip
/// until it has caught up rather than sleeping a fixed duration — this returns
/// as soon as the wallet is in sync, and fails loudly if it never catches up.
pub async fn wait_for_wallet_sync(post_setup: &mut PostSetup) -> anyhow::Result<()> {
    const POLL_INTERVAL: Duration = Duration::from_millis(250);
    const TIMEOUT: Duration = Duration::from_secs(60);

    let target_height: u32 = post_setup
        .bitcoin_cli
        .command::<String, _, String, _, _>([], "getblockcount", [])
        .run_utf8()
        .await?
        .trim()
        .parse()?;
    tracing::debug!("Waiting for wallet to sync to block {target_height}");

    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let wallet_height = post_setup
            .wallet_service_client
            .get_info(GetInfoRequest::default())
            .await?
            .into_owned()
            .tip
            .into_option()
            .map(|tip| tip.height)
            .unwrap_or(0);
        if wallet_height >= target_height {
            return Ok(());
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "wallet did not sync to block {target_height} within {TIMEOUT:?} \
             (stuck at {wallet_height})"
        );
        sleep(POLL_INTERVAL).await;
    }
}

pub async fn fund_enforcer(post_setup: &mut PostSetup) -> anyhow::Result<()> {
    use std::convert::Infallible;
    const BLOCKS: u32 = 100;
    tracing::info!("Funding enforcer");
    let () = match post_setup.network {
        Network::Regtest => {
            let address = post_setup
                .wallet_service_client
                .create_new_address(CreateNewAddressRequest::default())
                .await?
                .into_owned()
                .address;

            post_setup
                .bitcoin_cli
                .command::<String, _, _, _, _>(
                    [],
                    "generatetoaddress",
                    [BLOCKS.to_string(), address],
                )
                .run_utf8()
                .await?;
        }
        Network::Signet => {
            mine_signet_check::<_, Infallible>(post_setup, BLOCKS, |_| Ok(())).await?;
        }
    };
    tracing::debug!("Waiting for wallet sync...");
    let () = wait_for_wallet_sync(post_setup).await?;
    Ok(())
}

pub fn tests(
    bin_paths: &BinPaths,
    file_registry: TestFileRegistry,
    failure_collector: TestFailureCollector,
) -> Vec<TestTrial> {
    // TODO: add a signet test here?
    let unconfirmed_transactions_tests =
        [(Network::Regtest, Mode::Mempool)]
            .iter()
            .map(|(network, mode)| {
                new_trial_with_setup(
                    format!("unconfirmed_transactions (mode: {mode}, network: {network})"),
                    TestSetupComponents {
                        bin_paths: bin_paths.clone(),
                        network: *network,
                        mode: *mode,
                        file_registry: file_registry.clone(),
                        failure_collector: failure_collector.clone(),
                    },
                    test_unconfirmed_transactions::test_unconfirmed_transactions,
                )
            });

    let mut async_trials = vec![];

    async_trials.extend(unconfirmed_transactions_tests);

    async_trials.extend([new_trial(
        "file_based_block_parser".to_string(),
        TestSetupComponents {
            bin_paths: bin_paths.clone(),
            network: Network::Regtest,
            mode: Mode::Mempool,
            file_registry: file_registry.clone(),
            failure_collector: failure_collector.clone(),
        },
        crate::test_file_based_block_parser::test_file_based_block_parser,
    )]);
    // Uses `new_trial` rather than `new_trial_with_setup`: it needs custom
    // `SetupOpts` to start the enforcer without a wallet.
    // GetBlockTemplate mode mines from templates served by the enforcer's own
    // `getblocktemplate` server; NoMempool mode exercises the fallback to
    // Bitcoin Core's templates.
    async_trials.extend([Mode::GetBlockTemplate, Mode::NoMempool].map(|mode| {
        new_trial(
            format!("generate_to_address (mode: {mode})"),
            TestSetupComponents {
                bin_paths: bin_paths.clone(),
                network: Network::Regtest,
                mode,
                file_registry: file_registry.clone(),
                failure_collector: failure_collector.clone(),
            },
            move |setup| crate::test_generate_to_address::test_generate_to_address(setup, mode),
        )
    }));
    // Uses `new_trial` rather than `new_trial_with_setup`: it needs custom
    // `SetupOpts` to start the enforcer without a wallet.
    async_trials.push(new_trial(
        "wallet_less_block_template".to_string(),
        TestSetupComponents {
            bin_paths: bin_paths.clone(),
            network: Network::Regtest,
            mode: Mode::GetBlockTemplate,
            file_registry: file_registry.clone(),
            failure_collector: failure_collector.clone(),
        },
        crate::test_wallet_less_block_template::test_wallet_less_block_template,
    ));
    // Uses `new_trial`: it pre-populates the data dir with a pre-split
    // wallet DB before starting the enforcer.    // Needs direct `bin_paths` (respawns the enforcer/electrs mid-test),
    // so it uses a bespoke trial rather than `new_trial_with_setup`.
    async_trials.push({
        let name = crate::test_wallet_reorg_multi_block::TEST_NAME;
        AsyncTrial::new(
            name,
            Box::pin({
                let bin_paths = bin_paths.clone();
                async move {
                    let test_future =
                        crate::test_wallet_reorg_multi_block::test_wallet_reorg_multi_block(
                            bin_paths,
                        )
                        .instrument(tracing::info_span!("test", name = %name));
                    catch_unwind(test_future).await
                }
            }),
            file_registry.clone(),
            failure_collector.clone(),
        )
    });

    // Needs direct `bin_paths` (to respawn the enforcer mid-test), so it uses
    // a bespoke trial rather than `new_trial_with_setup`.
    async_trials.push({
        let name = crate::test_wallet_large_gap_sync::TEST_NAME;
        AsyncTrial::new(
            name,
            Box::pin({
                let bin_paths = bin_paths.clone();
                async move {
                    let test_future =
                        crate::test_wallet_large_gap_sync::test_wallet_large_gap_sync(bin_paths)
                            .instrument(tracing::info_span!("test", name = %name));
                    catch_unwind(test_future).await
                }
            }),
            file_registry.clone(),
            failure_collector.clone(),
        )
    });

    async_trials.push(new_trial_with_setup(
        crate::test_no_secrets_in_logs::TEST_NAME.to_string(),
        TestSetupComponents {
            bin_paths: bin_paths.clone(),
            network: Network::Regtest,
            mode: Mode::Mempool,
            file_registry: file_registry.clone(),
            failure_collector: failure_collector.clone(),
        },
        crate::test_no_secrets_in_logs::test_no_secrets_in_logs,
    ));

    // FINAL_REPORT claim: testmempoolaccept never inserts (control: sendraw does).
    async_trials.push(new_trial_with_setup_opts(
        "cusf_claim_testmempoolaccept_no_insert".to_string(),
        TestSetupComponents {
            bin_paths: bin_paths.clone(),
            network: Network::Regtest,
            mode: Mode::NoMempool,
            file_registry: file_registry.clone(),
            failure_collector: failure_collector.clone(),
        },
        crate::setup::SetupOpts {
            // Mature coinbases in bitcoind wallet; no electrs needed.
            enforcer_wallet: crate::setup::EnforcerWallet::Disabled,
            bitcoind_args: vec!["-fallbackfee=0.0002".to_string()],
            ..Default::default()
        },
        crate::test_cusf_claims::test_cusf_claim_testmempoolaccept_no_insert,
    ));

    // Full BIP 360 wallet lifecycle (create → receive → spend → mine →
    // validate) for all four schemes against plain bitcoind. Needs the
    // enforcer's own block-template server (to inject nonstandard P2MR spends)
    // and an enabled enforcer wallet, so it runs in `GetBlockTemplate` mode with
    // its own setup opts.
    async_trials.push(new_trial_with_setup_opts(
        "bip360_wallet_lifecycle".to_string(),
        TestSetupComponents {
            bin_paths: bin_paths.clone(),
            network: Network::Regtest,
            mode: Mode::GetBlockTemplate,
            file_registry: file_registry.clone(),
            failure_collector: failure_collector.clone(),
        },
        crate::test_bip360_wallet_lifecycle::wallet_lifecycle_setup_opts(),
        crate::test_bip360_wallet_lifecycle::test_bip360_wallet_lifecycle,
    ));

    // Enforcement: invalid P2MR spends must be rejected (invalidateblock). Runs
    // validator-only (no wallet/mempool), so the trial fn builds its own setup
    // opts and calls `setup` itself — hence `new_trial`, not `_with_setup`.
    async_trials.push(new_trial(
        "bip360_enforcement".to_string(),
        TestSetupComponents {
            bin_paths: bin_paths.clone(),
            network: Network::Regtest,
            mode: Mode::NoMempool,
            file_registry: file_registry.clone(),
            failure_collector: failure_collector.clone(),
        },
        crate::test_bip360_enforcement::test_bip360_enforcement,
    ));

    // Vault enforcement: OP_VAULT/OP_VAULT_RECOVER covenant on a live chain — a
    // correct trigger and recovery accept; a forged signature and a mismatching
    // trigger-output taptree are rejected (invalidateblock). Validator-only.
    async_trials.push(new_trial(
        "bip360_vault_enforcement".to_string(),
        TestSetupComponents {
            bin_paths: bin_paths.clone(),
            network: Network::Regtest,
            mode: Mode::NoMempool,
            file_registry: file_registry.clone(),
            failure_collector: failure_collector.clone(),
        },
        crate::test_bip360_vault_enforcement::test_bip360_vault_enforcement,
    ));

    async_trials
}
