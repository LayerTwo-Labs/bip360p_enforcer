//! Block templates without a wallet, against a node without `txindex`.

use cusf_enforcer_lib::bins::CommandExt as _;
use futures::channel::mpsc;

use crate::{
    mine::mine_gbt_check,
    setup::{EnforcerWallet, Mode, PreSetup, SetupOpts},
};

pub async fn test_wallet_less_block_template(setup: PreSetup) -> anyhow::Result<()> {
    let (res_tx, _res_rx) = mpsc::unbounded();
    let setup_opts: SetupOpts = SetupOpts {
        enforcer_wallet: EnforcerWallet::Disabled,
        ..Default::default()
    };

    let mut post_setup = setup
        .setup(Mode::GetBlockTemplate, setup_opts, res_tx)
        .await?;

    // Verify there's really no wallet here
    let balance = post_setup
        .wallet_service_client
        .get_balance(cusf_enforcer_lib::proto::mainchain::GetBalanceRequest::default())
        .await;
    let status = balance.err().ok_or_else(|| {
        anyhow::anyhow!("GetBalance succeeded, but the enforcer was started without a wallet")
    })?;
    anyhow::ensure!(
        status.code == connectrpc::ErrorCode::Unimplemented,
        "expected WalletService to be unserved without a wallet, got: {status}"
    );

    // Guard the premise. A wallet-enabled enforcer hard-fails unless the node
    // has `txindex`; the block producer must not need it. If something later
    // switches the node back to `-txindex`, this test would still pass while
    // silently no longer covering that, so assert the node really lacks it.
    let index_info = post_setup
        .bitcoin_cli
        .command::<String, _, String, _, _>([], "getindexinfo", [])
        .run_utf8()
        .await?;
    anyhow::ensure!(
        !index_info.contains("txindex"),
        "this test must run against a node without `txindex`, but the node reports: {index_info}"
    );

    // Mine a few blocks from the enforcer's own template server: if the block
    // producer needed a wallet or `txindex`, template production or submission
    // would fail here.
    let () = mine_gbt_check::<_, std::convert::Infallible>(&mut post_setup, 3, |_| Ok(()))
        .await
        .map_err(|err| match err {
            either::Either::Left(err) => anyhow::anyhow!("mine_gbt failed: {err}"),
        })?;

    drop(post_setup);
    Ok(())
}
