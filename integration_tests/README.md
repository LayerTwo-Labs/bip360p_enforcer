# Integration tests

Trials drive real processes — `bitcoind`, `electrs` (for wallet trials), and
the enforcer binary — via a `libtest-mimic` harness.

## Setup

```bash
just setup-core   # downloads stock Bitcoin Core, writes integrationtests.env
```

or point the harness at binaries you already have:

```bash
export CUSF_ENFORCER_INTEGRATION_TEST_ENV=$PWD/integration_tests/example.env
```

Env vars (see `example.env`): `CUSF_ENFORCER`, `BITCOIND`,
`BITCOIND_UNPATCHED`, `BITCOIN_CLI`, `BITCOIN_UTIL`, `ELECTRS`.

## Running

```bash
just it-all               # every trial
just it <trial-name>      # one trial
cargo run --example integration_tests -- --list   # list trial names
```

Wallet trials start electrs; validator-only trials run without it
(`EnforcerWallet::Disabled` in `SetupOpts`).
