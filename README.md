# cusf_enforcer — a soft-fork enforcer template

A **CUSF** ("Core Untouched Soft Fork") enforcer: a sidecar daemon that
watches an unmodified Bitcoin Core node and enforces additional consensus
rules out-of-band. When a block violates the rules, the enforcer tells the
node to `invalidateblock` it; when a mempool transaction violates them, the
enforcer keeps it out of its own template-building mempool and evicts it
from the node's mempool. Miners point at the enforcer's
`getblocktemplate` server and only ever build on rule-compliant blocks.

**This repository is a template.** It ships the full enforcer machinery with
an intentionally empty rule set — every block and transaction is accepted.
Fork it, add your soft-fork's validation logic, and you have a deployable
enforcer that composes with the rest of the CUSF stack.

## What the template provides

- **Chain sync**: headers via Bitcoin Core's REST interface, blocks via
  JSON-RPC (or direct `blk*.dat` reads), reorg handling with automatic
  state rollback (`lib/validator/`).
- **Enforcement plumbing** via the `CusfEnforcer` trait
  (`cusf-enforcer-mempool`): `connect_block` → `invalidateblock` on reject;
  `accept_tx` → mempool filtering; a `getblocktemplate` server for miners.
- **State scaffolding**: LMDB block/header store with a reversible per-block
  diff (`lib/validator/dbs/diff.rs`) — track your rule's state there and
  reorgs undo it automatically. A deterministic consensus-state digest
  (`--verify-consensus-state`) for cross-run consistency checks.
- **Wallet** (BDK; encrypted seed storage) and **mining** support
  (`GenerateToAddress` for regtest, template server for real miners).
- **gRPC API** (connect-rpc): chain queries, block/header info, event
  subscriptions, wallet operations (`proto/cusf/`).
- **Integration test harness** driving real `bitcoind` + enforcer processes
  (`integration_tests/`; `just it-all`).

## Where to add your soft fork

1. Implement validation over transactions and blocks (your own module tree
   under `lib/validator/`).
2. Wire it into `BlockHandler::{validate_tx, connect_block}`
   (`lib/validator/task/mod.rs`) — the fork points are marked with
   comments. Rejecting a block means returning a non-fatal
   `error::ConnectBlock` variant; the driver then has Bitcoin Core
   `invalidateblock` it.
3. Track block-derived state in `dbs::diff::Block` so reorgs roll it back.
4. Add integration trials to `integration_tests/` and wire them into
   `just it-all`.
5. Rename the crates/binary (`cusf_enforcer` → `your_enforcer`) if desired.

To run **several soft forks against one node**, run each fork's enforcer as
its own validator-only process — each independently invalidates blocks that
violate its rules — and point miners at exactly one enforcer's
`getblocktemplate` server.

## Build and test

```bash
just build          # debug build
just test           # fmt + clippy + unit tests (needs cargo-nextest + nightly rustfmt)
just verify         # pre-submit subset without nextest
just setup-core     # download stock Bitcoin Core; write integrationtests.env
just it-all         # integration trials against real bitcoind
```

Requires a stock Bitcoin Core (v29+) with `-rest` enabled, ZMQ
`pubsequence`, and `-txindex` when running with a wallet.

## Lineage

Derived from [`bip300301_enforcer`](https://github.com/LayerTwo-Labs/bip300301_enforcer)
(the BIP300/301 drivechain enforcer) by removing the drivechain rule set and
generalizing the rule plumbing. The BIP360+ enforcer is built from this
template in the same repository history.
