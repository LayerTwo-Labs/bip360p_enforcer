# CUSF BIP 360 Enforcer

This document describes the BIP 360 (P2MR + post-quantum cryptography)
enforcement layer. It is the enforcer's sole consensus rule set — there is no
drivechain code and no feature flag: P2MR output validation, PQC signature
verification (`validator/pqc/`), and the `bitcoin-p2mr-pqc` / `bitcoinpqc`
dependencies are all built unconditionally.

The enforcer validates the four P2MR spend schemes — Schnorr, ML-DSA-44,
SLH-DSA-SHA2-128s, and hybrid EC+SLH — against a plain, unpatched Bitcoin Core
node.

## Activation height

BIP 360 rules apply at and after `--activation-height` (default `0` on regtest).

```bash
cargo run --features bip360 -- --activation-height 100 ...
cargo run --features bip360 -- --pqc-verify-budget-ms 500 ...
```

### Per-block PQC verify budget

During `connect_block`, ML-DSA and SLH-DSA verification wall time is accumulated
across the block. When the budget is exceeded, further signature checks in that
block are rejected (`BlockVerifyBudgetExhausted` for any scheme;
`PqcVerifyBudgetExceeded` when a PQC verify pushes elapsed time over the limit).

| Setting                     | Default | CLI flag                 |
| --------------------------- | ------- | ------------------------ |
| Per-block PQC verify budget | 500 ms  | `--pqc-verify-budget-ms` |

**Mempool vs block asymmetry:** `accept_tx` (mempool) does **not** apply the
per-block budget (`pqc_budget` is unset). A transaction can pass mempool
validation and still cause block rejection when batched with other PQC spends
that exhaust the block budget.

## Overloaded tapscript signature opcodes (no OP_SUBSTR)

P2MR leaves reuse existing BIP 342 tapscript signature-check opcodes — no new
opcode numbers and no `OP_SUBSTR` (0x7f) as a PQ algorithm tag:

| Opcode                   | Byte | Role                                                                      |
| ------------------------ | ---- | ------------------------------------------------------------------------- |
| `OP_CHECKSIG`            | 0xac | Primary overloaded verifier                                               |
| `OP_CHECKSIGVERIFY`      | 0xad | Same as `OP_CHECKSIG`, fails on invalid sig                               |
| `OP_CHECKSIGADD`         | 0xba | Overloaded verifier (one sig site per opcode; see BIP342 deviation below) |
| `OP_CHECKMULTISIG`       | 0xae | N-site overload (`OP_0 PUSH pk… OP_N`); **not** Bitcoin M-of-N            |
| `OP_CHECKMULTISIGVERIFY` | 0xaf | Same as `OP_CHECKMULTISIG`, fails on invalid sig                          |

### BIP342 deviations (CUSF overload model)

**`OP_CHECKSIGADD`:** BIP342 pops `(pubkey, accumulator, sig)` from the stack
and increments the accumulator on success (MuSig2-style scripts). The CUSF
overload model treats each `OP_CHECKSIGADD` like `OP_CHECKSIG`: one preceding
pubkey push and one witness signature per site. Key-aggregation scripts that
rely on stack semantics are not supported.

**`OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY`:** Bitcoin classic multisig is
**M-of-N** (witness supplies M ≤ N signatures). The CUSF overload model requires
**exactly N witness signatures** for the N pubkey pushes before `OP_N` — each
(pubkey, sig) pair is verified independently via size-gated duck typing.
Example: `OP_0 PUSH pk₁ PUSH pk₂ OP_2 OP_CHECKMULTISIG` requires **two** witness
sigs (not one for 1-of-2). Only the last N pubkey pushes before `OP_N` are used.

At each signature-check site the enforcer
(`schemes::verify_overloaded_checksig`):

1. Extracts the pubkey from the immediately preceding push
   (`PUSH <pk> OP_CHECKSIG`).
2. **Signature size** (witness element, in script order) classifies the
   verifier: 64 → Schnorr, ~2420 → ML-DSA-44, ~7856 → SLH-DSA-SHA2-128s.
3. **Pubkey size** is checked for consistency with the classified scheme (32 B
   for Schnorr/SLH; 1312 B for ML-DSA-44). Mismatches are rejected.
4. Parses optional trailing sighash byte (defaults to `SIGHASH_DEFAULT` for bare
   64-byte Schnorr).
5. Recomputes tapscript sighash with the parsed type and verifies.

| Sig size (bytes) | Algorithm                   | Pubkey size |
| ---------------- | --------------------------- | ----------- |
| 64               | BIP 340 Schnorr (secp256k1) | 32          |
| ~2420            | ML-DSA-44 (FIPS 204)        | 1312        |
| ~7856            | SLH-DSA-SHA2-128s           | 32          |

**Hybrid EC+PQ in one leaf** uses multiple `OP_CHECKSIG` call sites (not one
opcode verifying both keys):

```text
PUSH32 <ec_pk> OP_CHECKSIG
PUSH32 <slh_pk> OP_CHECKSIG
OP_BOOLAND OP_VERIFY
```

Witness (bottom → top): `[ec_sig, slh_sig, leaf_script, control_block]` —
signatures are consumed in script execution order. Hybrid EC+SLH is the heaviest
supported leaf: total signature WU = **7_920** (64 + 7856), comfortably under
the per-input cap of **12_288 WU** (`MAX_PQC_SIG_WU_PER_INPUT` in `limits.rs`).

**Exclusion** (different algorithms in different leaves) is a wallet/miner
concern; the enforcer validates whichever leaf is revealed.

Leaf scripts containing `OP_SUBSTR` as an opcode are rejected.

## Stock Bitcoin Core deployment model

The enforcer runs alongside **one unmodified `bitcoind`** (no consensus
patches):

1. **ZMQ `sequence`** — the mempool enforcer (`cusf-enforcer-mempool`) watches
   the mainchain tip and receives new block/tx notifications.
2. **`getblock` / block connect** — the validator's
   `CusfEnforcer::connect_block` applies CUSF rules (drivechain and/or BIP 360,
   per Cargo features).
3. **`submitblock`** — integration tests and miners submit candidate blocks to
   Core; Core accepts them into its chain view initially.
4. **`invalidateblock`** — when the enforcer rejects a connected block, the
   mempool adapter calls `invalidateblock` so the strict enforcer view diverges
   from stock Core's permissive validation.

Stock Core validates standard rules only; the enforcer adds CUSF constraints on
top.

## Enforcement points

- **Block connect** (`connect_block`): validates all non-coinbase txs in the
  block, merging a persistent P2MR UTXO set (confirmed prior blocks) with
  intra-block outputs. Spends of confirmed non-P2MR UTXOs from earlier blocks
  are not re-validated (prevout not in map → skip).
- **Mempool** (`accept_tx`): validates with explicit parent transactions from
  the mempool adapter.
- Rejection causes `invalidateblock` (blocks) or tx reject (mempool), consistent
  with existing CUSF enforcer behavior.

## Dependencies

- `bitcoin-p2mr-pqc` — P2MR types and merkle/control-block helpers (git pin:
  [cryptoquick/rust-bitcoin](https://github.com/cryptoquick/rust-bitcoin) `p2mr`
  @ `9093253a` / `0.32.6-p2mr-pqc.1`)
- `bitcoinpqc` — Schnorr + ML-DSA-44 + SLH-DSA-SHA2-128s verification (git pin:
  [cryptoquick/libbitcoinpqc-bindings](https://github.com/cryptoquick/libbitcoinpqc-bindings)
  PR [#1](https://github.com/cryptoquick/libbitcoinpqc-bindings/pull/1)
  `wasm-tests` @ `5ef7067`; native `libbitcoinpqc` submodule @ `b309f44` from
  [cryptoquick/libbitcoinpqc](https://github.com/cryptoquick/libbitcoinpqc) PR
  [#29](https://github.com/cryptoquick/libbitcoinpqc/pull/29))

No Kellnr / `crates.denver.space` required.

## Module layout

```
lib/validator/pqc/
  activation.rs   # activation height gating
  limits.rs       # consensus size limits
  p2mr_output.rs  # P2MR scriptPubKey validation
  merkle.rs       # control block / merkle path checks
  leaf_script.rs  # tapscript walker + sig-site extraction
  schemes.rs      # overloaded checksig verification
  spend.rs            # witness stack + spend validation
  p2mr_utxo.rs        # P2MR UTXO diff for block connect / disconnect
  signer.rs           # single-leaf P2MR spend construction (wallet + tests)
  mod.rs              # public entry points

lib/validator/dbs/
  p2mr_utxos.rs   # redb table: OutPoint → TxOut for confirmed P2MR outputs
```

## Implementation status

| Component                                                              | Status                                                               |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------- |
| P2MR output + merkle + control block validation                        | Done                                                                 |
| Leaf script walker + `OP_SUBSTR` rejection                             | Done                                                                 |
| `verify_overloaded_checksig` (Schnorr, ML-DSA-44, SLH-DSA-SHA2-128s)   | Done                                                                 |
| Hybrid EC+PQ (multi-site `OP_CHECKSIG` + `OP_BOOLAND OP_VERIFY`)       | Done                                                                 |
| `OP_CHECKSIGADD` / `OP_CHECKMULTISIG*`                                 | Done                                                                 |
| DoS limits (witness stack, sig WU, per-block PQC budget)               | Done                                                                 |
| Sighash matrix tests (non-`ALL` types, all schemes)                    | Done                                                                 |
| `connect_block` intra-block UTXO map                                   | Done                                                                 |
| Cross-block P2MR prevout lookup                                        | Done — `dbs/p2mr_utxos.rs` + incremental block validation            |
| Mempool `accept_tx` with explicit parents                              | Done                                                                 |
| Unit tests (`cargo test -p bip360p_enforcer_lib pqc::`)                | Done — per-scheme sign/verify roundtrips + rejection matrix          |
| Wallet lifecycle (create → receive → spend → mine → validate)          | Done — `SpendP2mr` + block-producer suffix injection                 |
| Integration trial `bip360_wallet_lifecycle` (four schemes, plain Core) | Live **PASS** — create/fund/spend/mine/validate for all four schemes |

## Verification

```bash
cargo test -p bip360p_enforcer_lib pqc::          # per-scheme roundtrips + rejection matrix
just verify                                    # fmt-check, clippy, unit + pqc tests, integration-build
BIP360P_ENFORCER_INTEGRATION_TEST_ENV=$PWD/integration_tests/example.env \
  just it bip360_wallet_lifecycle              # full four-scheme E2E vs plain bitcoind
```

The `bip360_wallet_lifecycle` trial creates a P2MR address for each of the four
schemes, funds it from the enforcer wallet, spends it via `SpendP2mr` (injected
into the enforcer's own block template), mines the block on a plain Bitcoin Core
node, and asserts the enforcer validates the spend and drops the output from the
P2MR UTXO set. Negative paths (tampered signatures, wrong pubkey size, bad
merkle path, forbidden opcodes, budget exhaustion) are covered by the `pqc::`
unit-test rejection matrix.
