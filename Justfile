# Tooling debt: this file is large (~1k lines). Quality gate (fmt-check → clippy →
# test) is intentional; setup/e2e/multiproc bulk is residual — see
# cusf/RESIDUAL.md ("Justfile sprawl → hermetic Nix"). Desired end state: idiomatic
# hermetic Nix flakes, not bash wrapped by Nix. Prefer scripts/ or flake checks
# over growing new long recipes here.
import? 'local.just'

env_file := env_var_or_default('BIP360P_ENFORCER_INTEGRATION_TEST_ENV', 'integrationtests.env')
enforcer_bin := env_var_or_default('BIP360P_ENFORCER', 'target/debug/bip360p_enforcer')

default:
    @just --list

# Ensure buf is on PATH for generate / lint-proto.
# Local: auto-installs to ~/.local/bin when missing (optional pre-install).
# CI: buf is already present via bufbuild/buf-action.
# fmt: optional — skips with a note if buf is absent (does not call this recipe).
_ensure_buf:
    #!/usr/bin/env bash
    set -euo pipefail
    export PATH="${HOME}/.local/bin:${PATH}"
    if command -v buf >/dev/null 2>&1; then
        exit 0
    fi
    BUF_VERSION="${BUF_VERSION:-1.50.0}"
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
    OS=$(uname -s)
    ARCH=$(uname -m)
    case "$OS" in
        Linux) BUF_OS=Linux ;;
        Darwin) BUF_OS=Darwin ;;
        *)
            echo "error: buf not on PATH and auto-install unsupported on OS=$OS" >&2
            echo "       install: https://buf.build/docs/installation" >&2
            echo "       or: put a buf binary on PATH / in ~/.local/bin" >&2
            exit 1
            ;;
    esac
    case "$ARCH" in
        x86_64) BUF_ARCH=x86_64 ;;
        aarch64|arm64)
            if [ "$BUF_OS" = Darwin ]; then BUF_ARCH=arm64; else BUF_ARCH=aarch64; fi
            ;;
        *)
            echo "error: buf not on PATH and unsupported arch $ARCH for auto-install" >&2
            echo "       install: https://buf.build/docs/installation" >&2
            exit 1
            ;;
    esac
    URL="https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-${BUF_OS}-${BUF_ARCH}"
    echo "buf not on PATH; installing ${BUF_VERSION} → ${INSTALL_DIR}/buf"
    if ! command -v curl >/dev/null 2>&1; then
        echo "error: curl required to auto-install buf" >&2
        echo "       install buf manually: https://buf.build/docs/installation" >&2
        exit 1
    fi
    if ! curl -fsSL -o "${INSTALL_DIR}/buf" "$URL"; then
        echo "error: failed to download buf from:" >&2
        echo "       $URL" >&2
        echo "       install manually: https://buf.build/docs/installation" >&2
        rm -f "${INSTALL_DIR}/buf"
        exit 1
    fi
    chmod +x "${INSTALL_DIR}/buf"
    "${INSTALL_DIR}/buf" --version

# Regenerate checked-in protobuf code (auto-installs buf if needed)
generate: _ensure_buf
    #!/usr/bin/env bash
    set -euo pipefail
    export PATH="${HOME}/.local/bin:${PATH}"
    buf generate --clean

# Lint protos under proto/ (auto-installs buf if needed)
lint-proto: _ensure_buf
    #!/usr/bin/env bash
    set -euo pipefail
    export PATH="${HOME}/.local/bin:${PATH}"
    buf lint proto

# Signet sync benchmark (arg: height or prior consensus-state.json path)
@sync-benchmark-signet target='0':
    #!/usr/bin/env bash
    set -euo pipefail
    target='{{target}}'
    if [[ -f "$target" ]]; then
        echo "Verifying consensus state against reference: $target"
        mode=(--verify-consensus-state "$target")
    else
        echo "Syncing to height: $target"
        mode=(--exit-after-sync="$target")
    fi
    datadir="$(mktemp -d "./datadir-sync-benchmark.XXXXXX")"
    echo "Using fresh data dir: $datadir"
    env RUST_BACKTRACE=1 cargo run --release -- \
        --data-dir "$datadir" \
        --node-rpc-addr=localhost:38332 \
        --node-rpc-user=user \
        --node-rpc-pass=password \
        "${mode[@]}"
    echo "Consensus state written to $datadir/consensus-state.json"

# --- Quality gate (fmt → clippy → tests; check-only, never --fix) ---
# Feature matrices match CI (no --all-features / no reserved shrincs).

# rustfmt --check via nightly (matches rustfmt.toml; no stable spam)
fmt-check:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> fmt-check: cargo +nightly fmt --all -- --check"
    cargo +nightly fmt --all -- --check

# Clippy *check* only — never --fix / --allow-dirty / --allow-staged.
# Workspace clippy + nightly import lint.
_clippy-check:
    cargo clippy --workspace --all-targets -- --deny warnings
    cargo +nightly clippy -- -A clippy::all -D unqualified_local_imports -Zcrate-attr="feature(unqualified_local_imports)"

# Standalone lint: format first, then clippy check (no --fix)
clippy: fmt-check _clippy-check

# Optional auto-fix (writes the tree). Never used by `just test` / CI / clippy.
clippy-fix:
    cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged -- --deny warnings

# Primary gate — single sequential body so order is undeniable and visible:
#   1) fmt-check  2) clippy check (no --fix)  3) cargo-nextest (all cargo unit tests)
# Requires cargo-nextest + nightly rustfmt.
# Bitcoind libtest-mimic example (`integration_tests` harness) is excluded via
# `-E 'not kind(example)'` — run those with `just it` / `it-all` (need Core env).
# Pass-through nextest args: `just test -- --no-fail-fast`
test *args='':
    #!/usr/bin/env bash
    set -euo pipefail
    root='{{ justfile_directory() }}'
    cd "$root"
    echo "==> [1/3] fmt-check (fail on incorrect formatting)"
    cargo +nightly fmt --all -- --check
    echo "==> [2/3] clippy (fail on warnings; check-only, never auto-fix)"
    # Invoke check body only — not `just clippy` (avoids double fmt-check).
    just _clippy-check
    if ! cargo nextest --version >/dev/null 2>&1; then
        echo "error: cargo-nextest required (cargo install cargo-nextest --locked)" >&2
        exit 1
    fi
    echo "==> [3/3] cargo-nextest (every cargo unit test; not bitcoind trials)"
    # Exclude kind(example): only the libtest-mimic bitcoind harness is
    # registered as an example-as-test (needs BITCOIND_*).
    cargo nextest run --workspace --all-targets \
        -E 'not kind(example)' {{ args }}
    echo "==> just test: all stages passed"

# Default developer build.
build *args='':
    cargo build {{ args }}

# --- Hub + rule workers (docs/MULTI_ENFORCER.md) ---
# Hub: bip360p_enforcer (Local feature ballots + optional --rules-worker UDS remotes on hot path).

# Apply rustfmt (nightly) across the workspace.
fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo +nightly fmt --all
    if command -v bunx >/dev/null 2>&1; then
        bunx prettier --write .
    elif command -v npx >/dev/null 2>&1; then
        npx --yes prettier --write .
    else
        echo "note: prettier skipped (install bunx or npx for md/yaml format)" >&2
    fi
    if command -v buf >/dev/null 2>&1; then
        buf format -w proto
    else
        echo "note: buf format skipped (buf not on PATH)" >&2
    fi

# All cargo unit tests (no bitcoind trials).
test-unit:
    cargo test -p bip360p_enforcer_lib

# P2MR / PQC validation unit tests only.
test-pqc:
    cargo test -p bip360p_enforcer_lib pqc::

check-integration-build:
    cargo check --example integration_tests

verify: fmt-check test-unit test-pqc _clippy-check check-integration-build

setup-core:
    #!/usr/bin/env bash
    set -euo pipefail
    REPO_ROOT="$(pwd)"
    GIT_COMMON_DIR="$(git rev-parse --git-common-dir)"
    case "$GIT_COMMON_DIR" in
        /*) ;;
        *) GIT_COMMON_DIR="$REPO_ROOT/$GIT_COMMON_DIR" ;;
    esac
    DEPS_ROOT="$(cd "$GIT_COMMON_DIR/.." && pwd)"
    DEPS_DIR="$DEPS_ROOT/.integration-deps"
    VERSION_FILE="$REPO_ROOT/lib/version.rs"
    ALL_BITCOIN_VERSIONS="$(grep -oE '"[0-9]+\.[0-9]+"' "$VERSION_FILE" | tr -d '"' || true)"
    if [ -z "$ALL_BITCOIN_VERSIONS" ]; then
        echo "Could not parse CI_BITCOIN_CORE_VERSIONS from $VERSION_FILE" >&2
        exit 1
    fi
    BITCOIN_VERSION="${ALL_BITCOIN_VERSIONS%%$'\n'*}"
    UNPATCHED_DIR="$DEPS_DIR/bitcoin-stock-$BITCOIN_VERSION"
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"
    case "$OS-$ARCH" in
        linux-x86_64)  STOCK_TARGET="x86_64-linux-gnu" ;;
        darwin-x86_64) STOCK_TARGET="x86_64-apple-darwin" ;;
        darwin-arm64)  STOCK_TARGET="arm64-apple-darwin" ;;
        *) echo "Unsupported platform: $OS-$ARCH" >&2; exit 1 ;;
    esac
    mkdir -p "$DEPS_DIR"
    if [ ! -x "$UNPATCHED_DIR/bitcoind" ]; then
        echo "Downloading stock Bitcoin Core $BITCOIN_VERSION ($STOCK_TARGET)..."
        TMP=$(mktemp -d)
        trap 'rm -rf "$TMP"' EXIT
        TARBALL="bitcoin-$BITCOIN_VERSION-$STOCK_TARGET.tar.gz"
        curl -# -fL "https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/$TARBALL" -o "$TMP/$TARBALL"
        tar -C "$TMP" -xf "$TMP/$TARBALL"
        rm -rf "$UNPATCHED_DIR"
        mv "$TMP/bitcoin-$BITCOIN_VERSION/bin" "$UNPATCHED_DIR"
        chmod +x "$UNPATCHED_DIR"/bitcoind "$UNPATCHED_DIR"/bitcoin-cli "$UNPATCHED_DIR"/bitcoin-util
        rm -rf "$TMP"
        trap - EXIT
    else
        echo "Stock bitcoin: cached"
    fi
    ENV_FILE="$REPO_ROOT/integrationtests.env"
    {
        echo "BIP360P_ENFORCER='target/debug/bip360p_enforcer'"
        echo "BITCOIND_UNPATCHED='$UNPATCHED_DIR/bitcoind'"
        echo "BITCOIN_CLI='$UNPATCHED_DIR/bitcoin-cli'"
        echo "BITCOIN_UTIL='$UNPATCHED_DIR/bitcoin-util'"
    } > "$ENV_FILE"
    echo
    echo "Wrote $ENV_FILE"
    echo "Deps cache: $DEPS_DIR"
    echo "Run BIP 360 trials with: just demo-a / just it <trial_name>"

# Run one integration trial by name (pass `yes` to auto-setup).
it trial auto='':
    @just _run-it {{trial}} {{auto}}

# Run every integration trial against stock bitcoind.
it-all auto='':
    #!/usr/bin/env bash
    set -euo pipefail
    just build
    export TEMPLATE_SKIP_REBUILD=1
    trials=(
        bip360_wallet_lifecycle
        bip360_enforcement
        bip360_vault_enforcement
        cusf_claim_testmempoolaccept_no_insert
        "unconfirmed_transactions (mode: Mempool, network: Regtest)"
        file_based_block_parser
        generate_to_address
        wallet_less_block_template
        wallet_reorg_multi_block
        wallet_large_gap_sync
        no_secrets_in_logs
    )
    for trial in "${trials[@]}"; do
        echo "==> $trial"
        just _run-it "$trial" "{{auto}}"
    done

[private]
_run-it trial auto_setup='':
    #!/usr/bin/env bash
    set -euo pipefail
    ENV_FILE="{{env_file}}"
    ENFORCER="{{enforcer_bin}}"
    TRIAL="{{trial}}"
    AUTO_SETUP="{{auto_setup}}"
    if [ ! -f "$ENV_FILE" ]; then
        if [ "$AUTO_SETUP" = "yes" ] || [ "$AUTO_SETUP" = "1" ]; then
            echo "WARN: env file $ENV_FILE missing — running just setup-core" >&2
            just setup-core
            ENV_FILE="integrationtests.env"
        else
            echo "env file $ENV_FILE not found — run: just setup-core" >&2
            echo "or re-run with: just it $TRIAL yes" >&2
            exit 1
        fi
    fi
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
    if [ "${TEMPLATE_SKIP_REBUILD:-}" != "1" ]; then
        echo "==> building enforcer binaries"
        just build
    fi
    export BIP360P_ENFORCER_INTEGRATION_TEST_ENV="$ENV_FILE"
    export BIP360P_ENFORCER="$ENFORCER"
    if [ -n "${BITCOIND_UNPATCHED:-}" ] && [ -x "${BITCOIND_UNPATCHED}" ]; then
        export BITCOIND="${BITCOIND_UNPATCHED}"
        export BITCOIN_CLI="$(dirname "$BITCOIND_UNPATCHED")/bitcoin-cli"
        export BITCOIN_UTIL="$(dirname "$BITCOIND_UNPATCHED")/bitcoin-util"
        echo "==> using stock bitcoind: $BITCOIND"
    elif [ -z "${BITCOIND:-}" ] || [ ! -x "$BITCOIND" ]; then
        echo "BITCOIND_UNPATCHED not set or not executable — run: just setup-core" >&2
        exit 1
    fi
    echo "==> running integration trial: $TRIAL"
    cargo run --example integration_tests -- --exact "$TRIAL"

verify-reflection:
    #!/usr/bin/env bash
    set -euo pipefail
    ENFORCER="{{enforcer_bin}}"
    BITCOIND="${BITCOIND:-bitcoind}"
    BITCOIND_RPC_PORT=18943
    BITCOIND_ZMQ_PORT=18944
    ENFORCER_GRPC_PORT=18945
    GRPC_ADDR="127.0.0.1:$ENFORCER_GRPC_PORT"
    for tool in grpcurl buf; do
        command -v "$tool" >/dev/null || { echo "missing required command: $tool" >&2; exit 1; }
    done
    if [ ! -x "$BITCOIND" ] && ! command -v "$BITCOIND" >/dev/null; then
        echo "missing or not executable bitcoind: $BITCOIND" >&2
        exit 1
    fi
    if [ ! -x "$ENFORCER" ]; then
        echo "missing or not executable enforcer: $ENFORCER" >&2
        exit 1
    fi
    WORK_DIR="$(mktemp -d)"
    BITCOIND_PID=""
    ENFORCER_PID=""
    cleanup() {
        [ -n "$ENFORCER_PID" ] && kill "$ENFORCER_PID" 2>/dev/null || true
        [ -n "$BITCOIND_PID" ] && kill "$BITCOIND_PID" 2>/dev/null || true
        wait 2>/dev/null || true
        rm -rf "$WORK_DIR"
    }
    trap cleanup EXIT
    wait_for_port() {
        local port="$1" name="$2"
        for _ in $(seq 1 100); do
            if (exec 3<> "/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
                exec 3>&- 3<&-
                return 0
            fi
            sleep 0.2
        done
        echo "$name did not open port $port in time" >&2
        return 1
    }
    fail() {
        echo "FAIL: $1" >&2
        cat "$WORK_DIR/enforcer.log" >&2
        exit 1
    }
    mkdir -p "$WORK_DIR/bitcoind"
    "$BITCOIND" -regtest -datadir="$WORK_DIR/bitcoind" -rpcport="$BITCOIND_RPC_PORT" \
        -rpcuser=reflection -rpcpassword=verify \
        -zmqpubsequence="tcp://127.0.0.1:$BITCOIND_ZMQ_PORT" -listen=0 -server=1 -rest=1 \
        >"$WORK_DIR/bitcoind.log" 2>&1 &
    BITCOIND_PID=$!
    wait_for_port "$BITCOIND_RPC_PORT" bitcoind
    "$ENFORCER" --data-dir "$WORK_DIR/enforcer" \
        --node-rpc-addr="127.0.0.1:$BITCOIND_RPC_PORT" --node-rpc-user=reflection \
        --node-rpc-pass=verify --node-zmq-addr-sequence="tcp://127.0.0.1:$BITCOIND_ZMQ_PORT" \
        --serve-grpc-addr="$GRPC_ADDR" >"$WORK_DIR/enforcer.log" 2>&1 &
    ENFORCER_PID=$!
    wait_for_port "$ENFORCER_GRPC_PORT" enforcer || { cat "$WORK_DIR/enforcer.log" >&2; exit 1; }
    # ListServices advertises what this process actually mounted, not
    # everything in the descriptor pool. The enforcer above runs on regtest
    # with neither --enable-wallet nor --enable-block-template-server, so
    # WalletService and BlockProducerService are absent while MiningService
    # (regtest) is present.
    EXPECTED_SERVICES="$(printf '%s\n' \
        'cusf.crypto.v1.CryptoService' \
        'cusf.mainchain.v1.MiningService' \
        'cusf.mainchain.v1.ValidatorService')"
    ACTUAL_SERVICES="$(grpcurl -plaintext "$GRPC_ADDR" list | sort)"
    [ "$ACTUAL_SERVICES" = "$EXPECTED_SERVICES" ] || fail "grpcurl list returned unexpected services"
    grpcurl -plaintext "$GRPC_ADDR" describe cusf.mainchain.v1.ValidatorService \
        | grep -q GetBlockHeaderInfo || fail "grpcurl describe is missing GetBlockHeaderInfo"
    RIPEMD_REQUEST='{"msg":{"hex":"616263"}}'
    RIPEMD_DIGEST='8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'
    grpcurl -plaintext -d "$RIPEMD_REQUEST" "$GRPC_ADDR" cusf.crypto.v1.CryptoService/Ripemd160 \
        | grep -q "$RIPEMD_DIGEST" || fail "grpcurl Ripemd160 returned wrong digest"
    buf curl --protocol grpc --http2-prior-knowledge -d "$RIPEMD_REQUEST" \
        "http://$GRPC_ADDR/cusf.crypto.v1.CryptoService/Ripemd160" \
        | grep -q "$RIPEMD_DIGEST" || fail "buf curl (grpc) returned wrong digest"
    buf curl --protocol connect --http2-prior-knowledge --reflect-protocol grpc-v1alpha \
        -d "$RIPEMD_REQUEST" "http://$GRPC_ADDR/cusf.crypto.v1.CryptoService/Ripemd160" \
        | grep -q "$RIPEMD_DIGEST" || fail "buf curl (connect) returned wrong digest"
    echo "OK: reflection verified with grpcurl + buf curl"

# Optional upstream dev tools (scripts/ retained from upstream).

analyze-sync log:
    uv run scripts/analyze_sync_logs.py {{log}}

trace-macos:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "$(uname -s)" != "Darwin" ]; then
        echo "trace-macos is macOS-only (uses dtrace)" >&2
        exit 1
    fi
    exec ./scripts/trace_enforcer_macos.sh









# Claim pins: testmempoolaccept no-insert; stock rejects P2MR spend
cusf-claims auto='':
    #!/usr/bin/env bash
    set -euo pipefail
    ENV_FILE="{{env_file}}"
    if [ -f "$ENV_FILE" ]; then
        set -a
        # shellcheck disable=SC1090
        source "$ENV_FILE"
        set +a
    fi
    cargo build -p bip360p_enforcer
    cargo build --example integration_tests
    export BIP360P_ENFORCER_INTEGRATION_TEST_ENV="{{env_file}}"
    export BIP360P_ENFORCER="{{enforcer_bin}}"
    export TEMPLATE_SKIP_REBUILD=1
    just _run-it cusf_claim_testmempoolaccept_no_insert "{{auto}}"
    just _run-it cusf_claim_stock_rejects_p2mr_spend "{{auto}}"
