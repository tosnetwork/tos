#!/usr/bin/env bash
# =============================================================================
# tos.cmd — hive client entrypoint for the TOS validator
# =============================================================================
#
# Hive contract (see https://github.com/ethereum/hive/blob/master/docs/clients.md):
#   - Hive places a /genesis.json (geth-format) before starting us.
#   - Hive may set HIVE_* env vars to override chain parameters.
#   - We MUST start a JSON-RPC server on TCP 8545 (HIVE_CHECK_LIVE_PORT)
#     and stay in the foreground.
#   - Hive considers us ready when 8545 accepts a TCP connection.
#   - exit code 0 = clean shutdown; non-zero = simulator records a fail.
#
# Recognised HIVE_* variables (subset hive's rpc-compat actually sends):
#   HIVE_CHAIN_ID         decimal chain id (default: 0x544F53 / 5525331)
#   HIVE_NETWORK_ID       decimal network id (we map this to chain id)
#   HIVE_NODETYPE         "full" | "archive" (we always run as archive-equiv)
#   HIVE_LOGLEVEL         0..5 (we map directly to validator-engine -v)
#   HIVE_CHECK_LIVE_PORT  TCP port hive probes for readiness (default: 8545)
#   HIVE_FORK_HOMESTEAD … HIVE_FORK_PRAGUE
#                         block-number / time activation per fork
#   HIVE_GENESIS_*        genesis header overrides (see mapper.jq)
#
# Two operating modes (selected by env):
#   1. TOS_PROXY_UPSTREAM=<host:port>    — proxy mode: forward 8545 to an
#                                          upstream TOS RPC.  Used for
#                                          end-to-end pipeline demos.
#   2. (default)                          — full validator: build single-node
#                                          state and run tos-validator-engine.
#
# The proxy mode lets the Hive simulator drive a real TOS chain without the
# full single-node bootstrap (which is not yet wired — see README "Gap"
# table).  When TOS_PROXY_UPSTREAM is unset, the script attempts the full
# init flow but will exit non-zero if the prerequisites for a single-node
# chain are absent.
# =============================================================================

set -euo pipefail

DATA="${TOS_DATA:-/data}"
FIFT_DIR="${TOS_FIFT_DIR:-/usr/local/share/tos/fift/lib}"
RPC_BIND_PORT="${HIVE_CHECK_LIVE_PORT:-8545}"
RPC_BIND="${TOS_JSONRPC_BIND:-0.0.0.0:${RPC_BIND_PORT}}"
SYNC_DELAY="${TOS_INITIAL_SYNC_DELAY:-0}"
LOGLEVEL="${HIVE_LOGLEVEL:-3}"

# Default chain id matches the live TOS testnet (0x544F53 == 5525331).
HIVE_CHAIN_ID="${HIVE_CHAIN_ID:-5525331}"
HIVE_NETWORK_ID="${HIVE_NETWORK_ID:-${HIVE_CHAIN_ID}}"

mkdir -p "$DATA" "$DATA/keyring" "$DATA/static" "$DATA/session-logs"

log() { printf '[tos.cmd] %s\n' "$*" >&2; }

# Convert "0x..." to decimal.  Hive sometimes hands chain ids as hex.
hex2dec() {
    local v="$1"
    if [[ "$v" =~ ^0[xX] ]]; then
        printf '%d\n' "$v"
    else
        printf '%s\n' "$v"
    fi
}

CHAIN_ID_DEC="$(hex2dec "$HIVE_CHAIN_ID")"
NETWORK_ID_DEC="$(hex2dec "$HIVE_NETWORK_ID")"

# -----------------------------------------------------------------------------
# Fork policy.  Reject anything later than what the validator implements.
# Today: London-equivalent (EIP-1559 base-fee on chain).  Shanghai/Cancun/
# Prague are not yet supported and we exit non-zero so the simulator marks
# the test as un-runnable rather than silently passing.
# -----------------------------------------------------------------------------
SUPPORTED_LATEST="london"
for unsupported in HIVE_FORK_PRAGUE HIVE_FORK_CANCUN HIVE_FORK_SHANGHAI; do
    if [ -n "${!unsupported:-}" ]; then
        log "ERROR: $unsupported requested but TOS validator only supports up to $SUPPORTED_LATEST"
        log "       Set TOS_FORK_RELAX=1 to override (proxy mode only)."
        if [ -z "${TOS_FORK_RELAX:-}" ] && [ -z "${TOS_PROXY_UPSTREAM:-}" ]; then
            exit 64  # EX_USAGE
        fi
        log "       Continuing because TOS_FORK_RELAX=1 or proxy mode is active."
    fi
done

# -----------------------------------------------------------------------------
# 1) Translate hive's geth-format /genesis.json into our intermediate JSON.
#    The intermediate JSON documents what the future tos-create-state init
#    helper would consume; for now mapper.jq writes it to disk and we log
#    its summary so debugging the gap is easier.
# -----------------------------------------------------------------------------
GENESIS_IN="${HIVE_GENESIS_PATH:-/genesis.json}"
ZEROSTATE_OUT="$DATA/zerostate.json"

if [ -f "$GENESIS_IN" ]; then
    log "Mapping hive genesis $GENESIS_IN -> $ZEROSTATE_OUT"
    jq -f /etc/tos/mapper.jq \
        --arg chain_id "$CHAIN_ID_DEC" \
        --arg network_id "$NETWORK_ID_DEC" \
        "$GENESIS_IN" > "$ZEROSTATE_OUT"
    log "  chain_id=$CHAIN_ID_DEC network_id=$NETWORK_ID_DEC"
    log "  alloc_count=$(jq '.alloc | length' "$ZEROSTATE_OUT")"
else
    log "No $GENESIS_IN provided; using built-in single-validator template (chainId=$CHAIN_ID_DEC)"
    jq --arg chain_id "$CHAIN_ID_DEC" \
       --arg network_id "$NETWORK_ID_DEC" \
       '.chain_id = ($chain_id | tonumber) | .network_id = ($network_id | tonumber) | .fork_config.chainId = ($chain_id | tonumber)' \
       /etc/tos/genesis.tmpl.json > "$ZEROSTATE_OUT"
fi

# -----------------------------------------------------------------------------
# 2) Mode dispatch.
# -----------------------------------------------------------------------------
if [ -n "${TOS_PROXY_UPSTREAM:-}" ]; then
    log "MODE: proxy"
    log "      forwarding ${RPC_BIND} -> ${TOS_PROXY_UPSTREAM}"
    # The proxy mode demonstrates the Hive harness end-to-end: the simulator
    # talks to *us* (this container) on 8545; we forward to a real TOS RPC
    # already running elsewhere.  This is the working path until a true
    # single-node TOS bootstrap is wired (see README "Gap" table).
    exec /usr/local/bin/tos-rpc-proxy.py \
        --listen "${RPC_BIND}" \
        --upstream "${TOS_PROXY_UPSTREAM}" \
        --ready-marker "TOS-VALIDATOR-READY"
fi

# -----------------------------------------------------------------------------
# 3) Full single-node validator path.
#    NOT YET FUNCTIONAL — the TOS validator currently requires a 4-validator
#    consensus topology and a pre-built zerostate.  A real init step needs
#    to: (a) generate validator keys via tos-genkey, (b) build zerostate
#    via tos-create-state from the mapped genesis, (c) emit tos-global.json
#    pointing at the local DHT.  See README "Gap" for the engineering
#    estimate.
#
#    For now we still attempt to launch (so the surface is reachable for
#    debugging), but tag the WARNING clearly.
# -----------------------------------------------------------------------------
log "MODE: full validator (single-node, EXPERIMENTAL — see README)"

if [ ! -f "$DATA/config.json" ]; then
    log "WARNING: $DATA/config.json missing — emitting empty stub."
    log "         The validator will bind ${RPC_BIND} but will not produce blocks"
    log "         (no zerostate, no peers, no consensus).  This is a known gap."
    cat > "$DATA/config.json" <<'JSON'
{ "@type": "engine.validator.config", "out_port": 0,
  "addrs": [], "adnl": [], "validators": [],
  "fullnodeslaves": [], "fullnodemasters": [],
  "liteservers": [], "control": [], "shards_to_monitor": [],
  "gc": {"@type": "engine.validator.gc", "ids": []} }
JSON
fi

if [ ! -f "$DATA/tos-global.json" ]; then
    log "WARNING: $DATA/tos-global.json missing — copying empty stub"
    echo '{}' > "$DATA/tos-global.json"
fi

# Background readiness watcher: poll RPC, log a clear marker once it's up so
# operators can grep logs.  (Hive itself only watches the TCP port, but the
# marker helps debugging.)
(
    for i in $(seq 1 60); do
        sleep 1
        if curl -fsS -X POST -H 'Content-Type: application/json' \
                -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
                "http://127.0.0.1:${RPC_BIND_PORT}" >/dev/null 2>&1; then
            log "TOS-VALIDATOR-READY (eth_chainId responsive after ${i}s)"
            exit 0
        fi
    done
    log "TOS-VALIDATOR-NOT-READY (eth_chainId not responsive after 60s)"
) &

log "Starting tos-validator-engine on $RPC_BIND (sync-delay=$SYNC_DELAY, log=$LOGLEVEL)"

exec /usr/local/bin/tos-validator-engine \
    -C "$DATA/tos-global.json" \
    -c "$DATA/config.json" \
    -D "$DATA" \
    -f "$FIFT_DIR" \
    -l "$DATA/log" \
    -t 4 \
    -v "$LOGLEVEL" \
    --initial-sync-delay "$SYNC_DELAY" \
    --session-logs "$DATA/session-logs" \
    --quic-flood-control -1 \
    --json-rpc-address "$RPC_BIND" \
    --json-rpc-cors-origin "*"
