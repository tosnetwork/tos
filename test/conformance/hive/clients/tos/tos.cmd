#!/usr/bin/env bash
# =============================================================================
# tos.cmd — hive client entrypoint for the TOS validator
# =============================================================================
#
# Hive contract (see https://github.com/ethereum/hive/blob/master/docs/clients.md):
#   - The simulator places a genesis.json at /genesis.json before starting us.
#   - The simulator may set HIVE_* env vars to override chain parameters.
#   - We MUST start a JSON-RPC server on TCP 8545 and stay in the foreground.
#   - exit code 0 = clean shutdown; non-zero = test framework records a fail.
#
# Recognised HIVE_* variables (subset hive's rpc-compat actually depends on):
#   HIVE_CHAIN_ID         decimal chain id
#   HIVE_NETWORK_ID       decimal network id (we map this to chain id)
#   HIVE_NODETYPE         "full" | "archive" (we always run as archive-equiv)
#   HIVE_LOGLEVEL         0..5 (we map directly to validator-engine -v)
#   HIVE_GENESIS_TIMESTAMP, HIVE_GENESIS_GASLIMIT, HIVE_GENESIS_DIFFICULTY,
#   HIVE_GENESIS_COINBASE, HIVE_GENESIS_NONCE, HIVE_GENESIS_MIXHASH,
#   HIVE_GENESIS_BASEFEE, HIVE_GENESIS_EXTRADATA   — passed via mapper.jq
#   HIVE_FORK_HOMESTEAD, HIVE_FORK_BYZANTIUM, HIVE_FORK_LONDON, ...
#                         — fork activation block numbers (mapper.jq stub)
# =============================================================================

set -euo pipefail

DATA="${TOS_DATA:-/data}"
FIFT_DIR="${TOS_FIFT_DIR:-/usr/local/share/tos/fift/lib}"
RPC_BIND="${TOS_JSONRPC_BIND:-0.0.0.0:8545}"
SYNC_DELAY="${TOS_INITIAL_SYNC_DELAY:-0}"
LOGLEVEL="${HIVE_LOGLEVEL:-3}"

mkdir -p "$DATA" "$DATA/keyring" "$DATA/static" "$DATA/session-logs"

log() { printf '[tos.cmd] %s\n' "$*" >&2; }

# -----------------------------------------------------------------------------
# 1) Translate hive's genesis.json -> a TOS zerostate config.
# -----------------------------------------------------------------------------
GENESIS_IN="${HIVE_GENESIS_PATH:-/genesis.json}"
ZEROSTATE_OUT="$DATA/zerostate.json"

if [ -f "$GENESIS_IN" ]; then
    log "Mapping hive genesis $GENESIS_IN -> $ZEROSTATE_OUT"
    # mapper.jq is responsible for the schema translation. It is currently
    # a stub that emits a minimal single-validator zerostate; see TODO list
    # in mapper.jq itself.
    jq -f /usr/local/bin/mapper.jq \
        --arg chain_id "${HIVE_CHAIN_ID:-1}" \
        --arg network_id "${HIVE_NETWORK_ID:-${HIVE_CHAIN_ID:-1}}" \
        "$GENESIS_IN" > "$ZEROSTATE_OUT"
else
    log "No $GENESIS_IN provided; using built-in single-validator template"
    cp /etc/tos/genesis.tmpl.json "$ZEROSTATE_OUT"
fi

# -----------------------------------------------------------------------------
# 2) Initialise the validator-engine state directory if needed.
#    TODO: real flow is `tos-create-state` + `tos-genkey` to produce keyring
#          and zerostate file_hashes. For the scaffold we assume the operator
#          (or a future init-container) has done this already and dropped
#          ready-to-go {config.json, keyring/, static/} into $DATA before we
#          run. The block below is a placeholder that fails loudly so the
#          missing wiring is obvious.
# -----------------------------------------------------------------------------
if [ ! -f "$DATA/config.json" ]; then
    log "WARNING: $DATA/config.json missing — generating a stub via tos-create-state"
    log "         This is NOT production-grade; it must be replaced with a real"
    log "         hive-genesis-driven init step before rpc-compat will pass."
    # TODO(phase-g.3): invoke tos-create-state with parameters derived from
    # HIVE_GENESIS_* + the mapper.jq output.
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
    # TODO(phase-g.3): a real global config requires DHT static_nodes +
    # zerostate root_hash/file_hash. Until this is wired, the validator will
    # bind 8545 but never produce blocks. rpc-compat read methods that don't
    # require a tip (eth_chainId, web3_clientVersion, net_version) will still
    # answer; anything block-dependent will error.
    echo '{}' > "$DATA/tos-global.json"
fi

# -----------------------------------------------------------------------------
# 3) Launch the validator with JSON-RPC bound on hive's expected port.
# -----------------------------------------------------------------------------
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
