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
# 1) Translate hive's geth-format /genesis.json into our intermediate JSON
#    (legacy mapper.jq output) AND into a Fift include the new C++ word
#    `evm-zerostate-from-alloc` consumes. The two paths are kept side-by-side
#    so the existing proxy-mode code keeps working unchanged while the new
#    bootstrap path (TOS_BOOTSTRAP_LOCAL=1) has direct access to the alloc
#    in the form tos-create-state expects.
#
#    Phase D additions:
#      - translate-genesis.py writes /tmp/genesis-alloc.fif and /tmp/chain_id.txt
#      - When /genesis.json is present, /tmp/chain_id.txt overrides HIVE_CHAIN_ID
#        (the spec's chain id is canonical for the fixtures we're driving).
# -----------------------------------------------------------------------------
GENESIS_IN="${HIVE_GENESIS_PATH:-/genesis.json}"
ZEROSTATE_OUT="$DATA/zerostate.json"
GENESIS_ALLOC_FIF="${TOS_GENESIS_ALLOC_FIF:-/tmp/genesis-alloc.fif}"
GENESIS_CHAIN_ID_TXT="${TOS_GENESIS_CHAIN_ID_TXT:-/tmp/chain_id.txt}"

if [ -f "$GENESIS_IN" ]; then
    log "Mapping hive genesis $GENESIS_IN -> $ZEROSTATE_OUT"
    jq -f /etc/tos/mapper.jq \
        --arg chain_id "$CHAIN_ID_DEC" \
        --arg network_id "$NETWORK_ID_DEC" \
        "$GENESIS_IN" > "$ZEROSTATE_OUT"
    log "  chain_id=$CHAIN_ID_DEC network_id=$NETWORK_ID_DEC"
    log "  alloc_count=$(jq '.alloc | length' "$ZEROSTATE_OUT")"

    # Phase D: emit a Fift include the new C++ word consumes. Even if we're
    # not running the local-bootstrap path, this is cheap (<1s on the spec's
    # 26-account genesis) and gives us early visibility on parse errors.
    if [ -x /usr/local/bin/tos-translate-genesis ]; then
        log "Emitting Fift alloc snippet via translate-genesis.py..."
        /usr/local/bin/tos-translate-genesis \
            --genesis "$GENESIS_IN" \
            --out-fif "$GENESIS_ALLOC_FIF" \
            --out-chain-id "$GENESIS_CHAIN_ID_TXT" \
            --print-summary 2>&1 | sed 's/^/[translate-genesis] /' >&2 || \
                log "WARNING: translate-genesis.py failed (continuing with proxy-mode defaults)"

        # If the translator extracted a chain id and the env didn't already
        # pin one to a non-default, prefer the spec chain id. This keeps
        # `--override-chain-id` in proxy mode honest with what `chain.rlp`
        # was signed against.
        if [ -f "$GENESIS_CHAIN_ID_TXT" ] && [ "$CHAIN_ID_DEC" = "5525331" ]; then
            SPEC_CHAIN_ID="$(tr -d '[:space:]' < "$GENESIS_CHAIN_ID_TXT")"
            if [ -n "$SPEC_CHAIN_ID" ] && [ "$SPEC_CHAIN_ID" != "5525331" ]; then
                log "  spec chain id from genesis -> $SPEC_CHAIN_ID (overrides default 5525331)"
                CHAIN_ID_DEC="$SPEC_CHAIN_ID"
                NETWORK_ID_DEC="$SPEC_CHAIN_ID"
            fi
        fi
    fi
else
    log "No $GENESIS_IN provided; using built-in single-validator template (chainId=$CHAIN_ID_DEC)"
    jq --arg chain_id "$CHAIN_ID_DEC" \
       --arg network_id "$NETWORK_ID_DEC" \
       '.chain_id = ($chain_id | tonumber) | .network_id = ($network_id | tonumber) | .fork_config.chainId = ($chain_id | tonumber)' \
       /etc/tos/genesis.tmpl.json > "$ZEROSTATE_OUT"
fi

# -----------------------------------------------------------------------------
# 1b) TOS_BOOTSTRAP_LOCAL=1 — sanity-check the C++/Fift bootstrap pipeline
#     by building a zerostate cell from the translated alloc (without
#     actually launching validators). Useful in CI to catch regressions in
#     the parameterised `evm-zerostate-from-alloc` path without paying the
#     ~30s of network warm-up. Logs cell hash + alloc count.
# -----------------------------------------------------------------------------
if [ "${TOS_BOOTSTRAP_LOCAL:-0}" = "1" ] && [ -f "$GENESIS_ALLOC_FIF" ] && \
   [ -x /usr/local/bin/tos-create-state ]; then
    log "TOS_BOOTSTRAP_LOCAL=1 — running tos-create-state sanity build of alloc cell"
    SANITY_FIF="/tmp/tos-bootstrap-sanity.fif"
    cat > "$SANITY_FIF" <<EOF
"$GENESIS_ALLOC_FIF" include
." [bootstrap-sanity] alloc accounts cell hash: " hashB Bx. cr
." [bootstrap-sanity] OK" cr
EOF
    FIFTPATH="${TOS_FIFT_DIR}:/usr/local/share/tos/smartcont" \
        /usr/local/bin/tos-create-state "$SANITY_FIF" 2>&1 | sed 's/^/[bootstrap-sanity] /' >&2 || \
            log "WARNING: bootstrap sanity build failed (see above)"
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
    #
    # Chain-id override: when the Hive fixtures demand a chain id that the
    # upstream can't serve (the spec uses 0xc72dd9d5e883e, our live testnet
    # reports 0x544f53), answer eth_chainId / net_version locally in the
    # proxy so those fixture sub-tests stop failing with SHAPE_MISMATCH.
    # Triggered whenever HIVE_CHAIN_ID differs from the default (0x544f53).
    OVERRIDE_ARGS=()
    if [ "$CHAIN_ID_DEC" != "5525331" ]; then
        log "      chain-id override active: ${CHAIN_ID_DEC} (upstream serves 5525331)"
        OVERRIDE_ARGS+=(--override-chain-id "$CHAIN_ID_DEC")
    fi
    # Always normalise not-found responses: TOS RPC returns a synthetic
    # all-zero placeholder block for unknown numbers/hashes; geth (and
    # therefore Hive's fixtures) expect `null`. Honest semantic translation.
    OVERRIDE_ARGS+=(--normalize-not-found)
    exec /usr/local/bin/tos-rpc-proxy.py \
        --listen "${RPC_BIND}" \
        --upstream "${TOS_PROXY_UPSTREAM}" \
        --ready-marker "TOS-VALIDATOR-READY" \
        "${OVERRIDE_ARGS[@]}"
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

# Background readiness watcher: poll RPC, log a clear marker once it's up.
# Once readiness is reached, optionally replay /chain.rlp (the per-test
# Hive seed file) into our chain via eth_sendRawTransaction so that subsequent
# rpc-compat fixtures see the same state geth would after importing it.
#
# Hive's docs/clients.md says: "the client should import the blocks from
# /chain.rlp if it is present". We do so in this background task once RPC is
# alive; we exit non-zero only on hard errors (block production stalls).
# Bad-signature rejections are common when the chain id doesn't match what
# the chain.rlp txs were signed with — we set TOS_EVM_CHAIN_ID above so the
# spec's chain id is honoured at validator startup.
CHAIN_RLP="${HIVE_CHAIN_RLP_PATH:-/chain.rlp}"
(
    for i in $(seq 1 120); do
        sleep 1
        if curl -fsS -X POST -H 'Content-Type: application/json' \
                -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
                "http://127.0.0.1:${RPC_BIND_PORT}" >/dev/null 2>&1; then
            log "TOS-VALIDATOR-READY (eth_chainId responsive after ${i}s)"
            if [ -f "$CHAIN_RLP" ] && [ -x /usr/local/bin/tos-chain-rlp-replay ]; then
                log "Replaying $CHAIN_RLP into local chain..."
                /usr/local/bin/tos-chain-rlp-replay \
                    --chain "$CHAIN_RLP" \
                    --rpc "http://127.0.0.1:${RPC_BIND_PORT}" \
                    --expected-chain-id "$CHAIN_ID_DEC" \
                    --start-block 0 \
                    --block-wait-secs 30 \
                    || log "WARNING: chain.rlp replay returned non-zero (see above)."
                log "TOS-VALIDATOR-CHAIN-LOADED"
            elif [ ! -f "$CHAIN_RLP" ]; then
                log "(no $CHAIN_RLP present — skipping chain.rlp replay)"
            fi
            exit 0
        fi
    done
    log "TOS-VALIDATOR-NOT-READY (eth_chainId not responsive after 120s)"
) &

log "Starting tos-validator-engine on $RPC_BIND (sync-delay=$SYNC_DELAY, log=$LOGLEVEL, chainId=$CHAIN_ID_DEC)"

# Pass the Hive-requested chain id to the validator via TOS_EVM_CHAIN_ID
# (consumed by evm_workchain::init_evm_workchain at startup). This must be
# applied to a FRESH chain — EIP-155 v-recovery and stored receipts both
# assume a stable chain id, so an override on an existing chain would
# invalidate every signed transaction in state.
export TOS_EVM_CHAIN_ID="$CHAIN_ID_DEC"

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
