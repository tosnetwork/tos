#!/usr/bin/env bash
# Scheduled A/B/C transfer soak.
#
# Launches a throwaway 4-node localnet and drives randomized transfers among three wallets
# (A, B, C) under real block production, verifying after every transfer that all nodes agree
# on the three balances at a common masterchain height (到账 consistency). In parallel it runs
# scripts/soak-mem-monitor.py to sample each validator-engine's RSS/FD and flag a leak.
#
# The randomized transfer scheduling (random source/destination, random amount, random
# interval) runs inside the Python driver, which holds the wallet seqno state; this wrapper
# is the scheduler/launcher. It uses its own ports so it can run alongside other localnets.
#
# Usage: scripts/transfer-soak.sh [DURATION_SECONDS] [RPC_BASE_PORT] [BASE_PORT]
set -euo pipefail
cd "$(dirname "$0")/.."

# NOTE: each experiment node binds TWO ADNL ports -- base_port+offset AND base_port+1000+
# offset -- so a network at base_port B occupies roughly [B .. B+1011]. Pick BASE_PORT at
# least ~2000 above any other running localnet's base to avoid a bind collision.
DURATION="${1:-900}"
RPC_BASE="${2:-8131}"
BASE_PORT="${3:-30000}"

echo "transfer-soak: duration=${DURATION}s rpc_base=${RPC_BASE} base_port=${BASE_PORT}"

# Start the randomized transfer load + cross-node consistency checks.
uv run python scripts/validator-election-stage-a.py \
  --mode transfer-soak --stage a \
  --base-port "${BASE_PORT}" --rpc-base-port "${RPC_BASE}" \
  --soak-duration "${DURATION}" --soak-min-interval 1 --soak-max-interval 4 &
SOAK_PID=$!

# Give the network a moment to come up, then start the per-node leak monitor against it.
# (The soak driver also samples storage via its own metrics_monitor; this adds RSS/FD.)
sleep 60
RUN_DIR="$(ls -dt test/integration/.validator-election-experiment/*/ 2>/dev/null | head -1)"
if [ -n "${RUN_DIR}" ]; then
  uv run python scripts/soak-mem-monitor.py \
    --rpc "127.0.0.1:${RPC_BASE}" --interval 20 --duration "${DURATION}" \
    --out "${RUN_DIR}mem-monitor.jsonl" &
  MON_PID=$!
fi

wait "${SOAK_PID}"
SOAK_RC=$?
[ -n "${MON_PID:-}" ] && wait "${MON_PID}" 2>/dev/null || true
echo "transfer-soak: driver exited rc=${SOAK_RC}; analysis in ${RUN_DIR:-<run dir>}"
exit "${SOAK_RC}"
