#!/usr/bin/env bash
# Run the tos32 release-candidate local testnet validation loop.
#
# This script assumes scripts/setup-testnet.sh has already installed the
# local 3-node systemd testnet, unless TOS_RC_SETUP=1 is set.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACT_DIR="${TOS_RC_ARTIFACT_DIR:-$ROOT/build/tos32-rc-$(date -u +%Y%m%dT%H%M%SZ)}"
DURATION_SECONDS="${TOS_RC_DURATION_SECONDS:-3600}"
HEALTH_INTERVAL_SECONDS="${TOS_RC_HEALTH_INTERVAL_SECONDS:-30}"
RESTART_INTERVAL_SECONDS="${TOS_RC_RESTART_INTERVAL_SECONDS:-900}"
CATCHUP_LAG_SECONDS="${TOS_RC_CATCHUP_LAG_SECONDS:-300}"
CATCHUP_TIMEOUT_SECONDS="${TOS_RC_CATCHUP_TIMEOUT_SECONDS:-600}"
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

mkdir -p "$ARTIFACT_DIR"
exec > >(tee "$ARTIFACT_DIR/driver.log") 2>&1

json_rpc() {
  local port="$1"
  local method="$2"
  local params="${3:-[]}"
  curl -fsS --max-time 5 \
    -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "http://127.0.0.1:$port/"
}

json_result() {
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("result", ""))'
}

hex_to_int() {
  python3 -c 'import sys; s=sys.stdin.read().strip(); print(int(s, 16) if s.startswith("0x") else int(s or "0"))'
}

node_port() {
  echo $((8010 + $1))
}

node_block_number() {
  local port
  port="$(node_port "$1")"
  json_rpc "$port" eth_blockNumber | json_result | hex_to_int
}

check_node() {
  local node="$1"
  local port
  port="$(node_port "$node")"
  local active
  active="$($SUDO systemctl is-active "tos-validator@$node" 2>/dev/null || true)"
  if [ "$active" != "active" ]; then
    echo "node $node inactive: $active" >&2
    return 1
  fi
  local chain_id block_number
  chain_id="$(json_rpc "$port" eth_chainId | json_result)"
  block_number="$(json_rpc "$port" eth_blockNumber | json_result | hex_to_int)"
  printf "%s,node=%s,active=%s,chain_id=%s,block=%s\n" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$node" "$active" "$chain_id" "$block_number" \
    | tee -a "$ARTIFACT_DIR/health.csv"
}

check_all_nodes() {
  check_node 1
  check_node 2
  check_node 3
}

collect_logs() {
  for svc in tos-dht tos-validator@1 tos-validator@2 tos-validator@3; do
    $SUDO journalctl -u "$svc" --no-pager -n 2000 > "$ARTIFACT_DIR/${svc//@/_}.log" 2>&1 || true
  done
  $SUDO systemctl status tos-dht tos-validator@1 tos-validator@2 tos-validator@3 \
    --no-pager > "$ARTIFACT_DIR/systemd-status.txt" 2>&1 || true
}

run_catchup_probe() {
  echo
  echo "### catch-up probe: stop node 3 for ${CATCHUP_LAG_SECONDS}s, then restart and wait"
  $SUDO systemctl stop tos-validator@3
  sleep "$CATCHUP_LAG_SECONDS"
  local target
  target="$(node_block_number 1)"
  echo "target block from node 1 after lag: $target"
  $SUDO systemctl start tos-validator@3
  local deadline=$((SECONDS + CATCHUP_TIMEOUT_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    local b
    b="$(node_block_number 3 || echo 0)"
    echo "node 3 catch-up block=$b target=$target"
    if [ "$b" -ge "$target" ]; then
      echo "catch-up probe passed"
      return 0
    fi
    sleep "$HEALTH_INTERVAL_SECONDS"
  done
  echo "catch-up probe failed: node 3 did not reach block $target within ${CATCHUP_TIMEOUT_SECONDS}s" >&2
  return 1
}

echo "tos32 RC validation"
echo "root=$ROOT"
echo "artifact_dir=$ARTIFACT_DIR"
echo "duration_seconds=$DURATION_SECONDS"
echo "restart_interval_seconds=$RESTART_INTERVAL_SECONDS"
echo "git_commit=$(git -C "$ROOT" rev-parse HEAD)"
echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
uname -a

if [ "${TOS_RC_SETUP:-0}" != "0" ] && [ -n "${TOS_RC_SETUP:-}" ]; then
  $SUDO "$ROOT/scripts/setup-testnet.sh" --clean
fi

"$ROOT/scripts/testnet-ctl.sh" start
trap collect_logs EXIT

check_all_nodes

if [ "${TOS_RC_CATCHUP_TEST:-0}" != "0" ] && [ -n "${TOS_RC_CATCHUP_TEST:-}" ]; then
  run_catchup_probe
fi

deadline=$((SECONDS + DURATION_SECONDS))
next_restart=$((SECONDS + RESTART_INTERVAL_SECONDS))
restart_node=1
while [ "$SECONDS" -lt "$deadline" ]; do
  check_all_nodes
  if [ "$RESTART_INTERVAL_SECONDS" -gt 0 ] && [ "$SECONDS" -ge "$next_restart" ]; then
    echo "restarting tos-validator@$restart_node"
    $SUDO systemctl restart "tos-validator@$restart_node"
    restart_node=$((restart_node % 3 + 1))
    next_restart=$((SECONDS + RESTART_INTERVAL_SECONDS))
  fi
  sleep "$HEALTH_INTERVAL_SECONDS"
done

check_all_nodes
collect_logs

cat > "$ARTIFACT_DIR/summary.txt" <<EOF
tos32 RC validation completed
commit: $(git -C "$ROOT" rev-parse HEAD)
duration_seconds: $DURATION_SECONDS
restart_interval_seconds: $RESTART_INTERVAL_SECONDS
catchup_test: ${TOS_RC_CATCHUP_TEST:-0}
artifacts: $ARTIFACT_DIR
EOF

echo
echo "tos32 RC validation completed: $ARTIFACT_DIR"
