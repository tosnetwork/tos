#!/usr/bin/env bash
# Run the tos32 release-candidate local testnet validation loop.
#
# Native-only (wc=0): drives the native TVM testnet installed by
# scripts/setup-testnet.sh (a 4-node systemd cluster). Each node is probed
# through its own liteserver via tos-lite-client (ADNL); there is no
# EVM/JSON-RPC surface. Assumes setup-testnet.sh has already installed the
# cluster, unless TOS_RC_SETUP=1 is set.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACT_DIR="${TOS_RC_ARTIFACT_DIR:-$ROOT/build/tos32-rc-$(date -u +%Y%m%dT%H%M%SZ)}"
DURATION_SECONDS="${TOS_RC_DURATION_SECONDS:-3600}"
HEALTH_INTERVAL_SECONDS="${TOS_RC_HEALTH_INTERVAL_SECONDS:-30}"
RESTART_INTERVAL_SECONDS="${TOS_RC_RESTART_INTERVAL_SECONDS:-900}"
CATCHUP_LAG_SECONDS="${TOS_RC_CATCHUP_LAG_SECONDS:-300}"
CATCHUP_TIMEOUT_SECONDS="${TOS_RC_CATCHUP_TIMEOUT_SECONDS:-600}"
NODE_COUNT="${TOS_RC_NODE_COUNT:-4}"
GLOBAL_CONFIG="${TOS_RC_GLOBAL_CONFIG:-/data/tos-global.json}"
LITE_CLIENT="${TOS_RC_LITE_CLIENT:-/usr/local/bin/tos-lite-client}"
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

if [ ! -x "$LITE_CLIENT" ]; then
  alt="$ROOT/build/lite-client/lite-client"
  [ -x "$alt" ] && LITE_CLIENT="$alt"
fi

mkdir -p "$ARTIFACT_DIR"
exec > >(tee "$ARTIFACT_DIR/driver.log") 2>&1

# Masterchain seqno from a specific node's liteserver. The liteservers in the
# global config are ordered node 1..N, so node K maps to liteserver idx K-1.
node_masterchain_seqno() {
  local node="$1"
  local out
  out="$(timeout 15 "$LITE_CLIENT" -C "$GLOBAL_CONFIG" -i "$((node - 1))" -v 0 \
    -c "time" -c "last" -c "quit" 2>/dev/null)" || return 1
  # parse: latest masterchain block known to server is (-1,8000000000000000,SEQNO):roothash:filehash ...
  echo "$out" | sed -nE 's/.*\(-1,[0-9a-fA-F]+,([0-9]+)\).*/\1/p' | head -1
}

check_node() {
  local node="$1"
  local active
  active="$($SUDO systemctl is-active "tos-validator@$node" 2>/dev/null || true)"
  if [ "$active" != "active" ]; then
    echo "node $node inactive: $active" >&2
    return 1
  fi
  local mc_seqno
  mc_seqno="$(node_masterchain_seqno "$node" || true)"
  printf "%s,node=%s,active=%s,mc_seqno=%s\n" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$node" "$active" "${mc_seqno:-NA}" \
    | tee -a "$ARTIFACT_DIR/health.csv"
}

check_all_nodes() {
  local n
  for n in $(seq 1 "$NODE_COUNT"); do
    check_node "$n" || true
  done
}

collect_logs() {
  local n svc
  $SUDO journalctl -u tos-dht --no-pager -n 2000 > "$ARTIFACT_DIR/tos-dht.log" 2>&1 || true
  for n in $(seq 1 "$NODE_COUNT"); do
    svc="tos-validator@$n"
    $SUDO journalctl -u "$svc" --no-pager -n 2000 > "$ARTIFACT_DIR/tos-validator_$n.log" 2>&1 || true
  done
  # shellcheck disable=SC2046
  $SUDO systemctl status tos-dht $(for n in $(seq 1 "$NODE_COUNT"); do echo "tos-validator@$n"; done) \
    --no-pager > "$ARTIFACT_DIR/systemd-status.txt" 2>&1 || true
}

run_catchup_probe() {
  # Stop the highest-numbered node (a pure validator; node 1 also hosts the
  # DHT bootstrap). With NODE_COUNT=4 the remaining 3 (weight 51) still exceed
  # the quorum threshold (quorum_threshold(68)=46), so the chain keeps
  # producing while the stopped node falls behind and must catch up on restart.
  local probe_node="$NODE_COUNT"
  echo
  echo "### catch-up probe: stop node $probe_node for ${CATCHUP_LAG_SECONDS}s, then restart and wait"
  $SUDO systemctl stop "tos-validator@$probe_node"
  sleep "$CATCHUP_LAG_SECONDS"
  local target
  target="$(node_masterchain_seqno 1 || true)"
  echo "target masterchain seqno from node 1 after lag: $target"
  $SUDO systemctl start "tos-validator@$probe_node"
  local deadline=$((SECONDS + CATCHUP_TIMEOUT_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    local b
    b="$(node_masterchain_seqno "$probe_node" 2>/dev/null || true)"
    if [ -z "$b" ]; then
      echo "node $probe_node catch-up: liteserver not ready yet"
      sleep "$HEALTH_INTERVAL_SECONDS"
      continue
    fi
    echo "node $probe_node catch-up mc_seqno=$b target=$target"
    if [ -n "$target" ] && [ "$b" -ge "$target" ]; then
      echo "catch-up probe passed"
      return 0
    fi
    sleep "$HEALTH_INTERVAL_SECONDS"
  done
  echo "catch-up probe failed: node $probe_node did not reach masterchain seqno $target within ${CATCHUP_TIMEOUT_SECONDS}s" >&2
  return 1
}

echo "tos32 RC validation (native-only, wc=0)"
echo "root=$ROOT"
echo "artifact_dir=$ARTIFACT_DIR"
echo "node_count=$NODE_COUNT"
echo "lite_client=$LITE_CLIENT"
echo "global_config=$GLOBAL_CONFIG"
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
    restart_node=$((restart_node % NODE_COUNT + 1))
    next_restart=$((SECONDS + RESTART_INTERVAL_SECONDS))
  fi
  sleep "$HEALTH_INTERVAL_SECONDS"
done

check_all_nodes
collect_logs

cat > "$ARTIFACT_DIR/summary.txt" <<EOF
tos32 RC validation completed (native-only, wc=0)
commit: $(git -C "$ROOT" rev-parse HEAD)
node_count: $NODE_COUNT
duration_seconds: $DURATION_SECONDS
restart_interval_seconds: $RESTART_INTERVAL_SECONDS
catchup_test: ${TOS_RC_CATCHUP_TEST:-0}
artifacts: $ARTIFACT_DIR
EOF

echo
echo "tos32 RC validation completed: $ARTIFACT_DIR"
