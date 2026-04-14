#!/bin/bash
# End-to-end test suite for tosctl against a running 3-node TOS testnet.
#
# Assumes:
#   - Local testnet running with JSON-RPC on ports 2011-2013
#     and console on ports 2004/2007/2010.
#   - tosctl Rust workspace at /home/tomi/tos/tosctl/src/Cargo.toml.
#
# Usage:
#   ./e2e-test.sh                     # defaults
#   RPC_URL=http://10.0.0.1:2011 ./e2e-test.sh   # override RPC endpoint

set -euo pipefail

TOSCTL="${TOSCTL:-cargo run --manifest-path /home/tomi/tos/tosctl/src/Cargo.toml -p tosctl --}"
RPC_URL="${RPC_URL:-http://127.0.0.1:2011}"
CONFIG="/tmp/tosctl-e2e-config.json"

PASS=0
FAIL=0

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

run() {
    local label="$1"; shift
    if "$@" > /dev/null 2>&1; then
        pass "$label"
    else
        fail "$label"
    fi
}

cleanup() {
    echo ""
    echo "Cleaning up temporary artifacts..."
    $TOSCTL wallet rm -c "$CONFIG" -n test-wallet --yes 2>/dev/null || true
    rm -f "$CONFIG" /tmp/tosctl_backup_*.tar.gz
}
trap cleanup EXIT

echo "=== TOS E2E Test Suite ==="
echo "RPC endpoint : $RPC_URL"
echo "Config file  : $CONFIG"
echo ""

# ---------------------------------------------------------------
# Generate a test config and point it at the local RPC endpoint
# ---------------------------------------------------------------
$TOSCTL config generate -o "$CONFIG" --force
# Patch chain_rpc URL into the generated config
if command -v python3 &>/dev/null && [ -f "$CONFIG" ]; then
    python3 -c "
import json
with open('$CONFIG') as f:
    cfg = json.load(f)
if isinstance(cfg.get('chain_rpc'), dict):
    cfg['chain_rpc']['urls'] = ['$RPC_URL/']
else:
    cfg['chain_rpc'] = {'urls': ['$RPC_URL/'], 'api_key': None}
with open('$CONFIG', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>/dev/null || true
fi

# ---------------------------------------------------------------
# Test 1: host commands
# ---------------------------------------------------------------
echo "[1/10] host commands"
run "host about"  $TOSCTL host about -c "$CONFIG"
run "host status" $TOSCTL host status -c "$CONFIG" --format json

# ---------------------------------------------------------------
# Test 2: node commands
# ---------------------------------------------------------------
echo "[2/10] node status"
run "node status" $TOSCTL node status -c "$CONFIG" --format json

# ---------------------------------------------------------------
# Test 3: JSON-RPC health endpoints
# ---------------------------------------------------------------
echo "[3/10] JSON-RPC health"
run "/healthcheck"      curl -sf --max-time 5 "$RPC_URL/healthcheck"
run "/readyz"           curl -sf --max-time 5 "$RPC_URL/readyz"
run "getMasterchainInfo" curl -sf --max-time 10 -X POST "$RPC_URL/jsonRPC" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"getMasterchainInfo","params":{},"id":1}'

# ---------------------------------------------------------------
# Test 4: account commands
# ---------------------------------------------------------------
echo "[4/10] account status (elector)"
ELECTOR="-1:3333333333333333333333333333333333333333333333333333333333333333"
run "account status" $TOSCTL account status -c "$CONFIG" --address="$ELECTOR" --format json

# ---------------------------------------------------------------
# Test 5: observe commands
# ---------------------------------------------------------------
echo "[5/10] observe validators"
run "observe validators" $TOSCTL observe validators -c "$CONFIG" --format json

# ---------------------------------------------------------------
# Test 6: wallet create + ls
# ---------------------------------------------------------------
echo "[6/10] wallet create + ls"
run "wallet create" $TOSCTL wallet create -c "$CONFIG" -n test-wallet -v V3R2
run "wallet ls"     $TOSCTL wallet ls -c "$CONFIG" --format json

# ---------------------------------------------------------------
# Test 7: vote offer ls
# ---------------------------------------------------------------
echo "[7/10] vote offer ls"
run "vote offer ls" $TOSCTL vote offer ls -c "$CONFIG" --format json

# ---------------------------------------------------------------
# Test 8: backup create + verify
# ---------------------------------------------------------------
echo "[8/10] backup create + verify"
run "backup create" $TOSCTL backup create -c "$CONFIG" -o /tmp
BACKUP="$(ls -t /tmp/tosctl_backup_*.tar.gz 2>/dev/null | head -1 || true)"
if [ -n "$BACKUP" ]; then
    run "backup verify" $TOSCTL backup verify -f "$BACKUP"
else
    fail "backup verify (no backup file found)"
fi

# ---------------------------------------------------------------
# Test 9: bookmarks
# ---------------------------------------------------------------
echo "[9/10] bookmarks"
run "bookmark add" $TOSCTL account bookmark add -c "$CONFIG" --name elector --address="$ELECTOR"
run "bookmark ls"  $TOSCTL account bookmark ls -c "$CONFIG" --format json
run "bookmark rm"  $TOSCTL account bookmark rm -c "$CONFIG" --name elector

# ---------------------------------------------------------------
# Test 10: (cleanup handled by trap)
# ---------------------------------------------------------------
echo "[10/10] cleanup"
run "wallet rm" $TOSCTL wallet rm -c "$CONFIG" -n test-wallet --yes

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
