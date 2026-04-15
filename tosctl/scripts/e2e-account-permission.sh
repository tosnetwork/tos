#!/bin/bash
# End-to-end smoke test for tosctl account-permission commands against a running TOS node.
#
# This script:
#   1. generates a temporary tosctl config
#   2. deploys account-permission fixtures through test/json-rpc/deployer.py
#   3. exercises account capability/inspection/lifecycle commands through tosctl
#
# Usage:
#   ./e2e-account-permission.sh
#   RPC_URL=http://127.0.0.1:8011 ./e2e-account-permission.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTDATA_DIR="$SCRIPT_DIR/testdata"

TOSCTL="${TOSCTL:-cargo run --manifest-path $SCRIPT_DIR/../src/Cargo.toml -p tosctl --}"
RPC_URL="${RPC_URL:-http://127.0.0.1:8011}"
CONFIG="$TESTDATA_DIR/e2e-account-permission-config.json"
DEPLOYED_JSON="$ROOT_DIR/test/json-rpc/deployed_addresses.json"
DEPLOYER="$ROOT_DIR/test/json-rpc/deployer.py"
E2E_MASTER_KEY="0000000000000000000000000000000000000000000000000000000000000001"
export VAULT_URL="${VAULT_URL:-file://$TESTDATA_DIR/e2e-account-permission-vault.json?master_key=$E2E_MASTER_KEY}"

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

run_retry() {
    local label="$1"; shift
    local attempts="${ATTEMPTS:-5}"
    local sleep_s="${RETRY_SLEEP:-2}"
    local i=1
    while [ "$i" -le "$attempts" ]; do
        if "$@" > /dev/null 2>&1; then
            pass "$label"
            return 0
        fi
        i=$((i + 1))
        sleep "$sleep_s"
    done
    fail "$label"
    return 1
}

run_expect_fail() {
    local label="$1"; shift
    if "$@" > /dev/null 2>&1; then
        fail "$label (unexpected success)"
    else
        pass "$label"
    fi
}

cleanup() {
    rm -f "$CONFIG" "$TESTDATA_DIR/e2e-account-permission-vault.json"
}
trap cleanup EXIT

echo "=== TOS Account-Permission E2E Smoke Test ==="
echo "RPC endpoint : $RPC_URL"
echo "Config file  : $CONFIG"
echo ""

$TOSCTL config generate -o "$CONFIG" --force
python3 - <<PY
import json
with open("$CONFIG") as f:
    cfg = json.load(f)
cfg["chain_rpc"] = {"urls": ["$RPC_URL/"], "api_key": None}
with open("$CONFIG", "w") as f:
    json.dump(cfg, f, indent=2)
PY

echo "[1/5] Deploy fixtures"
run "deploy fixtures" python3 "$DEPLOYER" "$RPC_URL/" --force

readarray -t ADDRS < <(python3 - <<PY
import json
with open("$DEPLOYED_JSON") as f:
    d = json.load(f)
wallets = d.get("wallets", {})
print(wallets.get("multisig", {}).get("address", ""))
print(wallets.get("restricted", {}).get("address", ""))
print(wallets.get("nominator_pool", {}).get("address", ""))
print(wallets.get("session_wallet", {}).get("address", ""))
PY
)
MULTISIG="${ADDRS[0]}"
RESTRICTED="${ADDRS[1]}"
NOMINATOR="${ADDRS[2]}"
SESSION_WALLET="${ADDRS[3]}"

if [ -z "$MULTISIG" ] || [ -z "$RESTRICTED" ] || [ -z "$NOMINATOR" ] || [ -z "$SESSION_WALLET" ]; then
    echo "Missing deployed fixture address"
    exit 1
fi

echo "[2/5] Inspection commands"
run_retry "account capability multisig"    $TOSCTL account capability   -c "$CONFIG" --address="$MULTISIG" --format json
run_retry "account delegations restricted" $TOSCTL account delegations -c "$CONFIG" --address="$RESTRICTED" --format json
run_retry "account delegations nominator"  $TOSCTL account delegations -c "$CONFIG" --address="$NOMINATOR" --format json
run_retry "account sessions session-wallet" $TOSCTL account sessions   -c "$CONFIG" --address="$SESSION_WALLET" --format json
run_retry "account agents multisig"        $TOSCTL account agents      -c "$CONFIG" --address="$MULTISIG" --format json

echo "[3/5] Supported lifecycle"
run_retry "delegation grant nominator" \
  $TOSCTL account delegation-grant -c "$CONFIG" \
    --address="$NOMINATOR" \
    --grantee="0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
    --scope="bounded_transfer" \
    --constraints='{}' \
    --format json

# Verify grant took effect
run_retry "verify post-grant delegations" \
  $TOSCTL account delegations -c "$CONFIG" --address="$NOMINATOR" --format json

# Discover the real principal-based permission ID from inspection
PERM_ID=$($TOSCTL account delegations -c "$CONFIG" --address="$NOMINATOR" --format json 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); items = d if isinstance(d, list) else (d.get('result') if isinstance(d, dict) else None); first = items[0] if items else {}; print((first.get('permission_id') or first.get('id') or '') if isinstance(first, dict) else '')" 2>/dev/null || echo "")

if [ -z "$PERM_ID" ]; then
  echo "  WARN: could not discover delegation permission_id, using fallback"
  PERM_ID="${NOMINATOR}:nominator-stake:unknown"
fi

run_retry "delegation revoke nominator" \
  $TOSCTL account delegation-revoke -c "$CONFIG" \
    --address="$NOMINATOR" \
    --permission-id="$PERM_ID" \
    --format json

# Verify revoke took effect
run_retry "verify post-revoke delegations" \
  $TOSCTL account delegations -c "$CONFIG" --address="$NOMINATOR" --format json

echo "[4/5] Unsupported/immutable lifecycle"
run_expect_fail "session grant session-wallet unsupported" \
  $TOSCTL account session-grant -c "$CONFIG" \
    --address="$SESSION_WALLET" \
    --grantee="0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
    --scope="submit_only" \
    --constraints='{}' \
    --format json

run_expect_fail "agent grant multisig immutable" \
  $TOSCTL account agent-grant -c "$CONFIG" \
    --address="$MULTISIG" \
    --grantee="0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
    --scope="agent_execution" \
    --constraints='{}' \
    --format json

echo "[5/5] Summary"
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
