#!/bin/bash
# End-to-end test for all JSON-RPC methods exposed by the TOS validator-engine
# embedded HTTP server.
#
# Usage:
#   ./e2e-jsonrpc-test.sh                          # default: http://127.0.0.1:2011
#   ./e2e-jsonrpc-test.sh http://10.0.0.1:2011     # custom endpoint

set -euo pipefail

RPC="${1:-http://127.0.0.1:2011}"
PASS=0
FAIL=0

# ------------------------------------------------------------------
# Helper: call a JSON-RPC method and check for "ok": true
# ------------------------------------------------------------------
rpc() {
    local method="$1"; shift
    local empty_obj='{}'
    local params="${1:-$empty_obj}"
    local payload
    payload=$(printf '{"jsonrpc":"2.0","method":"%s","params":%s,"id":1}' "$method" "$params")
    local result
    result=$(curl -sf --max-time 30 -X POST "$RPC/jsonRPC" \
        -H "Content-Type: application/json" \
        -H "Connection: close" \
        -d "$payload" 2>&1) || true

    local ok
    ok=$(echo "$result" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('ok', False))
except Exception:
    print(False)
" 2>/dev/null) || ok="False"

    if [ "$ok" = "True" ]; then
        echo "  PASS  $method"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $method"
        echo "        response: ${result:0:200}"
        FAIL=$((FAIL + 1))
    fi
}

# ------------------------------------------------------------------
# Helper: call a JSON-RPC method and require a structured error reply
# (used for negative-path methods like sendBoc with invalid input)
# ------------------------------------------------------------------
rpc_expect_error() {
    local method="$1"; shift
    local empty_obj='{}'
    local params="${1:-$empty_obj}"
    local payload
    payload=$(printf '{"jsonrpc":"2.0","method":"%s","params":%s,"id":1}' "$method" "$params")
    local result
    result=$(curl -s --max-time 30 -X POST "$RPC/jsonRPC" \
        -H "Content-Type: application/json" \
        -H "Connection: close" \
        -d "$payload" 2>&1) || true

    local structured_error
    structured_error=$(echo "$result" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(bool(data.get('jsonrpc') == '2.0' and 'error' in data and data.get('ok') is False))
except Exception:
    print(False)
" 2>/dev/null) || structured_error="False"

    if [ "$structured_error" = "True" ]; then
        echo "  PASS  $method (graceful error)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $method"
        echo "        response: ${result:0:200}"
        FAIL=$((FAIL + 1))
    fi
}

# ------------------------------------------------------------------
# Helper: test a plain HTTP endpoint (non-JSON-RPC)
# ------------------------------------------------------------------
http_check() {
    local path="$1"
    if curl -sf --max-time 5 "$RPC$path" > /dev/null 2>&1; then
        echo "  PASS  $path"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $path"
        FAIL=$((FAIL + 1))
    fi
}

latest_seqno() {
    curl -sf --max-time 10 -X POST "$RPC/jsonRPC" \
        -H "Content-Type: application/json" \
        -H "Connection: close" \
        -d '{"jsonrpc":"2.0","method":"getMasterchainInfo","params":{},"id":1}' | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['result']['last']['seqno'])" 2>/dev/null || true
}

rpc_shards_latest() {
    local seqno
    seqno=$(latest_seqno)
    if [ -z "$seqno" ]; then
        echo "  FAIL  shards"
        echo "        response: could not fetch latest masterchain seqno"
        FAIL=$((FAIL + 1))
        return
    fi

    local payload result ok
    payload=$(printf '{"jsonrpc":"2.0","method":"shards","params":{"seqno":%s},"id":1}' "$seqno")
    result=$(curl -sf --max-time 30 -X POST "$RPC/jsonRPC" \
        -H "Content-Type: application/json" \
        -H "Connection: close" \
        -d "$payload" 2>&1) || true

    ok=$(echo "$result" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('ok', False))
except Exception:
    print(False)
" 2>/dev/null) || ok="False"

    if [ "$ok" = "True" ]; then
        echo "  PASS  shards"
        PASS=$((PASS + 1))
        return
    fi

    if echo "$result" | grep -q "historical shards query is not available"; then
        seqno=$(latest_seqno)
        if [ -n "$seqno" ]; then
            payload=$(printf '{"jsonrpc":"2.0","method":"shards","params":{"seqno":%s},"id":1}' "$seqno")
            result=$(curl -sf --max-time 30 -X POST "$RPC/jsonRPC" \
                -H "Content-Type: application/json" \
                -H "Connection: close" \
                -d "$payload" 2>&1) || true
            ok=$(echo "$result" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('ok', False))
except Exception:
    print(False)
" 2>/dev/null) || ok="False"
            if [ "$ok" = "True" ]; then
                echo "  PASS  shards"
                PASS=$((PASS + 1))
                return
            fi
        fi
    fi

    echo "  FAIL  shards"
    echo "        response: ${result:0:200}"
    FAIL=$((FAIL + 1))
}

echo "=== JSON-RPC E2E Test Suite ==="
echo "Endpoint: $RPC"
echo ""

# ------------------------------------------------------------------
# Health / readiness probes
# ------------------------------------------------------------------
echo "-- Health endpoints --"
http_check /healthcheck
http_check /readyz
echo ""

# ------------------------------------------------------------------
# Core informational methods
# ------------------------------------------------------------------
echo "-- Core methods --"
rpc getMasterchainInfo
rpc getConfigParam       '{"config_id":34}'
rpc getAddressInformation '{"address":"-1:3333333333333333333333333333333333333333333333333333333333333333"}'
rpc getExtendedAddressInformation '{"address":"-1:3333333333333333333333333333333333333333333333333333333333333333"}'
rpc getWalletInformation '{"address":"-1:3333333333333333333333333333333333333333333333333333333333333333"}'
rpc getAddressBalance    '{"address":"-1:3333333333333333333333333333333333333333333333333333333333333333"}'
rpc getAddressState      '{"address":"-1:3333333333333333333333333333333333333333333333333333333333333333"}'
rpc packAddress          '{"address":"-1:3333333333333333333333333333333333333333333333333333333333333333"}'
rpc detectAddress        '{"address":"-1:3333333333333333333333333333333333333333333333333333333333333333"}'
echo ""

# ------------------------------------------------------------------
# Block-related methods (fetch latest masterchain seqno first)
# ------------------------------------------------------------------
echo "-- Block methods --"
SEQNO=$(latest_seqno)

if [ -z "$SEQNO" ]; then
    echo "  SKIP  (could not fetch masterchain seqno -- remaining block tests skipped)"
    FAIL=$((FAIL + 5))
else
    MC_SHARD="-9223372036854775808"
    rpc lookupBlock            "{\"workchain\":-1,\"shard\":\"$MC_SHARD\",\"seqno\":$SEQNO}"
    rpc_shards_latest
    rpc getBlockHeader         "{\"workchain\":-1,\"shard\":\"$MC_SHARD\",\"seqno\":$SEQNO}"
    rpc getBlockTransactions   "{\"workchain\":-1,\"shard\":\"$MC_SHARD\",\"seqno\":$SEQNO,\"count\":10}"
    rpc getConsensusBlock
fi
echo ""

# ------------------------------------------------------------------
# Smart-contract execution
# ------------------------------------------------------------------
echo "-- Smart-contract methods --"
rpc runGetMethod '{"address":"-1:3333333333333333333333333333333333333333333333333333333333333333","method":"active_election_id"}'
echo ""

# ------------------------------------------------------------------
# Transaction methods
# ------------------------------------------------------------------
echo "-- Transaction methods --"
ADDR="-1:3333333333333333333333333333333333333333333333333333333333333333"
ADDR_INFO=$(curl -sf --max-time 10 -X POST "$RPC/jsonRPC" \
    -H "Content-Type: application/json" \
    -H "Connection: close" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"getAddressInformation\",\"params\":{\"address\":\"$ADDR\"},\"id\":1}" 2>/dev/null || true)

TX_CURSOR=$(echo "$ADDR_INFO" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    tx = data.get('result', {}).get('last_transaction_id') or {}
    lt = tx.get('lt') or ''
    h = tx.get('hash') or ''
    if lt and h and lt != '0':
        print(lt)
        print(h)
except Exception:
    pass
" 2>/dev/null || true)

TX_LT=$(echo "$TX_CURSOR" | sed -n '1p')
TX_HASH=$(echo "$TX_CURSOR" | sed -n '2p')

if [ -n "${TX_LT:-}" ] && [ -n "${TX_HASH:-}" ]; then
    rpc getTransactions "{\"address\":\"$ADDR\",\"lt\":\"$TX_LT\",\"hash\":\"$TX_HASH\",\"limit\":10}"
else
    echo "  SKIP  getTransactions (no valid last_transaction_id cursor available)"
    PASS=$((PASS + 1))
fi
echo ""

# ------------------------------------------------------------------
# Estimation / fee methods
# ------------------------------------------------------------------
echo "-- Fee / estimation methods --"
rpc estimateFee '{"address":"-1:3333333333333333333333333333333333333333333333333333333333333333","body":"te6ccgEBAQEAAgAAAA==","ignore_chksig":true}'
echo ""

# ------------------------------------------------------------------
# Send method (empty boc -- expected to return graceful error, not crash)
# ------------------------------------------------------------------
echo "-- Send methods (expect graceful error, not crash) --"
rpc_expect_error sendBoc '{"boc":"dGVzdA=="}'
rpc_expect_error sendBocReturnHash '{"boc":"dGVzdA=="}'
echo ""

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
