#!/usr/bin/env bash
#
# Regression check for the head-tracking lag: send an EVM tx, capture the
# receipt's blockNumber, then assert eth_blockNumber returned by the node
# is >= that block. Pre-fix the node returned 0x0 because store_block()
# never updated the in-RAM block_number_; post-fix store_block() bumps
# block_number_ = max(block_number_, block.number) and the head tracks.
#
# Usage:
#   RPC=http://127.0.0.1:8011 bash proof-block-number-tracks-head.sh
set -euo pipefail
RPC="${RPC:-http://127.0.0.1:8011}"

rpc() {
    local method="$1"; shift
    local params="${1:-[]}"
    curl -sS --max-time 10 -X POST -H 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}" \
        "$RPC"
}

hex_to_int() {
    python3 -c "import sys; print(int(sys.argv[1], 16))" "$1"
}

# 1. Send a tx via the existing helper and capture the receipt block.
out=$(node "$(dirname "$0")/proof-receipt-survives-restart.js")
echo "$out"
receipt_block=$(printf '%s\n' "$out" | sed -n 's/^RECEIPT_BLOCK=//p')
if [ -z "$receipt_block" ]; then
    echo "FAIL: could not parse RECEIPT_BLOCK from helper output" >&2
    exit 1
fi

# 2. Read eth_blockNumber and assert it >= the receipt block.
# Allow a small grace window for catch-up after the receipt landed.
for i in 1 2 3 4 5; do
    resp=$(rpc eth_blockNumber)
    bn_hex=$(printf '%s' "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('result','0x0'))")
    bn=$(hex_to_int "$bn_hex")
    if [ "$bn" -ge "$receipt_block" ]; then
        echo "PASS: eth_blockNumber=${bn_hex} (${bn}) >= RECEIPT_BLOCK=${receipt_block}"
        exit 0
    fi
    echo "  retry ${i}: eth_blockNumber=${bn} < ${receipt_block}"
    sleep 2
done

echo "FAIL: eth_blockNumber=${bn} stayed below RECEIPT_BLOCK=${receipt_block}" >&2
exit 1
