#!/usr/bin/env bash
#
# End-to-end check that block/tx indexing RPC methods return correct
# data for a transaction we just mined. Covers the six methods listed
# as "weak coverage" in doc/evm-workchain-known-divergences.md:
#
#   - debug_getRawTransaction       (RLP of a tx we just sent)
#   - debug_getRawBlock             (RLP of the block that contains it)
#   - debug_getRawHeader            (RLP of that block's header)
#   - debug_getRawReceipts          (RLP list of that block's receipts)
#   - eth_getBlockTransactionCountByHash
#   - eth_getTransactionByBlockHashAndIndex
#   - eth_getTransactionByBlockNumberAndIndex
#   - eth_getBlockReceipts
#
# The execution-apis conformance suite flags these methods as
# SHAPE_MISMATCH when queried against hashes that don't exist on our
# chain (false positives — see Category A). This test fills that gap
# by seeding a known tx on *our* chain first, then asserting each
# method returns sensible data indexed by the freshly-observed hashes.
#
# Exit codes:
#   0 = every probe passes (methods indexing correctly)
#   1 = setup / env error
#   2 = one or more probes returned wrong data
#
# Usage:  sudo bash test/evm-workchain/proof-rpc-indexing.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RPC=http://127.0.0.1:8011
SENDER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
RECIPIENT=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# Hardhat account #0 private key
PRIV=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Randomize amount so the tx hash changes across reruns.
AMOUNT_ETH="$((RANDOM % 90 + 10)).$(printf '%02d' $((RANDOM % 100)))"

log() { echo "[$(date +%H:%M:%S)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# Accumulate failures but keep probing so the log shows every gap in
# one run; set exit code at the end.
FAILED=0
fail() {
  echo "  FAIL: $*" >&2
  FAILED=1
}

# Discover node (nvm installs don't land in root's PATH under sudo).
NODE="${NODE_BIN:-}"
if [ -z "$NODE" ]; then
  NODE=$(command -v node || true)
fi
if [ -z "$NODE" ]; then
  for n in /home/tomi/.nvm/versions/node/*/bin/node /usr/local/bin/node; do
    [ -x "$n" ] && NODE="$n" && break
  done
fi

[ "$(id -u)" -eq 0 ] || die "run with sudo (needs systemctl + setup-testnet.sh)"
[ -x "$NODE" ] || die "node not found (set NODE_BIN or install via nvm)"
command -v curl >/dev/null || die "curl not on PATH"
command -v python3 >/dev/null || die "python3 not on PATH"
[ -x /usr/local/bin/tos-validator-engine ] || die "tos-validator-engine not installed"
[ -x "$REPO_ROOT/scripts/setup-testnet.sh" ] || die "setup-testnet.sh missing"
[ -x "$REPO_ROOT/scripts/testnet-ctl.sh" ] || die "testnet-ctl.sh missing"

# ---- JSON-RPC helpers ------------------------------------------------------

# rpc <method> <params-json> → raw full JSON response
rpc() {
  local method="$1"; local params="${2:-[]}"
  curl -sS --max-time 5 -X POST -H 'Content-Type: application/json' \
    "$RPC" -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}"
}

# rpc_result <method> <params-json> → the "result" value (JSON, including quotes for strings)
rpc_result() {
  rpc "$1" "$2" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin).get('result')))"
}

# Strip Python's double-encoded quotes — give the raw hex string / null / number.
rpc_raw() {
  rpc "$1" "$2" | python3 -c "
import json,sys
r = json.load(sys.stdin).get('result')
if r is None: print('null')
elif isinstance(r, str): print(r)
else: print(json.dumps(r))"
}

# --- Stage 1: fresh testnet --------------------------------------------------
log "Stage 1: clean testnet"
HOME=/home/tomi REPO_ROOT="$REPO_ROOT" \
  "$REPO_ROOT/scripts/setup-testnet.sh" --clean >/dev/null 2>&1 \
  || die "setup-testnet.sh --clean failed"
"$REPO_ROOT/scripts/testnet-ctl.sh" start >/dev/null 2>&1 \
  || die "testnet-ctl.sh start failed"

log "waiting 90s for wc=1 to finalize past block 1..."
sleep 90

# --- Stage 2: send a tx and wait for receipt --------------------------------
log "Stage 2: send $AMOUNT_ETH TOS transfer"
TX_HASH=$(cd /tmp && timeout 30 "$NODE" -e "
const {ethers}=require('ethers');
(async()=>{
  const p=new ethers.JsonRpcProvider('$RPC',undefined,{batchMaxCount:1});
  const w=new ethers.Wallet('$PRIV',p);
  const tx=await w.sendTransaction({to:'$RECIPIENT',value:ethers.parseEther('$AMOUNT_ETH'),gasLimit:21000n});
  console.log(tx.hash);
})().catch(e=>{console.error(e.message);process.exit(7)});
" 2>&1 | tail -1) || die "failed to submit tx: $TX_HASH"
log "  tx hash: $TX_HASH"

log "  polling for receipt..."
DEADLINE=$(( $(date +%s) + 90 ))
BLOCK_NUM=""
BLOCK_HASH=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  RCPT=$(rpc eth_getTransactionReceipt "[\"$TX_HASH\"]")
  PARSED=$(echo "$RCPT" | python3 -c "
import json,sys
r = json.load(sys.stdin).get('result')
if not r: print('null null null'); exit()
print(r.get('status','null'), r.get('blockNumber','null'), r.get('blockHash','null'))")
  STATUS=$(echo "$PARSED" | awk '{print $1}')
  if [ "$STATUS" = "0x1" ]; then
    BLOCK_NUM=$(echo "$PARSED" | awk '{print $2}')
    BLOCK_HASH=$(echo "$PARSED" | awk '{print $3}')
    break
  fi
  sleep 3
done
[ "$STATUS" = "0x1" ] || die "tx $TX_HASH never mined within 90s"
log "  mined in block $BLOCK_NUM (hash=$BLOCK_HASH)"

# --- Stage 3: probe each indexing RPC method --------------------------------
log "Stage 3: indexing RPC probes"

# 3a. debug_getRawTransaction — returns RLP hex of the tx.
log "  3a. debug_getRawTransaction($TX_HASH)"
RAW_TX=$(rpc_raw debug_getRawTransaction "[\"$TX_HASH\"]")
if [ "$RAW_TX" = "null" ] || [ -z "$RAW_TX" ] || [ "${#RAW_TX}" -lt 10 ]; then
  fail "expected non-empty RLP hex, got '$RAW_TX'"
else
  case "$RAW_TX" in
    0x*) log "      OK (len=${#RAW_TX})" ;;
    *) fail "expected '0x'-prefixed RLP, got '${RAW_TX:0:80}'" ;;
  esac
fi

# 3b. debug_getRawHeader — RLP of the block header at this number.
log "  3b. debug_getRawHeader($BLOCK_NUM)"
RAW_HDR=$(rpc_raw debug_getRawHeader "[\"$BLOCK_NUM\"]")
if [ "$RAW_HDR" = "null" ] || [ "${#RAW_HDR}" -lt 10 ]; then
  fail "expected non-empty RLP header, got '$RAW_HDR'"
else
  case "$RAW_HDR" in
    0x*) log "      OK (len=${#RAW_HDR})" ;;
    *) fail "expected '0x'-prefixed RLP, got '${RAW_HDR:0:80}'" ;;
  esac
fi

# 3c. debug_getRawBlock — RLP of the block (header + txs + ommers).
log "  3c. debug_getRawBlock($BLOCK_NUM)"
RAW_BLOCK=$(rpc_raw debug_getRawBlock "[\"$BLOCK_NUM\"]")
if [ "$RAW_BLOCK" = "null" ] || [ "${#RAW_BLOCK}" -lt 10 ]; then
  fail "expected non-empty RLP block, got '$RAW_BLOCK'"
else
  case "$RAW_BLOCK" in
    0x*) log "      OK (len=${#RAW_BLOCK}, ≥ header)" ;;
    *) fail "expected '0x'-prefixed RLP, got '${RAW_BLOCK:0:80}'" ;;
  esac
  # Sanity: full block must be at least as long as the header.
  if [ "${#RAW_BLOCK}" -lt "${#RAW_HDR}" ] 2>/dev/null; then
    fail "block RLP shorter than header RLP — malformed"
  fi
fi

# 3d. debug_getRawReceipts — list of RLP hex strings.
log "  3d. debug_getRawReceipts($BLOCK_NUM)"
RAW_RECEIPTS=$(rpc debug_getRawReceipts "[\"$BLOCK_NUM\"]" | python3 -c "
import json,sys
r = json.load(sys.stdin).get('result')
if not isinstance(r, list):
  print('NOT_A_LIST'); exit()
print(f'count={len(r)} first_len={len(r[0]) if r else 0}')")
case "$RAW_RECEIPTS" in
  count=1*) log "      OK ($RAW_RECEIPTS)" ;;
  count=0*) fail "expected ≥1 receipt, got 0" ;;
  NOT_A_LIST) fail "not a list" ;;
  *) log "      OK ($RAW_RECEIPTS) — multi-tx block is fine" ;;
esac

# 3e. eth_getBlockTransactionCountByHash — hex quantity, expect ≥ 0x1.
log "  3e. eth_getBlockTransactionCountByHash($BLOCK_HASH)"
TX_COUNT=$(rpc_raw eth_getBlockTransactionCountByHash "[\"$BLOCK_HASH\"]")
if [ "$TX_COUNT" = "null" ] || [ "$TX_COUNT" = "0x0" ]; then
  fail "expected ≥ 0x1, got '$TX_COUNT'"
else
  log "      OK ($TX_COUNT)"
fi

# 3f. eth_getTransactionByBlockHashAndIndex — should return our tx object.
log "  3f. eth_getTransactionByBlockHashAndIndex($BLOCK_HASH, 0x0)"
TX_BY_HASH_IDX=$(rpc eth_getTransactionByBlockHashAndIndex "[\"$BLOCK_HASH\",\"0x0\"]" | python3 -c "
import json,sys
r = json.load(sys.stdin).get('result')
if not r: print('null'); exit()
print(r.get('hash', 'missing-hash'))")
if [ "$TX_BY_HASH_IDX" = "$TX_HASH" ]; then
  log "      OK (hash matches)"
else
  fail "expected tx.hash=$TX_HASH, got $TX_BY_HASH_IDX"
fi

# 3g. eth_getTransactionByBlockNumberAndIndex — same but by number.
log "  3g. eth_getTransactionByBlockNumberAndIndex($BLOCK_NUM, 0x0)"
TX_BY_NUM_IDX=$(rpc eth_getTransactionByBlockNumberAndIndex "[\"$BLOCK_NUM\",\"0x0\"]" | python3 -c "
import json,sys
r = json.load(sys.stdin).get('result')
if not r: print('null'); exit()
print(r.get('hash', 'missing-hash'))")
if [ "$TX_BY_NUM_IDX" = "$TX_HASH" ]; then
  log "      OK (hash matches)"
else
  fail "expected tx.hash=$TX_HASH, got $TX_BY_NUM_IDX"
fi

# 3h. eth_getBlockReceipts — list containing our tx's receipt.
log "  3h. eth_getBlockReceipts($BLOCK_NUM)"
BLOCK_RCPTS=$(rpc eth_getBlockReceipts "[\"$BLOCK_NUM\"]" | python3 -c "
import json,sys
r = json.load(sys.stdin).get('result')
if not isinstance(r, list):
  print('NOT_A_LIST'); exit()
if not r:
  print('EMPTY'); exit()
print(r[0].get('transactionHash', 'missing'))")
if [ "$BLOCK_RCPTS" = "$TX_HASH" ]; then
  log "      OK (receipt[0].transactionHash matches)"
elif [ "$BLOCK_RCPTS" = "EMPTY" ]; then
  fail "expected ≥1 receipt in list, got empty"
elif [ "$BLOCK_RCPTS" = "NOT_A_LIST" ]; then
  fail "not a list"
else
  fail "expected receipt[0].transactionHash=$TX_HASH, got $BLOCK_RCPTS"
fi

# --- Stage 4: verdict -------------------------------------------------------
log "Stage 4: verdict"
if [ "$FAILED" -eq 0 ]; then
  log "PASS: all 8 indexing RPC methods returned correct data for the seeded tx."
  log "       → execution-apis Category A false positives are now covered by this proof."
  exit 0
fi
log "FAIL: one or more indexing RPC probes returned wrong data (see 'FAIL:' lines above)."
exit 2
