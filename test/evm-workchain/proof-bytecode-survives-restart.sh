#!/usr/bin/env bash
#
# Proof test (Phase E.4): deployed contract bytecode survives validator
# restart under the single-executor design.
#
# Background
# ----------
# Under the single-executor design (Phase E.1), the entire EVM world —
# including contract code — is serialized into cp.new_data on the
# executor account (wc=1, addr=0x00..01) and rebuilt from canonical
# state on restart by populate_state_from_shard_accounts. This test
# proves that code_ (the in-RAM bytecode map CellEvmState holds) is
# fully re-populated from canonical state after process restart.
#
# Before Phase E.1, bytecode was attempted to be embedded in each
# account's StateInit.code via the mirror merge — but that mutation
# was rejected by validate-query's AccountBlock invariant, so
# eth_getCode returned 0x after restart for any contract that hadn't
# been re-called yet.
#
# Test flow
#   1. Fresh testnet.
#   2. Deploy a minimal contract (tiny stub that returns 0x42).
#   3. Verify eth_getCode returns the deployed runtime bytecode.
#   4. Restart validator@1 (wipes RAM).
#   5. Verify eth_getCode STILL returns the same runtime bytecode.
#   6. Verify eth_call still executes against the contract.
#
# Exit codes:
#   0 = bytecode survived restart (E.4 passes)
#   1 = setup error
#   2 = bytecode did not survive restart
#
# Usage:  sudo bash test/evm-workchain/proof-bytecode-survives-restart.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RPC=http://127.0.0.1:8011
DEPLOYER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
# Devnet fixture account #0 private key. This public Hardhat key must never be
# assumed in production genesis/runtime.
PRIV=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

log() { echo "[$(date +%H:%M:%S)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

[ "${TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS:-}" = "1" ] || \
  die "devnet fixture requires TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS=1; public Hardhat keys are not production genesis"

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
[ -x /usr/local/bin/tos-validator-engine ] || die "tos-validator-engine not installed"
[ -x "$REPO_ROOT/scripts/setup-testnet.sh" ] || die "setup-testnet.sh missing"
[ -x "$REPO_ROOT/scripts/testnet-ctl.sh" ] || die "testnet-ctl.sh missing"

rpc_quantity() {
  local method="$1"; shift
  local params="${1:-[]}"
  curl -sS --max-time 5 -X POST -H 'Content-Type: application/json' \
    "$RPC" -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['result'])"
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

# --- Stage 2: deploy minimal contract ---------------------------------------
#
# Contract (minimal): returns 0x42 on any call.
#   Runtime bytecode (10 bytes):
#     60 42      PUSH1 0x42      // value to return
#     60 00      PUSH1 0x00      // memory offset
#     52         MSTORE          // memory[0x00..0x20] = 0x42
#     60 20      PUSH1 0x20      // length = 32
#     60 00      PUSH1 0x00      // offset = 0
#     F3         RETURN
#   = 0x604260005260206000f3
#
# Deploy code (constructor, 12 bytes): copies the 10-byte runtime into return data.
#   600a       PUSH1 0x0a       // runtime length = 10
#   600c       PUSH1 0x0c       // runtime offset in deploy bytecode = 12
#   6000       PUSH1 0x00       // destination in memory
#   39         CODECOPY         // copy 10 bytes
#   600a       PUSH1 0x0a       // return length
#   6000       PUSH1 0x00       // return offset
#   f3         RETURN
#   <runtime>  604260005260206000f3
#
# Concat:  0x600a600c600039600a6000f3604260005260206000f3  (22 bytes total)
DEPLOY_BYTECODE="0x600a600c600039600a6000f3604260005260206000f3"
# Runtime (what eth_getCode returns after deploy) — 10 bytes.
EXPECTED_RUNTIME="0x604260005260206000f3"

log "Stage 2: deploy minimal contract"
DEPLOY_OUT=$(cd /tmp && timeout 30 "$NODE" -e "
const {ethers}=require('ethers');
(async()=>{
  const p=new ethers.JsonRpcProvider('$RPC',undefined,{batchMaxCount:1});
  const w=new ethers.Wallet('$PRIV',p);
  const tx=await w.sendTransaction({data:'$DEPLOY_BYTECODE',gasLimit:200000n});
  console.log(tx.hash);
})().catch(e=>{console.error(e.message);process.exit(7)});
" 2>&1 | tail -1) || die "failed to submit deploy tx: $DEPLOY_OUT"
TX_HASH="$DEPLOY_OUT"
log "  deploy tx hash: $TX_HASH"

log "  polling receipt..."
CONTRACT_ADDR=""
DEADLINE=$(( $(date +%s) + 90 ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  RESP=$(curl -sS --max-time 5 -X POST -H 'Content-Type: application/json' "$RPC" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX_HASH\"],\"id\":1}")
  PARSED=$(echo "$RESP" | python3 -c "
import json,sys
r=json.load(sys.stdin).get('result')
if not r:
  print('null null')
else:
  print(r.get('status','null'), r.get('contractAddress','null'))")
  STATUS=$(echo "$PARSED" | awk '{print $1}')
  ADDR=$(echo "$PARSED" | awk '{print $2}')
  if [ "$STATUS" = "0x1" ]; then
    CONTRACT_ADDR="$ADDR"
    log "  receipt: status=0x1 contractAddress=$CONTRACT_ADDR"
    break
  fi
  sleep 3
done
[ "$STATUS" = "0x1" ] || die "deploy tx never mined within 90s: $RESP"
[ -n "$CONTRACT_ADDR" ] && [ "$CONTRACT_ADDR" != "null" ] \
  || die "no contractAddress in receipt: $RESP"

# --- Stage 3: eth_getCode before restart ------------------------------------
log "Stage 3: eth_getCode before restart"
PRERESTART_CODE=$(rpc_quantity eth_getCode "[\"$CONTRACT_ADDR\",\"latest\"]")
log "  pre-restart code: $PRERESTART_CODE"
[ "$PRERESTART_CODE" = "$EXPECTED_RUNTIME" ] \
  || die "pre-restart code mismatch: got=$PRERESTART_CODE expected=$EXPECTED_RUNTIME"

# --- Stage 4: restart validator@1 -------------------------------------------
log "Stage 4: restart validator@1 (wipes g_evm_state RAM)"
systemctl restart tos-validator@1
log "waiting 60s for hydration to fire..."
sleep 60

# --- Stage 5: eth_getCode after restart -------------------------------------
log "Stage 5: eth_getCode after restart"
POSTRESTART_CODE=$(rpc_quantity eth_getCode "[\"$CONTRACT_ADDR\",\"latest\"]")
log "  post-restart code: $POSTRESTART_CODE"

HYDRATION_LINE=$(grep -aE "evm-workchain: hydrated" /data/tos1/log.thread*.log 2>/dev/null \
                 | tail -1 || true)
log "  hydration log: ${HYDRATION_LINE:-<none>}"

# --- Stage 6: eth_call against the contract ---------------------------------
log "Stage 6: eth_call against contract after restart"
CALL_RESULT=$(rpc_quantity eth_call \
  "[{\"to\":\"$CONTRACT_ADDR\",\"data\":\"0x\"},\"latest\"]" || echo "call-failed")
log "  eth_call returned: $CALL_RESULT"

# --- Stage 7: verdict --------------------------------------------------------
log "Stage 7: verdict"
if [ "$POSTRESTART_CODE" = "$EXPECTED_RUNTIME" ]; then
  log "PASS: contract bytecode survived restart."
  log "       → single-executor cp.new_data → populate_state_from_shard_accounts"
  log "         correctly rehydrated code_ from canonical state."
  # eth_call must also return the expected 0x42, padded to 32 bytes.
  EXPECTED_CALL="0x0000000000000000000000000000000000000000000000000000000000000042"
  if [ "$CALL_RESULT" = "$EXPECTED_CALL" ]; then
    log "       + eth_call against the contract returned 0x42 as expected."
  else
    log "WARN: eth_call returned $CALL_RESULT (expected $EXPECTED_CALL)"
    log "      → bytecode is present but silkworm execution against it failed."
    exit 2
  fi
  exit 0
fi

log "FAIL: contract bytecode did not survive restart."
log "  contract:      $CONTRACT_ADDR"
log "  pre-restart:   $PRERESTART_CODE"
log "  post-restart:  $POSTRESTART_CODE"
log "  expected:      $EXPECTED_RUNTIME"
exit 2
