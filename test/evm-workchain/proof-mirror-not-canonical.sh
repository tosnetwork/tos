#!/usr/bin/env bash
#
# Proof test: Phase A's per-account mirror does NOT write into accepted
# canonical wc=1 ShardAccounts.
#
# Background
# ----------
# Phase A added a post-loop merge in Collator::combine_account_transactions
# that walks evm_state_mirror_dict_, wraps each EvmAccountData into a
# ShardAccount cell, and writes via account_dict->set_builder. The local
# AugmentedDictionary in @1's process accepts the writes (DEBUG_MERGE
# readback confirms wrote_nonce == canonical_nonce locally).
#
# However, TOS validate-query (precheck_one_account_update at
# validator/impl/validate-query.cpp:3064-3125) enforces that every
# ShardAccounts change must have a matching AccountBlock. A normal EVM
# tx produces exactly ONE AccountBlock — for the sender's outer account
# (the ext-msg dest, see evm-workchain/crypto/block/evm-workchain/
# evm-external-message.cpp:63). Any other mutations the mirror tries to
# land (recipient balance, contract code, etc.) have no AccountBlock and
# would cause validate-query to reject the block.
#
# Since the chain continues to produce blocks, those multi-account mirror
# writes are NOT part of the accepted state. The accepted state only
# retains what a single AccountBlock commits: the sender's outer account
# with cp.new_data (a cell containing "EVM magic + Maybe ^CellEvmState
# root + bits256 stateRoot", NOT an EvmAccountData). Phase B's hydration
# reads EvmAccountData only, so it skips this cp.new_data format — and
# the sender's nonce reverts to the zerostate value after restart.
#
# This test captures that failure mode:
#   1. Fresh testnet (zerostate seeds 10 EOAs at nonce=0).
#   2. Send 1 tx: sender nonce 0→1 (RPC via RAM).
#   3. Restart validator@1 (wipes RAM, hydrates from canonical).
#   4. Re-query sender nonce:
#      - If 0x1: canonical state preserves the nonce → test PASSES.
#      - If 0x0: canonical state dropped the update → test FAILS (expected).
#
# Exit codes:
#   0 = canonical state preserved the mutation (bug is fixed)
#   1 = script setup error (env / build / testnet)
#   2 = canonical state did NOT preserve the mutation (current behavior)
#
# Usage:  sudo bash test/evm-workchain/proof-mirror-not-canonical.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RPC=http://127.0.0.1:8011
SENDER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
RECIPIENT=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# Devnet fixture account #0 private key. This public Hardhat key must never be
# assumed in production genesis/runtime.
PRIV=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# The test uses a random amount so the tx hash changes across reruns
# (avoids "duplicate message" cache hits on the same signed payload).
AMOUNT_ETH="$((RANDOM % 90 + 10)).$(printf '%02d' $((RANDOM % 100)))"

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
  # $1 = method, $2... = params JSON
  local method="$1"; shift
  local params="${1:-[]}"
  curl -sS --max-time 5 -X POST -H 'Content-Type: application/json' \
    "$RPC" -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['result'])"
}

nonce_of() {
  rpc_quantity eth_getTransactionCount "[\"$1\",\"latest\"]"
}
balance_of() {
  rpc_quantity eth_getBalance "[\"$1\",\"latest\"]"
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

INITIAL_SENDER_NONCE=$(nonce_of "$SENDER")
INITIAL_RECIPIENT_BAL=$(balance_of "$RECIPIENT")
log "  initial sender nonce:    $INITIAL_SENDER_NONCE"
log "  initial recipient balance: $INITIAL_RECIPIENT_BAL"
[ "$INITIAL_SENDER_NONCE" = "0x0" ] || die "sender nonce expected 0x0 on fresh chain"

# --- Stage 2: send tx --------------------------------------------------------
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

# Poll for receipt via curl (ethers' wait() can time out even after mining).
log "  polling receipt..."
DEADLINE=$(( $(date +%s) + 90 ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  RESP=$(curl -sS --max-time 5 -X POST -H 'Content-Type: application/json' "$RPC" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX_HASH\"],\"id\":1}")
  STATUS=$(echo "$RESP" | python3 -c "
import json,sys
r=json.load(sys.stdin).get('result')
print(r.get('status','null') if r else 'null')")
  if [ "$STATUS" = "0x1" ]; then
    log "  receipt: status=0x1"
    break
  fi
  sleep 3
done
[ "$STATUS" = "0x1" ] || die "tx $TX_HASH never mined within 90s: $RESP"

POSTTX_SENDER_NONCE=$(nonce_of "$SENDER")
POSTTX_RECIPIENT_BAL=$(balance_of "$RECIPIENT")
log "  post-tx sender nonce:    $POSTTX_SENDER_NONCE"
log "  post-tx recipient balance: $POSTTX_RECIPIENT_BAL"

[ "$POSTTX_SENDER_NONCE" = "0x1" ] \
  || die "RPC (via g_evm_state RAM) didn't see nonce update — something else is broken"
[ "$POSTTX_RECIPIENT_BAL" != "$INITIAL_RECIPIENT_BAL" ] \
  || die "RPC didn't see recipient balance update — something else is broken"

# --- Stage 3: restart validator@1 -------------------------------------------
log "Stage 3: restart validator@1 (wipes g_evm_state RAM)"
systemctl restart tos-validator@1
log "waiting 60s for hydration to fire..."
sleep 60

# --- Stage 4: re-query canonical-backed state --------------------------------
log "Stage 4: canonical-backed state after hydration"
POSTRESTART_SENDER_NONCE=$(nonce_of "$SENDER")
POSTRESTART_RECIPIENT_BAL=$(balance_of "$RECIPIENT")
log "  post-restart sender nonce:    $POSTRESTART_SENDER_NONCE"
log "  post-restart recipient balance: $POSTRESTART_RECIPIENT_BAL"

# Hydration log line (proves hydration actually ran)
HYDRATION_LINE=$(grep -aE "evm-workchain: hydrated" /data/tos1/log.thread*.log 2>/dev/null \
                 | tail -1 || true)
log "  hydration log: ${HYDRATION_LINE:-<none>}"

# --- Stage 5: verdict --------------------------------------------------------
log "Stage 5: verdict"
if [ "$POSTRESTART_SENDER_NONCE" = "0x1" ] \
   && [ "$POSTRESTART_RECIPIENT_BAL" = "$POSTTX_RECIPIENT_BAL" ]; then
  log "PASS: canonical wc=1 ShardAccounts preserved BOTH sender nonce and recipient balance."
  log "       → Phase A mirror writes ARE landing in accepted state."
  exit 0
fi

log "FAIL (expected): canonical wc=1 ShardAccounts did not preserve mutations."
log "  sender nonce:    pre=$INITIAL_SENDER_NONCE post-tx=$POSTTX_SENDER_NONCE post-restart=$POSTRESTART_SENDER_NONCE"
log "  recipient bal:   pre=$INITIAL_RECIPIENT_BAL post-tx=$POSTTX_RECIPIENT_BAL post-restart=$POSTRESTART_RECIPIENT_BAL"
log ""
log "  Diagnosis:"
log "    * Phase A's per-account mirror merge writes to the collator's"
log "      in-memory AugmentedDictionary locally (DEBUG_MERGE readback"
log "      confirmed this), but those writes do not become part of the"
log "      accepted canonical state on every validator."
log "    * A normal EVM tx produces exactly ONE AccountBlock (for the"
log "      ext-msg dest = sender outer account). validate-query"
log "      (precheck_one_account_update) rejects any ShardAccounts"
log "      change without a matching AccountBlock. Any multi-account"
log "      mutation (recipient, contract code, etc.) the mirror tries"
log "      to write cannot land in a block that survives consensus."
log "    * What DOES land canonically is the sender's outer account"
log "      with cp.new_data = 'EVM magic + Maybe ^CellEvmState root +"
log "      bits256 stateRoot' (evm-compute-phase.cpp:118-141). Phase B"
log "      hydration only understands EvmAccountData format, so it skips"
log "      this cp.new_data cell — sender reverts to the zerostate"
log "      nonce=0 after restart."
log ""
log "  Fix direction: lift to single-executor account (one fixed wc=1"
log "  TOS address; its StateInit.data holds the whole EVM world). Every"
log "  EVM tx mutates exactly one outer TOS account, matching TOS's"
log "  AccountBlock invariant naturally."
exit 2
