#!/usr/bin/env bash
# =============================================================================
# bootstrap-validators.sh — single-container 4-validator + DHT bootstrap
# =============================================================================
#
# Brings up the minimum TOS topology required for a fresh chain inside a
# single container (no systemd, no useradd, no Python orchestration). All 4
# validators + 1 DHT node share the same loopback addresses (127.0.0.1) on
# distinct ports, write their state under "${DATA}/{tos1..tos4,dht}", and
# log to stderr (so docker logs captures everything).
#
# This script is the bash port of the proven path that
# `scripts/setup-testnet.sh` follows via Python+tostester. We avoid pulling
# in the tostester package (Python 3.14, libtoslibjson.so, pytosiq_core,
# nacl, ...) so the runtime image stays close to the slim proxy build.
#
# Inputs (env):
#   DATA                  base data dir (default /data)
#   FIFT_DIR              fift include dir (default /usr/local/share/tos/fift/lib)
#   SMARTCONT_DIR         smartcont include dir (default /usr/local/share/tos/smartcont)
#   GENESIS_ALLOC_FIF     optional Fift include emitting an alloc tuple +
#                         calling evm-zerostate-from-alloc
#                         (default: zero-arg evm-zerostate-accounts-cell)
#   TOS_EVM_CHAIN_ID      decimal evm chain id; exported to validators
#   PORT_BASE             starting port (default 2000); contiguous block of 16 ports used
#   READY_HOOK            optional command run once tos1 RPC is up
#
# Outputs:
#   ${DATA}/state/{zerostate,basestate0,evmstate1}.{boc,fhash,rhash}
#   ${DATA}/{tos1..tos4}/{config.json,keyring/,static/}
#   ${DATA}/dht/{config.json,keyring/}
#   ${DATA}/tos-global.json
#   ${DATA}/testnet-ports.json
#   PIDs in ${DATA}/run/{dht,tos1..tos4}.pid
#
# Exit code 0 once all 4 validators have been launched (in background) and
# the script has registered a SIGTERM handler that kills them. The caller
# is expected to `wait` on $!.
# =============================================================================

set -euo pipefail

DATA="${DATA:-/data}"
FIFT_DIR="${FIFT_DIR:-/usr/local/share/tos/fift/lib}"
SMARTCONT_DIR="${SMARTCONT_DIR:-/usr/local/share/tos/smartcont}"
GENESIS_ALLOC_FIF="${GENESIS_ALLOC_FIF:-}"
PORT_BASE="${PORT_BASE:-2000}"
TOS_EVM_CHAIN_ID="${TOS_EVM_CHAIN_ID:-5525331}"

KEYGEN="${KEYGEN:-/usr/local/bin/tos-genkey}"
CREATE_STATE="${CREATE_STATE:-/usr/local/bin/tos-create-state}"
VALIDATOR_ENGINE="${VALIDATOR_ENGINE:-/usr/local/bin/tos-validator-engine}"
DHT_SERVER="${DHT_SERVER:-/usr/local/bin/tos-dht-server}"

log() { printf '[bootstrap] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

[ -x "$KEYGEN" ]           || die "missing $KEYGEN"
[ -x "$CREATE_STATE" ]     || die "missing $CREATE_STATE"
[ -x "$VALIDATOR_ENGINE" ] || die "missing $VALIDATOR_ENGINE"
[ -x "$DHT_SERVER" ]       || die "missing $DHT_SERVER"
command -v jq >/dev/null   || die "missing jq"
command -v python3 >/dev/null || die "missing python3"

mkdir -p "$DATA" "$DATA/run" "$DATA/state"

# -----------------------------------------------------------------------------
# Port plan (loopback, distinct per service):
#   DHT     :  $PORT_BASE
#   tos1    :  validator=$PORT_BASE+1  liteserver=+2  console=+3  jsonrpc=8011
#   tos2    :  validator=$PORT_BASE+4  liteserver=+5  console=+6  jsonrpc=8012
#   tos3    :  validator=$PORT_BASE+7  liteserver=+8  console=+9  jsonrpc=8013
#   tos4    :  validator=$PORT_BASE+10 liteserver=+11 console=+12 jsonrpc=8014
# -----------------------------------------------------------------------------
DHT_PORT=$((PORT_BASE + 0))
declare -a VAL_PORT=( $((PORT_BASE+1)) $((PORT_BASE+4)) $((PORT_BASE+7)) $((PORT_BASE+10)) )
declare -a LS_PORT=(  $((PORT_BASE+2)) $((PORT_BASE+5)) $((PORT_BASE+8)) $((PORT_BASE+11)) )
declare -a CON_PORT=( $((PORT_BASE+3)) $((PORT_BASE+6)) $((PORT_BASE+9)) $((PORT_BASE+12)) )
# JSON-RPC ports (where Hive talks to us on validator 1).
RPC_BASE="${RPC_BASE:-8011}"
declare -a RPC_PORT=( $((RPC_BASE+0)) $((RPC_BASE+1)) $((RPC_BASE+2)) $((RPC_BASE+3)) )

IP_INT=2130706433  # 127.0.0.1

# -----------------------------------------------------------------------------
# 1. Generate keys.
#
# `tos-genkey -m keys -n NAME` writes:
#    NAME      = 36 bytes: 4-byte magic 17 23 68 49 + 32-byte ed25519 priv
#    NAME.pub  = 36 bytes: 4-byte magic c6 b4 13 48 + 32-byte ed25519 pub
# and prints "<HEX_SHORTID> <BASE64_SHORTID>" to stdout. The keyring file
# name expected by validator-engine is the HEX_SHORTID (uppercase).
#
# Per validator we need 5 keys (fullnode, validator, liteserver, console-server,
# console-client). Plus 1 for the DHT node.
# -----------------------------------------------------------------------------
gen_key() {
    # gen_key <out_dir> <var_prefix>
    # Side effects: $out_dir/$var_prefix and $out_dir/$var_prefix.pub
    # Sets globals: ${var_prefix^^}_HEX, ${var_prefix^^}_B64
    local out="$1"; local name="$2"
    mkdir -p "$out"
    local stdout
    stdout="$( "$KEYGEN" -m keys -n "$out/$name" 2>/dev/null )"
    local hex_id b64_id
    hex_id="$(printf '%s\n' "$stdout" | awk '{print $1}')"
    b64_id="$(printf '%s\n' "$stdout" | awk '{print $2}')"
    [ -n "$hex_id" ] || die "keygen produced empty short id"
    # Move file under its canonical hex name (uppercase) for the keyring layout.
    mv "$out/$name"     "$out/$hex_id"
    mv "$out/$name.pub" "$out/$hex_id.pub"
    # Export back via printf-friendly globals.
    printf '%s %s\n' "$hex_id" "$b64_id"
}

# Helper: convert HEX short id (64 hex chars) to base64-of-32-bytes (no newline).
hex2b64() {
    python3 -c "import sys, base64; print(base64.b64encode(bytes.fromhex(sys.argv[1])).decode())" "$1"
}

# DHT node key.
#   DHT_HEX      = uppercase hex of the short id (= keyring filename)
#   DHT_ID_B64   = base64 of the short id bytes (= what config.json `id` fields use)
log "Generating DHT key..."
mkdir -p "$DATA/dht/keyring"
read -r DHT_HEX DHT_ID_B64 < <(gen_key "$DATA/dht/keyring" "dht")
log "  DHT short id: $DHT_HEX"

# Per-validator keys.
declare -a FN_HEX FN_ID_B64 VAL_HEX VAL_ID_B64 LS_HEX LS_ID_B64 CSV_HEX CSV_ID_B64 CCL_HEX CCL_ID_B64
for i in 0 1 2 3; do
    n=$((i+1))
    KR="$DATA/tos$n/keyring"
    mkdir -p "$KR"
    read -r v1 v2 < <(gen_key "$KR" "fn$n");   FN_HEX[$i]="$v1";  FN_ID_B64[$i]="$v2"
    read -r v1 v2 < <(gen_key "$KR" "val$n");  VAL_HEX[$i]="$v1"; VAL_ID_B64[$i]="$v2"
    read -r v1 v2 < <(gen_key "$KR" "ls$n");   LS_HEX[$i]="$v1";  LS_ID_B64[$i]="$v2"
    read -r v1 v2 < <(gen_key "$KR" "csv$n");  CSV_HEX[$i]="$v1"; CSV_ID_B64[$i]="$v2"
    read -r v1 v2 < <(gen_key "$KR" "ccl$n");  CCL_HEX[$i]="$v1"; CCL_ID_B64[$i]="$v2"
    log "  tos$n keys: fn=${FN_HEX[$i]:0:8}.. val=${VAL_HEX[$i]:0:8}.. ls=${LS_HEX[$i]:0:8}.."
done

# Public-key bytes (32-byte raw, base64) — needed for global config liteservers
# (the `pub.ed25519.key` field) and for the validator set in zerostate (where
# `add-validator` consumes the raw 32-byte pubkey, NOT the short id). The
# .pub file is 4-byte magic + 32-byte ed25519 pubkey.
read_pub_b64() {
    python3 -c "
import sys, base64, pathlib
p = pathlib.Path(sys.argv[1]).read_bytes()
assert p[:4] == bytes.fromhex('c6b41348'), 'wrong magic'
print(base64.b64encode(p[4:]).decode())
" "$1"
}

declare -a VAL_PUB_B64 LS_PUB_B64
for i in 0 1 2 3; do
    n=$((i+1))
    VAL_PUB_B64[$i]="$(read_pub_b64 "$DATA/tos$n/keyring/${VAL_HEX[$i]}.pub")"
    LS_PUB_B64[$i]="$(read_pub_b64 "$DATA/tos$n/keyring/${LS_HEX[$i]}.pub")"
done
DHT_PUB_B64="$(read_pub_b64 "$DATA/dht/keyring/$DHT_HEX.pub")"

# -----------------------------------------------------------------------------
# 2. DHT signed address — needed for tos-global.json static_nodes.
#    `tos-genkey -m dht -k <pk> -a <addr-list-json>` outputs a signed dht.node.
# -----------------------------------------------------------------------------
log "Signing DHT address..."
DHT_ADDR_LIST="$(jq -nc \
    --argjson ip "$IP_INT" \
    --argjson port "$DHT_PORT" \
    '{ "@type": "adnl.addressList",
       "addrs": [{"@type":"adnl.address.udp","ip":$ip,"port":$port}],
       "version":0,"reinit_date":0,"priority":0,"expire_at":0 }')"

DHT_SIGNED_NODE="$( "$KEYGEN" -m dht \
    -k "$DATA/dht/keyring/$DHT_HEX" \
    -a "$DHT_ADDR_LIST" )"

# -----------------------------------------------------------------------------
# 3. Build tos-global.json — DHT static node + validator zerostate hashes
#    (we write file_hash/root_hash placeholders now, then patch in step 5).
# -----------------------------------------------------------------------------
log "Writing tos-global.json (placeholder hashes; patched after zerostate)"
GLOBAL="$DATA/tos-global.json"

# We synthesize the JSON via Python rather than jq because jq parses numbers
# as doubles, losing precision on the magic shard value -2^63
# (-9223372036854775808). Python's json module preserves arbitrary-precision
# ints round-trip, which is what tos-validator-engine's TL parser expects.
LS_PORT_LIST="${LS_PORT[*]}"
LS_PUB_LIST="${LS_PUB_B64[*]}"
DHT_SIGNED_NODE="$DHT_SIGNED_NODE" \
LS_PORT_LIST="$LS_PORT_LIST" \
LS_PUB_LIST="$LS_PUB_LIST" \
IP_INT="$IP_INT" \
GLOBAL="$GLOBAL" \
python3 - <<'PYEOF'
import json, os
ip_int = int(os.environ["IP_INT"])
ls_ports = [int(x) for x in os.environ["LS_PORT_LIST"].split()]
ls_pubs  = os.environ["LS_PUB_LIST"].split()
dht_node = json.loads(os.environ["DHT_SIGNED_NODE"])
out = {
  "@type": "config.global",
  "dht": {
    "@type": "dht.config.global",
    "static_nodes": {"@type": "dht.nodes", "nodes": [dht_node]},
    "k": 3, "a": 3,
  },
  "validator": {
    "@type": "validator.config.global",
    "zero_state": {
      "@type": "tosNode.blockIdExt",
      "workchain": -1,
      "shard": -9223372036854775808,
      "seqno": 0,
      "root_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "file_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    },
    "hardforks": [],
  },
  "liteservers": [
    {"ip": ip_int, "port": p, "id": {"@type": "pub.ed25519", "key": k}}
    for p, k in zip(ls_ports, ls_pubs)
  ],
}
with open(os.environ["GLOBAL"], "w") as f:
    json.dump(out, f, indent=2)
PYEOF

# -----------------------------------------------------------------------------
# 4. Per-node config.json
# -----------------------------------------------------------------------------
write_node_config() {
    local n="$1"; local i=$((n-1))
    local out="$DATA/tos$n/config.json"
    # IMPORTANT: The `id` field in engine.adnl/dht/validator/etc. config
    # entries is the SHORT id (b64 of the 32-byte sha256 of TL-serialized
    # pubkey), NOT the raw pubkey bytes b64. The validator-engine looks up
    # `keyring/<UPPER_HEX_OF_SHORT_ID>` on startup. (Ref: tostester
    # `Engine_adnl(id=key.id(), ...)` where Key.id() returns the short id.)
    jq -n \
        --argjson ip "$IP_INT" \
        --argjson val_port "${VAL_PORT[$i]}" \
        --argjson ls_port  "${LS_PORT[$i]}" \
        --argjson con_port "${CON_PORT[$i]}" \
        --arg     fn_id   "${FN_ID_B64[$i]}" \
        --arg     val_id  "${VAL_ID_B64[$i]}" \
        --arg     ls_id   "${LS_ID_B64[$i]}" \
        --arg     csv_id  "${CSV_ID_B64[$i]}" \
        --arg     ccl_id  "${CCL_ID_B64[$i]}" \
        '{ "@type":"engine.validator.config",
           "out_port":0,
           "addrs":[{ "@type":"engine.addr","ip":$ip,"port":$val_port,
                      "categories":[0],"priority_categories":[] }],
           "adnl":[
             { "@type":"engine.adnl","id":$fn_id,"category":0 },
             { "@type":"engine.adnl","id":$val_id,"category":0 }
           ],
           "dht":[ { "@type":"engine.dht","id":$fn_id } ],
           "validators":[
             { "@type":"engine.validator",
               "id":$val_id,
               "temp_keys":[
                 { "@type":"engine.validatorTempKey","key":$val_id,"expire_at":2147483647 }
               ],
               "adnl_addrs":[
                 { "@type":"engine.validatorAdnlAddress","id":$val_id,"expire_at":2147483647 }
               ],
               "election_date":0,"expire_at":2147483647 }
           ],
           "fullnode":$fn_id,
           "fullnodeslaves":[],"fullnodemasters":[],
           "liteservers":[ { "@type":"engine.liteServer","id":$ls_id,"port":$ls_port } ],
           "control":[
             { "@type":"engine.controlInterface","id":$csv_id,"port":$con_port,
               "allowed":[ { "@type":"engine.controlProcess","id":$ccl_id,"permissions":15 } ] }
           ],
           "shards_to_monitor":[],
           "gc":{"@type":"engine.gc","ids":[]} }' > "$out"
}

for n in 1 2 3 4; do
    mkdir -p "$DATA/tos$n/static" "$DATA/tos$n/session-logs"
    write_node_config "$n"
done

# DHT local config — same key short-id semantics as above.
jq -n \
    --argjson ip "$IP_INT" \
    --argjson port "$DHT_PORT" \
    --arg dht_id "$DHT_ID_B64" \
    '{ "@type":"engine.validator.config",
       "out_port":0,
       "addrs":[{"@type":"engine.addr","ip":$ip,"port":$port,
                 "categories":[0],"priority_categories":[]}],
       "adnl":[{"@type":"engine.adnl","id":$dht_id,"category":0}],
       "dht":[{"@type":"engine.dht","id":$dht_id}],
       "validators":[],"fullnode":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
       "fullnodeslaves":[],"fullnodemasters":[],
       "liteservers":[],"control":[],"shards_to_monitor":[],
       "gc":{"@type":"engine.gc","ids":[]} }' > "$DATA/dht/config.json"

# -----------------------------------------------------------------------------
# 5. Generate zerostate.
#
# We inline the same Fift template the Python `tostester.zerostate.create_zerostate`
# builds, with these substitutions:
#   {validators}            -> 4 lines of `B{<hex>} 17 add-validator`
#   {mc_validators}         -> 4
#   {monitor_min_split}=0   {split}=0
#   {global_version}=13     {shard_val}=4
#   {block_limit_mul}=1
#   {*_lifetime}=100000
#   {new_consensus_config}  -> two `make-simplex-params` lines (mc + shard)
# Plus, IF $GENESIS_ALLOC_FIF is given, replace the `evm-zerostate-accounts-cell`
# call (no args, baked-in 10 EOAs) with `include` of the alloc fif (which calls
# `evm-zerostate-from-alloc` to leave the cell on stack).
# -----------------------------------------------------------------------------
log "Generating zerostate (chainId=$TOS_EVM_CHAIN_ID, alloc=${GENESIS_ALLOC_FIF:-builtin-10-EOAs})"

ZS_FIF="$DATA/state/gen-zerostate-evm.fif"

# How to push the EVM accounts cell on the stack?
if [ -n "$GENESIS_ALLOC_FIF" ] && [ -s "$GENESIS_ALLOC_FIF" ]; then
    EVM_ACCOUNTS_PROVIDER='"'"$GENESIS_ALLOC_FIF"'" include'
else
    EVM_ACCOUNTS_PROVIDER='evm-zerostate-accounts-cell'
fi

# 4 validator pubkeys to add
VAL_KEYS_FIF=""
for i in 0 1 2 3; do
    pub_hex="$( python3 -c "
import sys, base64
b = base64.b64decode(sys.argv[1])
print(b.hex())
" "${VAL_PUB_B64[$i]}" )"
    VAL_KEYS_FIF+="B{$pub_hex} 17 add-validator
"
done

cat > "$ZS_FIF" <<FIF
"TosUtil.fif" include
"Asm.fif" include
"Lists.fif" include
"FiftExt.fif" include

256 1<<1- 15 / constant AllOnes

wc_master setworkchain
3 setglobalid

// Initial state of Workchain 0 (Basic workchain) — empty mintless basechain.
0 mkemptyShardState

{ <b x{a7} s, 5 roll 32 u, 4 roll 8 u, 3 roll 8 u, rot 8 u, x{e000} s,
  3 roll 256 u, rot 256 u, 0 32 u, x{1} s, -1 32 i, 0 64 u, x{0} s, 20 32 u, 20 32 u, 10 32 u, 1000 32 u, 0 8 u, b>
  dup isWorkchainDescr? not abort"invalid WorkchainDescr created"
  <s swap workchain-dict @ 32 idict!+ 0= abort"cannot add workchain"
  workchain-dict !
} : add-std-workchain-v2

// EVM workchain (wc=1) — vm_version=0x45564D ("EVM").
{ <b x{a7} s, 5 roll 32 u, 4 roll 8 u, 3 roll 8 u, rot 8 u, x{e000} s,
  3 roll 256 u, rot 256 u, 0 32 u, x{1} s, 0x45564D 32 i, 0 64 u, x{0} s, 20 32 u, 20 32 u, 10 32 u, 1000 32 u, 0 8 u, b>
  dup isWorkchainDescr? not abort"invalid WorkchainDescr created"
  <s swap workchain-dict @ 32 idict!+ 0= abort"cannot add workchain"
  workchain-dict !
} : add-evm-workchain-v2

dup dup 31 boc+>B dup "basestate0.boc" B>file
Bhashu dup =: basestate0_fhash 256 u>B "basestate0.fhash" B>file
hashu dup =: basestate0_rhash 256 u>B "basestate0.rhash" B>file
basestate0_rhash basestate0_fhash now 0 0 dup 0 add-std-workchain-v2

// EVM workchain zerostate.
// ( accounts_ref wc -- shard_state_cell )
{ <b x{9023afe2} s, globalid@ 32 i, 0 8 i,
  swap 32 i, 1 63 << 64 u, 0 64 i, now 32 u, 0 64 i, -1 32 i,
  <b 0 67 u, b> ref, 0 1 u,
  swap ref,
  <b 0 128 10 + 1+ 1+ u, b> ref, 0 1 u, b>
  dup isShardState? not abort"invalid ShardState created"
} : mkShardStateWithAccounts

$EVM_ACCOUNTS_PROVIDER 1 mkShardStateWithAccounts
dup dup 31 boc+>B dup "evmstate1.boc" B>file
Bhashu dup =: evmstate1_fhash 256 u>B "evmstate1.fhash" B>file
hashu dup =: evmstate1_rhash 256 u>B "evmstate1.rhash" B>file
evmstate1_rhash evmstate1_fhash now 0 0 dup 1 add-evm-workchain-v2

config.workchains!

// SmartContract #1 (Simple wallet)
<{ SETCP0 DUP IFNOTRET
   DUP 85143 INT EQUAL IFJMP:<{
     DROP c4 PUSHCTR CTOS 32 PLDU
   }>
   INC 32 THROWIF
   512 INT LDSLICEX DUP 32 PLDU
   c4 PUSHCTR CTOS 32 LDU 256 LDU ENDS
   s1 s2 XCPU
   EQUAL 33 THROWIFNOT
   s2 PUSH HASHSU
   s0 s4 s4 XC2PU
   CHKSIGNU
   34 THROWIFNOT
   ACCEPT
   SWAP 32 LDU NIP 8 LDU LDREF ENDS
   SWAP SENDRAWMSG
   INC NEWC 32 STU 256 STU ENDC c4 POPCTR
}>c
<b 0 32 u,
   "main-wallet.pk" load-generate-keypair drop
   B,
b>
Libs{
  x{ABACABADABACABA} s>c public_lib
  x{1234} x{5678} |_ s>c private_lib
}Libs
TM\$4999990000
0
0
AllOnes 0 *
6
register_smc
dup make_special dup constant smc1_addr
Masterchain over
2dup ."wallet address = " .addr cr 2dup 6 .Addr cr
"main-wallet.addr" save-address-verbose

// SmartContract #3
PROGRAM{
  recv_internal x{} PROC
  run_ticktock PROC:<{
    c4 PUSHCTR CTOS 32 LDU 256 LDU ENDS
    NEWC ROT INC 32 STUR OVER 256 STUR ENDC
    c4 POPCTR
    NEWC b{00100010011111111} STSLICECONST TUCK 256 STU
    100000000 INT STTOMIS
    1 4 + 4 + 64 + 32 + 1+ 1+ INT STZEROES ENDC
    ZERO SENDRAWMSG
    -17 INT 256 STIR 130000000 INT STTOMIS
    107 INT STZEROES ENDC
    ZERO
    NEWC b{11000100100000} "test" \$>s |+ STSLICECONST
    123456789 INT STTOMIS
    107 INT STZEROES "Hello, world!" \$>s STSLICECONST ENDC
    ZERO SENDRAWMSG SENDRAWMSG
  }>
}END>c
<b x{11EF55AA} s, smc1_addr 256 u, b>
Libs{
  x{ABACABADABACABA} s>c public_lib
  x{1234} x{5678} |_ s>c public_lib
}Libs
TM\$1
0
3
2
register_smc
dup make_special dup constant smc3_addr
."address = " 64x. cr

// SmartContract #4 (elector)
"auto/elector-code.fif" include
<b 0 1 1+ 1+ 4 + 32 + u, 0 256 u, b>
empty_cell
TM\$10
0
2
AllOnes 3 *
6
register_smc
dup make_special dup constant smc4_addr dup constant elector_addr
Masterchain swap
."elector smart contract address = " 2dup .addr cr 2dup 7 .Addr cr
"elector" +".addr" save-address-verbose

// Configuration parameters
13 capCreateStats capBounceMsgBody or capReportVersion or capShortDequeue or capStoreOutMsgQueueSize or capMsgMetadata or capDeferMessages or config.version!
<b globalid@ 32 i, b> 19 config!
40 20 4 config.validator_num!
TM\$10000 TM\$100000 TM\$10000 sg~10 config.validator_stake_limits!
86400 4000 600 1000 config.election_params!
AllOnes 5 * constant config_addr
config_addr config.config_smc!
elector_addr config.elector_smc!

1 500 1000 500000 config.storage_prices!
config.special!

10 sg* 1 *M dup   10000 1000 *M TM\$0.1 TM\$1.0 100 1000 config.gas_prices!
10 sg* 1 *M 20 *M 10000 1000 *M TM\$0.1 TM\$1.0 100 1000 config.mc_gas_prices!
100 10 sg* 10 sg* 3/2 sg*/ 1/3 sg*/ 1/3 sg*/ config.fwd_prices!
100 10 sg* 10 sg* 3/2 sg*/ 1/3 sg*/ 1/3 sg*/ config.mc_fwd_prices!
100000 100000 100000 4 true config.catchain_params!

<b x{d9} s, 1 8 u, 3 8 u, 2000 32 u, 16000 32 u, 3 32 u, 8 32 u, 4 32 u, 4 *Mi 32 u, 4 *Mi 32 u, 5 16 u, 0 32 u, b>
29 config!

{ <b x{5e} s, 3 roll param_limits, rot param_limits, swap param_limits,
  x{d3} s, 200000 32 u, 30 32 u, b>
} : make-block-limits-v2

128 *Ki 512 *Ki 1 * 1 *Mi 1 * triple
2000000 100000000 100000000 triple
1000 500000 1000000 triple
triple dup
untriple make-block-limits 22 config!
untriple make-block-limits 23 config!

TM\$1.7 TM\$1 config.block_create_fees!
smc1_addr config.minter_smc!

1000000000000 -17 of-cc 666666666666 239 of-cc cc+ config.to_mint!

( 0 1 9 10 12 14 15 16 17 18 20 21 22 23 24 25 28 34 ) config.mandatory_params!
( -999 -1000 -1001 0 1 9 10 12 14 15 16 17 32 34 36 ) config.critical_params!

_( 2 3 2 2 1000000 10000000 1 500 )
_( 4 7 4 2 5000000 20000000 2 1000 )
config.param_proposals_setup!

TM\$100 1 500 config.complaint_prices!

$VAL_KEYS_FIF
now dup 3600 + 4 config.validators!

400 4 1000 2 make-simplex-params
400 4 1000 2 make-simplex-params
config.new_consensus_params_all!

{
  =: data
  <b @' data B, b> <s
    b{00000000}
} : collator-entry
{ -rot dup sbits rot swap [[ <{ DICTSET }>s ]] 0 runvmx abort"dict-insert failed" } : dict-insert

// SmartContract #5 (Configuration)
"auto/config-code.fif" include
<b configdict ref,
   0 32 u,
   "config-master" +".pk" load-generate-keypair drop
   B,
   dictnew dict,
b>
empty_cell
TM\$10
0 1 config_addr 6 register_smc
dup set_config_smc
Masterchain swap
."config smart contract address = " 2dup .addr cr 2dup 7 .Addr cr
"config-master" +".addr" save-address-verbose

create_state
dup 31 boc+>B dup "zerostate.boc" B>file
Bhashu dup =: zerostate_fhash 256 u>B "zerostate.fhash" B>file
hashu dup =: zerostate_rhash 256 u>B "zerostate.rhash" B>file
FIF

# Run create-state. The cwd is set so output BOCs land in $DATA/state.
log "Running tos-create-state (this can take 5-15s)..."
( cd "$DATA/state" && \
  FIFTPATH="$FIFT_DIR:$SMARTCONT_DIR" \
    "$CREATE_STATE" -I "$FIFT_DIR:$SMARTCONT_DIR" "$ZS_FIF" \
  ) > "$DATA/state/create-state.log" 2>&1 || {
    log "ERROR: tos-create-state failed; tail of log follows"
    tail -50 "$DATA/state/create-state.log" >&2 || true
    die "zerostate generation failed"
}

ZS_BOC="$DATA/state/zerostate.boc"
ZS_FHASH="$DATA/state/zerostate.fhash"
ZS_RHASH="$DATA/state/zerostate.rhash"
[ -s "$ZS_BOC" ]   || die "missing $ZS_BOC after create-state"
[ -s "$ZS_FHASH" ] || die "missing $ZS_FHASH after create-state"
[ -s "$ZS_RHASH" ] || die "missing $ZS_RHASH after create-state"

ZS_FHASH_B64="$( python3 -c "import base64,sys; print(base64.b64encode(open(sys.argv[1],'rb').read()).decode())" "$ZS_FHASH" )"
ZS_RHASH_B64="$( python3 -c "import base64,sys; print(base64.b64encode(open(sys.argv[1],'rb').read()).decode())" "$ZS_RHASH" )"
ZS_FHASH_HEX="$( python3 -c "import sys; print(open(sys.argv[1],'rb').read().hex().upper())" "$ZS_FHASH" )"
BS_FHASH_HEX="$( python3 -c "import sys; print(open(sys.argv[1],'rb').read().hex().upper())" "$DATA/state/basestate0.fhash" )"
EVM_FHASH_HEX="$( python3 -c "import sys; print(open(sys.argv[1],'rb').read().hex().upper())" "$DATA/state/evmstate1.fhash" )"

log "  zerostate root  = $ZS_RHASH_B64"
log "  zerostate file  = $ZS_FHASH_B64"

# Patch the global config with real hashes (using python to keep the
# shard:-2^63 int intact — see comment above).
ZS_RHASH_B64="$ZS_RHASH_B64" ZS_FHASH_B64="$ZS_FHASH_B64" GLOBAL="$GLOBAL" \
python3 - <<'PYEOF'
import json, os
p = os.environ["GLOBAL"]
with open(p) as f:
    d = json.load(f)
d["validator"]["zero_state"]["root_hash"] = os.environ["ZS_RHASH_B64"]
d["validator"]["zero_state"]["file_hash"] = os.environ["ZS_FHASH_B64"]
with open(p, "w") as f:
    json.dump(d, f, indent=2)
PYEOF

# -----------------------------------------------------------------------------
# 6. Distribute zerostate to each validator's static dir (symlinks).
# -----------------------------------------------------------------------------
for n in 1 2 3 4; do
    ln -sf "$ZS_BOC"             "$DATA/tos$n/static/$ZS_FHASH_HEX"
    ln -sf "$DATA/state/basestate0.boc" "$DATA/tos$n/static/$BS_FHASH_HEX"
    ln -sf "$DATA/state/evmstate1.boc"  "$DATA/tos$n/static/$EVM_FHASH_HEX"
done

# -----------------------------------------------------------------------------
# 7. Write port info for callers.
# -----------------------------------------------------------------------------
jq -n \
    --argjson dht "$DHT_PORT" \
    --argjson v1 "${VAL_PORT[0]}" --argjson l1 "${LS_PORT[0]}" --argjson c1 "${CON_PORT[0]}" --argjson r1 "${RPC_PORT[0]}" \
    --argjson v2 "${VAL_PORT[1]}" --argjson l2 "${LS_PORT[1]}" --argjson c2 "${CON_PORT[1]}" --argjson r2 "${RPC_PORT[1]}" \
    --argjson v3 "${VAL_PORT[2]}" --argjson l3 "${LS_PORT[2]}" --argjson c3 "${CON_PORT[2]}" --argjson r3 "${RPC_PORT[2]}" \
    --argjson v4 "${VAL_PORT[3]}" --argjson l4 "${LS_PORT[3]}" --argjson c4 "${CON_PORT[3]}" --argjson r4 "${RPC_PORT[3]}" \
    '{ "dht_port":$dht,
       "nodes":[
         {"idx":1,"validator_port":$v1,"liteserver_port":$l1,"console_port":$c1,"jsonrpc_port":$r1},
         {"idx":2,"validator_port":$v2,"liteserver_port":$l2,"console_port":$c2,"jsonrpc_port":$r2},
         {"idx":3,"validator_port":$v3,"liteserver_port":$l3,"console_port":$c3,"jsonrpc_port":$r3},
         {"idx":4,"validator_port":$v4,"liteserver_port":$l4,"console_port":$c4,"jsonrpc_port":$r4}
       ] }' > "$DATA/testnet-ports.json"

# -----------------------------------------------------------------------------
# 8. Launch DHT + 4 validators in background.
# -----------------------------------------------------------------------------
if [ "${BOOTSTRAP_DRY_RUN:-0}" = "1" ]; then
    log "BOOTSTRAP_DRY_RUN=1 — skipping process launch (zerostate + configs ready under $DATA)"
    exit 0
fi

log "Launching DHT server on udp/$DHT_PORT..."
"$DHT_SERVER" \
    --global-config "$GLOBAL" \
    --local-config "$DATA/dht/config.json" \
    --db "$DATA/dht" \
    --threads 2 \
    > "$DATA/dht/log" 2>&1 &
DHT_PID=$!
echo "$DHT_PID" > "$DATA/run/dht.pid"

# Give DHT 2s to bind.
sleep 2

declare -a NODE_PIDS=()
for n in 1 2 3 4; do
    i=$((n-1))
    log "Launching validator $n on val=$IP_INT:${VAL_PORT[$i]} ls=${LS_PORT[$i]} jsonrpc=${RPC_PORT[$i]}..."
    (
        cd "$DATA/tos$n"
        export TOS_EVM_CHAIN_ID="$TOS_EVM_CHAIN_ID"
        exec "$VALIDATOR_ENGINE" \
            --global-config "$GLOBAL" \
            --local-config "$DATA/tos$n/config.json" \
            --db "$DATA/tos$n" \
            --fift-dir "$FIFT_DIR" \
            --initial-sync-delay 5 \
            --session-logs "$DATA/tos$n/session-logs" \
            --quic-flood-control -1 \
            -t 4 \
            -l "$DATA/tos$n/log" \
            --json-rpc-address "0.0.0.0:${RPC_PORT[$i]}" \
            --json-rpc-cors-origin "*" \
            > "$DATA/tos$n/stderr.log" 2>&1
    ) &
    pid=$!
    NODE_PIDS+=( "$pid" )
    echo "$pid" > "$DATA/run/tos$n.pid"
done

# Forward SIGTERM/SIGINT to children.
_term() {
    log "received termination signal — killing children"
    kill "${NODE_PIDS[@]}" "$DHT_PID" 2>/dev/null || true
    wait
    exit 0
}
trap _term SIGTERM SIGINT

log "All processes spawned: dht=$DHT_PID validators=(${NODE_PIDS[*]})"
log "Tailing combined logs to stderr; container will block on validator processes."

# Tail every validator log to our stderr so docker logs sees everything.
tail -F -q "$DATA/dht/log" \
       "$DATA/tos1/log.thread0.log" 2>/dev/null \
       "$DATA/tos2/log.thread0.log" 2>/dev/null \
       "$DATA/tos3/log.thread0.log" 2>/dev/null \
       "$DATA/tos4/log.thread0.log" 2>/dev/null \
       "$DATA/tos1/stderr.log" \
       "$DATA/tos2/stderr.log" \
       "$DATA/tos3/stderr.log" \
       "$DATA/tos4/stderr.log" >&2 &
TAIL_PID=$!

# Wait for any node to exit (one going down means consensus is gone).
wait -n "${NODE_PIDS[@]}" "$DHT_PID"
RC=$?
log "ERROR: a child process exited with code $RC — tearing down"
kill "${NODE_PIDS[@]}" "$DHT_PID" "$TAIL_PID" 2>/dev/null || true
wait
exit "$RC"
