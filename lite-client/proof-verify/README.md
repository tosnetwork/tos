# tos-proof-verify

`tos-proof-verify` authenticates one masterchain block from a locally
provisioned anchor and returns results proven from that block: configuration
parameters, an account state, and get-method results computed locally on that
proven account state. It is the single verification core shared by every
consumer that must not trust a lite-server or RPC endpoint.

An endpoint only ever supplies proof material. It cannot choose the anchor,
the verifier, the execution context, or the verdict. Any failed check refuses
the whole request; there is no partial result.

## Commands

```
tos-proof-verify anchor --zerostate FILE
tos-proof-verify verify --anchor FILE --request FILE
                        (--liteserver FILE | --material DIR)
                        [--state FILE] [--save-material DIR]
                        [--min-interval-ms N] [--timeout-seconds N]
```

`anchor` reads a locally stored masterchain zerostate BOC and prints its anchor
object (root hash of the deserialized state, file hash = SHA-256 of the bytes).
Use it to provision the anchor from a file you obtained independently, never
from an endpoint.

`verify` either fetches material from a lite-server (`--liteserver`, a lite
client global config listing the server; queries are sent one at a time, at most
one per `--min-interval-ms`, default 200) or reads material saved earlier
(`--material`). `--save-material` keeps the raw answers of a fetch for later
offline re-verification.

Exactly one JSON object is written to stdout, followed by a newline.

| Exit | stdout |
|---|---|
| 0 | `{"status":"verified", ...}` |
| 1 | `{"status":"refused","interface":"tos-proof-verify/1","reason":"..."}` |
| 2 | the same refusal object, for a usage error |

A consumer must treat anything other than exit 0 with `"status":"verified"` and
`"interface":"tos-proof-verify/1"` as a refusal.

## Anchor file

```json
{"kind":"zerostate","workchain":-1,"shard":"8000000000000000","seqno":0,
 "root_hash":"<64 hex>","file_hash":"<64 hex>"}
```

`kind` is `zerostate` (seqno 0) or `key_block` (an explicitly provisioned
trusted key block, seqno > 0). Hashes are hex in either case. Unknown fields are
refused.

## Request file

```json
{"mode":"historical",
 "target":{"seqno":123,"root_hash":"<hex>","file_hash":"<hex>"},
 "config_params":[34],
 "account":"-1:<64 hex>",
 "get_methods":[{"method":"get_pool_data","args":[{"type":"int","value":"5"}]}]}
```

* `mode`: `historical` requires an exact `target` and has no age limit and no
  live state. `live` requires `max_age_seconds` (1 .. 604800) and `--state`;
  `target` is optional — without it the latest block reported by the endpoint is
  used, and then authenticated like any other target.
* `target`: a masterchain block; `workchain` (-1) and `shard`
  (`"8000000000000000"`) may be stated and must then match.
* `config_params`: distinct parameter indexes (at most 64). Each must be present
  and fully contained in the proof.
* `account`: `-1:<hex>` or `0:<hex>`.
* `get_methods`: at most 16, each run on the same proven account state; requires
  `account`. Arguments are listed bottom first, in the order the method takes
  them. Argument entries: `{"type":"null"}`, `{"type":"int","value":"<decimal>"}`,
  `{"type":"cell","boc":"<base64>"}`, `{"type":"slice","boc":"<base64>"}`,
  `{"type":"tuple","items":[...]}`.

Unknown fields are refused everywhere.

## What is checked

1. The proof chain starts at the anchor (or, in live mode, at the newest key
   block this verifier already authenticated from that same anchor and recorded
   in `--state`) and reaches exactly the target, with no gap. Every link is a
   forward link carrying a post-quantum finality signature set; a classical
   carrier is refused.
2. Each link is checked by `block::BlockProofChain::validate`: the validator set
   is computed from the source key block's (or zerostate's) proven
   configuration and must match the destination header; the expected session is
   derived independently from the global id in the source's authenticated
   header, its proven ConfigParams 29/30, the validator set and the
   destination coordinates; signatures are verified with
   `verify_pq_finality` for the final role, refusing unknown, duplicate or
   invalid signers, unsupported algorithms and insufficient verified weight.
3. Configuration, account and library proofs must answer for the exact target
   and descend from its state root (`block::check_extract_state_proof`,
   `block::AccountState::validate`). The account cell must name the requested
   address.
4. Get-methods run locally with this context, all from proven inputs:
   unixtime and logical time of the shard block holding the account; balance,
   code, data and due payment from the proven account; the configuration, global
   version, previous-block information and unpacked configuration from the
   target's proven state; libraries only from a library proof against the target;
   a random seed derived as
   `SHA-256("tos-proof-verify/rand-seed/1" || target root || target file ||
   workchain (4 bytes, big endian) || address)`. Gas limit 1,000,000. A missing
   library, an exit code other than 0 or 1, or any VM failure refuses the request.
5. Live mode only: the target must be no older than `max_age_seconds` by the
   local clock (and not more than 60 s in its future); a target below the
   recorded head is a rollback and is refused; a different block at the head's
   height is a conflict and is refused; a target above the head must be shown
   to descend from it by a backward proof from the target. The state record is
   written only after the whole verification succeeded. Proofs establish
   finality, not that the endpoint returned the newest block.

## Result

```json
{"status":"verified","interface":"tos-proof-verify/1","mode":"historical",
 "anchor":{...},"start":{...block id...},
 "target":{"workchain":-1,"shard":"8000000000000000","seqno":N,
           "root_hash":"...","file_hash":"...","gen_utime":T,"is_key_block":false},
 "chain":{"links":5,"key_blocks":[{...block id...}]},
 "live":{"now":T,"age_seconds":A,"max_age_seconds":M,"descends_from":{...}},
 "request_sha256":"<sha256 of the request file bytes>",
 "config_params":[{"index":34,"cell_hash":"...","boc":"<base64>"}],
 "account":{"address":"-1:...","shard_block":{...},"exists":true,
            "gen_utime":T,"gen_lt":L,"last_trans_lt":L,"last_trans_hash":"...",
            "state_hash":"...","state_boc":"<base64>","balance":"<decimal>",
            "active":true,"code_hash":"...","data_hash":"..."},
 "execution_context":{"unixtime":T,"block_lt":L,"rand_seed":"...",
            "config_root_hash":"...","global_version":G,"gas_limit":1000000,
            "libraries":["..."]},
 "get_methods":[{"method":"...","method_id":I,"args":[...],"exit_code":0,
                 "gas_used":G,"stack":[...],"stack_boc":"<base64 VmStack>"}]}
```

All hashes are lowercase hex. `live` appears only in live mode; `descends_from`
only when a recorded head was extended. `stack` is bottom first: entry 0 is the
first value the method returned. Stack entries use the argument encoding plus
`{"type":"nan"}` and `{"type":"builder","boc":...}`; a slice is rendered as a
cell holding its remaining bits and references. `stack_boc` is the exact
serialized `VmStack`.

## Material directory

Raw lite API answers, TL-serialized, exactly as received:
`masterchain-info.tl`, `chain-0000.tl` ..., `descent-0000.tl`, `config.tl`,
`account.tl`, `exec-config.tl`, `libraries.tl`. Any other entry is refused.
Material carries no authority: re-verifying it needs the same anchor and
request.

## Live state file

Written by the verifier only (`tos-proof-verify-state/1`): the anchor, the
verified head and the newest authenticated key block. It is locked
(`FILE.lock`) for the duration of a run and replaced atomically. A missing file
starts from the anchor.
