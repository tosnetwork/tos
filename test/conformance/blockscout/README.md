# Blockscout indexer sync (Phase P-6)

Phase P-6 of `doc/evm-workchain-test-plan.md` is *Third-party indexer
(Blockscout or similar) syncs the chain without warnings.* This directory
ships a minimal Docker-Compose stack that launches Blockscout 9.0.2 against
the live 4-validator TOS testnet (validator @1, RPC port 8011) and the
diagnostics that catalogue every warning / RPC rejection seen during sync.

**Status (2026-04-18, second run):** Blockscout 9.0.2 reaches
`finished_indexing: true, indexed_blocks_ratio: 1` **directly against the
TOS validator-engine** in under 90 seconds. The two original BUGs (#1
non-spec error envelope, #2 batch-rejection) are **fixed in the
validator-engine** as of:

- `fix(json-rpc-server): emit spec-compliant error envelope` — every
  `/jsonRPC`-envelope error now uses `{jsonrpc, id, error:{code,
  message}}` with HTTP 200 (was: `{ok:false, error:<str>, code:N}` with
  mapped HTTP status).  Blockscout's `EthereumJSONRPC.HTTP.standardize_error/1`
  decodes this without crashing.
- `feat(json-rpc-server): JSON-RPC 2.0 batch request support` — the
  server now parses JSON arrays, dispatches each element through the
  existing single-request handler, and returns the response array
  preserving order.  Notification elements (no `id`) are dropped from
  the output per spec; an all-notification batch returns HTTP 204; an
  empty array returns a single `-32600 Invalid Request`; arrays larger
  than 100 elements are rejected with `-32600 Batch too large` (DoS
  guard).

The `normalize-proxy.py` shim is **retained but no longer wired in**
(see [Files](#files)) — older validator-engine binaries from before the
fix still need it, so we keep the workaround documented. To switch back
to it (e.g. when bisecting a regression), set
`ETHEREUM_JSONRPC_HTTP_URL=http://normalize-proxy:9545/` etc. in
`blockscout.env` and `docker-compose down -v && docker-compose up -d`.

See [Issues found](#issues-found-categorised) below for the categorised
list (BUG #1 / BUG #2 entries are now marked **FIXED**).

The chain currently has 1 block (genesis); steady-state polling exercises
3 RPC methods (`eth_blockNumber`, `eth_getBlockByNumber`, `txpool_content`)
and surfaces 1 missing-method gap. Heavier paths (`eth_getBlockReceipts`,
`eth_getLogs` over wide ranges, `eth_getProof`, `eth_call` against
contracts, `debug_*`) will only fire once the chain has user transactions
to index — re-run after the live testnet has activity to surface that
class. See [Future runs](#future-runs).

---

## Topology

```
+------------------+         forward 0.0.0.0:18011 -> 127.0.0.1:8011
| tos-rpc-forwarder|<-----------------------------------------------+
| (socat, host net)|                                                |
+--------+---------+                                                |
         | 172.17.0.1:18011 (host.docker.internal:18011)            |
         v                                                          |
+--------+---------+    +-------+    +------------+                 |
| blockscout       |--->|  db   |    |  redis-db  |                 |
| backend (9.0.2)  |    +-------+    +------------+                 |
+--------+---------+                                                |
         | host port 4001 (API)                                     |
         v                                                          |
operator $ curl http://localhost:4001/api/v2/...

(Optional, only for bisecting against pre-fix binaries:)

+------------------+
| normalize-proxy  |  rewrites error shape (legacy),
| (python stdlib)  |  fans out batch requests (legacy)
+--------+---------+
         normalize-proxy:9545
         (set ETHEREUM_JSONRPC_HTTP_URL to route through this instead
         of host.docker.internal:18011)
```

The TOS validator binds RPC on `127.0.0.1:8011`. Bridge-mode containers
cannot reach loopback, so `tos-rpc-forwarder` runs in `network_mode:
host` and re-exposes the port on the docker bridge gateway.

---

## Install + run

Prerequisites: docker (tested with `Docker version 29.2.1`) and
`docker-compose` (tested with `Docker Compose version v5.0.2`). Free
disk: ~3 GB for images + DB volume. RAM: ~2 GB at idle, ~3.5 GB during
catchup.

```bash
cd test/conformance/blockscout

# Pull all images (≈1.5 GB; one-shot)
docker-compose pull

# Build the local normalize-proxy image (tiny, stdlib python)
docker-compose build normalize-proxy

# Bring everything up; backend takes ~60-90 s to migrate the schema
docker-compose up -d

# Wait for backend API
until curl -s --max-time 2 http://localhost:4001/api/v2/stats >/dev/null; do
  sleep 4
done

# Confirm sync state
curl -s http://localhost:4001/api/v2/main-page/indexing-status
# {"finished_indexing":true,"finished_indexing_blocks":true,
#  "indexed_blocks_ratio":"1","indexed_internal_transactions_ratio":"1"}

curl -s http://localhost:4001/api/v2/stats | python3 -m json.tool
# total_blocks: "1", total_transactions: "0", ...

# Watch which RPC methods Blockscout is hammering
docker logs --since 1m -f tos-blockscout-normalize-proxy 2>&1 | grep -A 20 'per-method'
```

### Override config snippets

`docker-compose.yml` deviates from upstream in three places:

1. **No frontend / stats / NFT / nginx / sig-provider / visualizer
   services.** P-6 is about the indexer + JSON-RPC, not the UI. The full
   stack is well-documented in upstream's
   `docker-compose/docker-compose.yml`; copy that in if you want the UI.
2. **`normalize-proxy` sits between Blockscout and TOS** (see Issues #1
   and #2). Without it, the indexer GenServer (`Indexer.Block.Catchup.
   MissingRangesCollector`) crashes on the first batch RPC.
3. **`tos-rpc-forwarder`** (`alpine/socat` in host-net) bridges the
   container network to the validator's loopback-only RPC.

`blockscout.env` overrides versus upstream's
`docker-compose/envs/common-blockscout.env`:

| Var | Value | Why |
|-----|-------|-----|
| `ETHEREUM_JSONRPC_HTTP_URL` | `http://normalize-proxy:9545/` | Route via shim |
| `ETHEREUM_JSONRPC_TRACE_URL` | `http://normalize-proxy:9545/` | Same |
| `ETHEREUM_JSONRPC_ETH_CALL_URL` | `http://normalize-proxy:9545/` | Same |
| `ETHEREUM_JSONRPC_VARIANT` | `geth` | TOS speaks geth-flavoured JSON-RPC |
| `CHAIN_ID` | `5525331` | Decimal 0x544f53 |
| `COIN_NAME` / `COIN` / `NETWORK` | `TOS` | Cosmetic |
| `INDEXER_DISABLE_INTERNAL_TRANSACTIONS_FETCHER` | `true` | TOS lacks `debug_traceBlock*` |
| `INDEXER_DISABLE_PENDING_TRANSACTIONS_FETCHER` | (NB: NOT disabled) | Left on intentionally to surface the `txpool_content` gap |
| `INDEXER_DISABLE_BEACON_*` | `true` | Beacon node not present |
| `MICROSERVICE_*_ENABLED` | `false` | Optional sidecars not running |
| `ACCOUNT_CLOAK_KEY` | base64 | Blockscout calls `Base.decode64!/2` on it |

---

## Issues found (categorised)

Definitions:

- **BUG** — TOS RPC violates the JSON-RPC 2.0 wire contract or returns
  wrong data; should be fixed in `validator-engine` (or wherever the
  RPC server lives in `crypto/block/evm-workchain/`).
- **MISSING** — TOS RPC does not implement a method Blockscout calls.
  Whether to add it depends on the indexer feature it gates.
- **SHAPE** — Field is present but not in the shape the spec demands.

### BUG #1 — Error response shape is non-spec — **FIXED**

**Original symptom:** when Blockscout sent a single-call request whose
method was unknown, TOS replied with:

```json
{"ok":false,"jsonrpc":"2.0","id":1,
 "error":"Method not found: txpool_content","code":-32601}
```

JSON-RPC 2.0 (and Blockscout's
`EthereumJSONRPC.HTTP.standardize_error/1`) requires:

```json
{"jsonrpc":"2.0","id":1,
 "error":{"code":-32601,"message":"Method not found: txpool_content"}}
```

**Original severity:** **HARD BLOCKER**. Blockscout's
`Indexer.Block.Catchup.MissingRangesCollector` GenServer crashed with
`FunctionClauseError` on `standardize_error/1`, and the supervisor
restarted it in a tight loop until the next catchup attempt also
crashed. No blocks were indexed.

**Fix:** commit `fix(json-rpc-server): emit spec-compliant error
envelope` switched the JSON-RPC envelope path
(`process_body`/`process_single_object_request` and the dispatcher's
last-resort method-not-found) to use `make_eth_json_error()`.  That
helper emits the spec shape `{jsonrpc, id, error:{code, message}}` with
HTTP 200 — the same shape `evm_workchain::handle_eth_rpc()` already
used for in-EVM errors.  The legacy `make_json_error()` (`{ok:false,
error:<str>, code}` + mapped HTTP status) is retained for the dedicated
REST endpoints (`POST /getMasterchainInfo`, etc.) whose pytest suite
under `test/json-rpc/` still depends on it.

**Verification:** `test/conformance/manual-rpc/error_shape/*.io` pins
the new shape on the wire.  Direct probe:

```bash
$ curl -s -X POST http://127.0.0.1:8011/jsonRPC \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":42,"method":"txpool_content","params":[]}'
{"jsonrpc":"2.0","id":42,"error":{"code":-32601,"message":"Method not found: txpool_content"}}
```

**Secondary BUG (also fixed):** the dispatcher used to return
`"'params' must be an object"` for *unknown methods called with array
params*, masking the real "Method not found" reason because the params
shape check ran before method lookup.  Resolved in the same commit:
when params is an array and the method isn't an `eth_*` method, we now
substitute an empty params object and let the dispatcher emit
`Method not found` (or per-handler missing-field error) via the spec
shape.

### BUG #2 — Batch JSON-RPC unsupported — **FIXED**

**Original symptom:** TOS rejected any JSON-array request body with the
malformed single-error shape from BUG #1 plus message
`"Batch requests are not supported"`.

**Original severity:** **HARD BLOCKER**. Blockscout always batches its
block catchup fetch (10–50 calls per HTTP roundtrip). Without batch
support the entire catchup pipeline failed on the first request.

**Fix:** commit `feat(json-rpc-server): JSON-RPC 2.0 batch request
support` added the spec-compliant batch dispatcher.  Implementation:
`process_body` peeks at the parsed JSON; on Array it hands off to
`process_batch`, which iterates elements sequentially through
`process_single_object_request` (the same code path used for single
requests) and accumulates response bodies into an output array.

Per-spec edge cases:

- **Empty array** → single `-32600 Invalid Request: empty batch`
  response (NOT an empty array).
- **Notification** (element with no `id` field) → response is dropped
  from the output array.
- **All notifications** → HTTP 204 No Content with empty body.
- **Per-element invalid request** (non-Object) → spec-shape `-32600`
  error in that array slot with `id: null`.
- **Batch over 100 elements** → single `-32600 Batch too large` error
  (DoS guard; aligned with ethers BatchProvider / web3.js defaults).
- **Order preserved** (not strictly required by spec but matches
  client expectations).

**Verification:** `test/conformance/manual-rpc/batch/*.io` pins the
contract.  Direct probe:

```bash
$ curl -s -X POST http://127.0.0.1:8011/jsonRPC \
    -H 'Content-Type: application/json' \
    -d '[{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]},
         {"jsonrpc":"2.0","id":2,"method":"eth_chainId","params":[]}]'
[{"jsonrpc":"2.0","id":1,"result":"0x544f53"},
 {"jsonrpc":"2.0","id":2,"result":"0x544f53"}]
```

**Note on serial dispatch:** the batch is processed one element at a
time (each waits for the previous to complete before starting).  This
keeps memory usage and the in-flight liteserver-query count bounded
(one per batch instead of N), and avoids racing `cache_misses_` /
`active_requests_` counters.  With the 100-element cap, worst-case
batch latency is ~100× per-method service time, well under the 30 s
request_timeout.

### MISSING — `txpool_content`

**Symptom:** Blockscout's pending-transactions fetcher polls
`txpool_content` once per second; TOS replies with the BUG #1 error
shape carrying `"Method not found: txpool_content"` (or, when called
with `params: []`, the misleading `"'params' must be an object"`).

**Severity:** **noisy, non-blocking**. Blockscout treats the error as
"no pending data this tick" and moves on. Adds ~5400 lines/hour of
error-level log spam at 1 error / 0.66 s (proxy stats:
`txpool_content err=90` in 6 minutes).

**Should we add it?** **Optional**. TOS's mempool-equivalent visibility
is an open design question (validator-engine's pending pool is not
currently exposed via JSON-RPC). For Blockscout's needs we could either:
- Implement `txpool_content` returning `{"pending":{}, "queued":{}}` —
  trivially makes Blockscout happy and is honest while we have no
  mempool visibility (status quo: nothing is pending).
- Set `INDEXER_DISABLE_PENDING_TRANSACTIONS_FETCHER=true` in
  `blockscout.env` to stop the polling — purely a Blockscout-side mute.

Recommend adding the no-op stub on the TOS side; it's a 5-line method.

### MISSING — `debug_traceBlockByNumber`, `debug_traceBlockByHash`, `debug_traceCall`, `debug_traceTransaction` (all the `debug_trace*` family)

**Detected via direct probe (not yet fired by Blockscout against this
empty chain)**. Blockscout uses these for *internal-transaction*
indexing (calls inside contract calls). With
`INDEXER_DISABLE_INTERNAL_TRANSACTIONS_FETCHER=true` they don't fire.

**Severity:** **major feature gap**. Without `debug_trace*` Blockscout
cannot reconstruct internal transactions, contract creations from
`CREATE2`, or the call tree of a complex tx. UX is degraded but the
indexer doesn't crash — internal-tx columns just stay empty.

**Should we add it?** **Yes for full UX, but heavy.** Geth's tracer
contract is non-trivial; silkworm provides one we could wrap. Track as
a separate phase (Q/R-level), not a P-6 blocker.

### MISSING — `txpool_status`, `parity_subscribe`, `trace_block`, `trace_replayBlockTransactions`

**Detected via direct probe.** Blockscout fallbacks gracefully when
these are absent — no log spam observed (only `txpool_content` is in
the polling loop). All optional.

### MISSING — `eth_getCompilers`

**Detected via direct probe.** Deprecated in geth 1.6+; Blockscout
doesn't call it. Documented for completeness.

### SHAPE — `eth_getBlockByNumber` for unknown blocks returns synthetic placeholder, not `null`

**Symptom:** asking TOS for a block number it doesn't have returns a
fully-populated all-zero-fielded block object instead of the
geth-canonical `null`.

```bash
$ curl ... eth_getBlockByNumber 0x9999999999999999 false
# TOS:  {"result":{"number":"0x9999...","hash":"0x0000...","parentHash":"0x0000...",...}}
# geth: {"result":null}
```

**Severity:** **low / known**. Already documented in
`test/conformance/hive/README.md`; the `tos-rpc-proxy.py` used by Hive
has a `--normalize-not-found` flag that rewrites these. Blockscout
itself only calls `eth_getBlockByNumber` for blocks it already knows
exist (it polled `eth_blockNumber` first), so we did **not** observe a
crash here in the P-6 run. But any indexer that scans speculatively
ahead of `eth_blockNumber` will mis-attribute these placeholders as
real blocks and corrupt its DB. Recommend fixing on the TOS side: when
the requested block number > tip, return `null`.

### SHAPE — block-0 (genesis) hash is all-zero

**Symptom:** `eth_getBlockByNumber 0x0` returns a block with
`hash: "0x0000...0000"` and `parentHash: "0x0000...0000"`.

**Severity:** **cosmetic for now, latent risk**. Blockscout indexes it
fine because it's "the only block" and genesis-hash collisions never
occur. But the moment block 1 is produced, `parentHash` of block 1 will
be the *real* hash of block 0, not all-zero — which is fine — yet
fetching genesis again will still return the all-zero hash, creating
a chain-discontinuity in any indexer that double-checks
`block(N).parentHash == block(N-1).hash`. Recommend computing genesis's
hash like any other block.

### Benign noise (NOT bugs)

- `Could not find static manifest at "/app/lib/block_scout_web-9.0.2/
  priv/static/cache_manifest.json"` — Blockscout backend was started
  without the frontend asset bundle. Expected since we run API-only.
- `Failed to drop DB index 'logs_block_number_ASC__index_ASC_index':
  deadlock_detected` — Blockscout's own DB migration race during first
  startup; self-resolves on retry. Not RPC-related.
- `Failed to fetch rate limit config: :invalid_config_url. Fallback to
  local config.` — Blockscout config loader; benign.
- `Mint.TransportError{reason: :econnrefused}` — only seen for the brief
  ~1 s window when `normalize-proxy` was being recreated; auto-recovers
  via `URL ... is available now, switching back from fallback urls`.

---

## What Blockscout actually exercised in this run

Per-method tally from the second-run direct-pipe (no normalize-proxy)
after ~3 min steady-state on the still-empty (1-block) chain.  The
shape changes (BUG #1 / #2 fixed) mean we no longer have a per-method
tally from a proxy — the validator-engine itself exposes per-method
counters at `:9100/metrics` (Prometheus), e.g.
`jsonrpc_method_requests_total{method="eth_blockNumber"}`.  Methods
exercised under continuous polling on this empty chain:

| Method | Result |
|--------|--------|
| `eth_blockNumber` | OK |
| `eth_getBlockByNumber` | OK |
| `txpool_content` | err — `-32601 Method not found` (spec-shape, decoded by Blockscout) |

Methods exercised at startup but not in steady-state:
`eth_chainId`, `net_version`, `web3_clientVersion`, `eth_syncing`,
`eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory`,
`eth_getBalance` (for the all-zero-address coinbase).

Methods Blockscout *would* call once the chain has activity, validated
ad-hoc but not under indexing load:
`eth_getBlockReceipts`, `eth_getTransactionReceipt`,
`eth_getTransactionByHash`, `eth_getLogs`, `eth_call`, `eth_getCode`,
`eth_getStorageAt`, `eth_getProof`, `eth_estimateGas`.
**All return spec-shape responses on direct probe.** See section
"Future runs" below.

## Future runs

When the testnet has user transactions:

1. Re-launch the stack: `docker-compose up -d` (DB volume persists).
2. Wait for catchup to re-poll the new tip.
3. Tail `normalize-proxy` per-method stats for any new errors.
4. Hit `/api/v2/transactions`, `/api/v2/blocks/<hash>`, and
   `/api/v2/addresses/<addr>` to exercise the receipt + log + balance
   read paths through the API layer.

Suggested smoke transactions:
- A simple value transfer (exercises `eth_getBalance` + receipts).
- A contract deploy (exercises `eth_getCode`, `eth_getTransactionReceipt`
  with a `contractAddress` field).
- An ERC-20 transfer (exercises `eth_getLogs` topic filtering and the
  token-transfer fetcher).

## Teardown

```bash
# Stop everything, drop the named DB volume
docker-compose down -v

# Optional: remove the local proxy image
docker rmi tos-blockscout-normalize-proxy:local
```

The validator on port 8011 is untouched throughout — this entire stack
is read-only against TOS.

## Files

- `docker-compose.yml` — the stack (5 services).
- `blockscout.env` — Blockscout backend env. ~70 vars; only the ones
  that differ from upstream defaults.
- `Dockerfile.normalize-proxy` — 6-line `python:3.12-slim` image.
- `normalize-proxy.py` — the JSON-RPC compatibility shim (BUGs #1, #2).
- `README.md` — this file.
