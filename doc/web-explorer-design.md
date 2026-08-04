# TOS Web Explorer — Design Document

## Status

- Document type: product/technical design proposal, non-normative
- Status: proposed
- Date: 2026-08-04
- Related code: `~/tos/validator-engine/json-rpc-server*.cpp`, `~/tos/doc/json-rpc-policy.md`,
  `~/tos/doc/openapi.yaml`, `~/tos/crypto/block/check-proof.{h,cpp}`, `~/tos/emulator/CMakeLists.txt`
  (existing Emscripten precedent)
- Related prior art (do not build on top of): `~/tos/blockchain-explorer/` (legacy, inherited from
  Telegram Systems LLP's TON explorer, server-rendered Bootstrap-4 HTML tables, no JSON API, no
  visualization layer)

## 1. Purpose

Build a new, standalone, browser-based block explorer for TOS Network with a distinct visual
identity: a real-time, cinematic, "digital-rain" / neon-glow presentation of chain activity —
blocks, shards, accounts and transactions rendered as a living, animated graph rather than as
static HTML tables. The explorer should read as a piece of the TOS brand (precise, engineering-
forward, technically substantiated — see `~/tos/doc/tos.pdf` §2 Design Principles) while looking
unmistakably premium: this is the public-facing surface most people will actually open, and it
should not look like a decade-old testnet tool.

Concretely, the explorer must, at minimum:

- Show the most recent masterchain blocks (initial scope: last 10) as they are produced, with
  seqno, shard summary, transaction count and timestamp.
- Let a viewer drill into a block to see its transactions, and into a transaction to see its
  accounts, value and fees.
- Let a viewer look up an account/address and see its balance, state and recent transaction
  history.
- Render all of the above as an animated, force-directed relationship graph (blocks → shard
  blocks → transactions → accounts) with continuous motion, particle/glow effects and smooth
  entry animation for new blocks — not a plain list.

## 2. Non-Goals (this iteration)

- No wallet functionality (no signing, no `sendBoc`/`sendQuery`); the explorer is read-only.
- No indexing of full historical chain state at launch. MVP renders a rolling recent window
  (blocks, and transactions/accounts reachable from those blocks); a full historical index/search
  engine is a later phase.
- No NFT/Jetton-style token gallery UI at launch (the underlying RPC methods exist —
  `getTokenData`, `getAccountJettons`, `getAccountNfts` — but are out of scope for v1).
- No attempt to replace or modify `~/tos/blockchain-explorer/`; it can keep serving as an
  operator-facing debug tool. This is a fully separate product.
- No multi-node/liteserver-pool aggregation at launch — see §9 for the single-node caveat this
  implies.

## 3. Why the existing tooling doesn't fit

Two things already exist in the repo that touch this problem; neither is a foundation to build on:

1. **`~/tos/blockchain-explorer/`** — a C++ `libmicrohttpd` HTTP server
   (`blockchain-explorer-http.cpp`, `blockchain-explorer-query.cpp`) that talks the raw ADNL
   lite-client protocol to a liteserver and renders server-side Bootstrap-4 HTML (`<table
   class="table-sm table-striped">`, `bootstrap.min.css` from a CDN). Its copyright header reads
   `Copyright 2017-2020 Telegram Systems LLP` — it is the original TON explorer, unmodified in
   substance. It emits HTML, not JSON, and has no visualization layer of any kind. Not reusable
   for a modern web frontend.
2. **Raw ADNL / lite-client** (`~/tos/adnl/`, `~/tos/lite-client/`) — the TL-schema query interface
   (`liteServer.getMasterchainInfo`, `liteServer.getBlock`, `liteServer.getAccountState`, etc.,
   defined in `~/tos/tl/generate/scheme/lite_api.tl`) is the "real" protocol everything else is
   built on, but it is a binary protocol over a custom ADNL transport (UDP-based, with its own
   handshake and encryption). There is no WebSocket or HTTP transport for it anywhere in this
   repository, and no browser can speak it directly. It is not a viable integration point for a
   browser frontend without writing and running a custom bridge process — which brings us to §4.

## 4. Data Source: the embedded JSON-RPC server

`validator-engine` already embeds a JSON-RPC 2.0 HTTP server for exactly this purpose
(`~/tos/validator-engine/json-rpc-server.{h,cpp}` + `json-rpc-server-{blocks,accounts,
transactions,send,runmethod,config,token,...}.cpp`; policy documented in
`~/tos/doc/json-rpc-policy.md`; machine-readable spec in `~/tos/doc/openapi.yaml`). This is the
correct integration point. It is off by default and must be explicitly enabled by the node
operator:

```
--json-rpc-address <host:port>      # required; server is disabled unless this is set
--json-rpc-readonly                 # recommended for an explorer: disables sendBoc/sendBocReturnHash/sendQuery
--json-rpc-cors-origin <origin>     # default "*"; set explicitly for production
--json-rpc-api-key <key>            # optional; if set, callers must present it
--json-rpc-trust-proxy-headers      # only if the explorer's own backend sits behind a reverse proxy TOS should trust
```

(Flags confirmed directly in `validator-engine.cpp` — `set_json_rpc_cors_origin` at line 5894;
option registrations at lines 6479, 6486, 6489, 6509, 6529.)

Per `json-rpc-policy.md` R6, every query is routed through
`ValidatorManagerInterface::run_ext_query` against **that validator's own local liteserver
state** — there is no built-in liteserver pool or failover. For an explorer this means: point it
at one (or, for redundancy, several independently polled) known-good node(s); do not assume the
JSON-RPC server load-balances for you.

### 4.1 Transport shape

- `POST /jsonRPC` — standard JSON-RPC 2.0 (`{"method": "...", "params": {...}, "id": ...}`). This
  is the only endpoint for write methods and the fully general form for all read methods.
- `GET /<methodName>?param1=val1&param2=val2` — REST-style aliases, confirmed in
  `json-rpc-server.cpp` (search `─── REST-style GET endpoints ───`, ~line 495), mapped 1:1 to the
  same handlers as the equivalent `POST /jsonRPC` call, **for a curated read-only subset only**.
  Confirmed available via GET, and directly relevant to the explorer:
  `getMasterchainInfo`, `getConsensusBlock`, `lookupBlock`, `shards` (alias `getShards`),
  `getBlockHeader`, `getBlockTransactions`, `getBlockTransactionsExt`, `getTransactions`,
  `getTransactionsStd`, `getAddressInformation`, `getExtendedAddressInformation`,
  `getAddressBalance`, `getAddressState`, `getWalletInformation`, `getConfigParam`,
  `getConfigAll`, `tryLocateTx`/`tryLocateResultTx`/`tryLocateSourceTx`,
  `getMasterchainBlockSignatures`, `getShardBlockProof`, `getLibraries`, `getTokenData`,
  `packAddress`/`unpackAddress`/`detectAddress`/`detectHash`, `getOutMsgQueueSize`,
  `estimateFee`.
  (`sendBoc`/`sendBocReturnHash`/`sendQuery` and the agent/session/delegation write methods are
  POST-only by design — irrelevant here since the explorer is read-only.)
- `GET /healthcheck`, `GET /readyz` — liveness/readiness probes.
- `GET /api-info` — machine-readable metadata listing the server's own endpoints
  (`health`, `readyz`, `api_info`, and the Prometheus `metrics` URL). No auth required.
- Prometheus metrics are exposed separately on `http://<node>:9100/metrics` (confirmed in
  `json-rpc-server.cpp`; counters/gauges collected in `JsonRpcServer::collect`, e.g.
  `jsonrpc_requests_total`, `jsonrpc_errors_total`, `jsonrpc_cache_hits_total`).
- `OPTIONS` on any path returns a CORS preflight response.

There is **no push/subscription transport** (no WebSocket, no SSE, no long-poll) on this server —
every read is a discrete request against current state, per R8 ("no response caching... every
request executes a fresh liteserver query"). Real-time behavior on the explorer side must be
built by polling. This directly shapes the architecture in §6.

Parameter handling worth designing around (`json-rpc-policy.md` R10/R11):

- `getTransactions` defaults `limit=10` (max 100); `getBlockTransactions` /
  `getBlockTransactionsExt` default `count=40`.
- Address parameters accept both raw (`workchain:hex`) and user-friendly base64/base64url form —
  the explorer does not need to pre-normalize addresses before calling the RPC.

### 4.2 Data interface: fetching the latest 10 (masterchain) blocks

MVP scope is masterchain blocks only (workchain `-1`); shard-block drill-down is a later-phase
extension (§10 Phase 5) because TOS uses dynamic sharding and "the last 10 blocks" is ambiguous
once multiple shards are in play.

**Step 1 — find the chain tip.**

```
GET /getMasterchainInfo
```
returns (per `liteServer.masterchainInfo`, `~/tos/tl/generate/scheme/lite_api.tl`):
```json
{
  "last": { "workchain": -1, "shard": "-9223372036854775808", "seqno": 4181732,
            "root_hash": "...", "file_hash": "..." },
  "state_root_hash": "...",
  "init": { "workchain": -1, "root_hash": "...", "file_hash": "..." }
}
```
`last.seqno` is the current tip. Target window is `[last.seqno - 9, last.seqno]`.

**Step 2 — fetch each block's header.** For `seqno` in that window:
```
GET /lookupBlock?workchain=-1&shard=-9223372036854775808&seqno=<seqno>
```
or, once the exact `BlockIdExt` is known from step 1/a prior lookup,
```
GET /getBlockHeader?workchain=-1&shard=...&seqno=<seqno>&root_hash=...&file_hash=...
```
Both resolve to `liteServer.blockHeader` (`id`, `mode`, `header_proof`), from which the JSON-RPC
handler layer (not the raw TL type) extracts the fields an explorer actually wants to show —
`gen_utime`, previous-block references, key-block flag. These are unpacked from the block's
merkle proof BOC via `block::gen` TLB inside the handler; the exact JSON field names returned to
the client should be pinned down by reading `handle_getBlockHeader` in
`json-rpc-server-blocks.cpp` before frontend work starts (flagged as unverified in §11 — the TL
schema alone does not expose `gen_utime` as a named field, only the raw proof).

**Step 3 — fetch each block's transaction list.**
```
GET /getBlockTransactionsExt?workchain=-1&shard=...&seqno=<seqno>&count=40
```
(`count` defaults to 40 per R10; raise or paginate via the `after` cursor —
`liteServer.transactionId3{account, lt}` — if a block has more). Per-transaction JSON fields
(from `getBlockTransactionsExt`/`getTransactions`, `json-rpc-server-transactions.cpp`):
`@type: "raw.transaction"`, `data` (base64 BOC), `account` (hex), `lt` (string), `utime`, `hash`
(base64), `fee` (decimal string), `in_msg_hash` (base64, when present). In/out message detail
(value, src/dest, message body/comment) is **not confirmed** in the current research pass — the
handler unpacks it via `block::gen::Transaction`/`Message` TLB records, and the exact JSON shape
needs to be read directly from `json-rpc-server-transactions.cpp` before the frontend contract is
finalized.

**Step 4 (drill-down, not part of the 10-block MVP list, but needed for the account view).**
```
GET /getAddressInformation?address=<addr>
GET /getExtendedAddressInformation?address=<addr>
GET /getWalletInformation?address=<addr>
```
Returns balance (nanotomi, decimal string), code/data (base64 BOC), `last_transaction_id`
(`lt`/`hash`), `block_id`, `sync_utime`, `state` (`uninit`/`active`/`frozen`).

This gives a complete, verified path from "open the explorer" to "render the last 10 blocks with
their transaction counts and let the viewer click into any of them" using only documented,
existing RPC surface — no new node-side code is required for v1.

## 5. Client-Side Proof Verification via WebAssembly

### 5.1 Motivation

Everything in §4 is fetched through the Aggregator Service (§6), which means the browser is, by
default, trusting three layers it did not choose: the polled node, the Aggregator's network path
to that node, and the Aggregator's own code. `getBlockHeader`, `getAccountState`, and the
block-transaction listing responses all carry a `proof`/`header_proof`/`shard_proof` field
alongside the data (§4.2) — these are Merkle proofs, and they exist specifically so a client does
not have to extend that trust. Right now nothing in this design reads them; they are fetched and
discarded. Verifying them client-side, instead of only displaying the data they authenticate, is
the difference between "a nice-looking dashboard" and "a client that can prove what it shows you
is what the chain actually produced" — for a flagship public explorer this is a real
differentiator, not a decorative feature.

### 5.2 This verification logic already exists and is already trusted

This is not new cryptography to design. `~/tos/crypto/block/check-proof.h` /
`check-proof.cpp` implements exactly the functions needed, and they are not experimental — they
are the same functions `lite-client` itself calls to avoid blindly trusting a liteserver's
answers (confirmed: `grep -l check_block_header_proof lite-client/ toslib/` matches both
`lite-client/lite-client.cpp` and `toslib/toslib/ToslibClient.cpp`). Relevant entry points, and
how they map onto the §4.2 data flow:

| Function (`crypto/block/check-proof.h`) | Verifies | Matches JSON-RPC field (§4.2) |
|---|---|---|
| `check_block_header_proof(root, blkid, ...)` | A block header's proof against its claimed `BlockIdExt` (root_hash/file_hash), optionally recovering `gen_utime`/`gen_lt` | `getBlockHeader` → `header_proof` |
| `check_shard_proof(blk, shard_blk, shard_proof)` | A shard block's inclusion under a masterchain block | `shards`/shard drill-down (Phase 5) → `shard_proof` |
| `check_account_proof(proof, shard_blk, addr, root, ...)` / `AccountState::validate(...)` | An account state against a shard block, recovering `last_trans_lt`/`last_trans_hash`/`gen_utime` | `getAddressInformation` / `getExtendedAddressInformation` → `proof`, `shard_proof` |
| `Transaction::validate()` / `TransactionList::validate()` / `BlockTransaction::validate()` | A transaction (or list of transactions) against the block it claims to belong to | `getBlockTransactionsExt` → per-tx proof data |

The explorer's job is to expose these four checks to the browser, not to reimplement Merkle/cell
verification in JavaScript. A hand-written JS reimplementation is exactly the kind of thing that
silently drifts from the real consensus/serialization rules over time (cell hashing edge cases,
pruned-branch handling, exotic cells); compiling the real implementation removes that entire
failure class.

### 5.3 The WASM build path already exists in this repo

`USE_EMSCRIPTEN` is not a hypothetical toolchain choice — it is already wired into the build:

- `~/tos/CMakeLists.txt` (line 79): `option(USE_EMSCRIPTEN "Use \"ON\" for config building wasm." OFF)`.
- `~/tos/emulator/CMakeLists.txt` already produces a working, browser-loadable WASM module today:
  `emulator-emscripten.cpp` → `EmulatorModule`, with link options
  `-sEXPORTED_FUNCTIONS=_emulate,_free,_malloc,_run_get_method,...`, `-sMODULARIZE=1`,
  `-sENVIRONMENT=web,node`, `-sALLOW_MEMORY_GROWTH=1`. This is the same mechanism TON's published
  `@ton/emulator` npm package uses upstream — proof this toolchain produces real, shippable
  browser artifacts from this codebase, not just native binaries.
- `~/tos/toslib/CMakeLists.txt` also gates on `USE_EMSCRIPTEN` (forcing `TOSLIBJSON_STATIC=ON`
  when set) — `toslib` is where the proof-checking call sites in `ToslibClient.cpp` already live.

**Recommendation: do not compile all of `toslib` for the browser.** `toslib` links `adnllite`,
`tl_lite_api`, `lite-client-common`, and `emulator_static` — most of that weight is the ADNL
networking stack, which this design deliberately does not use in the browser (§3 point 2; the
Aggregator/JSON-RPC path is the transport). Pulling in `ExtClient` and friends would bloat the
WASM payload with a networking stack that can never actually open a connection in a browser
sandbox anyway. Instead, add a new, narrow Emscripten target — e.g.
`explorer-verify-emscripten`, modeled directly on `emulator/CMakeLists.txt`'s pattern — that links
only `crypto/block/check-proof.*`, `vm/cells`, and the hashing primitives they depend on, and
exports four functions: `verify_block_header`, `verify_shard_proof`, `verify_account_state`,
`verify_block_transactions`. Each takes the base64 proof blob(s) plus the claimed `BlockIdExt`/
address already present in the corresponding JSON-RPC response, and returns verified/rejected
plus the fields it independently recovered (`gen_utime`, `last_trans_lt`, etc.) so the frontend
can cross-check them against what the Aggregator claimed.

### 5.4 Where this sits in the frontend

- Load the verification WASM module lazily, off the initial render path — the 10-block MVP view
  (§4.2, §10 Phase 0/1) should never block on it. Fetch and instantiate it only when a viewer
  opens a block/account/transaction detail panel (§10 Phase 3), or opts into a persistent
  "verified" mode.
- Run it in a Web Worker, not the main thread. This is a hard requirement, not a nice-to-have:
  the main thread is already carrying the three.js/WebGL render loop (§7) and cannot absorb
  synchronous WASM verification work without dropping frames on exactly the kind of continuous
  particle/glow animation this design is built around. `postMessage` the proof blobs in, get a
  verified/rejected result back.
- Surface the result as a UI signal tied to the affected node/edge in the graph — e.g. a
  verified block/account renders with a distinct glow state versus one whose proof has not yet
  been (or failed to be) checked — so verification reinforces the visual language instead of
  living in a separate, easy-to-ignore panel.
- This is also the natural place for the "more CPU-bound, less blockchain-specific" WASM use
  case: once the graph is rendering hundreds of nodes (Phase 5 shard awareness, Phase 6
  historical search), the force-directed layout physics step becomes a second, independent
  candidate for a WASM (e.g. Rust) implementation running in its own worker — unrelated to proof
  verification, but the same "keep heavy compute off the main render thread" principle applies.

## 6. System Architecture

```
┌─────────────────────┐      ADNL (local, node-internal)     ┌──────────────────┐
│  TOS validator-engine│ ─────────────────────────────────────│  liteserver state │
│  (--json-rpc-address)│                                      │  (this node only) │
└──────────┬───────────┘
           │ HTTP: POST /jsonRPC, GET /<method>, /healthcheck, /readyz, /api-info
           ▼
┌───────────────────────────────┐
│  Explorer Aggregator Service   │  (new component — this design)
│  Node.js/Go, stateless-ish     │
│  - polls getMasterchainInfo    │
│  - diffs tip seqno, fetches    │
│    new block header + txs      │
│  - normalizes to explorer's    │
│    graph schema (§8)           │
│  - short-TTL cache (R8 says    │
│    the RPC server won't cache, │
│    so the aggregator must)     │
│  - fans out over WebSocket/SSE │
└──────────┬─────────────────────┘
           │ WebSocket (block/tx graph deltas) + REST (initial load, search, account lookup)
           ▼
┌───────────────────────────────┐
│  Web Frontend                  │  (new component — this design)
│  WebGL/three.js render layer   │
│  - animated force-directed     │
│    graph of blocks/txs/accounts│
│  - bloom/particle/glow effects │
│  - block/tx/account detail     │
│    panels on click             │
│  - Web Worker: proof           │
│    verification WASM (§5)      │
└─────────────────────────────────┘
```

A dedicated **Explorer Aggregator Service** is necessary — not optional — for two independent
reasons documented above: (a) the JSON-RPC server has no push transport (§4.1), so something has
to poll and turn deltas into a stream; (b) it explicitly does no caching (R8) and is meant to run
co-located with a single validator, so an explorer hammering it directly with per-viewer polling
would multiply load on a validator node for no reason. The aggregator polls once, caches briefly,
and fans out to any number of connected browsers.

This also gives a natural place to add multi-node redundancy later (poll two or three
independently operated nodes' JSON-RPC endpoints and reconcile) without touching the frontend or
the node itself, addressing the single-liteserver-view caveat from R6.

## 7. Frontend Visual Architecture

Mira (the sibling multi-agent simulation product; see `~/mira/frontend/src/components/
GraphPanel.vue`) already has a working force-directed relationship graph, but it is D3 + SVG:
`d3.forceSimulation` with `forceLink`/`forceManyBody`/`forceCenter`/`forceCollide`, rendered as
SVG `<circle>`/`<line>` elements, with glow limited to CSS `filter: drop-shadow(...)` keyframe
animation. That is adequate for a few hundred knowledge-graph nodes updated occasionally; it is
not capable of the target aesthetic here (continuous particle motion, bloom, depth, dozens of
simultaneous animated transaction-flow trails) at the frame rates a flagship product page needs.
**The rendering layer for this explorer should not reuse Mira's SVG code directly** — it should
reuse the *concept* (force-directed relationship layout) reimplemented on a GPU-accelerated
stack:

- **Renderer**: WebGL via `three.js`. Use `UnrealBloomPass`-style post-processing for neon glow
  on blocks/nodes, additive-blended particle systems for transaction "flow" between accounts and
  blocks, and a subtle depth-of-field/parallax camera for a 3D scene rather than a flat 2D plane.
- **Layout**: a 3D force-directed graph (e.g. `d3-force-3d` driving positions, or the
  `3d-force-graph` library which already wraps three.js + d3-force-3d) — blocks as anchor nodes,
  transactions as edges/particles flowing from source to destination account nodes, new blocks
  entering the scene with an animated "materialize" transition rather than popping in.
  Masterchain blocks in a clear chain/backbone layout (reflecting seqno order); their transactions
  branch outward.
  - See `~/tos/doc/tos.pdf` §3.6 (Sharding) when a future phase needs to visualize shard
    structure rather than the linear masterchain backbone — dynamic shard splits/merges will need
    their own layout treatment; this design does not attempt to solve that for Phase 0–3 (see
    §10 Phase 5).
- **Aesthetic direction ("digital rain" / cyberpunk-technical)**: dark background, monospaced/
  technical type for data (matching the whitepaper's own "austere, precise, engineering-forward"
  brand voice — see the persona language style Mira generated for the TOS Network account in an
  unrelated simulation run), green/cyan glow accents on active elements, particle trails for
  in-flight transactions, a subtle animated background suggestive of falling code — but data
  density and correctness must win over spectacle: every animated element should map to a real
  field from §4, never a decorative fabrication. This is a chain explorer, not a screensaver;
  the bar is "looks incredible AND every number is real and verifiable," not one at the expense
  of the other.
- **Framework**: Vue 3 (consistent with the rest of the TOS/Mira frontend ecosystem) driving a
  three.js canvas plus conventional DOM overlays for detail panels, search, and address input.

## 8. Data Model (Aggregator → Frontend graph schema)

The aggregator normalizes RPC responses into a single graph shape the frontend already knows how
to lay out and animate:

```ts
type ExplorerNode =
  | { kind: "block"; id: string /* workchain:shard:seqno */; seqno: number; gen_utime: number;
      tx_count: number; workchain: number; shard: string }
  | { kind: "account"; id: string /* address */; balance: string; state: string }
  | { kind: "transaction"; id: string /* hash */; lt: string; fee: string; utime: number };

type ExplorerEdge =
  | { kind: "contains"; from: string /* block id */; to: string /* tx id */ }
  | { kind: "touches"; from: string /* tx id */; to: string /* account id */; direction: "in" | "out" };
```

New blocks/transactions/accounts are pushed as additive graph deltas over the WebSocket channel;
the frontend force layout absorbs new nodes without discarding existing positions (this is the
same "delta, not full reload" principle the aggregator needs internally to avoid re-fetching the
whole 10-block window on every poll tick — track the last-seen tip `seqno` and only fetch blocks
above it).

## 9. Security & Operational Notes

- Run the explorer's node(s) with `--json-rpc-readonly` — the explorer never needs `sendBoc`/
  `sendBocReturnHash`/`sendQuery`.
- The JSON-RPC server has no built-in auth or rate limiting beyond the optional
  `--json-rpc-api-key` (R13); if the aggregator talks to a node over the public internet rather
  than a private link, put it behind a reverse proxy/firewall and set an API key, per policy.
- Because R6 means each node only reflects its own local view, treat the explorer's data as "this
  node's view of the chain," not a globally-agreed source — acceptable for a public explorer as
  long as the polled node is well-connected and kept in sync (monitor `/readyz`); call this out in
  the UI (e.g. a small "synced via node X, block Y seconds old" indicator) rather than presenting
  it as an oracle of absolute truth.
- Prometheus metrics on `:9100/metrics` should be scraped by the aggregator's own ops stack to
  alert on `jsonrpc_errors_total`/cache miss spikes — useful signal for "the visual explorer just
  went quiet because the node it polls is unhealthy."
- §5's client-side proof verification narrows, but does not remove, the "trust this node's view"
  caveat above: it proves the Aggregator did not alter what the polled node returned, not that the
  polled node itself is honest or in consensus with the network. Say exactly that in the UI copy
  next to the verified-state indicator — do not oversell it as full light-client trustlessness.

## 10. Phased Delivery

1. **Phase 0 — data plumbing**: aggregator service polling `getMasterchainInfo` +
   `getBlockHeader` + `getBlockTransactionsExt` for the last 10 masterchain blocks; plain
   (non-cinematic) frontend list to validate the data path end-to-end.
2. **Phase 1 — the real visual layer**: three.js/WebGL force-directed graph, bloom/particle
   effects, animated block arrival, replacing the plain list.
3. **Phase 2 — live streaming**: WebSocket delta push from aggregator, continuous animation as
   new blocks land, no manual refresh.
4. **Phase 3 — drill-down**: transaction detail panel (needs the in/out-message field audit from
   §4.2 step 3), account lookup/search bar using `getAddressInformation`/
   `getExtendedAddressInformation`.
5. **Phase 4 — client-side verification (§5)**: new `explorer-verify-emscripten` CMake target
   wrapping `crypto/block/check-proof.*`; Web Worker integration; verified/unverified visual state
   on block, account and transaction nodes.
6. **Phase 5 — shard awareness**: extend beyond masterchain-only to render shard blocks
   (`shards`/`getAllShardsInfo`) and the masterchain/shard relationship, `check_shard_proof`
   verification (§5.2), and multi-node polling for redundancy (§6).
7. **Phase 6 (stretch)**: token/NFT visualization (`getTokenData`, `getAccountJettons`,
   `getAccountNfts`), full historical search/index.

## 11. Open Questions / Follow-ups Before Implementation

- **Block header JSON shape**: the exact field names `handle_getBlockHeader` returns for
  `gen_utime`, previous-block references and key-block flag are not yet confirmed against
  `json-rpc-server-blocks.cpp` — read that handler directly before finalizing the frontend's
  block-card data contract.
- **Transaction message detail**: in/out message value, source/destination address and comment
  fields are not yet confirmed against `json-rpc-server-transactions.cpp` / the
  `block::gen::Transaction`/`Message` TLB unpacking — required before the transaction detail
  panel (Phase 3) can be built against a real contract instead of guesses.
- **`~/tos/adnl/` has no dedicated prose documentation** beyond code comments; if the aggregator
  ever needs to speak ADNL directly instead of going through the JSON-RPC server (it shouldn't,
  per §4), this is a gap to fill first.
- **Which node(s) to poll** in non-development environments is an operational decision, not a
  code one — needs an answer before Phase 0 ships anywhere but localhost.
- **`check-proof.cpp`'s dependency footprint** (what it pulls in from `vm/cells`, hashing, and
  `block::gen` beyond what's declared in `check-proof.h`) has not been traced end-to-end — needed
  to size the new `explorer-verify-emscripten` WASM target (§5.3) and confirm it can be built
  without dragging in ADNL/networking code.
- **JSON-RPC does not appear to return raw proof bytes verbatim for every field** — the
  `header_proof`/`shard_proof`/`proof` fields in the TL schema are raw BOC bytes, but whether the
  JSON-RPC layer forwards them unmodified (as opposed to only returning the fields it already
  unpacked from them) needs to be confirmed in `json-rpc-server-blocks.cpp`/
  `json-rpc-server-accounts.cpp` before §5 can be implemented — if the raw proof is not exposed
  over JSON-RPC today, exposing it is a small, additive node-side change, not a redesign.
