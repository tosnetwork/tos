# TOS Birdeye — Design Document

## Status

- Document type: product/technical design proposal, non-normative
- Status: reviewed proposal; implementation gates identified
- Date: 2026-08-04
- Related code: `~/tos/validator-engine/json-rpc-server*.cpp`, `~/tos/doc/json-rpc-policy.md`,
  `~/tos/doc/openapi.yaml`, `~/tos/crypto/block/check-proof.{h,cpp}`, `~/tos/emulator/CMakeLists.txt`
  (existing Emscripten precedent)
- Related prior art (do not build on top of): `~/tos/blockchain-explorer/` (legacy, inherited from
  Telegram Systems LLP's TON explorer, server-rendered Bootstrap-4 HTML tables, no JSON API, no
  visualization layer)

## 1. Purpose

Build **TOS Birdeye**, a new, standalone, browser-based spatial explorer for TOS Network with a
distinct visual identity: a real-time, cinematic, "digital-rain" / neon-glow presentation of chain activity —
blocks, shards, accounts and transactions rendered as a living, animated graph rather than as
static HTML tables. The explorer should read as a piece of the TOS brand (precise, engineering-
forward, technically substantiated — see `~/tos/doc/tos.pdf` §2 Design Principles) while looking
unmistakably premium: this is the public-facing surface most people will actually open, and it
should not look like a decade-old testnet tool.

Concretely, the explorer must, at minimum:

- Open on a live **Consensus Matrix** showing the current validator set, validator weight/stake
  distribution, recent masterchain participation and block signatures. Consensus should be
  visible as signals converging on a block, not reduced to a validator table.
- Distinguish the **global validator population** from the protocol-selected current validator
  set and from the actual signers of one block. The global view may use aggregate/LOD clusters,
  but it must state its source, snapshot time and whether its count is complete, sampled or a
  static-demo fixture. A 14-member active set must never visually imply that the whole TOS
  Network has only 14 validators.
- Show the most recent masterchain blocks (initial scope: last 10) as they are produced, with
  seqno, shard summary, transaction count and timestamp.
- Let a viewer drill into a block to see its transactions, and into a transaction to see its
  accounts, value and fees.
- In every block view, distinguish the block's authoritative `tx_count` from transactions that
  are actually loaded or sampled in the current client window. A static demo must visibly label
  sampled rows/particles and must not imply that a bounded transaction fixture is the complete
  history.
- Let a viewer look up an account/address and see its balance, state and recent transaction
  history.
- Render all of the above as an animated, hybrid-constrained relationship graph (blocks → shard
  blocks → transactions → accounts) with continuous motion, particle/glow effects and smooth
  entry animation for new blocks — not a plain list.
- Recognize TOS AI Actor contracts and render an **AI Execution Matrix**: Agent Account → Task
  Escrow → Service Actor / remote AI Edge Terminal → result/evidence commitment → verifier or
  dispute → settlement. A user must be able to distinguish an ordinary value transfer from an
  AI workflow and inspect the contract execution that caused each state transition.
- Show remote AI Edge Terminals as live, separately sourced service nodes: advertised capability,
  model/runtime commitment, region, price, admission state, recent receipt-backed work and claim
  evidence level. The UI must never present self-declared hardware or off-chain execution as a
  chain-verified fact.

The product is therefore not "Etherscan with a cyberpunk skin." It is a real-time observability
surface for three connected systems: consensus, chain state transition, and verifiable AI service
execution. The cinematic presentation is a semantic instrument: every node, edge, pulse, color
and particle must correspond to a real datum or an explicitly labeled inference.

### 1.1 Product identity

- **Product name**: TOS Birdeye
- **Short name**: Birdeye
- **Canonical production URL**: `https://birdeye.tos.network`
- **Product category**: evidence-native spatial blockchain and AI execution explorer
- **Working repository/component prefix**: `tos-birdeye` / `birdeye-*`

"Birdeye" expresses the primary interaction: begin with a network-wide bird's-eye view, identify a
validator, block, transaction, contract or AI execution path, then descend without losing spatial
or causal context. The product name is not a claim of affiliation with any third-party product
using the same word. TOS branding, the `tos.network` domain and the complete name **TOS Birdeye**
must remain prominent in metadata, navigation, social cards and public documentation.

The interaction vocabulary may use:

- **Skyview** for the global network overview;
- **Consensus Matrix**, **Chain Matrix** and **AI Execution Matrix** for semantic scene modes;
- **Lens** or **Inspector** for selected-entity and evidence detail;
- **Zoom** only as an interaction verb, not a product or subsystem name.

### 1.2 Innovation thesis

The defensible innovation is not any one visual effect. Three-dimensional graphs, bloom and
digital-rain backgrounds are established techniques and must not be marketed as protocol
innovation. TOS Birdeye becomes meaningfully different when it combines all of the following:

1. **Consensus as an inspectable process** — validator-set weight, actual proof-chain signatures,
   shard context and threshold progress share the same time axis as blocks and transactions.
2. **State transition as a causal graph** — messages and contract execution connect persistent
   identities instead of being flattened into unrelated transaction rows.
3. **AI execution as a cross-boundary evidence graph** — an on-chain task/escrow/service lifecycle
   is joined to a remote terminal span only through explicit request/result/receipt commitments.
4. **Provenance-native UX** — chain-reported, proof-verified, signed, attested, observed, declared,
   inferred and stale values remain visibly distinct at field level.
5. **One navigable temporal model** — Consensus, Chain and AI views are projections of one event
   graph, with camera continuity and deterministic replay rather than separate dashboards.

This combination is the product claim. The project must not claim to be the first 3D blockchain
explorer or the first WebGPU explorer without a separately maintained market survey. It may claim
that TOS exposes its own consensus and AI-service evidence model in a way conventional transfer-
centric explorers do not, once the corresponding features are actually shipped.

### 1.3 Technical feasibility summary

| Capability | Feasibility | Current repository support | Required work / gate |
|---|---|---|---|
| recent masterchain blocks | high / available now | JSON-RPC tip, lookup, header and transaction-list handlers | normalize, cache, paginate and test against a live node |
| block/account lookup | high / available now | address and transaction RPCs return decoded state plus raw BOCs where documented | pin response fixtures and error semantics |
| current validator weights | high, with backend decoding | config RPC returns a validated config-param BOC | add shared decoder or decoded read-only endpoint; do not decode consensus TLB ad hoc in UI code |
| per-block signer graph | medium-high | `getMasterchainBlockSignatures` extracts signatures from forward proof links | prove exact block/signature semantics and join `node_id_short` to validator set |
| true live consensus animation | low with current public API | only later proof-chain signatures are exposed; no gossip/catchain event stream | label as reconstructed participation, or add a separate opt-in telemetry source |
| transaction/message execution graph | medium | transaction BOC and basic fields exist; full messages/compute phases are not exposed by the examined handler | implement canonical backend decoder/API before AI workflow visualization |
| AI contract workflow graph | medium | contract sources and schemas exist; only Agent Account and Task Escrow are in the standard `GenFif` build list today | publish code-hash/version registry, build/deploy supported contracts, add fixtures and decoders |
| remote Edge Terminal map | medium, ecosystem-dependent | architecture and evidence schemas exist; production discovery/receipt feed is not established here | define signed manifest/receipt transport, identity binding, expiry and privacy policy |
| browser proof verification | medium after node/API work | native proof checks and Emscripten precedent exist | expose complete raw proof packages, define trust-root bootstrap, build/size a narrow WASM target |
| cinematic graph rendering | high at bounded scale | mature WebGL 2; WebGPU is a viable progressive path | prototype and benchmark representative worst-case graphs on device tiers |
| full historical search/replay | high but operationally substantial | not supplied by rolling node RPC calls | durable index, checkpointing, reorg model, retention and storage budget |

No red item invalidates the product. It does mean the implementation plan must deliver a truthful
Consensus + Chain MVP before presenting reconstructed signatures as live consensus, proof-derived
data as browser-verified, or terminal declarations as executed AI work.

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
- No public exposure of validator or terminal private network coordinates. Validator geography,
  ASN/provider and terminal region are optional enrichment data, never consensus data; precise
  IP addresses and stable hardware fingerprints must not be published by default.
- No claim that a payment, receipt or on-chain hash proves that a particular GPU, model or
  inference runtime performed semantically correct work. The explorer visualizes the strongest
  available evidence and its provenance; it does not manufacture an execution guarantee.

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

### 3.1 Open-source landscape and competitive position

No surveyed open-source project combines the full target: spatial real-time chain visualization,
validator/consensus participation, causal contract execution, AI Agent workflows, remote Edge
Terminal evidence and field-level provenance. Several projects solve important subsets and should
influence the implementation without becoming the product foundation:

| Project | What it proves / provides | What it does not provide for TOS | Reuse posture |
|---|---|---|---|
| [TxStreet](https://github.com/txstreet/txstreet) (MIT frontend) | real-time transaction/mempool animation; Vue + Phaser scene lifecycle; REST + WebSocket event model | validator consensus, proof semantics, contract causality and AI execution; its official backend is not open source | study event-to-animation mapping, aggregation and scene lifecycle; do not fork the renderer or depend on its backend |
| [Polkadot Telemetry](https://github.com/paritytech/substrate-telemetry) (GPL-3.0) | production-shaped ingestion of node-reported connectivity, block import and finality telemetry | chain explorer, cryptographic authority for operator telemetry, TOS protocol semantics | adopt the separation between opt-in node telemetry and on-chain facts; design a TOS-native schema |
| [Polkadot Introspector](https://github.com/paritytech/polkadot-introspector) (GPL-3.0) | validator tracking and relay/parachain tracing from on-chain plus telemetry data | public spatial explorer and TOS-compatible consensus decoder | study validator identity joins, tracing and diagnostic outputs; avoid code reuse unless GPL obligations are deliberately accepted |
| [Beaconcha.in Explorer](https://github.com/gobitfly/eth2-beaconchain-explorer) | mature validator/proposal/attestation indexing and operational history | TOS catchain/shard semantics, spatial causality and AI evidence | use as a requirements reference for validator history, status and indexing depth, not as a codebase |
| [mempool](https://github.com/mempool/mempool) (AGPL-3.0) | production self-hosted explorer, live mempool/block/fee visualization and scalable deployment practice | validator view, general contract execution and AI workflows | study caching, live-data degradation and operations; do not copy AGPL code into a differently licensed component without review |
| [Chaingraph](https://github.com/bitauth/chaingraph) (MIT) | multi-node acknowledgement, PostgreSQL/GraphQL indexing, reorganization and observation timeline | frontend visualization, validator consensus and AI semantics | strongest architectural reference for per-source provenance, append-only observations, replay and corrections |
| [AEVS SDK](https://github.com/fetchai/AEVS-sdk) (Apache-2.0) | signed/hash-chained AI tool-call receipts and public/private/proof-only disclosure modes | blockchain consensus, smart-contract escrow/settlement and physical Edge Terminal evidence | study receipt envelopes, redaction modes and verification UX; define independent TOS receipt compatibility rather than coupling to its hosted backend |
| [Blockscout](https://github.com/blockscout/blockscout) and [Esplora](https://github.com/Blockstream/esplora) | comprehensive conventional explorer indexing, search and detail workflows | the target visual/causal/consensus/AI model; both are chain-family-specific | requirements references for search, canonical URLs, pagination, API hygiene and operational completeness only |

This survey changes the implementation strategy in four concrete ways:

1. Use TxStreet as evidence that semantic live animation works, while retaining the hybrid
   constrained three.js design rather than inheriting a 2D/game metaphor.
2. Model validator telemetry the way Polkadot separates node-submitted operational observations
   from on-chain state; never merge liveness, geography or client version into consensus truth.
3. Make Chaingraph-style source attribution and correction history part of the aggregator from
   the beginning instead of adding multi-node provenance after the single-node MVP schema freezes.
4. Treat AEVS-style privacy modes as a minimum AI receipt requirement: public metadata,
   selectively disclosed payloads and hash-only evidence must all remain useful in the explorer.

The recommended public position is:

> **An evidence-native spatial explorer for blockchain consensus and AI execution.**

"Matrix-style" remains the visual direction, not the technical novelty claim. Do not advertise
"the first 3D blockchain explorer" or imply that no animated transaction explorers exist. A
competitive claim should describe shipped, testable integration: consensus participation + causal
chain execution + remote AI evidence + explicit provenance in one replayable graph.

### 3.2 Build, adapt or integrate decisions

- **Build TOS-native**: canonical block/config/message/AI-contract decoder, proof-package API,
  consensus/chain/AI graph schema, deterministic projector, truth-state model and spatial UI.
- **Adapt patterns, not code**: live event coalescing, validator telemetry ingestion, historical
  indexing, receipt redaction and operational dashboards from the projects above.
- **Integrate by open format where useful**: permit import/verification of compatible signed AI
  receipts or terminal evidence, but normalize them into TOS provenance and require explicit
  identity/commitment binding.
- **Do not adopt as a base**: an EVM/Bitcoin explorer backend, TxStreet's closed backend contract,
  or a chain-specific validator indexer. Their domain models would create more impedance than they
  remove.
- **Perform license review before copying**: MIT/Apache patterns are generally integration-
  friendly; GPL/AGPL components require an intentional distribution and service-source strategy.
  This document's links are prior-art references, not authorization to copy code or assets.

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
extension (§10 Phase 7) because TOS uses dynamic sharding and "the last 10 blocks" is ambiguous
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
handler extracts the fields an explorer wants to show. Direct code audit confirms the successful
decoded response currently contains `global_id`, `version`, split/merge flags,
`validator_list_hash_short`, `catchain_seqno`, `min_ref_mc_seqno`, `is_key_block`,
`prev_key_block_seqno`, `start_lt`, `end_lt` and `gen_utime`. It does **not** currently include
ordinary previous-block references or return `header_proof` on the successful parse path; the raw
proof is only returned by the handler's parse-failure fallback. That asymmetry must be fixed before
client-side header verification is possible. The aggregator may use the decoded response for the
reported-data MVP, but must not label it browser-verified.

**Step 3 — fetch each block's transaction list.**
```
GET /getBlockTransactionsExt?workchain=-1&shard=...&seqno=<seqno>&count=40
```
(`count` defaults to 40 in this handler and is capped at 256; paginate using `after_lt` plus the
base64 account value currently named `after_hash` if `incomplete=true`). Per-transaction JSON fields
(from `getBlockTransactionsExt`/`getTransactions`, `json-rpc-server-transactions.cpp`):
`@type: "raw.transaction"`, `data` (base64 BOC), `account` (hex), `lt` (string), `utime`, `hash`
(base64), `fee` (decimal string), `in_msg_hash` (base64, when present). Direct code audit confirms
that this endpoint does **not** decode source, destination, message value/body/opcode, out messages,
description/compute/action phases, exit code or gas. The raw transaction BOC is enough for a
canonical TOS decoder to recover many of these fields, but it is not itself a transaction-inclusion
proof. Phase 0 therefore needs a shared decoder in the aggregator or an additive decoded RPC;
frontend code must not implement a second consensus serialization stack in TypeScript.

**Step 4 (drill-down, not part of the 10-block MVP list, but needed for the account view).**
```
GET /getAddressInformation?address=<addr>
GET /getExtendedAddressInformation?address=<addr>
GET /getWalletInformation?address=<addr>
```
Returns balance (nanotomi, decimal string), code/data (base64 BOC), `last_transaction_id`
(`lt`/`hash`), `block_id`, `sync_utime`, `state` (`uninit`/`active`/`frozen`).

The account handler validates the upstream `shard_proof` and account `proof` inside the node before
constructing this JSON, but the response does not forward those raw proofs. This is stronger than
an unvalidated transformation inside the node, yet still means the browser trusts that JSON-RPC
node and aggregator until a complete proof package is exposed.

This gives a complete, verified path from "open the explorer" to "render the last 10 blocks with
their transaction counts and let the viewer click into any of them" using only documented,
existing RPC surface — no new node-side code is required for v1.

### 4.3 Validator and consensus data

The Consensus Matrix must derive identity, weight and participation from chain data rather than
from an operator-maintained validator directory:

- `getConfigParam` for masterchain configuration parameters 32–37 (previous/current/next
  validator sets, as applicable at the selected block). The aggregator must decode and normalize
  the returned config BOC into validator public key, ADNL identifier, weight, set validity and
  total-weight fields. If the current JSON-RPC response does not expose the decoded members, add a
  narrow read-only decoded-validator-set endpoint rather than duplicating TLB parsing in the
  frontend.
- `getMasterchainBlockSignatures?seqno=<n>` for actual signer `node_id_short` values on a selected
  masterchain block. Join them to the selected block's validator set and calculate signed weight,
  missing weight and threshold progress. A signature edge means "this validator signed evidence
  included in the returned proof chain"; it must not be invented from validator liveness.
- `getBlockHeader` for `validator_list_hash_short`, catchain sequence and shard/masterchain context.
  These fields bind a block to the set expected to participate.
- `shards`/`getShardBlockProof` in the shard-aware phase for masterchain-to-shard inclusion. The
  protocol's validator-subset assignment must be recovered from verified config and block context
  where possible; the UI must not imply that every validator signs every shard block.

Validator "distribution" has several meanings and the API contract must keep them separate:

| View | Source | Authority |
|---|---|---|
| voting/stake weight | masterchain config | on-chain, proof-verifiable |
| block signer participation | masterchain block proof/signatures | on-chain, proof-verifiable |
| shard/catchain assignment | config + block context | protocol-derived |
| observed availability/latency | aggregator probes or operator telemetry | off-chain observation |
| country/region/ASN/provider | opt-in metadata or network enrichment | off-chain claim/inference |

Geographic presentation should default to coarse region/ASN clusters, never a precise validator
location. Unknown location is a valid state. A node with no metadata remains fully represented in
the consensus graph and must not be visually penalized as though it were offline.

#### 4.3.1 Validator population, active set and signer layers

The data contract and UI must expose three separate scopes:

1. **Global population** — all validators known from the selected authoritative registry/config
   window, or a clearly labeled sampled/estimated population where a complete enumeration is not
   available. This layer communicates network scale and coarse distribution; it is not evidence
   that every node is currently elected, online or signing.
2. **Active validator set** — the previous/current/next protocol set decoded from masterchain
   configuration, including set ID, validity interval, member count and total weight. This is the
   authoritative scope for voting-weight visualization at the selected block.
3. **Block signers** — the subset joined from the selected block's proof/signature response. This
   layer alone drives signer convergence, signed-weight and threshold progress.

The default Skyview should show global scale without rendering hundreds or thousands of labels.
Use deterministic aggregate clusters or a bounded swarm, then expand the selected active set into
stable inspectable nodes. A scope control must let users distinguish `NETWORK`, `ACTIVE SET` and
`SIGNERS`. Cluster size maps population count; active-node size maps voting weight. Neither size
may be reused to imply liveness, wealth or geographic precision. Static fixtures must include
explicit `population_total`, `population_rendered`, `population_kind` (`complete`, `sampled`, or
`fixture`) and `generated_at` fields.

### 4.4 AI workflow and remote Edge Terminal data

TOS AI execution spans an authoritative on-chain state machine and an off-chain execution plane.
The explorer joins them by stable identifiers and commitments; it must never collapse them into
one undifferentiated "verified" status.

**On-chain sources** are Agent Account, Task Escrow, Service Actor, Capability Registry and
Dispute contract state and messages, documented in `ai-actors.md`, `ai-actor-message-catalog.md`
and `ai-workflow-schemas.md`. The aggregator should identify these contracts by known code hash
and version, decode their supported opcodes/get-methods, and reconstruct:

```text
TaskRequest -> TaskAccept -> TaskProgress? -> TaskResult
            -> TaskSettle | TaskDispute -> ruling -> settlement/refund
```

Relevant values include creator/agent/service/verifier addresses, budget, deadline, status,
request/result/evidence hashes, service-call request/response hashes, proof-scheme commitment and
payouts. Contract recognition must be versioned. An unknown code hash remains a generic smart
contract; it must not be guessed to be an AI contract from address labels or message text.

**Off-chain sources** are opt-in AI service/terminal manifests, ARD catalogs, live signed health
and capacity documents, quotes, runtime attestations, benchmark evidence and signed usage/result
receipts described by `ai-edge-computing-terminal-architecture.md`. These may provide:

- terminal/service identity and its binding to a Service Actor or TOS domain;
- service profile and exact model/artifact/runtime commitments;
- coarse region, ingress transport and short-expiry availability/admission state;
- declared resources, price units, queue/load class and supported evidence level;
- request, output, usage and receipt hashes that can be joined to an on-chain service call;
- Declared, Observed, Benchmarked, Audited, Attested or Replicated evidence per claim.

The aggregator may fetch public manifests and evidence documents, but it must retain the raw
signed envelope, retrieval time, expiry, signer and content hash. Rapid capacity data must expire
rather than lingering as false "online" state. Prompts, model outputs, private tool transcripts,
precise host fingerprints and administrative endpoints are not explorer data. Raw artifacts are
only fetched or displayed when explicitly public and content-addressed; otherwise the explorer
shows commitments and verification results only.

The minimum correlation key is a tuple of chain/network, contract address, task or call identifier,
and request/result/receipt hash. A display name, URL or model name is never sufficient to join an
off-chain terminal event to an on-chain settlement.

## 5. Client-Side Proof Verification via WebAssembly

### 5.1 Motivation

Everything in §4 is fetched through the Aggregator Service (§6), which means the browser initially
trusts the polled node, the Aggregator's network path to that node and the Aggregator's own code.
The underlying lite-server responses contain Merkle/proof data, and the node already validates
some of it internally, but the present explorer-facing JSON does **not** expose a complete proof
package for headers, accounts and transaction inclusion (§4.2). Browser verification is therefore
a gated architectural objective, not an MVP capability that can be wired up without node changes.

When the API exposes complete packages, verifying them client-side instead of only displaying the
transformed data will be a real differentiator. The verification contract must define more than a
boolean function: it needs the claimed object, raw proof BOCs, anchor block IDs, verification time,
network identity and a trust-root/bootstrap policy. A Merkle proof anchored only to an untrusted
block ID proves internal consistency, not canonical-chain membership.

### 5.2 Native verification primitives already exist

This is not new cryptography to design. `~/tos/crypto/block/check-proof.h` /
`check-proof.cpp` implements the core functions needed, and the same primitives are used by
`lite-client` and Toslib to avoid blindly trusting a liteserver's answers (confirmed:
`grep -l check_block_header_proof lite-client/ toslib/` matches both
`lite-client/lite-client.cpp` and `toslib/toslib/ToslibClient.cpp`). Reuse reduces implementation
drift, but does not waive WASM build, trust-bootstrap, fixture, fuzzing or audit requirements.
Relevant entry points, and
how they map onto the §4.2 data flow:

| Function (`crypto/block/check-proof.h`) | Verifies | Matches JSON-RPC field (§4.2) |
|---|---|---|
| `check_block_header_proof(root, blkid, ...)` | A block header's proof against its claimed `BlockIdExt` (root_hash/file_hash), optionally recovering `gen_utime`/`gen_lt` | `getBlockHeader` → `header_proof` |
| `check_shard_proof(blk, shard_blk, shard_proof)` | A shard block's inclusion under a masterchain block | `shards`/shard drill-down (Phase 7) → `shard_proof` |
| `check_account_proof(proof, shard_blk, addr, root, ...)` / `AccountState::validate(...)` | An account state against a shard block, recovering `last_trans_lt`/`last_trans_hash`/`gen_utime` | `getAddressInformation` / `getExtendedAddressInformation` → `proof`, `shard_proof` |
| `Transaction::validate()` / `TransactionList::validate()` / `BlockTransaction::validate()` | A transaction (or list of transactions) against the block it claims to belong to | `getBlockTransactionsExt` → per-tx proof data |

The explorer's eventual job is to expose these checks to the browser, not to reimplement Merkle/cell
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
`birdeye-verify-emscripten`, modeled directly on `emulator/CMakeLists.txt`'s pattern — that links
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
  case: once the graph is rendering thousands of nodes (Phase 7 shard awareness, Phase 8
  historical search), bounded local layout physics becomes a second, independent
  candidate for a WASM (e.g. Rust) implementation running in its own worker — unrelated to proof
  verification, but the same "keep heavy compute off the main render thread" principle applies.

### 5.5 Verification readiness gate

Phase 6 may use the label **Chain verified** only after all of these are true:

- header, account and transaction endpoints return versioned, byte-preserving proof packages;
- the verifier rejects mismatched network, block ID, address, transaction and claimed decoded data;
- a documented trust-root path anchors the verified block to a configured checkpoint or verified
  validator-set/signature chain, rather than trusting the aggregator's chosen root;
- native and WASM implementations pass the same positive, corrupted, truncated, wrong-anchor and
  cross-network fixtures;
- verification results include verifier build/version and anchor identity and survive replay;
- WASM size, initialization latency, peak memory and per-object verification time meet the device
  budgets in §10.

Before that gate, use **Node validated / Chain reported**: it accurately says that the node's native
code validated data before the explorer received it without implying independent browser trust.

## 6. System Architecture

```
┌─────────────────────┐      ADNL (local, node-internal)     ┌──────────────────┐
│  TOS validator-engine│ ─────────────────────────────────────│  liteserver state │
│  (--json-rpc-address)│                                      │  (this node only) │
└──────────┬───────────┘
           │ HTTP: POST /jsonRPC, GET /<method>, /healthcheck, /readyz, /api-info
           ▼
┌───────────────────────────────┐
│  Birdeye Aggregator Service    │  (new component — this design)
│  Go/Rust/Node.js service       │
│  - polls getMasterchainInfo    │
│  - reads validator config +    │
│    per-block signatures        │
│  - diffs tip seqno, fetches    │
│    new block header + txs      │
│  - recognizes versioned AI     │
│    contracts and workflows     │
│  - verifies signed, expiring   │
│    terminal manifests/receipts │
│  - normalizes to explorer's    │
│    graph schema (§8)           │
│  - short-TTL cache (R8 says    │
│    the RPC server won't cache, │
│    so the aggregator must)     │
│  - durable event log + graph   │
│    checkpoints and provenance  │
│  - fans out over WebSocket/SSE │
└──────────┬─────────────────────┘
           │ WebSocket (block/tx graph deltas) + REST (initial load, search, account lookup)
           ▼
┌───────────────────────────────┐
│  Web Frontend                  │  (new component — this design)
│  WebGL/three.js render layer   │
│  - Consensus / Chain / AI      │
│    Matrix scene modes          │
│  - bloom/particle/glow effects │
│  - block/tx/account detail     │
│    panels on click             │
│  - Web Worker: proof           │
│    verification WASM (§5)      │
└─────────────────────────────────┘

       optional, explicitly non-authoritative enrichment inputs
┌──────────────────────────────────────────────────────────────────┐
│ signed terminal manifests + receipts │ ARD catalogs │ coarse     │
│ validator metadata/telemetry          │ evidence/attestations     │
└──────────────────────────────┬───────────────────────────────────┘
                               └──────────────► Aggregator
```

A dedicated **Birdeye Aggregator Service** is necessary — not optional — for two independent
reasons documented above: (a) the JSON-RPC server has no push transport (§4.1), so something has
to poll and turn deltas into a stream; (b) it explicitly does no caching (R8) and is meant to run
co-located with a single validator, so an explorer hammering it directly with per-viewer polling
would multiply load on a validator node for no reason. The aggregator polls once, caches briefly,
and fans out to any number of connected browsers.

This also gives a natural place to add multi-node redundancy later (poll two or three
independently operated nodes' JSON-RPC endpoints and reconcile) without touching the frontend or
the node itself, addressing the single-liteserver-view caveat from R6.

The aggregator is also a semantic indexer, but not a new source of truth. It maintains a rolling
graph projection with provenance on every field, a versioned registry of recognized AI contract
code hashes/opcodes, validator-set snapshots by masterchain block, and expiring off-chain terminal
observations. It may cache and correlate these records; it may not silently upgrade a declared or
observed claim into a chain-verified claim.

Calling this component "stateless-ish" is misleading once replay, correction, AI workflow joins
and historical search exist. Separate its responsibilities:

- **collector**: polls one or more RPC nodes with bounded concurrency and persists raw,
  content-addressed responses plus source/timing metadata;
- **canonical decoder**: converts BOCs/config/transactions with shared TOS libraries and emits
  versioned normalized events; malformed data is quarantined, not partially rendered;
- **projector**: builds current graph snapshots and deterministic deltas from the append-only event
  log; projections are rebuildable after decoder upgrades;
- **enrichment verifier**: isolated egress worker for signed terminal/validator metadata with SSRF,
  schema, signature, size and expiry enforcement;
- **stream gateway**: serves snapshots/search and bounded deltas without coupling browser count to
  validator RPC load.

For the rolling MVP, one durable embedded/relational database plus object/blob storage is enough;
do not introduce Kafka or a graph database before measured scale requires it. PostgreSQL-style
tables and indexes fit block/transaction/account lookup, while adjacency tables/materialized
neighborhoods serve graph expansion. A graph database is an optimization decision, not a product
prerequisite.

Each stream connection has a byte/event budget. Standard browser `WebSocket` has no application-
level backpressure contract, so the gateway must coalesce superseded telemetry, bound per-client
queues and disconnect/resnapshot slow consumers. Chain events and retractions are never silently
dropped; ephemeral particle/telemetry hints may be coalesced because they are reconstructable from
the authoritative graph delta.

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

- **Renderer**: use `three.js` behind a narrow renderer abstraction. WebGL 2 is the compatibility
  baseline. Prototype `WebGPURenderer` early and enable it progressively when its required
  post-processing/material path passes visual parity and device tests; it can use WebGPU where
  available and fall back to a WebGL 2 backend. Do not fork shaders deeply into two permanent
  implementations. Use bloom carefully, instanced geometry, batched lines and GPU particle
  buffers; avoid one scene object/material per graph entity.
- **Layout**: use a **hybrid constrained layout**, not a global unconstrained force simulation.
  Masterchain time/seqno owns one stable axis; shard ancestry owns lanes/branches; validators use a
  stable weighted ring or cluster; AI workflows use a layered causal/DAG layout; local account
  neighborhoods may use bounded 2D/3D forces. This preserves the user's mental map, makes replay
  deterministic and prevents every new block from moving the whole scene. Force simulation is a
  local collision/legibility tool, not the source of truth for topology. Transactions/messages
  render as edges/particles between stable anchors, and new blocks enter with an animated
  "materialize" transition rather than popping in.
  - See `~/tos/doc/tos.pdf` §3.6 (Sharding) when a future phase needs to visualize shard
    structure rather than the linear masterchain backbone — dynamic shard splits/merges will need
    their own layout treatment; this design does not attempt to solve that for Phase 0–3 (see
    §10 Phase 7).
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

WebGPU exposes both rendering and compute, which may eventually move layout or aggregation kernels
to the GPU, but that is an optimization after profiling. Proof verification remains in WASM/Web
Workers: cryptographic verification and GPU rendering have different portability, side-channel,
testability and failure-isolation requirements.

### 7.1 Three connected scene modes

The explorer uses one graph and one camera vocabulary, with three semantic projections. Switching
modes changes emphasis and layout; it does not navigate to an unrelated dashboard.

1. **Consensus Matrix (default landing scene).** Validator nodes orbit or cluster around the
   current masterchain backbone. Node volume represents validator weight, not wealth inferred from
   an unrelated account balance. When signature evidence becomes available, reconstructed signals
   converge from actual signers and expose signed weight and threshold. The scene labels this
   **proof-derived participation**, including its observation delay; it must not imply that the
   explorer witnessed live catchain votes. Current/previous/next validator sets and shard/catchain
   assignments can be scrubbed over time. Skyview uses three explicit semantic depths:
   `NETWORK` shows a bounded global validator swarm or aggregate clusters, `ACTIVE SET` expands
   protocol-selected members sized by voting weight, and `SIGNERS` filters/emphasizes only proof-
   joined signers for the selected block. Camera transitions preserve the user's spatial context,
   and all three scopes display both their source and their member/rendered counts.
2. **Chain Matrix.** Masterchain blocks form the stable spine, shard blocks branch from it,
   transactions attach to blocks, and messages flow between persistent account/contract nodes.
   Success, bounce, compute failure and aborted/action failure use distinct, accessible visual
   states. Value, fees and compute consumption affect controlled visual channels with legends.
   The initial retained window contains ten masterchain anchors. Each anchor displays its total
   `tx_count`, while loaded transaction nodes display an explicit `loaded / total` or `sampled /
   total` contract. Desktop may expand the full bounded fixture neighborhood; mobile must apply
   deterministic LOD and disclose what was collapsed. Blocks, transactions, shard blocks,
   accounts and contracts remain globally searchable even when their labels are collapsed.
3. **AI Execution Matrix.** The scene expands a recognized AI workflow into principals, Agent
   Account, Task Escrow, Service Actor, remote Edge Terminal, evidence/receipt, verifier/dispute
   and settlement nodes. Animated transitions follow actual contract messages and signed receipt
   events. Off-chain execution spans are visually distinct from on-chain messages but connected by
   their verified hashes.

A global search accepts block ID/seqno, transaction hash, address, validator identifier, task or
service contract, terminal identity and public receipt hash. Search should move the camera to the
entity and reveal its upstream/downstream neighborhood rather than replacing the graph with a
static result page. A timeline scrubber freezes the live stream and reconstructs the graph at a
selected masterchain block or AI workflow event.

### 7.2 Visual grammar and truth states

The Matrix aesthetic must be learnable. Initial recommended grammar:

| Entity/event | Visual role |
|---|---|
| masterchain block | bright, stable backbone anchor |
| shard block | smaller branch anchor linked to its masterchain inclusion |
| validator | persistent identity node sized by selected-set weight |
| block signature | converging pulse from validator to block |
| transaction/message | directional particle trail; selection exposes exact values |
| account/contract | persistent endpoint; recognized contract type changes glyph, not truth level |
| AI Edge Terminal | off-chain service node outside the chain plane |
| receipt/evidence commitment | bridge node joining terminal span to contract state |
| dispute/failure | interrupted or branching path, never merely a red decorative flash |

Color alone must not encode status; shape, motion and labels must remain usable with reduced motion
and common forms of color-vision deficiency. The UI must provide reduced-motion and low-GPU modes,
cap particle counts, pause background animation when hidden, and fall back to a 2D/canvas or DOM
inspection view without losing data.

Every selected node and edge shows a provenance badge:

- **Chain verified** — included in chain state and successfully checked against its proof/trust
  root where client verification is available.
- **Node validated** — native node code checked an upstream proof, but the browser did not receive
  enough material to repeat the check independently.
- **Chain reported** — returned by the configured node without an independently checked proof path.
- **Signed off-chain** — signature and identity binding checked; not a chain execution fact.
- **Attested/audited/benchmarked/replicated** — evidence method checked under its named policy.
- **Observed** — measured by the aggregator or derived from receipts, with time and observer.
- **Declared** — self-reported by a validator/terminal operator.
- **Inferred** — e.g. ASN or coarse geography derived from network data, with source and confidence.
- **Expired/stale** — formerly valid short-lived data that is no longer current.

No single green checkmark may combine these meanings. Detail copy must state what was verified,
by whom, against which commitment or trust root, and at what time.

## 8. Data Model (Aggregator → Frontend graph schema)

The aggregator normalizes RPC responses into a single graph shape the frontend already knows how
to lay out and animate:

```ts
type Provenance = {
  class: "chain_verified" | "node_validated" | "chain_reported" | "signed_offchain" |
         "attested" | "audited" | "benchmarked" | "replicated" |
         "observed" | "declared" | "inferred" | "stale";
  source: string;
  observed_at: number;
  expires_at?: number;
  evidence_hash?: string;
  details?: string;
};

type ExplorerNode =
  | { kind: "block"; id: string /* workchain:shard:seqno */; seqno: number; gen_utime: number;
      tx_count: number; workchain: number; shard: string; validator_set_hash?: number;
      catchain_seqno?: number; provenance: Provenance }
  | { kind: "validator"; id: string /* node_id_short or public-key-derived ID */;
      public_key?: string; adnl_id?: string; weight: string; weight_fraction: number;
      set: "previous" | "current" | "next"; provenance: Provenance }
  | { kind: "account"; id: string /* address */; balance: string; state: string }
  | { kind: "contract"; id: string /* address */; code_hash: string;
      contract_type: "agent_account" | "task_escrow" | "service_actor" |
                     "capability_registry" | "dispute" | "unknown";
      contract_version?: string; provenance: Provenance }
  | { kind: "transaction"; id: string /* hash */; lt: string; fee: string; utime: number;
      compute_exit_code?: number; gas_used?: string; aborted?: boolean; provenance: Provenance }
  | { kind: "ai_task"; id: string; contract: string; status: string; creator: string;
      agent?: string; budget?: string; deadline?: number; result_hash?: string;
      evidence_hash?: string; provenance: Provenance }
  | { kind: "ai_service"; id: string; contract?: string; service_profile?: string;
      pricing_hash?: string; proof_scheme_hash?: string; provenance: Provenance }
  | { kind: "edge_terminal"; id: string /* revocable terminal identity */; service_id?: string;
      region?: string; admission?: "available" | "busy" | "draining" | "offline" | "unknown";
      capabilities: string[]; expires_at: number; provenance: Provenance }
  | { kind: "ai_receipt"; id: string /* receipt/content hash */; request_hash: string;
      output_hash?: string; usage_hash?: string; evidence_level: string;
      provenance: Provenance }
  | { kind: "dispute"; id: string; contract: string; status: string;
      ruling_hash?: string; provenance: Provenance };

type ExplorerEdge =
  | { kind: "contains"; from: string /* block id */; to: string /* tx id */ }
  | { kind: "precedes"; from: string /* block id */; to: string /* block id */ }
  | { kind: "signed"; from: string /* validator */; to: string /* block */;
      signature: string; signed_weight: string; provenance: Provenance }
  | { kind: "assigned_to"; from: string /* validator */; to: string /* shard/catchain */;
      provenance: Provenance }
  | { kind: "touches"; from: string /* tx id */; to: string /* account id */;
      direction: "in" | "out" }
  | { kind: "message"; from: string; to: string; tx: string; value?: string; opcode?: number;
      bounced?: boolean; provenance: Provenance }
  | { kind: "workflow"; from: string; to: string;
      event: "request" | "accept" | "service_call" | "result" | "verify" |
             "dispute" | "settle" | "refund"; tx?: string; provenance: Provenance }
  | { kind: "executes_on"; from: string /* service call/task */; to: string /* terminal */;
      request_hash: string; provenance: Provenance }
  | { kind: "commits"; from: string /* chain event */; to: string /* receipt/evidence */;
      hash: string; provenance: Provenance };

type GraphDelta = {
  cursor: string;              // monotonically ordered stream cursor, not necessarily chain seqno
  chain_tip: string;
  generated_at: number;
  upsert_nodes: ExplorerNode[];
  upsert_edges: ExplorerEdge[];
  remove_node_ids: string[];   // expiry/window eviction, not chain deletion
  remove_edge_ids: string[];
};
```

New blocks/transactions/accounts are pushed as additive graph deltas over the WebSocket channel;
the frontend force layout absorbs new nodes without discarding existing positions (this is the
same "delta, not full reload" principle the aggregator needs internally to avoid re-fetching the
whole 10-block window on every poll tick — track the last-seen tip `seqno` and only fetch blocks
above it).

All monetary quantities, weights and logical times remain decimal strings across the API boundary;
JavaScript `number` must not silently truncate 64/128-bit values. Graph entity IDs are namespaced
by network and kind to prevent a transaction hash, receipt hash and terminal identity from
colliding. Off-chain fields require field-level provenance when one node mixes sources (for
example, a chain-bound Service Actor with an operator-declared display name and observed latency).

The stream protocol needs replay and resynchronization semantics: the frontend reconnects with its
last cursor, the aggregator replays retained deltas when possible, and otherwise returns a compact
snapshot plus a new cursor. Reorganizations or a corrected upstream view are represented as
explicit retractions/replacements, not hidden behind a full page reload.

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
- Treat terminal manifests, ARD records, evidence bundles and validator metadata as untrusted input
  even when signed. Enforce response size/content-type/time limits, schema validation, signature
  verification, URL allow/deny policy and outbound SSRF protections in a dedicated fetch worker.
  Never render fetched HTML or execute terminal-provided script/shader/3D assets.
- Do not proxy private terminal administrative APIs, model-provider credentials or validator
  control interfaces through the explorer. Public discovery and health endpoints are separate from
  control planes by design.
- Coarse geography and provider/ASN enrichment create validator privacy and targeting risk. Make
  them opt-in where possible, retain source/collection time, avoid precise coordinates, and provide
  a deployment switch that disables all network enrichment.
- Public AI payloads may contain prompts, outputs, personal information or malicious content. The
  default UI shows hashes and bounded metadata, not raw payloads. Any opt-in artifact viewer must
  be sandboxed, size-limited and safe for hostile media.
- Search, graph-neighborhood expansion and WebSocket connections need per-client quotas. A single
  query must not recursively expand an unbounded account or AI workflow graph.

## 10. Phased Delivery

1. **Phase 0 — contracts and data plumbing**: pin down real block/message/compute JSON shapes;
   aggregator polls the last 10 masterchain blocks; define GraphDelta/provenance contracts and a
   plain diagnostic frontend. Decode current validator config and signatures in this phase even if
   the first diagnostic UI is textual. Include source/node identity and correction history in the
   schema even though the first deployment polls only one node.
2. **Phase 1 — Consensus + Chain Matrix**: three.js/WebGL scene, masterchain backbone, validator
   weight distribution, real signature convergence, transactions/messages, bloom/particle effects,
   legends and reduced-motion/low-GPU modes.
3. **Phase 2 — live streaming and time**: WebSocket delta/replay protocol, continuous block
   arrival, reconnect/resync behavior and timeline scrubbing over the retained window.
4. **Phase 3 — chain drill-down**: transaction/message/TVM execution panel, account and global
   lookup, raw identifiers and value/fee/compute fields. Complete the in/out-message audit from
   §4.2 before committing the public schema.
5. **Phase 4 — AI contract semantics**: versioned code-hash/opcode registry; decode Agent Account,
   Task Escrow, Service Actor, Capability Registry and Dispute state; reconstruct the on-chain AI
   workflow and settlement graph. Unknown versions degrade safely to generic contracts.
6. **Phase 5 — remote AI Edge layer**: ingest signed, expiring terminal/service manifests and
   public receipts; join them to chain commitments; render capability, admission and evidence
   levels with strict provenance. Support public, selectively disclosed and hash-only receipt
   modes; do not require private prompts or outputs.
7. **Phase 6 — client-side verification (§5)**: new `birdeye-verify-emscripten` CMake target,
   Web Worker integration and precise chain reported/verified states. Add supported receipt,
   signature and attestation verifiers as separate policies, never as one universal check.
8. **Phase 7 — shard and network awareness**: shard blocks, masterchain/shard relationships,
   validator subset views, shard proofs, multi-node polling and upstream disagreement display.
9. **Phase 8 — optional enrichment and history**: opt-in coarse validator region/ASN/provider,
   terminal performance history, full historical index/search, then token/NFT visualization.

### 10.1 Release gates and measurable acceptance criteria

Phases are capability gates, not calendar promises. Initial budgets must be validated on real TOS
data and may be tightened, but they must exist before visual implementation expands:

| Gate | Minimum acceptance signal |
|---|---|
| data correctness | golden fixtures for pagination, split/merge flags, large integer values, unknown contract versions and malformed BOCs; normalized output is deterministic |
| freshness | healthy-node p95 tip-to-browser graph delta under 2 seconds beyond the chain/API observation delay; UI always displays block age and upstream status |
| stream recovery | reconnect from retained cursor without duplication; forced snapshot recovery after cursor expiry; slow-client queue remains bounded |
| render performance | representative desktop tier sustains p95 frame time ≤ 16.7 ms at the declared normal graph budget; mobile/low-GPU mode sustains p95 ≤ 33.3 ms |
| interaction | selection/search response under 100 ms for already-loaded entities; stable node positions across identical replay |
| validator scope | Network, Active Set and Signers are separately selectable; each reports source, total and rendered count; no active-set count is presented as total network population |
| chain legibility | initial view exposes 10 masterchain blocks; block `tx_count` and loaded/sampled transaction count are visibly distinct; mobile LOD reports collapsed detail |
| accessibility | complete keyboard/DOM route to search and details; no information encoded only by color/motion; automatic and interactive non-essential motion can be paused/disabled |
| provenance | every externally visible field resolves to source, observation time and truth class; expired off-chain data changes state automatically |
| proof verification | cross-implementation fixtures and trust-root gate in §5.5; no **Chain verified** label before it passes |
| privacy/security | egress/SSRF tests, hostile manifest/media fixtures, exact-coordinate suppression and bounded graph expansion |
| product differentiation | one recorded workflow demonstrates validator participation → block → transaction/message → AI contract → terminal receipt/evidence → settlement with source/truth state inspectable at every step; unsupported portions are visibly absent, not simulated |

The team should choose explicit normal and stress graph budgets after Phase 0 captures real block
distributions. As a starting test matrix, benchmark 2k/10k/50k visible entities and 5k/25k/100k
edges with particle density capped independently of edge count. Level-of-detail rules collapse old
transactions into aggregate flows before frame rate degrades; selection expands detail on demand.

### 10.2 Recommended implementation decisions

- Prefer a typed, memory-safe service language with strong TOS decoding support. Go or Rust is a
  better default for the long-running collector/projector than Node.js if native TOS parsers can be
  integrated cleanly; choose by a Phase 0 spike, not fashion.
- Keep the normalized event schema transport-neutral and versioned. JSON is acceptable for initial
  REST/debugging; use compact binary deltas only after profiling proves serialization/bandwidth is
  material.
- Begin with WebGL 2 through three.js and a renderer abstraction; promote WebGPU after parity and
  device testing. Advanced product semantics matter more than selecting the newest GPU API.
- Use deterministic server/projector coordinates for the consensus backbone and time axis, with
  client-local forces only for bounded neighborhoods. This makes screenshots, replay and incident
  comparison reproducible.
- Ship the provenance inspector in the first visual release. Adding truth labels after the visual
  language is established is both harder and less credible.

## 11. Open Questions / Follow-ups Before Implementation

- **Decoded explorer API**: code audit confirmed the current header fields and confirmed that
  `getBlockTransactionsExt` omits message endpoints/value/body/opcode and execution phases. Decide
  whether one versioned `getExplorerBlock`-style read model or shared aggregator decoder becomes
  the canonical contract; freeze golden response fixtures before frontend implementation.
- **`~/tos/adnl/` has no dedicated prose documentation** beyond code comments; if the aggregator
  ever needs to speak ADNL directly instead of going through the JSON-RPC server (it shouldn't,
  per §4), this is a gap to fill first.
- **Which node(s) to poll** in non-development environments is an operational decision, not a
  code one — needs an answer before Phase 0 ships anywhere but localhost.
- **`check-proof.cpp`'s dependency footprint** (what it pulls in from `vm/cells`, hashing, and
  `block::gen` beyond what's declared in `check-proof.h`) has not been traced end-to-end — needed
  to size the new `birdeye-verify-emscripten` WASM target (§5.3) and confirm it can be built
  without dragging in ADNL/networking code.
- **Proof package API**: code audit confirmed that successful decoded block headers omit
  `header_proof`, account responses omit `shard_proof`/`proof`, and raw transaction BOCs do not
  provide a complete inclusion proof. Design a byte-preserving, versioned proof-package endpoint
  plus trust-root bootstrap before beginning the WASM UI integration.
- **Decoded validator set contract**: confirm whether `getConfigParam`/`getConfigAll` currently
  exposes enough decoded validator member data for public use. If it only returns a config BOC,
  choose whether decoding belongs in the aggregator via shared TOS code or in a new narrow
  read-only JSON-RPC method. Also confirm the exact join from validator public key/ADNL ID to
  `node_id_short` returned by `getMasterchainBlockSignatures`.
- **Signature semantics and timing**: document exactly which proof-link destination each returned
  signature authenticates and whether the endpoint can transiently return an incomplete set near
  the tip. The animation must show a completed historical signature set, not pretend to be a live
  gossip capture when the source is a later block proof.
- **AI contract registry ownership**: define the canonical, signed mapping of network + code hash
  to contract family/version/opcode decoder. The explorer must be upgradeable without relabeling
  old blocks under a new ABI.
- **AI execution trace availability**: audit transaction JSON for inbound/outbound messages,
  opcodes, compute/action phases, exit codes, gas and state-change evidence. Decide which missing
  decoded fields warrant additive node-side read endpoints versus aggregator-side BOC decoding.
- **Terminal identity binding and discovery**: specify the production path from Service Actor or
  Capability Registry commitment to signed terminal manifest/ARD record, including key rotation,
  revocation, expiry and TOS domain binding. A public URL alone is not an identity.
- **Receipt transport and privacy**: decide where public receipt/evidence bundles are retrieved,
  their retention policy and maximum size, and which fields are safe to expose. Hash-only
  workflows must remain useful in the UI when no preimage is public.
- **Validator geography policy**: decide whether the production explorer accepts only opt-in
  operator metadata or also performs IP/ASN inference. Document granularity, retention, takedown
  and anti-targeting controls before enabling a map.
- **Performance budget**: establish device tiers and measurable budgets for initial JS/WASM bytes,
  time-to-first-meaningful-graph, steady-state frame time, node/edge/particle counts, worker CPU and
  memory. The Matrix must remain an explorer on ordinary hardware, not only on a workstation GPU.

## 12. Related Design Sources

- `doc/ai-actors.md` — authoritative actor roles, task lifecycle and chain/evidence boundary.
- `doc/ai-actor-message-catalog.md` — stable AI workflow message categories and required fields.
- `doc/ai-workflow-schemas.md` — canonical result, evidence, service-call and receipt commitments.
- `doc/ai-edge-computing-terminal-architecture.md` — remote terminal capability, admission,
  evidence levels, privacy and signed receipt model.
- `doc/ai-inference-sharing-tos-domains.md` — TOS domain to AI service/terminal binding.
- `doc/tos-trust-tiers.md` — distinctions between local full-node, proof-backed and trusted RPC
  reads; the explorer provenance vocabulary should remain consistent with it.
- `doc/json-rpc-policy.md` and `doc/openapi.yaml` — public node data and transport contract.

## 13. External Technical Baselines

These references support implementation choices; they do not establish a competitive "first":

- [W3C WebGPU Candidate Recommendation](https://www.w3.org/TR/webgpu/) — standardized GPU
  rendering/compute model, worker exposure, validation and security considerations. WebGPU is a
  progressive performance path, not a reason to remove the WebGL 2 fallback.
- [three.js WebGPURenderer guide](https://threejs.org/manual/en/webgpurenderer) — current renderer
  architecture and WebGL 2 fallback behavior; also documents material/shader migration constraints
  that require an early visual-parity spike.
- [MDN WebSocket API](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API) — browser
  WebSocket behavior and the backpressure distinction from the non-standard/limited
  `WebSocketStream`; the production protocol must bound queues itself.
- [W3C Understanding Animation from Interactions](https://www.w3.org/WAI/WCAG21/Understanding/animation-from-interactions.html)
  — user control and reduced-motion expectations for non-essential animation.

## 14. Review Conclusion

The design is technically feasible if delivered as a sequence of truth-preserving projections,
not as one large visualization project. The strongest near-term product is a live Consensus +
Chain Matrix backed by the existing JSON-RPC server, a canonical decoder and reconstructed signer
evidence. The strongest long-term differentiator is the AI Execution Matrix joining on-chain state
to signed and expiring remote-execution evidence.

The highest risks are data-contract incompleteness, overclaiming signature liveness or proof
verification, unstable global force layouts, unbounded browser/stream load, and dependence on a
remote-terminal ecosystem that is not yet a production data feed. The changes and gates above
turn each into an explicit engineering dependency. If the team ships provenance, causal replay and
truthful evidence semantics first, the Matrix aesthetic amplifies a genuinely advanced explorer;
without them, it would remain only a premium visualization of trusted RPC data.
