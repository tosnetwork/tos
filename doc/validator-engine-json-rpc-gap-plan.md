# Validator Engine JSON-RPC Gap-to-Implementation Plan

## Purpose

This document converts the current JSON-RPC gap analysis into a concrete implementation plan for:

- `~/tos/validator-engine/json-rpc-server.h`
- `~/tos/validator-engine/json-rpc-server.cpp`

The target is not to re-implement all of `tos-http-api` at once. The target is to define a clean, incremental patch plan that can be implemented in small reviewable steps.

## Current State

> **Last updated: 2026-04-14**

The embedded JSON-RPC server dispatches **35 methods** plus **3 HTTP endpoints** with full REST GET + POST + JSON-RPC support.

All methods (35/35):

- ✅ `getMasterchainInfo`
- ✅ `getConsensusBlock`
- ✅ `lookupBlock`
- ✅ `shards` / `getShards`
- ✅ `getBlockHeader`
- ✅ `getBlockTransactions`
- ✅ `getBlockTransactionsExt`
- ✅ `getMasterchainBlockSignatures`
- ✅ `getShardBlockProof`
- ✅ `getOutMsgQueueSize`
- ✅ `getAddressInformation`
- ✅ `getExtendedAddressInformation`
- ✅ `getWalletInformation`
- ✅ `getAddressBalance`
- ✅ `getAddressState`
- ✅ `getTokenData`
- ✅ `getTransactions`
- ✅ `getTransactionsStd`
- ✅ `getBlockTransactions`
- ✅ `getBlockTransactionsExt`
- ✅ `tryLocateTx`
- ✅ `tryLocateResultTx`
- ✅ `tryLocateSourceTx`
- ✅ `runGetMethod`
- ✅ `runGetMethodStd`
- ✅ `sendBoc`
- ✅ `sendBocReturnHash`
- ✅ `sendBocReturnHashNoError`
- ✅ `sendQuery`
- ✅ `estimateFee`
- ✅ `getConfigParam`
- ✅ `getConfigAll`
- ✅ `getLibraries`
- ✅ `packAddress`
- ✅ `unpackAddress`
- ✅ `detectAddress`
- ✅ `detectHash`

HTTP endpoints:

- ✅ `GET /healthcheck` — liveness probe
- ✅ `GET /readyz` — readiness probe with sync lag check
- ✅ `OPTIONS *` — CORS preflight with configurable origin

Runtime configuration:

- ✅ `--json-rpc-readonly` — disable send-family methods
- ✅ `--json-rpc-cors-origin` — configurable CORS origin
- ✅ `--json-rpc-readyz-threshold` — configurable sync lag threshold
- ✅ `--json-rpc-request-timeout` — configurable request timeout (default 30s)
- ✅ `--json-rpc-api-key` — optional API key authentication
- ✅ `--json-rpc-cache-ttl` — response cache TTL

Protocol:

- ✅ JSON-RPC request-id type preservation
- ✅ Explicit batch JSON-RPC rejection
- ✅ Canonical `/jsonRPC` path as the only JSON-RPC envelope endpoint
- ✅ REST GET endpoints for supported query-parameter read methods
- ✅ REST POST endpoints for all methods
- ✅ HTTP status code mapping (422/500/404/400/401/409)
- ✅ QueryTimeoutGuard with configurable timeout

Testing:

- ✅ 478 pytest tests passing against live 4-node testnet
- ✅ Tests aligned with tos-http-api-cpp reference test suite
- ✅ 6 wallet contracts deployed for wallet type detection tests

Remaining gaps: **NONE** — all planned methods and features implemented.

## Compatibility Scope Clarification

This plan targets two different compatibility layers:

1. **JSON-RPC method compatibility**
2. **HTTP surface compatibility**

They are related but not identical.

### JSON-RPC Method Compatibility

This means:

- matching method names
- matching parameter names
- matching result and error payload shapes closely enough for existing clients

### HTTP Surface Compatibility

This means:

- exposing the canonical JSON-RPC endpoint path
- deciding whether REST-style per-method endpoints should also exist
- preserving operational helper endpoints such as health checks
- preserving cross-origin behavior and request validation behavior

The original document focused mostly on method coverage. The missing pieces below make the plan complete.

## Implementation Strategy

Use the following delivery pattern:

1. make the existing methods semantically correct
2. add missing low-risk read APIs
3. add send and fee-estimation APIs
4. add advanced block/proof/lookup APIs

Each patch should preserve the current simple actor model:

- parse HTTP JSON body
- validate params
- build liteserver TL query or local VM execution request
- forward through `ValidatorManagerInterface::run_ext_query`
- parse the reply
- normalize response into tos-http-api-compatible JSON shape

## Shared Refactoring Tasks

These tasks should be done early because multiple methods depend on them.

### ✅ R0. Add reusable parsing helpers

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Add helper functions for:

- address parsing from raw and user-friendly forms
- optional `seqno`
- optional block id lookup
- hash decoding from hex/base64
- base64 BOC decoding
- stack item parsing for `runGetMethod`

Why:

- current handlers inline too much logic
- new APIs will duplicate block lookup and account lookup patterns otherwise

### ✅ R1. Add reusable liteserver workflows

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Add reusable helper flows for:

- latest masterchain lookup
- block lookup by `(workchain, shard, seqno|lt|utime)`
- account state fetch at latest block
- account state fetch at a requested masterchain seqno
- block header fetch
- block transactions fetch

Why:

- many APIs differ only in the final liteserver request

### ✅ R2. Add response builders

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Add builders for normalized JSON payloads:

- account info
- wallet info
- block id
- block header
- transaction id
- stack result

Why:

- current handlers manually emit JSON strings
- that will become brittle once output formats grow

### ✅ R3. Add protocol and endpoint policy

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Define and document:

- canonical JSON-RPC path, preferably `/jsonRPC`
- optional API root prefix compatibility, comparable to `TOS_API_ROOT_PATH`
- whether non-JSON-RPC REST endpoints will be supported
- health endpoint path, preferably `/healthcheck`
- worker/debug endpoint policy
- CORS behavior
- `OPTIONS` behavior for browser-based clients
- payload size policy and configuration
- request `Content-Type` policy

Why:

- `tos-http-api` compatibility is not just a method list
- current implementation accepts any POST path and has no explicit path model
- downstream clients often depend on stable endpoint paths

### ✅ R4. Add common error and envelope normalization

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Add shared policy for:

- JSON-RPC success envelope
- JSON-RPC error envelope
- HTTP status code mapping
- method-not-found behavior
- invalid-params behavior
- internal-error behavior

Why:

- compatibility work will fail if method outputs are added but envelope behavior drifts
- current implementation already has a custom envelope and should make that choice explicit

### ✅ R5. Add runtime policy and feature-gating

Files:

- `validator-engine/validator-engine.cpp`
- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Define and document runtime policy for:

- JSON-RPC enable/disable
- `runGetMethod` enable/disable
- API root prefix or fixed-path policy
- request timeout defaults
- maximum payload size
- per-request concurrency limits if needed
- listen address configuration

Why:

- `tos-http-api` explicitly exposes feature gates such as JSON-RPC and get-method toggles
- an embedded server should still have operational controls even if the implementation is simpler
- these controls affect rollout safety

### ✅ R7. Add documentation-surface policy

Files:

- implementation docs
- operator docs

Define and document:

- whether the embedded server will expose OpenAPI/Swagger docs
- whether it will expose a docs root path
- whether docs are enabled in production by default

Why:

- `tos-http-api` exposes a documentation surface by default
- the embedded server may intentionally choose not to do so
- this should be a documented compatibility decision rather than an accidental omission

Recommended policy:

- do not block JSON-RPC delivery on OpenAPI support
- treat embedded docs as optional

### ✅ R8. Add caching and non-goals policy

Files:

- implementation docs
- operator docs

Define and document:

- whether response caching exists in the embedded server
- whether Redis-style external cache integration is in scope
- whether cache parity with `tos-http-api` is explicitly out of scope

Why:

- `tos-http-api` includes optional cache infrastructure
- embedded `validator-engine` may reasonably reject that complexity
- the omission should be deliberate and recorded

Recommended policy:

- declare external cache parity out of scope for the embedded server
- revisit only if read load demonstrates the need

### ✅ R9. Add REST transport-shape policy

Files:

- implementation docs
- operator docs

Define and document:

- if REST endpoints are added, which methods use `GET` with query params
- which methods use `POST` with JSON bodies
- whether REST parameter names exactly mirror `tos-http-api`
- whether REST and JSON-RPC responses share the same normalized result payloads

Why:

- `tos-http-api` compatibility is not only about endpoint names
- clients may rely on concrete transport conventions such as:
  - `GET /getAddressInformation?address=...`
  - `POST /runGetMethod` with JSON body
- this should be a conscious compatibility contract rather than an ad hoc implementation detail

### ✅ R10. Add parameter-default and validation parity policy

Files:

- implementation docs
- operator docs

Define and document:

- compatibility-sensitive default values such as:
  - `getTransactions.limit=10`
  - `getBlockTransactions.count=40`
- validation bounds such as:
  - `getTransactions.limit > 0`
  - `getTransactions.limit <= 100`
- whether the embedded server preserves these defaults and limits exactly
- whether stricter validation will be introduced and where

Why:

- `tos-http-api` compatibility includes parameter defaults and bounds
- explorers and SDKs may omit optional fields assuming those defaults

### ✅ R11. Add input-normalization and encoding policy

Files:

- implementation docs
- operator docs

Define and document:

- address normalization behavior:
  - raw form
  - user-friendly form
  - "any format" operator-facing inputs
- hash normalization behavior:
  - hex
  - base64
- library-hash normalization
- BOC encoding expectations for send and run-method APIs

Why:

- `tos-http-api` uses helper normalization functions such as `prepare_address` and `prepare_hash`
- many compatibility bugs come from encoding mismatches rather than missing methods

### ✅ R12. Add public method-name stability policy

Files:

- implementation docs
- operator docs

Define and document:

- that public JSON-RPC method names must follow `tos-http-api` compatibility names exactly
- that internal helper or backend naming must not leak into the public API
- whether any compatibility aliases are supported

Why:

- some public names are compatibility-facing API names rather than direct internal backend names
- clients depend on exact strings such as:
  - `shards`
  - `getBlockTransactionsExt`
  - `sendBocReturnHash`
- this should be preserved deliberately

### ✅ R13. Add security and exposure policy

Files:

- implementation docs
- operator docs
- validator-engine runtime options/docs

Define and document:

- whether the embedded JSON-RPC server is intended for:
  - localhost-only use
  - trusted LAN use
  - public Internet exposure
- default bind behavior
- whether TLS termination is out of scope and expected to be handled by a reverse proxy
- whether authentication is intentionally absent
- whether rate limiting is expected to be external
- whether `send`-family APIs should be disabled by default on publicly exposed nodes

Why:

- `tos-http-api` is a separate service and can be isolated operationally
- an embedded API inside `validator-engine` changes the risk profile
- this must be a design decision, not an accident of implementation

Recommended policy:

- default to explicit bind configuration, not implicit public exposure
- assume TLS and auth are external unless a later milestone adds them
- document public exposure of write endpoints as high risk

### ✅ R14. Add API versioning and deprecation policy

Files:

- implementation docs
- operator docs

Define and document:

- whether the embedded API exposes a version header such as `X-API-Version`
- how compatibility with `tos-http-api` versions is described
- how deprecated methods are labeled
- how behavior changes are rolled out without breaking `tosctl` and external clients

Why:

- `tos-http-api` exposes version information in the HTTP layer
- embedded replacement needs a stability story once clients start depending on it

### ✅ R6. Add liteserver selection and archival-routing policy

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`
- validator-manager-facing integration points as needed

Define and document:

- how the embedded server chooses a liteserver/backend path
- whether it always uses the local validator state, forwarded liteserver queries, or mixed mode
- how "archival" queries are handled
- what happens when full history is unavailable

Why:

- `tos-http-api` has explicit `archival` semantics for transaction history
- this is a compatibility-sensitive behavioral decision, not just an implementation detail

## Patch Group A: Fix Existing Methods

### ✅ A1. `handle_getAddressInformation`

Current status:

- implemented
- incomplete

Current issues:

- ignores optional `seqno`
- returns placeholder `last_transaction_id`
- returns placeholder `sync_utime`
- hardcodes `extra_currencies` to `[]`
- only partially reflects account state

Files:

- `validator-engine/json-rpc-server.cpp`

Required changes:

1. Accept optional `seqno` parameter
2. Resolve the correct masterchain block if `seqno` is provided
3. Use the real account state response fields to populate:
   - `balance`
   - `extra_currencies`
   - `last_transaction_id`
   - `sync_utime`
4. Preserve current `state`, `code`, `data`, `frozen_hash`
5. Keep output aligned with `tos-http-api` shape

Dependencies:

- R0
- R1
- R2

Recommended patch split:

- Patch A1.1: add optional `seqno` support
- Patch A1.2: fill real `last_transaction_id` and `sync_utime`
- Patch A1.3: parse `extra_currencies`

### ✅ A2. `handle_getExtendedAddressInformation`

Current status:

- stub
- currently forwards to `handle_getAddressInformation`

Current issues:

- no generic known-contract parsing
- no enriched contract-type fields

Files:

- `validator-engine/json-rpc-server.cpp`

Required changes:

1. Stop delegating directly to `getAddressInformation`
2. Build on the same account state fetch path
3. Add contract code/data inspection for recognized contract families
4. Return extended state object in a shape compatible with tos-http-api expectations

Scope note:

- this does not need to support every historical TOS contract immediately
- start with the contract families TOS actually uses

Dependencies:

- A1
- R2

Recommended patch split:

- Patch A2.1: separate implementation from `getAddressInformation`
- Patch A2.2: add code-hash-based known-type detection
- Patch A2.3: add structured per-type parsed fields

### ✅ A3. `handle_getWalletInformation`

Current status:

- stub
- currently forwards to `handle_getAddressInformation`

Current issues:

- no wallet type detection
- no `wallet` boolean
- no `wallet_type`
- no `seqno`
- no wallet-specific state extraction

Files:

- `validator-engine/json-rpc-server.cpp`

Required changes:

1. Stop delegating directly to `getAddressInformation`
2. Reuse account state fetch
3. Detect wallet code hashes for supported wallet types
4. Parse wallet-specific fields, starting with:
   - account state
   - balance
   - extra currencies
   - last transaction id
   - seqno
   - wallet type
5. Return `wallet: true|false`

Dependencies:

- A1
- R2

Recommended patch split:

- Patch A3.1: add wallet response structure
- Patch A3.2: add wallet code-hash registry
- Patch A3.3: add seqno extraction by local decode or `runGetMethod`

### ✅ A4. `handle_runGetMethod`

Current status:

- implemented
- too narrow

Current issues:

- accepts only string `method`
- does not support numeric method id
- ignores incoming `stack`
- ignores optional `seqno`
- returns incomplete stack type coverage
- hardcodes `gas_used` to `0`

Files:

- `validator-engine/json-rpc-server.cpp`

Required changes:

1. Accept `method` as string or integer
2. Accept input `stack`
3. Accept optional `seqno`
4. Serialize input stack to BOC
5. Resolve correct reference block
6. Parse returned stack into tos-http-api-compatible stack items
7. Return real `gas_used` if available from the response

Dependencies:

- R0
- R1
- R2

Recommended patch split:

- Patch A4.1: support method id integer
- Patch A4.2: support input stack parsing and serialization
- Patch A4.3: support `seqno`
- Patch A4.4: expand output stack type coverage

### ✅ A5. `handle_getConfigParam`

Current status:

- implemented
- latest-only

Current issues:

- no optional `seqno`
- response shape is minimal

Files:

- `validator-engine/json-rpc-server.cpp`

Required changes:

1. Accept optional `seqno`
2. Resolve target masterchain block when provided
3. Keep current config-proof-based extraction path
4. Preserve current response shape unless a stronger compatibility reason appears

Dependencies:

- R1

Recommended patch split:

- Patch A5.1: add `seqno`
- Patch A5.2: add shared config lookup helper for later block APIs

### ✅ A6. `handle_sendBoc`

Current status:

- implemented

Current issues:

- only covers the most basic send path
- response shape may not match the future send family

Files:

- `validator-engine/json-rpc-server.cpp`

Required changes:

1. Keep current implementation as baseline
2. Normalize send-result shaping so it can be reused by:
   - `sendBocReturnHash`
   - `sendQuery`

Dependencies:

- R2

Recommended patch split:

- Patch A6.1: isolate send-message helper

## Patch Group B0: HTTP and Protocol Surface

These items were missing from the original plan and should be treated as first-class implementation work.

### ✅ B0.1 Add canonical `/jsonRPC` routing

Priority:

- P0

Files:

- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Route JSON-RPC handling only for the canonical JSON-RPC path
2. Reject unsupported POST paths rather than treating them as implicit JSON-RPC endpoints
3. Keep direct REST-style POST endpoints only for explicitly registered method paths

Why:

- `tos-http-api` exposes `/jsonRPC`
- clients and reverse proxies may rely on stable path semantics

### ✅ B0.2 Add `/healthcheck`

Priority:

- P0

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Add a lightweight non-JSON-RPC health endpoint
2. Return a minimal successful body, such as `OK`
3. Avoid liteserver dependency for basic process health

Why:

- `tos-http-api` exposes `/healthcheck`
- deployments commonly depend on a simple HTTP health probe

### ✅ B0.3 Decide on `/getWorkerState`

Priority:

- P2

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Decide whether an embedded-node equivalent exists or should exist
2. If yes, expose a lightweight worker/runtime state endpoint
3. If no, explicitly mark it unsupported in the design

Why:

- `tos-http-api` exposes `/getWorkerState`
- even if not implemented, the omission should be deliberate rather than accidental

### ✅ B0.4 Add `OPTIONS` and CORS policy

Priority:

- P1

Files:

- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Handle `OPTIONS` requests on supported paths
2. Return CORS headers consistently
3. Document browser-client support expectations

Why:

- current server only supports `POST`
- browser-facing tools often require preflight support

### ✅ B0.5 Add REST endpoint compatibility decision

Priority:

- P1

Tasks:

1. Decide whether the embedded server will expose only `/jsonRPC`
2. Or also provide REST endpoints like:
   - `/getAddressInformation`
   - `/getMasterchainInfo`
   - `/lookupBlock`
3. Record the decision in code comments and docs

Why:

- `tos-http-api` supports both REST and JSON-RPC entrypoints
- this is an architectural compatibility decision, not just an implementation detail

Recommended policy:

- support `/jsonRPC` first
- add REST endpoints only for the high-value read APIs if compatibility pressure appears

### ✅ B0.7 Add API root-prefix decision

Priority:

- P2

Tasks:

1. Decide whether the embedded server supports a configurable root prefix such as `/api/v2`
2. If yes, apply it consistently to JSON-RPC, REST, and health endpoints
3. If no, explicitly document fixed-path behavior

Why:

- `tos-http-api` supports configurable root-path deployment behind reverse proxies
- reverse-proxy deployments may depend on this behavior

### ✅ B0.6 Add timeout and overload behavior

Priority:

- P1

Files:

- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Define request timeout behavior for long-running liteserver calls
2. Decide what JSON-RPC error is returned on timeout
3. Define overload/backpressure behavior when too many requests are in flight
4. Document whether send-path and read-path timeouts differ

Why:

- `tos-http-api` exposes request-timeout policy operationally
- embedded mode still needs predictable failure behavior

## Patch Group B: Add Missing Core Read APIs

### ✅ B1. Add `getMasterchainInfo`

Priority:

- P0

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Add dispatcher entry
2. Add method handler declaration
3. Query `liteServer.getMasterchainInfo`
4. Return tos-http-api-compatible block id structure

Why:

- required by explorers, tooling, and many block-relative calls

### ✅ B2. Add `lookupBlock`

Priority:

- P0

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Add dispatcher entry
2. Accept `workchain`, `shard`, and one of `seqno|lt|utime`
3. Build `liteServer.lookupBlock`
4. Return normalized block id

Why:

- foundational for block-oriented queries

### ✅ B3. Add `shards`

Priority:

- P0

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Add dispatcher entry
2. Accept masterchain `seqno`
3. Resolve masterchain block
4. Query `liteServer.getShards`
5. Return shard list in tos-http-api-compatible shape

Why:

- standard block navigation surface

### ✅ B4. Add `getBlockHeader`

Priority:

- P0

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Add dispatcher entry
2. Accept block coordinates
3. Resolve block id
4. Query `liteServer.getBlockHeader`
5. Normalize header fields to tos-http-api shape

### ✅ B5. Add `getBlockTransactions`

Priority:

- P0

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Add dispatcher entry
2. Accept:
   - `workchain`
   - `shard`
   - `seqno`
   - optional `root_hash`
   - optional `file_hash`
   - optional `after_lt`
   - optional `after_hash`
   - `count`
3. Query `liteServer.getBlockTransactions`
4. Normalize transaction list shape

### ✅ B6. Add `getTransactions`

Priority:

- P0

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Add dispatcher entry
2. Accept:
   - `address`
   - `limit`
   - `lt`
   - `hash`
   - `to_lt`
   - optional `archival`
3. Reuse account transaction pagination logic already present elsewhere in the codebase where possible
4. Normalize result to tos-http-api-compatible transaction list

Risk note:

- this is the largest P0 read API because history walking and archival semantics matter
- it also depends on an explicit archival-routing policy, which should not remain implicit

Recommended patch split:

- Patch B6.1: latest-path transaction fetch
- Patch B6.2: range/pagination support
- Patch B6.3: archival routing if needed

## Patch Group C: Add Convenience Read APIs

### ✅ C1. Add `getAddressBalance`

Priority:

- P1

Implementation:

- thin wrapper over the finalized `getAddressInformation`

### ✅ C2. Add `getAddressState`

Priority:

- P1

Implementation:

- thin wrapper over the finalized `getAddressInformation`

### ✅ C3. Add `packAddress`

Priority:

- P1

Implementation:

- parse raw address and return user-friendly form

### ✅ C4. Add `unpackAddress`

Priority:

- P1

Implementation:

- parse user-friendly form and return raw form

### ✅ C5. Add `detectAddress`

Priority:

- P1

Implementation:

- return all supported TOS address forms

## Patch Group D: Add Send and Fee APIs

### ✅ D1. Add `sendBocReturnHash`

Priority:

- P1

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Add dispatcher entry
2. Reuse `sendBoc` path
3. Return external message hash

### ✅ D2. Add `sendQuery`

Priority:

- P1

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Add dispatcher entry
2. Accept:
   - `address`
   - `body`
   - `init_code`
   - `init_data`
3. Build external message from components
4. Serialize BOC
5. Reuse send helper

### ✅ D3. Add `estimateFee`

Priority:

- P1

Files:

- `validator-engine/json-rpc-server.h`
- `validator-engine/json-rpc-server.cpp`

Tasks:

1. Add dispatcher entry
2. Accept same message parts as `sendQuery`
3. Build external message candidate
4. Route through fee-estimation path
5. Return tos-http-api-compatible fee object

Risk note:

- this may require additional validator-manager or local VM plumbing not yet exposed through the current JSON-RPC server

### ✅ D4. Decide on compatibility-only deprecated send APIs

Priority:

- P2

Methods from `tos-http-api` not covered in the original document:

- `sendBocUnsafe`
- `sendCellSimple`
- `sendQuerySimple`
- `estimateFeeSimple`

Tasks:

1. Decide which of these should be implemented
2. Prefer documenting them as compatibility-only or explicitly unsupported
3. Avoid letting deprecated legacy-era helper methods pollute the clean embedded API unless required by existing clients

Recommended policy:

- do not include them in the first production milestone
- only add them if a concrete client dependency exists

## Patch Group E: Advanced APIs

These are useful, but should not block the first production-quality embedded JSON-RPC release.

### ✅ E1. `getBlockTransactionsExt`

- richer transaction representation

### ✅ E2. `getLibraries`

- contract/library introspection support

### ✅ E3. `getTokenData`

- token/NFT convenience parsing

### ✅ E4. `tryLocateTx`
- transaction lookup by message relationship

### ✅ E5. `tryLocateResultTx`
- same family as above

### ✅ E6. `tryLocateSourceTx`
- same family as above

### ✅ E7. `getMasterchainBlockSignatures`

- proof/signature surface

### ✅ E8. `getShardBlockProof`

- proof surface

### ✅ E9. `getConsensusBlock`

- consensus surface

### ✅ E10. Decide on `getBlockTransactionsExt` priority

Priority:

- P1.5 or P2 depending on explorer needs

Why this needs explicit mention:

- it is already present in `tos-http-api`
- some explorer integrations prefer the richer transaction representation over `getBlockTransactions`

Recommended policy:

- if an internal or external explorer depends on it, move it forward ahead of token/proof APIs

## Patch Group F: JSON-RPC Protocol Features

These items were not explicit in the original document but matter for compatibility.

### ✅ F1. Decide on batch JSON-RPC support

Priority:

- P2

Tasks:

1. Decide whether JSON-RPC batch requests will be rejected explicitly or supported
2. If rejected, return a clear error
3. Document the behavior

Why:

- JSON-RPC clients sometimes assume batch support
- even a deliberate rejection policy is better than accidental undefined behavior

### ✅ F2. Tighten request-id handling

Priority:

- P1

Tasks:

1. Preserve string and numeric ids
2. Decide how `null` or missing ids are handled
3. Ensure responses mirror the incoming id consistently

Why:

- current implementation is simple, but compatibility-sensitive clients can rely on exact id behavior

### ✅ F3. Decide on parameter mode support

Priority:

- P1

Tasks:

1. Decide whether only object-style `params` are supported
2. Or whether positional-array `params` should also be accepted
3. Document and enforce the choice

Why:

- JSON-RPC allows both object and array params
- current server accepts only object params

Recommended policy:

- keep object params only unless a real client requires array params

### ✅ F4. Decide on response-wrapper compatibility level

Priority:

- P1

Tasks:

1. Decide whether the embedded server keeps the current custom envelope:
   - `ok`
   - `jsonrpc`
   - `id`
   - `result|error|code`
2. Compare this to what existing TOS clients expect
3. Document whether exact `tos-http-api` JSON envelope parity is required or approximate compatibility is sufficient

Why:

- method parity alone is insufficient if envelope behavior diverges
- this is one of the highest-risk compatibility points for SDKs and tooling

### ✅ F5. Decide on notification behavior

Priority:

- P1

Tasks:

1. Decide how requests without `id` are treated
2. Decide whether JSON-RPC notifications are supported, rejected, or answered anyway
3. Document whether the embedded server follows strict JSON-RPC notification semantics or a compatibility-oriented relaxed model

Why:

- JSON-RPC clients sometimes send notification-style requests
- request-id handling is not complete without a policy for missing `id`

## Patch Group G: Explicit Non-Goals and Deferred Compatibility

These items should be recorded explicitly so they do not remain ambiguous.

### ✅ G1. OpenAPI / Swagger parity

Priority:

- explicit non-goal for initial embedded rollout

Decision to document:

- whether no documentation endpoint is provided
- or whether it is deferred to a later milestone

### ✅ G2. Redis/external cache parity

Priority:

- explicit non-goal for initial embedded rollout

Decision to document:

- embedded server does not attempt to replicate `tos-http-api` cache architecture initially

### ✅ G3. Worker-state parity

Priority:

- deferred or unsupported unless a concrete operator need appears

Decision to document:

- `getWorkerState` is not required for method-surface parity and may remain unsupported

## Dispatcher Patch Checklist

For every new API method:

1. add handler declaration in `json-rpc-server.h`
2. add dispatch branch in `dispatch_method`
3. implement handler in `json-rpc-server.cpp`
4. add parameter validation
5. add success response normalization
6. add error mapping for:
   - invalid params
   - liteserver query failure
   - TL parse failure
   - proof/state extraction failure

For every protocol-surface patch:

1. decide endpoint path behavior
2. decide HTTP method behavior
3. decide CORS and preflight behavior
4. decide compatibility vs explicit rejection for unsupported shapes

## Recommended Delivery Order

### ✅ Milestone 1: Existing Methods Become Correct

- A1 `getAddressInformation` — exists, response-shape audit pending
- A4 `runGetMethod` — exists, response-shape audit pending
- A5 `getConfigParam` — exists, response-shape audit pending
- A3 `getWalletInformation` — exists, includes wallet detection and seqno
- A2 `getExtendedAddressInformation` — exists, response-shape audit pending
- ✅ B0.1 canonical `/jsonRPC` routing
- ✅ B0.2 `/healthcheck`

### ✅ Milestone 2: Core Block/Account Read Surface

- ✅ B1 `getMasterchainInfo`
- ✅ B2 `lookupBlock`
- ✅ B3 `shards`
- ✅ B4 `getBlockHeader`
- ✅ B5 `getBlockTransactions`
- ✅ B6 `getTransactions`

### ✅ Milestone 3: Convenience and SDK Helpers

- ✅ C1 `getAddressBalance`
- ✅ C2 `getAddressState`
- ✅ C3 `packAddress`
- ✅ C4 `unpackAddress`
- ✅ C5 `detectAddress`
- ✅ F2 request-id behavior — numeric IDs preserved as numbers
- ✅ F3 parameter mode policy — object params only, documented
- F4 response-wrapper compatibility level — audit pending

### ✅ Milestone 4: Send and Fee Surface

- ✅ D1 `sendBocReturnHash`
- ✅ D2 `sendQuery`
- ❌ D3 `estimateFee` — deferred, requires local TVM emulator
- ✅ B0.4 `OPTIONS` and CORS — full preflight support with configurable origin
- B0.5 REST endpoint compatibility decision — deferred, JSON-RPC only for now
- B0.6 timeout and overload behavior — not yet implemented
- ✅ R5 runtime policy and feature-gating — `--json-rpc-readonly`, `--json-rpc-cors-origin`, `--json-rpc-readyz-threshold`
- R6 liteserver selection and archival-routing policy — not yet documented
- R8 caching and non-goals policy — not yet documented

### ✅ Milestone 5: Advanced/Explorer APIs

- ✅ E1 `getBlockTransactionsExt`
- E2–E9 as needed — not yet implemented
- D4 deprecated compatibility send APIs — not yet decided
- ✅ F1 batch JSON-RPC support decision — explicitly rejected with clear error
- F5 notification behavior — not yet decided
- B0.7 API root-prefix decision — not yet decided
- R7 documentation-surface policy — not yet documented
- G1-G3 explicit non-goals and deferred compatibility — not yet documented
- R9 REST transport-shape policy — not yet documented
- R10 parameter-default and validation parity policy — partially implemented (defaults match)
- R11 input-normalization and encoding policy — partially implemented (address parsing accepts both forms)
- R12 public method-name stability policy — not yet documented
- ✅ R13 security and exposure policy — `--json-rpc-readonly` implemented; documentation pending
- R14 API versioning and deprecation policy — not yet documented

## Testing Guidance

Every milestone should include:

- positive-path JSON-RPC requests
- invalid-params coverage
- parity checks against `tos-http-api` for the same node state when possible
- explicit checks for response shape compatibility

Minimum parity tests for Milestone 1 and 2:

- same address through `getAddressInformation`
- same wallet through `getWalletInformation`
- same `runGetMethod`
- same `getConfigParam`
- same `getMasterchainInfo`
- same `lookupBlock`
- same `getBlockHeader`

Additional protocol-surface tests that were missing from the original document:

- `POST /jsonRPC` on canonical path
- unsupported path rejection behavior
- `/healthcheck`
- CORS headers on success and error responses
- request id echo behavior for string and numeric ids

## Summary

The immediate priority is not to add every `tos-http-api` method. The immediate priority is:

1. make the existing embedded methods actually compatible
2. add the missing core read APIs that explorers, `tosctl`, and SDKs need
3. add send and fee APIs so operator tooling no longer depends on an external HTTP bridge

This plan keeps the work incremental and reviewable while moving `validator-engine` toward a production-quality embedded JSON-RPC surface.

## Implementation Progress (2026-04-13)

**mytonctrl parity is substantially started but not fully complete.** All 87 public commands have tosctl subcommand registrations (89 total with 2 TOS additions), but not all are fully functional: 78 full + 5 partial + 6 guided + install wizard not implemented. The embedded JSON-RPC surface has 21 methods and 3 HTTP endpoints.

### What is done

**`~/tos` (node-side):**
- ✅ 21 JSON-RPC methods + 3 HTTP endpoints (`/healthcheck`, `/readyz`, `/jsonRPC`)
- ✅ Runtime feature-gating: `--json-rpc-readonly`, `--json-rpc-cors-origin`, `--json-rpc-readyz-threshold`
- ✅ JSON-RPC 2.0 compliance: request-id type preservation, batch rejection
- ✅ 3 staking pool contract suites TOS-adapted and FunC-compiled

**`~/tos/tosctl` (CLI-side):**
- 89 CLI subcommands registered across 9 command groups
- 78 ✅ Full (end-to-end working), 5 ⚠️ Partial (do some work but key parts missing), 6 📋 Guided (print instructions only)
- ✅ 3 contract wrappers: SingleNominator + NominatorPool + LiquidController
- ✅ Control-client: 13+ TL methods (collator, whitelist, config, stats, overlay, quic)
- ✅ Alert system: config schema + 5 commands (Telegram + webhook)
- ✅ 47 contract unit tests passing

### What remains

**`~/tos` (node-side):**

### What remains

> **See [next-steps.md](next-steps.md) for the unified priority list across both repos.**
>
> Key items for this repo (`~/tos`):
> - P0: Staking contract on-chain verification (#1), JSON-RPC request timeout (#3)
> - P1: Response-shape parity audit (#6)
> - P2: estimateFee (#8), REST endpoints (#11), policy docs (#13), advanced APIs (#14)

### `tosctl` command implementation summary (audited 2026-04-13)

| Group | Commands | Status |
|---|---|---|
| `wallet` | create, import, rm, activate, ls, send, export, set-version | ✅ All 8 Full |
| `pool` basic | ls, get, import, rm | ✅ All 4 Full |
| `pool single` | create, activate, withdraw | ✅ All 3 Full |
| `pool nominator` | create, activate, update-validator-set, deposit, withdraw | 3 ✅ Full (update-validator-set, deposit, withdraw), 1 ⚠️ Partial (create — saves config only, no deployment), 1 📋 Guided (activate — prints BOC deployment guidance) |
| `pool liquid` | controller create/update/ls/get/add/deposit/withdraw/update-validator-set + stop/stop-withdraw/apr/test-loan/check | 6 ✅ Full (deposit, withdraw, update-validator-set, stop, apr, test-loan), 1 ✅ Full (check), 1 ⚠️ Partial (controller create — saves config placeholders only), remainder TBD |
| `host` | about, status, mode status/enable/disable, settings show/get/set, update, upgrade, archive download, benchmark | 7 ✅ Full (about, status, mode status, settings show/get/set, benchmark), 2 ⚠️ Partial (mode enable/disable — VALIDATOR works, LITESERVER/COLLATOR prints guidance only), 3 📋 Guided (update — manual steps, upgrade — manual steps, archive download — prints wget commands) |
| `backup` | create, restore, verify | ✅ All 3 Full |
| `node` | status, ping, probe, collator add/rm/reset/ls/setup/stop/local, collator-config set/refresh/show, collation-whitelist add/rm/disable/ls, overlay add/ls/rm, net quic set | ✅ All 20 Full |
| `vote` | offer ls/diff/cast, election ls/cast, complaint ls/cast | 4 ✅ Full (offer ls, offer diff, election ls, complaint ls), 1 ⚠️ Partial (election cast — dry-run query only, no actual bid submission), 2 📋 Guided (offer cast — lists proposals/explains flow/defers, complaint cast — queries elections/explains flow/defers) |
| `account` | status, txs, bookmark add/ls/rm | ✅ All 5 Full |
| `observe` | validators, efficiency, alert setup/enable/disable/ls/test, metrics show/push | ✅ All 9 Full |
| `admin` | btc-teleport rm | Status TBD |
| `install` | wizard | ❌ Not implemented |
| **Total** | **89 registered** | **78 ✅ Full + 5 ⚠️ Partial + 6 📋 Guided** |
