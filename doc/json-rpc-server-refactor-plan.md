# JSON-RPC Server Refactor Plan

Version: v1.0

## Purpose

This document proposes a refactor plan for the embedded `validator-engine` JSON-RPC server.

The goal is to reduce the maintenance cost of the current implementation without changing the architectural decision to keep JSON-RPC embedded inside `validator-engine`.

This is not a proposal to turn the embedded server into a separate daemon.
It is a proposal to split responsibilities inside the current implementation.

## Problem Statement

The current embedded JSON-RPC implementation is concentrated mainly in:

- `validator-engine/json-rpc-server.cpp`
- `validator-engine/json-rpc-server.h`

This has become difficult to maintain because one implementation unit now contains several different concerns at once:

- HTTP request handling
- JSON-RPC protocol parsing and validation
- REST-style path dispatch
- backend query dispatch
- domain-specific API handlers
- output formatting and normalization helpers
- request parameter parsing helpers

As the method surface grows, this concentration increases:

- review cost
- merge-conflict frequency
- regression risk
- difficulty of parallel work
- difficulty of isolating domain-specific behavior

## Reference Observation

The local reference project at `~/tos-http-api-cpp` uses clear internal separation between:

- protocol entry
- domain handlers
- backend worker logic
- converters and result normalization

TOS should not copy that project mechanically, because TOS is embedding JSON-RPC inside `validator-engine` rather than running a separate HTTP service.

However, the separation principle is still valid:

> protocol entry, domain logic, backend access, and conversion logic should not all live in one implementation file.

## Refactor Goal

The target design should preserve:

- one central `JsonRpcServer` class
- one embedded service boundary inside `validator-engine`
- one dispatcher for public method names

But it should split implementation by domain so that the JSON-RPC server becomes easier to extend and safer to review.

## Design Principles

1. Keep one central `JsonRpcServer` type
2. Keep HTTP and JSON-RPC entry logic centralized
3. Split handler implementations by functional domain
4. Move reusable parsing and formatting logic out of large handler files
5. Avoid excessive class proliferation
6. Do not create one class per API method
7. Preserve existing public API names and embedded deployment model

## Proposed File Structure

The recommended target structure under `validator-engine/` is:

- ✅ `json-rpc-server.h`
- ✅ `json-rpc-server.cpp`
- ✅ `json-rpc-server-internal.h`
- ✅ `json-rpc-server-accounts.cpp`
- ✅ `json-rpc-server-blocks.cpp`
- ✅ `json-rpc-server-transactions.cpp`
- ✅ `json-rpc-server-runmethod.cpp`
- ✅ `json-rpc-server-send.cpp`
- ✅ `json-rpc-server-config.cpp`
- ✅ `json-rpc-server-utils.cpp`
- ✅ `json-rpc-server-shared.cpp`

This is a domain split, not a class-per-method split.

> **Status: ALL FILES IMPLEMENTED** (completed 2026-04-14)

## Responsibility Split

### ✅ `json-rpc-server.cpp` (885 lines)

Retains the central entry and dispatch responsibilities:

- ✅ HTTP request entry
- ✅ `/healthcheck` and `/readyz`
- ✅ REST-style GET path mapping for supported query-parameter read methods
- ✅ REST-style POST path mapping (35 methods)
- ✅ JSON-RPC envelope parsing on canonical `/jsonRPC`
- ✅ `dispatch_method(...)` / `cached_dispatch_method(...)`
- ✅ Top-level method routing
- ✅ JSON success/error envelope helpers with HTTP status code mapping
- ✅ API key authentication (`--json-rpc-api-key`)
- ✅ Response cache with configurable TTL (`--json-rpc-cache-ttl`)
- ✅ CORS preflight (`OPTIONS`)
- ✅ QueryTimeoutGuard (30s default, `--json-rpc-request-timeout`)

### ✅ `json-rpc-server-accounts.cpp` (1175 lines)

- ✅ `getAddressInformation` (seqno, last_tx_id, sync_utime, extra_currencies)
- ✅ `getExtendedAddressInformation` (code-hash wallet type detection)
- ✅ `getWalletInformation` (wallet_type, seqno, wallet_id, is_signature_allowed)
- ✅ `getAddressBalance`
- ✅ `getAddressState`
- ✅ `getTokenData` (Jetton master/wallet, NFT collection/item, DNS)

### ✅ `json-rpc-server-blocks.cpp` (686 lines)

- ✅ `getMasterchainInfo`
- ✅ `getConsensusBlock`
- ✅ `lookupBlock`
- ✅ `shards` / `getShards`
- ✅ `getBlockHeader`
- ✅ `getMasterchainBlockSignatures`
- ✅ `getShardBlockProof`
- ✅ `getOutMsgQueueSize`

### ✅ `json-rpc-server-transactions.cpp` (1340 lines)

- ✅ `getBlockTransactions`
- ✅ `getBlockTransactionsExt`
- ✅ `getTransactions` (lt/hash optional with auto-lookup, pair validation)
- ✅ `getTransactionsStd` (raw.transactions object format)
- ✅ `tryLocateTx`
- ✅ `tryLocateResultTx`
- ✅ `tryLocateSourceTx`

### ✅ `json-rpc-server-runmethod.cpp` (512 lines)

- ✅ `runGetMethod` (POST-only; stack input/output, seqno, @type)
- ✅ `runGetMethodStd` (POST-only)

### ✅ `json-rpc-server-send.cpp` (699 lines)

- ✅ `sendBoc`
- ✅ `sendBocReturnHash`
- ✅ `sendBocReturnHashNoError`
- ✅ `sendQuery`
- ✅ `estimateFee` (local TVM emulation)

### ✅ `json-rpc-server-config.cpp` (457 lines)

- ✅ `getConfigParam` (seqno support)
- ✅ `getConfigAll` (seqno support, config_params map)
- ✅ `getLibraries`

### ✅ `json-rpc-server-utils.cpp`

- ✅ `packAddress`
- ✅ `unpackAddress`
- ✅ `detectAddress`
- ✅ `detectHash`

### ✅ `json-rpc-server-shared.cpp` (45 lines)

- ✅ `parse_address_param()` — common address parsing
- ✅ `format_block_id_json()` — block ID JSON builder
- ✅ `format_zero_state_json()` — zero state JSON builder

### ✅ `json-rpc-server-internal.h` (75 lines)

- ✅ `ParsedAccountState` struct — shared account state parsing
- ✅ Minimal shared declarations — each .cpp adds its own deps

## Header Strategy

`json-rpc-server.h` should remain relatively small.

It should contain:

- the `JsonRpcServer` class declaration
- the public actor-facing methods
- the private `handle_*` member declarations
- only the shared declarations that must be visible across translation units

It should not become a dumping ground for large helper implementations or large inline utility blocks.

Where possible:

- keep helper definitions in `.cpp`
- expose only minimal helper declarations in a dedicated helper header

## Why This Split Is Appropriate

This structure fits TOS better than copying the reference project directly.

Reasons:

- TOS still keeps one embedded JSON-RPC server
- the actor and backend model remains centered in `validator-engine`
- public method dispatch stays unified
- implementation complexity is isolated by domain without introducing unnecessary framework weight

This produces most of the maintainability benefits of a layered handler architecture without turning the embedded server into an over-engineered micro-framework.

## What Not To Do

### Do Not Keep Everything in One `.cpp`

The current concentration is already too large for safe long-term growth.

### Do Not Create One File Per Method

That would create too many tiny files, too much declaration overhead, and too much friction for related changes.

### Do Not Introduce One Class Per Endpoint

The embedded server does not need the same class-per-handler structure as a separate HTTP framework.

### Do Not Duplicate Shared Backend Logic

Common backend helpers should remain centralized rather than copied across domain files.

## Suggested Refactor Order

To reduce risk, the refactor should proceed in stages:

1. ✅ `utils`
2. ✅ `config`
3. ✅ `accounts`
4. ✅ `blocks`
5. ✅ `transactions`
6. ✅ `runmethod`
7. ✅ `send`
8. ✅ `shared` (extracted as `json-rpc-server-shared.cpp` + `json-rpc-server-internal.h`)

> **ALL STAGES COMPLETED** (2026-04-14)

## Phase 1 Target

The first refactor phase should not aim for perfection.
It should aim for a healthier maintenance shape.

A reasonable first target is:

- ✅ `json-rpc-server.cpp` reduced to entry, routing, and shared-envelope logic (885 lines)
- ✅ domain files each containing one coherent handler family (10 files)
- ✅ no behavioral change to public APIs
- ✅ successful build and regression validation (478 tests passing)

## Review and Testing Guidance

Each extraction step should be small enough to review independently.

Validation should include:

- successful compilation
- smoke testing of affected JSON-RPC methods
- regression checks for error envelopes
- verification that method names and semantics remain unchanged

The refactor should be treated as structural maintenance, not as an opportunity to change API semantics opportunistically.

## Expected Benefits

If implemented well, this refactor should produce:

- smaller review units
- lower merge-conflict frequency
- easier domain ownership
- clearer standards work by API family
- safer addition of new JSON-RPC methods
- easier future testing and migration work

## Final Rule

The embedded JSON-RPC server should remain one coherent service boundary.

But its implementation should no longer behave as if every concern belongs in one source file.
