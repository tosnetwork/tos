# wc=3 DoS Hardening: Surface Inventory

> **Audience**: security auditors, validator operators, and core
> contributors making changes to the wc=3 RPC or compute path.
> Last updated: Phase U landing.

This document is the canonical inventory of the wc=3 attack surface
and the limits that protect each layer.  Every cap below carries
the source file + line where it is enforced AND the test that pins
it.  A change anywhere in this surface that removes a cap, raises
it materially, or skips a test should require explicit review.

The wc=3 attack surface decomposes into four layers, listed
inside-to-outside:

  1. **Compute path** — per-call resource caps inside the JVM /
     dispatch engine (gas, heap, storage cells, action count).
  2. **State path** — per-account on-chain artifact caps (JVAC
     fields, class bytes, manifest entries).
  3. **RPC path** — per-call public-API limits on the validator's
     JSON-RPC server (params size, response size, scan depth).
  4. **Transport path** — per-connection HTTP-level limits on
     request body size and concurrent requests.

For each layer the convention below is:

  | Cap | Value | File | Test |

---

## 1. Compute path

### 1.1 Gas per transaction

| Cap | Value | File | Test |
|---|---|---|---|
| `max_gas_per_tx` | 1 000 000 (default; ConfigParam-85 settable) | `jvm/core/config-param.cpp:283` | `RpcCallContractCapsToMaxGasBeforeFloor` |

Caps the per-call gas budget BEFORE the compute_phase starts.
A call that requests more is rejected pre-runtime; a call that
runs out is committed up to the budget then `sk_out_of_gas`.

### 1.2 Heap per call

| Cap | Value | File | Test |
|---|---|---|---|
| `max_heap_bytes` | 4 194 304 (4 MiB; ConfigParam-85 settable) | `jvm/core/config-param.cpp:282` | `JvmRuntimeRejectsOverHeapLimit` |

Per-call JVM heap allocation budget.  Enforced by the Avata
interpreter; out-of-heap surfaces as `JvmAvataInvocationResult::
out_of_memory = true`.

### 1.3 Storage cells per call

| Cap | Value | File | Test |
|---|---|---|---|
| `max_storage_cells` | 65 536 (ConfigParam-85 settable) | `jvm/core/config-param.cpp` | `RpcCallContractDetectsMaxStorageCellsAfterWalkBypass`, `RpcCallContractMirrorsConsensusWalkGasCap` |

Caps the number of cells touched in the per-account storage dict.
Critical for `jvm_callContract` simulation: an attacker who deploys
a contract with a deep storage tree could otherwise force a single
local-simulation call to walk millions of cells.

### 1.4 Outbound actions per call

| Cap | Value | File | Test |
|---|---|---|---|
| `kJvmOutboundActionCountMax` | 12 (combined send + create_account) | `jvm/core/message-host.h:74` | `MessageHostEnforcesCombinedOutboundActionCountCap` |

Per-tx outbound action queue depth.  Caps both `System.sendMessage`
and `System.createAccount` emissions in a single transaction.
Prevents an unbounded fanout where one inbound call would have to
process N outbound messages in the action phase.

### 1.5 Helper-gas table

| Cap | Value | File | Test |
|---|---|---|---|
| Per-call gas accounting | 23-entry table | `jvm/core/config-param.cpp` (default_activation) | `CryptoConformance*`, helper-specific tests |

Every JNI host helper (`Crypto.keccak256`, `System.sendMessage`,
`Context.contractAddress`, etc.) charges from this table.  Sets
the floor cost so unlimited helper invocations don't run for free.

---

## 2. State path

### 2.1 Class bytes size

| Cap | Value | File | Test |
|---|---|---|---|
| `max_class_bytes` | 65 536 (64 KiB; ConfigParam-85 settable) | `jvm/core/config-param.cpp:281` | `RpcDeployContractAdmissionChecksClassSize`, `RpcCallContractRejectsAccountStateExceedingMaxClassBytes` |

The compiled `.class` bytecode embedded in every JVAC.  Capped at
64 KiB by default; ConfigParam 85 lets governance raise it.
Enforced at deploy admission AND at every per-call account-state
load (so a contract with oversized class_bytes can't be loaded
even if it somehow got onto the chain).

### 2.2 Storage value size

| Cap | Value | File | Test |
|---|---|---|---|
| `kJvmStorageValueMaxBytes` | 1 048 576 (1 MiB) | `jvm/core/storage-cell-host.h:29` | `StorageCellHostRoundTripAndTransactions` |

Per-value cap on the chunked storage_value encoding.  Each
account-state slot value, every class_bytes blob, every storage-
dict entry inherits this cap.  1 MiB chosen so a single huge value
can't dominate per-block walk costs while still admitting realistic
ABI-encoded payloads.

### 2.3 Manifest entries

| Cap | Value | File | Test |
|---|---|---|---|
| `JVM_METHOD_MANIFEST_MAX_ENTRIES` | 1024 | `jvm/core/class-manifest.h` (mirrored in Rust `manifest.rs`) | `MethodManifestRoundTripsAndRejectsDuplicates` |

Per-account method manifest size cap.  Mirrors the Rust port to
prevent a malicious deploy that ships a manifest with millions of
entries (would otherwise inflate the on-chain account state and
every address-derivation hash).

### 2.4 JVAC cell depth

| Cap | Value | File | Test |
|---|---|---|---|
| `vm::CellTraits::max_depth` | (TVM-inherited) | `vm/cells/CellTraits.h` | `JvmContractAccountStateEncoderRejectsExcessiveDepth` |

Standard TVM cell depth limit.  Round-119/120 fixes wrap every
JVAC / state_init / event payload encoder in try/catch around
`CellBuilder::finalize` so a near-max-depth user input doesn't
propagate `CellWriteError` out of consensus / RPC handlers.

---

## 3. RPC path

### 3.1 Receipt scanning

| Cap | Value | File | Test |
|---|---|---|---|
| `kJvmReceiptPageSize` | 64 | `validator-engine/json-rpc-server-jvm.cpp:43` | (manual RPC conformance) |
| `kJvmReceiptMaxScannedTransactions` | 4096 | `validator-engine/json-rpc-server-jvm.cpp:44` | (manual RPC conformance) |
| `kJvmReceiptMaxResults` | 1024 | `validator-engine/json-rpc-server-jvm.cpp:45` | (manual RPC conformance) |
| `kJvmReceiptResponseByteBudget` | 1 MiB | `validator-engine/json-rpc-server-jvm.cpp:54` | (manual RPC conformance) |

`jvm_getReceipts` walks transaction history backward from
`to_block`.  Three orthogonal caps: page size (per fetch), total
scanned tx count, total receipts returned, and a byte budget on
the JSON response.  Round-57 fix added the byte budget after the
per-tx and result-count caps were found to admit ~1 GiB responses
for noisy contracts.

### 3.2 Storage slot enumeration

| Cap | Value | File | Test |
|---|---|---|---|
| `kEnumerateDefaultLimit` | 100 | `jvm/core/storage-cell-host.h` | `RpcGetContractStateFetchesPerAccount` |
| `kSlotsResponseByteBudget` | 1 MiB | `jvm/core/rpc.cpp:1468` | `RpcGetContractStateBoundsResponseByteBudget` (Round 54/55) |

`jvm_getContractState` returns up to 100 storage slots; the
byte-budget cap (Round 54/55) prevents a contract with 1 MiB
values from forcing ~200 MiB of hex-encoded response.

### 3.3 Class-bytes hex decode

| Cap | Value | File | Test |
|---|---|---|---|
| `max_class_bytes` (post-decode) | 64 KiB | `jvm/core/rpc.cpp:614` | `RpcDeployContractAdmissionChecksClassSize` |

`jvm_deployContract` accepts `classBytes` as a hex string.  The
hex decode allocates 1 byte per 2 hex chars.  The cap is enforced
on the DECODED size, so an attacker sending a 1 MiB hex string
(which decodes to ~500 KiB) still triggers the cap.  The 4 MiB
request-body cap (§4.1) is the outer guard.

### 3.4 Account-state forwarding

| Cap | Value | File | Test |
|---|---|---|---|
| `max_class_bytes` (account-state path) | 64 KiB | `jvm/core/rpc.cpp:813,906` | `RpcCallContractRejectsAccountStateExceedingMaxClassBytes` |

`jvm_callContract` / `jvm_getContractState` accept an
`accountStateBoc` parameter for local simulation against a caller-
supplied state.  The class_bytes embedded in that BOC are capped
the same way as on the deploy path.

### 3.5 Admission gas floor

| Cap | Value | File | Test |
|---|---|---|---|
| `kJvmAdmissionGasFloor` | (compile-time constant) | `jvm/core/rpc.cpp` | `RpcCallContractZeroBalanceTriggersFloorReject` |

`jvm_callContract` rejects calls whose gas budget falls below the
admission floor.  Round-37 / Round-45 fixes ensure runtime errors
still bill the admission floor so a contract that always reverts
can't be used for free probing.

---

## 4. Transport path

### 4.1 Request body size

| Cap | Value | File | Test |
|---|---|---|---|
| `kJsonRpcMaxRequestBodyBytes` | 4 MiB (4 << 20) | `validator-engine/json-rpc-server.cpp:54` | manual conformance (`test/conformance/manual-rpc/http_large_request_body.io`) |

Hard cap on the HTTP POST body size for every JSON-RPC method.
Prevents an attacker from spamming `jvm_deployContract` with a 1
GiB params blob.  Enforced at the transport adapter, BEFORE JSON
parsing.

### 4.2 Concurrent requests

| Cap | Value | File | Test |
|---|---|---|---|
| (TBD) | (defer to deployment) | — | — |

The JSON-RPC server itself doesn't cap per-connection or per-IP
concurrent requests; this is expected to be enforced at the
deployment-layer reverse proxy (nginx / haproxy / cloudflare).
Each validator operator is responsible for choosing a sensible
rate limit for their public-facing endpoint.

---

## 5. Known un-covered surfaces

These surfaces don't have an explicit cap and are documented here
for future hardening passes:

* **JSON parse depth** — the validator's JSON parser is hand-
  rolled (`jvm/core/rpc.cpp::strip_top_level_field` et al.) and
  doesn't recurse on nested arrays/objects; the entire surface is
  string-scan-based.  No stack-overflow exposure.

* **Concurrent request count per IP** — see §4.2.  Out of scope
  for the in-process validator-engine; defer to the deployment-
  layer reverse proxy.

* **Event topic count per emission** — `JvmEvent::topics` is a
  `std::vector` with no compile-time bound.  In practice the
  Avata helper-gas table charges per-topic so an attacker emitting
  10 000 topics in one event runs out of gas; still, a future
  hardening pass could add an explicit cap (e.g. 32 topics per
  event, matching EVM convention).

---

## 6. Audit checklist

When changing wc=3 code that touches any of the above:

- [ ] Has the cap value changed?  If yes, justify in the commit
      message + update this doc's table cell.
- [ ] Has the file/line citation moved?  If yes, update the table.
- [ ] Does the test that pins the cap still cover the changed
      path?  Run `./test-workchain-execution-registry` after the
      change.
- [ ] If the change removes a cap, is there a layered cap upstream
      that still bounds the resource?  (E.g. removing
      `max_class_bytes` from §2.1 is OK iff §4.1's request-body
      cap covers it; this would require explicit reasoning.)
- [ ] If the change adds a new resource consumer (a new RPC
      method, a new host helper, a new state field), add the
      corresponding cap to this doc + a test that pins it.

---

## 7. References

| File                                                    | Role                                  |
|---------------------------------------------------------|---------------------------------------|
| `jvm/core/rpc.cpp`                                      | Core RPC handlers (validator + tests) |
| `validator-engine/json-rpc-server-jvm.cpp`             | Full-node JSON-RPC dispatch + scans   |
| `validator-engine/json-rpc-server.cpp`                 | Transport-layer body/timeout caps     |
| `jvm/core/config-param.cpp`                             | ConfigParam 85 defaults + decoder     |
| `jvm/core/message-host.{h,cpp}`                         | Outbound action queue caps            |
| `jvm/core/storage-cell-host.h`                          | Per-value storage limits              |
| `crypto/test/test-workchain-execution-registry.cpp`    | Cap tests (114 + counting)            |
| `doc/jvm/jvm-validator-ops.md`                              | Operator runbook (cross-references this doc) |
