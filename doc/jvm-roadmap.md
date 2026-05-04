# JVM Workchain Roadmap

Status: design — not started
Date: 2026-05-04

This document describes the plan to add a third non-TVM workchain to TOS: a JVM
execution domain (`wc=3`). It covers engine selection rationale, design
constraints, per-phase work breakdown, and estimated effort. It does not
constitute an implemented spec; each phase must be preceded by a detailed design
review before code is written.

All workchain integration rules defined in
`doc/workchain-execution-registry.md` apply to this workchain without exception.
In particular: `transaction.cpp` must not gain a new hardcoded branch for `wc=3`;
the JVM engine must register through `WorkchainExecutionRegistry` using its
`(format, selector)` key; and consensus compute must be a deterministic pure
function of chain state, message data, and block context.

## Motivation

EVM (`wc=1`) and Uno (`wc=2`) cover the two dominant smart-contract paradigms
currently targeted by TOS: EVM-compatible DeFi and privacy-preserving payments.
A JVM workchain would add a third paradigm: general-purpose contract logic in a
strongly-typed, garbage-collected language with a mature toolchain, without
requiring developers to learn a novel language.

The target audience is Java/Kotlin/Scala developers who want to deploy business
logic that is too complex for Solidity but does not require ZK primitives. The
workchain is not a general-purpose JVM for arbitrary Java programs. It is a
restricted, deterministic subset of Java 8 class-file execution suitable for
on-chain state transition functions.

## Engine Selection: Avian

The C++ JVM landscape has very few embeddable candidates. A survey as of May
2026 found no actively-maintained C++ JVM designed for embedding. The relevant
options are:

| Project | Language | Embeddable | Java 8 | Last active |
|---|---|---|---|---|
| Avian (ReadyTalk) | C++ | Yes, by design | Partial (no invokedynamic) | 2019 |
| KiVM | C++ | No (CLI only) | Yes | 2022 |
| JamVM | C | Partial | Yes (needs OpenJDK classpath) | 2015 |
| JLLVM | C++ | No | Yes | 2025 (LLVM JIT only) |
| JDK Zero | C++ | No (requires full OpenJDK) | Yes | Active |

**Avian is the starting point.** It is the only option explicitly designed for
embedding as a library. Its maintenance status (inactive since 2019) is a concern
for a general-purpose JVM but not for this use case: Java 8 class-file bytecodes
are specified by the JVM Specification (JVMS, a stable JCP-governed document)
and have not changed for the bytecode set targeted here. The set of bytecodes
this workchain must execute does not evolve with OpenJDK releases.

Avian will be **forked** and owned by this repository. The fork is not a tracking
clone; it is a permanent maintenance commitment to the stripped subset of Avian
needed for consensus execution. No attempt will be made to track upstream Avian
or upstream OpenJDK class library changes. The fork will be maintained to the
same standard as `evm/` and `uno/`.

The fork lives at `jvm/vendor/avian/` with a pinned commit hash recorded in
`jvm/vendor/avian/PINNED_COMMIT`. Any change to Avian internals must be made
inside this repository; no patch file workflow.

## Java 8 Subset

This workchain does not attempt to run arbitrary Java 8 programs. The supported
subset is:

**Supported:**
- All numeric and reference bytecodes except `invokedynamic`
- Static and virtual method dispatch (`invokestatic`, `invokevirtual`,
  `invokeinterface`, `invokespecial`)
- Generics (compiler-erased; JVM-transparent)
- Annotations (retained at runtime for contract metadata only)
- Single-dimensional and multi-dimensional arrays of primitives and references
- Object inheritance and interfaces
- Exception handling (`athrow`, `try/catch/finally`)
- `synchronized` blocks are accepted syntactically but forbidden in contract
  classes: the JVM will throw `ContractViolationError` at runtime if
  `monitorenter` / `monitorexit` is executed

**Explicitly not supported:**
- `invokedynamic` (covers all lambda expressions, method references, and
  `java.util.stream`); descriptors invoking this bytecode are rejected at class
  load time
- `java.lang.Thread` and any multi-threading API
- Any `java.io`, `java.net`, `java.nio`, or `java.sql` class
- Reflection (`java.lang.reflect`, `Class.forName`, `ClassLoader`)
- Native methods (`native` keyword); no JNI surface exposed to contract classes
- `System.currentTimeMillis()`, `Math.random()`, `UUID.randomUUID()`, or any
  other non-deterministic stdlib entry point

The contract stdlib (see Phase 3) is a purpose-built replacement for
`java.lang.*` basics: `Object`, `String` (immutable, value-type semantics),
`Math` (deterministic operations only), `System` (block context read-only API),
and a small collection of persistent data structure types.

A contract class that references any forbidden class or bytecode is rejected at
class-load time with an error that names the specific offending reference. The
rejection is deterministic and consensus-safe.

## Design Constraints

### Determinism is the primary invariant

Every validator running the same block must produce identical compute output.
This rules out:
- JIT compilation with optimizer-visible non-determinism (Avian's JIT is
  disabled in this fork; the interpreter path is used exclusively)
- Any system call that returns non-deterministic values (time, entropy, pid)
- Avian's threading primitives; the fork runs single-threaded
- GC-compacting that would reorder object addresses visible to contract code
  (the fork's GC must be configured to preserve address ordering or use a
  non-compacting collector for the contract heap region)

### State is cell-native

The JVM workchain follows the same state commitment model as EVM and Uno.
Account state enters `run_compute` as `input.current_data` (a TOS cell tree)
and exits as `output.new_data` (a TOS cell tree). The JVM heap is a transient
in-memory structure created at the start of each transaction and serialized
at the end. There is no persistent in-process heap across transactions.

This is the snapshot pattern used by EVM. It is the mandatory model for
consensus correctness: every validator reconstructs the JVM heap from the same
cell input, executes the same bytecode, and serializes the same cell output.
Any attempt to retain a live JVM heap across transactions in a global or
process-local cache would break this invariant.

### Singleton executor account

JVM v1 follows the same account execution policy as EVM v1 and Uno v1:
`SingletonExecutor(0x0000...0001)`. All messages targeting `wc=3` are routed
through the executor account. Per-contract state is stored as sub-cells of the
executor account's data cell, keyed by a contract address or class hash. This
is not the long-term account model but it is the correct v1 starting point:
it matches the existing host-side policy machinery and avoids designing a new
account topology before the serialization model is proven.

A future JVM v2 may adopt an account-native model where each Java contract is a
distinct TOS account on `wc=3`. That is a separate workchain design, not a
cleanup of v1. The v1 executor account address `0x0000...0001` and activation
code marker (`0x4a` = `'J'`) are frozen as part of the JVM v1 descriptor.

### No invokedynamic

Avian does not implement `invokedynamic`. This workchain inherits that
constraint deliberately: supporting `invokedynamic` would require a correct
implementation of `java.lang.invoke.MethodHandle` and `CallSite` chaining,
which is a significant JVM subsystem. The tradeoff is that lambda expressions
and method references in contract source code are compile errors. Developers
must use anonymous inner classes instead. This is a deliberate restriction, not
a deficiency to be patched later without a full design review.

### Activation requires a capability gate

Activating `wc=3` follows the same coordination requirements defined in
`doc/workchain-execution-registry.md §Activation and Capability Coordination`.
No validator may be assigned to `wc=3` before advertising JVM execution
capability. The JVM workchain must not be active in mainnet genesis; it is a
post-genesis governance activation.

## Engine Identity

| Field | Value |
|---|---|
| Workchain ID | `wc=3` |
| ConfigParam 12 format | `wfmt_basic` |
| `vm_version` (engine selector) | `0x4a564d31` (`"JVM1"`) |
| `vm_mode` | Reserved; `0` for JVM v1 |
| Activation code marker | `0x4a` (`'J'`) |
| Engine ConfigParam | ConfigParam 85 (JVM v1 chain parameters) |

The `(format, selector)` key `{Basic, 0x4a564d31}` identifies this engine in
the registry. As with EVM and Uno, `vm_mode = 0` is a legacy sentinel and must
be treated as an invalid production descriptor. Production descriptors are built
by `jvm_workchain::build_jvm_workchain_descr()`.

## Architecture Overview

```
Inbound message (wc=3)
        │
        ▼
WorkchainExecutionRegistry::resolve()
    └─ JvmNativeEngine::validate_and_resolve_config()
           reads ConfigParam 85 → JvmEngineConfig
        │
        ▼
JvmNativeEngine::run_compute(input, context)
    │
    ├─ Deserialize input.current_data (cell) → JvmHeap
    │      └─ JvmCellCodec::decode_heap()
    │
    ├─ Load contract class from JvmHeap.class_store
    │
    ├─ Decode input.inbound_body → JvmCallDescriptor
    │      (method name, argument encoding, value transfer)
    │
    ├─ Avian interpreter: execute entry method
    │      single-threaded, gas-metered, no JIT
    │
    ├─ Serialize post-execution JvmHeap → new_data (cell)
    │      └─ JvmCellCodec::encode_heap()
    │
    └─ Return WorkchainComputeOutput
           (committed, gas_used, new_data, action_list)
```

Side effects (event logs emitted by contracts) are staged in
`WorkchainComputeOutput::side_effects` and applied post-block-accept through
`WorkchainRuntimeServices::apply_post_accept_side_effects`. They are not
consensus state.

## Phase Breakdown and Effort Estimates

Estimates assume one senior C++ engineer with familiarity with the TOS
codebase. Phases 1–3 can begin in parallel once Phase 0 is complete. Phase 4
depends on Phase 1. Phases 5 and 6 are independent of each other and can be
done in parallel after Phase 4. Phases 7 and 8 depend on Phases 5 and 6.

---

### Phase 0 — Design decisions and constraints

**Goal:** Pin the design before any code is written. Write tests against the
registry interface that a JVM engine must pass. Document the heap serialization
format and the message ABI at the TL-B / binary level.

**Deliverables:**
- This document updated with any design changes discovered during review
- Registry integration tests for a stub JVM engine (registers, resolves,
  respects required-workchain preflight; no actual bytecode execution)
- TL-B schema for `JvmHeap` cell layout and `JvmCallDescriptor` message body

**Effort:** 1–2 weeks

---

### Phase 1 — Avian fork and determinism hardening

**Goal:** Produce a stripped, deterministic, embeddable build of Avian suitable
for consensus execution. No TOS integration yet; tested standalone.

**Work items:**

- Fork `ReadyTalk/avian` into `jvm/vendor/avian/` at a pinned commit
- Remove or disable Avian's JIT compiler (`avian/src/compile*.cpp`); force
  interpreter-only execution path (`avian/src/interpret.cpp`)
- Remove Avian's threading primitives; `monitorenter`/`monitorexit` must
  throw `ContractViolationError` at runtime
- Audit and remove or stub all `syscall` / `time` / `rand` / `getpid` paths
  in Avian's platform layer
- Validate GC behavior: determine whether Avian's semi-space collector
  produces deterministic address assignment for identical allocation sequences;
  if not, replace with a non-compacting mark-sweep for the contract heap region
- Add class-load-time rejection of `invokedynamic` instructions
- Add class-load-time rejection of references to forbidden packages
  (`java.io`, `java.net`, `java.lang.Thread`, `java.lang.reflect`, etc.)
- Wire a per-transaction gas counter into Avian's interpreter dispatch loop;
  `OutOfGasError` must be thrown deterministically when the counter reaches zero
- Build system: integrate Avian as a static library via CMake;
  `jvm/vendor/avian/CMakeLists.txt` exports a single `avian_interpreter` target

**Determinism test harness:**
Run the same bytecode twice in the same process with freshly initialized heaps
and assert byte-identical output state. Run with `valgrind --tool=memcheck` to
eliminate undefined behavior that could cause inter-validator divergence.

**Effort:** 4–8 weeks

**Key risk:** GC non-determinism. If Avian's collector cannot be made
deterministic without significant surgery, evaluate replacing it with a simpler
arena allocator that is reset per transaction. A per-transaction arena (no GC
at all) is safe if gas limits are low enough that no single transaction can
exhaust a pre-allocated arena; this simplifies determinism at the cost of
disabling long-lived in-contract allocation patterns.

---

### Phase 2 — Framework integration

**Goal:** Wire the stripped Avian build into the TOS workchain execution
registry. No real contract execution yet; the `run_compute` stub returns a
placeholder result.

**Work items:**

- `jvm/core/dispatch-engine.h` / `.cpp`:
  - `JvmEngineConfig` (parsed from ConfigParam 85)
  - `JvmNativeEngine` implementing `WorkchainEngine`
  - `engine_key()` returns `{Basic, 0x4a564d31}`
  - `validate_and_resolve_config()` reads and validates ConfigParam 85
  - `account_policy()` returns `SingletonExecutor(0x0000...0001)` with
    activation code `0x4a`
  - `run_compute()` stub: deserialize nothing, execute nothing, return
    `completed=false, skip_reason=WORKCHAIN_NOT_READY`
- `jvm/core/config-param.h` / `.cpp`:
  - `build_jvm_workchain_descr()` (ConfigParam 12 descriptor)
  - `build_jvm_config_cell()` / `parse_jvm_config_cell()` (ConfigParam 85)
  - ConfigParam 85 fields: `chain_id`, `gas_price`, `max_gas_per_tx`,
    `max_class_bytes`, `max_heap_cells`, `contract_stdlib_hash`
- `jvm/core/zerostate.h` / `.cpp`:
  - `build_jvm_zerostate_accounts_cell()`: creates singleton executor account
    with empty `JvmHeap` data cell and activation code marker `0x4a`
- `jvm/core/init.h` / `.cpp`:
  - `init_jvm_workchain(db_root)`: initializes Avian library state, reads
    ConfigParam 85, calls `register_jvm_workchain_engine(registry)`
- `validator-engine/validator-engine.cpp`:
  - One added line: `jvm_workchain::init_jvm_workchain(db_root_)`

**Effort:** 2–3 weeks

---

### Phase 3 — Contract standard library

**Goal:** Provide the minimal class library that contract classes may import.
This is not `java.lang.*` from OpenJDK. It is a purpose-built set of classes
compiled as `.class` files and bundled into the executor account's zerostate.

**Classes required:**
- `tos.jvm.lang.Object` — root class; replaces `java.lang.Object`
- `tos.jvm.lang.String` — immutable UTF-8 value type; no interning
- `tos.jvm.lang.Math` — deterministic arithmetic (no `random`, no
  `log`/`sin`/`cos` unless bit-exact IEEE 754 is proven per JLS §15.4)
- `tos.jvm.lang.System` — read-only block context: `blockNumber()`,
  `blockTimestamp()`, `randSeed()` (from `context.rand_seed`),
  `callerAddress()`, `value()`
- `tos.jvm.lang.Error`, `tos.jvm.lang.OutOfGasError`,
  `tos.jvm.lang.ContractViolationError`
- `tos.jvm.contract.ContractEntry` — annotation type; marks a `public static`
  method as callable from an inbound message (referenced by Phase 6 ABI)
- `tos.jvm.storage.PersistentMap<K,V>` — ordered key-value map backed by the
  cell tree; the primary persistent data structure for contracts
- `tos.jvm.storage.PersistentList<T>` — append-only list backed by the cell tree
- `tos.jvm.emit.EventLog` — emit a log entry staged in side effects

Classes from `java.lang.*` in OpenJDK are **not** available. Any contract class
that references `java.lang.Object` directly will fail class loading; it must
reference `tos.jvm.lang.Object`. This is enforced by the class-load-time
forbidden-package filter installed in Phase 1.

Contracts are compiled with a custom `javac` bootstrap classpath pointing only
at the `tos.jvm.*` classes. This is toolchain work outside the consensus path
and may be delivered separately from the validator binary.

**Effort:** 3–5 weeks

---

### Phase 4 — Heap serialization

**Goal:** Implement `JvmCellCodec`: bidirectional translation between a live
Avian heap and a TOS cell tree. This is the largest single engineering task in
the entire workchain.

The problem: a JVM heap is an object graph (directed, potentially cyclic if
contracts use mutable references across objects). A TOS cell tree is a DAG. The
cell codec must define a canonical serialization of the contract heap that is:
- deterministic (same heap → same cell, regardless of allocation order or GC
  compaction history)
- compact (does not serialize dead objects or class metadata that can be
  reconstructed from the bundled class store)
- replayable (cell → heap reconstructs exactly the object graph needed for
  execution, including all field values and array contents)

**Recommended approach for v1:** restrict the heap surface that is serialized.
Rather than attempting a general object-graph serializer, require that all
persistent contract state flow through `tos.jvm.storage.PersistentMap` and
`tos.jvm.storage.PersistentList`. These types are implemented as thin Java
wrappers over cell-tree operations in native C++ (similar to how Uno's state
types are thin wrappers over nullifier and commitment tree operations). The
contract heap between calls is then reduced to:
- the values of all static fields of the contract class that are of a
  `Persistent*` type (the roots of the persistent state)
- primitive static fields (int, long, boolean, etc.)
- no heap-allocated mutable objects survive across transaction boundaries

This eliminates the general object-graph serialization problem at the cost of
restricting contracts to a structured state model. It is the correct v1
tradeoff; unrestricted cross-transaction heap persistence can be addressed in
v2 with a full object-graph serializer once the execution model is proven.

**Work items:**

- `jvm/core/cell-codec.h` / `.cpp`:
  - `JvmCellCodec::encode_heap(JvmHeap&) → td::Ref<vm::Cell>`
  - `JvmCellCodec::decode_heap(td::Ref<vm::Cell>) → JvmHeap`
  - Encode: walk static fields of contract class; for `Persistent*` fields,
    flush the underlying cell-tree root; for primitive fields, pack into a
    flat cell
  - Decode: reconstruct `Persistent*` wrappers from stored cell roots; restore
    primitive static fields; re-initialize the contract class loader with the
    decoded state
- `jvm/core/persistent-map.cpp` / `persistent-list.cpp`:
  - Native C++ implementations of `tos.jvm.storage.Persistent*` that operate
    directly on `vm::Cell` trees (no intermediate Java heap objects for stored
    data)
- TL-B schema for `JvmHeap` cell (defined in Phase 0; implemented here).
  A magic tag is required, following the pattern of `UnoConfig` (`#26554E4F`):
  ```
  // magic = 0x4a564d31 ("JVM1")
  jvm_heap#4a564d31 class_store_hash:bits256
                    static_fields:(HashmapE 16 ^StaticFieldCell)
                    = JvmHeap;
  ```
  The static field map uses a 16-bit key (field index within the contract class,
  matching the `fields_count` limit in the class file format). A content-hash
  key (256-bit) would be robust to field reordering but is unnecessary for v1
  where class upgrades deploy a new class hash; the simpler index key is
  preferred. This choice must be pinned in Phase 0 and frozen thereafter.

**Effort:** 3–5 months

**Key risk:** Avian's class loader may store per-class metadata in ways that
are not easily separable from the heap. A detailed audit of
`avian/src/machine.cpp` and `avian/src/heap.cpp` is required before estimating
this phase more precisely. If Avian's class loader state is entangled with the
object heap in ways that prevent clean per-transaction reset, the fork may need
significant restructuring.

---

### Phase 5 — Gas metering

**Goal:** Map JVM bytecode execution to a gas schedule. Gas is charged
per-bytecode-instruction, per-cell-operation, and per-heap-allocation.

The gas counter installed in Phase 1 (into Avian's interpreter loop) is
extended with a full per-opcode gas table.

**Gas schedule design principles:**
- Constant-time opcodes (`iload`, `iadd`, `dup`, etc.) have a small fixed cost
- Heap allocation (`new`, `newarray`) costs proportionally to the allocated size
  in bytes, with a base overhead for GC pressure
- Cell-tree operations (reads and writes through `PersistentMap`) cost per cell
  traversal depth, matching the TOS cell gas model used by TVM
- Method dispatch (`invokevirtual`, `invokeinterface`) carries a small vtable
  lookup cost
- Exception handling (`athrow`) carries a higher base cost to discourage
  exception-driven control flow

The gas schedule is stored in ConfigParam 85 as a versioned table so it can be
adjusted by governance without a binary upgrade.

**Effort:** 3–5 weeks

---

### Phase 6 — Message ABI

**Goal:** Define and implement the binary encoding for JVM contract calls
carried in `input.inbound_body`, and the encoding for outbound messages
(calls to other contracts or TOS native contracts).

**Inbound call descriptor (`JvmCallDescriptor`):**
```
jvm_call#_  class_hash:bits256
            method_id:uint32        // first 4 bytes of keccak(method_sig)
            args:^ArgsCell
            = JvmCallDescriptor;
```

`class_hash` identifies which contract class to invoke. `method_id` selects the
public static entry method. `ArgsCell` encodes arguments using a compact binary
encoding derived from the method descriptor signature.

Only `public static` methods annotated with `@ContractEntry` are callable from
inbound messages. Other methods may only be called from within the same
transaction's execution.

**Outbound action encoding:**
Contract code may enqueue outbound messages by calling
`tos.jvm.lang.System.sendMessage(destAddr, value, body)`. This builds a
standard TOS action list cell compatible with the host action phase. The
encoding mirrors the existing TVM action list model so the host action phase
requires no changes.

**Effort:** 2–4 weeks

---

### Phase 7 — RPC namespace

**Goal:** Implement `jvm_*` JSON-RPC endpoints through
`WorkchainRuntimeServices::register_rpc`. These are non-consensus surfaces and
must not affect compute dispatch.

**Endpoints:**
- `jvm_deployContract`: submit a class file and initial state; builds an
  external message targeting the executor account
- `jvm_call`: call a view (read-only) method locally; does not submit a tx
- `jvm_getContractState`: return the decoded static fields of a deployed contract
- `jvm_getReceipts`: return event logs for a given block range

Admission (`jvm_deployContract` pre-check) validates class files against the
forbidden-bytecode and forbidden-package rules before building the external
message, as a convenience; consensus compute re-validates on execution.

**Effort:** 2–4 weeks

---

### Phase 8 — Hardening and integration testing

**Goal:** End-to-end testing with real contract execution, security review, and
performance profiling.

**Work items:**
- Integration test suite: deploy a reference contract, call it across multiple
  transactions, assert state evolution matches expected cell sequence
- Determinism regression test: run the same block twice in the same process
  and assert byte-identical block hashes
- Replay test: serialize a block to disk, reimport it, assert identical state
- Gas exhaustion test: contract that runs out of gas mid-execution; assert state
  does not commit
- Forbidden-bytecode test: class that contains `invokedynamic`; assert
  deterministic load-time rejection
- Performance baseline: measure wall time for a 1000-tx block of representative
  contracts under a release build; set a regression gate so future changes do
  not silently degrade throughput
- Security review: class loader isolation (one contract cannot access another
  contract's static fields via reflection or class cast); heap bounds (gas
  exhaustion before heap overflows the pre-allocated arena); cell codec
  round-trip correctness (decode(encode(h)) == h for all reachable heaps)

**Effort:** 4–6 weeks

---

## Summary Effort Table

| Phase | Description | Estimated effort |
|---|---|---|
| 0 | Design pinning, stub registry tests | 1–2 weeks |
| 1 | Avian fork, determinism hardening | 4–8 weeks |
| 2 | Framework integration (WorkchainEngine, ConfigParam, genesis) | 2–3 weeks |
| 3 | Contract standard library (`tos.jvm.*`) | 3–5 weeks |
| **4** | **Heap serialization (cell codec)** | **3–5 months** |
| 5 | Gas metering | 3–5 weeks |
| 6 | Message ABI | 2–4 weeks |
| 7 | RPC namespace | 2–4 weeks |
| 8 | Hardening and integration testing | 4–6 weeks |
| **Total** | | **~9–14 engineer-months** |

Phase 4 (heap serialization) dominates the estimate. The v1 restricted-state
model (persistent state flows only through `tos.jvm.storage.Persistent*` types)
is the design decision that keeps Phase 4 in the 3–5 month range rather than
the 12–18 month range that a general object-graph serializer would require. This
restriction must not be relaxed without a full Phase 4 redesign.

Phases 1–3 can begin in parallel once Phase 0 is complete. Phase 4 depends on
Phase 1. Phases 5 and 6 are independent and can run in parallel after Phase 4.
Phases 7 and 8 depend on Phases 5 and 6.

## Implementation Progress

Legend:

- ✅ Complete
- 🟡 In progress
- ⬜ Not started
- ⏭ Explicitly deferred

Last updated: 2026-05-04.

| Phase | Status | Notes |
|---|---|---|
| Phase 0 — Design | ⬜ | This document is the starting point; TL-B schemas and stub tests not yet written |
| Phase 1 — Avian fork | ⬜ | |
| Phase 2 — Framework integration | ⬜ | |
| Phase 3 — Contract stdlib | ⬜ | |
| Phase 4 — Heap serialization | ⬜ | Largest risk item; must be prototyped before committing to timeline |
| Phase 5 — Gas metering | ⬜ | |
| Phase 6 — Message ABI | ⬜ | |
| Phase 7 — RPC namespace | ⬜ | |
| Phase 8 — Hardening | ⬜ | |
| JVM v2 account-native topology | ⏭ | Requires a separate consensus migration design; out of scope for v1 |
| Lambda / invokedynamic support | ⏭ | Requires full MethodHandle/CallSite implementation; out of scope for v1 |
| Per-account contract model | ⏭ | Each Java contract as a distinct TOS account on wc=3; out of scope for v1 |

## File Layout (target)

```
jvm/
  vendor/
    avian/              ← forked Avian, pinned commit, stripped and determinized
      PINNED_COMMIT
      CMakeLists.txt
      src/
        interpret.cpp   ← interpreter loop with gas counter wired in
        machine.cpp
        heap.cpp
        ...
  core/
    dispatch-engine.h
    dispatch-engine.cpp ← JvmNativeEngine, register_jvm_workchain_engine()
    config-param.h
    config-param.cpp    ← ConfigParam 12 descriptor + ConfigParam 85
    zerostate.h
    zerostate.cpp       ← build_jvm_zerostate_accounts_cell()
    init.h
    init.cpp            ← init_jvm_workchain()
    compute-phase.h
    compute-phase.cpp   ← jvm_run_compute_phase() called by JvmNativeEngine
    cell-codec.h
    cell-codec.cpp      ← JvmCellCodec encode/decode
    persistent-map.cpp  ← native C++ PersistentMap
    persistent-list.cpp ← native C++ PersistentList
    message-abi.h
    message-abi.cpp     ← JvmCallDescriptor encode/decode
    gas-table.h
    gas-table.cpp       ← per-opcode gas schedule from ConfigParam 85
    rpc.h
    rpc.cpp             ← jvm_* JSON-RPC handlers
  stdlib/
    src/
      tos/jvm/lang/Object.java
      tos/jvm/lang/String.java
      tos/jvm/lang/Math.java
      tos/jvm/lang/System.java
      tos/jvm/lang/Error.java
      tos/jvm/lang/OutOfGasError.java
      tos/jvm/lang/ContractViolationError.java
      tos/jvm/contract/ContractEntry.java
      tos/jvm/storage/PersistentMap.java
      tos/jvm/storage/PersistentList.java
      tos/jvm/emit/EventLog.java
    build/              ← compiled .class files bundled into zerostate
  test/
    ...
```

## Open Questions

The following questions must be answered before Phase 1 begins:

1. **GC model for v1.** Should the fork replace Avian's semi-space GC with a
   per-transaction arena allocator, or determinize the existing GC? An arena is
   simpler to audit for determinism but limits maximum per-transaction heap size.
   Gas limits should prevent abuse either way, but the interaction between gas
   limits and heap limits needs a concrete number for ConfigParam 85.

2. **Class store location.** Contract class files must be available to the class
   loader during execution. In v1 the class store is part of the executor
   account's data cell (`JvmHeap.class_store_hash` identifies the class tree).
   This means deploying a new contract is a transaction that updates the executor
   account's class store cell. Alternatively, class files could be addressed by
   content hash and stored in a separate global class registry cell. The choice
   affects deploy transaction design and class isolation guarantees.

3. **Cross-contract calls in v1.** Can one deployed contract call a method on
   another deployed contract within the same transaction? If yes, the call must
   be mediated (one contract cannot access another's static fields directly),
   which requires a call-dispatch mechanism. If no, cross-contract interaction
   requires asynchronous TOS message passing. The simpler v1 answer is no
   synchronous cross-contract calls; each inbound message targets exactly one
   contract class.

4. **TOS native contract interop.** Can a JVM contract send a synchronous
   read-only query to a TOS TVM contract (e.g. a token balance query)? In v1
   the answer should be no: all cross-workchain and cross-contract interaction
   is asynchronous through TOS messages. Synchronous reads from external state
   would break the snapshot execution model.

5. **`wc=3` vs new network.** Should the JVM workchain be activated on the
   existing TOS network as `wc=3`, or should it initially be deployed as a
   separate devnet to validate the design before integration? A separate devnet
   allows Phase 4 to be proven without affecting EVM and Uno validator
   operations, at the cost of a later integration step.
