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

The target audience is Java developers, and eventually Kotlin/Scala developers
whose compilers can emit Java 8 compatible class files against the TOS runtime
classpath. The v1 toolchain is Java-first; Kotlin/Scala support depends on
whether their runtime dependencies can be mapped onto the deterministic TOS
runtime library.

The workchain is not a general-purpose JVM for arbitrary Java programs. It is a
deterministic Java 8 class-file execution environment suitable for on-chain
state transition functions. Opcode and class-file compatibility follows the
Java 8 JVMS/OpenJDK model; the restriction is on non-deterministic runtime APIs
and persistence, not on inventing a non-Java bytecode dialect.

## Engine Selection: Avata

The C++ JVM landscape has very few embeddable candidates. A survey as of May
2026 found no actively-maintained C++ JVM designed for deterministic embedding
inside a consensus engine. The relevant options are:

| Project | Language | Embeddable | Java 8 profile | Blocking issue |
|---|---|---|---|---|
| Avata (ReadyTalk source import) | C++ | Yes, by design | Partial / audit required | Retired upstream; must fork, rename, and own |
| KiVM | C++ | No (CLI-oriented) | Audit required | Not designed as a consensus library |
| JamVM | C | Partial | Depends on classpath choice | Needs external class library integration |
| JLLVM-style approaches | C++ / LLVM | No for v1 | JIT-oriented | JIT/AOT pipeline is too large for v1 determinism |
| JDK Zero | C++ in OpenJDK tree | No | Full Java depends on OpenJDK | Requires full OpenJDK distribution/runtime surface |

**Avata is the starting point.** It is the only option explicitly designed for
embedding as a library. Its maintenance status is a concern for a
general-purpose JVM: upstream declares the project inactive, and the latest
commits are old security fixes rather than active development. For this use case
that risk is manageable only if the fork is treated as consensus code and is
completed to the Java 8 opcode compatibility target. Java 8 class-file bytecodes
are specified by the JVM Specification (JVMS, a stable JCP-governed document),
but that does not make Avata itself consensus-safe. The fork must prove that the
bytecode interpreter, verifier, class-loader, allocation, exception,
`invokedynamic`, and floating-point paths used by contracts are deterministic.

Avata will be **forked** and owned by this repository. The fork is not a tracking
clone; it is a permanent maintenance commitment to the Java 8 execution profile
needed for consensus execution. No attempt will be made to track the retired
upstream automatically. OpenJDK class-library inputs are vendored/pinned explicitly as
part of the TOS runtime library and audited like consensus code. The fork will
be maintained to the same standard as `evm/` and `uno/`.

The fork lives at `jvm/avata/` with a pinned commit hash recorded in
`jvm/avata/PINNED_COMMIT`. Any change to Avata internals must be made
inside this repository; no patch file workflow.

Phase 0 must also record the Avata license text and third-party notices in the
repository's normal audit path before the fork is vendored.

## Java 8 Compatibility Profile

This workchain does not attempt to run arbitrary host-side Java programs, but it
does commit to Java 8 class-file and opcode compatibility. A class file produced
by a standard Java 8 toolchain must remain a normal JVM class file; TOS does not
define a new bytecode dialect.

**Supported compatibility surface:**
- Class-file major version 52 (`Java SE 8`) using JVMS-compatible parsing,
  verification, linking, and exception semantics
- All Java 8 bytecode opcodes, including `invokedynamic`, floating-point
  opcodes, `monitorenter`, and `monitorexit`. Floating-point opcodes execute
  through the TOS deterministic fixed floating-point engine, not host CPU
  floating-point instructions.
- Constant-pool structures required by Java 8, including
  `CONSTANT_InvokeDynamic`, `MethodHandle`, `MethodType`, and
  `BootstrapMethods`
- Static, virtual, interface, special, and dynamic method dispatch
- Generics (compiler-erased; JVM-transparent)
- Annotations parsed by the validator for contract metadata; runtime annotation
  reflection is available only if the deterministic runtime profile admits it
- Single-dimensional and multi-dimensional arrays of primitives and references
- Object inheritance and interfaces
- Exception handling (`athrow`, `try/catch/finally`)
- Class initialization (`<clinit>`) with deterministic execution rules; Phase 0
  must define when initializers run during deploy and per-transaction restore

The runtime class library is a TOS-pinned `rt.jar` derived from OpenJDK classes
and extended with TOS APIs. Language-level classes remain under `java.lang`
(`Object`, `String`, `Math`, `System`, errors, and related helpers). TOS domain
APIs that are not language primitives live under `tos.*`, such as
`tos.storage.*`, `tos.contract.*`, and `tos.emit.*`.

**Consensus runtime restrictions:**
- `java.lang.Thread`, monitor wait/notify, executors, and other multi-threading
  APIs must be unavailable or throw deterministic `ContractViolationError`.
  The opcodes `monitorenter` / `monitorexit` still execute with deterministic
  single-thread monitor semantics for Java compatibility.
- Host IO, networking, filesystem, processes, native libraries, and database
  APIs (`java.io`, `java.net`, `java.nio` where host-backed, `java.sql`,
  `java.lang.Process`, JNI/native methods) must not access validator-local
  resources. The class library may include OpenJDK-derived class shapes, but
  consensus execution must reject or deterministically trap calls that would
  observe the host.
- Non-deterministic entry points such as wall-clock time, entropy,
  `Math.random()`, UUID generation, environment variables, and system
  properties are replaced by deterministic TOS-defined APIs or rejected.
- Floating-point execution is strictfp-equivalent for all contract code,
  regardless of the source method's `strictfp` modifier. The TOS fixed
  floating-point engine pins rounding, NaN canonicalization, signed-zero,
  infinity, overflow, underflow, and subnormal handling so Linux/macOS/Windows
  and different CPU architectures produce identical bits.
- Reflection and class loading are allowed only to the extent Phase 0 can pin a
  deterministic, contract-local behavior. Arbitrary `ClassLoader` access to
  validator-local code is forbidden.
- Finalizers, cleaners, weak/soft/phantom references, and object-address-derived
  identity behavior are unavailable unless a deterministic implementation is
  specified.

A contract class that violates the deterministic runtime profile is rejected or
traps with an error that names the specific offending reference. The rejection
or trap is deterministic and consensus-safe.

The validator must run a real class-file verifier for the supported profile,
including constant-pool validation, StackMapTable/type checks, access checks,
method descriptor checks, static field shape checks, and the forbidden-reference
rules above. Admission checks in RPC or tooling are convenience only; consensus
compute re-validates the exact class bytes it executes.

## Design Constraints

### Determinism is the primary invariant

Every validator running the same block must produce identical compute output.
This rules out:
- JIT compilation with optimizer-visible non-determinism (Avata's JIT is
  disabled in this fork; the interpreter path is used exclusively)
- Any system call that returns non-deterministic values (time, entropy, pid)
- Avata's threading primitives; the fork runs single-threaded
- Any object-address leakage to contract code. Default `Object.hashCode`,
  `System.identityHashCode`, `toString` identity suffixes, and any native object
  pointer exposure must either be absent or derived from deterministic
  per-transaction object ids. A compacting GC is acceptable only if object
  addresses are never observable and serialization is canonical.
- Host-dependent floating-point behavior. v1 supports Java 8 floating opcodes,
  but they must run through the TOS fixed floating-point implementation with
  pinned strictfp-equivalent semantics, not host-dependent x87/SSE/ARM behavior.

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
executor account's data cell, keyed by a `contract_id`. The deployed class bytes
are stored separately by `class_hash`; each `contract_id` points to the
`class_hash` it executes plus its own static state. This allows multiple
deployments of the same class to have distinct state.

This is not the long-term account model but it is the correct v1 starting
point: it matches the existing host-side policy machinery and avoids designing
a new account topology before the serialization model is proven.

A future JVM v2 may adopt an account-native model where each Java contract is a
distinct TOS account on `wc=3`. That is a separate workchain design, not a
cleanup of v1. The v1 executor account address `0x0000...0001` and activation
code marker (`0x4a` = `'J'`) are frozen as part of the JVM v1 descriptor.

### OpenJDK opcode compatibility

The JVM workchain commits to Java 8 opcode compatibility, including
`invokedynamic`. Avata's historical support is not sufficient by itself:
Phase 1 must complete or replace the `java.lang.invoke`, `MethodHandle`,
bootstrap-method, `CallSite`, and generated-lambda paths needed for standard
Java 8 bytecode. This is a major consensus-safety item, not an optional
post-v1 feature.

The compatibility promise is bytecode-level, not a promise to expose host
capabilities. Bytecode that calls OpenJDK APIs with non-deterministic or
host-observing behavior must still trap deterministically under the TOS runtime
profile.

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
the registry. `vm_mode = 0` is valid for JVM v1, matching Uno's reserved-mode
pattern. JVM chain identity and gas/class limits live in ConfigParam 85, not in
`vm_mode`. A future JVM v2 that changes descriptor semantics must use either a
new selector or a documented migration boundary; it must not silently reinterpret
the v1 descriptor.

Production descriptors are built by `jvm_workchain::build_jvm_workchain_descr()`.
The builder must also add ConfigParam 85 to the config dictionary and update
`doc/ConfigParam.md` when the slot is reserved.

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
    ├─ Decode input.inbound_body → JvmCallDescriptor
    │      (contract_id, method_id, argument encoding, value transfer)
    │
    ├─ Resolve contract_id → class_hash + static state
    │
    ├─ Load contract class from JvmHeap.class_store[class_hash]
    │
    ├─ Avata interpreter: execute entry method
    │      single-threaded, gas-metered, no JIT
    │
    ├─ Serialize post-execution JvmHeap → new_data (cell)
    │      └─ JvmCellCodec::encode_heap()
    │
    └─ Return WorkchainComputeOutput
           (committed, gas_used, new_data, action_list)
```

Side effects (event logs emitted by contracts) are staged in
`WorkchainComputeOutput::side_effects` and applied only after block acceptance.
The preferred target hook is
`WorkchainRuntimeServices::apply_post_accept_side_effects`; if that hook has
not landed, JVM should mirror the EVM post-accept stash/replay pattern. Side
effects are not consensus state.

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
- TL-B schema for `JvmExecutorState` cell layout and `JvmCallDescriptor`
  message body
- ConfigParam 85 schema, slot reservation note in `doc/ConfigParam.md`, and
  governance activation checklist for adding it to mandatory/critical params if
  the implementation chooses to require presence for active `wc=3`
- Class-file verifier profile: exact supported class-file version, forbidden
  class-library references, OpenJDK opcode/class-file compatibility cases,
  deterministic runtime traps, static field rules, and duplicate ABI method-id
  handling
- OpenJDK-derived runtime library plan: pinned source revision, license/notice
  handling, package list, TOS extensions, and deterministic replacements for
  host-observing APIs
- Persisted value profile: exact allowed static field types and
  `PersistentMap` / `PersistentList` key-value encodings. Arbitrary Java object
  graphs are not persisted in v1.
- Node capability plan: add a JVM bit next to
  `kTosNodeCapabilityWorkchainEvm` / `kTosNodeCapabilityWorkchainUno`, and
  require `validate_required_workchains` coverage before activation

**Effort:** 1–2 weeks

---

### Phase 1 — Avata fork and determinism hardening

**Goal:** Produce a stripped, deterministic, embeddable build of Avata suitable
for consensus execution. No TOS integration yet; tested standalone.

**Work items:**

- Import the pinned ReadyTalk source snapshot into `jvm/avata/`
- Add Avata license/notice material to the repository's third-party audit files
- Remove or disable Avata's JIT compiler (`avata/src/compile*.cpp`); force
  interpreter-only execution path (`avata/src/interpret.cpp`)
- Remove Avata's host threading primitives. `monitorenter`/`monitorexit` remain
  supported opcodes, but execute with deterministic single-thread monitor
  semantics; `wait`/`notify`/`Thread` APIs trap deterministically.
- Audit and remove or stub all `syscall` / `time` / `rand` / `getpid` paths
  in Avata's platform layer
- Validate GC behavior: determine whether Avata's semi-space collector
  can run without exposing addresses or preserving process-local state between
  transactions; if not, replace it with a bounded per-transaction arena or a
  non-compacting collector for the contract heap region
- Complete Java 8 opcode support in the interpreter, including
  `invokedynamic`, `java.lang.invoke` linkage, floating-point opcodes, and
  monitor opcodes
- Add the TOS fixed floating-point engine for Java `float`/`double` opcodes:
  strictfp-equivalent binary32/binary64 arithmetic with pinned rounding,
  NaN/signed-zero/infinity/subnormal behavior, plus conformance tests for all
  supported platforms
- Add class-load-time validation for unsupported class-file versions and
  deterministic runtime traps for forbidden host-observing packages/classes
  (`java.io`, `java.net`, `java.lang.Thread`, `java.lang.reflect` where not
  admitted by Phase 0, etc.)
- Make `Object.hashCode`, `System.identityHashCode`, object `toString`, and
  exception stack traces deterministic or unavailable
- Wire a per-transaction gas counter into Avata's interpreter dispatch loop;
  `OutOfGasError` must be thrown deterministically when the counter reaches zero
- Build system: integrate Avata as a static library via CMake;
  `jvm/avata/CMakeLists.txt` exports a single `avata_interpreter` target

**Determinism test harness:**
Run the same bytecode twice in the same process with freshly initialized heaps
and assert byte-identical output state. Run with `valgrind --tool=memcheck` to
eliminate undefined behavior that could cause inter-validator divergence.

**Effort:** 8–14 weeks

**Key risk:** Avata VM surface area. GC behavior, class loading, exceptions,
JNI/native stubs, and object identity must all be reduced to deterministic
consensus-safe behavior. If Avata's collector cannot be made deterministic
without significant surgery, evaluate replacing it with a simpler arena
allocator that is reset per transaction. A per-transaction arena (no GC at all)
is safe if gas limits are low enough that no single transaction can exhaust a
pre-allocated arena; this simplifies determinism at the cost of limiting
allocation-heavy contracts.

---

### Phase 2 — Framework integration

**Goal:** Wire the stripped Avata build into the TOS workchain execution
registry. No real contract execution yet; the `run_compute` stub returns a
placeholder result for tests only. A production binary must fail closed if
`wc=3` is active before real compute is implemented.

**Work items:**

- `jvm/core/dispatch-engine.h` / `.cpp`:
  - `JvmEngineConfig` (parsed from ConfigParam 85)
  - `JvmNativeEngine` implementing `WorkchainEngine`
  - `engine_key()` returns `{Basic, 0x4a564d31}`
  - `validate_and_resolve_config()` reads and validates ConfigParam 85
  - `account_policy()` returns `SingletonExecutor(0x0000...0001)` with
    activation code `0x4a`
  - `run_compute()` test stub: deserialize nothing, execute nothing, return a
    deterministic not-ready result; production startup must refuse active JVM
    descriptors until Phase 4+ real compute is wired
- `jvm/core/config-param.h` / `.cpp`:
  - `build_jvm_workchain_descr()` (ConfigParam 12 descriptor)
  - `build_jvm_config_cell()` / `parse_jvm_config_cell()` (ConfigParam 85)
  - ConfigParam 85 fields: `chain_id`, `schema_version`, `gas_price`,
    `max_gas_per_tx`, `max_class_bytes`, `max_total_class_bytes`,
    `max_heap_bytes`, `max_static_fields`, `class_file_major = 52`,
    `gas_schedule_version`, and `stdlib_hash`
- `jvm/core/zerostate.h` / `.cpp`:
  - `build_jvm_zerostate_accounts_cell()`: creates singleton executor account
    with empty `JvmExecutorState` data cell and activation code marker `0x4a`
- `jvm/core/init.h` / `.cpp`:
  - `init_jvm_workchain(db_root)`: initializes non-consensus Avata process
    resources and calls `register_jvm_workchain_engine(registry)`. Consensus
    ConfigParam 85 parsing happens only inside `validate_and_resolve_config()`
    against the block-transition config snapshot.
- `crypto/block/workchain-execution-dispatch.h` / `.cpp`:
  - Add `jvm_workchain_engine_key()`, `workchain_engine_key_is_jvm()`, and a
    `kTosNodeCapabilityWorkchainJvm` capability bit
  - Include the JVM bit in `workchain_execution_capability_flags()`
- `validator-engine/validator-engine.cpp`:
  - One added line: `jvm_workchain::init_jvm_workchain(db_root_)`

**Effort:** 2–3 weeks

---

### Phase 3 — Contract standard library

**Goal:** Provide the deterministic `rt.jar` that contract classes compile and
link against. This runtime is based on pinned OpenJDK Java 8 class-library
sources and extended with TOS-specific APIs. It is bundled into the executor
account's zerostate by content hash.

**Classes required:**
- `java.lang.Object` — minimal JVM root class required by class-file semantics;
  no finalization and no address-derived hash code
- `java.lang.Class` — opaque class token only; no class loading or reflective
  member access
- `java.lang.String` — deterministic immutable string/value type; string
  literal conversion rules and interning behavior must be pinned in Phase 0
- `java.lang.CharSequence` and small interfaces needed by `String`
- `java.lang.Throwable`, `java.lang.Error`, `java.lang.RuntimeException`, and
  the narrow exception types emitted by the verifier/runtime
- `java.lang.Math` / `java.lang.StrictMath` — OpenJDK-compatible method surface
  backed by the same TOS fixed floating-point engine; transcendental methods
  require pinned bit-exact algorithms before they are admitted in consensus
- `java.lang.System` — no time, environment, properties, or IO streams; exposes
  only deterministic chain APIs: `blockNumber()`,
  `blockTimestamp()`, `randSeed()` (from `context.rand_seed`),
  `callerAddress()`, `value()`, and `sendMessage(destAddr, value, body)`
- `java.lang.OutOfGasError` and `java.lang.ContractViolationError`, both
  subclasses of `java.lang.Error`
- `tos.contract.ContractEntry` — annotation type; marks a `public static`
  method as callable from an inbound message (referenced by Phase 6 ABI)
- `tos.storage.PersistentMap<K,V>` — ordered key-value map backed by the
  cell tree; the primary persistent data structure for contracts
- `tos.storage.PersistentList<T>` — append-only list backed by the cell tree
- `tos.emit.EventLog` — emit a log entry staged in side effects

The list above is the minimum class surface that must be audited explicitly; it
is not the entire runtime library. Phase 3 must decide which OpenJDK packages
are included in `rt.jar`, which methods are deterministic and callable, and
which methods are present only as linkage-compatible traps.

OpenJDK class shapes are the baseline, but not every OpenJDK behavior is
admitted in consensus. Host-observing methods are replaced, stubbed, or trapped
deterministically. Because this workchain ships its own pinned `rt.jar`, TOS can
extend `java.lang.System` with chain context methods while still preserving
normal Java class-file compatibility.

Contracts are compiled with a custom Java 8 boot classpath containing the
whitelisted `java.lang` runtime classes and `tos.*` APIs. The build tool must
force class-file major version 52 and then run the same verifier/admission
checks as the validator. This toolchain work is outside the consensus path and
may be delivered separately from the validator binary, but consensus never
trusts it.

**Effort:** 8–12 weeks

---

### Phase 4 — Heap serialization

**Goal:** Implement `JvmCellCodec`: bidirectional translation between a live
Avata heap and a TOS cell tree. This is the largest single engineering task in
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
persistent contract state flow through `tos.storage.PersistentMap` and
`tos.storage.PersistentList`. These types are implemented as thin Java
wrappers over cell-tree operations in native C++ (similar to how Uno's state
types are thin wrappers over nullifier and commitment tree operations). The
contract heap between calls is then reduced to:
- the values of all allowed static fields for the target `contract_id`
- primitive static fields (int, long, boolean, etc.)
- cell roots for `Persistent*` static fields
- no heap-allocated mutable objects survive across transaction boundaries

Allowed persisted values must be a closed set: primitive integers/booleans,
fixed-size byte arrays or addresses, deterministic strings if admitted by
Phase 0, and cell-backed `Persistent*` roots. Ordinary object references,
arrays of references, and mutable heap objects are transient only.

This eliminates the general object-graph serialization problem at the cost of
restricting contracts to a structured state model. It is the correct v1
tradeoff; unrestricted cross-transaction heap persistence can be addressed in
v2 with a full object-graph serializer once the execution model is proven.

Contract classes may not use arbitrary executable `<clinit>` logic. Deployment
creates the initial `JvmContractState` from the deploy message and constant
static field defaults; subsequent transactions restore static fields from the
cell state before invoking the entry method. This prevents class loading from
resetting persisted state every transaction.

Static fields are scoped to `contract_id`, not to `class_hash`. The runtime must
therefore use an isolated class-loader/runtime context per contract invocation,
or an equivalent mechanism, so two deployments of the same class never share
mutable static fields.

**Work items:**

- `jvm/core/cell-codec.h` / `.cpp`:
  - `JvmCellCodec::encode_heap(JvmHeap&) → td::Ref<vm::Cell>`
  - `JvmCellCodec::decode_heap(td::Ref<vm::Cell>) → JvmHeap`
  - Encode: walk static fields of the invoked contract instance; for
    `Persistent*` fields, flush the underlying cell-tree root; for primitive
    fields, pack into a canonical field cell
  - Decode: reconstruct `Persistent*` wrappers from stored cell roots; restore
    primitive static fields; initialize the contract class loader without
    running arbitrary user `<clinit>` code
- `jvm/core/persistent-map.cpp` / `persistent-list.cpp`:
  - Native C++ implementations of `tos.storage.Persistent*` that operate
    directly on `vm::Cell` trees (no intermediate Java heap objects for stored
    data)
- TL-B schema for `JvmExecutorState` cell (defined in Phase 0; implemented
  here).
  A magic tag is required, following the pattern of `UnoConfig` (`#26554E4F`):
  ```
  // magic = 0x4a564d31 ("JVM1")
  jvm_executor_state#4a564d31
      schema_version:uint8
      class_store:(HashmapE 256 ^JvmClassCell)
      contracts:(HashmapE 256 ^JvmContractState)
      = JvmExecutorState;

  jvm_class_cell#_ class_hash:bits256
                    class_bytes:^Cell
                    verifier_profile_hash:bits256
                    = JvmClassCell;

  jvm_contract_state#_ class_hash:bits256
                       static_fields:(HashmapE 16 ^StaticFieldCell)
                       = JvmContractState;
  ```
  The `contracts` map key is `contract_id`. The `class_store` map key is
  `class_hash`. The static field map uses a 16-bit key (field index within the
  contract class, matching the `fields_count` limit in the class file format).
  A content-hash key (256-bit) would be robust to field reordering but is
  unnecessary for v1 where class upgrades deploy a new class hash; the simpler
  index key is preferred. This choice must be pinned in Phase 0 and frozen
  thereafter.

**Effort:** 3–5 months

**Key risk:** Avata's class loader may store per-class metadata in ways that
are not easily separable from the heap. A detailed audit of
`avata/src/machine.cpp` and `avata/src/heap.cpp` is required before estimating
this phase more precisely. If Avata's class loader state is entangled with the
object heap in ways that prevent clean per-transaction reset, the fork may need
significant restructuring.

---

### Phase 5 — Gas metering

**Goal:** Map JVM bytecode execution to a gas schedule. Gas is charged
per-bytecode-instruction, per-cell-operation, and per-heap-allocation.

The gas counter installed in Phase 1 (into Avata's interpreter loop) is
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

**Effort:** 4–6 weeks

---

### Phase 6 — Message ABI

**Goal:** Define and implement the binary encoding for JVM contract calls
carried in `input.inbound_body`, and the encoding for outbound messages
(calls to other contracts or TOS native contracts).

**Inbound call descriptor (`JvmCallDescriptor`):**
```
jvm_call#_  contract_id:bits256
            method_id:uint32        // first 4 bytes of keccak(method_sig)
            args:^ArgsCell
            = JvmCallDescriptor;
```

`contract_id` identifies the deployed contract instance. The executor state maps
that id to a `class_hash`, and the `class_hash` selects the verified class
bytes. `method_id` selects the public static entry method. `ArgsCell` encodes
arguments using a compact binary encoding derived from the method descriptor
signature.

Only `public static` methods annotated with `@ContractEntry` are callable from
inbound messages. Other methods may only be called from within the same
transaction's execution.

Class-load validation must reject duplicate `method_id` values among callable
entry methods in the same class. The ABI must also define a deploy message:
class bytes, constructor/initializer arguments, optional deployment salt, and
the deterministic `contract_id = hash(deployer, class_hash, salt, init_args)`
derivation.

**Outbound action encoding:**
Contract code may enqueue outbound messages by calling
`java.lang.System.sendMessage(destAddr, value, body)`. This builds a standard
TOS action list cell compatible with the host action phase. The encoding mirrors
the existing TVM action list model so the host action phase requires no changes.

**Effort:** 2–4 weeks

---

### Phase 7 — RPC namespace

**Goal:** Implement `jvm_*` JSON-RPC endpoints through the target
`WorkchainRuntimeServices::register_rpc` hook once it lands. If that runtime
services hook is still only a design target, mirror the existing EVM/Uno RPC
registration pattern but keep it outside consensus dispatch. These are
non-consensus surfaces and must not affect compute.

**Endpoints:**
- `jvm_deployContract`: submit a class file and initial state; builds an
  external message targeting the executor account and returns the deterministic
  `contract_id`
- `jvm_call`: call a view (read-only) method locally; does not submit a tx
- `jvm_getContractState`: return the decoded static fields of a deployed contract
- `jvm_getReceipts`: return event logs for a given block range

Admission (`jvm_deployContract` pre-check) validates class files against the
Java 8 verifier profile and deterministic runtime API policy before building
the external message, as a convenience; consensus compute re-validates on
execution.

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
- OpenJDK opcode compatibility tests: lambdas/method references
  (`invokedynamic`), floating-point arithmetic, `monitorenter`/`monitorexit`,
  exceptions, arrays, interface dispatch, and class initialization
- Fixed floating-point conformance test: run the same float/double corpus on
  every supported OS/CPU target and assert byte-identical results, including
  NaN, signed zero, infinities, overflow, underflow, and subnormals
- Forbidden host API tests: classes that call time, entropy, threads, IO,
  networking, native methods, or host reflection; assert deterministic rejection
  or deterministic `ContractViolationError`
- Duplicate ABI id test: two `@ContractEntry` methods with the same
  four-byte `method_id`; assert class-load rejection
- Multi-instance test: deploy the same `class_hash` twice with different salts;
  assert the two `contract_id` states evolve independently
- Performance baseline: measure wall time for a 1000-tx block of representative
  contracts under a release build; set a regression gate so future changes do
  not silently degrade throughput
- Security review: class loader isolation (one contract cannot access another
  contract's static fields via reflection or class cast); heap bounds (gas
  exhaustion before heap overflows the pre-allocated arena); cell codec
  round-trip correctness for every persisted `JvmContractState`

**Effort:** 6–8 weeks

---

## Summary Effort Table

| Phase | Description | Estimated effort |
|---|---|---|
| 0 | Design pinning, stub registry tests | 1–2 weeks |
| 1 | Avata fork, opcode compatibility, determinism hardening | 8–14 weeks |
| 2 | Framework integration (WorkchainEngine, ConfigParam, genesis) | 2–3 weeks |
| 3 | OpenJDK-derived `rt.jar` + `tos.*` domain APIs | 8–12 weeks |
| **4** | **Heap serialization (cell codec)** | **3–5 months** |
| 5 | Gas metering | 4–6 weeks |
| 6 | Message ABI | 2–4 weeks |
| 7 | RPC namespace | 2–4 weeks |
| 8 | Hardening and integration testing | 6–8 weeks |
| **Total** | | **~14–24 engineer-months** |

Phase 4 (heap serialization) dominates the estimate. The v1 restricted-state
model (persistent state flows only through `tos.storage.Persistent*` types)
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
| Phase 1 — Avata fork | ⬜ | |
| Phase 2 — Framework integration | ⬜ | |
| Phase 3 — Contract stdlib | ⬜ | |
| Phase 4 — Heap serialization | ⬜ | Largest risk item; must be prototyped before committing to timeline |
| Phase 5 — Gas metering | ⬜ | |
| Phase 6 — Message ABI | ⬜ | |
| Phase 7 — RPC namespace | ⬜ | |
| Phase 8 — Hardening | ⬜ | |
| JVM v2 account-native topology | ⏭ | Requires a separate consensus migration design; out of scope for v1 |
| Lambda / invokedynamic support | ⬜ | Required for OpenJDK Java 8 opcode compatibility; implemented in Phase 1 |
| Per-account contract model | ⏭ | Each Java contract as a distinct TOS account on wc=3; out of scope for v1 |

## File Layout (target)

```
jvm/
  vendor/
    avata/              ← forked Avata, pinned commit, stripped and determinized
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
    OPENJDK_PINNED_COMMIT
    THIRD_PARTY_NOTICES.md
    openjdk/            ← pinned OpenJDK-derived class-library sources
    src/
      java/lang/Object.java
      java/lang/Class.java
      java/lang/String.java
      java/lang/CharSequence.java
      java/lang/Throwable.java
      java/lang/Error.java
      java/lang/RuntimeException.java
      java/lang/Math.java
      java/lang/StrictMath.java
      java/lang/System.java
      java/lang/OutOfGasError.java
      java/lang/ContractViolationError.java
      tos/contract/ContractEntry.java
      tos/storage/PersistentMap.java
      tos/storage/PersistentList.java
      tos/emit/EventLog.java
    build/              ← compiled .class files bundled into zerostate
  test/
    ...
```

## Open Questions

The following questions must be answered before Phase 1 begins:

1. **GC model for v1.** Should the fork replace Avata's semi-space GC with a
   per-transaction arena allocator, or determinize the existing GC? An arena is
   simpler to audit for determinism but limits maximum per-transaction heap size.
   Gas limits should prevent abuse either way, but the interaction between gas
   limits and heap limits needs a concrete number for ConfigParam 85.

2. **Class store retention limits.** Contract class files must be available to
   the class loader during execution. In v1 the class store is part of the
   executor account's data cell (`class_store[class_hash]`). Deploying a new
   contract is therefore a transaction that updates the executor account's class
   store and `contracts[contract_id]`. Phase 0 must set concrete limits for
   `max_class_bytes`, `max_total_class_bytes`, eviction/pruning policy if any,
   and whether identical `class_hash` entries are deduplicated.

3. **Cross-contract calls in v1.** The recommended v1 rule is no synchronous
   cross-contract calls: each inbound message targets exactly one `contract_id`,
   and cross-contract interaction uses asynchronous TOS messages. Phase 0 must
   either freeze this rule or define a mediated call-dispatch mechanism that
   preserves per-`contract_id` static-field isolation.

4. **TOS native contract interop.** Can a JVM contract send a synchronous
   read-only query to a TOS TVM contract (e.g. a token balance query)? In v1
   the answer should be no: all cross-workchain and cross-contract interaction
   is asynchronous through TOS messages. Synchronous reads from external state
   would break the snapshot execution model.

5. **OpenJDK runtime package boundary.** The v1 class-file profile is
   OpenJDK/JVMS-compatible, but consensus cannot expose host resources. Phase 0
   must decide which OpenJDK packages/methods are callable, which are present
   only as linkage-compatible deterministic traps, and how the developer
   toolchain reports those restrictions before deployment.

6. **`wc=3` vs new network.** Should the JVM workchain be activated on the
   existing TOS network as `wc=3`, or should it initially be deployed as a
   separate devnet to validate the design before integration? A separate devnet
   allows Phase 4 to be proven without affecting EVM and Uno validator
   operations, at the cost of a later integration step.
