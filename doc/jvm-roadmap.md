# JVM Workchain Roadmap

Status: working design — Avata slim baseline in progress
Date: 2026-05-05

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
strongly-typed language with a mature toolchain, deterministic transaction-local
memory accounting, and no Java-observable GC semantics, without
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
upstream automatically. OpenJDK/JDK8u sources are reference inputs only for
opcode, verifier, and admitted API semantics. The consensus build uses the
self-contained Avata/TOS runtime and audits it like consensus code. The fork
will be maintained to the same standard as `evm/` and `uno/`.

The fork lives at `jvm/avata/` with a pinned commit hash recorded in
`jvm/avata/PINNED_COMMIT`. Any change to Avata internals must be made
inside this repository; no patch file workflow.

Phase 0 must also record the Avata license text and third-party notices in the
repository's normal audit path before the fork is vendored.

## Java 8 Compatibility Profile

The detailed working profile and Avata development order are maintained in
`doc/jvm-profile.md`. This roadmap summarizes the same boundary at the phase
level.

The compatibility target is a **blockchain VM-committable restricted Java 8 API
profile**, not full OpenJDK 8 API compatibility. Within the admitted profile,
Avata/TOS APIs must match Java 8/OpenJDK 8 semantics closely enough that
standard Java 8 tooling can compile normal class files and contracts observe
predictable Java behavior. Outside that profile, APIs must be rejected by the
verifier or fail through deterministic consensus-safe traps; they must not
silently expose validator-local host behavior or diverge from Java semantics in
untracked ways.

The first-principles compatibility boundary is:
- **100% Java 8 class-file and bytecode opcode compatibility** for the execution
  engine, including verifier/linker/interpreter semantics for the supported
  class-file profile. TOS commits to executing ordinary Java 8 class files, not
  a TOS-specific bytecode dialect.
- **A TOS smart-contract runtime library**, not full OpenJDK 8 class-library
  compatibility. The shipped `rt.jar` is designed for deterministic contract
  execution and may include OpenJDK-shaped classes, Java language primitives,
  and `tos.*` APIs, but it intentionally excludes or traps host-side Java APIs
  that are not meaningful or safe on-chain.
- **Familiar Java developer workflow** through TOS-provided `javac` and local
  `java`-style runner tooling. Developers should be able to write Java 8
  source, compile it to normal class files against the TOS `rt.jar`, and run the
  same contract locally before deployment.

This workchain does not attempt to run arbitrary host-side Java programs, but it
does commit to Java 8 class-file and opcode compatibility. A class file produced
by a standard Java 8 toolchain must remain a normal JVM class file; TOS does not
define a new bytecode dialect.

**Supported compatibility surface:**
- Class-file major version 52 (`Java SE 8`) using JVMS-compatible parsing,
  verification, linking, and exception semantics
- All Java 8 bytecode opcodes in the engine decoder, including
  `invokedynamic`, floating-point opcodes, `monitorenter`, and `monitorexit`.
  The v1 contract verifier currently rejects `invokedynamic` class-file
  structures until deterministic VM-internal bootstrap linkage is admitted.
  Floating-point opcodes execute through the TOS deterministic fixed
  floating-point engine, not host CPU floating-point instructions.
- Constant-pool parsing for Java 8 structures. The v1 profile rejects
  `CONSTANT_InvokeDynamic`, `MethodHandle`, `MethodType`, and
  `BootstrapMethods` before execution because public `java.lang.invoke` is not
  part of the contract runtime.
- Static, virtual, interface, and special method dispatch; dynamic dispatch is
  a VM-internal future item, not a public method-handle API item.
- Generics (compiler-erased; JVM-transparent)
- Annotations parsed by the validator for contract metadata; runtime annotation
  reflection is available only if the deterministic runtime profile admits it
- Single-dimensional and multi-dimensional arrays of primitives and references
- Object inheritance and interfaces
- Exception handling (`athrow`, `try/catch/finally`)
- No application class initialization (`<clinit>`) in the v1 contract profile;
  static entry/helper methods remain allowed, but hidden initializer execution
  is rejected by the verifier
- No application enum classes (`ACC_ENUM`). Java enum classes synthesize static
  state and are outside the v1 profile.
- No application `ACC_SYNCHRONIZED` or `ACC_NATIVE` methods. Synchronized
  blocks still compile to `monitorenter`/`monitorexit` and use deterministic
  single-thread monitor semantics; native entry points are limited to audited
  boot-runtime helpers.
- No application `finalize()V` methods. Object finalization is not part of the
  contract lifecycle.

The runtime class library is a TOS-pinned `rt.jar` built from the Avata/TOS
classpath and extended with TOS APIs. OpenJDK/JDK8u class shapes may be used as
semantic references, but they are not runtime build inputs for the consensus
profile. Language-level classes remain under `java.lang` (`Object`, `String`,
`Math`, `System`, errors, and related helpers). TOS domain APIs that are not
language primitives live under `tos.*`, such as `tos.storage.*`,
`tos.contract.*`, and `tos.emit.*`.

**Consensus runtime restrictions:**
- `java.lang.Thread`, monitor wait/notify, executors, and other multi-threading
  APIs must be unavailable or throw deterministic `ContractViolationError`.
  The opcodes `monitorenter` / `monitorexit` still execute with deterministic
  single-thread monitor semantics for Java compatibility.
- Host IO, networking, filesystem, processes, native libraries, and database
  APIs must not access validator-local resources. In the v1 `rt.jar`, broad
  host-facing Java SE packages are absent by default: `java.net`, host-backed
  `java.nio`, `java.security`, `java.text`, `java.math`,
  `java.util.concurrent`, `java.util.logging`, `java.util.regex`,
  `java.util.zip`, and `java.util.jar` are not shipped unless explicitly
  admitted later. Minimal `java.io` remains only for byte-array/string streams
  and VM stdin/stdout/stderr descriptors; path-based filesystem APIs are absent.
  JNI/native methods and any remaining internal host hook must reject or trap
  deterministically before observing the host.
- Non-deterministic entry points such as wall-clock time, entropy,
  `Math.random()`, UUID generation, environment variables, and system
  properties are replaced by deterministic TOS-defined APIs or rejected.
- Hash-backed and identity/weak collections (`HashMap`, `HashSet`,
  `LinkedHashMap`, `LinkedHashSet`, `Hashtable`, `IdentityHashMap`,
  `WeakHashMap`, and `Properties`) are not part of the contract `rt.jar`;
  transient maps must use explicitly ordered structures such as `TreeMap`, and
  persistent state must use Avata storage abstractions.
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
  per-transaction object ids. The v1 contract heap should not expose Java GC
  semantics; allocation is accounted against a bounded transaction-local memory
  budget and the transaction heap is discarded at the transaction boundary.
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
`class_hash` it executes plus its own explicit storage state. This allows multiple
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
`invokedynamic`, but the contract runtime does not ship public
`java.lang.invoke` classes. Avata's historical lambda support was removed from
the v1 profile because it carried Java SE method-handle and bootstrap API
surface into `rt.jar`. Future `invokedynamic` admission must be implemented as
deterministic VM-internal linkage and verified without exposing
`MethodHandle`, `MethodType`, `CallSite`, or `LambdaMetafactory` classes to
contracts.

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
    ├─ Resolve contract_id → class_hash + storage root
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
- TOS runtime library profile plan: package list, license/notice handling,
  optional OpenJDK/JDK8u semantic references, TOS extensions, and deterministic
  replacements for host-observing APIs
- Persisted value profile: exact allowed storage value types and
  `PersistentMap` / `PersistentList` key-value encodings. Arbitrary Java object
  graphs and Java static fields are not persisted in v1.
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
- Keep the current slim Avata baseline: interpreter-only execution path
  (`avata/src/interpret.cpp`), Avata/TOS `rt/` runtime only, and no OpenJDK/Android
  classpath bridges, bootimage/codeimage generator, JIT/codegen, embed loader,
  or LZMA build variants
- Remove Avata's host threading primitives. `monitorenter`/`monitorexit` remain
  supported opcodes, but execute with deterministic single-thread monitor
  semantics; `wait`/`notify`/`Thread` APIs trap deterministically.
- Audit and remove or stub all `syscall` / `time` / `rand` / `getpid` paths
  in Avata's platform layer
- Replace the legacy Avata contract-heap collection model with bounded
  transaction-local memory accounting. `java.lang.Memory` exposes
  used/remaining/limit counters; the contract ABI can start execution with gas
  and memory
  limits; allocation increments the transaction memory counter and fails
  deterministically when the limit is exceeded. Movable contract allocations
  now run under an arena checkpoint that is rolled back at transaction end, and
  contract execution rejects fixed/oversized allocation plus the legacy
  collector fallback. Application classes may not declare mutable static
  fields; the verifier admits only `static final` primitive/String constants
  with `ConstantValue`, while static methods remain allowed. Boot runtime
  classes may not perform reference-type `putstatic` during contract execution,
  so Java static fields cannot accidentally retain transient heap objects
  across invocations. The remaining heap work is to serialize explicitly
  admitted persistent state into cells.
- Complete Java 8 opcode support in the interpreter, including deterministic
  VM-internal `invokedynamic` linkage, floating-point opcodes, and monitor
  opcodes. Public `java.lang.invoke` remains outside the v1 runtime profile.
- Add the TOS fixed floating-point engine for Java `float`/`double` opcodes:
  strictfp-equivalent binary32/binary64 arithmetic with pinned rounding,
  NaN/signed-zero/infinity/subnormal behavior, plus conformance tests for all
  supported platforms
- Add class-load-time validation for unsupported class-file versions and
  deterministic runtime traps for forbidden host-observing packages/classes.
  In the v1 classpath, broad host packages such as `java.net` and host-backed
  `java.nio` are absent; minimal `java.io` is descriptor/string/byte-array
  only; non-admitted whole classes/packages such as `java.lang.invoke`,
  `sun.misc.Unsafe`, `java.internal.Machine`, and `java.internal.Traces` are absent from
  `rt.jar`; `java.lang.Thread` and non-admitted reflection/class-loading
  surfaces must reject or trap deterministically where their containing classes
  are still required.
- Make `Object.hashCode`, `System.identityHashCode`, object `toString`, and
  exception stack traces deterministic or unavailable
- Wire a per-transaction gas counter into Avata's interpreter dispatch loop;
  `OutOfGasError` must be thrown deterministically when the counter reaches zero
- Build system: Avata is integrated as a static library via CMake;
  `jvm/avata/CMakeLists.txt` exports `avata_interpreter`, `jvm_workchain_core`
  links it, and `make_linked_jvm_avata_execution_api()` maps the workchain
  bridge to the Avata C ABI. `init_jvm_workchain()` now installs a linked
  Avata VM runtime when the runtime jar is available and keeps wc=3 fail-closed
  if VM creation fails.

**Determinism test harness:**
`make -C jvm/avata run-test` runs each Java test twice with the same bytecode,
VM flags, classpath, and input, then compares complete stdout/stderr. The
generated `run-determinism.sh` is also used by the remote-test path so the same
replay check can run on Linux, macOS, Windows, FreeBSD, and target validator
architectures. The workchain registry test also replays the same JVM compute
input and compares `new_data` and action-list cell hashes, gas, exit code, and
VM log. Run stress builds with `valgrind --tool=memcheck` to eliminate undefined
behavior that could cause inter-validator divergence.

**Effort:** 8–14 weeks

**Key risk:** Avata VM surface area. Class resolution, exceptions, JNI/native
stubs, object identity, and heap allocation must all be reduced to deterministic
consensus-safe behavior. The v1 target is a per-transaction arena with explicit
memory counters, not Java-observable garbage collection. Gas and memory limits
must be sized together so a single transaction cannot exhaust validator memory.

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
    deterministic not-ready result until the production Avata resolver is
    installed
- `jvm/core/config-param.h` / `.cpp`:
  - `build_jvm_workchain_descr()` (ConfigParam 12 descriptor)
  - `build_jvm_config_cell()` / `parse_jvm_config_cell()` (ConfigParam 85)
  - ConfigParam 85 fields: `chain_id`, `schema_version`, `gas_price`,
    `max_gas_per_tx`, `max_class_bytes`, `max_total_class_bytes`,
    `max_heap_bytes`, `max_storage_cells`, `class_file_major = 52`,
    `gas_schedule_version`, and `stdlib_hash`
- `jvm/core/zerostate.h` / `.cpp`:
  - `build_jvm_zerostate_accounts_cell()`: creates singleton executor account
    with empty `JvmExecutorState` data cell and activation code marker `0x4a`
- `jvm/core/init.h` / `.cpp`:
  - `init_jvm_workchain(db_root)`: initializes non-consensus Avata process
    resources, creates the linked Avata runtime from
    `TOS_JVM_AVATA_RT_JAR`/the CMake default plus optional
    `TOS_JVM_AVATA_CONTRACT_CLASSPATH`, and calls
    `register_jvm_workchain_engine(registry, runtime)`. Consensus ConfigParam
    85 parsing happens only inside `validate_and_resolve_config()` against the
    block-transition config snapshot.
- `jvm/core/avata-runtime.h` / `.cpp`:
  - `JvmAvataRuntime` installs storage/event hosts and invokes Avata through
    the execution bridge. `make_linked_jvm_avata_execution_api()` binds that
    bridge to the linked Avata C ABI. `make_linked_jvm_avata_runtime()` creates
    the process-local Avata VM/thread and resolves inbound calls from the
    executor-state class manifest before entering the gas/memory transaction.
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
link against. This runtime is the smart-contract API surface for the JVM
workchain, not an attempt to reproduce the full OpenJDK 8 class library. It is
built from the Avata/TOS `rt/` tree, may use JDK8u as a semantic reference where
that helps preserve Java language and tooling compatibility, and is extended
with TOS-specific APIs. It is bundled into the executor account's zerostate by
content hash.

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
- `java.lang.Math` — only the deterministic arithmetic helper subset is
  admitted in v1. `Math.random`, host-libm transcendental functions, and
  float/double string parse/format helpers stay out until pinned software
  implementations exist. `StrictMath` is not shipped in the v1 profile.
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
is not the entire runtime library. Phase 3 must decide which Java-compatible
packages are included in `rt.jar`, which methods are deterministic and
callable, and which methods are present only as linkage-compatible traps.

JDK8u class shapes are references, but not every OpenJDK behavior is admitted
in consensus. Host-observing methods are replaced, stubbed, or trapped
deterministically. Because this workchain ships its own pinned `rt.jar`, TOS can
extend `java.lang.System` with chain context methods while still preserving
normal Java class-file compatibility.

Contracts are compiled with a custom Java 8 boot classpath containing the
whitelisted `java.lang` runtime classes and `tos.*` APIs. The build tool must
force class-file major version 52 and then run the same verifier/admission
checks as the validator. This toolchain work is outside the consensus path and
may be delivered separately from the validator binary, but consensus never
trusts it.

The developer distribution must provide a `javac` command path and a local
`java`-style runner path configured for the TOS runtime profile. The compiler
uses the TOS `api.jar` as the boot classpath so unsupported OpenJDK
APIs and VM-private `java.internal.*` helpers fail early at compile or admission time.
The local runner executes the same Avata interpreter profile with the full
`rt.jar`, gas rules, fixed floating-point behavior, deterministic traps, and
heap/state codec as validators, so local tests exercise the same contract
surface that will run on-chain.

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
persistent contract state flow through `Storage`, `Mapping`, and future
cell-backed persistent containers. Application classes may not declare static
fields except compile-time `static final` primitive/String constants with
`ConstantValue`; javac features that synthesize mutable static state, including
enum constants, are outside the v1 contract profile. The contract heap between
calls is then reduced to:
- storage cells addressed by explicit slot keys
- cell roots for future `Persistent*` containers
- no heap-allocated mutable objects survive across transaction boundaries

Allowed persisted values must be a closed set: primitive integers/booleans,
fixed-size byte arrays or addresses, deterministic strings if admitted by
Phase 0, and cell-backed persistent roots. Ordinary object references, arrays
of references, and mutable heap objects are transient only.

This eliminates the general object-graph serialization problem at the cost of
restricting contracts to a structured state model. It is the correct v1
tradeoff; unrestricted cross-transaction heap persistence can be addressed in
v2 with a full object-graph serializer once the execution model is proven.

Contract classes may not use mutable static fields as hidden state. Compile-time
`static final` primitive/String constants are admitted because they do not
create a state root. Deployment creates the initial `JvmContractState` from the
deploy message and explicit storage roots; subsequent transactions install the
account-state storage overlay before invoking the entry method. This prevents
class loading from resetting or sharing contract state implicitly.

**Work items:**

- `jvm/core/cell-codec.h` / `.cpp`:
  - `JvmCellCodec::encode_heap(JvmHeap&) → td::Ref<vm::Cell>`
  - `JvmCellCodec::decode_heap(td::Ref<vm::Cell>) → JvmHeap`
  - Encode: flush explicit storage roots and future `Persistent*` container
    roots into canonical cells
  - Decode: reconstruct storage overlays and future `Persistent*` wrappers from
    stored cell roots without restoring Java static fields
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
                       storage_root:^Cell
                       = JvmContractState;
  ```
  The `contracts` map key is `contract_id`. The `class_store` map key is
  `class_hash`. `storage_root` is the canonical root of the explicit
  contract-storage tree; Java static fields are not encoded in v1 state.

**Effort:** 3–5 months

**Key risk:** Avata's class-space metadata may store per-class state in ways
that are not easily separable from the heap. A detailed audit of
`avata/src/machine.cpp` and `avata/src/heap.cpp` is required before estimating
this phase more precisely. If Avata's class-space state is entangled with the
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
jvm_call#4a564d49
    schema_version:uint8  // 1
    contract_id:bits256
    method_id:uint32      // first 4 bytes of keccak(method_sig)
    args:^ArgsCell
    = JvmCallDescriptor;
```

`contract_id` identifies the deployed contract instance. The executor state maps
that id to a `class_hash`, and the `class_hash` selects the verified class
bytes. `method_id` selects the public static entry method. `ArgsCell` encodes
arguments using a compact binary encoding derived from the method descriptor
signature.

**Typed args (`JvmArgs`):**
```
jvm_args#4a564d41
    schema_version:uint8  // 1
    count:uint8
    values:^(JvmArg chain)?
    = JvmArgs;

jvm_arg
    type:uint8
    has_next:bit
    next:^(JvmArg)?
    value:^BytesCell
    = JvmArg;
```

V1 typed args are descriptor-checked against void-return method specs and admit
only deterministic contract ABI values: `boolean`, `int`, `long`,
`java.lang.Address`, `java.lang.Uint256`, `java.lang.Bytes32`,
`java.lang.Bytes4`, and variable-length `java.lang.Bytes`.

Only `public static` methods annotated with `@ContractEntry` are callable from
inbound messages. Other methods may only be called from within the same
transaction's execution.

Class-load validation must reject duplicate `method_id` values among callable
entry methods in the same class. The ABI must also define a deploy message:
class bytes, constructor/initializer arguments, optional deployment salt, and
the deterministic `contract_id = sha256("TOS-JVM-CONTRACT-v1" || deployer ||
class_hash || salt || init_args_cell_hash)` derivation.

**Class manifest (`JvmAvataClassManifest`):**
```
jvm_manifest#4a564d4d
    schema_version:uint8  // 1
    count:uint16
    entries:^(JvmManifestEntry chain)
    = JvmAvataClassManifest;

jvm_manifest_entry
    contract_id:bits256
    method_id:uint32
    has_next:bit
    next:^(JvmManifestEntry)?
    class_name:^StringCell
    method_name:^StringCell
    method_spec:^StringCell
    = JvmManifestEntry;
```

**Class state (`JvmAvataClassState`):**
```
jvm_class_state#4a564d43
    schema_version:uint8  // 1
    class_count:uint16
    manifest:^JvmAvataClassManifest
    classes:^(JvmClassDefinition chain)?
    = JvmAvataClassState;

jvm_class_definition
    class_hash:bits256    // sha256(class_bytes)
    has_next:bit
    next:^(JvmClassDefinition)?
    class_name:^StringCell
    class_bytes:^BytesCell
    = JvmClassDefinition;
```

Implementation status: `jvm/core/message-abi.*` implements the v1 call
descriptor envelope and `JvmNativeEngine` rejects malformed inbound bodies
before entering an installed runtime. `jvm/core/class-manifest.*` implements the
v1 callable `JVMM` manifest and the `JVMC` class-state envelope. The manifest
rejects duplicate `(contract_id, method_id)` entries, admits only ASCII Java
internal class names, Java identifier method names, and supported static-void
descriptors, and `JvmCellCodec` validates both manifest-only and `JVMC`
class-state roots when decoding executor state. The linked Avata runtime
resolver uses that manifest to resolve a static-void Avata method before
executing the gas/memory transaction. Legacy `()V` entries still accept only the
canonical empty args cell; parameterized entries must use the deterministic
`JVMA` typed args cell.
The deploy envelope, deterministic class-byte installation into `JVMC`, typed
`ArgsCell` codec/descriptor validator, and typed Avata invocation bridge are
implemented. The linked resolver now caches Avata VMs by `class_state_root`
hash, installs `JVMC` class bytes into that isolated app class space through
`avata_define_contract_class()`, resolves the static-void manifest entry, and
passes decoded `boolean`, `int`, `long`, `Address`, `Uint256`, `Bytes32`,
`Bytes4`, and `Bytes` arguments through the Avata C ABI.

**Deploy descriptor (`JvmDeployDescriptor`):**
```
jvm_deploy#4a564d44
    schema_version:uint8  // 1
    deployer:bits256
    salt:bits256
    class_hash:bits256    // sha256(class_bytes)
    class_name:^StringCell
    class_bytes:^BytesCell
    init_args:^ArgsCell
    = JvmDeployDescriptor;
```

`jvm/core/deploy-abi.*` implements this envelope, validates `class_hash` against
the supplied bytes, validates the class name, and derives the deterministic
`contract_id`. `install_jvm_deploy_descriptor()` applies the descriptor to
`class_state_root` by storing a verified class definition under `JVMC` while
enforcing ConfigParam 85 class-store limits (`max_class_bytes` and
`max_total_class_bytes`) through the installer overload used by deploy
admission. Callable method ids remain the responsibility of the verified
manifest/admission layer. Runtime resolution loads the installed class bytes
from `JVMC` into the VM cache entry for that `class_state_root`.

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
- `jvm_getContractState`: return the decoded explicit storage state of a
  deployed contract
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
- Security review: contract storage isolation (one contract cannot access
  another contract's storage root); heap bounds (gas exhaustion before heap
  overflows the pre-allocated arena); cell codec round-trip correctness for
  every persisted `JvmContractState`

**Effort:** 6–8 weeks

---

## Summary Effort Table

| Phase | Description | Estimated effort |
|---|---|---|
| 0 | Design pinning, stub registry tests | 1–2 weeks |
| 1 | Avata fork, opcode compatibility, determinism hardening | 8–14 weeks |
| 2 | Framework integration (WorkchainEngine, ConfigParam, genesis) | 2–3 weeks |
| 3 | TOS contract `rt.jar` + `tos.*` domain APIs | 8–12 weeks |
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

Last updated: 2026-05-07.

| Phase | Status | Notes |
|---|---|---|
| Phase 0 — Design | 🟡 | Roadmap and restricted API profile are written; TL-B schemas and stub tests not yet written |
| Phase 1 — Avata fork | 🟡 | Fork imported and renamed; current slim baseline builds as interpreter + Avata/TOS `rt/` runtime only. Remaining work: fixed floating point, gas schedule, verifier policy, traps, and TOS integration target |
| Phase 2 — Framework integration | ⬜ | |
| Phase 3 — Contract stdlib | ⬜ | |
| Phase 4 — Heap serialization | ⬜ | Largest risk item; must be prototyped before committing to timeline |
| Phase 5 — Gas metering | ⬜ | |
| Phase 6 — Message ABI | 🟡 | `JvmCallDescriptor`, typed `JVMA` args codec, `JvmDeployDescriptor`, restricted `JVMM` manifest, `JVMC` class-state envelope, deterministic deploy class-byte installation, state-backed Avata class loading, pre-runtime inbound validation, legacy static-void empty-args validation, typed static-void invocation, duplicate manifest-key rejection, and linked resolver integration are implemented |
| Phase 7 — RPC namespace | ⬜ | |
| Phase 8 — Hardening | ⬜ | |
| JVM v2 account-native topology | ⏭ | Requires a separate consensus migration design; out of scope for v1 |
| Lambda / invokedynamic support | ⬜ | Required for full Java 8 opcode compatibility, but must be VM-internal and deterministic; public `java.lang.invoke` stays absent from v1 `rt.jar` |
| Per-account contract model | ⏭ | Each Java contract as a distinct TOS account on wc=3; out of scope for v1 |

## File Layout (target)

```
jvm/
  avata/                ← forked Avata, pinned commit, stripped and determinized
    PINNED_COMMIT
    CMakeLists.txt
    src/
      interpret.cpp     ← interpreter loop with gas counter wired in
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
    message-abi.cpp     ← JvmCallDescriptor + typed JVMA args codec
    class-manifest.h
    class-manifest.cpp  ← class_state_root JVMM/JVMC codec and resolver map
    gas-table.h
    config-param.cpp    ← ConfigParam 85 limits and gas schedule codec
    rpc.h
    rpc.cpp             ← jvm_* JSON-RPC handlers
  rt/
    PROFILE.md
    THIRD_PARTY_NOTICES.md
    src/
      java/lang/Object.java
      java/lang/Class.java
      java/lang/String.java
      java/lang/CharSequence.java
      java/lang/Throwable.java
      java/lang/Error.java
      java/lang/RuntimeException.java
      java/lang/Math.java
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

The following questions must be answered before Phase 1 is considered complete:

1. **Persistent state and transaction arena boundary for v1.** Explicit
   memory-limit accounting and movable-heap arena rollback exist in the contract
   ABI and allocation path. Application mutable static fields are rejected, so
   the remaining work is serializing explicit storage/persistent-container
   roots into cells and ensuring no transient heap reference crosses the
   transaction boundary. Phase 0 must set concrete heap and gas numbers for
   ConfigParam 85
   so allocation-heavy contracts fail deterministically before exhausting
   validator memory.

2. **Class store retention policy.** Contract class files must be available to
   the class loader during execution. In v1 the class store is part of the
   executor account's data cell (`class_store[class_hash]`). Deploying a new
   contract is therefore a transaction that updates the executor account's class
   store and `contracts[contract_id]`. The installer enforces
   `max_class_bytes` and `max_total_class_bytes` from ConfigParam 85; Phase 0
   must still set concrete activation values and define eviction/pruning policy
   if any.

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

5. **TOS runtime package boundary.** The v1 class-file profile is
   OpenJDK/JVMS-compatible, but consensus cannot expose host resources. Phase 0
   must decide which Java-compatible packages/methods are callable, which are present
   only as linkage-compatible deterministic traps, and how the developer
   toolchain reports those restrictions before deployment.

6. **`wc=3` vs new network.** Should the JVM workchain be activated on the
   existing TOS network as `wc=3`, or should it initially be deployed as a
   separate devnet to validate the design before integration? A separate devnet
   allows Phase 4 to be proven without affecting EVM and Uno validator
   operations, at the cost of a later integration step.
