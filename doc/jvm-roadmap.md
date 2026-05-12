# JVM Workchain Roadmap

Status: **implemented** — Phases 0–8 + JVM v2 account-native topology + post-v2 wc=3 wallet bootstrap (Phases A–G) landed
Date: 2026-05-12

This document is now both the historical roadmap and the implemented spec
for `wc=3` (Avata JVM).  It covers engine selection rationale, design
constraints, per-phase work breakdown, and the as-built v2 account-native
state model that supersedes the original v1 SingletonExecutor design.
For the dense as-built reference see
[`doc/jvm-v2-account-topology.md`](jvm-v2-account-topology.md); for the
host-side `EngineDefined` policy + `action_create_account` see
[`doc/workchain-execution-registry.md`](workchain-execution-registry.md);
for ConfigParam 85 schema_version=2 see
[`doc/ConfigParam.md`](ConfigParam.md).

The phase-by-phase narrative below records the v1 design that was
implemented first and then collapsed into v2 as part of pre-launch
cleanup.  v1 code has been removed from the tree (see §"v1 removal").

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
  and TOS contract APIs under `java.lang`, but it intentionally excludes or
  traps host-side Java APIs that are not meaningful or safe on-chain.
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
- All Java 8 bytecode opcodes in the engine decoder except `invokedynamic`,
  floating-point opcodes, `monitorenter`, and `monitorexit`.
  Floating-point opcodes execute through the TOS deterministic fixed
  floating-point engine, not host CPU floating-point instructions.
  `invokedynamic` is **permanently unsupported** — rejected at class-load time
  and not planned for v2 or any future version (see "OpenJDK opcode
  compatibility" below).
- Constant-pool parsing for Java 8 structures. `CONSTANT_InvokeDynamic`,
  `CONSTANT_MethodHandle`, `CONSTANT_MethodType`, and `BootstrapMethods` are
  rejected at class load; `java.lang.invoke` is absent from `rt.jar` and
  `api.jar` by design.
- Static, virtual, interface, and special method dispatch.
- Generics (compiler-erased; JVM-transparent)
- Annotations parsed by the validator for contract metadata; runtime annotation
  reflection is available only if the deterministic runtime profile admits it
- Single-dimensional and multi-dimensional arrays of primitives and references
- Object inheritance and interfaces
- Exception handling (`athrow`, `try/catch/finally`)
- No application class initialization (`<clinit>`) in the contract profile;
  static entry/helper methods remain allowed, but hidden initializer execution
  is rejected by the verifier
- No application enum classes (`ACC_ENUM`). Java enum classes synthesize static
  state and are outside the contract profile.
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
`Math`, `System`, errors, and related helpers). The TOS contract API is
also packaged under `java.lang` because the workchain ships its own pinned
`rt.jar`/`api.jar` rather than the OpenJDK class library.

**Consensus runtime restrictions:**
- `java.lang.Thread`, monitor wait/notify, executors, and other multi-threading
  APIs must be unavailable or throw deterministic `ContractViolationError`.
  The opcodes `monitorenter` / `monitorexit` still execute with deterministic
  single-thread monitor semantics for Java compatibility.
- Host IO, networking, filesystem, processes, native libraries, and database
  APIs must not access validator-local resources. In `rt.jar`, broad
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
  per-transaction object ids. The contract heap does not expose Java GC
  semantics; allocation is accounted against a bounded transaction-local memory
  budget and the transaction heap is discarded at the transaction boundary.
- Host-dependent floating-point behavior. Java 8 floating opcodes are supported,
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

### Per-contract accounts (account-native)

Each JVM contract is its own wc=3 account at a deterministic 256-bit
address derived by `derive_jvm_contract_address`. The activation code
marker (`0x4a` = `'J'`) and ConfigParam slot 85 are frozen as part of
the wc=3 descriptor.

The account-creation policy is `AccountExecutionPolicyKind::EngineDefined`
with `admits_engine_create_account_actions=true`: the host accepts any
address in wc=3 and lets a wc=3 transaction emit `action_create_account`
to materialize a new contract account at a deterministic address.

The per-account state cell `JvmContractAccountState` (magic JVAC,
schema_version=2) carries the contract's `class_hash`, inline
`class_bytes` cell ref (Cell DB hash dedup makes identical bytecode
physically shared across accounts), `storage_root`, and `manifest_root`.
There is no shared executor account or shared class store.

### OpenJDK opcode compatibility

The JVM workchain commits to Java 8 opcode compatibility for the opcodes
defined in the JVMS. **`invokedynamic` is permanently excluded** — it is
rejected at three independent layers (constant-pool entries, `BootstrapMethods`
attribute, and opcode dispatch) and will not be admitted in v2 or any future
version. A deterministic consensus VM cannot safely admit arbitrary bootstrap
method linkage; the anonymous-inner-class pattern covers all practical contract
use cases without it. `java.lang.invoke` is absent from `rt.jar` and `api.jar`
by design.

The compatibility promise covers the remaining opcode set. Bytecode that calls
OpenJDK APIs with non-deterministic or host-observing behaviour must still trap
deterministically under the TOS runtime profile.

### Activation requires a capability gate

Activating `wc=3` follows the same coordination requirements defined in
`doc/workchain-execution-registry.md §Activation and Capability Coordination`.
No validator may be assigned to `wc=3` before advertising JVM execution
capability. The JVM workchain must not be active in mainnet genesis; it is a
post-genesis governance activation.

The JVM activation point is the masterchain block where the accepted
`ConfigParam 12` update becomes active with the `wc=3` descriptor marked
`active=true`, with ConfigParam 85 already present in the same config snapshot.
`enabled_since` records activation metadata but is not an automatic delayed
height trigger in the current dispatch path.

## Engine Identity

| Field | Value |
|---|---|
| Workchain ID | `wc=3` |
| ConfigParam 12 format | `wfmt_basic` |
| `vm_version` (engine selector) | `0x4a564d31` (`"JVM1"`) |
| `vm_mode` | Reserved; `0` |
| Account policy | `EngineDefined` + `admits_engine_create_account_actions=true` |
| Activation code marker | `0x4a` (`'J'`) |
| Engine ConfigParam | ConfigParam 85 (schema_version=2) |

The `(format, selector)` key `{Basic, 0x4a564d31}` identifies this engine
in the registry.  The literal selector name `"JVM1"` is preserved for
descriptor stability; the v2 in `JvmContractAccountState` /
`JvmCallDescriptor` schema_version refers to the wire format of the
state and call envelopes, not the engine selector itself.  `vm_mode = 0`
is the only valid mode, matching Uno's reserved-mode pattern.  JVM
chain identity and gas/class limits live in ConfigParam 85, not in
`vm_mode`.  A future engine revision that changes descriptor semantics
must use either a new selector or a documented migration boundary; it
must not silently reinterpret the existing descriptor.

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
- TL-B schema for `JvmContractAccountState` (JVAC) per-account state cell
  and `JvmCallDescriptor` (JVI2) inbound message body
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
  `PersistentMap` / `PersistentList` key-value encodings.  Arbitrary Java
  object graphs and Java static fields are not persisted.
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
  opcodes. Public `java.lang.invoke` remains outside the runtime profile.
- Add the TOS fixed floating-point engine for Java `float`/`double` opcodes:
  strictfp-equivalent binary32/binary64 arithmetic with pinned rounding,
  NaN/signed-zero/infinity/subnormal behavior, plus conformance tests for all
  supported platforms
- Add class-load-time validation for unsupported class-file versions and
  deterministic runtime traps for forbidden host-observing packages/classes.
  In the classpath, broad host packages such as `java.net` and host-backed
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
consensus-safe behavior. The target is a per-transaction arena with explicit
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
  - `account_policy()` returns `EngineDefined` with
    `admits_engine_create_account_actions=true` and activation code
    `0x4a`; the host accepts any wc=3 address and lets the engine emit
    `action_create_account` to materialize per-contract accounts at the
    deterministic `derive_jvm_contract_address` output
  - `run_compute()` decodes the per-account `JvmContractAccountState`
    from `input.current_data` (skip with `sk_no_state` if null), checks
    `stdlib_hash` against ConfigParam 85, and dispatches to the
    installed Avata resolver
- `jvm/core/config-param.h` / `.cpp`:
  - `build_jvm_workchain_descr()` (ConfigParam 12 descriptor)
  - `build_jvm_config_cell()` / `parse_jvm_config_cell()` (ConfigParam
    85, schema_version=2)
  - ConfigParam 85 fields: `chain_id`, `schema_version`, `gas_price`,
    `max_gas_per_tx`, `max_class_bytes`, `max_heap_bytes`,
    `max_storage_cells`, `class_file_major = 52`, `gas_schedule_version`,
    and `stdlib_hash` — `max_total_class_bytes` is NOT carried (no
    shared class store under per-account topology)
- `jvm/core/zerostate.h` / `.cpp`:
  - `build_jvm_zerostate_accounts_cell()`: returns the canonical empty
    `HashmapAugE(256, aug_ShardAccounts)` cell — wc=3 has no preexisting
    accounts at genesis; per-contract accounts materialize later via
    `action_create_account`
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
  admitted. `Math.random`, host-libm transcendental functions, and
  float/double string parse/format helpers stay out until pinned software
  implementations exist. `StrictMath` is not shipped in the profile.
- `java.lang.System` — no time, environment, properties, or IO streams; exposes
  only deterministic chain APIs: `blockNumber()`,
  `blockTimestamp()`, `randSeed()` (from `context.rand_seed`),
  `callerAddress()`, `value()`, and `sendMessage(destAddr, value, body)`
- `java.lang.OutOfGasError` and `java.lang.ContractViolationError`, both
  subclasses of `java.lang.Error`
- `java.lang.ContractEntry` — annotation type; marks a `public static`
  method as callable from an inbound message (referenced by Phase 6 ABI)
- `java.lang.PersistentMap<K,V>` — ordered key-value map backed by the
  cell tree; the primary persistent data structure for contracts
- `java.lang.PersistentList<T>` — append-only list backed by the cell tree
- `java.lang.Event` — emit a log entry staged in side effects

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
whitelisted `java.lang` runtime and contract APIs. The build tool must
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

**Approach:** restrict the heap surface that is serialized.
Rather than attempting a general object-graph serializer, require that all
persistent contract state flow through `Storage`, `Mapping`, and future
cell-backed persistent containers. Application classes may not declare static
fields except compile-time `static final` primitive/String constants with
`ConstantValue`; javac features that synthesize mutable static state, including
enum constants, are outside the contract profile. The contract heap between
calls is then reduced to:
- storage cells addressed by explicit slot keys
- cell roots for future `Persistent*` containers
- no heap-allocated mutable objects survive across transaction boundaries

Allowed persisted values must be a closed set: primitive integers/booleans,
fixed-size byte arrays or addresses, deterministic strings if admitted by
Phase 0, and cell-backed persistent roots. Ordinary object references, arrays
of references, and mutable heap objects are transient only.

This eliminates the general object-graph serialization problem at the cost of
restricting contracts to a structured state model. It is the correct
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
  - Native C++ implementations of `java.lang.Persistent*` that operate
    directly on `vm::Cell` trees (no intermediate Java heap objects for stored
    data)
- TL-B schema for the per-account state cell `JvmContractAccountState`
  (magic `JVAC`, schema_version=2):
  ```
  jvm_contract_account#4a564143
    schema_version:uint8 (=2)
    stdlib_hash:bits256
    class_hash:bits256
    class_bytes:^Cell                             // JvmStorageValue-encoded
    storage_root:(Maybe ^Cell)
    manifest_root:(Maybe ^Cell)
    = JvmContractAccountState;
  ```
  One cell per wc=3 account, stored in `account.data`; the matching
  `account.code` is the activation marker (single byte `0x4a`).
  `class_bytes` is held as a `^Cell` so the underlying cell DB
  physically deduplicates contracts that share identical bytecode
  (verified at `crypto/vm/db/CellStorage.cpp:267`).  Java static fields
  are not encoded.

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
jvm_call#4a564932
    schema_version:uint8  // 2
    method_id:uint32      // first 4 bytes of keccak(method_sig)
    args:^ArgsCell
    = JvmCallDescriptor;
```

The destination wc=3 account address already names the contract, so the
descriptor body carries only `method_id` + the typed args cell.  The
account's per-account `manifest_root` maps `method_id` to
`(class_name, method_name, method_spec)`; the resolver loads the
contract's `class_bytes` from the same per-account state cell.
`method_id` selects the public static entry method.  `ArgsCell` encodes
arguments using a compact binary encoding derived from the method
descriptor signature.

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

Typed args are descriptor-checked against void-return method specs and admit
only deterministic contract ABI values: `boolean`, `int`, `long`,
`java.lang.Address`, `java.lang.Uint256`, `java.lang.Bytes32`,
`java.lang.Bytes4`, and variable-length `java.lang.Bytes`.

Only `public static` methods annotated with `@ContractEntry` are callable from
inbound messages. Other methods may only be called from within the same
transaction's execution.

Class-load validation must reject duplicate `method_id` values among callable
entry methods in the same class. The ABI also defines a deploy descriptor
(see below) and the deterministic per-contract address derived through the
five-input nested formula in `derive_jvm_contract_address_from_state`
(`jvm/core/deploy-abi.cpp:215-232`):
`address_commit = sha256(deployer || salt || init_args_cell.hash)`,
`manifest_root_hash = manifest_cell.hash()` (or zeros when manifest is null),
`contract_address = sha256("TOS-JVM-CONTRACT-v2" || deployer ||
address_commit || class_hash || manifest_root_hash)`.  The
`address_commit` indirection authenticates first-activation
`msg.src.addr == state.deployer` and binding `manifest_root_hash` prevents
post-deploy method-id redirection.

**Per-account method manifest (`JvmMethodManifest`):**
```
jvm_method_manifest#4a564d32
    schema_version:uint8  // 1
    count:uint16
    entries:^(JvmMethodManifestEntry chain)?
    = JvmMethodManifest;

jvm_method_manifest_entry
    method_id:uint32
    has_next:bit
    next:^(JvmMethodManifestEntry)?
    class_name:^StringCell
    method_name:^StringCell
    method_spec:^StringCell
    = JvmMethodManifestEntry;
```

The destination wc=3 address already names the contract, so the manifest
entry no longer carries `contract_id`.  The manifest is per-account
(stored in `JvmContractAccountState.manifest_root`), keyed by `method_id`
only, and is immutable after deploy.

Implementation status: `jvm/core/message-abi.*` implements the JVI2 call
descriptor envelope and `JvmNativeEngine` rejects malformed inbound bodies
before entering an installed runtime.  `jvm/core/class-manifest.*`
implements the per-account `JvmMethodManifest` (JVM2): the encoder
rejects duplicate `method_id` entries, admits only ASCII Java internal
class names, Java identifier method names, and supported static-void
descriptors.  The linked Avata runtime resolver
(`linked_avata_resolve_call_target` in `jvm/core/avata-runtime.cpp`)
looks up the manifest entry by `method_id`, loads `class_bytes` from
`JvmContractAccountState.class_bytes`, and resolves a static-void Avata
method before executing the gas/memory transaction.  Static-void `()V`
entries accept only the canonical empty args cell; parameterized
entries must use the deterministic `JVMA` typed args cell.
The deploy envelope, typed `ArgsCell` codec/descriptor validator, and
typed Avata invocation bridge are implemented.  The linked resolver
caches Avata VMs by the contract's `class_hash` (32 B); two contract
accounts that deploy the same class share one cached VM, mirroring
the cell-DB physical dedup of `class_bytes` itself.  The resolver
installs the per-account class bytes through
`avata_define_contract_class()`, resolves the static-void manifest
entry, and passes decoded `boolean`, `int`, `long`, `Address`,
`Uint256`, `Bytes32`, `Bytes4`, and `Bytes` arguments through the
Avata C ABI.

**Deploy descriptor (`JvmDeployDescriptor`):**
```
jvm_deploy#4a564d44
    schema_version:uint8  // 2
    deployer:bits256
    salt:bits256
    class_hash:bits256    // sha256(class_bytes)
    class_name:^StringCell
    class_bytes:^BytesCell
    init_args:^ArgsCell
    = JvmDeployDescriptor;
```

`jvm/core/deploy-abi.*` implements this envelope, validates `class_hash`
against the supplied bytes, validates the class name, and derives the
deterministic per-contract wc=3 address via `derive_jvm_contract_address`.
The deployer wraps the descriptor in a TLB `StateInit{code=0x4a marker,
data=^JvmContractAccountState}` (`encode_jvm_state_init_cell`) and emits
an `action_create_account#4a435241` whose `dest_addr` is that derived
address.  ConfigParam 85 `max_class_bytes` is enforced at deploy.
Callable method ids remain the responsibility of the verified
manifest/admission layer.  Runtime resolution loads the per-account
class bytes from `JvmContractAccountState.class_bytes` into the
`class_hash`-keyed VM cache entry on first call to that contract.

**Outbound action encoding:**
Contract code may enqueue outbound messages by calling
`java.lang.System.sendMessage(destAddr, value, body)`. This builds a standard
TOS action list cell compatible with the host action phase. The encoding mirrors
the existing TVM action list model so the host action phase requires no changes.

**Effort:** 2–4 weeks

---

### Phase 7 — RPC namespace

**Goal:** Implement `jvm_*` JSON-RPC endpoints through the full-node RPC
surface. The original `WorkchainRuntimeServices::register_rpc` hook
remains a design target, but the current implementation mirrors the
existing EVM/Uno pattern directly in `validator-engine`: `JsonRpcServer`
dispatches `jvm_*` methods to `handle_jvm_rpc_method()`, which resolves
live ConfigParam 85 through liteserver and, for stateful methods, loads
the per-contract wc=3 account at the request's `contractAddress` when
the client does not supply `accountStateBoc`. These are non-consensus
surfaces and must not mutate block state.

**Endpoints:**
- `jvm_deployContract`: submit a class file and deploy descriptor;
  derives the deterministic per-contract wc=3 address and returns it
  as `contractAddress` together with `deployDescriptorBoc`.  The
  client wraps the descriptor in `StateInit` and emits
  `action_create_account` from a wc=3 sender to materialize the
  contract account at that address.  Params: `classBytes` (0x hex),
  `className`, `deployer` (0x-32), `salt` (0x-32, optional).
- `jvm_callContract`: build a `JvmCallDescriptor` cell and return it
  as a hex-encoded BOC (`callDescriptorBoc`).  The descriptor can be
  submitted as an internal message body to the contract address or
  passed to the local runner.  Params: `contractAddress` (0x-32;
  legacy alias `contractId` accepted), `methodId` (uint32), `gasLimit`
  (optional), `accountStateBoc` (optional hex BOC of the
  `JvmContractAccountState` cell; legacy alias `executorStateBoc`
  accepted — when omitted, full-node RPC loads the live wc=3 account
  data at `contractAddress` from the latest masterchain snapshot).
- `jvm_getContractState`: return `className`, `classHash`, and
  `storageRootHash` for a deployed contract.  Params:
  `contractAddress` (0x-32; legacy alias `contractId` accepted),
  `accountStateBoc` (optional hex BOC).  When omitted, full-node RPC
  loads the live per-account state at `contractAddress` from the
  latest masterchain snapshot.  The handler reads class metadata from
  `JvmContractAccountState` and enumerates up to 100 storage slots
  from the per-account `storage_root`.
- `jvm_getReceipts`: return event receipts for a given wc=3 block
  range.  Params: `contractAddress` (0x-32; legacy alias `contractId`
  accepted), `fromBlock`, `toBlock`.  Full-node RPC reads the wc=3
  account history at `contractAddress`, decodes committed JVME event
  payloads from transaction out-msgs, and returns chronological
  receipt objects with bounded `scannedTransactions` / `truncated`
  metadata.  No singleton-executor lookup; the receiving account
  itself is the contract.

Admission (`jvm_deployContract` pre-check) validates class name shape
and ConfigParam 85 `max_class_bytes` as a developer convenience;
consensus compute re-validates on execution.

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
- OpenJDK opcode compatibility tests: floating-point arithmetic,
  `monitorenter`/`monitorexit`, exceptions, arrays, interface dispatch, and
  class initialization (lambdas/`invokedynamic` are permanently unsupported —
  no test needed)
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
| 3 | TOS contract `rt.jar` + `java.lang` domain APIs | 8–12 weeks |
| **4** | **Heap serialization (cell codec)** | **3–5 months** |
| 5 | Gas metering | 4–6 weeks |
| 6 | Message ABI | 2–4 weeks |
| 7 | RPC namespace | 2–4 weeks |
| 8 | Hardening and integration testing | 6–8 weeks |
| **Total** | | **~14–24 engineer-months** |

Phase 4 (heap serialization) dominates the estimate. The restricted-state
model (persistent state flows only through `java.lang.Persistent*` types)
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

Last updated: 2026-05-12.  All numbered phases (0–8) plus JVM v2
account-native topology landed; post-v2 wc=3 wallet bootstrap (Phases
A–G) landed on top.  91/91 `test-workchain-execution-registry` C++
tests pass plus all standalone Avata Java tests (initial run +
determinism replay); `tosctl/.../jvm_codec` Rust crate ships 13/13
unit tests green.

| Phase | Status | Notes |
|---|---|---|
| Phase 0 — Design | ✅ | Roadmap, restricted API profile, TL-B schemas, ConfigParam 85 schema, engine identity, and activation checklist are written. All six pre-Phase-1 design questions answered (see "Design Decisions" section). `THIRD_PARTY_NOTICES.md` records Avata ISC and SoftFloat BSD-3-Clause licenses. Formal standalone stub-registry test (no real bytecode) not yet isolated as a named test case, but `test-workchain-execution-registry` exercises the same path end-to-end |
| Phase 1 — Avata fork | ✅ | Fork imported, renamed, and slimmed to interpreter + Avata/TOS `rt/` only. SoftFloat 3e deterministic float/double, tiered opcode gas schedule, verifier profile (version gate, forbidden attrs/classes, static-field/clinit/enum/sync/native/finalizer policy, ContractEntry enforcement), object-identity counter, arena transaction reset, non-deterministic syscall removal, and all test harnesses complete. Reserved and undefined opcodes (`breakpoint` 0xca, undefined range 0xcb–0xfd, `impdep2` 0xff — 53 byte values total) are rejected at class-load time with `VerifyError` by `verifyCodeOpcodes` in `machine.cpp`; application class methods are bytecode-walked before any execution, eliminating a DoS vector where a hand-crafted class file could previously crash the validator process via `abort()` |
| Phase 2 — Framework integration | ✅ | `JvmNativeEngine`, ConfigParam 85 parsing, `init_jvm_workchain`, `JvmAvataRuntime`, capability bits, CMake integration, linked Avata runtime bridge, `build_jvm_zerostate_accounts_cell()` (`jvm/core/zerostate.{cpp,h}`), `JvmConfig::default_activation()` factory (chain_id=3, gas_schedule_version=1, tiered opcode costs, 13 helper costs), and `jvm-config-param-cell` Fift word in `create-state.cpp` complete. `ZerostateAccountsCell` and `JvmActivationConfigBuildsAndRoundTrips` tests pass |
| Phase 3 — Contract stdlib | ✅ | `rt.jar` / `api.jar` built from `jvm/avata/rt/` tree. All required `java.lang` classes present: Object, String, Class, Throwable, Error hierarchy, Math (deterministic subset), System (chain context only), OutOfGasError, ContractViolationError, ContractEntry annotation, Storage, Mapping, PersistentMap, PersistentList, Event. `javac` and `java` wrapper tools cover contract compile/run/admission workflow including `@ContractEntry` checks. `rt/check-profile.sh` and `rt/check-native-profile.sh` gate the build against profile regressions |
| Phase 4 — Heap serialization | ✅ | Restricted persisted-state model: only explicit `Storage`/`Mapping`/`PersistentMap`/`PersistentList` state is persisted; transient heap is discarded at transaction boundary via arena checkpoint rollback (`checkpointContractHeap` / `resetContractHeap`). Mutable static fields are forbidden at class-load time (`VerifierProfile`: `makeStaticField` → VerifyError). `JvmCellCodec` encodes/decodes the canonical `JvmContractAccountState` (JVAC, schema_version=2) cell — one cell per wc=3 account, holding `class_hash`/`class_bytes`/`storage_root`/`manifest_root`. `JvmStorageCellHost` provides per-account cell-backed 256-bit-slot storage with nested snapshot semantics.  No general Java object-graph serializer needed |
| Phase 5 — Gas metering | ✅ | Tiered default opcode schedule (`gas_schedule.h`), per-opcode table in interpreter (`Machine::opcodeGasCosts[256]`), helper-gas table for storage/event/native surcharges, ConfigParam 85 gas-schedule codec (`avata_set_opcode_gas_costs`, `avata_set_contract_helper_gas_costs`), and OOG trap complete. All gas paths covered by `TieredOpcodeGasSchedule` and `HelperGasOutOfGasRegression` tests |
| Phase 6 — Message ABI | ✅ | `JvmCallDescriptor` (JVI2, schema_version=2; carries only `method_id` + `args` since the wc=3 destination address already names the contract), typed `JVMA` args codec (bool/int/long/Address/Uint256/Bytes32/Bytes4/Bytes), `JvmDeployDescriptor` (schema_version=2 with explicit `manifest_root`), per-account `JvmMethodManifest` (JVM2, keyed by `method_id` only — duplicate ids rejected at encode/parse), `derive_jvm_contract_address("TOS-JVM-CONTRACT-v2")` for the deterministic per-contract wc=3 address, `encode_jvm_state_init_cell` for the canonical `StateInit{code=0x4a marker, data=^JVAC}` consumed by `action_create_account`, ConfigParam 85 `max_class_bytes` enforced at deploy, per-account class loading into Avata threads keyed by `class_hash`, pre-runtime inbound validation, typed static-void invocation, and linked resolver integration all implemented.  Outbound action encoding: committed events flow through `event-host` to `OutList` action cells compatible with the TOS action phase |
| Phase 7 — RPC namespace | ✅ | `jvm_deployContract`, `jvm_callContract`, `jvm_getContractState`, `jvm_getReceipts` — request/response codecs and admission checks in `jvm/core/rpc.{h,cpp}`. Full-node routing is wired through `validator-engine/json-rpc-server-jvm.cpp`: `JsonRpcServer` recognizes `jvm_*`, fetches live ConfigParam 85 from the latest masterchain config proof, passes the installed Avata runtime from `current_jvm_compute_runtime()`, and for stateful methods loads the per-contract wc=3 account at the request's `contractAddress` when `accountStateBoc` is omitted. `jvm_deployContract` returns `deployDescriptorBoc` + `contractAddress` (the deterministic v2 wc=3 account address). `jvm_callContract` accepts optional `argsBoc`; when runtime + per-account state are present it runs local simulation and appends `localResult` {success, outOfGas, outOfMemory, gasUsed, vmLog, newStateBoc}. `jvm_getContractState` enumerates storage slots (up to 100) from the supplied per-account state and returns `storageSlots` + `storageTruncated`. `jvm_getReceipts` resolves the wc=3 account at the requested `contractAddress`, pages through its transaction history, decodes committed JVME event messages from transaction out-msgs, and returns bounded chronological receipts with `truncated`/`scannedTransactions` metadata. Legacy `contractId` / `executorStateBoc` JSON parameter names are accepted as aliases for `contractAddress` / `accountStateBoc` for transition. |
| Phase 8 — Hardening | ✅ | End-to-end coverage: `JvmEndToEndDeployCallSequence` (deploy→call→call→determinism replay), `MultiContractIsolatedStorageWithSharedClass` (per-account storage isolation + Cell DB physical class_bytes dedup), `JvmDeterminismReplay` (10-step engine replay with byte-identical new_data hashes), `JvmActivationConfigBuildsAndRoundTrips` (ConfigParam 85 schema=2 round-trip), `JvmEngineDispatchesAccountStateToRuntime` and `JvmEngineRejectsMalformedAccountState` (engine policy gate). Verifier negative tests (`VerifierProfile`, `CoreTrapProfile`), float determinism (`DeterministicFloatTest`), and path-sanitization tests (`StackTraceSourceFileTest`: unix/windows/plain/no-SourceFile) all pass. Float conformance vector (`FloatConformanceVector.java` + `float-conformance-reference.txt`): 160-line hex-bit reference covering all float/double opcodes and edge cases (NaN, ±0, ±Inf, subnormals, conversions, array round-trips); verified by `check-float-conformance` on every build. Performance baseline (`PerfBaseline.java`): deterministic checksum gated by `check-perf-baseline` makefile target (wired into `run-test`); reference stored in `test/perf-baseline-reference.txt`; `regen-perf-baseline` updates it when the gas schedule intentionally changes. Cross-platform float-vector parity verified: `check-float-conformance` produces a byte-identical 160-line reference vector on both Linux x86_64 and macOS arm64 (Apple Silicon) — sha256 `9f7f29d26a55def0abb74db60402fb0ff634dc08b7057e9eb20cf76a52234d4a` on both hosts. SoftFloat 3e is therefore confirmed deterministic across the two real validator host architectures; no WASM validator target exists in TOS today (the `USE_EMSCRIPTEN` option only builds FunC/Fift), so no third platform is in scope |
| JVM v2 account-native topology | ✅ | Each Java contract is a real wc=3 account at a deterministic 256-bit address. Host plumbing (`EngineDefined` policy + `action_create_account#4a435241` TLB + handler), per-account state cell `JvmContractAccountState` (JVAC, schema=2), call descriptor `JvmCallDescriptor` (JVI2), per-account method manifest `JvmMethodManifest` (JVM2), `derive_jvm_contract_address("TOS-JVM-CONTRACT-v2")`, `encode_jvm_state_init_cell`, ConfigParam 85 schema=2 (no `max_total_class_bytes`), empty wc=3 zerostate, deploy RPC returning `contractAddress`, full v1 path removed (no `JvmExecutorState` / global `class_state_root` / `derive_jvm_contract_id` / `JvmAvataClassDefinition` / `install_jvm_deploy_descriptor` / SingletonExecutor `account_policy`). 56/56 tests pass; covered by `JvmEndToEndDeployCallSequence`, `JvmEngineDispatchesAccountStateToRuntime`, `ContractAccountStateCodecRoundTripsClassBytesAndStorage`, `DeriveJvmContractAddressIsDeterministicAndSensitive`, `DeriveJvmContractAddressFormulaMatchesSpec`, `MethodManifestRoundTripsAndRejectsDuplicates`, `EncodeJvmStateInitCellPassesTlbValidation`, `EngineDefinedPolicyValidates`, `RpcDeployContractReturnsContractAddress`, `RpcCallContractAcceptsAddressNotContractId`, `RpcGetContractStateFetchesPerAccount`, `MultiContractIsolatedStorageWithSharedClass`, `JvmDeterminismReplay`, `ActionCreateAccountTlbRoundTrip`, `ZerostateAccountsCellIsEmpty`, plus the existing storage / events / config / Avata-transaction / EVM+Uno tests |
| Lambda / `invokedynamic` support | ⛔ | **Not supported in any version.** `invokedynamic` is rejected at three independent layers: (1) `CONSTANT_MethodHandle`, `CONSTANT_MethodType`, and `CONSTANT_InvokeDynamic` constant-pool entries throw `VerifyError` at class load; (2) the `BootstrapMethods` attribute is in the forbidden attribute list; (3) the `invokedynamic` opcode throws `VerifyError` in the interpreter as a fallback. `java.lang.invoke` is absent from `rt.jar` and `api.jar`. Lambda expressions and method references compiled by `javac` are rejected. The equivalent pattern — anonymous inner classes — is fully supported. There is no plan to support `invokedynamic` in v2 or any future version: a deterministic consensus VM cannot safely admit arbitrary bootstrap method linkage, and the anonymous-inner-class pattern covers all practical contract use cases without it. Decision and rationale documented in `jvm/avata/README.md` |
| Per-account contract model | ✅ | Same scope as JVM v2 account-native topology above; tracked as one row in this table going forward |
| Phase A — `java.lang.Context` | ✅ | Per-call chain-context primitives that OpenZeppelin-style contracts depend on: `caller()`, `value()`, `contractAddress()`, `blockNumber()`, `blockTimestamp()`, `chainId()`, `isStaticCall()`, `requireCaller(Address)`. Values are pulled from the inbound message + `WorkchainComputeContext` that `run_compute` already receives, pinned in Avata thread state via `avata_set_contract_context`, and surfaced through JNI getters charged at one CONTEXT_READ helper-gas unit each (default 5 gas). C ABI in `jvm/avata/include/avata/context.h`; install paths in `jvm/core/avata-execution.cpp` (`execute_jvm_avata_transaction` installs the context per call) and `jvm/core/avata-runtime.cpp`. Inbound-message parsing (addr_std src + Uint256 attached value) is extracted into `jvm/core/inbound-parse.{h,cpp}` so the dispatch-engine first-activation auth path and the avata-runtime context plumbing share a single canonical implementation. `Ownable` / `Ownable2Step` / `AccessControl` gain no-arg overloads that pull the caller from `Context.caller()`; the existing Address-caller overloads remain `@Deprecated` for one release. Pinned by `ContextTest` (every getter traps with `ContractViolationError` when no host is installed). Commit `1f123df22`. |
| Phase B — `java.lang.Crypto` natives | ✅ | Five signature/hash primitives: `sha256`, secp256k1 `ecRecover`, ECDSA `ecdsaVerify`, `ed25519Verify`, BLS12-381 `bls12381Verify` (min-pk arrangement). Installed via an `AvataCryptoHost` host (C ABI in `jvm/avata/include/avata/crypto.h`); standalone Avata builds leave the host unset so sigverify traps deterministically in the test runner, while validator builds install a production host (`jvm/core/crypto-host.{h,cpp}`) that binds to libsecp256k1 + libsodium + blst (all already vendored under `third-party/`). Gas defaults track EVM precompile cost classes: SHA-256 60+12/B, ecRecover/ECDSA 3000, Ed25519 2000, BLS 43000. ConfigParam 85's helper-gas table grew 14→21 entries to accommodate the new helpers. Pinned by `CryptoTest` (keccak256 known-answer + trap-when-no-host). Commit `1f123df22`. |
| Phase C — ABI extensions + EIP-712 | ✅ | `java.lang.ABI` adds Solidity-style helpers: `encodePacked(Object...)` (tight concatenation, no length prefixes, no zero padding), `encode(Object[])` (32-byte-padded encode), `encodeWithSelector(bytes4, Object[])`, `encodeWithSignature(String, Object[])`. Type whitelist is the contract profile (Uint256, Bytes32, Bytes4, Address, Bytes, byte[], String, Boolean, Integer/Long/Short/Byte); unknown types raise `IllegalArgumentException` so contracts cannot accidentally serialize a host-shaped `Object.toString`. `java.lang.EIP712` provides `domainSeparator` / `typeHash` / `hashStruct` / `digest` using the canonical EIP-191 0x1901 prefix; composes on top of `Crypto.keccak256` — no host needed. A second `domainSeparator` overload pulls `chainId` from the active Context (the form OpenZeppelin permits / votes write against). `Contract.revert(String signature, Object[] args)` ABI-encodes the args into the `ContractRevertException` payload so callers decode the error symmetrically. Pinned by `EIP712Test`, `ABIPackedTest`. Commit `aeff6f502`. |
| Phase D — wc=3 wallet test + Wallet realization | ✅ | Same commit as Phase C. `Wallet.java` skeleton (still test-scoped at this point) stores the raw Ed25519 public key, verifies the spend signature via `Crypto.ed25519Verify(ownerKey, digest, sig)`, binds the replay digest to `Context.contractAddress`, and emits outbound transfers via `System.sendMessage`. Four standalone-runner tests landed: `ContextTest`, `CryptoTest`, `EIP712Test`, `ABIPackedTest`. All 38+ Java tests pass twice (initial run + determinism replay). Commit `aeff6f502`. |
| `System.sendMessage` outbound primitive | ✅ | Same installable-host topology as Storage/Event/Crypto: `AvataMessageHost` C ABI in `jvm/avata/include/avata/message.h`; `JvmMessageHost` adapter in `jvm/core/message-host.{h,cpp}` serializes each emitted message as a canonical `action_send_msg` cell carrying a `MessageRelaxed` `int_msg_info` with `src=addr_none` (filled by the host's `check_replace_src_addr`), `dest=addr_std(wc, addr)`, `value=Uint256 tomis`, and the contract-supplied body. `execute_jvm_avata_transaction` installs the message host between events and the contract transaction, commits on success, rolls back on revert / OOG / OOM so a failed call emits zero outbound messages. `build_jvm_combined_action_list` splices the existing event `OutList` with one `action_send_msg` node per outbound message. Caps: `kJvmMessageCountMax = 12 messages/tx`, `kJvmMessageBodyMaxBytes = 128 016 byte body` — keeps spine + payload chain comfortably under `vm::CellTraits::max_depth`. Gas: `AVATA_CONTRACT_HELPER_MESSAGE_BASE` (default 500) + `MESSAGE_BYTE` (default 1); helper-gas table grew 21→23 entries. Java surface: `java.lang.System.sendMessage(Address, Uint256, byte[])` + zero-body overload. Pinned by `SendMessageTest`. Commit `8a1390170`. |
| Phase E — `java.lang.Wallet` promoted to rt.jar | ✅ | `jvm/avata/test/Wallet.java` moves to `jvm/avata/rt/java/lang/Wallet.java` under package `java.lang` and `extends Contract` so it can be referenced by other admitted contracts (e.g. `extends Wallet` for paymaster / multi-sig variants), reuses `Contract.revert()`, and is picked up by api.jar / rt.jar through the standard classpath walk. Slot constants (`SLOT_OWNER_PUBKEY` / `SLOT_NONCE` / `SLOT_INIT_FLAG`) are `public static final String` so Phase F's genesis seeder hashes the same names the live runtime does (no drift between off-chain seeders and on-chain execution). Internal helpers (`loadNonce`, `requireInitialized`, `digest`, `dispatch`, `dispatchOne`) become `protected static` so subclasses can swap one piece (e.g. override `dispatch()` to inject fee-burning) without re-implementing the whole entry surface. `jvm/avata/src/avata/contract-profile.h` admits `java/lang/Wallet`. `doc/jvm-rt.md` adds Wallet to the Initial classes list and the OpenZeppelin capability mapping table with the consensus-stability caveat. `WalletTest.java` pins standalone-runner behaviour: arg validation traps, re-init guard, slot derivation invariant. Commit `6e9b7f48f`. |
| Phase F — wc=3 genesis seeding | ✅ | Closes the wc=3 bootstrap deadlock (previously the wc=3 ShardAccounts dict was empty at genesis, but `action_create_account` requires a same-workchain sender → no first contract was deployable). `jvm/core/genesis-wallet.{h,cpp}` materializes one wallet per declaration as a fully-active wc=3 account with storage_root pre-populated as if `Wallet.init(ownerPubKey)` had already run, manifest_root carrying `init`/`execute`/`getNonce`, JVAC (schema=2) with sentinel all-zero deployer, and address derived through `derive_jvm_contract_address_from_state` (the same formula the dispatch-engine recomputes on every call, so the dispatch engine accepts the genesis account without any new code path). `jvm/core/zerostate.{h,cpp}` gains a parameterized `build_jvm_zerostate_accounts_cell(wallets, stdlib_hash, class_bytes)` overload; the zero-parameter form still returns the canonical `hme_empty$0` so chains that bootstrap purely via `action_create_account` from an external sender remain supported. Fift word `jvm-zerostate-from-alloc` (in `crypto/block/create-state.cpp:648`, registered at line 1083) mirrors `evm-zerostate-from-alloc`: stack signature `( T class_bytes stdlib_hash -- accounts_cell )` where T is a tuple of `(owner_pubkey:32B, salt:32B, balance:int)`. Length validation runs before the C++ builder so malformed declarations surface as a clear `fift::IntError`. Five C++ tests pin consensus-stable invariants: `GenesisWalletBuildIsDeterministic`, `GenesisWalletAddressBindingMatchesDispatchGate`, `GenesisWalletStorageSlotsMatchWalletInit`, `GenesisWalletDifferentSaltProducesDifferentAddresses`, `GenesisZerostateAccountsCellEmbedsAllWallets` (91/91 total; up from 86). Commit `652d39c5e`. |
| Phase G — tosctl Rust `jvm_codec` | ✅ | Foundation layer for the wc=3 wallet CLI. Faithful Rust port of every consensus-side cell codec a wc=3 wallet client needs, under `tosctl/src/node-control/contracts/src/jvm_codec/`: `args.rs` (`JvmArgs` / `JvmTypedArg` + `encode_jvm_args`; mirrors `jvm_args#4a564d41`), `call_descriptor.rs` (`JvmCallDescriptor` + `encode_jvm_call_descriptor`; mirrors `jvm_call#4a564932`), `deploy_descriptor.rs` (`JvmDeployDescriptor` + encoder; mirrors `jvm_deploy#4a564d44`), `state_init.rs` (`encode_jvm_state_init_cell` wrapping a JVAC for `action_create_account`; single-byte `0x4a` code marker + JVAC data), `storage_value.rs` (chunked storage-value encoding, 127 B per chunk + 1-bit has_next, `max_depth − 16` wrapper margin), `address.rs` (`compute_jvm_class_hash` / `compute_jvm_address_commit` / `compute_jvm_manifest_root_hash` / `derive_jvm_contract_address`, matching the C++ `sha256("TOS-JVM-CONTRACT-v2" || deployer || address_commit || class_hash || manifest_root_hash)` formula). Reuses `keccak_hash::keccak_256` and `sha2::Sha256` already available in the tosctl workspace (only new declaration is an explicit `sha2` Cargo dep). 13 unit tests cover encode determinism, ref-shape invariants, address-formula sensitivity, and storage-value chunk linking. Out of scope for this commit (future follow-ups): `action_create_account#4a435241` OutAction builder, `JvmWalletContract` trait + concrete impl, `jvm-wallet` CLI subcommand family, `jvm_*` `ClientJsonRpc` bindings. Commit `6a28d551e`. |

**Mainnet-activation blockers (post-Phase-G):**

- **`stdlib_hash` is not yet pinned.** `JvmConfig::default_activation()`
  emits an all-zero `stdlib_hash` (`jvm/core/config-param.cpp:285` —
  "stdlib_hash stays zero-initialized until the stdlib archive is
  locked in").  Before mainnet wc=3 activation, governance must build
  the canonical `rt.jar`, compute `sha256(rt.jar)`, and ship that as
  the ConfigParam 85 `stdlib_hash`.  Until that value is non-zero
  every JVAC `state.stdlib_hash` check at compute time will be
  meaningless (any deploy with `stdlib_hash=0` will pass).
- **Initial genesis wallet keypairs unset.** Phase F gives the
  capability to pre-seed wc=3 wallets; the keypairs themselves are a
  governance decision (which Ed25519 keys, with which initial
  balances, at which salts) that has not been made.  Without at least
  one genesis wallet the chain is still in the empty-default
  configuration and cannot deploy a first contract; see
  `doc/jvm-mainnet-activation.md` for the activation runbook.
- **Canonical `java.lang.Wallet` class_bytes not pinned.** The genesis
  seeder hashes `wallet_class_bytes` (passed as a parameter) into both
  the address derivation and the storage layout.  Until governance
  pins a specific `Wallet.class` byte sequence (compiled from the rt.jar
  source at a specific revision), genesis-seeded addresses cannot be
  computed off-chain by clients.  The contract source itself is stable
  (`jvm/avata/rt/java/lang/Wallet.java`); the missing artifact is the
  versioned compiled bytecode + its class_hash.

These are operational pinning decisions, not code changes — the
implementation is feature-complete.

**Resolved during the run-up to v2:**
- Cross-platform float conformance: `check-float-conformance` (160-line
  hex-bit reference covering all float/double opcodes and edge cases —
  NaN, ±0, ±Inf, subnormals, conversions, array round-trips) is
  verified on both real validator host architectures.  Linux x86_64
  and macOS arm64 (Apple Silicon) produce a byte-identical output
  vector with sha256 `9f7f29d26a55def0abb74db60402fb0ff634dc08b7057e9eb20cf76a52234d4a`,
  confirming that SoftFloat 3e is deterministic across architectures.
  No WASM full-validator build exists in TOS (the `USE_EMSCRIPTEN`
  option targets FunC/Fift only), so no third platform is in scope.
  Apple Silicon native build of the Avata interpreter was enabled as
  part of this verification — `jvm/avata/makefile` and
  `jvm/avata/src/tools/object-writer/mach-o.cpp` carry the host
  arch-detection fix, the macosx-arm64 cflags/lflags, the
  `CPU_SUBTYPE_ARM64_ALL` (was `CPU_SUBTYPE_ARM_V8`) Mach-O subtype
  fix, and the `LC_BUILD_VERSION` load command needed by modern ld64.
- Full-node JVM RPC wiring: `JsonRpcServer` routes `jvm_*` requests
  through `handle_jvm_rpc_method()`, resolves ConfigParam 85 from a
  liteserver config proof, injects the Avata runtime installed by
  `init_jvm_workchain()`, and for stateful methods loads the live
  per-contract wc=3 account at the request's `contractAddress` when
  no `accountStateBoc` is supplied.
- ConfigParam 85 concrete activation values:
  `JvmConfig::default_activation()` encodes chain_id=3, gas_price=1000,
  max_gas_per_tx=1M, max_class_bytes=64 KiB, max_heap_bytes=4 MiB,
  max_storage_cells=65536, tiered opcode and helper costs from
  `gas_schedule.h`.  Values are a baseline; governance can adjust via
  ConfigParam update before or after mainnet activation.
- v2 account-native topology landed and v1 SingletonExecutor path
  removed (see §"v1 removal" further below for the full list of
  deleted symbols).

## JVM v2 Account-Native Topology

Each Java contract is a real wc=3 account at a deterministic 256-bit
address with its own class bytes, per-account method manifest, and
isolated storage.  The v1 SingletonExecutor path is fully removed.

### Address derivation

Five-input nested formula (`derive_jvm_contract_address_from_state` at
`jvm/core/deploy-abi.cpp:215-232`):

```
class_hash         = sha256(class_bytes)                         // 32B
address_commit     = sha256(
    deployer_addr.bits256                                        // 32B — wc=3 sender of deploy action
 || salt                                                         // 32B — caller-chosen
 || init_args_cell.get_hash().bits256                            // 32B — cell hash, consensus-stable
)                                                                // 32B
manifest_root_hash = manifest_root_cell.get_hash().bits256       // 32B (or zero if null)

addr_bytes := sha256(
    "TOS-JVM-CONTRACT-v2"
 || deployer_addr.bits256                                        // 32B
 || address_commit                                               // 32B
 || class_hash                                                   // 32B
 || manifest_root_hash                                           // 32B
)
```

The `address_commit` indirection lets the engine authenticate the
first-activation message source (`msg.src.addr == state.deployer`) and
binding `manifest_root_hash` into the address prevents post-deploy
method-id redirection.  Both commitments live inside the JVAC and are
re-verified on every `run_compute` by the address-binding gate at
`dispatch-engine.cpp:370-402`.

Implemented by `derive_jvm_contract_address` in `jvm/core/deploy-abi.cpp`.
Two contracts that share `(deployer, class_hash, salt, init_args)` collapse
to the same address (second deploy fails with `account_already_exists`). Same
class bytes + different salt produce different addresses with isolated
storage. Property covered by the
`DeriveJvmContractAddressIsDeterministicAndSensitive` test.

### Per-account state cell — `JvmContractAccountState` (magic JVAC)

```
jvm_contract_account#4a564143
  schema_version:uint8 (=2)
  stdlib_hash:bits256
  class_hash:bits256
  class_bytes:^Cell
  storage_root:(Maybe ^Cell)
  manifest_root:(Maybe ^Cell)
  = JvmContractAccountState;
```

`class_bytes` is held as a Cell ref so the Cell DB physically deduplicates
contracts that share identical bytecode (verified at
`crypto/vm/db/CellStorage.cpp:267` — KV is keyed by hash with refcount
accounting via `merge`). No explicit refcount design is needed.

### Per-account method manifest (magic JVM2)

```
jvm_method_manifest#4a564d32
  schema_version:uint8 (=1)
  count:uint16
  entries:^(JvmMethodManifestEntryNode chain)?
```

Each node carries `(method_id, class_name, method_name, method_spec)`.
Drops `contract_id` (the destination address already names the contract).
Implemented in `jvm/core/class-manifest.{h,cpp}` as
`JvmMethodManifestEntry` + `encode/parse/find_jvm_method_manifest_entry`.

### Call descriptor (magic JVI2)

```
jvm_call#4a564932
  schema_version:uint8 (=2)
  method_id:uint32
  args:^Cell
  = JvmCallDescriptor;
```

The destination wc=3 address names the contract, so the descriptor body
carries only `method_id` + a typed args cell.  Implemented in
`jvm/core/message-abi.{h,cpp}`.

### Engine policy — `EngineDefined`

`JvmNativeEngine::account_policy()` now returns
`AccountExecutionPolicyKind::EngineDefined` with
`admits_engine_create_account_actions=true`. The host's
`crypto/block/transaction.cpp Transaction::try_action_create_account`
dispatches the new `action_create_account#4a435241` TLB action: it builds a
synthetic internal `MessageRelaxed` carrying the supplied `state_init` and
optional `body`, then re-uses `try_action_send_msg` so all fee, validation,
and outbound-queue logic is shared. The receiving account is materialized
when its first inbound message lands, via the existing TVM/TON
`acc_uninit→acc_active` path. Account *materialization* is therefore
visible to the next transaction in the same block; method *invocation* on
the new account remains async via the message queue (no synchronous
cross-contract calls).

### Engine `run_compute`

`JvmNativeEngine::run_compute()` parses `input.current_data` as a
`JvmContractAccountState` (magic `0x4a564143` "JVAC"), looks up the
method via the per-account `manifest_root` keyed by `method_id`, and
dispatches to `JvmComputeRuntime::run_contract`.  The linked Avata
runtime caches VM threads keyed by `class_hash` (32 B) so contracts
sharing identical class bytes share one cached VM.  Implementation in
`jvm/core/avata-runtime.cpp` (`linked_avata_resolve_call_target`,
`get_vm_for_account`, `install_account_class_into_vm`).

### Zerostate

`build_jvm_zerostate_accounts_cell()` returns the canonical empty
`HashmapAugE(256, aug_ShardAccounts)` cell — the wc=3 genesis shard
ships with no preexisting accounts; contracts materialize later via
`action_create_account`.

### Tests landed

- `EngineDefinedPolicyValidates` — host accepts the new policy variant
- `JvmEngineAccountPolicyIsEngineDefined` — JVM engine declares
  EngineDefined + admits_engine_create_account_actions
- `ContractAccountStateCodecRoundTripsClassBytesAndStorage` — JVAC codec
  round-trip with Cell DB physical dedup property check
- `EncodeJvmStateInitCellPassesTlbValidation` — generated StateInit
  validates against `block::gen::t_StateInit.validate_ref` and decodes back
  to the same JvmContractAccountState
- `MessageAbiCallDescriptorRoundTripsAndOmitsContractId` — JVI2 codec
- `DeriveJvmContractAddressIsDeterministicAndSensitive` — address formula
  determinism and sensitivity to deployer / class_hash / salt / init_args
- `MethodManifestRoundTripsAndRejectsDuplicates` — JVM2 manifest codec
- `JvmEngineDispatchesAccountStateToRuntime` — engine dispatches JVAC
  cells through the per-account runtime path
- `JvmEngineV2RejectsMalformedAccountState` — JVAC magic + truncated body
  fails `sk_bad_state` without entering either runtime path
- `JvmV2EndToEndDeployCallSequence` — engine + mock runtime: derive
  address, build initial JVAC, two sequential calls advance storage,
  determinism replay produces identical `new_data` hash
- `ZerostateAccountsCellIsEmpty` — wc=3 genesis accounts dict is the
  canonical `hme_empty$0`

### ConfigParam 85 schema v2

`kJvmConfigSchemaVersion = 2`.  The wire format does not carry
`max_total_class_bytes`: there is no shared class store, and Cell DB
physical hash dedup handles bytecode sharing automatically.  The C++
struct field is removed entirely — v1 install paths no longer exist.

### Deploy RPC

`jvm_deployContract` returns `contractAddress` (the deterministic wc=3
account address from `derive_jvm_contract_address`) in its result JSON
together with the deploy-descriptor BOC.  Clients use
`contractAddress` to drive `action_create_account` to the right
per-account address.  Covered by
`RpcDeployContractReturnsContractAddress`.

`jvm_callContract` and `jvm_getContractState` accept a `contractAddress`
parameter (legacy `contractId` JSON key still parsed as alias), and
when the caller does not supply `accountStateBoc` the full-node
JSON-RPC server (`validator-engine/json-rpc-server-jvm.cpp`) loads the
per-account state from the wc=3 account at that address.
`jvm_getReceipts` scans the same per-contract account's transaction
history (no singleton executor lookup).

### v1 removal

The v1 SingletonExecutor path is fully gone:

- `JvmExecutorState` codec and `kJvmExecutorState*` constants — removed
- `derive_jvm_contract_id` (TOS-JVM-CONTRACT-v1) — removed
- `JvmAvataClassManifestEntry` (with `contract_id`),
  `JvmAvataClassDefinition`, `JvmAvataClassState` (JVMM/JVMC),
  `install_jvm_deploy_descriptor`, `JvmClassStoreLimits` — removed
- v1 `JvmCallDescriptor` (with `contract_id`, magic JVMI) — removed; the
  current descriptor uses magic JVI2, schema_version=2, and no
  `contract_id` field
- v1 `build_jvm_workchain_output(JvmExecutorState)` — removed; only the
  per-account variant remains
- v1 `linked_avata_resolve_call_target`, `install_class_state_into_vm`,
  `get_vm_for_class_state` in `avata-runtime.cpp` — removed; the per-
  account resolver and `class_hash`-keyed VM cache are the only paths
- `JvmConfig.max_total_class_bytes` field — removed (no shared class
  store under per-account topology; Cell DB hash dedup handles bytecode
  sharing automatically)
- v1 RPC fields (`contract_id`, `executor_state` on requests) — renamed
  to `contract_address` / `account_state`; legacy JSON parameter names
  (`contractId`, `executorStateBoc`) are still accepted as aliases for a
  transition period
- ~30 v1-only test cases — removed (`ExecutorStateCodecRoundTripsStorageRoot`,
  `MessageAbiCallDescriptorRoundTripsAndRejectsMalformed` v1 variant,
  `ClassManifestRoundTripsAndRejectsMalformed`,
  `ClassStateStoresDeployBytesAndKeepsManifestResolver`,
  `DeployAbiRoundTripsAndDerivesContractId`,
  `LinkedAvataExecutionApiUsesInterpreterAbi`,
  `AvataInvocationBuildsSuccessfulComputeOutput` and
  `…Failed`/`…OutOfGas`/`…OutOfMemory` v1 builders,
  `JvmEngineRunsInstalledRuntimeAdapter`,
  `JvmEngineRejectsMalformedInboundAbiBeforeRuntime`,
  `JvmEngineRunsAvataRuntimeExecutionBridge`,
  `JvmComputeOutputIsDeterministicAcrossReplay`,
  `JvmAvataRuntimeFailsClosedOnBadTargets`,
  `EndToEndDeployCallPersistAndRollback` v1,
  `MultiInstanceIndependentStorageSlots`,
  `JvmStateCellBocRoundTripPreservesComputeOutput`,
  `MaxHeapBytesExceededReturnsError`, and the v1 RPC test suite)
- v2-suffixed names dropped now that v1 is gone:
  `JvmCallDescriptorV2 → JvmCallDescriptor`,
  `kJvmCallDescriptorV2Magic → kJvmCallDescriptorMagic`,
  `linked_avata_resolve_call_target_v2 → linked_avata_resolve_call_target`,
  `build_jvm_workchain_output_v2 → build_jvm_workchain_output`,
  `JvmEngineDispatchesV2AccountStateToRuntime →
  JvmEngineDispatchesAccountStateToRuntime`, etc.

44/44 tests pass on the cleaned tree; full project build green.

## File Layout (actual)

```
jvm/
  avata/                ← forked Avata, pinned commit, stripped and determinized
    PINNED_COMMIT       ← upstream commit hash (0871979b…); TOS does not track upstream
    LICENSE.txt         ← Avata ISC license
    THIRD_PARTY_NOTICES.md ← SoftFloat BSD-3-Clause notice + Avata ISC notice
    CMakeLists.txt
    src/
      interpret.cpp     ← interpreter loop with gas counter and SoftFloat wired in
      machine.cpp
      heap.cpp
      softfloat/berkeley/  ← Berkeley SoftFloat 3e (BSD-3-Clause)
      ...
    include/avata/
      contract.h        ← Avata contract execution C ABI (gas, invoke, define)
      event.h           ← event host C ABI
      storage.h         ← storage host C ABI
      gas_schedule.h    ← tiered opcode + helper gas schedule types
    rt/java/lang/       ← TOS contract runtime Java sources
      Object.java, String.java, Math.java, System.java,
      Throwable.java, Error.java hierarchy,
      OutOfGasError.java, ContractViolationError.java,
      ContractEntry.java, Storage.java, Mapping.java,
      StorageCodec.java, PersistentMap.java, PersistentList.java,
      Event.java, ABI.java, Address.java, Uint256.java,
      Bytes.java, Bytes32.java, Bytes4.java, Crypto.java,
      ERC20.java, ERC721.java, ERC1155.java, ERC6909.java,
      Ownable.java, ReentrancyGuard.java, Pausable.java, ...
    rt/check-profile.sh       ← gates rt.jar against profile regressions
    rt/check-native-profile.sh
    rt/generate-profile-header.sh
    test/
      ContractEntryPoint.java  ← @ContractEntry-annotated reference contract
      ContractRuntimePrimitives.java
      ContractLibraryPrimitives.java
      StorageTest.java
      DeterministicFloatTest.java
      FloatConformanceVector.java   ← 160-line hex-bit float/double corpus
      float-conformance-reference.txt  ← x86_64 reference output for CI diff
      PerfBaseline.java         ← gas regression baseline (200 outer iters)
      VerifierProfile.java, CoreTrapProfile.java, ContractStaticProfile.java
      Strings.java, StringBuilderTest.java, Integers.java, Longs.java,
      Floats.java, AllFloats.java, Exceptions.java, MonitorTest.java,
      Switch.java, Tree.java, ArraysTest.java, ArrayDequeTest.java, ...
      avata-execution.{h,cpp}   ← C++ JVM execution bridge tests
      avata-runtime.{h,cpp}
      cell-codec.{h,cpp}        ← C++ executor state codec tests
      class-manifest.{h,cpp}
    tools/
      javac                ← TOS javac wrapper (pins api.jar boot classpath)
      java                 ← TOS java wrapper (--gas, --memory resource mode)
  core/
    dispatch-engine.{h,cpp}   ← JvmNativeEngine, register_jvm_workchain_engine()
    config-param.{h,cpp}      ← ConfigParam 12 descriptor + ConfigParam 85 codec
    zerostate.{h,cpp}         ← build_jvm_zerostate_accounts_cell()
    init.{h,cpp}              ← init_jvm_workchain()
    avata-execution.{h,cpp}   ← execute_jvm_avata_transaction(), gas bridge
    avata-runtime.{h,cpp}     ← JvmAvataRuntime, make_linked_jvm_avata_runtime()
    cell-codec.{h,cpp}        ← JvmCellCodec encode/decode (JvmContractAccountState, StateInit)
    message-abi.{h,cpp}       ← JvmCallDescriptor + typed JVMA args codec
    class-manifest.{h,cpp}    ← per-account JvmMethodManifest codec (JVM2)
    deploy-abi.{h,cpp}        ← JvmDeployDescriptor + derive_jvm_contract_address
    storage-cell-host.{h,cpp} ← JvmStorageCellHost (cell-backed 256-bit slots)
    event-host.{h,cpp}        ← JvmEventHost + event payload codec
    rpc.{h,cpp}               ← jvm_* JSON-RPC handlers + accountStateBoc parsing
    ── post-v2 (Phases A–G) ──
    inbound-parse.{h,cpp}     ← shared addr_std src + Uint256 value parser
                                (dispatch-engine + avata-runtime context plumbing)
    crypto-host.{h,cpp}       ← validator AvataCryptoHost binding to
                                libsecp256k1 / libsodium / blst
    message-host.{h,cpp}      ← JvmMessageHost — System.sendMessage adapter
                                that serializes outbound action_send_msg cells
    genesis-wallet.{h,cpp}    ← per-wallet builder for the Phase F seeder
  avata/
    rt/java/lang/Wallet.java  ← canonical wc=3 wallet contract (Phase E)
    include/avata/
      context.h               ← AvataContractContext C ABI (Phase A)
      crypto.h                ← AvataCryptoHost C ABI (Phase B)
      message.h               ← AvataMessageHost C ABI (System.sendMessage)
```

Outside `jvm/`, Phase F adds the Fift word
`jvm-zerostate-from-alloc` in `crypto/block/create-state.cpp:648`
(stack signature `( T class_bytes stdlib_hash -- accounts_cell )`)
and Phase G adds the Rust `jvm_codec` crate at
`tosctl/src/node-control/contracts/src/jvm_codec/` (mirrors the C++
cell codecs for wallet clients).

Note: `persistent-map.cpp` / `persistent-list.cpp` as separate C++ files are
not needed: `PersistentMap` and `PersistentList` are implemented as Java classes
in `rt/java/lang/` backed by the `Storage` abstraction, which in turn uses
`JvmStorageCellHost`. The gas schedule is in `avata/include/avata/gas_schedule.h`
and wired into ConfigParam 85 via `config-param.cpp`.

## Design Decisions (Resolved)

These questions were open during Phase 0–1 design and are now answered by the
implementation. They are recorded here for traceability.

1. **Persistent state and transaction arena boundary.**
   **Resolved.** Only explicit `Storage`/`Mapping`/`PersistentMap`/`PersistentList`
   state is persisted across transaction boundaries. The transaction-local arena
   is reset via `checkpointContractHeap` / `resetContractHeap` at each transaction
   boundary; transient heap objects are discarded. Mutable static fields are
   rejected by the verifier at class-load time. ConfigParam 85 activation values
   are set by `JvmConfig::default_activation()`: max_gas_per_tx=1M gas,
   max_heap_bytes=4 MiB. Allocation-heavy contracts fail deterministically with
   `OutOfMemoryError` before exhausting validator memory.

2. **Class store retention policy.**
   **Resolved.** Each contract's `class_bytes` lives inline in its
   per-account `JvmContractAccountState` cell.  Two contracts that
   share identical bytecode share one Cell DB row physically (verified
   at `crypto/vm/db/CellStorage.cpp:267`); no shared class-store
   account is needed.  ConfigParam 85 enforces `max_class_bytes`
   (64 KiB per class) at deploy time as a hard limit; governance can
   adjust it before or after mainnet activation.  No
   `max_total_class_bytes` is needed because there is no shared class
   store under per-account topology.  When a contract account is
   eventually deleted (out of scope for the current release), Cell DB
   refcount accounting prunes its `class_bytes` row only after every
   sharing account has been removed.

3. **Cross-contract calls.**
   **Resolved (frozen).** No synchronous cross-contract calls.  Each
   inbound message targets exactly one wc=3 contract account.
   Cross-contract interaction uses asynchronous TOS messages via
   `java.lang.System.sendMessage(destAddr, value, body)`.  This rule
   is enforced by the execution model (a single `run_compute`
   invocation handles one contract) and does not require an explicit
   verifier check.  Synchronous cross-contract calls can be added in a
   future revision as a mediated call-dispatch path if isolation can
   be preserved.

4. **TOS native contract interop.**
   **Resolved (frozen).** All cross-workchain and cross-contract
   interaction is asynchronous.  A JVM contract cannot make
   synchronous read-only queries to TVM contracts or other workchains.
   Synchronous reads from external state would break the snapshot
   execution model.  This decision is not expected to change at the
   consensus layer; it may be revisited in a future workchain version
   with explicit call-depth and re-entrancy semantics.

5. **TOS runtime package boundary.**
   **Resolved.** The admitted package surface is defined by
   `rt/check-profile.sh` and `rt/check-native-profile.sh`. The
   developer toolchain enforces the same boundary via `tools/javac`
   (which wraps javac with the TOS `api.jar` boot classpath) and the
   `check-api-javac` makefile target. Unsupported packages
   (`java.net`, host-backed `java.nio`, `java.lang.Thread`, etc.) are
   absent from `rt.jar`; remaining classes with forbidden host-observing
   methods trap deterministically.  `check-contract-profile-header`
   gates `src/avata/contract-profile.h` against profile drift on every
   build.

6. **`wc=3` vs new network.**
   **Resolved (governance decision).** `wc=3` on the main TOS network
   is the target. A separate devnet is not planned; the integration
   test suite and determinism replay tests validate the design
   in-process before any mainnet activation. Since TOS is pre-launch,
   both options remain available to
   governance; this roadmap assumes mainnet `wc=3` as the default path.
