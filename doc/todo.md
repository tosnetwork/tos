# TOS JVM / Avata Remaining Work

This document tracks the remaining work for the TOS JVM workchain runtime.
`~/jdk8u` is the local OpenJDK 8u reference checkout used to compare JVM and
class-library behavior. Current reference revision: `24fbffc3f77f`.
Reference code is used to understand semantics; Avata changes must still fit
the TOS deterministic consensus model.

Status legend: `✅` completed, unchecked items are still open.

## P0 Consensus-Safety Work

- ✅ Implement deterministic fixed floating-point execution for all Java
  `float` and `double` opcodes. The implementation must pin rounding, NaN,
  signed-zero, infinity, and subnormal behavior across supported OS/CPU
  combinations.
  - ✅ Berkeley SoftFloat 3e is vendored under
    `jvm/avata/src/softfloat/berkeley/` and the Avata makefile compiles only the
    f32/f64 functions needed by Java 8 opcodes. `tos_softfloat.h` now routes
    all float/double arithmetic, comparisons, and conversions through SoftFloat
    with round-to-nearest-even, canonical NaNs (`0x7FC00000` and
    `0x7FF8000000000000`), deterministic Java cast clamping, and no host-FPU
    arithmetic. `frem`/`drem` use Avata's SoftFloat-derived fmod helper because
    SoftFloat's public `f*_rem` routines implement IEEE remainder, not Java `%`.
    `DeterministicFloatTest` and `AllFloats` pass on the new path.

- ✅ Add gas accounting to the Avata interpreter dispatch loop. Every bytecode and
  admitted runtime helper must charge deterministic gas and throw a deterministic
  out-of-gas trap.
  - **Implemented:** `Thread::gasCounter` (uint64_t) and
    `Thread::identityHashCounter` (uint32_t) fields added to `vm::Thread` in
    `jvm/avata/src/avata/machine.h`. The interpreter dispatch loop
    (`interpret3()` in `jvm/avata/src/interpret.cpp`, label `loop:` at line 784)
    now decrements `gasCounter` on every bytecode dispatch and throws
    `GcOutOfGasError` when gas is insufficient; a value of `UINT64_MAX`
    bypasses the check (bootstrap mode). `java.lang.OutOfGasError` is wired in
    `types.def`. `include/avata/contract.h` now exposes
    `avata_begin_contract_transaction()`, `avata_end_contract_transaction()`,
    and `avata_contract_remaining_gas()` so the workchain bridge can
    initialize gas and reset Java-visible identity hash state at the
    transaction boundary. `Machine::opcodeGasCosts[256]` now holds a
    per-opcode gas table. The interpreter charges
    `opcodeGasCosts[instruction]` before executing each bytecode. The default
    profile charges 1 for every opcode, and `include/avata/contract.h` exposes
    ABI calls to reset, set, bulk-set, and read opcode costs.
    `avata_charge_contract_gas()` now charges deterministic helper/native gas,
    returning `AVATA_CONTRACT_OUT_OF_GAS` and consuming the remaining counter on
    failure. `Machine::contractHelperGasCosts[13]` now holds helper schedules
    for storage load/store/clear, dynamic opcode surcharges (`new` object
    words, `newarray`/`anewarray`/`multianewarray` array bases and elements),
    `System.arraycopy()` base/per-element copy costs, and the fixed native-call
    surcharge charged by every Java native method invocation. The public ABI can
    reset, set, bulk-set, read, and charge helper costs through
    `avata_charge_contract_helper_gas()`. `java.lang.Storage` charges from
    that helper table before host/fallback storage access. `java.lang.Event`
    exposes deterministic log/event emission and charges event base, per-topic,
    and per-data-byte helper gas before forwarding to the installed event host.
    `include/avata/contract.h` also exposes transaction memory-limit and
    memory-counter ABI calls:
    `avata_begin_contract_transaction_with_limits()`,
    `avata_contract_memory_used()`,
    `avata_contract_memory_remaining()`, and
    `avata_contract_memory_limit()`. Contract allocations increment
    `Thread::contractMemoryUsed` and throw deterministic `OutOfMemoryError`
    if the configured transaction memory limit is exceeded. `java.lang.Memory`
    reads these transaction-local counters while a contract transaction is
    active.
  - ✅ **Gas schedule finalization:** The flat "1 per opcode" default replaced with
    a tiered default schedule in `include/avata/gas_schedule.h`. Tiers:
    NOP/STACK=1, INT_ARITH/LONG_ARITH/CONVERT/COMPARE/BRANCH=2,
    FLOAT_ARITH/DOUBLE_ARITH/MONITOR=3, FIELD=3, ALLOC/TYPECHECK=5, DIV=5,
    INVOKE/THROW=10. `machine.cpp` `resetOpcodeGasCosts()` now loads from
    `kTosDefaultOpcodeGasCosts[256]`. Tests `TieredOpcodeGasSchedule` (all 256
    slots > 0, spot-check every tier, ordering invariants) and
    `HelperGasOutOfGasRegression` (storage load/store/clear OOG boundaries) added
    to `unittest/contract-transaction-test.cpp`. All tests pass.
  - ✅ **Config descriptor helper:** `build_jvm_workchain_descr()` now builds the
    JVM v1 ConfigParam 12 `WorkchainDescr` (`wfmt_basic`,
    `vm_version="JVM1"`, `vm_mode=0`) and validates it against the generated
    TL-B schema. `test-workchain-execution-registry` checks that the normalized
    descriptor resolves to the JVM engine key.
  - ✅ **Workchain execution bridge:** `JvmAvataRuntime` now implements
    `JvmComputeRuntime` and calls `execute_jvm_avata_transaction()` for the
    resolved Avata thread/call target. That bridge installs ConfigParam 85
    opcode/helper gas tables, opens storage/event snapshots, calls
    `avata_begin_contract_transaction_with_limits(thread, input.gas_limit,
    config.max_heap_bytes)`, invokes the supplied contract entry callback,
    reads `avata_contract_remaining_gas()` and
    `avata_contract_memory_used()`, and converts successful results to the
    canonical `JvmExecutorState` plus action list. The registry test exercises
    this path through `JvmNativeEngine::run_compute()`.
  - **Completed work:**
    - ✅ Added deterministic compute-output assembly:
      `build_jvm_workchain_output()` converts an Avata invocation result into
      `WorkchainComputeOutput`, charges `gas_used * ConfigParam85.gas_price`,
      commits only successful storage roots into the canonical
      `JvmExecutorState`, preserves the class-state root, emits a non-null
      TOS action list for successful executions, and reports failure/OOG
      without committing `new_data` or actions.
    - ✅ `JvmNativeEngine::run_compute()` now decodes the executor-state cell,
      validates the `stdlib_hash`, enforces ConfigParam 85 gas bounds, and
      delegates actual contract invocation to an installed `JvmComputeRuntime`.
      If no runtime is installed, wc=3 compute still fails closed with a
      deterministic skipped output. The registry test injects a mock runtime and
      verifies the full path from ConfigParam 85 resolution through
      `WorkchainComputeOutput`.
    - ✅ ConfigParam 85 parsing is now implemented in
      `jvm/core/config-param.{h,cpp}` and `JvmNativeEngine` resolves it during
      `validate_and_resolve_config()`. The parsed chain limits, opcode gas
      table, and helper gas table are carried in `JvmEngineConfig`; malformed
      or missing ConfigParam 85 is a consensus error. The standalone
      `gas_schedule.h` defaults remain only for local Avata tests; consensus
      execution applies the resolved tables through
      `avata_set_opcode_gas_costs()` and
      `avata_set_contract_helper_gas_costs()` at transaction start.
    - Extend dynamic deterministic helper costs to future native crypto, ABI,
      cross-contract calls, and any other admitted native entry points whose
      cost depends on input size. `Crypto.java` and `ABI.java` are currently
      pure Java, so they are covered by opcode gas and do not have a separate
      native helper entry yet. `java.lang.Event` is now native-hosted and has
      explicit event base/topic/data-byte helper gas. Do not add gas to Java
      classes directly; Java-level libraries are covered by opcode gas plus any
      native/helper calls they make.

- ✅ Disable or isolate JIT/AOT/host-VM compilation paths for consensus execution.
  Contract execution must use a deterministic interpreter-only profile unless a
  future compiled profile is proven byte-identical across validators.
  - **Status:** Completed by slimming the Avata source and build profile. The
    legacy JIT/codegen/AOT sources (`src/codegen/**`, `include/avata/codegen/**`,
    `src/compile*`) and codegen unit tests have been removed. Make and CMake now
    build the interpreter profile only.

- ✅ Define and enforce a deterministic class-file verifier profile: supported
  class-file versions, TOS extensions, forbidden attributes/classes, duplicate
  ABI method handling, class initialization rules, and deterministic trap
  behavior.
  - **Implemented:** `jvm/avata/src/machine.cpp` now rejects class
    files with `major < 45` (pre-Java 1.1), `major > 52` (Java 9+), or
    `minor == 0xFFFF` (Java preview features) by throwing
    `GcUnsupportedClassVersionError`. It also rejects forbidden class
    references in constant-pool class entries and field/method descriptors:
    `java.lang.Thread`, `java.lang.ClassLoader`, `java.lang.Runtime`,
    all `java.lang.invoke.*`, all `java.lang.reflect.*`, and all
    `java.lang.ref.*`. Packages absent from `rt.jar`, such as
    `java.net` and `java.nio`, are enforced by absence plus the build-time
    `rt/check-profile.sh` check rather than verifier special cases. Forbidden
    Java 9+ class-file attributes (`Module`,
    `ModulePackages`, `ModuleMainClass`, `NestHost`, `NestMembers`,
    `BootstrapMethods`, `Record`, `PermittedSubclasses`) are rejected in field,
    method, and class attribute tables with `GcVerifyError`. Duplicate method
    name+descriptor pairs are rejected with `GcClassFormatError`.
    `CONSTANT_MethodHandle`, `CONSTANT_MethodType`, and
    `CONSTANT_InvokeDynamic` are rejected by the v1 contract verifier because
    the runtime no longer ships public `java.lang.invoke` classes. Application
    class initializers (`<clinit>`) are rejected with `VerifyError`; boot
    runtime class initializers remain internal and must be static `()V` methods
    with bytecode. Application methods with `ACC_SYNCHRONIZED` or `ACC_NATIVE`
    are rejected with `VerifyError`; deterministic `monitorenter`/`monitorexit`
    opcodes remain supported for synchronized blocks, and native entry points
    are limited to the pinned boot runtime. Application `finalize()V` methods
    are rejected with `VerifyError`, so object finalization is not an
    application lifecycle hook. Application classes with `ACC_ENUM` are
    rejected with `VerifyError`. Constructors must be non-static and return
    `void`.
    Supporting Java files now include
    `ClassFormatError`, `UnsupportedClassVersionError`, and `VerifyError`.
    `VerifierProfile` covers forbidden class refs, forbidden descriptors,
    forbidden attributes, duplicate methods, forbidden method-handle /
    method-type / invokedynamic constants, malformed class
    initializers/constructors, application `<clinit>`, mutable static fields,
    admitted static-final constants, synchronized/native/finalizer application
    methods, enum class flags, forbidden reflection/ref refs, class-file
    version acceptance/rejection (major 52/45 accepted; 53+ and 44- and
    minor=0xFFFF rejected), stale `avata/*` namespace rejection in both
    constant-pool class refs and declared class names, additional explicit class
    ref tests for Thread/ClassLoader/invoke/reflect, forbidden
    `java/internal/*` field descriptors, static mutable String fields, and
    all six remaining forbidden attributes (Module, ModulePackages,
    ModuleMainClass, NestHost, Record, PermittedSubclasses).
    `machine.cpp` now also rejects constant-pool class refs and declared class
    names under the stale `avata/` package prefix.
  - ✅ **Deploy-time verifier negative tests added:** `VerifierProfile` now covers
    all forbidden package/class references, stale namespace rejection, version
    boundary tests, and all forbidden attribute variants.
  - ✅ **Generated contract API manifest added:** `build-test` now regenerates
    `jvm/avata/src/avata/contract-profile.h` from `api.jar` and fails if the
    checked-in manifest is stale. The deploy-time verifier admits only classes
    present in that generated manifest for `java/*` references, while keeping
    VM boot helper classes available inside `rt.jar`.

- ✅ Replace host-observing APIs with deterministic traps or TOS-provided values:
  wall-clock time, filesystem, networking, process APIs, native library loading,
  reflection surfaces outside the admitted profile, and thread scheduling.
  - **Status:** `java.lang.System` in `rt/java/lang/System.java` already
    traps `currentTimeMillis()`, `nanoTime()`, `getenv()`, `load()`,
    `loadLibrary()`, `mapLibraryName()`, `exit()` with
    `UnsupportedOperationException`. The Android/libcore and OpenJDK classpath
    bridges have been removed from the TOS Avata profile.
  - **Completed in slim pass:** public `java.lang.ClassLoader` and the old
    `Avata_java_lang_ClassLoader_load` path have been removed. The legacy
    `Java_java_lang_System_currentTimeMillis` JNI body returns deterministic
    zero if reached by future classpath changes.
  - **Completed in classpath cut:** broad host-facing packages are absent from
    `rt.jar`; `java.lang.invoke`, `sun.misc.Unsafe`, `java.internal.Machine`, and
    `java.internal.Traces` are no longer shipped.
  - ✅ **Completed in contract-profile audit:** `System.getProperty()` now exposes
    only a fixed deterministic allow-list and no longer ingests VM command-line
    `-D` properties such as `avata.builtins` or `java.class.path`. The profile
    also removed legacy thread/security/type shell classes
    (`IllegalThreadStateException`, `ThreadDeath`, `SecurityException`,
    `TypeNotPresentException`) plus `Collections.shuffle`.
  - ✅ **Deploy-time verifier negative tests added:** see VerifierProfile above.

- ✅ Make object identity deterministic or unavailable: `Object.hashCode`,
  `System.identityHashCode`, object `toString`, and exception stack traces must
  not leak process addresses or host-local execution details.
  - **Implemented:**
    - `Thread::identityHashCounter` (uint32_t) added to `vm::Thread` in
      `jvm/avata/src/avata/machine.h`, initialized to 0 in `Thread::Thread()`
      in `machine.cpp`.
    - `Thread::identityHashes` stores the first Java-visible identity hash per
      object, so repeated `Object.hashCode()` / `System.identityHashCode()`
      calls remain stable.
    - `objectHash()` in `machine.h` returns a per-transaction counter value for
      un-extended non-fixed objects, replacing the address-derived value.
    - The legacy heap-copy callback preserves the counter-based identity hash
      when a side table entry exists; `gcTakeHash()` is now only a fallback for
      VM-internal hashTaken objects without a Java-visible identity entry.
    - `Object.toString()` still uses `ClassName@0x<hash>`, but the hash now
      comes from the deterministic `objectHash()` path rather than the heap
      address.
  - ✅ Exception stack traces no longer expose path-like `SourceFile` payloads.
    `makeStackTraceElement()` strips `/`, `\`, and `:` prefixes and exposes
    only the basename from the class-file `SourceFile` attribute.
    `StackTraceSourceFileTest` constructs a class whose `SourceFile` is an
    absolute host-like path and verifies `StackTraceElement.getFileName()` only
    returns `SecretContract.java`.
  - ✅ `execute_jvm_avata_transaction()` opens the Avata contract transaction at
    the start of each workchain invocation, so identity counters are scoped to
    the transaction.
  - ✅ `endContractTransaction()` clears the identity-hash side table and resets
    the transaction arena checkpoint, discarding transient objects and hashes
    materialized during the previous transaction.

- ✅ Finalize contract heap/state persistence: persisted value profiles,
  `PersistentMap`/`PersistentList` encoding, heap reset/snapshot model, and
  bounded arena memory accounting.
  - **Implemented:** `java.lang.Storage` now exposes scalar
    32-byte slot operations, `java.lang.Mapping` derives Ethereum-style hashed
    slots, and `include/avata/storage.h` exposes the native
    `avata_set_storage_host()` C ABI plus begin/commit/rollback transaction
    entry points plus `avata_storage_execute_transaction()`. `Storage.host()`
    delegates through that installed host when
    present and otherwise uses a deterministic process-local fallback with
    nested snapshots for tests. `avata-unittest` now covers callback forwarding
    fallback transaction begin/commit/rollback behavior, and invocation-wrapper
    commit/rollback behavior. The
    `StorageHostReferenceAdapter` unit test also models gas charging, write-set
    journaling, nested commit merging, and rollback restoration for the future
    chain execution adapter.
  - **Design:**
    - Application classes may not declare mutable static fields in the v1
      profile. `machine.cpp` `parseFieldTable()` admits only `static final`
      primitive/String constants with `ConstantValue` for non-boot class
      spaces; other `ACC_STATIC` fields are rejected with `VerifyError`.
      Static methods remain allowed. During contract execution, application
      `getstatic` is allowed only for these admitted final constants, and
      application `putstatic` is rejected. Boot runtime classes may keep audited
      static constants/helpers, but the interpreter still rejects reference-type
      boot `putstatic` while a contract transaction is active.
    - ✅ Transaction memory accounting is implemented for contract-observable
      memory: `Thread::contractMemoryUsed` is reset at transaction boundaries,
      allocation increments it, `java.lang.Memory.used/remaining/limit`
      exposes it, and the contract ABI can set/read the memory limit.
    - ✅ Transaction-local movable heap reset is implemented with an arena
      checkpoint: `beginContractTransactionWithLimits()` records the current
      `Thread::heap`/`heapIndex`/`heapOffset` and `Machine::heapPoolIndex`;
      `endContractTransaction()` clears allocations after that checkpoint and
      frees heap chunks added during the transaction. Contract execution also
      rejects fixed/oversized allocation and does not invoke the legacy
      collector fallback while `contractActive` is true. `avata-unittest`
      covers checkpoint rollback and heap-chunk release.
    - ✅ Static-field profile is enforced before execution: application
      mutable static fields are rejected at class load, while `static final`
      primitive/String constants with `ConstantValue` are admitted.
      `VerifierProfile` covers rejected mutable statics, rejected static-final
      fields without `ConstantValue`, and admitted static-final constant reads.
      Java enum classes remain outside the profile because javac emits mutable
      static state for them.
    - ✅ `PersistentMap` and `PersistentList` are now available in `java.lang`.
      `PersistentMap` wraps the existing deterministic slot-hashed `Mapping`;
      `PersistentList` stores a deterministic length slot and indexed element
      slots. `Storage.current()` now defaults to `Storage.host()`, so default
      persistent containers use the host/native storage path; `Storage.memory()`
      remains available for explicit unit-test state. `StorageTest` covers map
      overwrite/remove semantics, list reconstruction/removal/clear behavior,
      and default host-backed reconstruction.
    - ✅ Added the first `JvmCellCodec` state envelope in `jvm/core/cell-codec.*`.
      It encodes/decodes the canonical v1 executor-state cell carrying
      `stdlib_hash`, `storage_root`, and `class_state_root`, rejecting wrong
      magic/schema, special cells, malformed Maybe refs, and trailing bits/refs.
      This is the `cp.new_data` root shape; it is intentionally not a general
      Java heap object-graph serializer.
    - ✅ Added `jvm/core/storage-cell-host.*`: a cell-backed 256-bit-slot
      dictionary for `Storage` values. It supports arbitrary byte values through
      chunked cell chains, validates storage roots, provides nested
      begin/commit/rollback snapshots, and can fill an `AvataStorageHost`
      callback table for `avata_set_storage_host()`. `JvmCellCodec` now
      validates the storage root shape when decoding executor state.
      `test-workchain-execution-registry` now covers missing slots, present
      empty values, chunked value round-trips, root reload, nested transaction
      rollback/commit, and the Avata callback convention that present empty
      values are returned as a non-null pointer with length zero.
    - ✅ `JvmAvataRuntime` now creates `JvmStorageCellHost` from
      `JvmExecutorState.storage_root`, installs the generated
      `AvataStorageHost` and `AvataEventHost` around Avata execution, applies
      ConfigParam 85 gas tables to the Avata thread, and lets
      `build_jvm_workchain_output()` persist the updated storage root into
      `cp.new_data`.
    - ✅ Added `jvm/core/avata-execution.*`: a narrow function-pointer gas
      bridge that applies the resolved ConfigParam 85 opcode/helper gas arrays
      to an Avata thread. The compute bridge passes
      `avata_set_opcode_gas_costs()` and
      `avata_set_contract_helper_gas_costs()` through this helper before
      invoking contract bytecode. It now also exposes
      `execute_jvm_avata_transaction()`, which installs the cell-backed
      storage host, opens the storage snapshot, begins the Avata contract
      gas/memory transaction, invokes a narrow contract callback, queries
      gas/memory usage, commits storage only on success, rolls back storage on
      failure/OOG, and clears the global Avata storage host on every path.
      `test-workchain-execution-registry` covers successful table
      installation, failed gas-table installation, successful storage commit,
      failed invocation rollback, OOG classification, failed transaction begin,
      invalid gas reports, and host cleanup.
    - ✅ Added `jvm/core/event-host.*` and wired it into
      `execute_jvm_avata_transaction()`. The execution bridge can now install
      an `AvataEventHost` beside the storage host, record deterministic ordered
      events during invocation, commit them only on successful contract
      execution, roll them back on failure/OOG/OOM, and clear the global event
      host on every path. JVM event payloads now have a canonical cell encoding
      and can be converted into valid `OutList` action cells carrying outbound
      external messages, so committed events are ready to flow through the
      normal TOS transaction action phase once the interpreter bridge supplies
      real invocations.
    - Persistent ordered list storage is implemented. The v1 profile still does
      not expose full map iteration because storage slots are hashed and the
      chain adapter must define an explicit index structure before enumerable
      maps are admitted.
    - ✅ The storage/event/gas bridge, output assembly, linked interpreter ABI,
      and manifest-backed runtime resolver are now covered by
      `test-workchain-execution-registry`. Class-byte storage/loading from
      `JVMC`, deploy descriptor installation, typed argument decoding, and
      typed static-void invocation are covered by the same suite.
    - ✅ Added a narrow two-phase contract entry ABI in
      `include/avata/contract.h`: `avata_resolve_contract_static_void()`
      resolves a class/method outside the transaction arena and returns an
      opaque `AvataContractMethod`; `avata_invoke_contract_static_void()` then
      invokes that pre-resolved method inside the gas/memory transaction. This
      prevents class loading from retaining transaction-arena objects after
      `endContractTransaction()` resets the arena. `ContractStaticVoidInvocationAbi`
      covers success, Java exception classification, OOG classification, and
      pending-exception cleanup.

## Added classpath files

- ✅ `rt/java/lang/ContractViolationError.java` — deterministic trap base
  class for forbidden host-API access; extends `Error`.
- ✅ `rt/java/lang/OutOfGasError.java` — thrown by the interpreter when
  `gasCounter` reaches zero; extends `Error`.
- ✅ `rt/java/lang/ClassFormatError.java` — base for class-file format
  violations; extends `LinkageError`.
- ✅ `rt/java/lang/VerifyError.java` — thrown when class verification rejects a
  class that violates the TOS contract profile; extends `LinkageError`.
- ✅ `rt/java/lang/UnsupportedClassVersionError.java` — thrown by the
  class reader for class files targeting Java 9+ or pre-Java 1.1; extends
  `ClassFormatError`.

## Historical JDK8u Compatibility Work

This section records work completed before the slim contract-classpath cut.
Several APIs listed here were intentionally removed from the current v1
contract profile after the first-principles review. They remain useful as
history, not as a promise that the current `rt.jar` exposes those APIs.

- ✅ Continue aligning native IO error handling with JDK8u:
  file metadata helpers, directory handling, interrupted syscalls, and close
  semantics now have a full pass for the current Avata `java.io` surface.
- ✅ Removed public `java.lang.invoke` from the admitted v1 Java profile:
  `CallSite`, `ConstantCallSite`, `MutableCallSite`, `VolatileCallSite`,
  `SerializedLambda`, `MethodHandle`, `MethodHandles`, `MethodType`,
  `WrongMethodTypeException`, `LambdaConversionException`,
  `LambdaMetafactory`, and `MethodHandleInfo` are absent from `rt.jar`.
  The verifier rejects `CONSTANT_MethodHandle`, `CONSTANT_MethodType`,
  `CONSTANT_InvokeDynamic`, and `BootstrapMethods`. Future Java 8
  `invokedynamic` admission must be VM-internal and deterministic, not a public
  Java SE method-handle API surface.
- ✅ Removed Java reflection compatibility from the contract profile:
  `java.lang.reflect.*`, dynamic proxies, generic reflection, `Class.newInstance`,
  reflective method/field lookup, `InstantiationException`, and
  `ReflectiveOperationException` are no longer shipped. `Class` keeps only the
  deterministic metadata methods needed by normal Java 8 code and lambda
  linkage.
- ✅ Finish encoding/console behavior:
  `file.encoding`, `System.out`/`System.err` default encoding, and
  reader/writer explicit charset handling are pinned to deterministic UTF-8
  plus ISO-8859-1/Latin-1 where explicitly admitted. `Utf8` now handles
  standard four-byte UTF-8 code points instead of relying on host charset
  behavior, `OutputStreamWriter` and `InputStreamReader` reject unsupported
  charsets deterministically, and `Strings` covers UTF-8 supplementary
  characters, Latin-1 round trips, and unsupported charset exceptions.
- ✅ Align serialization and object stream behavior with the admitted runtime
  profile: array objects serialized as TC_ARRAY with JDK8u wire format; enum,
  `Externalizable`, `writeReplace`, and `readResolve` trap deterministically;
  `InvalidClassException` added with JDK8u-compatible `classname` field;
  exception types aligned (`StreamCorruptedException`, `InvalidClassException`,
  `NotSerializableException`).
- ✅ Fill class-library gaps: `java.util.function` package (6 interfaces),
  `Optional<T>`, `StringJoiner`, `UUID` deterministic rewrite
  (`randomUUID()` traps), `Date` `Comparable` + mutators, `Map` Java
  8 default methods, `Collections` 15+ missing methods, `Arrays` full primitive
  sorts/`copyOfRange`/`binarySearch`/`hashCode`/`deepToString`, `TreeSet`
  `SortedSet` + backed range views, `ArrayList.subList`, `Collection.removeIf`,
  `Iterable.forEach`, `CharBuffer.wrap(CharSequence)` + `toString`/`subSequence`,
  `Long.compare(long,long)`.

## P2 Platform And Build Work

- ✅ Install the production Avata runtime resolver in the JVM workchain.
  - ✅ `jvm/avata/CMakeLists.txt` now exports `avata_interpreter`, an imported
    static target backed by the canonical Avata makefile's
    `build/<platform>-<arch>/libavata.a` output. The target also declares the
    generated `rt.jar` and `api.jar` byproducts.
  - ✅ `jvm_workchain_core` now links `avata_interpreter`, so the main CMake
    build and `validator-engine` drive the canonical Avata static archive and
    jar outputs.
  - ✅ `make_linked_jvm_avata_execution_api()` now maps the core execution
    bridge to the linked Avata C ABI, including gas tables, storage/event host
    installation, transaction resource counters, and the two-phase static-void
    contract invocation adapter.
  - ✅ `jvm/core/class-manifest.*` defines the v1 `class_state_root` manifest
    (`JVMM`, schema 1). It maps `(contract_id, method_id)` to an Avata
    `class_name`, `method_name`, and `method_spec`, rejects malformed strings and
    duplicate keys, restricts v1 entries to ASCII Java internal class names,
    Java identifier method names, and supported static-void descriptors, and is
    now validated by `JvmCellCodec` when decoding executor state.
  - ✅ `make_linked_jvm_avata_runtime()` validates the linked Avata boot runtime
    at initialization, then creates and caches execution VMs keyed by
    `class_state_root` hash. Each cached VM has its own app class space, so
    installed application classes are isolated by deterministic executor state.
    The resolver loads `JVMC` class bytes into that VM before resolving inbound
    `JvmCallDescriptor` values through the manifest and invoking the resolved
    static-void method through the existing gas/storage/event bridge.
  - ✅ `init_jvm_workchain()` now installs that linked runtime from
    `TOS_JVM_AVATA_RT_JAR` or the CMake Avata bridge default, optional
    `TOS_JVM_AVATA_CONTRACT_CLASSPATH`, and `TOS_JVM_AVATA_HEAP`. If VM creation
    fails, registration still succeeds with a null runtime and wc=3 remains
    fail-closed.
- ✅ Add the first inbound JVM message ABI codec:
  `jvm/core/message-abi.*` encodes and decodes the canonical v1
  `JvmCallDescriptor` (`contract_id`, `method_id`, `args`), rejects malformed
  bodies before Avata runtime invocation, validates that v1 linked `()V`
  entrypoints receive the canonical empty args cell, and is covered by
  `test-workchain-execution-registry`. The same module now also provides the
  deterministic `JVMA` typed `ArgsCell` codec and descriptor validator for
  `boolean`, `int`, `long`, `Address`, `Uint256`, `Bytes32`, `Bytes4`, and
  variable `Bytes` arguments. The linked Avata invocation bridge now decodes
  those `JVMA` cells and invokes matching static-void methods with typed
  arguments through the Avata C ABI, while preserving canonical empty-cell
  compatibility for legacy `()V` entries.
- ✅ Add the first JVM deploy message ABI codec:
  `jvm/core/deploy-abi.*` encodes and decodes the canonical v1
  `JvmDeployDescriptor` (`deployer`, `salt`, `class_hash`, `class_name`,
  `class_bytes`, `init_args`), verifies `class_hash == sha256(class_bytes)`,
  validates the class-name shape, and derives
  `contract_id = sha256("TOS-JVM-CONTRACT-v1" || deployer || class_hash || salt
  || init_args_cell_hash)`.
- ✅ Add the first deploy-to-class-state installer:
  `jvm/core/class-manifest.*` now also defines the `JVMC` class-state envelope,
  keeps the callable `JVMM` manifest as a nested ref, stores verified
  `(class_name, class_hash, class_bytes)` definitions, accepts both legacy
  manifest-only roots and `JVMC` roots at executor-state validation, and exposes
  `install_jvm_deploy_descriptor()` for deterministic class-byte installation.
  The installer now enforces `max_class_bytes` and `max_total_class_bytes`
  through a `JvmConfig`/`JvmClassStoreLimits` overload, so deploy admission can
  apply ConfigParam 85 class-store retention limits before updating
  `class_state_root`.
- ✅ Load state-backed contract classes into Avata:
  Avata now exposes `avata_define_contract_class()`, covered by
  `ContractDefineClassAbi`, and the linked resolver installs all class
  definitions from `JVMC` into the per-`class_state_root` VM before method
  resolution. Parameterized static-void invocation is now covered by the typed
  `JVMA` bridge and `ContractStaticVoidInvocationAbi`.
- ✅ Keep the JDK8u reference revision pinned in docs when behavior is copied or
  compared. Current local reference checkout: `~/jdk8u` at `24fbffc3f77f`.
- ✅ Add cross-platform deterministic test runs: same bytecode, same inputs,
  fresh heap, byte-identical output state on Linux/macOS/Windows and target
  validator architectures. `make -C jvm/avata run-test` now runs a deterministic
  replay phase after the normal Java tests, executing every Java test twice with
  the same VM/classpath/input and comparing complete stdout/stderr. The same
  generated `run-determinism.sh` is also used by the existing remote-test path,
  so CI/remote runners can enforce the same replay check on each supported OS
  and architecture. `test-workchain-execution-registry` also includes
  `JvmComputeOutputIsDeterministicAcrossReplay`, which runs the same JVM compute
  input twice and compares committed `new_data` and action-list cell hashes plus
  gas, exit code, and VM log.
- ✅ Add profile negative tests for forbidden host APIs. Historical
  `test/HostAPITest.java` covered broad Java SE host surfaces before the
  classpath cut; the current profile suite includes `test/CoreTrapProfile.java`
  for `Object.wait/notify` and thread join/interruption traps. Whole-class
  forbidden APIs are validated by their absence from `rt.jar`.

## Completed In `feature/avata-jvm`

- ✅ Avata fork imported and renamed.
- ✅ Classpath wildcard support.
- ✅ Bounds hardening for `arraycopy`, `String`, `Writer`, `defineClass`, and
  zip/zlib APIs.
- ✅ NIO accept descriptor leak coverage.
- ✅ LZMA temporary loader cleanup.
- ✅ Slimmed Avata to the TOS contract VM profile: removed OpenJDK/Android
  classpath bridges, bootimage/codeimage generator, JIT/codegen/AOT sources,
  embed loader, LZMA build variants, and legacy build-matrix entries. The
  remaining local build is interpreter + self-contained Avata/TOS runtime.
- ✅ Slimmed the Java class library to the v1 contract `rt.jar` profile:
  removed `java.net`, `java.nio`, `java.security`, `java.text`, `java.math`,
  `java.util.concurrent`, `java.util.logging`, `java.util.regex`,
  `java.util.zip`, `java.util.jar`, `dalvik`, `libcore`, process APIs,
  filesystem path APIs, public file descriptor streams, object-stream
  serialization, URL/resource handler packages, hash/identity/weak collections,
  `Properties`, legacy synchronized collections/tokenizers, and thread-local
  APIs. The generated `rt.jar` now contains only `java.lang`, annotations,
  minimal `java.io`, deterministic ordered/list collections,
  `java.util.function`, and VM-private `java.internal.*` support classes required by
  the boot runtime. Contract admission rejects application class names and
  references under `java/internal/*`. `java.util.EnumSet` is absent because application
  enum classes are outside v1. Public
  `java.lang.invoke`, `java.lang.ref`, `java.lang.reflect`, and `sun.*`
  classes are no longer shipped.
- ✅ Removed additional non-contract public surfaces from the v1 `rt.jar`:
  `java.lang.Runtime`, `java.io.FileNotFoundException`, host-backed
  `System.in`, `Math.random`, host-native `Math` transcendental functions,
  host-libc float/double string parse/format APIs, `StringBuffer`, and
  `Collections.synchronized*` wrappers. `System.in` is now deterministic EOF;
  stdout/stderr writes are best-effort debug output and do not feed host IO
  errors back into contract behavior.
- ✅ Added `rt/check-profile.sh` to `build-test`, so generated `rt.jar` fails
  the build if forbidden packages or non-admitted shell classes are reintroduced.
- ✅ Removed callable native-internal and non-admitted invoke shell classes:
  `java.lang.invoke`, `sun.misc.Unsafe`, `java.internal.Machine`, and `java.internal.Traces`
  are absent from `rt.jar`.
- ✅ Removed non-contract class-generation and continuation APIs from
  `rt.jar`: `java.internal.Assembler`, `java.internal.ConstantPool`, `java.internal.Stream`,
  `java.internal.Continuations`, `java.internal.Callback`, `java.internal.Function`, and
  `java.internal.IncompatibleContinuationException`. The verifier test keeps private
  class-file writer helpers under `test/avata/testing/bytecode`.
- ✅ Removed stale broad-profile tests and extra tools that depended on APIs no
  longer present in the contract runtime, including host file IO,
  application enums/`EnumSet`, command-line property override behavior, old
  tail-call variants, and heap-dump helpers built on hash collections.
- ✅ Turned `Object.wait/notify/notifyAll` and `Thread.join/interruption` into
  deterministic `ContractViolationError` traps. `Thread.activeCount()`,
  `enumerate()`, and `getId()` now return fixed single-thread profile values.
- ✅ POSIX synchronization error checks.
- ✅ `file.encoding` user override handling.
- ✅ File input/output native calls now retry interrupted syscalls and reject
  directories at open time, following JDK8u behavior.
- ✅ `RandomAccessFile` now follows the same JDK8u native open/read/write retry
  model, rejects directories on open, supports `rws`/`rwd`, EOF reads,
  `setLength`, and the core `DataOutput` methods.
- ✅ `File` metadata helpers now follow JDK8u-style behavior for canonical
  paths, exclusive file creation, existing-directory `mkdir`, interrupted
  `stat`/`access`/`chmod`/`remove`/`rename` calls, and directory iteration.
- ✅ Removed the earlier Java-surface lambda bootstrap implementation from the
  v1 profile. It is no longer part of `rt.jar`; future `invokedynamic` work
  must be VM-internal and consensus-specified.
- ✅ `Method.getExceptionTypes` and `Constructor.getExceptionTypes` now expose
  declared exception classes from the parsed class-file `Exceptions` attribute.
- ✅ `Class.getTypeParameters` now follows the JDK8u class-level type-variable
  surface for admitted signatures, including declaration identity, multiple
  bounds, default `Object` bounds, bound-array cloning, and equality/hash code.
- ✅ `Method` and `Constructor` now implement the admitted JDK8u generic
  reflection surface for type parameters, generic parameter types, generic
  exception types, method generic return types, and parameter counts.
- ✅ `ParameterizedType` results now use JDK8u-style structural equality,
  hash codes, and cloned actual-type-argument arrays.
- ✅ Generic reflection now parses admitted JDK8u wildcard type arguments and
  generic array types, including cloned wildcard bounds plus structural
  equality/hash codes.
- ✅ `Pattern.compile(regex, flags)` now follows JDK8u flag validation for the
  admitted deterministic subset: `LITERAL`, `DOTALL`, `MULTILINE`, and ASCII
  `CASE_INSENSITIVE`; unsupported locale/Unicode/canonical modes, including
  Java 8's `UNICODE_CHARACTER_CLASS`, fail deterministically.
- ✅ `LinkedBlockingQueue.iterator()` now exposes the admitted queue iterator
  surface as a deterministic FIFO snapshot; iterator mutation fails explicitly.
- ✅ `ConcurrentLinkedQueue` now covers the JDK8u queue surface that Avata had
  left unsupported: size/emptiness, containment, removal, bulk removal,
  typed/untyped arrays, weakly consistent iteration, null rejection, and
  `addAll` edge cases.
- ✅ `TreeMap.subMap`, `headMap`, and `tailMap` now return backed `SortedMap`
  range views with JDK8u-style endpoint checks, range-limited reads/writes,
  iteration, removal, and clear behavior.
- ✅ `Reader.skip`/`ready` now follows JDK8u defaults. The earlier
  `FilterReader` compatibility work was superseded by the contract profile:
  `FilterReader` is now removed from `rt.jar`.
- ✅ `ByteBuffer.order(ByteOrder)` now supports deterministic big-endian and
  little-endian primitive access with JDK8u null/default-order behavior.
- ✅ `Formatter` integer conversions now cover the admitted JDK8u flag surface:
  sign, leading-space, parentheses, grouping, alternate octal/hex prefixes,
  zero padding after prefixes/signs, previous-argument reuse, and zero-length
  string precision.
- ✅ Heap `ByteBuffer` and `CharBuffer` views now follow JDK8u read-only and
  backing-array rules: writable slices stay writable, read-only views hide
  arrays and preserve read-only state through slices/duplicates.
- ✅ `Long`/`Integer` radix string helpers now follow the JDK8u unsigned
  conversion surface for hex/octal/binary and Java 8 `toUnsignedString`
  helpers, including invalid-radix fallback to base 10.
- ✅ `SimpleDateFormat` now supports a deterministic JDK8u-compatible numeric
  subset for `y/M/d/H/m/s` fields plus quoted literals, while still rejecting
  locale-specific text fields outside the consensus profile.
- ✅ `BitSet` core navigation and sizing now follow JDK8u behavior for logical
  length, `nextSetBit`/`nextClearBit`, full clear, range checks, and
  differently-sized intersection checks.
- ✅ `Locale` and locale-aware `String` case conversion now cover the admitted
  JDK8u deterministic surface: core locale constants, constructor
  normalization, old ISO language-code mapping, structural equality/hash codes,
  null handling, ROOT/English-compatible case operations, and explicit traps for
  locale-specific Turkish/Azeri/Lithuanian casing.
- ✅ Hash-backed collections were removed from the admitted contract profile:
  `HashMap`, `HashSet`, `LinkedHashMap`, `LinkedHashSet`, `Hashtable`,
  `IdentityHashMap`, `WeakHashMap`, and `Properties` are absent from `rt.jar`.
- ✅ `TreeMap` top-level and ranged collection views now follow the admitted
  JDK8u mutation rules: key/entry view `add` rejects, entry containment/removal
  matches both key and value, values support removal and bulk removal, and
  range values can remove backed map entries in sorted order.
- ✅ `java.util.regex.Matcher` now follows the admitted JDK8u match-state
  surface: reset and failed matches clear prior state, `find(int)` rejects
  invalid start offsets, group count is available before matching, invalid
  groups throw bounded exceptions, and unmatched optional groups return
  `-1`/`null`.
- ✅ `ObjectOutputStream` now writes JDK8u-style stream handles for strings,
  class descriptors, and ordinary objects, so admitted serialization preserves
  shared references and self-references; array field descriptors are emitted
  and read using binary names compatible with JDK8u descriptor strings.
- ✅ `ObjectOutputStream` and `ObjectInputStream` now handle array object
  serialization via TC_ARRAY (classDesc with sUID=0, SC_SERIALIZABLE, 0 fields;
  int length; all element types), matching the JDK8u wire format exactly. Enum,
  `Externalizable`, `writeReplace`, and `readResolve` throw deterministic
  `UnsupportedOperationException` with fixed messages. `InvalidClassException`
  added with JDK8u-compatible `classname` field. Exception types aligned across
  write and read paths.
- ✅ `java.lang.invoke` removed from the v1 contract classpath. The remaining
  Java 8 `invokedynamic` work is tracked as a VM-internal deterministic
  bootstrap design item, not as a public method-handle API compatibility item.
- ✅ Reflection API removed from the contract profile; `Class.isSynthetic()`
  remains as a pinned metadata helper, while dynamic `Class.forName` and the
  old private `Class$ClassType` anonymous/local/member classification helper
  were removed from `rt.jar`. Reflection checked-exception shells
  `IllegalAccessException`, `NoSuchFieldException`, and
  `NoSuchMethodException` were also removed. `FunctionalInterface` annotation
  added; `Long.compare(long,long)` added.
- ✅ Further runtime slimming removed Java SE package metadata and low-value
  reflection conveniences from `rt.jar`: `java.lang.Package`,
  `Class.getPackage`, declared/enclosing/declaring-class queries,
  `desiredAssertionStatus`, `asSubclass`, and `cast`. The VM package-source
  map and native package lookup entry point were removed too.
- ✅ Removed the old VM wait/notify helper paths from the contract runtime.
  `Object.wait/notify` remain deterministic `ContractViolationError` traps.
  `InterruptedException` stays only as a JDK8 `javac` boot-classpath symbol,
  and application references to it are rejected by the verifier.
- ✅ Contract-profile class library cleanup removed source/parser reader
  decorators (`FilterReader`, `LineNumberReader`, `PushbackReader`) plus
  empty or partial collection shells (`AbstractMap`, `NavigableMap`). The
  verifier and `rt/check-profile.sh` now reject references to these APIs.
- ✅ Removed additional Java SE wrapper and hierarchy shells:
  `FilterInputStream`, `FilterOutputStream`, and `AbstractSequentialList`.
  `LinkedList` now extends the admitted `AbstractList` base directly. The
  verifier also rejects application references to boot-only compatibility
  symbols such as `Serializable`, `Cloneable`, `CloneNotSupportedException`,
  and `ClassNotFoundException`.
- ✅ Marked `java.internal.*` as VM-private instead of contract-facing API:
  contract-facing memory counters are exposed through `java.lang.Memory`, while
  strict contract admission rejects application class names and constant-pool
  references under `java/internal/*`. `java.lang.Class` no longer exposes
  `java.internal.VMClass` through public fields, constructors, or methods.
- ✅ Moved the VM-private Java runtime implementation package from `avata.*`
  to `java.internal.*`: sources now live under `jvm/avata/rt/java/internal`,
  native entry points use `Avata_java_internal_*`, `types.def` names
  `java/internal/*`, and the old `avata/*` Java package is rejected as stale.
- ✅ Removed stale Avian host native entry points that are not part of the
  contract runtime: `sun.misc.Unsafe`, host file-system IO, process runtime
  hooks, host `System` property/environment/time/library helpers, Date
  formatting, object-stream allocation, resource URL handlers, and internal
  Machine escape hatches. `build-test` now runs `rt/check-native-profile.sh` to
  prevent these symbols from returning.
- ✅ Added a separate contract compiler API artifact:
  `jvm/avata/build/<platform>-<arch>/api.jar` is generated from the
  runtime class tree with the VM-private `java/internal/*` package excluded. `build-test`
  checks that this jar has no `java/internal/*` entries, can compile a basic contract
  source through javac, and rejects source-level `import java.internal.*`.
- ✅ Added a generated contract profile manifest for the verifier:
  `rt/generate-profile-header.sh` reads `api.jar`, removes VM/runtime-private
  bridge classes from the application-visible profile, and writes
  `src/avata/contract-profile.h`. `build-test` diffs a freshly generated copy
  against the checked-in header so `api.jar` and verifier policy cannot drift.
- ✅ Added the initial `tos-javac` prototype at `jvm/avata/tools/tos-javac`.
  It forces Java 8 source/target settings, uses `api.jar` as the boot
  classpath, rejects user bootclasspath/source/target overrides, runs a
  post-compile class-file admission check against the generated contract
  profile, and is covered by `build-test`. The wrapper now rejects generated
  lambda/`invokedynamic` bytecode, mutable static fields, application
  `<clinit>`, enum classes, native/synchronized/finalizer methods, unsupported
  class-file versions, stale `avata/*` classes, and `java/*` references outside
  the admitted profile before deployment.
- ✅ Host-API consensus hardening: `System` exposes only deterministic VM-managed
  streams and fixed property reads; `Runtime` is removed from the v1 `rt.jar`;
  `Thread` remains VM-internal and contract references are rejected. The earlier
  `java.net.*` and `java.nio.channels.*` trap shells were removed from the v1
  `rt.jar` entirely.
- ✅ Class-library sweep: `java.util.function` package (Function, BiFunction,
  Consumer, BiConsumer, Predicate, Supplier); `Optional<T>`; `StringJoiner`;
  `UUID` deterministic rewrite (`randomUUID()` traps, `fromString`/`toString`
  lowercase, `Comparable`); `Date` (`setTime`, `before`/`after`, `compareTo`,
  `Comparable`); `Map` Java 8 defaults (`computeIfAbsent`, `merge`,
  `forEach`, `replaceAll`, `getOrDefault`);
  `Collections` additions (`singleton`, `singletonMap`, `nCopies`, `min`/`max`,
  `frequency`, `fill`, `copy`, `disjoint`, `reverseOrder`, `unmodifiableSorted*`,
  `indexOfSubList`, `addAll` varargs, `swap`, `binarySearch(Comparator)`);
  `Arrays` (primitive sorts all types, `copyOfRange` all types, additional
  `binarySearch` overloads, `hashCode` all types, `deepToString`); `TreeSet`
  `SortedSet` + backed `subSet`/`headSet`/`tailSet`; `ArrayList.subList` backed;
  `Collection.removeIf`; `Iterable.forEach`; `CharBuffer.wrap(CharSequence)`,
  `toString`, `subSequence`.
- ✅ P0 gas counter infrastructure: `Thread::gasCounter` (uint64_t, init
  `UINT64_MAX`) and `Thread::identityHashCounter` (uint32_t, init 0) added to
  `vm::Thread`; interpreter dispatch loop decrements counter and traps on zero.
- ✅ P0 object identity: `objectHash()` replaced with per-transaction counter
  (`++identityHashCounter & 0x7FFFFFFF`), eliminating ASLR pointer leakage.
- ✅ P0 class-file version gate: `machine.cpp` rejects major < 45, major > 52,
  or minor == 0xFFFF; `UnsupportedClassVersionError`, `ClassFormatError`,
  `ContractViolationError`, `OutOfGasError` added to classpath.
