# TOS JVM / Avata Remaining Work

This document tracks the remaining work for the TOS JVM workchain runtime.
`~/jdk8u` is the local OpenJDK 8u reference checkout used to compare JVM and
class-library behavior. Current reference revision: `24fbffc3f77f`.
Reference code is used to understand semantics; Avata changes must still fit
the TOS deterministic consensus model.

Status legend: `✅` completed, unchecked items are still open.

## P0 Consensus-Safety Work

- [ ] Implement deterministic fixed floating-point execution for all Java
  `float` and `double` opcodes. The implementation must pin rounding, NaN,
  signed-zero, infinity, and subnormal behavior across supported OS/CPU
  combinations.
  - **Design (not yet implemented):** All float/double opcodes (`fadd`, `fsub`,
    `fmul`, `fdiv`, `frem`, `dadd`, `dsub`, `dmul`, `ddiv`, `drem`, `fcmpg`,
    `fcmpl`, `dcmpg`, `dcmpl`, `f2d`, `d2f`, `f2i`, `f2l`, `d2i`, `d2l`,
    `i2f`, `i2d`, `l2f`, `l2d`) are dispatched in `interpret.cpp` using native
    C++ `float`/`double` operations which rely on the host FPU. The fix requires
    replacing each operation with a call to a software-float library that
    implements IEEE 754 with fixed round-to-nearest-even, canonical NaN
    (`0x7FC00000` for float, `0x7FF8000000000000` for double), and no
    extended precision. Recommended approach: integrate Berkeley SoftFloat 3e
    (`jvm/avata/src/softfloat/`) or use the existing
    `jdk8u/hotspot/src/share/vm/runtime/sharedRuntime.cpp` `f2i`/`d2i` clamping
    as a model for the conversion opcodes. The `fcmpg`/`fcmpl` NaN branch in
    `interpret.cpp` (lines 1469-1480) is structurally correct but uses host
    `fpclassify` and comparison operators which have no strictfp guarantee.
    Estimated scope: 400-600 lines of opcode rewrites + softfloat integration.

- [ ] Add gas accounting to the Avata interpreter dispatch loop. Every bytecode and
  admitted runtime helper must charge deterministic gas and throw a deterministic
  out-of-gas trap.
  - **Partially implemented:** `Thread::gasCounter` (uint64_t) and
    `Thread::identityHashCounter` (uint32_t) fields added to `vm::Thread` in
    `jvm/avata/src/avata/machine.h`. The interpreter dispatch loop
    (`interpret3()` in `jvm/avata/src/interpret.cpp`, label `loop:` at line 784)
    now decrements `gasCounter` on every bytecode dispatch and throws
    `GcOutOfGasError` when gas is insufficient; a value of `UINT64_MAX`
    bypasses the check (bootstrap mode). `java.lang.OutOfGasError` is wired in
    `types.def`. `include/avata/contract.h` now exposes
    `avata_begin_contract_transaction()`, `avata_end_contract_transaction()`,
    and `avata_contract_remaining_gas()` so the future workchain adapter can
    initialize gas and reset Java-visible identity hash state at the
    transaction boundary. `Machine::opcodeGasCosts[256]` now holds a
    per-opcode gas table. The interpreter charges
    `opcodeGasCosts[instruction]` before executing each bytecode. The default
    profile charges 1 for every opcode, and `include/avata/contract.h` exposes
    ABI calls to reset, set, bulk-set, and read opcode costs.
    `avata_charge_contract_gas()` now charges deterministic helper/native gas,
    returning `AVATA_CONTRACT_OUT_OF_GAS` and consuming the remaining counter on
    failure. `Machine::contractHelperGasCosts[10]` now holds helper schedules
    for storage load/store/clear, dynamic opcode surcharges (`new` object
    words, `newarray`/`anewarray`/`multianewarray` array bases and elements),
    `System.arraycopy()` base/per-element copy costs, and the fixed native-call
    surcharge charged by every Java native method invocation. The public ABI can
    reset, set, bulk-set, read, and charge helper costs through
    `avata_charge_contract_helper_gas()`. `java.lang.Storage` charges from
    that helper table before host/fallback storage access.
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
  - **Remaining work:**
    - Add the actual JVM workchain compute-phase adapter and call
      `avata_begin_contract_transaction_with_limits(thread, input.gas_limit,
      input.memory_limit)` before each contract invocation, then read
      `avata_contract_remaining_gas()` and `avata_contract_memory_used()` to
      derive resource usage.
    - Load the opcode and helper cost tables from `jvm/core/gas-table.cpp`
      (ConfigParam 85) through `avata_set_opcode_gas_costs()` and
      `avata_set_contract_helper_gas_costs()` instead of using the standalone
      defaults.
    - Extend dynamic deterministic helper costs beyond `Storage`, dynamic
      allocation, and `System.arraycopy()` to crypto, ABI, event emission,
      cross-contract calls, and any future admitted native entry points whose
      cost depends on input size. Do not add gas to Java classes directly;
      Java-level libraries are covered by opcode gas plus any native/helper
      calls they make.

- ✅ Disable or isolate JIT/AOT/host-VM compilation paths for consensus execution.
  Contract execution must use a deterministic interpreter-only profile unless a
  future compiled profile is proven byte-identical across validators.
  - **Status:** Completed by slimming the Avata source and build profile. The
    legacy JIT/codegen/AOT sources (`src/codegen/**`, `include/avata/codegen/**`,
    `src/compile*`) and codegen unit tests have been removed. Make and CMake now
    build the interpreter profile only.

- [ ] Define and enforce a deterministic class-file verifier profile: supported
  class-file versions, TOS extensions, forbidden attributes/classes, duplicate
  ABI method handling, class initialization rules, and deterministic trap
  behavior.
  - **Partially implemented:** `jvm/avata/src/machine.cpp` now rejects class
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
    methods, enum class flags, and forbidden reflection/ref refs.
  - **Remaining work:**
    - Move from the current verifier helper allowlist to a generated profile
      manifest once `rt.jar` is finalized.

- [ ] Replace host-observing APIs with deterministic traps or TOS-provided values:
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
    `rt.jar`; `java.lang.invoke`, `sun.misc.Unsafe`, `avata.Machine`, and
    `avata.Traces` are no longer shipped.
  - ✅ **Completed in contract-profile audit:** `System.getProperty()` now exposes
    only a fixed deterministic allow-list and no longer ingests VM command-line
    `-D` properties such as `avata.builtins` or `java.class.path`. The profile
    also removed legacy thread/security/type shell classes
    (`IllegalThreadStateException`, `ThreadDeath`, `SecurityException`,
    `TypeNotPresentException`) plus `Collections.shuffle`.
  - **Remaining work:**
    - Add deploy-time verifier negative tests for forbidden package/class
      references that are absent or internal-only.

- [ ] Make object identity deterministic or unavailable: `Object.hashCode`,
  `System.identityHashCode`, object `toString`, and exception stack traces must
  not leak process addresses or host-local execution details.
  - **Partially implemented:**
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
  - **Remaining work:**
    - Exception stack traces (`Throwable`, `StackTraceElement`, native trace
      builders) must not include
      host-local file paths. Verify that `StackTraceElement.getFileName()` and
      `.getLineNumber()` only include class-file-embedded source info, not
      absolute host paths.
    - The future JVM workchain compute-phase adapter must call
      `avata_begin_contract_transaction()` at the start of each transaction so
      counter values are transaction-scoped.
    - The transaction-scoped heap reset path must also discard objects whose
      identity hash was materialized in the previous transaction.

- [ ] Finalize contract heap/state persistence: persisted value profiles,
  `PersistentMap`/`PersistentList` encoding, heap reset/snapshot model, and
  bounded arena memory accounting.
  - **Partially implemented:** `java.lang.Storage` now exposes scalar
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
    - Remaining heap/state work: implement the cell-backed persistent value
      profile for `Storage`, `Mapping`, and future persistent containers;
      ensure bootstrap/classpath objects stay outside the transaction arena.
    - The real chain integration still needs to install an account-state
      overlay through `avata_set_storage_host()` before contract invocation,
      call `avata_storage_execute_transaction()` around execution, and implement
      gas charging plus chain-level write-set persistence.
    - Persistent enumerable containers are not yet implemented. The v1 profile
      currently has non-iterable `Mapping`; enumerable state needs a separately
      specified ordered container.
    - Files to modify: `jvm/avata/src/machine.cpp` (static table snapshot
      hooks), `jvm/avata/src/heap/heap.cpp` (transaction reset), and the
      TOS chain execution adapter that embeds Avata.

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
- [ ] Finish encoding/console behavior:
  `file.encoding` default/override behavior is fixed, but stdout/stderr console
  encoding and unsupported charset handling still need cross-platform checks.
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

- [ ] Integrate Avata as a static library in the main TOS CMake build with a narrow
  exported target for the interpreter profile.
- [ ] Keep the JDK8u reference revision pinned in docs when behavior is copied or
  compared. Current local reference checkout: `~/jdk8u` at `24fbffc3f77f`.
- [ ] Add cross-platform deterministic test runs: same bytecode, same inputs,
  fresh heap, byte-identical output state on Linux/macOS/Windows and target
  validator architectures.
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
  `java.util.function`, and VM-private `avata.*` support classes required by
  the boot runtime. Contract admission rejects application class names and
  references under `avata/*`. `java.util.EnumSet` is absent because application
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
  `java.lang.invoke`, `sun.misc.Unsafe`, `avata.Machine`, and `avata.Traces`
  are absent from `rt.jar`.
- ✅ Removed non-contract class-generation and continuation APIs from
  `rt.jar`: `avata.Assembler`, `avata.ConstantPool`, `avata.Stream`,
  `avata.Continuations`, `avata.Callback`, `avata.Function`, and
  `avata.IncompatibleContinuationException`. The verifier test keeps private
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
- ✅ Marked `avata.*` as VM-private instead of contract-facing API:
  contract-facing memory counters are exposed through `java.lang.Memory`, while
  strict contract admission rejects application class names and constant-pool
  references under `avata/*`. `java.lang.Class` no longer exposes
  `avata.VMClass` through public fields, constructors, or methods.
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
