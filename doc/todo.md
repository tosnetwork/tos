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
    `GcOutOfGasError` when the counter reaches zero; a value of `UINT64_MAX`
    bypasses the check (bootstrap mode). `java.lang.OutOfGasError` is wired in
    `types.def`. `include/avata/contract.h` now exposes
    `avata_begin_contract_transaction()`, `avata_end_contract_transaction()`,
    and `avata_contract_remaining_gas()` so the future workchain adapter can
    initialize gas and reset Java-visible identity hash state at the
    transaction boundary.
  - **Remaining work:**
    - Add the actual JVM workchain compute-phase adapter and call
      `avata_begin_contract_transaction(thread, input.gas_limit)` before each
      contract invocation, then read `avata_contract_remaining_gas()` to derive
      `gas_used`.
    - Replace the flat per-opcode cost of 1 with the opcode cost table from
      `jvm/core/gas-table.cpp` (ConfigParam 85).

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
    `java.net.*`, `java.nio.channels.*`, `java.lang.Thread`,
    `java.lang.Runtime`, and `java.lang.reflect.*` outside the admitted reflect
    surface. Forbidden Java 9+ class-file attributes (`Module`,
    `ModulePackages`, `ModuleMainClass`, `NestHost`, `NestMembers`, `Record`,
    `PermittedSubclasses`) are rejected in field, method, and class attribute
    tables with `GcVerifyError`. Duplicate method name+descriptor pairs are
    rejected with `GcClassFormatError`. `BootstrapMethods` is now restricted to
    the admitted Java 8 lambda surface:
    `LambdaMetafactory.metafactory` and `altMetafactory` with exact
    descriptors, method-type / method-handle / marker / bridge argument shape,
    no missing table for invokedynamic, and no serializable or unknown
    altMetafactory flags. Class initializers are admitted only as static
    `()V` methods with bytecode, and native/abstract/synchronized
    `<clinit>` methods are rejected. Constructors must be non-static and return
    `void`. Runtime initialization failure remains deterministic: an exception
    thrown from class initialization marks the class with `InitErrorFlag`,
    rethrows as `ExceptionInInitializerError`, and later initialization attempts
    throw `NoClassDefFoundError`. Supporting Java files now include
    `ClassFormatError`, `UnsupportedClassVersionError`, and `VerifyError`.
    `VerifierProfile` covers forbidden class refs, forbidden descriptors,
    forbidden attributes, duplicate methods, forbidden bootstrap methods,
    forbidden serializable bootstrap flags, missing `BootstrapMethods`,
    malformed class initializers/constructors, and admitted reflection refs.
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
  - **Completed in slim pass:** `Avata_java_lang_ClassLoader_load` now throws
    `ContractViolationError`, and the legacy
    `Java_java_lang_System_currentTimeMillis` JNI body returns deterministic
    zero if reached by future classpath changes.
  - **Completed in classpath cut:** broad host-facing packages are absent from
    `rt.jar`; `sun.misc.Unsafe`, `avata.Machine`, `avata.Traces`,
    `MutableCallSite`, `VolatileCallSite`, `SerializedLambda`, and
    `MethodHandleInfo` are no longer shipped.
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
    - GC copy callback preserves the counter-based identity hash when a side
      table entry exists; `gcTakeHash()` is now only a fallback for VM-internal
      hashTaken objects without a Java-visible identity entry.
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

- [ ] Finalize contract heap/state persistence: static field admission rules,
  persisted primitive/value profiles, `PersistentMap`/`PersistentList`
  encoding, heap reset/snapshot model, and GC/arena behavior.
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
    - Static fields are allocated in `GcSingleton* staticTable` per class (see
      `machine.cpp` `parseFieldTable`). Between transactions the static table
      must be snapshotted into the contract's persistent cell store and restored
      on re-entry. Primitive types (`int`, `long`, `boolean`, etc.) map directly
      to TL-B cell fields. Reference-type statics are admitted only if they hold
      a `PersistentMap` or `PersistentList` root.
    - Heap reset: after each transaction, all per-transaction heap objects must
      be discarded. `Thread::heap` and `Thread::defaultHeap` should be reset to
      a fresh allocation or zeroed arena. The GC (heap.cpp) needs a
      `resetForTransaction()` entry point that discards gen1/gen2 objects but
      preserves bootstrap/classpath objects loaded before the gas counter was
      enabled.
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
- ✅ Complete `invokedynamic`/lambda support for the admitted Java profile:
  marker interfaces, bridge methods, and deterministic bootstrap linkage now
  follow the JDK8u `altMetafactory` argument model for Avata's lambda surface.
- ✅ Audit `java.lang.invoke` against OpenJDK 8u behavior: `CallSite` is now
  abstract per JDK8u; `ConstantCallSite` is the sole admitted subclass;
  `MutableCallSite` and `VolatileCallSite` were initially deterministic traps
  and are now removed from the v1 classpath (runtime target mutation breaks
  consensus); `MethodHandle` non-admitted methods trap;
  `MethodHandles.lookup()`/`publicLookup()` and all `Lookup` factory methods
  trap (host-observing); `SerializedLambda` was initially a deterministic trap
  and is now removed from the v1 classpath (lambda serialization not admitted);
  `WrongMethodTypeException` retained; `MethodHandleInfo`/`Lookup.revealDirect`
  removed from the v1 classpath because direct-handle introspection is outside
  the admitted contract API profile.
- ✅ Complete reflection compatibility: `Class.getClassLoader()` returns `null`
  (bootstrap model); `Class.isSynthetic()` checks `ACC_SYNTHETIC`; `Field`
  generic type reflection works; `AccessibleObject.setAccessible` is a no-op
  (consensus profile does not restrict access); `Class.newInstance()` works for
  concrete classes, throws `InstantiationException` for interfaces;
  `Class.forName` uses caller loader; `FunctionalInterface` annotation added.
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
  (`randomUUID()` traps), `Date` `Comparable` + mutators, `Map`/`HashMap` Java
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
  filesystem path APIs, object-stream serialization, and URL/resource handler
  packages. The generated `rt.jar` now contains only `java.lang`,
  annotations, `java.lang.invoke`, `java.lang.ref`, admitted reflection,
  minimal `java.io`, deterministic collections, `java.util.function`, Avata VM
  support classes, and small `sun.*` internals required by VM internals.
- ✅ Removed callable native-internal and non-admitted invoke shell classes:
  `sun.misc.Unsafe`, `avata.Machine`, `avata.Traces`, `MutableCallSite`,
  `VolatileCallSite`, `SerializedLambda`, and `MethodHandleInfo` are absent
  from `rt.jar`.
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
- ✅ `invokedynamic` lambda bootstrap handling now resolves JDK8u-style
  `altMetafactory` marker and bridge arguments, emits marker interfaces without
  duplicate interface entries, and generates bridge forwarding methods when
  requested.
- ✅ `LambdaConversionException` constructors now match the JDK8u surface,
  including cause/message handling and the writable-stack-trace flag.
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
- ✅ `Reader.skip`/`ready` and `FilterReader.skip`/`ready` now follow JDK8u
  defaults and delegation instead of hitting unsupported runtime paths.
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
- ✅ `LinkedHashMap` collection views now follow the admitted JDK8u mutation
  rules: key/entry view `add` rejects, entry containment/removal matches both
  key and value, values support removal and bulk removal, iterator removal is
  single-use, and the linked-order index stays in sync across remove/clear.
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
- ✅ `java.lang.invoke` profile audited and aligned: `CallSite` abstract per
  JDK8u; `ConstantCallSite` admitted; `MutableCallSite`/`VolatileCallSite`
  removed from the v1 classpath;
  `MethodHandle` Java-surface non-admitted methods trap; `MethodHandles.Lookup`
  factory methods trap; `SerializedLambda` and `MethodHandleInfo` removed from
  the v1 classpath;
  `WrongMethodTypeException` retained; `LambdaMetafactory`
  updated to use `ConstantCallSite`.
- ✅ Reflection API aligned: `Class.getClassLoader()` returns null;
  `Class.isSynthetic()` added; `Class.forName` fixed; `FunctionalInterface`
  annotation added; `Long.compare(long,long)` added.
- ✅ Host-API consensus hardening: `System` (time/env/load/exit), `Runtime`
  (exec/halt/hooks, `availableProcessors()` → 1), `Thread` (start/sleep/yield),
  `java.net.*` (Socket/ServerSocket/DatagramSocket/InetAddress/URLClassLoader/URL
  http-handler), `java.nio.channels.*` (SocketChannel/ServerSocketChannel/
  DatagramChannel/Selector) all throw deterministic `UnsupportedOperationException`.
  System properties replaced with a static deterministic set. 28-test negative
  suite `HostAPITest.java` passes.
- ✅ Class-library sweep: `java.util.function` package (Function, BiFunction,
  Consumer, BiConsumer, Predicate, Supplier); `Optional<T>`; `StringJoiner`;
  `UUID` deterministic rewrite (`randomUUID()` traps, `fromString`/`toString`
  lowercase, `Comparable`); `Date` (`setTime`, `before`/`after`, `compareTo`,
  `Comparable`); `Map`/`HashMap` Java 8 defaults (`computeIfAbsent`, `merge`,
  `forEach`, `replaceAll`, `getOrDefault`, `putIfAbsent`, `replace`);
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
