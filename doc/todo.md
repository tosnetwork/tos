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
    `GcOutOfMemoryError` (placeholder) when the counter reaches zero; a value of
    `UINT64_MAX` bypasses the check (bootstrap mode).
  - **Remaining work:**
    - Replace placeholder `GcOutOfMemoryError` with `GcOutOfGasError` once
      `OutOfGasError` is wired into `types.def` and the generated Gc types.
    - Wire `jvm/core/compute-phase.cpp` to set `t->gasCounter = input.gas_limit`
      and `t->identityHashCounter = 0` before each contract invocation.
    - Replace the flat per-opcode cost of 1 with the opcode cost table from
      `jvm/core/gas-table.cpp` (ConfigParam 85).

- [ ] Disable or isolate JIT/AOT/host-VM compilation paths for consensus execution.
  Contract execution must use a deterministic interpreter-only profile unless a
  future compiled profile is proven byte-identical across validators.
  - **Status:** The JIT (`compile.cpp`, `compile-x86_64.S`, etc.) is present in
    the source tree but `src/CMakeLists.txt` does not include `compile.cpp` in
    any library target. The `MyProcessor::compileMethod()` in `interpret.cpp`
    calls `abort(s)`, making JIT invocation a hard crash at runtime. The CMake
    `avata_interpreter` static library target (to be defined in P2 build work)
    must explicitly exclude all `compile-*.cpp` / `compile-*.S` files. No further
    code change is needed for correctness; the build configuration is the
    gate-keeper. Annotate `CMakeLists.txt` to document the intentional exclusion.

- [ ] Define and enforce a deterministic class-file verifier profile: supported
  class-file versions, TOS extensions, forbidden attributes/classes, duplicate
  ABI method handling, class initialization rules, and deterministic trap
  behavior.
  - **Partially implemented:** `jvm/avata/src/machine.cpp` now rejects class
    files with `major < 45` (pre-Java 1.1), `major > 52` (Java 9+), or
    `minor == 0xFFFF` (Java preview features) by throwing
    `GcUnsupportedClassVersionError`. Supporting Java files added:
    `classpath/java/lang/UnsupportedClassVersionError.java` and
    `classpath/java/lang/ClassFormatError.java`; `types.def` entry added for
    `unsupportedClassVersionError`.
  - **Remaining work:**
    - After the version gate, scan the constant pool in `parsePool()` for
      references to classes in forbidden packages (`java.net.*`,
      `java.nio.channels.*`, `java.lang.Thread`, `java.lang.Runtime`,
      `java.lang.reflect` outside the admitted surface) and throw
      `GcVerifyError` deterministically.
    - In `parseMethodTable()` / `parseFieldTable()`, reject forbidden attributes:
      `Module`, `ModulePackages`, `ModuleMainClass`, `NestHost`, `NestMembers`,
      `Record`, `PermittedSubclasses`.
    - Add duplicate ABI method detection: two methods with the same name+descriptor
      in the same class must be rejected (per JVMS §4.6).
    - Files to modify: `jvm/avata/src/machine.cpp` (`parsePool`,
      `parseMethodTable`, `parseFieldTable`).

- [ ] Replace host-observing APIs with deterministic traps or TOS-provided values:
  wall-clock time, filesystem, networking, process APIs, native library loading,
  reflection surfaces outside the admitted profile, and thread scheduling.
  - **Status:** `java.lang.System` in `classpath/java/lang/System.java` already
    traps `currentTimeMillis()`, `nanoTime()`, `getenv()`, `load()`,
    `loadLibrary()`, `mapLibraryName()`, `exit()` with
    `UnsupportedOperationException`. The native C++ surface
    (`classpath-android.cpp`) still calls `t->m->system->now()` for
    `Avata_java_lang_System_currentTimeMillis` and
    `Avata_java_lang_System_nanoTime` — these are reachable if the Java
    `System.java` trap is bypassed by native reflection.
  - **Remaining work:**
    - Patch `Avata_java_lang_System_currentTimeMillis` and
      `Avata_java_lang_System_nanoTime` in `src/classpath-android.cpp` to return
      0 unconditionally (or throw `ContractViolationError`).
    - Add `ContractViolationError` throw to `Avata_java_lang_ClassLoader_load`
      in `src/classpath-avata.cpp` (currently calls `loadLibrary`).
    - Audit `classpath/java-lang.cpp` `Java_java_lang_System_currentTimeMillis`
      (openjdk path) similarly.
    - Add negative tests in `unittest/` for each trapped surface.

- [ ] Make object identity deterministic or unavailable: `Object.hashCode`,
  `System.identityHashCode`, object `toString`, and exception stack traces must
  not leak process addresses or host-local execution details.
  - **Partially implemented:**
    - `Thread::identityHashCounter` (uint32_t) added to `vm::Thread` in
      `jvm/avata/src/avata/machine.h`, initialized to 0 in `Thread::Thread()`
      in `machine.cpp`.
    - `objectHash()` in `machine.h` now returns `(++t->identityHashCounter) &
      0x7FFFFFFF` for un-extended non-fixed objects, replacing the
      address-derived value. GC copy callback updated to call `gcTakeHash()`
      (pointer-based) rather than `takeHash()` so the counter is not consumed
      during GC moves.
    - `gcTakeHash()` (pointer-based, idempotent) added alongside `takeHash()`
      alias and the new counter-based `objectHash()`.
  - **Remaining work:**
    - `Avata_java_lang_Object_toString` in `src/builtin.cpp` still uses
      `objectHash(t, this_)` and formats `"ClassName@0x%x"`. Change to strip the
      `@` address suffix or replace with a fixed `"ClassName@<hash>"` using the
      counter-based value.
    - Exception stack traces (`Traces.java`, `builtin.cpp`) must not include
      host-local file paths. Verify that `StackTraceElement.getFileName()` and
      `.getLineNumber()` only include class-file-embedded source info, not
      absolute host paths.
    - `jvm/core/compute-phase.cpp` must reset `t->identityHashCounter = 0` at
      the start of each transaction so counter values are transaction-scoped.
    - GC-moved objects still get a pointer-based hash stored in their extended
      word (see `gcTakeHash`). Full determinism requires either (a) disabling GC
      during contract execution or (b) a side-table mapping objects to
      counter-assigned hashes that survives GC moves. Option (a) is preferred for
      the initial TOS execution model.

- [ ] Finalize contract heap/state persistence: static field admission rules,
  persisted primitive/value profiles, `PersistentMap`/`PersistentList`
  encoding, heap reset/snapshot model, and GC/arena behavior.
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
    - `PersistentMap` and `PersistentList` are not yet implemented; they need
      TL-B codec stubs in `jvm/core/` that the classpath Java classes delegate
      to via native methods.
    - Files to modify: `jvm/avata/src/machine.cpp` (static table snapshot
      hooks), `jvm/avata/src/heap/heap.cpp` (transaction reset), new files
      `jvm/avata/classpath/tos/storage/PersistentMap.java`,
      `jvm/avata/classpath/tos/storage/PersistentList.java`,
      `jvm/core/cell-codec.cpp`.

## Added classpath files

- ✅ `classpath/java/lang/ContractViolationError.java` — deterministic trap base
  class for forbidden host-API access; extends `Error`.
- ✅ `classpath/java/lang/OutOfGasError.java` — thrown by the interpreter when
  `gasCounter` reaches zero; extends `Error`.
- ✅ `classpath/java/lang/ClassFormatError.java` — base for class-file format
  violations; extends `LinkageError`.
- ✅ `classpath/java/lang/UnsupportedClassVersionError.java` — thrown by the
  class reader for class files targeting Java 9+ or pre-Java 1.1; extends
  `ClassFormatError`.

## P1 JDK8u Compatibility Gaps

- ✅ Continue aligning native IO error handling with JDK8u:
  file metadata helpers, directory handling, interrupted syscalls, and close
  semantics now have a full pass for the current Avata `java.io` surface.
- ✅ Complete `invokedynamic`/lambda support for the admitted Java profile:
  marker interfaces, bridge methods, and deterministic bootstrap linkage now
  follow the JDK8u `altMetafactory` argument model for Avata's lambda surface.
- ✅ Audit `java.lang.invoke` against OpenJDK 8u behavior: `CallSite` is now
  abstract per JDK8u; `ConstantCallSite` is the sole admitted subclass;
  `MutableCallSite` and `VolatileCallSite` trap deterministically (runtime
  target mutation breaks consensus); `MethodHandle` non-admitted methods trap;
  `MethodHandles.lookup()`/`publicLookup()` and all `Lookup` factory methods
  trap (host-observing); `SerializedLambda` traps (lambda serialization not
  admitted); `WrongMethodTypeException` and `MethodHandleInfo` added per JDK8u
  API surface.
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
- ✅ Add negative tests for forbidden host APIs: `test/HostAPITest.java` (28
  sub-tests) covers `System` time/env/load/exit, `Runtime.exec`/halt/hooks,
  `Thread.start`/sleep/yield, `Socket`/`InetAddress`/`URLClassLoader`,
  `SocketChannel`/`Selector` — all pass with deterministic
  `UnsupportedOperationException`.

## Completed In `feature/avata-jvm`

- ✅ Avata fork imported and renamed.
- ✅ Classpath wildcard support.
- ✅ Bounds hardening for `arraycopy`, `String`, `Writer`, `defineClass`, and
  zip/zlib APIs.
- ✅ NIO accept descriptor leak coverage.
- ✅ LZMA temporary loader cleanup.
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
  JDK8u; `ConstantCallSite` admitted; `MutableCallSite`/`VolatileCallSite` trap;
  `MethodHandle` Java-surface non-admitted methods trap; `MethodHandles.Lookup`
  factory methods trap; `SerializedLambda` traps; `WrongMethodTypeException` and
  `MethodHandleInfo` added; `LambdaMetafactory` updated to use `ConstantCallSite`.
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
