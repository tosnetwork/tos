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
- [ ] Add gas accounting to the Avata interpreter dispatch loop. Every bytecode and
  admitted runtime helper must charge deterministic gas and throw a deterministic
  out-of-gas trap.
- [ ] Disable or isolate JIT/AOT/host-VM compilation paths for consensus execution.
  Contract execution must use a deterministic interpreter-only profile unless a
  future compiled profile is proven byte-identical across validators.
- [ ] Define and enforce a deterministic class-file verifier profile: supported
  class-file versions, TOS extensions, forbidden attributes/classes, duplicate
  ABI method handling, class initialization rules, and deterministic trap
  behavior.
- [ ] Replace host-observing APIs with deterministic traps or TOS-provided values:
  wall-clock time, filesystem, networking, process APIs, native library loading,
  reflection surfaces outside the admitted profile, and thread scheduling.
- [ ] Make object identity deterministic or unavailable: `Object.hashCode`,
  `System.identityHashCode`, object `toString`, and exception stack traces must
  not leak process addresses or host-local execution details.
- [ ] Finalize contract heap/state persistence: static field admission rules,
  persisted primitive/value profiles, `PersistentMap`/`PersistentList`
  encoding, heap reset/snapshot model, and GC/arena behavior.

## P1 JDK8u Compatibility Gaps

- ✅ Continue aligning native IO error handling with JDK8u:
  file metadata helpers, directory handling, interrupted syscalls, and close
  semantics now have a full pass for the current Avata `java.io` surface.
- ✅ Complete `invokedynamic`/lambda support for the admitted Java profile:
  marker interfaces, bridge methods, and deterministic bootstrap linkage now
  follow the JDK8u `altMetafactory` argument model for Avata's lambda surface.
- [ ] Audit `java.lang.invoke` against OpenJDK 8u behavior and decide which parts
  are supported in consensus, rejected at verification, or trapped at runtime.
  `LambdaConversionException` now follows the JDK8u constructor surface.
- [ ] Complete reflection compatibility where admitted by the verifier:
  remaining unsupported paths and full generic signature parsing. Class,
  method, and constructor type parameters plus generic method/constructor
  parameter, return, and exception types now use admitted `Signature`
  metadata; `Method.getExceptionTypes` and
  `Constructor.getExceptionTypes` now resolve the class-file `Exceptions`
  attribute.
- [ ] Finish encoding/console behavior:
  `file.encoding` default/override behavior is fixed, but stdout/stderr console
  encoding and unsupported charset handling still need cross-platform checks.
- [ ] Align serialization and object stream behavior with the admitted runtime
  profile. Unsupported object graph cases must fail deterministically.
- [ ] Fill class-library gaps that matter for contract tooling and tests:
  selected `java.util`, `java.nio`, `java.util.regex`, and `java.text`
  unsupported paths.

## P2 Platform And Build Work

- [ ] Integrate Avata as a static library in the main TOS CMake build with a narrow
  exported target for the interpreter profile.
- [ ] Keep the JDK8u reference revision pinned in docs when behavior is copied or
  compared. Current local reference checkout: `~/jdk8u` at `24fbffc3f77f`.
- [ ] Add cross-platform deterministic test runs: same bytecode, same inputs,
  fresh heap, byte-identical output state on Linux/macOS/Windows and target
  validator architectures.
- [ ] Add negative tests for forbidden host APIs and unsupported class-file
  features so failures happen at verification or deterministic trap boundaries.

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
