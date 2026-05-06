# TOS JVM Contract Profile

Status: working design
Date: 2026-05-05

This document defines the practical development target for Avata inside the TOS
JVM workchain. It is intentionally narrower than OpenJDK 8. The goal is to build
a deterministic Java 8 bytecode smart-contract VM with a familiar Java developer
workflow, not a general-purpose host JVM.

## First Principles

The JVM workchain has three compatibility commitments:

1. **Java 8 bytecode compatibility is mandatory.** Avata must execute ordinary
   Java 8 class files. The class-file format, constant pool, verifier, linker,
   interpreter, exceptions, `invokedynamic`, monitor opcodes, and all Java 8
   bytecode opcodes must follow the Java 8 JVMS/OpenJDK execution model for the
   admitted class-file profile.
2. **The runtime library is a TOS smart-contract runtime.** The shipped
   `rt.jar` is designed for deterministic on-chain execution. It may reuse
   OpenJDK 8 class shapes and semantics where they serve Java source/tooling
   compatibility, but it is not required to implement the full OpenJDK 8 class
   library.
3. **The developer workflow should feel like Java.** Developers should write
   Java 8 source, compile it with a TOS-provided `javac` path against the TOS
   `rt.jar`, run it locally with a TOS-provided `java`-style runner, and deploy
   the resulting normal class files after verifier/admission checks.

Everything else follows from these principles. OpenJDK class-library parity is
not an independent goal. It is useful only when it supports the contract runtime
profile without violating consensus determinism.

## Non-Goals

- Run arbitrary desktop/server Java applications.
- Provide full OpenJDK 8 API compatibility.
- Expose validator-local filesystem, networking, process, native library,
  thread scheduling, wall-clock, entropy, environment, or host classpath state.
- Preserve host JVM implementation details such as address-derived identity
  hash codes, native stack traces, platform floating-point behavior, or
  class-loader access to local code.
- Support JIT/AOT execution in the consensus profile.

## Current Avata Slim Baseline

As of 2026-05-05, `jvm/avata` keeps only the execution pieces that fit the TOS
contract profile:

- Interpreter execution only.
- Self-contained Avata/TOS `rt/` only.
- No OpenJDK runtime/classpath bridge.
- No Android/libcore bridge.
- No bootimage/codeimage generator or runtime hook.
- No JIT/codegen, embed loader, or LZMA build variants.
- No legacy `jdk-test`/OpenJDK/Android/bootimage build matrix.
- Restricted Java 8 contract class library: broad Java SE host packages are
  removed from the shipped classpath rather than kept as partial host-facing
  compatibility layers.

The runtime source set was reduced from roughly 420 Java/C++/header files to
251 Java/C++/header files. The generated `rt.jar` no longer contains
these package prefixes:

- `java.net`
- `java.nio`
- `java.security`
- `java.text`
- `java.math`
- `java.util.concurrent`
- `java.util.logging`
- `java.util.regex`
- `java.util.zip`
- `java.util.jar`
- `dalvik`
- `libcore`
- Avata URL/file/jar/http resource-handler packages

The remaining `rt.jar` surface is intentionally narrow: `java.lang`,
annotations, minimal byte-array/string/descriptor-backed `java.io`,
deterministic collections, `java.util.function`, and Avata VM support classes.
It does not ship `java.lang.invoke`, `java.lang.reflect`, `java.lang.ref`, or
`sun.*`. Method handles, lambda bootstrap classes, reflection, dynamic proxies,
weak/soft/phantom references, finalization, cleaners, `sun.misc.Unsafe`,
`avata.Machine`, and `avata.Traces` are not shipped in `rt.jar`.

`~/jdk8u` remains useful as a reference checkout for Java 8 opcode, verifier,
and admitted API semantics. It is not a runtime build input for the consensus
profile.

The slim baseline has been verified with:

```bash
make -C jvm/avata java-version=8 build-test
make -C jvm/avata java-version=8 input=Hello run
make -C jvm/avata java-version=8 run-test
```

## Compatibility Boundary

### Engine Compatibility

Avata must be developed as a Java 8 class-file execution engine. This is the
hard compatibility boundary.

Required engine surface:

- Class-file major version 52.
- JVMS-compatible constant-pool parsing for Java 8 entries.
- StackMapTable/type verification for the admitted profile.
- All Java 8 bytecode opcodes.
- Static, virtual, special, interface, and dynamic dispatch.
- Java 8 opcode decoding, including `invokedynamic`. The v1 contract profile
  currently rejects `CONSTANT_MethodHandle`, `CONSTANT_MethodType`,
  `CONSTANT_InvokeDynamic`, and `BootstrapMethods` before execution because the
  runtime does not admit public `java.lang.invoke` classes. A future admission
  must use deterministic VM-internal bootstrap linkage rather than exposing the
  Java SE method-handle API.
- Exception handling and deterministic stack unwinding.
- Class initialization rules pinned for deploy-time and call-time execution.
- Deterministic monitor semantics for `monitorenter` and `monitorexit` in the
  single-threaded execution model.
- Strictfp-equivalent fixed floating-point execution for every `float` and
  `double` opcode.

Class files that use unsupported versions, attributes, host-observing
references, or profile-forbidden features must be rejected by the verifier or
fail through deterministic traps.

### Runtime Library Compatibility

The TOS `rt.jar` is a contract runtime surface, not a full Java SE runtime. It
has three categories:

- **Language-required Java classes:** `java.lang.Object`, `String`, `Class`,
  primitive wrappers, `Throwable`, core errors/exceptions, `Math`,
  and the small interfaces/classes needed for Java 8 source to compile and run.
- **Contract APIs:** `tos.contract.*`, `tos.storage.*`, `tos.emit.*`, and other
  chain-specific APIs for persistent state, ABI entry points, events, caller
  context, value transfer, and deterministic chain data.
- **Compiler-required metadata classes:** small Java 8 source/tooling support
  types that are genuinely required by `javac` and the admitted class-file
  profile. Host-facing Java SE classes are deleted from `rt.jar` instead of
  kept as empty throwing shells.

The runtime library should preserve Java behavior inside the admitted profile.
Outside it, deterministic failure is better than partial OpenJDK behavior.

## API Policy

Each API must be classified before implementation:

| Category | Meaning | Expected Behavior |
|---|---|---|
| Admitted | Safe and useful for contracts | Implement and test against Java 8 semantics where applicable |
| TOS-specific | Chain runtime API | Define TOS semantics and test deterministic behavior |
| Forbidden | Not allowed in contract bytecode | Verifier rejects reference before execution |
| Deferred | Potentially useful but not yet specified | Treat as forbidden until admitted |

Examples:

| Area | Policy |
|---|---|
| `java.lang.Object`, `String`, primitive wrappers | Admitted, deterministic subset |
| `java.lang.Math` | Admitted only when backed by bit-exact fixed algorithms; randomness is forbidden |
| `java.lang.System` | TOS-specific deterministic chain context only; host APIs forbidden |
| Minimal `java.io` | Admitted only for byte-array/string streams and VM stdio descriptors; no path-based host filesystem |
| `java.net`, host-backed `java.nio` | Absent from v1 `rt.jar` and forbidden unless explicitly admitted later |
| `java.lang.Thread`, wait/notify, executors | Forbidden or deterministic trap |
| Reflection | Public `java.lang.reflect.*` is absent; only pinned `Class` metadata helpers remain |
| Class loading | Forbidden except validator-controlled contract class resolution |
| Serialization, regex, text formatting, zip/jar, locale/date APIs | Absent from v1 `rt.jar` unless explicitly admitted later |
| `java.lang.invoke`, `sun.misc.Unsafe`, `avata.Machine`, `avata.Traces` | Absent from v1 `rt.jar`; forbidden unless explicitly admitted later |
| Collections | Admitted selectively when deterministic and useful for contracts |

## Avata Development Order

The next Avata work should prioritize the engine and consensus boundary before
more class-library breadth.

### 1. Freeze the Verifier/Profile Contract

Create a machine-readable and documented admission profile:

- Allowed class-file version range: Java 8 major 52 for contract code.
- Forbidden attributes and post-Java-8 metadata.
- Forbidden packages/classes/methods.
- Reflection-free class metadata surface.
- Static-field policy: application classes may not declare mutable static
  fields. The verifier admits only `static final` primitive/String constants
  with a `ConstantValue` attribute; static methods remain allowed.
- Enum policy: application classes may not declare `ACC_ENUM`; Java enum
  classes are outside the v1 contract profile.
- Class-initializer policy: application classes may not declare `<clinit>`;
  hidden static initialization is rejected at class load. Boot runtime
  initializers remain internal to the pinned `rt.jar`.
- Method-flag policy: application methods may not declare `ACC_SYNCHRONIZED` or
  `ACC_NATIVE`. `monitorenter`/`monitorexit` opcodes remain supported with
  deterministic single-thread semantics, and admitted runtime native helpers
  are provided only by the pinned boot `rt.jar`.
- Finalization policy: application classes may not declare `finalize()V`.
  Object finalization is not part of the contract lifecycle.
- ABI entry point rules.
- Class initialization rules.
- Deterministic trap taxonomy.

This profile is the contract between `tos-javac`, the local runner, deploy-time
checks, and validator execution. Tooling can reject early, but validators must
re-validate the exact bytes they execute.

### 2. Complete the Java 8 Opcode Engine

Focus on interpreter correctness and determinism:

- Audit every opcode implementation against Java 8 JVMS semantics.
- Complete deterministic VM-internal `invokedynamic` linkage, without adding
  public `java.lang.invoke` classes to `rt.jar`.
- Replace host floating-point operations with deterministic fixed
  floating-point calls.
- Ensure exception handling, class initialization, and monitor opcodes are
  deterministic.
- Keep JIT/AOT disabled for the consensus profile.

### 3. Add Gas and Deterministic Traps

Every executed bytecode and admitted runtime helper must charge deterministic
gas. When gas is exhausted, execution must throw a deterministic `OutOfGasError`
or equivalent consensus trap.

Forbidden APIs must fail deterministically. No forbidden path may reach host
filesystem, network, process, native library, thread scheduling, wall-clock, or
entropy APIs.

### 4. Make Object Identity Consensus-Safe

Contract code must not observe process addresses or heap layout. Required work:

- Deterministic or unavailable `Object.hashCode`.
- Deterministic or unavailable `System.identityHashCode`.
- No address suffix in default `Object.toString`.
- Deterministic exception stack traces with no host-local file paths.
- Transaction-scoped identity state reset.

### 5. Build the Contract `rt.jar`

Define the minimum useful runtime first:

- Java language basics under `java.lang`.
- Deterministic numeric/string helpers.
- TOS contract APIs as Avata runtime extensions under `java.lang`.
- Persistent state wrappers backed by TOS cells.
- No compatibility shells for host APIs in the shipped contract `rt.jar`;
  forbidden APIs are absent or rejected by the admission profile.

Do not continue broad OpenJDK API filling unless an API is admitted by the
contract profile and has deterministic tests.

### 6. Implement the Toolchain Experience

Provide two developer-facing tools:

- `tos-javac`: wraps or configures Java 8 `javac`, forces class-file major 52,
  uses the TOS `rt.jar` as boot classpath, and runs verifier/admission checks.
- `tos-java`: local deterministic runner using the same Avata interpreter,
  `rt.jar`, gas model, fixed floating-point behavior, traps, and heap/state
  codec as validators.

The local runner must be a developer convenience, not an alternate semantics
source. Validator execution remains authoritative.

## Testing Strategy

Testing should follow the profile, not full OpenJDK API coverage.

Required suites:

- **Opcode conformance:** each Java 8 opcode, including edge cases.
- **Verifier negative tests:** forbidden class files, attributes, references,
  invalid StackMapTable/type states, duplicate ABI methods.
- **Deterministic replay:** same class bytes, inputs, config, and state produce
  byte-identical outputs across repeated runs.
- **Fixed floating-point vectors:** pinned NaN, signed-zero, infinity, overflow,
  underflow, subnormal, conversion, and compare behavior.
- **Gas tests:** deterministic cost charging and out-of-gas traps.
- **Forbidden API tests:** host APIs fail before or during execution without
  observing the host.
- **Runtime API tests:** admitted `rt.jar` APIs match documented semantics.
- **Toolchain tests:** `tos-javac` output is accepted by the validator profile;
  `tos-java` local execution matches validator execution.

OpenJDK tests may be used as references for engine semantics and admitted API
behavior, but passing the full OpenJDK class-library test suite is not a release
criterion.

## Immediate Work Items

1. Write the verifier/profile matrix and keep it pinned in docs.
2. Stop expanding OpenJDK class-library coverage unless the API is admitted by
   the contract profile.
3. Finish interpreter-only Java 8 opcode support, especially fixed
   floating-point and `invokedynamic`.
4. Wire gas accounting into the interpreter and admitted runtime helpers.
5. Turn host-observing APIs into verifier rejects or deterministic traps.
6. ✅ Define the initial slim TOS `rt.jar` package list; next, add the
   contract-facing `tos.*` APIs.
7. Build `tos-javac` and `tos-java` prototypes around the same profile.

The practical rule is simple: Avata development should first make Java 8
bytecode execution deterministic and complete, then expose only the runtime
library surface that smart contracts can safely rely on forever.
