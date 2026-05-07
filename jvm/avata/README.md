# Avata

Avata is the interpreter backend for the TOS JVM workchain (`wc=3`). It is a
fork of [ReadyTalk/avian](https://github.com/ReadyTalk/avian) renamed and
hardened for consensus execution inside a blockchain validator.

Pinned upstream commit: `0871979b298add320ca63f65060acb7532c8a0dd`

**This is consensus-critical code.** Every change to this directory can affect
the state transition function for `wc=3` and must be treated with the same
review standard as changes to `evm/` or `uno/`. A bytecode evaluation difference
between two validator binaries causes a fork.

## What Avata is not

- Not a general-purpose JVM for standalone programs.
- Not a tracking clone of the upstream repository. The upstream project is
  retired; we own this fork permanently.
- Not built as a multi-mode upstream Avian distribution. The supported local
  profile is interpreter-only with the Avata/TOS `rt/` runtime tree.
- Not intended for iOS, Android, OpenJDK runtime builds, boot images,
  compressed embedded loaders, or ProGuard embedding. Those paths were removed
  for the TOS profile.

## Relationship to the upstream source

The fork was taken at commit `0871979b` and renamed from `avian` to `avata`.
All subsequent changes are made in this repository. The `PINNED_COMMIT` file
records the upstream commit the fork was cut from; it is updated only when an
explicit decision is made to pull in upstream changes (see "Updating the pinned
commit" below).

The original upstream `README.md` is replaced by this file. The upstream
`LICENSE.txt` is preserved unchanged; see `LICENSE.txt` for terms. Third-party
notices for the fork are covered by `../../THIRD_PARTY_NOTICES.md`.

## TOS-specific modifications

The following changes have been made to the upstream source since the fork:

### Interpreter-only execution

The JIT/codegen sources and build paths have been removed from the TOS profile.
All contract execution runs through `interpret.cpp`. JIT compilation introduces
platform-dependent optimisation decisions that would make consensus output
non-deterministic across validator hardware.

### Deterministic floating-point

All floating-point opcodes (`fadd`, `dadd`, `fcmpl`, `dcmpg`, etc.) are routed
through the TOS deterministic fixed-FP engine rather than host CPU instructions.
This enforces `strictfp`-equivalent semantics for all contract code regardless
of the source method's `strictfp` modifier, and pins rounding mode, NaN
canonicalization, signed-zero, infinity, overflow, underflow, and subnormal
handling so that Linux/macOS/Windows and different CPU microarchitectures produce
identical bit patterns.

### Threading: deterministic single-thread semantics

`monitorenter` and `monitorexit` execute with deterministic single-thread
monitor semantics (no OS mutex; a counter per object). They do not block or
yield. Public `java.lang.Thread`, `ThreadGroup`, `ThreadLocal`, and
`java.lang.ref.*` APIs are not shipped. `Object.wait()`, `Object.notify()`, and
related monitor-wait APIs throw `ContractViolationError` deterministically
before any OS call is made.

### Non-deterministic syscall removal

The following paths are removed or replaced with deterministic stubs:

- Wall-clock time (`gettimeofday`, `clock_gettime`, `System.currentTimeMillis`,
  `System.nanoTime`): return zero; contracts must use
  `Context.blockTimestamp()` instead.
- Entropy (`/dev/urandom`, `SecureRandom`): removed; contracts use
  `Context.randSeed()`.
- Process and environment APIs (`getenv`, `System.getenv`, `Runtime.exec`):
  throw `ContractViolationError`; `System.getProperties` is absent, and
  `System.getProperty` exposes only a fixed deterministic allow-list. VM
  command-line `-D` values are not visible to contract code.
- File and network IO where backed by validator-local resources: removed from
  the shipped class library or trapped before any host call.

### Gas counter

A per-transaction gas counter is wired into the interpreter dispatch loop in
`interpret.cpp`. When gas is insufficient, the interpreter throws
`java.lang.OutOfGasError` deterministically without executing the next
bytecode. The workchain adapter initializes the counter by calling
`avata_begin_contract_transaction()` from `include/avata/contract.h` with the
transaction gas limit before contract bytecode starts.

The VM stores a 256-entry opcode gas table. The standalone default charges 1
for every opcode; the workchain adapter must replace that table with
`avata_set_opcode_gas_costs()` from `include/avata/contract.h` after loading the
ConfigParam 85 schedule. Changing the gas table is a consensus parameter change
and requires a governance vote.

Native contract helpers charge explicit gas through `avata_charge_contract_gas()`
or the helper-cost table. The standalone helper table currently covers:
`java.lang.Storage` load/store/clear native costs, dynamic allocation
surcharges for Java allocation bytecodes, and `System.arraycopy()`
base/per-element copy costs. Every Java native method invocation also charges
the `AVATA_CONTRACT_HELPER_NATIVE_CALL` fixed surcharge before entering native
C++ code. The fixed base cost for each bytecode remains in the opcode gas
table; helper entries are only for variable-size or native/VM work. The
workchain adapter must replace the helper table with
`avata_set_contract_helper_gas_costs()` from the same consensus gas schedule
used for opcodes. `java.lang.Storage` charges from the helper table before
touching the installed storage host or the deterministic fallback store.
`java.lang.Event` charges event base, per-topic, and per-data-byte helper gas
before forwarding to the installed event host.

### Slim build profile

The supported standalone build is the slim `make` profile:

- `process=interpret` only
- restricted Java 8 contract class library from Avata/TOS `rt/` only
- no OpenJDK runtime/classpath bridge
- no Android/libcore bridge
- no bootimage/codeimage generator
- no JIT/codegen, embed loader, or LZMA variants
- no `java.net`, `java.nio`, `java.security`, `java.text`, `java.math`,
  `java.util.concurrent`, `java.util.logging`, `java.util.regex`,
  `java.util.zip`, `java.util.jar`, process APIs, filesystem path APIs,
  object-stream serialization, or URL-handler packages in `rt.jar`
- no `java.lang.invoke`, `sun.misc.Unsafe`, `java.internal.Machine`, or
  `java.internal.Traces` shell classes in `rt.jar`
- no public class-file generation helpers or continuation/coroutine APIs in
  `rt.jar`
- no runtime string-based class loading through `Class.forName`; contract class
  resolution is controlled by the deployment/call path
- no package metadata API or Java SE `Class` reflection conveniences such as
  `getPackage`, declared/enclosing/declaring-class queries,
  `desiredAssertionStatus`, `asSubclass`, or `cast`

`make build-test` runs `rt/check-profile.sh` against the generated `rt.jar` and
`api.jar`, and fails if any forbidden package or shell class is
reintroduced. It also verifies that `tools/javac` compiles against
`api.jar`, rejects source-level imports of VM-private `java.internal.*`
classes, rejects malformed `@ContractEntry` entry methods, and that
`tools/java` can execute a compiled class with the local Avata interpreter and
`rt.jar`.

The CMake files mirror this by excluding the removed codegen targets.

## Building

Standalone verification:

```bash
# from the TOS repository root
make -C jvm/avata java-version=8 build-test
make -C jvm/avata java-version=8 input=Hello run
make -C jvm/avata java-version=8 run-test
```

The current profile builds `jvm/avata/build/<platform>-<arch>/avata`,
`libjvm.so`, `libavata.a`, `rt.jar`, `api.jar`, and `avata-unittest`.

The contract compiler wrapper prototype is:

```bash
jvm/avata/tools/javac --avata-build-dir jvm/avata/build/linux-x86_64 \
  -d out Contract.java
jvm/avata/tools/java --avata-build-dir jvm/avata/build/linux-x86_64 \
  --gas 1000000 --memory 1048576 -cp out Contract
```

The compiler wrapper forces Java 8 source/target settings, uses `api.jar` as
the boot classpath, rejects user-supplied bootclasspath/source/target
overrides, and checks generated `.class` files against the Avata contract
profile before returning success. That post-compile check catches bytecode
`javac` can emit but the contract verifier rejects, including mutable static
fields, Java 8 lambda/`invokedynamic` output, and `@ContractEntry` methods
that are not `public static void` ABI v1 entry points. The Avata class loader
independently rechecks those `@ContractEntry` rules when application class bytes
are defined, so consensus does not trust the developer wrapper. The local
runner wrapper fixes the boot classpath to Avata `rt.jar` and rejects
bootclasspath/native library path overrides. Its `--gas` and `--memory` options
start the standalone interpreter in contract-resource mode, so local runs can
reproduce deterministic `OutOfGasError`/`OutOfMemoryError` failures before
deployment.

The Avata tests cover the interpreter loop, class loading, exception handling,
and the admitted runtime API profile. TOS cell codec, gas metering, and workchain
integration are tested outside this directory.

## Source layout

```
jvm/avata/
  src/
    interpret.cpp          ← interpreter loop; gas counter wired here
    machine.cpp            ← VM state, class loading, object allocation
    heap/                  ← bounded heap manager; contract-visible memory is
                              tracked by transaction-local counters
    jnienv.cpp             ← JNI surface; restricted for TOS
    ...
  rt/                      ← Avata/TOS Java runtime sources for rt.jar
  include/                 ← Public C++ headers (avata/vm.h, jni.h)
  test/                    ← Java test classes
  unittest/                ← C++ unit tests
  makefile                 ← Supported standalone slim build
  CMakeLists.txt           ← Slim CMake entry point
  LICENSE.txt              ← Original ReadyTalk/avian license (Apache 2.0)
  PINNED_COMMIT            ← Upstream commit this fork was cut from
```

## Runtime class library

The class library bundled with Avata is the Avata/TOS `rt/` tree. It is
not built from OpenJDK sources in this profile. OpenJDK/JDK 8 sources are used
as a reference for JVMS and admitted API behavior, not as an Avata runtime build
input.

The current `rt.jar` intentionally contains only the contract profile:

- `java.lang` and annotations for deterministic language/runtime metadata.
  `Class.forName`, `java.lang.Package`, and Java SE `Class` reflection
  conveniences such as package, declared/enclosing/declaring-class, assertion,
  subclass, and cast helpers are not shipped.
- no `java.lang.invoke`, `java.lang.reflect`, `java.lang.ref`, or `sun.*`
  classes. Method handles, lambda bootstrap classes, reflection,
  weak/soft/phantom references, finalization, dynamic proxies, and cleaner
  behavior are outside the v1 contract profile. `CONSTANT_MethodHandle`,
  `CONSTANT_MethodType`, `CONSTANT_InvokeDynamic`, and `BootstrapMethods` are
  rejected by the v1 verifier until a deterministic VM-internal bootstrap
  design is admitted.
- minimal `java.io` for byte-array/string streams, readers/writers,
  `DataInput`/`DataOutput`, and VM-private stdin/stdout/stderr streams. Public
  `FileDescriptor`, `FileInputStream`, `FileOutputStream`, and
  `FileNotFoundException` are not shipped. `FilterReader`, `LineNumberReader`,
  `PushbackReader`, `FilterInputStream`, and `FilterOutputStream` are also
  outside the contract runtime. `System.in` is deterministic EOF.
- deterministic ordered/list `java.util` collections plus `java.util.function`;
  hash/identity/weak collections, `EnumSet`, `AbstractMap`,
  `AbstractSequentialList`, `NavigableMap`, `Properties`, and synchronized
  collection wrappers are not shipped
- `java.lang.Runtime` is not shipped; host runtime and process APIs are outside
  the contract profile
- `SecurityException`, `ThreadDeath`, `IllegalThreadStateException`,
  `InstantiationException`, `ReflectiveOperationException`,
  `IllegalAccessException`, `NoSuchFieldException`,
  `NoSuchMethodException`, and `TypeNotPresentException` are not shipped;
  security-manager, thread-death, thread-scheduling, reflection, and optional
  reflective-type APIs are outside the contract profile. `InterruptedException`
  is retained only as a JDK8 `javac` boot-classpath requirement; verifier
  admission rejects contract references to it.
- `Math.random` and host-native transcendental `Math` functions are not shipped;
  floating-point opcode support is handled by the VM, not by host libm calls.
  Float/double string parse/format APIs are omitted until they have a pinned
  software implementation.
- `StringBuffer` is not shipped; contract code uses `StringBuilder`.
- `Collections.shuffle` is not shipped; the profile has no implicit random API.
- VM-private `java.internal.*` support classes required by the boot runtime
  implementation, including deterministic memory accounting helpers. These are
  not contract APIs; strict contract admission rejects application class names
  and references under `java/internal/*`. The v1 profile does not ship
  `java.lang.invoke`, `sun.misc.Unsafe`, `java.internal.Machine`, or `java.internal.Traces`.

Language-level classes and Avata contract runtime helpers remain under
`java.lang` (`Object`, `String`, `Math`, `System`, errors, storage, ABI, token
interfaces):

| Package | Contents |
|---|---|
| `java.lang` | Core Java classes plus Avata contract APIs such as `Storage`, `Mapping`, `ABI`, `OutOfGasError`, and `ContractViolationError` |

Contract classes are compiled against this class library, not against a standard
OpenJDK distribution. The bootstrap classpath used by the TOS contract compiler
is the `api.jar` produced by this build. The full `rt.jar` is the VM
runtime image and may contain VM-private `java.internal.*` implementation helpers that
are intentionally absent from `api.jar`.

Contract execution starts through `avata_begin_contract_transaction_with_limits`
when both gas and memory limits are available. Movable contract allocations run
under a transaction arena checkpoint and are rolled back at transaction end.
The Java runtime exposes only transaction-local memory counters through
`java.lang.Memory`; public Java GC, finalization, weak-reference, and cleaner
semantics are not part of the TOS profile. While a contract transaction is
active, boot runtime classes may not perform reference-type `putstatic`.
Application classes are stricter: the verifier admits only `static final`
primitive/String constants with `ConstantValue` and rejects mutable static
fields. Static methods remain allowed, but Java enum classes are outside the v1
profile because javac emits mutable static state; application `ACC_ENUM`
classes are rejected directly.
Application `<clinit>` methods are also rejected, so hidden static
initialization cannot run before an explicit entry method. Application methods
may not be `synchronized` or `native`; native helpers are limited to the pinned
boot runtime. Application classes may not declare `finalize()V`; object
finalization is not a contract lifecycle hook. Persistent state must use
`Storage`, `Mapping`, and future cell-backed state types rather than ordinary
Java static fields.

## Updating the pinned commit

Pulling upstream changes into Avata is a **consensus-impacting operation**.
Before updating `PINNED_COMMIT`:

1. Read the upstream commit history between the current pin and the target
   commit. Every change to `interpret.cpp`, `machine.cpp`, `heap/`, or any
   classpath class is a potential consensus divergence.
2. Run the full Avata unit test suite and the JVM workchain integration tests
   (`jvm/test/`) before and after the update and diff the outputs.
3. Run the determinism harness: execute the same bytecode twice from identical
   inputs and assert byte-identical output. Any divergence is a blocker.
4. Update `PINNED_COMMIT` and `../../THIRD_PARTY_NOTICES.md` in the same commit.
5. The commit message must name the upstream commit range pulled in and
   explicitly list any files in the consensus path that changed.

Do not update the pin to pick up unrelated upstream fixes without going through
this process. The current policy is to maintain Avata locally rather than track
upstream Avian.

## Determinism requirements

Any change to this directory must preserve the following invariant:

> Given the same `(class_bytes, method_id, args, gas_limit, block_context)`
> tuple, Avata must produce byte-identical output on every supported validator
> platform and compiler version.

The determinism test harness in `jvm/test/determinism_test.cpp` exercises this
invariant by running a fixed set of contracts twice in the same process and
asserting identical `WorkchainComputeOutput` values. This test must pass before
any change to Avata is merged.

## License

Copyright 2010-2017 ReadyTalk. Licensed under the Apache License, Version 2.0.
See `LICENSE.txt` for the full text.

TOS modifications copyright TOS Network contributors, also licensed under the
Apache License, Version 2.0.
