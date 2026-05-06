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
yield. `java.lang.Thread` construction, `Thread.start()`, `Object.wait()`,
`Object.notify()`, and related APIs throw `ContractViolationError`
deterministically before any OS call is made.

### Non-deterministic syscall removal

The following paths are removed or replaced with deterministic stubs:

- Wall-clock time (`gettimeofday`, `clock_gettime`, `System.currentTimeMillis`,
  `System.nanoTime`): return zero; contracts must use
  `Context.blockTimestamp()` instead.
- Entropy (`/dev/urandom`, `SecureRandom`): removed; contracts use
  `Context.randSeed()`.
- Process and environment APIs (`getenv`, `System.getenv`,
  `System.getProperties`, `Runtime.exec`): throw `ContractViolationError`.
- File and network IO where backed by validator-local resources: removed from
  the shipped class library or trapped before any host call.

### Gas counter

A per-transaction gas counter is wired into the interpreter dispatch loop in
`interpret.cpp`. When the counter reaches zero, the interpreter throws
`java.lang.OutOfGasError` deterministically without executing any further
bytecode. The workchain adapter initializes the counter by calling
`avata_begin_contract_transaction()` from `include/avata/contract.h` with the
transaction gas limit before contract bytecode starts.

Gas costs per opcode are loaded from the gas table in `jvm/core/gas-table.cpp`,
which reads ConfigParam 85 at startup. Changing the gas table is a consensus
parameter change and requires a governance vote.

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
- no `sun.misc.Unsafe`, `avata.Machine`, `avata.Traces`,
  `MutableCallSite`, `VolatileCallSite`, `SerializedLambda`, or
  `MethodHandleInfo` shell classes in `rt.jar`

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
`libjvm.so`, `libavata.a`, `rt.jar`, and `avata-unittest`.

The Avata tests cover the interpreter loop, class loading, exception handling,
and the admitted runtime API profile. TOS cell codec, gas metering, and workchain
integration are tested outside this directory.

## Source layout

```
jvm/avata/
  src/
    interpret.cpp          ← interpreter loop; gas counter wired here
    machine.cpp            ← VM state, class loading, object allocation
    heap/                  ← garbage collector
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

- `java.lang`, annotations, `java.lang.invoke`, `java.lang.ref`, and the
  admitted reflection subset needed by Java 8 source and lambda output
- minimal `java.io` for byte-array/string streams, readers/writers,
  `DataInput`/`DataOutput`, and VM stdin/stdout/stderr through
  `FileDescriptor` only
- deterministic `java.util` collections plus `java.util.function`
- Avata VM support classes and the small `sun.misc` / `sun.reflect` internal
  remnants still required by VM internals. The v1 profile does not ship
  `sun.misc.Unsafe`, `avata.Machine`, `avata.Traces`, `MutableCallSite`,
  `VolatileCallSite`, `SerializedLambda`, or `MethodHandleInfo`.

Language-level classes and Avata contract runtime helpers remain under
`java.lang` (`Object`, `String`, `Math`, `System`, errors, storage, ABI, token
interfaces):

| Package | Contents |
|---|---|
| `java.lang` | Core Java classes plus Avata contract APIs such as `Storage`, `Mapping`, `ABI`, `OutOfGasError`, and `ContractViolationError` |

Contract classes are compiled against this class library, not against a standard
OpenJDK distribution. The bootstrap classpath used by the TOS contract compiler
is the `rt.jar` produced by this build.

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
