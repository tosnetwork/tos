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
- Not built with `make`. The upstream `makefile` remains in the tree for
  historical reference but the TOS build uses CMake exclusively (see below).
- Not intended for iOS, Android, Windows/Cygwin, or ProGuard embedding. Those
  paths in the upstream source are dead code for our purposes.

## Relationship to the upstream source

The fork was taken at commit `0871979b` and renamed from `avian` to `avata`.
All subsequent changes are made in this repository. The `PINNED_COMMIT` file
records the upstream commit the fork was cut from; it is updated only when an
explicit decision is made to pull in upstream changes (see "Updating the pinned
commit" below).

The original upstream `README.md` is replaced by this file. The upstream
`LICENSE.txt` is preserved unchanged; see `LICENSE.txt` for terms. Third-party
notices for vendored components under `lzma/` and `openjdk-patches/` are
covered by `../../THIRD_PARTY_NOTICES.md`.

## TOS-specific modifications

The following changes have been made to the upstream source since the fork:

### Interpreter-only execution

The JIT compiler (`compile.cpp`, `compile-x86_64.S`, and related files) is
retained in the tree but **not linked** by the TOS CMake target. All contract
execution runs through `interpret.cpp`. JIT compilation introduces
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
  `tos.contract.Context.blockTimestamp()` instead.
- Entropy (`/dev/urandom`, `SecureRandom`): removed; contracts use
  `tos.contract.Context.randSeed()`.
- Process and environment APIs (`getenv`, `System.getenv`,
  `System.getProperties`, `Runtime.exec`): throw `ContractViolationError`.
- File and network IO where backed by validator-local resources: throw
  `ContractViolationError`. Class-library shapes may remain for source
  compatibility, but execution must not reach the host.

### Gas counter

A per-transaction gas counter is wired into the interpreter dispatch loop in
`interpret.cpp`. When the counter reaches zero, the interpreter throws
`tos.lang.OutOfGasError` deterministically without executing any further
bytecode. The counter is initialized by `jvm/core/compute-phase.cpp` from the
`gas_limit` field of `WorkchainComputeInput` before each transaction.

Gas costs per opcode are loaded from the gas table in `jvm/core/gas-table.cpp`,
which reads ConfigParam 85 at startup. Changing the gas table is a consensus
parameter change and requires a governance vote.

### CMake build

The upstream `makefile` is not used by TOS. The CMake target is defined in
`CMakeLists.txt` and exports a single static library target `avata_interpreter`.
The TOS top-level CMake includes this as a subdirectory dependency of
`jvm/core/`.

## Building

Avata is built as part of the normal TOS build. There is no standalone build
step.

```bash
# from the TOS repository root
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target avata_interpreter -j 64
```

To run Avata's own unit tests in isolation:

```bash
cmake --build build --target avata-unittest -j 64
./build/jvm/avata/avata-unittest
```

The unit tests cover the interpreter loop, class verifier, exception handling,
and floating-point determinism. They do not cover TOS cell codec or gas metering
(those are tested in `jvm/test/`).

## Source layout

```
jvm/avata/
  src/
    interpret.cpp          ← interpreter loop; gas counter wired here
    machine.cpp            ← VM state, class loading, object allocation
    heap/                  ← garbage collector
    compile.cpp            ← JIT (not linked by TOS target)
    jnienv.cpp             ← JNI surface; restricted for TOS
    classpath-openjdk.cpp  ← OpenJDK classpath bridge
    ...
  classpath/               ← Java class library sources (TOS-pinned rt.jar)
  include/                 ← Public C++ headers (avata/vm.h, jni.h)
  openjdk-patches/         ← Patches applied to OpenJDK classes at fork time
  test/                    ← Java test classes
  unittest/                ← C++ unit tests
  CMakeLists.txt           ← TOS build entry point
  LICENSE.txt              ← Original ReadyTalk/avian license (Apache 2.0)
  PINNED_COMMIT            ← Upstream commit this fork was cut from
```

## Runtime class library

The class library bundled with Avata is a TOS-pinned subset of OpenJDK, patched
at fork time and extended with TOS domain APIs. Language-level classes remain
under `java.lang` (`Object`, `String`, `Math`, `System`, errors). TOS domain
APIs live under `tos.*`:

| Package | Contents |
|---|---|
| `tos.contract` | `ContractEntry` annotation, `Context` (block metadata) |
| `tos.storage` | `PersistentMap`, `PersistentList` (cell-tree backed) |
| `tos.emit` | `EventLog` (side-effect log entries) |
| `tos.lang` | `OutOfGasError`, `ContractViolationError` |

Contract classes are compiled against this class library, not against a standard
OpenJDK distribution. The bootstrap classpath used by the TOS contract compiler
is the `classpath.jar` produced by this build.

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
this process. The maintenance burden of staying current with an unmaintained
upstream is lower than the risk of an unreviewed consensus change.

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
