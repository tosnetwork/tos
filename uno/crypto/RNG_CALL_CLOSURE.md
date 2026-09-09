# Verifier RNG call-closure review

This records the kernel-side review for design section 4.1. The measured
profile is Rust 1.97.1, release/unwind, Linux x86-64, the standard system
allocator, and the linked ABI corpus executable. The source inventory,
toolchain identity, build-script outputs, native library hashes, feature graph,
symbol observations and compiled controls accompany this review in
`doc/measurements/uno-m2-rng-controls.json` and
`doc/measurements/uno-m2-rng-source-review.json`. This is not a new execution
permission or a declaration of milestone acceptance.

## 1. Minimum verifier dependency/features graph

`fixtures/verifier-feature-graph.json` freezes 32 distinct normal
package/feature rows. `kernel-gates.py` compares the resolved graph against it,
in addition to the existing revision, source, archive and provider checks.
The graph is obtained with normal edges only, without enabling test features.

* Bulletproofs has no default features: no `std`, `kernel-test`, `yoloproofs`,
  randomized convenience entry points or R1CS verifier are admitted through
  feature selection. Its generic proving and explicit-RNG APIs still exist
  in source. Reachability, not their existence, determines the verifier path.
* Merlin has no features. In particular `std` and `debug-transcript` are off.
  The reviewed path uses `new`, `append_message`, `append_u64`, cloning and
  `challenge_bytes`; it does not use `build_rng` or `TranscriptRngBuilder::finalize`.
* The curve crate enables `alloc,digest,group,precomputed-tables,rand_core,serde,
  std,zeroize`. ECDLP and legacy compatibility are not enabled. `rand_core`
  supplies interfaces; it does not itself obtain entropy. The same is true
  of the enabled random-related trait support in digest/crypto-common.
* Hash/encoding support consists of SHA3/SHAKE, Keccak, STROBE, byteorder,
  subtle, zeroize and their typed buffer/array support. Their reviewed calls
  process supplied state and bytes; key generation and random sampling
  interfaces are not called.
* Derive macros occur in Cargo's normal graph as compile-time dependencies.
  The separately reviewed build graph includes cbindgen and its dependencies,
  some of which use randomness during compilation. The kernel build script
  generates and compares the C header; it does not emit runtime RNG calls.
  Macro/build source authenticity remains covered by locked archive/source
  checks. Build-time randomness is not classified as verifier runtime use.

`Cargo.lock` contains `rand` and `getrandom` for other dependency classes. This
is not a failure by itself. Conversely, a provider-name blacklist cannot freeze
features: enabling only Merlin `std` compiles and passes the source, symbol and
runtime entropy checks but fails the exact feature snapshot. The control
records the changed rows without inspecting error strings.

## 2. Source call graph

The reviewed roots are `uno_crypto_verify_v2`,
`uno_crypto_system_encrypt_v1`, and `uno_crypto_system_verify_v1`. The encryption
root here constructs public system ciphertexts; it is not the separate wallet
prover. The Rust `verify_relation` API reaches the same cryptographic body as
the balance ABI root. No ABI argument is a callback or a function pointer.

| Source layer | Calls followed | RNG disposition |
|---|---|---|
| `src/ffi.rs` | `contain_unwind`, request/span checks, borrowed slices, `verify_relation`, `system_ciphertext` | Local closures and checked spans; no sampling or randomized container |
| `src/relation.rs` | limits/shapes, point/scalar decoding, `prepare`, transcript constructors, `check_sigma`, `RangeProof::from_bytes`, `verify_independent` | Each Sigma row checked directly; no collector or random weight |
| `src/statement.rs` | `PreparedStatement` accessors and wrappers around preparation/transcript functions | Read-only reuse of the same path; no added RNG edge |
| `src/system_encryption.rs` | transcript binding, challenge extraction, wide scalar reduction, group operations | Scalar derived from public transcript bytes; no RNG builder or sampler |
| vendored range decoder | canonical scalar conversion and inner-product decoding | Input decoding only |
| `range_proof/deterministic.rs` | transcript replay, verification scalars, generator iterators, two optional MSMs, independent identity tests | c is replayed and discarded; no outer factor and no random collector |
| `inner_product_proof.rs::verification_scalars` | point validation, transcript challenges, scalar batch inversion and products | Deterministic inversion/product algorithm; `batch` here does not mean randomized checking |
| `generators.rs` | Pedersen defaults, `BulletproofGens::new/increase_capacity`, `GeneratorsChain` | SHA3 hash-to-group and domain-separated SHAKE stream, not an RNG stream |
| curve field/group layer | canonical decode, decompression/compression, identity/equality, scalar arithmetic/inversion, exact MSM | These arithmetic operations do not invoke the crate's random constructors or `Field::try_random` |
| curve backend selection | fixed serial/SIMD implementations selected by CPU capability | x86 CPUID/XGETBV feature detection, not RDRAND/RDSEED; backend code is included in the source inventory |
| transcript/hash layer | STROBE AD/PRF and Keccak permutations, SHA3/SHAKE updates/finalization | Internal deterministic state transitions; `challenge_bytes` is not `TranscriptRng::finalize` |

The shared source also contains random point/scalar constructors, prover
masking, randomized range collectors, transcript-RNG finalization and RNG
tests. Their source presence is explicitly distinguished from the calls above.
`Scalar::invert_batch_alloc` uses prefix products, a field inverse and a reverse
pass; it does not sample batch factors. Generator construction consumes SHAKE
bytes with fixed domains. The CPU capability table's `rdrand` feature name is
not execution of an entropy instruction; the linked image is separately scanned
for the instructions themselves.

First-party source scanning includes every Rust module under `src/` except
the exact fixture/prover test module `src/tests.rs`, plus the independent range
source. New first-party modules therefore cannot evade scanning merely by
having an unlisted filename. Dependency source changes must pass the existing
provenance checks and undergo this call-closure review again.

## 3. Indirect calls and platform runtime

The symbol tool follows named direct branches, relative GOT entries, and named
dynamic imports (`GLOB_DAT`/`JUMP_SLOT`). Imported entropy functions are terminal
graph nodes, rather than dropped edges. Full unresolved function names are
retained in the measurement artifact; they are not discarded to make the
report appear closed.

For the measured normal executable, the balance root has 803 unresolved
instruction sites in 113 named functions after named dynamic imports are
resolved. The two system roots each have 399 sites. These are **not 803
independently identified RNG calls**, nor are they a machine-proved empty
indirect closure. The source review groups them as follows:

* Curve/proof iterator and arithmetic monomorphizations: their callable values
  come from the concrete local iterator closures, arithmetic implementations,
  table operations and backend selection described above. None takes a caller-
  supplied callable from an authoritative request. Long demangled iterator
  types are preserved in full for checking this correspondence.
* Transcript/hash functions: calls are to the fixed STROBE/Keccak and buffer
  implementations. The entropy-finalization method is a separate API, and the
  compiled reconnection control distinguishes it from normal transcript use.
* Allocation, drop glue and formatting: reviewed source calls are Vec/buffer
  allocation, their fixed element destructors, and error/panic formatting.
  Native imports are memory allocation/copy, thread-local cleanup, unwind,
  synchronization, environment/error reporting and process termination. The
  generic `syscall` import is not automatically assumed entropy-free; the Rust
  runtime source paths involved are thread IDs and futex synchronization, and
  runtime entropy/device traps provide separate execution evidence.
* Panic machinery: `catch_unwind` receives the local FFI closure. The standard
  default hook can format errors and symbolize backtraces; it does not call
  the random constructors reviewed above. The source inventory includes the
  standard panic, backtrace, allocation and synchronization implementations.
  There is no hook registration or allocator replacement in the measured
  kernel/test executable. A different embedding that installs arbitrary panic
  hooks, allocators, symbol interposers or callbacks is not certified by this
  kernel-only executable and must have its composed call graph reviewed.

Native libraries are bound by hashes in the profile inventory. Their imported
entry points are not recursively analyzed as if the executable contained their
implementations. Source review plus the recorded native runtime profile and
execution controls is the evidence here; the disassembler alone is not a
whole-program proof. The results do not certify other architectures, compiler
versions, native libraries or runtime overrides.

## 4. Runtime trap

`balance-abi.cpp` loads the fixed corpus before installing the Linux seccomp
filter, then executes verification without first warming verifier RNG state.
The filter traps OS entropy and entropy-device access (`getrandom`, open/openat/
openat2, read), rejects the wrong syscall architecture and the x32 range, and
retains a direct `getrandom` canary. The normal corpus covers all nine full
SEND/COLLECT fixtures, system ciphertext operations, and ABI/encoding/binding
rejections. Four ordinary worker threads also run the complete corpus outside
the trap. No equality-of-two-accept-results claim substitutes for the trap.

Direct subprocess modes expose the actual signal status to the runner. A
successful baseline exits 0; an entropy reconnection terminates with SIGSYS
(subprocess status -31 on this profile). Exceptions or failed ABI assertions
exit 2 and do not count as the expected entropy signal. The canary itself is
tested by removing only the getrandom filter rule: it then exits 0, failing the
canary's required SIGSYS criterion. This does not rely on an error message or
on another file-read rule catching the same direct syscall.

## 5. Compiled controls and attribution

`tests/rng-acceptance.py` creates an isolated copy and builds with `-j32`.
Every source change is restored byte-for-byte with exact from/to records,
hashes and a replay audit. The temporary expanded dependency graph is an
explicit test fixture: it admits `rand` so real calls can compile. That graph
is rejected separately by the normal graph gate. Its unchanged verifier still
passes source, reachability and runtime checks, demonstrating why dormant RNG
code is not equivalent to verifier RNG use. Each source reconnection then
changes one source location relative to that stated fixture.

| Control | Separately observed result |
|---|---|
| Random scalar sampling | Source rejects the changed relation file; balance-root symbols identify RNG; runtime SIGSYS |
| Transcript RNG finalization | Same three independently recorded failures |
| Default HashMap construction | Same three independently recorded failures |
| Random range collector | Same three independently recorded failures |
| Direct libc `getentropy` import | Source lexer remains clear and no Rust RNG dependency is added; dynamic-import reachability and runtime trap fail |
| Merlin `std` feature | Other entropy checks pass; exact feature-snapshot check fails |
| Remove getrandom filter rule | Canary no longer produces SIGSYS, so the canary criterion fails |
| Admit runtime `rand` dependency | Normal graph admission fails; dormant uncalled code passes reachability/runtime |
| Remove disassembler from PATH | Symbol test fails; it does not skip or return a clean report |

No control uses build/link failure as behavioral evidence. The unsuccessful
attempt to use an unavailable libc symbol was not retained as a passing
control; the available `getentropy` interface was subsequently compiled and
executed successfully. Full stdout/stderr files, including captured empty
files, are retained. The final normal source and feature graph are restored
and rebuilt before the measurement finishes.

The controls establish that each of the four required RNG reconnections is
detected by at least one gate (in this profile, all three applicable source,
symbol and runtime checks detect each). They do not remove the need for source
review on refresh, and they do not close the separate relation-level D34 gap.
