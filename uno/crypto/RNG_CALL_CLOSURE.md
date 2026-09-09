# Verifier RNG call-closure review

This records the kernel-side review for design section 4.1. The measured
profile is Rust 1.97.1, release/unwind, Linux x86-64, the standard system
allocator, and the linked ABI corpus executable. The previously recorded checks
are in `doc/measurements/uno-m2-rng-controls.json`; that report remains draft.
The static review of its 1010 balance-root indirect sites is in section 3 and
`doc/measurements/uno-m2-rng-source-review.json`. The new inventory covers that
static review, not a completed native-library or whole-program closure.
Sections 1, 2, 4 and 5 retain the earlier gate design/background; this unit does
not refresh their experimental evidence. This is not a new execution permission
or a declaration of milestone acceptance.

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

## 3. Static review of the archived indirect sites

**Of the 1010 balance-root sites, this review excludes entropy access through
373 calls and leaves 637 calls unexcluded.** Identifying a target is a separate
result from excluding entropy in its transitive body. The 637 are not 637
identified entropy calls. Some have a known deterministic purpose but lack a
closed machine/source correspondence or a reviewed native implementation.

The input is the executable whose SHA256 is
`e15080cd8a5b400fdb8c3d63c5d5b69c8df79014d05e7c7d674e3fb53048944e`,
exactly matching `uno-m2-rng-controls.json` at `e8d1a47ce`. Applying the retained
old symbol reader to that image reproduces all three archived graph records,
including the complete function-name lists. The balance record contains 1010
instruction addresses in 146 functions. Its system-root records each contain
443 sites, of which 391 are shared with the balance set and 52 are outside this
review. Counts are static instruction sites, not executions or distinct target
functions; shared sites must not be summed across roots.

This replaces the earlier section's 803/399 figures. Those figures described
a later graph-reader profile, not the committed 1010/443 artifact being reviewed
here. The newer reader recognizes named dynamic relocations; the old reader
only recognized relative relocations. Removing an edge from the unresolved
counter by naming its import does not establish an entropy-free closure.

### 3.1 Why the old graph did not resolve each call

The mutually exclusive rows below account for every one of the 1010 sites.
The per-address record is [sites.json](../../doc/measurements/uno-m2-rng-source-review/sites.json);
[sites.tsv](../../doc/measurements/uno-m2-rng-source-review/sites.tsv) is its compact index.
`dyn` is a source-level explanation, not a synonym for every register call.

| Reason and reviewed target class | Sites | Entropy disposition and basis |
|---|---:|---|
| Direct GOT/PLT import slot, unsupported dynamic relocation in old reader | 207 | Not excluded. Relocation gives a symbol name, not its implementation closure. |
| Import address loaded into a register before the call | 232 | Not excluded. Fixed imported target recovered from the defining load; native body remains open. |
| Fixed local function address loaded into a register; reviewed leaf body | 371 | Excluded for this image. Eight target bodies contain only arithmetic, selection and ordinary memory operations, with no outgoing calls or entropy instructions. |
| Fixed local function address loaded into a register; nonleaf body | 80 | Not excluded transitively. Concrete arithmetic/transcript targets are identified; their downstream native, error and unresolved edges are not all closed. |
| Register copies, multiple definitions or incomplete predecessor reasoning | 99 | Not excluded. 44 stop at register-copy/multiple-definition reasoning; 55 retain predecessor or unhandled-flow uncertainty. Candidate defining instructions are retained, without promoting candidates to proved targets. |
| Vtable dispatch to `Any::type_id` | 2 | Excluded by the reviewed blanket implementation, which returns the compile-time `TypeId::of::<T>()`. |
| Other vtable dispatch, including vtable entries first loaded into registers | 16 | Not excluded. Panic payloads, hook dispatch, writers and destructors do not have a complete target inventory here. |
| Function pointer in a formatting argument | 1 | Not excluded. `fmt::rt::Argument` stores a formatter function pointer; the complete set of arguments reaching this call was not established. |
| Allocation-error hook function pointer | 1 | Not excluded. The mutable hook can select behavior beyond the default function. |
| Dynamic loader resolver slot | 1 | Not excluded. The PLT resolver target belongs to the loader, not a fixed relative relocation in this image. |
| **Total** | **1010** | **373 excluded; 637 not excluded** |

No site in this inventory needed an inline-assembly or jump-table explanation.
This does not mean that the whole executable contains no inline assembly. In
particular SIMD arithmetic and CPU detection elsewhere are a different matter.

The 99 conservative register-flow cases are not asserted to be inherently
unresolvable. Examples include register-to-register copies of a candidate
`memcpy` address in iterator materialization and a candidate deallocation
address in Vec drop glue. The worksheet deliberately stops at copies it does
not follow and at predecessor uncertainty (including unpruned padding or
landing regions). Source-level monomorphization names do not alone prove those
machine values. Closing these entries requires additional value-flow work;
this review does not disguise that remaining work as dynamic dispatch.

### 3.2 What supports the exclusions

For the 371 local-leaf calls, the worksheet records the defining instruction
and follows ordinary intrafunction predecessors to a fixed target. Caller-saved
register clobbers and unknown definitions prevent an exclusion. The review
assumes the measured ELF image and the x86-64 System V calling convention;
it does not certify code modification or corrupted control data. Full target
bodies are retained in
[leaf-bodies.json](../../doc/measurements/uno-m2-rng-source-review/leaf-bodies.json).

| Fixed target in the reviewed image | Incoming sites | Source correspondence |
|---|---:|---|
| `subtle::black_box::<u8>` at `0x714b0` | 163 | `subtle` 2.6.1 `src/lib.rs:224`: volatile read of the supplied byte; the body is a stack store, load and return. |
| `FieldElement51` reference multiplication at `0x69380` | 147 | Curve `backend/serial/u64/field.rs:115`: limb products and reduction. |
| `FieldElement51::pow2k` at `0x66510` | 20 | Same file, line 454: repeated squaring; its sole branch stays inside the body. |
| `CachedPoint::from(ExtendedPoint)` at `0x70030` | 18 | Curve `backend/vector/avx2/edwards.rs:198`: fixed lane operations and constants. |
| `ProjectiveNielsPoint::conditional_assign` at `0x77600` | 9 | Curve `backend/serial/curve_models.rs:305`: field selection. |
| `ExtendedPoint::conditional_assign` at `0x6fee0` | 9 | Curve `backend/vector/avx2/edwards.rs:92`: lane selection. |
| `FieldElement51::to_bytes` at `0x66790` | 4 | Curve `backend/serial/u64/field.rs:368`: reduction and byte packing. |
| `FieldElement2625x4::square_and_negate_D` at `0x435c0` | 1 | Curve `backend/vector/avx2/field.rs:602`: fixed vector field arithmetic. |

These bodies have no calls, indirect branches, external branch targets,
`syscall`, `sysenter`, software interrupts, `rdrand` or `rdseed`. This is a
positive body review, not an inference from an empty name blacklist. It
excludes entropy through these particular calls on ordinary defined execution;
it is not a statement that the entire caller, its other calls or process-level
fault handlers are entropy-free.

The two source-based exclusions are `0xaf799` and `0xaf7c4` in
`std::panicking::payload_as_str`. Both call the vtable slot loaded at `0xaf78e`.
Rust `std/src/panicking.rs:771` performs two `Any` downcasts. In
`core/src/any.rs:141`, the blanket `impl<T: 'static + ?Sized> Any for T` supplies
`type_id`; line 790 returns the compiler intrinsic as a constant. This does not
invoke a user formatter, destructor or RNG. These two exclusions do **not**
exclude the later destruction of the same erased payload.

### 3.3 Exact remaining set and what it means

[open-sites.tsv](../../doc/measurements/uno-m2-rng-source-review/open-sites.tsv)
lists all **637** unexcluded addresses with their function addresses and
categories. `sites.json` supplies the complete demangled function names,
instructions, known targets and candidate definitions for each address.
No omitted address is being treated as safe.

* **439 named native calls:** 403 name `memcpy`, four `memmove`, two `memset`,
  one `memcmp` and one `strlen`. The other 28 cover allocation/deallocation,
  synchronization/TLS, environment lookup, abort and unwinding. Their names
  explain normal purpose, but the actual native implementations, IFUNC/loader
  selection and downstream behavior have not been recursively reviewed here.
  This includes initialization and failure paths of allocation and unwinding.
  No entropy use is inferred merely from those names, and no absence is inferred
  either. Five calls name the generic `syscall` wrapper: four supply `0xca`
  (futex) and one supplies `0xba` (gettid), visible at the archived call sites
  `0x176d3`, `0x17aaf`, `0x17ae1`, `0x806d8`, and `0x8caf2`.
  Their arguments are not entropy syscall numbers; the wrapper/native closure
  remains outside this review's exclusions.
* **80 fixed local nonleaf calls:** concrete scalar/group operations,
  compression, SHA3 and transcript methods explain their normal mathematical
  behavior. They are not arbitrary caller-provided callbacks. They nevertheless
  contain outgoing calls, and this review has not recursively discharged all
  downstream open edges. A known deterministic operation's name is not a
  sufficient substitute. Their full target names are in the per-site record.
* **99 register-flow calls:** their candidate targets and failed resolution
  reasons are recorded individually as described above. The source generally
  exposes concrete arithmetic, iterator and allocation operations. A complete
  machine target assignment is still missing; none is excluded by that general
  source observation.
* **16 open vtable calls:** `0x206d8`, `0x80e51`, `0xcf97b` drop erased panic or
  I/O error payloads; `0x8cc1d`, `0x8cc76`, `0x8dccd`, `0x8dd08`, `0x8dd40`
  dispatch panic-output writer operations; `0xaf876`, `0xaf8a8`, `0xaf8cf`,
  `0xaf960` dispatch panic payload/hook operations; `0xcf9da` extracts the
  panic payload; `0xfdd85`, `0xfddd4`, `0xfdeb9` dispatch `fmt::Write`.
  `std/src/panicking.rs` declares `Hook::Custom(Box<dyn Fn(...)>)`, and
  `panic_unwind/src/gcc.rs` owns a `Box<dyn Any + Send>`. The FFI's
  `contain_unwind` drops its caught payload in the `Err(_)` arm. Having no
  callback argument in the ABI therefore does not eliminate these edges.
  Arbitrary hooks, writer implementations or destructors can contain entropy
  calls; this review has not established the complete subset reachable under
  every failure path of the measured executable. It also does not claim that
  arbitrary user implementations are actually present on its successful path.
* **Three other calls:** `0xfde76` invokes the formatting argument's function
  pointer (`core/src/fmt/rt.rs:19`); `0x17314` invokes the allocation-error hook
  loaded from `std::alloc::HOOK`, falling back to the default hook;
  `0x11026` is the loader resolver slot. The latter is labeled
  `std::ostream::put(char)@plt-0x10` by objdump because it precedes the first
  named PLT entry; it is **not** evidence that verification writes a character
  through that C++ method. None of these three target closures is excluded.

The 1010-set itself is the old graph's reachable-node approximation. It is
not a proved complete set of all calls reachable through unresolved edges.
Resolving an address can expose further nodes not traversed by that old graph;
this review does not silently fold those into the historical denominator.
The other roots' 52 nonshared sites each also remain outside this unit.

### 3.4 Reproduction and limits

The new static inventory is
[uno-m2-rng-source-review.json](../../doc/measurements/uno-m2-rng-source-review.json).
It binds the old report, the exact compressed ELF image, full objdump output,
relocations, old reader, worksheets, per-site decisions and the source files
read for the exclusions. It does **not** provide a completed native-library
source inventory or certify all five RNG gates. The old control report is
unchanged, including its draft review status.

To inspect the retained image without executing it, decompress
`reviewed-image.elf.gz` into a scratch directory and run the retained
`archived-symbol-reader.py` on that path. For the worksheets, copy `extract.py`
and `resolve.py` into a scratch directory with `relocations.txt` and decompressed
`disassembly.txt`, then run `resolve.py`, redirecting its long name summary to a
file. Its four mechanical kinds (207 direct imports, 683 constant-register
calls, 109 unresolved-register calls, 11 memory-dispatch calls) are refined by
the source/address decisions above; `sites.json` retains both levels. These
worksheets are static review aids, not new acceptance gates. Register copies,
landing paths, vtable target enumeration and transitive native analysis are
explicit limits, not passing results of a new test.

No source mutation, build, verifier execution or RNG control rerun was performed
for this unit. Static reconciliation checked the image hash, exact old graph,
unique address coverage, category totals and retained artifact hashes. This
review closes the request to classify the historical set; it leaves a
substantial unresolved entropy closure and makes no milestone-acceptance claim.

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
