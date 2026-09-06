# Prototype verification ABI v0

`include/uno_crypto.h` declares `uno_crypto_verify_v0`; `cargo build --locked
--offline --release -j48` produces the matching static library. This is a native
process interface, not a Cell codec, chain wire assignment or activation profile.
ABI version 0 and ABI profile 1 select only the pinned fixed bundle/circuit pair.
Unknown values fail; context tags are generated from Rust constants and must
not be obtained by casting another language's internal context enumeration.

The caller owns the request, Action array and proof bytes. All fields must be
initialized and all pointed-to allocations must remain readable, aligned and
immutable for the entire call. Null, alignment, multiplication, address-overflow
and slice-length checks do **not** prove that an arbitrary address is valid.
Never pass untrusted RPC pointer values. No pointers are retained, no secret
witness is accepted, and no allocation/free ownership crosses the boundary.
Amounts are high/low u64 words of u128 nanotomi, not host-endian byte strings.

All settlement contexts require a positive public principal in nanotomi,
including Unshield with a nonzero fee. Transfer may have a zero fee and must
have zero public principal. These public-context rules do not prohibit
zero-valued protocol dummy notes.

The entry point checks ABI/profile and representable context, checks lengths
before constructing slices, decodes canonical primitive fields, and calls the
combined context/proof/spend/binding verifier. Its process-local key cache is an
immutable successful verifier, with serialized initialization; callers cannot
replace the key. A construction error returns status 4 for that call without
caching the error, so later calls retry. Unwinding panics are contained
at the exported function and return status 5; OOM, process abort and invalid
caller memory cannot be recovered by this mechanism. It must not be advertised
as recovery from `panic=abort`. Development and release profiles explicitly
require unwind, and compiling this crate with `panic=abort` is rejected.

ABI v0 does not carry a KEM ciphertext or implement the required hybrid
encryption profile. Its raw encryption fields and integration fixtures are
prototype inputs, not durable UNO transactions or activation vectors. When
the hybrid profile changes the request contract, increment the ABI version
and regenerate profile-dependent integration fixtures; do not reinterpret v0
bytes as the new profile. Independently pinned primitive/VK reference vectors
remain useful for their original scope and are not automatically invalidated
by a change to the surrounding ABI.

Status 0 means these checks passed, **not** that a transaction may be committed.
The host must derive context/limits from authenticated state, derive the digest
from the full committed TOS core, authenticate output-only settlement authority,
and check expiry, anchor/nullifier state, resource accounting and finality.
Statuses 1–5 distinguish arguments, decoding, verification, key construction and
unwind failures. No ABI status is a consensus receipt or monetary delta.

Tests send generated valid output-only and real-spend bundles through the exported
function from Rust, plus bad digest/proof, flags, ABI/profile and context cases.
Test-only thread-local fault injection verifies the actual exported panic boundary;
bypassing containment aborts the test process. Bypassing version/profile checks or
the cryptographic call makes invalid fixtures return success and fails assertions.
All mutations were restored.

A separate C++ smoke caller checks 64-bit layouts, links the real static library,
and reaches both argument rejection and primitive decoding:

```sh
c++ -std=c++17 -O2 -Iinclude tests/abi-smoke.cpp target/release/libtos_uno_crypto_prototype.a -ldl -lpthread -lm -o target/abi-smoke
target/abi-smoke
```

## Real C++ verification fixtures

The real-proof Rust test can export two fresh public-only fixtures after they
pass ABI verification. The files contain flags, valueBalance, anchor, proof,
commitments, ciphertext and signatures; no spending key or witness is exported.
They use a test-only fixed-size record marked `UNOABIT0`, not native struct memory
or the TOS Cell encoding. The digest is the fixture's arbitrary `[42; 32]`, not
the full TOS authorization digest. These randomized temporary fixtures are not
frozen production golden vectors. Existing files are never overwritten.

From `uno/crypto`, reproduce the actual C++ positive/negative path with:

```sh
uno_fixture_dir=$(mktemp -d /tmp/uno-abi-real.XXXXXX)
UNO_ABI_FIXTURE_DIR="$uno_fixture_dir" cargo test --locked --offline --release -j48 real_bundle_requires_proof_and_signatures
cargo build --locked --offline --release -j48
c++ -std=c++17 -O2 -Iinclude tests/abi-real.cpp target/release/libtos_uno_crypto_prototype.a -ldl -lpthread -lm -o target/abi-real
target/abi-real "$uno_fixture_dir/output-only.bin" "$uno_fixture_dir/spend.bin"
```

The C++ program independently constructs borrowed ABI requests, accepts both
output-only and real-spend bundles, rejects an altered digest, proof, each Action
signature, binding signature, action limit and high-word public amount, then
accepts each original bundle again after restoring fields. It requires both
files, complete records and EOF. Removing proof, spend or binding verification
independently, rebuilding the static library and relinking the C++ program makes
the matching corrupted input return success and the test fail. All three mutations
were restored; these tests therefore exercise the linked implementation rather
than a stale binary or rejection-only stub.

## Opt-in CMake/CTest integration

From the repository root, on a native Linux build:

```sh
cmake -S . -B build -DTOS_UNO_CRYPTO_PROTOTYPE_TESTS=ON
cmake --build build --target test-uno-crypto-abi-smoke test-uno-crypto-abi-real -j48
ctest --test-dir build -R '^test-uno-crypto-' --output-on-failure
```

The option defaults to OFF. Enabling it adds three tests: the Rust unit suite,
the C++ smoke caller, and the C++ real-fixture caller. The C++ targets depend on
the locked/offline Cargo static-library build and join `all-tests`; no node or
engine target links this library. `UNO_CRYPTO_BUILD_JOBS` defaults to 48 and may
be configured separately. Preinstall the pinned toolchain and cache dependencies
before enabling these targets; Cargo dependency resolution uses `--locked --offline`.
Cargo artifacts live
inside the CMake build directory, separate from the manual Cargo target directory.

The real-fixture CTest generates fresh files in a unique build-directory path,
requires both files even if the generator exits successfully, and propagates
the C++ program's failure. Public fixtures are retained for inspection. Tests
that invoke Cargo share a CTest resource lock. Two repeat runs of all three tests
passed; a no-op generator and a failing C++ caller each caused the wrapper to fail.

ABI layout validation on other platforms, sanitizer/fuzz coverage and
actual node/UNO engine integration remain acceptance requirements before
production use. The CMake option does not activate a workchain or install config.

## C++ host adapter

`uno/core/crypto-verifier.h` provides an owning `CryptoBundle` container and
`verify_crypto_bundle`. The call borrows its vectors only for the duration of
verification; callers must not mutate them concurrently. It reuses the C++ public
amount/context checks, validates proof shape without allocating, explicitly maps
logical contexts to ABI tags, and constructs the raw request internally.

The result is `td::Result<bool>`: true means cryptography/context passed, false
means invalid bundle data. Unconfigured limits, unknown context, unexpected ABI
argument rejection, key construction failure, panic and unknown status are
**local errors**, not ordinary transaction-invalid results. Callers must preserve
this distinction when deciding whether local validation can proceed. Success
still does not authorize issuance, settlement, or a host state transition.

`test-uno-crypto-adapter` uses a separate stub backend to test all context/status
mappings and require zero backend calls on invalid public inputs or proof shape.
Removing either precheck still gives the same rejection result from the stub,
but fails the zero-call assertion. Other mutations detect an enum-order cast,
key failure incorrectly downgraded to invalid input, and size arithmetic wrap.
All were restored. The CMake real-fixture test additionally compiles with the
adapter and validates real positive, corrupted-proof and wrong-digest bundles
against the actual Rust library. The stub is never linked into that real test
or node binaries. No node/engine call site uses the adapter yet.

## Generated header and build-time drift gate

The header is generated from the Rust declarations by cbindgen **0.29.0**, pinned
as a build dependency with its transitive dependencies in Cargo.lock. Normal
Cargo builds generate into OUT_DIR and compare every byte with the committed
header. Generation errors, a missing header, or a mismatch fail the build;
there is no warning-only fallback. CMake's existing always-invoked Rust target
runs this check before linking either real ABI caller. Source-tree header edits
and changes anywhere under `src/` invalidate the Cargo build-script cache.
Default-OFF C++-only builds still use the committed header without requiring Rust;
they do not claim to check it against a Rust library they do not build or link.

To deliberately regenerate after reviewing an ABI change, from `uno/crypto`:

```sh
unset UNO_CRYPTO_HEADER_OUT
cargo build --locked --offline --release -j48
```

On drift, this command intentionally fails and prints the generated header's
exact OUT_DIR path. Review that file, explicitly update `include/uno_crypto.h`,
inspect its diff, then rerun the build. Do not set the export variable to the
committed header: it is no longer a regeneration switch.

`UNO_CRYPTO_HEADER_OUT` exports only after the committed-header comparison
succeeds, and creates a new file exclusively. Existing files, symlinks and
hardlinks are never overwritten. A stale variable therefore cannot repair a
drifted header or silently rewrite an existing source file. The opt-in CTest
`test-uno-crypto-header-guard` exercises the real build in a temporary source
copy, retains failed fixtures, and removes successful fixtures.
Review and commit the declarations, generated header and any ABI contract changes
together. First-time dependency provisioning may require `cargo fetch --locked`;
ordinary builds remain locked/offline after provisioning.

The request and Action layouts and exported function signature are generated
directly. Context/version/profile constants are also the constants used by the
Rust checks; status discriminants come from the actual Rust status enum. Context
macros replace the former unused C-only enum; the ABI continues accepting raw
u32 tags so unknown values can be rejected safely. Existing symbol, field and
constant names and their numeric values remain unchanged. Header generation
cannot prove pointer validity, length semantics, ownership or panic behavior;
the runtime guards and linked positive/negative tests remain necessary.

Five independent drift mutations (function pointer constness, ciphertext array
length, status discriminant, context constant, and only the C header's count
type) each failed specifically at the generated-header comparison, before Rust
library compilation. All were restored.

Historical build-pattern reference: `cd8e170a0^:uno/plonky3-ffi/build.rs` and
`cbindgen.toml`. We reuse generation plus a committed consumer header, but not
the historical warning-and-continue behavior. The historical
`third-party/corrosion/README.uno.md` records v0.5.2 and a whole-release refresh
policy keeping its CMake and generator components together. That policy was read;
Corrosion restoration and cross-platform native-library discovery remain deferred.
The present opt-in native-Linux Cargo integration and per-build target directory
are unchanged. Historical build/test target names are not current acceptance gates.

## Optional ABI timing experiment

Build `test-uno-crypto-abi-real` and run its ordinary CTest with `-V` to generate
fresh public fixtures and obtain their retained directory. Pass the same two
fixture paths and a third argument of 100 through 10000 to the executable:

```sh
build/uno/crypto/test-uno-crypto-abi-real PATH/output-only.bin PATH/spend.bin 1000
```

Without that third argument the ordinary correctness test is unchanged. Timing
mode still runs all its negative controls. For each fixture it separately reports
the first ABI call, then 10 warmups and the requested number of serial samples
for both a valid bundle and a wrong-digest rejection. Every sample must return
the expected status. The result uses steady-clock milliseconds and nearest-rank
p50/p95/p99/max. The first output-only call includes initial key construction;
the first spend call does not, because this process has already used the key.
Neither is a cold-OS-cache measurement or an initialization percentile.
Only accept a report when the process exits zero and prints the final fixture
success message; partial timing lines from a failed run are not valid evidence.

The timed boundary includes ABI decoding and cryptographic verification, but
excludes fixture reading, client proving, C++ owning-adapter construction, engine
state lookup/update, tree append, serialization, network and consensus. The two
fixtures each have two Actions and a 7264-byte proof; repeated verification of
these same fixtures gives warm-cache observations, not workload diversity or
maximum-block costs. Wrong digest is one rejection path, not a worst-case bound.
Record the source revision, locked dependencies, hardware, concurrency/load and
sample count with any results. Do not infer an achievable slot from this output.

## Tree transition ABI prototype

`uno_crypto_tree_append_v0` restores a `UnoTreeFrontier`, appends an ordered array
of 32-byte commitments, and writes one `UnoTreeResult` into caller-owned storage.
It uses the current prototype ABI version 0 and fixed profile 1; these are not
StateV2 wire tags. All declarations are generated with the existing drift check.

The frontier is fixed-size (1072 bytes): next position, a 32-byte last leaf,
64-bit prior-subtree count and 32 slots of 32 bytes each. Unused slots must be
zero; the empty frontier requires zero position/count/leaf. The result adds a
32-byte root (1104 bytes total). This native-layout ABI is not portable serialized
storage: Cell/endian encoding and authenticated snapshot binding remain separate.

Inputs are borrowed for the call; output storage remains owned by the caller.
No allocation is returned and no free function is needed. Output must not overlap
the request, input frontier or nonempty commitments array; numeric overlap is
rejected. Null commitments are allowed only for an empty batch. Pointer alignment,
span overflow and configured count bounds are checked before slice construction,
but allocation validity and exclusive access remain caller obligations.

Successful return publishes the new frontier/root only after all parsing,
appending and root hashing finish. Every nonzero status preserves output.
ARGUMENTS means ABI/profile/count/pointer/range/overlap failure; DECODE means
noncanonical frontier/leaf or unavailable tree capacity (including reservations);
PANIC means a caught unwind. OOM, process abort and invalid caller memory are not
recoverable. These prototype statuses do not classify local resource failure as
consensus-invalid input. The caller authenticates limits and reservations and
commits the output together with the rest of engine state.

The linked C++ tree test checks batch versus incremental results, no-op restore,
late-invalid-leaf rollback, reserved capacity, count/profile rejection, canonical
padding, null input, overlap and subsequent recovery. The real-ABI test computes
the output tree in C++ through this export and requires its root to match the
generated spend fixture's anchor before verifying that spend. Older single-leaf
spend fixtures are not valid for this paired test; regenerate both fixtures
together. Rust tests inject a panic immediately before publication and numeric
span overflow, requiring unchanged output in both cases. No production host
or Cell codec is enabled by these tests.

## C++ frontier Cell prototype

`uno/core/note-tree-state.h` wraps the tree ABI with immutable C++ state and a
strict Cell codec. This unactivated prototype has a 358-bit header:
`tag:32 = 0x554e4630`, `next_position:64`, `leaf:256`, `ommer_count:6`.
The header has exactly one reference when count is nonzero, otherwise none.
Its referenced list stores prior subtree nodes in ABI order, 256 bits per Cell,
with exactly one reference except at the last node. At most 32 nodes are accepted.
Integers use Cell bit encoding; node bytes retain their canonical crypto encoding.
No native C struct bytes or cached root are serialized. Restore recomputes the
root through the Rust ABI before publishing the object.

Special Cells, extra bits/references, invalid counts and malformed frontier shapes
are rejected. Library references are never implicitly resolved. The complete
load is at most 33 Cell reads; VM failures become Result errors. The root tag and
layout are prototype-local, not frozen StateV2 or an activated TL-B constructor.
There is no claim that a bounded frontier replaces output/ciphertext history or
authenticates the enclosing state. The opt-in `test-uno-tree-cell` links the actual
Rust implementation and tests BoC round trips followed by more appends.
