# Prototype verification ABI v0

`include/uno_crypto.h` declares `uno_crypto_verify_v0`; `cargo build --locked
--offline --release -j48` produces the matching static library. This is a native
process interface, not a Cell codec, chain wire assignment or activation profile.
ABI version 0 and ABI profile 1 select only the pinned fixed bundle/circuit pair.
Unknown values fail; context tags are defined explicitly in the header and must
not be obtained by casting another language's internal context enumeration.

The caller owns the request, Action array and proof bytes. All fields must be
initialized and all pointed-to allocations must remain readable, aligned and
immutable for the entire call. Null, alignment, multiplication, address-overflow
and slice-length checks do **not** prove that an arbitrary address is valid.
Never pass untrusted RPC pointer values. No pointers are retained, no secret
witness is accepted, and no allocation/free ownership crosses the boundary.
Amounts are high/low u64 words of u128 nanotomi, not host-endian byte strings.

The entry point checks ABI/profile and representable context, checks lengths
before constructing slices, decodes canonical primitive fields, and calls the
combined context/proof/spend/binding verifier. Its process-local key cache is an
immutable `OnceLock<Result<FixedVerifier, KeyConstructionFailed>>`; callers cannot
replace the key. A construction error fails closed. Unwinding panics are contained
at the exported function and return status 5; OOM, process abort and invalid
caller memory cannot be recovered by this mechanism. It must not be advertised
as recovery from `panic=abort`.

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

Generated-header consistency on other platforms, sanitizer/fuzz coverage and
actual node/UNO engine integration remain acceptance requirements before
production use. The CMake option does not activate a workchain or install config.
