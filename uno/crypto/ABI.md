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

This does not yet provide a C++ positive proof fixture, generated-header consistency
checks on other platforms, sanitizer/fuzz coverage, host CMake linking or real UNO
engine integration. Those remain acceptance requirements before production use.
