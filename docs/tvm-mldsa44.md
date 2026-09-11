# Native ML-DSA-44 verification (proposed TVM version 16)

## Scope and activation

This adds a C/C++ verifier and a general-purpose TVM instruction, not a wallet,
key store, authentication module, validator signature migration, or claim that
the entire chain is post-quantum secure. Existing account contracts and their
bytecode are unchanged. The separate Rust VM under `tosctl/src/vm` does not gain
this instruction from the C++ integration; use the native VM/emulator for these
tests until a separately reviewed compatible implementation exists.

`PQCHECKSIG_MLDSA44` has the proposed 24-bit code `F93100`. It is registered in
codepage 0 with `require_version(16)`. Versions 0 through 15 reject it as an
invalid opcode. Raising the binary's `SUPPORTED_VERSION` to 16 advertises
implementation support; this change does **not** edit ConfigParam 8, genesis,
capability masks or activate version 16 on a running network. Activation needs
coordinated validator deployment and a separate configuration decision. No
local feature toggle may change validation results after activation.

## Exact interface

Stack (bottom to top):

```
message:Cell context:Cell signature:Cell public_key:Cell -> valid:Int
```

The algorithm is FIPS 204 **Pure ML-DSA-44**, using its external message/context
interface. There is no implicit message prehash, no external-mu input, no
pre-standard Dilithium variant and no HashML-DSA mode. Applications may sign a
32-byte account-request commitment as the message, but must define that
commitment and the application context themselves. This general VM instruction
does not pin an account-specific context string.

| Operand | Byte length |
| --- | --- |
| Message | 0 to 8192 |
| Context | 0 to 255 |
| Signature | exactly 2420 |
| Raw public key | exactly 1312 |

Each operand is a canonical byte-chain Cell: ordinary level-zero cells only,
byte-aligned, at most one continuation reference. Every non-final cell has
exactly 127 bytes and one reference. A final cell has 1 to 127 bytes and no
references. Only the sole root of an empty byte string may contain zero bytes.
This is intentionally stricter than the arbitrary-chunk SHA256C interface.
No BOC headers, length prefixes, DER wrappers, exotic/library cells, branches,
trailing empty cells, or unused data are accepted as part of these operands.

Valid signatures return `-1`; mathematically invalid signatures return `0`.
Incorrect lengths or cell encodings throw cell-underflow (9). Wrong stack types
and stack underflow retain normal VM errors. A backend operational failure is
not silently converted to a mathematical rejection: it throws fatal (12).
An exhausted gas budget stops execution, rather than returning false.

The instruction deliberately does not honor `chksig_always_succeed` and does not
reuse the classical signature instruction's free-call allowance.

## Gas: deterministic draft schedule, not a final activation recommendation

Every invocation pays a base **50,000 gas**, charged after stack-depth checking
and before operand decoding or signature work. It then pays **1 gas per decoded
byte**, charged before copying those bytes, plus the existing VM cell
load/reload charges and normal opcode/return overhead. Size limits bound
allocation, hashing and cell traversal. Invalid proofs pay the same base fee.

These constants are an initial conservative engineering proposal. CI records
actual wall-clock timings for a short valid proof, an 8192-byte message and a
full-length invalid proof on x86-64 and AArch64. Timings are diagnostic, never
consensus input. Final CPU/DoS calibration against existing instructions,
production validator hardware and a block-wide workload is an activation gate.
Do not increase network limits to make verification pass.

The base fee exceeds the ordinary 10,000-gas external admission credit. A
production authentication module therefore needs an explicit funded-internal
message / relayer design, including its replay and fee-abuse policy. It must
not accept unauthenticated external traffic and spend unlimited account gas.
This PR does not implement that module or promise its end-to-end economics.

## Dependency and build

The backend is `pq-code-package/mldsa-native` release **v2.0.0**, pinned to
`834a90d5e846ffa1e1611bd24e160bb2e9b86d35`. CMake builds the fixed-level single
compilation unit with ML-DSA-44 only, key generation/signing/randomized APIs
disabled, and portable C arithmetic/FIPS202 backends. No CPU dispatch, AVX2/NEON
backend, runtime OpenSSL provider, private key or RNG is required by this build.
C is linked through a small C++17 wrapper; a pure-C++ reimplementation is not
necessary. Upstream's verify API assumes fixed-size keys/signatures, so the
wrapper independently checks all lengths before calling it.

CMake FetchContent downloads the fixed commit at configure time, never at node
runtime. An offline build can prepopulate that exact source and set
`FETCHCONTENT_SOURCE_DIR_TOS_MLDSA_SOURCE` to its directory. Pin verification and
upstream release review remain supply-chain responsibilities; do not substitute
a moving branch. Upstream source is licensed `Apache-2.0 OR ISC OR MIT`; preserve
its license and copyright notices in source/binary redistributions. The wrapper
and VM glue use the repository's LGPL-2.0-or-later license.

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target test-pq-mldsa44 test-pq-mldsa44-wrapper func fift -j2
python3 test/pq-mldsa44/prepare_vectors.py --out pq-results
build/crypto/pq/test-pq-mldsa44 pq-results/vectors.tsv pq-results/native.tsv --benchmark
python3 test/pq-mldsa44/bindings.py --build build --vectors pq-results/vectors.tsv --out pq-results
python3 test/pq-mldsa44/mutations.py --build build --vectors pq-results/vectors.tsv
```

The verifier alone can be built using `cmake -S crypto/pq -B build-pq`.
FunC callers include `crypto/smartcont/pq.fc`. Fift assembly must explicitly
include `PQ.fif` before including compiler output that uses the new mnemonic.
The matching low-level Tol declaration is in `crypto/smartcont/pq.tol`.

## Evidence and its limits

`prepare_vectors.py` retrieves and checks fixed Git blob hashes for:

- NIST ACVP-Server `975de31eb83d87039ec88934fdc47d8c312b892d` (v1.1.0.43),
  ML-DSA-sigVer-FIPS204 prompts and expected results. Only the external Pure
  ML-DSA-44 profile is included; other profiles are explicitly counted separately.
- Wycheproof `3fa63dd0344abb611f1fb1d77e119938603ea230`,
  `mldsa_44_verify_test.json`, including malformed-signature checks. Algorithm-valid
  inputs outside this instruction's bounded profile are reported separately,
  not counted as passed conformance tests.
- Three independently generated public OpenSSL 3.5.5 fixtures: empty inputs,
  a domain-bound 32-byte account commitment, and maximum message/context lengths.
  These contain no private keys. They are test data, not production credentials.

A missing download, mismatched source hash, empty corpus or absent positive /
negative controls fails the job. Both the C++ wrapper and actual TVM instruction
must agree with the expected results; a failure for the wrong reason is not a
passing negative test. Structural rejection, version gating, exact gas boundary,
BOC transport, ignored-classic-signature flag and eleven paid calls are also
exercised. A compiled FunC caller is executed, not just syntax-checked.

The workflow runs native GCC builds on x86-64 and AArch64, a Clang ASan/UBSan
verifier build, and compares exact public-vector manifests and transcripts.
Native transcripts include exit code, stack boolean, gas and committed data /
action cell hashes. This establishes consistency for the tested corpus, not a
mathematical proof over all inputs. Guard mutations remove signature checking,
version gating and base-gas charging; each must compile and make a previously
passing test fail, followed by restoration and a passing baseline.

Passing public vectors is **not** NIST certification, FIPS 140 validation,
independent cryptographic audit, or proof of complete post-quantum wallet support.
Before network activation: review opcode allocation, bounded encoding, native
backend errors and supply chain; calibrate gas; audit a real immutable/PQ-governed
authentication module and account relay lifecycle; and cover transaction/action
phase execution under target network funding and limits.
