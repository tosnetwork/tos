# Native ML-DSA-44 verification (TVM version 16)

## Scope and activation

This adds a C/C++ verifier and a general-purpose TVM instruction, not a wallet,
key store, authentication module or validator-signature migration. Existing
Wallet V5 and Agent Account contracts and their bytecode are unchanged. The
separate Rust VM under `tosctl/src/vm` does not gain this instruction from this
C++ integration; callers must use the native VM/emulator until that execution
route has a separately reviewed compatible implementation.

`PQCHECKSIG_MLDSA44` is codepage-0 instruction **F93100 (24 bits)**, registered
with `require_version(16)`. Versions 0 through 15 reject it as invalid opcode
(6). `SUPPORTED_VERSION` is **16**, with no build option to select anything
else; `test/pq-readiness/test_release_profile.py` fails if a second profile
reappears or if the ceiling and `pq_mldsa44_min_version` ever disagree.

That constant is not an execution gate, and must not be read as one. A node
whose configuration names a higher version logs an error and keeps collating and
validating: see the `get_global_version() > supported_version()` checks in
`validator/impl/collator.cpp` and `validator/impl/validate-query.cpp`, which
warn and fall through. A local chain built from this source when the constant
was still 15 was set to ConfigParam 8 version 16 and produced blocks that
executed this instruction; `doc/macos-local-node.md` records that run. What
actually gates the instruction is the global version the VM is constructed at,
which comes from ConfigParam 8.

Raising the constant to 16 therefore activates nothing. What it does change is
narrow and worth stating: a VM built with no configuration to consult now runs
at 16, so `lite-client runmethod`, Fift and `run_get_method` can reach this
instruction; the collator writes 16 into each block's informational
`gen_software` field, which `validate-query` never reads; and the message above
stops being logged on a chain already configured at 16. Between global versions
15 and 16 this tree has exactly one semantic difference -- whether this
instruction exists -- so nothing else moves with it. It is step one of the
sequence in `doc/GlobalVersions.md`: ship a capable binary first, upgrade every
validator, and only then consider ConfigParam 8.

ConfigParam 8, genesis and capability masks are untouched by this change.
Activation is therefore a coordinated protocol configuration decision with
validator deployment, and the supported-version constant is an advertisement of
what a binary implements, not a refusal to run anything else. Local feature
toggles must never change the instruction's semantics.

## Exact interface

Stack, bottom to top:

```
message:Cell context:Cell signature:Cell public_key:Cell -> valid:Int
```

The algorithm is FIPS 204 **Pure ML-DSA-44**, using the external message/context
interface. There is no implicit prehash, external-mu input, pre-standard
Dilithium variant or HashML-DSA mode. An application may sign a 32-byte account
commitment as its message, but it must specify that commitment and its own
context. The generic instruction does not hard-code a TOS-AUTH context.

| Operand | Byte length |
| --- | --- |
| Message | 0 to 8192 |
| Context | 0 to 255 |
| Signature | exactly 2420 |
| Raw public key | exactly 1312 |

All operands use canonical byte chains: ordinary level-zero cells, byte-aligned,
with at most one continuation reference. Every non-final cell has exactly 127
bytes and one reference. A final cell has 1..127 bytes and no references. Only
the sole root of an empty byte string may have zero bytes. This is stricter
than SHA256C's arbitrary-chunk interface. BOC/DER wrappers are not payload;
exotic/library cells, branches, partial intermediate cells and trailing empty
cells are rejected. BOC transport must decode to these same operand cells.

A valid signature returns `-1`; a mathematically invalid signature returns `0`.
Incorrect lengths or cell encodings throw cell-underflow (9). Stack underflow
and wrong types retain VM errors (2 and 7). A backend operational failure is
not reported as an invalid proof: it throws VM fatal error (12). Out-of-gas
stops execution, not verification-false. The instruction neither honors
`chksig_always_succeed` nor uses the classic free-signature-call allowance.

## Deterministic gas

Every invocation with sufficient stack depth pays **50,000 gas before operand
decoding**, then **1 gas per decoded byte before copying**, plus ordinary VM
cell-load/reload and instruction overhead. Invalid proofs pay the same base.
For a raw one-instruction program, ordinary overhead is 34 instruction gas,
5 implicit-return gas, and 100/25 gas for first/repeated cell loads. Loads are
identified by representation hash, not pointer identity. Compiled programs may
add their own dispatch overhead. Bounds constrain memory, hashing and traversal.

The price is fixed protocol data, never derived from a validator's CPU clock.
The validation workflow measures full-VM CPU cost across valid and invalid
vectors against the existing paid Ed25519 tariff, and exercises repeated-call
workloads. See [validation and calibration](tvm-mldsa44-validation.md) for the
formula, gate, model budget and limitations. Runner measurements do not replace
production-hardware load testing or protocol approval before activation.

The base fee exceeds the ordinary 10,000-gas external admission credit. A PQ
Auth Module needs an explicit funded-internal-message/relayer design, including
replay and fee-abuse policy. Do not ACCEPT unauthenticated external traffic just
to bypass the credit or raise network limits to make a test pass. The module's
authority, funding and transaction/action-phase lifecycle are separate scope.

## Dependency and build

The backend is `pq-code-package/mldsa-native` **v2.0.0**, fixed to commit
`834a90d5e846ffa1e1611bd24e160bb2e9b86d35`. CMake builds the single fixed-level
ML-DSA-44 compilation unit with keypair/sign/randomized APIs disabled and
portable C arithmetic/FIPS202. No native-backend CPU dispatch, runtime OpenSSL
provider, private key or RNG is used by this verifier. The C++17 wrapper checks
all lengths before calling the upstream fixed-size API. Test-only calibration
uses the existing Ed25519 implementation and a public fixed test seed.

The source is vendored at `third-party/mldsa-native`, like every other
dependency in this repository, so configuring the project never reaches the
network and offline builds need no extra option. Only the upstream `mldsa/`
compilation subtree is imported, unmodified; `third-party/mldsa-native/PROVENANCE.md`
records the revision and the import boundary. Changing that revision is a
supply-chain decision; do not replace the pinned import with a branch.
Upstream uses `Apache-2.0 OR ISC OR MIT`; preserve its license and notices in
source/binary distributions. Its LICENSE is installed under
`share/tos/licenses/mldsa-native`. VM glue and wrapper use LGPL-2.0-or-later.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target test-pq-mldsa44 test-pq-mldsa44-wrapper func fift tol -j2
python3 test/pq-mldsa44/prepare_vectors.py --out pq-results
build/crypto/pq/test-pq-mldsa44-wrapper pq-results/vectors.tsv pq-results/wrapper.tsv
build/crypto/pq/test-pq-mldsa44 pq-results/vectors.tsv pq-results/native.tsv --benchmark
python3 test/pq-mldsa44/bindings.py --build build --vectors pq-results/vectors.tsv --out pq-results
python3 test/pq-mldsa44/mutations.py --build build --vectors pq-results/vectors.tsv
```

The standalone wrapper builds with `cmake -S crypto/pq -B build-pq`. FunC uses
`crypto/smartcont/pq.fc`; Tol uses `crypto/smartcont/pq.tol`. Assembly must load
`PQ.fif` before compiler output using the new mnemonic. Binding tests compile
both public declarations and execute both resulting BOCs in the actual VM.
The node build prefers Clang by default; CI records actual CMake compiler
selection rather than inferring it from `cc --version`.

## Public vectors and execution evidence

`prepare_vectors.py` checks fixed Git blob hashes for ACVP-Server commit
`975de31eb83d87039ec88934fdc47d8c312b892d` (v1.1.0.43) and Wycheproof commit
`3fa63dd0344abb611f1fb1d77e119938603ea230`. It selects external Pure ML-DSA-44
sigVer cases, reports excluded profiles/out-of-bound valid inputs separately,
and adds three public OpenSSL 3.5.5 positive fixtures. Missing data, hash
mismatches and absent positive/negative controls fail, rather than skip, CI.

The final commit must pass native x86-64/AArch64 execution, both compiled
bindings, six guard mutations, wrapper and full-VM ASan/UBSan, and byte-identical
transcript/BOC comparisons. Artifacts contain corpus manifests, verdicts, gas,
commit-state hashes and diagnostic timing. Definitions are not execution proof;
use the final commit's successful jobs and artifacts. The detailed acceptance
matrix is in [tvm-mldsa44-validation.md](tvm-mldsa44-validation.md).

Public-vector success is not NIST/FIPS certification, an independent audit or a
claim that the whole chain or production wallets are quantum-safe. Activation
still requires protocol/security review, production-limit validation and a
separately audited immutable or PQ-governed authentication module.
