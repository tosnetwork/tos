# V2 balance-kernel validation record

This record concerns the unactivated mathematical kernel, not custody, full
transaction authorization, multi-account execution or a production K decision.
Amounts are confidential; participants and transfer relationships are not.

## Reproducible checks

The crate's README gives the native build and CTest entry points. The opt-in
parent configuration must enable `TOS_UNO_CRYPTO_PROTOTYPE_TESTS`.
On the Linux x86-64 build, all six `test-uno-crypto-` CTest entries passed.
One is the retained V0 mock adapter; it is not evidence for the new kernel.
The Rust suite has thirteen tests, including SEND and all COLLECT k=1..8 shapes,
frozen bytes, per-field mutations, shared-response equations and FFI recovery.

The following mutation runners operate only on disposable source copies:

```sh
python3 uno/crypto/tests/run-mutations.py \
  --output /absolute/new/mutation-evidence \
  --target-dir /absolute/scratch/mutation-cargo
python3 uno/crypto/tests/run-boundary-controls.py \
  --output /absolute/new/boundary-evidence \
  --target-dir /absolute/scratch/mutation-cargo \
  --archive /absolute/current/libtos_uno_crypto_prototype.a
```

Forty-eight mutation-runner checks passed after the follow-up, including
positive/restored controls and removal of the internal policy ceiling.
The earlier 32- and 47-control records are retained as historical evidence.
The recorded logs and source hashes are retained in
[the evidence archive](measurements/uno-v2-kernel-evidence.tar.gz).
The later F1-F5 run, including the 48-control result and checkout-status negative
control, is in [the follow-up archive](measurements/uno-v2-kernel-followup-evidence.tar.gz).
Use its `uno-kernel-f1-f5-final-mutations` directory for the corrected standalone
unknown-kind control; the earlier run is retained to show the incidental-test
failure identified by the focused review. Final boundary controls are in
`uno-kernel-f1-f5-final-boundaries`.
The baseline plus source hashes identify the uncommitted implementation tested;
the record does not claim that historical local logs automatically match a future HEAD.
Each of 21 possible Sigma equation positions was independently bypassed and
detected. The range checks include opposing nonzero residuals: replacing separate
zero tests with cancellation fails. Removing context/T binding, reversing witness
response indexing, dropping configured K enforcement and changing transcript
endianness also failed executed tests, not just compilation or error-text checks.
Boundary controls separately removed the lexical gate, unwind containment and
runtime entropy trap; each produced an observable failing test.
Post-review controls also disabled the actual vendor file-set and hash checks;
the added-file and changed-file tests failed respectively.
The follow-up also removes the checkout-status gate: the actual untracked-build
script test fails. These runners remain manual evidence, not registered CTest jobs.

## Sanitizer scope and firing controls

The real ABI harness passed with C++ ASan/UBSan plus Rust address instrumentation.
Rust target dependencies were built with the pinned compiler, explicit
`--target x86_64-unknown-linux-gnu`, `RUSTC_BOOTSTRAP=1` and
`RUSTFLAGS='-Zsanitizer=address -Cforce-frame-pointers=yes -Cdebuginfo=1'`.
The standard library was not rebuilt with sanitizers. Link using clang++-21,
`-fsanitize=address,undefined -fno-omit-frame-pointer`, and the instrumented archive.
This is not Rust UBSan coverage or a proof that every unsafe path was executed.

`tests/sanitizer-canary.cpp` intentionally violates the caller's allocation-size
contract. With Rust ASan it exits 1 and reports a 32-byte heap overread in the
Rust decoder. With only C++ instrumented it exits 2 with CANARY_NOT_DETECTED.
The contrast proves why C++-only sanitizer success cannot certify Rust accesses.
The canary is not a valid request and is not a production verifier target.
Building the crate with `-Cpanic=abort` separately fails at its intended
compile-time containment guard; a compilation failure is appropriate evidence
for this build guard, not for a behavioral proof-rejection test.

## Limits of the evidence

The symbol gate resolves direct/GOT edges, not all indirect calls. Its output
explicitly reports unresolved sites. Dormant standard-library entropy symbols
remain linked. Combine source/call-path review, locked normal dependency graph,
source-integrity checks, reachable-symbol checks and the runtime trap; no one of
them proves absence of randomness across all possible executions.

The independent C transcript reference matches two successive 64-byte challenges
and framing over a 1024-byte message. This is overlapping primitive evidence,
not differential validation of the complete SEND/COLLECT proof implementation.
No new production performance, RustSec clearance, host acceptance or cross-platform
determinism claim is made by this record.
