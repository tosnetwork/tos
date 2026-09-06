# Concurrent ABI and sanitizer evidence

2026-09-06, baseline `b00c408a0` plus this change, native x86_64 Linux.
These are prototype ABI v0 tests, not production activation or a race-freedom
proof. No ABI/schema, proof profile, or runtime implementation was changed.

## Real concurrent entry points

`abi-real.cpp` starts eight threads at a common gate. Each makes four valid
and four wrong-digest calls to `uno_crypto_verify_v0`, with private requests
and shared immutable proof/action buffers. This runs for both real public
funding and real spending fixtures. The first funding run precedes any serial
verification, exercising real concurrent verifier initialization. Measurement
mode deliberately skips this test to preserve its first-call measurement.

`abi-tree.cpp` starts eight gated callers with distinct commitment sequences.
Each makes four successful append calls and four invalid-commitment calls to
`uno_crypto_tree_append_v0`. Complete output is compared to its serial reference;
rejected calls must preserve the output. The tests link the actual Rust archive,
not a cache substitute or exported-function stub.

`EmptyAndOversizedShapesNeverInvokeBackend` covers empty actions, empty proof,
and a two-action/7264-byte bundle over a one-action limit. It checks invalid
results and zero backend invocations, followed by a successful control call.

## Mutation evidence

All mutations were removed before final testing:

| New property | Removed behavior | Observed failure |
| --- | --- | --- |
| Concurrent verification preserves signature rejection | Ignore `verify_in_context` failure | ABI executable exit 2, concurrent verification mismatch before serial verification |
| Concurrent tree append publishes its complete result | Skip output publication when reserved leaves are nonzero | Tree executable exit 18, its first concurrent test |
| Malformed host bundle shape never enters ABI | Bypass host shape guard | New adapter test fails invalid-result assertion; rejecting stub is not used to mask the missing gate |

Logs: `build/wave2-verify-concurrency-mutation.log`,
`build/wave2-tree-concurrency-mutation.log`, and
`build/wave2-adapter-shape-mutation.log`.
After restoration all four adapter tests and both real ABI executables passed.

## ASan and UBSan

An isolated build at `build/uno-ffi-sanitizer-rBm5he` used pinned Rust 1.97.1,
`CARGO_NET_OFFLINE=true`, `--locked --offline --release -j48`, explicit target
`x86_64-unknown-linux-gnu`, and
`RUSTFLAGS='-Zsanitizer=address -Cdebuginfo=1'` with `RUSTC_BOOTSTRAP=1` only in
that experimental test process. This did not change the production toolchain
or Cargo profiles. C++ drivers used clang++-21, `-std=c++17 -O1 -g
-fno-omit-frame-pointer -fsanitize=address,undefined`, linked to that instrumented
Rust archive with `-pthread -ldl -lm`.

Both concurrent/serial ABI executables passed with
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. Public fixtures were
`build/uno/crypto/fixtures/0c5be50e302c7406d822/{output-only,spend}.bin`.
Build/run logs are `build.log`, `tree.log`, and `verify.log` in the isolated
directory. The directory consumed about 437 MiB before adding the linked drivers.

The instrument was tested, not inferred from silent success. Build the opt-in
`uno/crypto/tests/sanitizer-canary.cpp` with the same compiler/link flags:

- No argument deliberately supplies too short a frontier allocation. Exit 1
  reports ASan heap-buffer-overflow at the **Rust** `tree_ffi::transition` read,
  demonstrating instrumentation beyond the C++ caller.
- An argument deliberately performs non-monetary signed integer overflow.
  Exit 1 reports UBSan signed overflow in the C++ canary.

Canary logs are `asan-canary.log` and `ubsan-canary.log`. Neither is evidence of
a valid-contract API defect: they deliberately violate test contracts to prove
the detectors run. They must never be registered as ordinary passing tests.

Coverage limitations: Rust target crate/dependencies were built with ASan, but
precompiled Rust standard library and system libraries were not rebuilt with it.
UBSan covers the C++ harness, not Rust undefined behavior generally. Sanitizer
drivers omit `UNO_TEST_HOST_ADAPTER`, so they do not instrument the full C++ VM
or host adapter. Normal tests do exercise that adapter. This is not TSan, a
memory-safety proof, exhaustive concurrency scheduling, or worst-case timing.
