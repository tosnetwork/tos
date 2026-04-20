# avatar-crypto — vendored subset for TOS Uno

This directory vendors a subset of the in-house **avatar** cryptography tree
so that the TOS repo is **self-contained** (no sibling checkout required for
CI, builds, or audits). avatar is 100% team-authored code; this is a mirror,
not a third-party dependency.

## What's vendored

- `include/at/` — the full avatar include tree (~340 headers, ~5 MB). Copied
  wholesale so transitive header dependencies resolve identically to the
  source avatar repo. Upstream expansion (adding another primitive) is a
  copy operation that lands the right `.c` files without needing to trace
  includes.
- `src/crypto/blake3/` — BLAKE3 sources:
  - `at_blake3.c` (main hash state machine, portable)
  - `at_blake3_ref.c` (reference-kernel round function)
  - `at_blake3_sse41.c`, `at_blake3_avx2.c`, `at_blake3_avx512.c` (x86 SIMD
    variants, **compiled conditionally** via `AT_HAS_SSE` / `AT_HAS_AVX` /
    `AT_HAS_AVX512` — disabled by default in `uno/CMakeLists.txt` for
    platform portability; enable only on known x86 hosts)

## What's NOT vendored (yet)

- Other avatar primitives (BLAKE2b, ChaCha20-Poly1305, Ristretto255, etc.):
  these come from libsodium today. Bring them over if/when we decide to
  drop libsodium.
- avatar's build system (GNUmakefile, Local.mk): replaced by
  `uno/CMakeLists.txt` probes (see the `AVATAR_CRYPTO_ROOT` block).
- avatar's test harness and unit tests: not needed for uno's build;
  BLAKE3 correctness is pinned by `uno/test/reference/hybrid_kem_kat.py`
  and verified by `test-uno-primitive-parity`.
- SIMD equivalence tests (`test_blake3_simd.c`): see §12 P.1 test matrix
  for the uno-side version.

## Upstream pin

avatar repo commit: **`ba0aab1486eaec640c5fb9d53254688faa3db1d1`** (mirrored
2026-04-20).

**Update policy**: avatar is an actively-developed sibling repo; this
vendor is a snapshot. Refresh by:

1. Copy the new BLAKE3 `.c` files + full `include/at/` tree from the
   avatar repo at the desired commit.
2. Bump the pin hash above.
3. Rebuild + re-run `test-uno-primitive-parity` to confirm the
   hybrid-KEM KAT still matches byte-for-byte.

Do not cherry-pick partial updates — copy wholesale to keep the transitive
header set consistent.

## See also

- `uno/CMakeLists.txt` — compilation + include-path wiring (`AVATAR_CRYPTO_ROOT`
  defaults to this directory).
- `uno/crypto/internal/blake3_adapter.{h,cpp}` — C++ wrapper that calls
  `at_blake3_*` symbols.
- `uno/crypto/internal/avatar_log_stubs.c` — minimal no-op stubs for the
  handful of `at_log_*` symbols avatar BLAKE3 references; stubbed to
  avoid dragging in avatar's shared-memory log-ring infrastructure.
- Design doc §16 decision #41 — BLAKE3 backend choice (UNO_BLAKE3_AVATAR).
