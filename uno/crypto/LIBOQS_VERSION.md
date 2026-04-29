# liboqs version pin for uno_workchain ML-KEM-768

This file records the exact upstream liboqs commit and build configuration
that `uno/crypto/mlkem768.cpp` is validated against. CI and mainnet
validator builds MUST pin this commit rather than track `main`, to keep the
FIPS 203 ML-KEM-768 implementation consensus-stable.

## Pinned commit

- Repository:  https://github.com/open-quantum-safe/liboqs
- Branch at time of pin: `main`
- Commit hash: `3cb781fd4737c900ad755ee0bb9e1949d0f68955`
- Commit date: 2026-04-15
- Commit summary: "Update pytest package version (#2408)"

To reproduce locally:

```sh
git clone https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs-src
cd /tmp/liboqs-src
git checkout 3cb781fd4737c900ad755ee0bb9e1949d0f68955
```

The TOS source tree also vendors this exact upstream revision at
`third-party/liboqs`. Production builds still honour explicit
`LIBOQS_INCLUDE_DIR` / `LIBOQS_LIBRARY` first; if no system liboqs is found,
`uno/CMakeLists.txt` builds the vendored tree directly.

## Build flags

The pinned build uses only the ML-KEM algorithm family (ML-DSA / SPHINCS /
etc. are not needed by the uno workchain) and produces a static archive.

```sh
cmake -S /tmp/liboqs-src -B /tmp/liboqs-build \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_ENABLE_KEM_ML_KEM=ON \
      -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/liboqs-build -j"$(nproc)"
sudo cmake --install /tmp/liboqs-build
```

On hosts without `sudo` (agent worktrees, dev containers, CI builders
running as non-root), swap `CMAKE_INSTALL_PREFIX` for `$HOME/.local` and
configure the uno build with:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug \
      -DLIBOQS_INCLUDE_DIR="$HOME/.local/include" \
      -DLIBOQS_LIBRARY="$HOME/.local/lib/liboqs.a"
# or simply
CMAKE_PREFIX_PATH="$HOME/.local" cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
```

## What the uno CMake probe checks

`uno/CMakeLists.txt` runs the following probes after locating liboqs:

1. `find_path(LIBOQS_INCLUDE_DIR oqs/oqs.h)` + `find_library(LIBOQS_LIBRARY NAMES oqs)`.
2. Compile-only probe (`check_cxx_source_compiles` using `sizeof(&fn)` to
   avoid dragging in the OpenSSL transitive link dep) that verifies
   `OQS_KEM_ml_kem_768_keypair_derand` and `OQS_KEM_ml_kem_768_encaps_derand`
   are declared in `oqs/kem_ml_kem.h`.
3. When those probes succeed, the build defines
   `OQS_HAVE_ML_KEM_KEYPAIR_DERAND=1` and `OQS_HAVE_ML_KEM_ENCAPS_DERAND=1`,
   which flip `uno/crypto/mlkem768.cpp` onto the deterministic-derand paths.
4. When liboqs is not found, the build falls back to
   `-DUNO_MLKEM_STUB=1`, which turns every ML-KEM entry point into a
   `std::abort()` — this keeps the skeleton build green on hosts without
   liboqs installed, but any test or runtime code that actually exercises
   ML-KEM will abort loudly, never silently returning wrong data.

## Dependencies pulled in by liboqs.a

The static `liboqs.a` has one non-trivial runtime dependency: **OpenSSL**
(`libcrypto`, for SHA3 / AES / cleanse helpers). The uno build already
links OpenSSL via `tos_crypto`, so the transitive link resolves without
additional CMake plumbing. On hosts where OpenSSL headers are missing,
the liboqs build itself fails during its `find_package(OpenSSL)` probe —
install `libssl-dev` (Debian/Ubuntu) or `openssl-devel` (RHEL family)
before invoking the liboqs configure step above.

## Consensus-relevant notes

ML-KEM-768 keypair bit-patterns depend on the exact upstream seed-expansion
code path. Different liboqs builds (`pq-crystals` reference vs.
AVX2-optimised) are byte-compatible for both `(pk, sk)` and `(ct, ss)`
outputs — the FIPS 203 final spec pinned this. However, any future
`OQS_BUILD_ONLY_LIB=ON` minimisation that changes which implementation is
selected (e.g. disabling AVX2 on older chips) does NOT change output
bytes; it only changes performance. So the commit hash above is the
primary pin, but validator operators are free to rebuild liboqs with
different `OQS_OPT_TARGET` flags so long as they stay on the pinned
commit.

## Reviewing a new commit

Before bumping the pin:

1. Check the liboqs changelog for any `kem/ml_kem/**` changes.
2. Rebuild with the new commit and run:
   ```
   ./build-uno-check/uno/test/test-uno-primitive-parity
   ```
   The `test_mlkem768_roundtrip` line must still print `PASSED`
   (deterministic keygen stability + encap/decap round-trip).
3. Confirm the derand probes still succeed in the CMake configure output.
4. Update the commit hash and date in this file.

## History

| Date       | Commit                                     | Notes                                                                                            |
|------------|--------------------------------------------|--------------------------------------------------------------------------------------------------|
| 2026-04-20 | `3cb781fd4737c900ad755ee0bb9e1949d0f68955` | Initial pin — M-liboqs build-bringup. `OQS_ENABLE_KEM_ML_KEM=ON`, `OQS_BUILD_ONLY_LIB=ON`.       |
