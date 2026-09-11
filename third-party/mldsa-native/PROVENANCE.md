# Vendored ML-DSA-44 verification backend

Upstream: https://github.com/pq-code-package/mldsa-native
Release: v2.0.0
Commit: 834a90d5e846ffa1e1611bd24e160bb2e9b86d35

Vendored in-tree so that configuring this repository never reaches the network,
matching how every other dependency under `third-party/` is carried.

Only the `mldsa/` compilation subtree is imported, together with `LICENSE` and
`RELICENSE.md`. Upstream proofs, tests, build scripts, examples and CI material
are not imported; nothing under `mldsa/` is modified, added to or reordered.

`crypto/pq/CMakeLists.txt` compiles `mldsa/mldsa_native.c` as a single unit with
`crypto/pq/mldsa44-config.h`, selecting ML-DSA-44 only, verification only, and
portable C arithmetic and FIPS202 backends. No CPU dispatch, assembly backend,
key generation, signing or RNG is compiled.

To re-vendor a different upstream revision, replace `mldsa/`, `LICENSE` and
`RELICENSE.md` from a clean checkout of that revision, update the commit
recorded above, and re-run the native verification workflow. A revision change
is a supply-chain decision, not a routine dependency bump.

Upstream is licensed `Apache-2.0 OR ISC OR MIT`; its license and copyright
notices are preserved here and installed with the build.
