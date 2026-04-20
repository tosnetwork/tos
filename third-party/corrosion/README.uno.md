# corrosion-rs — vendored for TOS Uno

This directory vendors [corrosion-rs](https://github.com/corrosion-rs/corrosion),
a CMake tool that imports Cargo crates as first-class CMake targets. We use
it to link the Rust FFI crate `uno/plonky3-ffi/` (which produces
`libuno_plonky3_ffi.a`) into the C++ `uno_workchain` static library so that
downstream binaries (`validator-engine`, `create-hardfork`, `test-tos-collator`,
every `test-uno-*` binary) resolve the real `uno_plonky3_*` and
`uno_poseidon2_goldilocks_permute_t8` symbols instead of the weak-symbol
stubs that live in `uno/core/parallel-verify.cpp` and friends.

## What's vendored

The full corrosion-rs release tree at tag **`v0.5.2`** (released by
upstream on 2025-10-28). We copied the GitHub release tarball wholesale
and stripped the git metadata — history is not needed for our use case.
Total size on disk is ~1.5 MB.

Layout preserved from upstream:

- `CMakeLists.txt` — corrosion's own top-level build file. When included
  via `add_subdirectory(third-party/corrosion)` from the repo-root
  `CMakeLists.txt` it exposes the `find_package(Corrosion)` semantics
  via `CORROSION_INSTALL_EXPORT` plus `corrosion_import_crate()` as a
  CMake function.
- `cmake/Corrosion.cmake` — the canonical entry point; `include()`-able
  from a parent CMakeLists.txt as an alternative to `add_subdirectory`.
  `uno/CMakeLists.txt` uses `find_package(Corrosion QUIET)` which
  resolves against the target that our top-level `add_subdirectory` call
  produces.
- `generator/` — a tiny Rust crate (`corrosion-generator`) that corrosion
  bootstraps on first configure. Built with the host `cargo`; does NOT
  touch the network (no crates.io pulls at configure time — the generator
  uses only stdlib + `Cargo.lock` entries already in the tree).
- `doc/`, `test/` — documentation + corrosion's own test suite. Kept for
  future refresh reference; we do NOT build the corrosion test suite
  (`CORROSION_BUILD_TESTS` defaults to OFF when corrosion is used as a
  subproject).

## Upstream pin

Corrosion release tag: **`v0.5.2`**
Tarball URL: <https://github.com/corrosion-rs/corrosion/archive/refs/tags/v0.5.2.tar.gz>
Vendored on: 2026-04-20.

## Update policy

Corrosion's CMake API is stable across 0.5.x minor versions. To refresh:

1. Pick a newer tag on the 0.5 or 0.6 line.
2. Download the release tarball, extract wholesale, replace the contents
   of `third-party/corrosion/` (keeping this `README.uno.md`).
3. Bump the tag in this file.
4. Re-run `cmake -S . -B build && cmake --build build --target validator-engine`
   and `build/uno/test/test-uno-parallel-verify` — both must pass.
5. Note in the commit message whether any `corrosion_import_crate()`
   call-site flags had to change (they shouldn't for 0.5 → 0.5).

Do not cherry-pick partial updates — always replace wholesale so the
cmake/ + generator/ pair stays in lockstep.

## Network / prerequisites

- Requires the host `cargo` + `rustc` on `PATH`. The build-host CI image
  already has these (needed for `uno/plonky3-ffi/` regardless).
- Does NOT touch the network at CMake configure time. Corrosion's own
  `corrosion-generator` crate compiles with stdlib only; the rebuilt
  `uno_plonky3_ffi` crate resolves all dependencies through the vendored
  `third-party/plonky3-uno/` tree (decision #43) so `cargo build` runs
  offline as well.

## See also

- `uno/CMakeLists.txt` — `find_package(Corrosion)` + `corrosion_import_crate(...)`
  block that links `libuno_plonky3_ffi.a` into `uno_workchain`.
- Repo-root `CMakeLists.txt` — `add_subdirectory(third-party/corrosion EXCLUDE_FROM_ALL)`
  call placed before `add_subdirectory(uno)`.
- `uno/plonky3-ffi/Cargo.toml` — the Rust crate corrosion imports.
- Design doc §16 decision #43 — Plonky3 vendor policy (sister decision to
  this file's "vendor corrosion" call).
