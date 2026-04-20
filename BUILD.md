# Build

This repository now has two actively used build surfaces:

- a C++/CMake/Ninja build for the node, networking, and core native components
- a Rust/Cargo workspace under `tosctl/src` for operator tooling and Rust-side runtime libraries

This document describes the practical Linux build flow that matches the current tree.

## Build Surfaces

### C++

The top-level repository build is driven by [`CMakeLists.txt`](CMakeLists.txt).

This is the primary path for:

- `validator-engine`
- native networking and protocol components
- core C++ libraries and tests
- bundled native third-party dependencies built from `third-party/`

### Rust

The Rust workspace root is:

- `tosctl/src/Cargo.toml`

This workspace currently includes crates such as:

- `tosctl`
- `tos_executor`
- `tos_vm`
- `chain_block`
- `chain_block_json`
- `sandbox`
- `node-control/*`

The pinned Rust toolchain is:

- `tosctl/src/rust-toolchain.toml`
- channel: `1.91.1`

## Verified C++ Environment

The native build flow below was verified on:

- OS: Ubuntu 22.04
- Generator: `Ninja`
- Build system: `CMake`
- Compiler: `clang-21` / `clang++-21`
- Build directory: out-of-source, for example `build-clang21`

## Linux Prerequisites

Install the base toolchain and libraries:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  git \
  cmake \
  ninja-build \
  ccache \
  autoconf \
  automake \
  libtool \
  texinfo \
  pkg-config \
  python3 \
  python3-dev \
  libgflags-dev \
  libreadline-dev \
  libgsl-dev \
  libblas-dev \
  libgslcblas0 \
  libjemalloc-dev \
  gawk \
  wget \
  curl \
  lsb-release \
  software-properties-common \
  gnupg
```

Install `clang-21` if it is not already available:

```bash
cd /tmp
rm -f llvm.sh
wget -q https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 21
```

Verify the compiler:

```bash
clang-21 --version
clang++-21 --version
```

## Uno Workchain (wc=2) — Additional Prerequisites

The Uno privacy workchain adds four native dependencies on top of the base tree:

| Dependency | Purpose | Where it lives | Action required |
|---|---|---|---|
| **libsodium** | Ristretto255, ChaCha20-Poly1305, BLAKE2b (§2.5, §2.7) | `third-party/sodium/` (built in-tree) | none — bundled |
| **liboqs** | ML-KEM-768 post-quantum KEM (§2.7 hybrid note encryption) | external, pinned to a specific commit | **must install manually** |
| **avatar BLAKE3** | `BLAKE3` for transcripts, cell hashing, KDF (decision #41) | `third-party/avatar-crypto/` (vendored) | none — bundled |
| **corrosion-rs** | CMake ↔ Cargo bridge for the `uno_plonky3_ffi` Rust static library | `third-party/corrosion/` (vendored v0.5.2) | none — bundled |
| **Plonky3 toolkit** | STARK prover/verifier, Goldilocks field, Poseidon2 (§2.1, decision #43) | `third-party/plonky3-uno/` (vendored) | none — bundled |
| **Rust toolchain** | Required to build `uno_plonky3_ffi` — even if you only target the C++ side | rustup-managed | install via rustup |

### Installing liboqs

The pinned commit is recorded in [`uno/crypto/LIBOQS_VERSION.md`](uno/crypto/LIBOQS_VERSION.md). Pick ONE of the two paths below; do not mix them.

#### Path A — system-level (recommended for CI / single-purpose nodes)

```bash
sudo apt install -y libssl-dev   # liboqs needs libcrypto for SHA3/AES
git clone https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs-src
cd /tmp/liboqs-src
git checkout 3cb781fd4737c900ad755ee0bb9e1949d0f68955   # see LIBOQS_VERSION.md
cmake -S . -B /tmp/liboqs-build \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_ENABLE_KEM_ML_KEM=ON \
      -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/liboqs-build -j"$(nproc)"
sudo cmake --install /tmp/liboqs-build
```

Trade-off: convenient (CMake finds it automatically, no extra env var), but needs `sudo` and can collide with `apt install liboqs-dev` if a distro package is installed later.

#### Path B — user-local `$HOME/.local` (dev machines, multi-user hosts, no sudo)

Same as Path A, but:

```bash
cmake -S . -B /tmp/liboqs-build \
      ... \
      -DCMAKE_INSTALL_PREFIX="$HOME/.local" \
      ...
cmake --install /tmp/liboqs-build    # no sudo
```

Under Path B, every subsequent `cmake -S tos -B tos/build` invocation must be prefixed with:

```bash
CMAKE_PREFIX_PATH="$HOME/.local" cmake -S . -B build ...
```

That env var tells CMake to add `$HOME/.local/{include,lib}` to the `find_path` / `find_library` search roots — without it the Uno build silently falls back to `UNO_MLKEM_STUB=1` and every runtime ML-KEM call aborts.

If you forget the env var, `uno/CMakeLists.txt` will print:

```
-- uno_workchain: liboqs not found — ML-KEM-768 built with UNO_MLKEM_STUB=1 (runtime abort).
```

This is the signal that you are building a Uno tree whose ML-KEM paths cannot actually run.

### Installing the Rust toolchain (required even for a pure C++ build of Uno)

The Uno C++ library links against the Rust static archive produced by `uno/plonky3-ffi/` (Plonky3 verifier + Poseidon2 FFI). Corrosion drives the Cargo build during CMake configure; Cargo needs rustc.

```bash
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
```

Tosctl's Rust workspace (`tosctl/src/`) pins `1.91.1`; the `uno/plonky3-ffi/` crate targets the same channel. Rustup will install what's needed on first build. No separate toolchain install is required for the Uno FFI — it rides the pin from `tosctl/src/rust-toolchain.toml`.

### What stays bundled (no action)

- **libsodium** is built from `third-party/sodium/` by the top-level CMake.
- **avatar BLAKE3** sits at `third-party/avatar-crypto/` (100% in-house code, vendored per decision #41). `uno/CMakeLists.txt` auto-detects it and defines `UNO_BLAKE3_AVATAR=1`.
- **corrosion-rs** sits at `third-party/corrosion/` (v0.5.2). Top-level `CMakeLists.txt` includes it via `add_subdirectory(third-party/corrosion EXCLUDE_FROM_ALL)`.
- **Plonky3** sits at `third-party/plonky3-uno/` (commit `6374a36f`). Built as a sub-crate of `uno_plonky3_ffi`.

Refresh policy for the vendored trees is documented in their respective `README.uno.md` files.

## C++ Configure

Always use an out-of-source build:

```bash
cd /path/to/tos
rm -rf build-clang21
mkdir -p build-clang21
cd build-clang21

cmake .. \
  -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 \
  -DCMAKE_CXX_COMPILER=clang++-21
```

If you installed **liboqs to `$HOME/.local`** (Uno prereq Path B), prefix every configure call:

```bash
CMAKE_PREFIX_PATH="$HOME/.local" cmake .. \
  -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 \
  -DCMAKE_CXX_COMPILER=clang++-21
```

Look for these lines in the configure output to confirm the Uno wiring is live:

```
-- uno_workchain: found liboqs at /.../liboqs.a
-- uno_workchain: liboqs exposes OQS_KEM_ml_kem_768_keypair_derand
-- uno_workchain: Corrosion found — linking libuno_plonky3_ffi.a into uno_workchain
-- uno_workchain: using vendored avatar BLAKE3 at /.../third-party/avatar-crypto
```

If instead you see `liboqs not found — ML-KEM-768 built with UNO_MLKEM_STUB=1`, stop and fix the liboqs path before building — a stubbed ML-KEM will produce an otherwise-clean build whose runtime aborts on every Uno tx.

## C++ Build

This repository builds successfully with `clang-21`.

Example with fixed parallelism:

```bash
cd /path/to/tos/build-clang21
ninja -j128
```

If you want a machine-sized default:

```bash
JOBS=$(( $(nproc) * 2 / 3 ))
cd /path/to/tos/build-clang21
ninja -j"${JOBS}"
```

## C++ Test

List available tests:

```bash
cd /path/to/tos/build-clang21
ctest -N
```

Run the suite:

```bash
cd /path/to/tos/build-clang21
ctest --output-on-failure -j128
```

### Uno-specific test targets

The Uno workchain tests live under `uno/test/` and can be run individually when iterating:

```bash
cd /path/to/tos/build-clang21
ninja test-uno-primitive-parity \
      test-uno-mandatory-negatives \
      test-uno-end-to-end \
      test-uno-parallel-verify \
      test-uno-transfer \
      test-uno-codec-shapes \
      test-uno-public-input-fixture \
      test-uno-state-transition-golden \
      test-uno-restart-survival \
      test-uno-determinism \
      test-uno-filter

# Run individually (each prints its own pass / fail / skip summary):
./uno/test/test-uno-primitive-parity
./uno/test/test-uno-mandatory-negatives
./uno/test/test-uno-end-to-end
./uno/test/test-uno-parallel-verify
```

If `liboqs` was installed to `$HOME/.local`, the test binaries also need the prefix at runtime for some paths — it's easier to just prefix `CMAKE_PREFIX_PATH` at both configure and run time:

```bash
CMAKE_PREFIX_PATH="$HOME/.local" ./uno/test/test-uno-primitive-parity
```

The Rust-side FFI crate has its own test suite:

```bash
cd /path/to/tos/uno/plonky3-ffi
cargo test --release --lib
# Expected: 43 passed; 0 failed; 0 ignored
```

The tosctl wallet crate (`P.6`) is a separate workspace:

```bash
cd /path/to/tos/tosctl/uno
cargo test --release
# Expected: 44 lib + 4 send_roundtrip + 1 derive_keys = 49 passed
```

Or:

```bash
JOBS=$(( $(nproc) * 2 / 3 ))
cd /path/to/tos/build-clang21
ctest --output-on-failure -j"${JOBS}"
```

## Rust Toolchain

Install Rust with `rustup` if needed:

```bash
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
```

Use the workspace-pinned toolchain:

```bash
cd /path/to/tos/tosctl/src
rustup show
cargo --version
rustc --version
```

If the pinned toolchain is not present yet:

```bash
cd /path/to/tos/tosctl/src
rustup toolchain install 1.91.1
rustup component add clippy --toolchain 1.91.1
```

## Rust Build

Build the full Rust workspace:

```bash
cd /path/to/tos/tosctl/src
cargo build --workspace
```

Build a specific crate when iterating faster:

```bash
cd /path/to/tos/tosctl/src
cargo build -p tosctl
cargo build -p tos_executor
```

Build optimized artifacts:

```bash
cd /path/to/tos/tosctl/src
cargo build --workspace --release
```

## Rust Test

Run the workspace test suite:

```bash
cd /path/to/tos/tosctl/src
cargo test --workspace
```

Run a narrower crate test cycle:

```bash
cd /path/to/tos/tosctl/src
cargo test -p tosctl
cargo test -p tos_executor
```

Lint with the pinned toolchain:

```bash
cd /path/to/tos/tosctl/src
cargo clippy --workspace --all-targets
```

## Recommended Build Order

If you are setting up a fresh development machine, the practical order is:

1. Install the native Linux dependencies and `clang-21`.
2. Install Rust via `rustup` (required for Uno's Plonky3 FFI — even if you only care about the C++ side).
3. Install **liboqs** at the pinned commit (see the Uno Workchain prerequisites above). Pick `/usr/local` if you have sudo, otherwise `$HOME/.local`.
4. Configure and build the top-level C++ tree. Pass `CMAKE_PREFIX_PATH="$HOME/.local"` at configure time if you chose the user-local liboqs path.
5. Build the Rust workspace in `tosctl/src`.
6. Run `ctest` for the C++ side and `cargo test --workspace` for the Rust side.
7. Run the Uno-specific test binaries (`test-uno-*`) and the Rust FFI crate tests (`cd uno/plonky3-ffi && cargo test --release --lib`).

This keeps both halves of the repository healthy and catches cross-surface breakage early.

## Optional Nix Build Paths

This tree also contains Nix-based build helpers under:

- `assembly/nix/build-linux-x86-64-nix.sh`
- `assembly/nix/build-linux-arm64-nix.sh`
- `assembly/nix/build-macos-nix.sh`
- `assembly/nix/flakes/`

Use those when you want a more reproducible environment or platform-specific packaging path. The default developer flow in this repository remains:

- C++ via top-level `CMake` + `Ninja`
- Rust via `cargo` in `tosctl/src`

## Verified Native Result

The following native C++ flow was verified successfully in this repository:

```bash
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21
ninja -j128
ctest --output-on-failure -j128
```

Observed result:

- Build: success
- Tests: `31/31` passed

## Notes

- The native C++ build downloads or builds several bundled dependencies from `third-party/` during configuration and compilation.
- `clang-14` was not sufficient for this tree; `clang-21` was used for the verified native build.
- The Rust workspace is not a small auxiliary tool anymore; treat it as a first-class build surface of the repository.
- If you have already modified branding, file names, or generated libraries in the source tree, keep include paths, generated artifacts, and tool names consistent before rebuilding.

## Troubleshooting

### `ninja: error: 'third-party/zlib/lib/libz.a', needed by ...`

After a `rm -rf build` on some CMake caches the zlib path resolves to a stale in-tree build dir that was never populated. Rebuild zlib via system package and re-point CMake at it:

```bash
sudo apt install -y zlib1g-dev
rm -rf build-clang21
cmake -S . -B build-clang21 \
      -DZLIB_LIBRARY=/usr/lib/x86_64-linux-gnu/libz.so \
      -DZLIB_INCLUDE_DIR=/usr/include \
      ...
```

### `undefined reference to 'uno_plonky3_abi_version' / 'uno_plonky3_verify' / 'uno_poseidon2_goldilocks_permute_t8'`

The Rust FFI crate was not linked into `uno_workchain`. Causes:

- `third-party/corrosion/` missing or broken → configure output will show `Corrosion not found`. Re-clone the submodule or re-vendor per `third-party/corrosion/README.uno.md`.
- Rust toolchain not installed → `cmake` configure succeeds but `ninja` fails at the cargo-build step. Install rustup.

### `uno_workchain: liboqs not found — ML-KEM-768 built with UNO_MLKEM_STUB=1`

liboqs is not installed or CMake cannot find it. Either install to `/usr/local` (sudo) or install to `$HOME/.local` and pass `CMAKE_PREFIX_PATH="$HOME/.local"` at configure time. See the Uno Workchain prerequisites above.

### Test binary aborts with "FFI symbol `uno_poseidon2_goldilocks_permute_t8` not linked"

The binary was built against the weak-symbol fallback in `uno/crypto/poseidon2.cpp` because corrosion wasn't active when CMake configured. Re-configure from a clean `build/` directory after confirming the Rust toolchain and `third-party/corrosion/` are in place.
