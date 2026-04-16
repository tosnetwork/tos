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
2. Configure and build the top-level C++ tree.
3. Install Rust via `rustup`.
4. Build the Rust workspace in `tosctl/src`.
5. Run `ctest` for the C++ side and `cargo test --workspace` for the Rust side.

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
