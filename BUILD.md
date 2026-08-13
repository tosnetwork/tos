# Build

This repository has two build surfaces:

- C++/CMake/Ninja for the node, networking, native execution, and tooling
- Rust/Cargo under `tosctl/src` for operator tooling and Rust-side libraries

The current build focuses on the native TVM execution surface for actor-based applications.

## Linux Prerequisites

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

## C++ Configure

Always use an out-of-source build:

```bash
cmake -S . -B build-clang21 \
  -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 \
  -DCMAKE_CXX_COMPILER=clang++-21
```

## C++ Build

```bash
cmake --build build-clang21 --target validator-engine create-state -j"$(nproc)"
```

Common targets:

- `validator-engine`
- `create-state`
- `fift`
- `func`
- `lite-client`
- `validator-engine-console`

FunC and Fift intermediates are generated only under the CMake build tree:

```text
build-clang21/crypto/smartcont/auto/
```

The source tree must remain unchanged after a build. Files below
`crypto/smartcont/auto/` are not source or release artifacts and must never be
committed. Canonical contract releases consist of the `.fc` source, a frozen
BOC, its hashes, and a release manifest.

## Rust Workspace

The Rust workspace root is:

```bash
tosctl/src/Cargo.toml
```

The repository-wide pinned toolchain is declared in:

```bash
rust-toolchain.toml
```

Build from the workspace root:

```bash
cd tosctl/src
cargo build
```

The repository pins Rust 1.97.1, including rustfmt and Clippy. The root-level
file applies even when Cargo is invoked with `--manifest-path`. Do not override
it with `+stable`, `+nightly`, or an IDE-specific toolchain. Use the canonical
formatting targets:

```bash
make fmt
make fmt-check
```

`fmt-check` is non-mutating and is enforced in CI. The root-level
`rustfmt.toml` applies one stable-only policy to the main workspace and every
standalone repository-owned Cargo project. Vendored and generated sources are
not reformatted as if they were hand-maintained source.
