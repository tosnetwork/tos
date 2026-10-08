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

Install `clang-21` if it is not already available. The installer checks the
apt.llvm.org signing key committed in this repository instead of running a
downloaded script:

```bash
sudo scripts/install-llvm-toolchain.sh 21
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

The frozen-artifact rules run `scripts/embed-*.sh` with `bash` and the Python
that CMake found (`Python3_EXECUTABLE`). Both are configure-time requirements;
`TOS_BASH_EXECUTABLE` overrides the bash that is used.

## Compiler Selection

A configure that names no compiler picks `clang`/`clang++` from `PATH`. Any
explicit choice turns that off: `CMAKE_C_COMPILER`/`CMAKE_CXX_COMPILER`, `CC`/`CXX`
in the environment, or a toolchain file. On a Windows host nothing is picked;
the Windows scripts choose the compiler themselves.

## Client-Only Builds and Windows

`-DTOS_CLIENT_ONLY=ON` builds the client toolchain without the node: `fift`,
`func`, `tlbc`, `tol`, `lite-client`, `toslib`, `toslibjson`, `toslib-cli`, and
the `emulator` library, with their tests. Node targets are not defined in this
configuration, so asking for one (for example `--target validator-engine`) fails
as an unknown target. This covers the validator and its engine, the network
stack above ADNL lite, storage, the proxies, the consensus and controller key
tools, and the proof verifier.

Windows builds the client toolchain only. On Windows `TOS_CLIENT_ONLY` is on by
default, and an explicit `-DTOS_CLIENT_ONLY=OFF` stops the configure. The node's
key and configuration files depend on POSIX file semantics: owner checks,
`flock`, directory `fsync`, and no-follow opens. Those have not been ported to
Windows, and a node built on unported file handling is worse than no node. This
is a deliberate reduction from the upstream Windows scope. Running a node on
Windows would be a separate porting project. Validators run on Linux, and macOS
builds the full tree for development.

The Windows builds use:

- `assembly/native/build-windows-2022.bat`: clang-cl and lld-link from a Visual
  Studio 2022 developer prompt, with Git for Windows `bash` for the
  frozen-artifact rules
- `assembly/msys2/build-mingw64.sh` and `build-ucrt64.sh`: MSYS2 clang

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
