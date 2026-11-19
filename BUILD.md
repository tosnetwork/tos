# Build

This repository has two build surfaces:

- C++/CMake/Ninja for the node, networking, native execution, and tooling
- Rust/Cargo under `tosctl/src` for operator tooling and Rust-side libraries

The current build focuses on the native TVM execution surface for actor-based applications.

## Supported Platforms

The node and its tools are built, tested in CI and released for Linux on
x86-64 and arm64. There are no Android or WebAssembly builds, build scripts or
release artifacts, and no Windows release artifacts.

Windows x86-64 builds the client tools from source, not the node: see
[Windows Build](#windows-build).

macOS on Apple silicon is built from source: see
[macOS Development Build](#macos-development-build). It can run a node and a
validator ([macOS validators](doc/Validator.md#macos-validators)). CI builds
and tests it on every pull request and push to `main`
(`.github/workflows/build-tos-macos-15-arm64-shared.yml`).
`.github/workflows/build-tos-macos-15-arm64-release.yml` packages the same
build for release on every version tag, with
`assembly/native/build-macos-release.sh`: Release, Apple clang, `apple-m1`,
minimum macOS 15.0, the system allocator, and only libraries macOS itself
provides. Its artifact `tos-arm64-macos` joins the release once that workflow
has succeeded on a tag ([release policy](doc/tos-release-policy.md)); until
then there are no macOS release assets.

One exception is not a node platform: `.github/workflows/quantum-mobile-native.yml`
also runs on macOS. It compiles and runs the post-quantum native C API in
`sdk/native/quantum` and the fee-state library behind its C state API, which
the iOS wallet vendors, with Apple's toolchain.

## Linux Prerequisites

Ubuntu 24.04 is the build and release baseline. CI, the builder image, the
node container image and the release binaries are all built on 24.04, so the
released binaries need glibc 2.39 or newer and do not run on Ubuntu 22.04.

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

## macOS Development Build

For Apple silicon, including a validator host. `assembly/native/build-macos-shared.sh -t`
runs the steps below, as CI does. Every third-party library is built from
`third-party/`, so Homebrew provides only the build tools:

```bash
xcode-select --install   # or a full Xcode
brew install cmake ninja pkg-config autoconf automake libtool
brew install ripgrep     # for the tests: the source-guard checks search with it
```

Build with Apple clang and the macOS SDK. Homebrew's GNU `ar` (binutils) writes
archives Apple's linker rejects, and Homebrew LLVM fails the QUIC library's
OpenSSL probe, so keep both off `PATH` for configure and build:

```bash
export PATH="$(echo "$PATH" | tr ':' '\n' | grep -v -E 'binutils|llvm|coreutils' | paste -sd: -)"
export PATH="/usr/bin:$PATH"
cmake -S . -B build-macos -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=/usr/bin/clang \
  -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
  -DCMAKE_SYSROOT="$(xcrun --show-sdk-path)"
cmake --build build-macos -j"$(sysctl -n hw.ncpu)"
```

`CMAKE_SYSROOT` is stored in the cache; after an Xcode upgrade that removes the
SDK it names, configure again with the new path. A local network runs from this
build with `TOS_BUILD_DIR=$PWD/build-macos` and `scripts/localnet-jsonrpc.py`.

Differences from Linux, by design:

- The SLH-DSA verifier uses the ARMv8 SHA2 backend, as on Linux arm64; the
  configure output prints `TOS_SLHDSA_ARMV8_SHA2=ON`. A build directory
  configured before this backend was available keeps `OFF` in its cache;
  configure it again with `-DTOS_SLHDSA_ARMV8_SHA2=ON`.
- The conformance reference library needs GNU ld's `--wrap` and is not built.
- File durability uses `F_FULLFSYNC`, birth time comes from `stat`, and the
  node data tools read process descriptors through libproc instead of `/proc`.
- The `native` feature of `node-data-sync` runs the database engine in a
  Linux sandbox (network namespace, bind mounts, parent-death signal) and is
  built on Linux only; its default features build and pass on macOS.
- Run Rust tests with `TMPDIR=/private/tmp`: the default macOS temporary
  directory is reached through the `/var` symlink and is not root-owned, and
  the node data tools refuse such a path.

Run the C++ tests without the ones macOS cannot host:

```bash
cd build-macos
TMPDIR=/private/tmp ctest -j"$(sysctl -n hw.ncpu)" -LE 'linux-only|loopback-aliases|gnu-tools|macos-known-failure'
```

CI aliases the loopback sources and runs the `loopback-aliases` tests too, serially:
`ctest --timeout 1800 -LE 'linux-only|gnu-tools|macos-known-failure'`.

The labels mark tests that macOS cannot host, not failures of the code they test:

- `linux-only`: the harness reads `/proc`, uses `LD_PRELOAD`, or drives a Linux
  container entrypoint.
- `loopback-aliases`: the test binds sources such as `127.0.0.2`. Linux routes
  all of `127.0.0.0/8`; macOS needs an alias for each, which lasts until
  reboot. QUIC admission uses `127.0.0.2` to `127.0.0.39`:
  `for i in $(seq 2 39); do sudo ifconfig lo0 alias 127.0.0.$i up; done`.
- `gnu-tools`: the test needs GNU grep (`grep -P`) or `flock(1)`.
- `macos-known-failure` (set on macOS only): the test's preconditions do not
  hold there. `test-http-server-limits` cannot pin loopback socket buffers as
  small as its slow-reader case requires, and `test-rldp2-decoder-heap` is
  calibrated against glibc's allocator, which rounds less than the macOS one.

## Windows Build

`assembly/native/build-windows-2022.bat` builds the client tools on Windows
x86-64 with clang-cl and lld-link from Visual Studio 2022: `lite-client`,
`validator-engine-console`, `storage-daemon-cli`, `blockchain-explorer`, `fift`,
`func`, `tol`, `toslib`, `toslibjson`, `toslib-cli`, `emulator`, `create-state`
and `json2tlo`. Every third-party library is built from `third-party\`.

Run it from the repository root in an "x64 Native Tools Command Prompt for VS
2022" with the Visual Studio "C++ Clang tools for Windows" component, ninja,
NASM and Perl on `PATH` (for example `choco install ninja nasm strawberryperl`):

```bat
assembly\native\build-windows-2022.bat
```

The output is in `build-windows\`. Nothing that links the node's own code is
built: not `validator-engine`, and not the programs that use its key store,
metrics or RLDP (`storage-daemon`, `dht-server`, `http-proxy`,
`rldp-http-proxy`, `proxy-liteserver`, `generate-random-id`, `tos-rpc`,
`tos-wallet-index`). That code relies on POSIX file semantics and is neither
ported nor compiled on Windows
([Windows](doc/Validator.md#windows)). CI builds the tools on every pull
request, every push to `main` and every version tag
(`.github/workflows/build-tos-windows-2022-x86-64.yml`), and
`assembly/native/package-windows.ps1` packages them into the artifact
`tos-x86-64-windows`: the tools, `smartcont\`, `lib\` and `BUILD-INFO`. The
package refuses a missing file, a tool whose `-V` does not report the commit,
and any DLL other than Windows' own, the Microsoft C/C++ runtime (the Visual
C++ 2015-2022 Redistributable, which a target machine needs) and the DLLs it
ships. The artifact joins the release once the workflow has succeeded on a tag
([release policy](doc/tos-release-policy.md)). `tosctl` is not part of the
Windows build.

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

The repository pins Rust 1.100.0, including rustfmt and Clippy. The root-level
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
