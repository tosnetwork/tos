# Build

This repository has two build surfaces:

- C++/CMake/Ninja for the node, networking, native execution, and tooling
- Rust/Cargo under `tosctl/src` for operator tooling and Rust-side libraries

The current build focuses on the native TVM execution surface for actor-based applications.

## Supported Platforms

The node and its tools are built, tested in CI and released for Linux only, on
x86-64 and arm64. There are no Windows or WebAssembly builds, build scripts or
release artifacts, and no macOS or Android release artifacts.

Android covers toslib only, not the node: see
[Android toslib Build](#android-toslib-build).

macOS on Apple silicon is built from source: see
[macOS Development Build](#macos-development-build). It can run a node and a
validator ([macOS validators](doc/Validator.md#macos-validators)). CI builds
and tests it on every pull request and push to `main`
(`.github/workflows/build-tos-macos-15-arm64-shared.yml`), but it is not
released.

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

## Android toslib Build

`example/android/build.sh` builds toslib for Android as a JNI library,
`libnative-lib.so`, for `arm64-v8a`, `armeabi-v7a`, `x86_64` and `x86` (or the
ABIs named on its command line), at API level 24, with the NDK that
`ANDROID_NDK_ROOT` names. It needs the [Linux prerequisites](#linux-prerequisites)
or a macOS development host, a JDK and Ninja:

```bash
ANDROID_NDK_ROOT=/path/to/android-ndk example/android/build.sh
test/android/run-jvm-smoke.sh
```

A cross build cannot run the generators, so the script first builds
`example/android` for the host. That build generates the TL, TL-B and contract
sources and the Java API, `src/org/tos/toslib/TosApi.java`, and its own
`libnative-lib` is what `test/android/run-jvm-smoke.sh` loads in a desktop JVM
to check the binding: synchronous and asynchronous requests, object
conversion in both directions, and `Client.close()`. The result is
`example/android/toslib-android/`: `libs/<ABI>/libnative-lib.so`, stripped;
`src/` with `org/tos/toslib/Client.java` and `TosApi.java`, which an app
compiles with its own sources; and `BUILD-INFO` with the commit, the NDK
version and each file's SHA-256. The Java package is `org.tos.toslib`.

`.github/workflows/build-toslib-android.yml` runs both on every pull request
and push to `main` with NDK r27d (27.3.13750724), checks each library's ELF
machine and its exported `JNI_OnLoad`, and keeps the result as the
`toslib-android` workflow artifact. It is not a release asset.

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
