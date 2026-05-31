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

That env var tells CMake to add `$HOME/.local/{include,lib}` to the `find_path` / `find_library` search roots — without it the configure step will abort with a `FATAL_ERROR`.

> **Warning:** If you omit `CMAKE_PREFIX_PATH` (or liboqs is otherwise not found), CMake will **abort configuration** with:
> ```
> CMake Error: uno_workchain: liboqs is required for production validator builds but was
> not found. Install liboqs-dev or build from source (see uno/crypto/LIBOQS_VERSION.md)
> and re-configure with -DLIBOQS_INCLUDE_DIR=<prefix>/include
> -DLIBOQS_LIBRARY=<prefix>/lib/liboqs.a.
> If you are knowingly building a non-production binary that does not need real ML-KEM
> (e.g. an early skeleton-build CI job), pass -DTOS_DEV_STUBS=ON to fall back to a
> runtime-abort stub instead.
> ```
> Fix the liboqs path (see above) before re-running CMake. A build that silently omits
> real ML-KEM is not possible without an explicit `-DTOS_DEV_STUBS=ON` opt-in.

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

## JVM Workchain (wc=3) — Additional Prerequisites

The wc=3 Avata JVM workchain is included in a normal validator build: the
top-level `CMakeLists.txt` adds `add_subdirectory(jvm)` for every build except
`TOS_ONLY_TOSLIB`, and `jvm/avata/CMakeLists.txt` is a CMake bridge that drives
the Avata fork's own makefile to produce the interpreter static library
(`libavata.a`). That bridge needs `make`/`gmake` (already required by the C++
build) — the **JVM C++ core itself adds no new package dependency** beyond the
standard validator toolchain.

What *does* need an extra tool is the **runtime archive `rt.jar` (and `api.jar`)**.
These are loaded by the interpreter at runtime as its boot classpath
(`jvm/core/init.cpp` → `TOS_AVATA_DEFAULT_RT_JAR`) and are **not checked into
git** — `jvm/avata/build/` is `.gitignore`d, so a fresh checkout has no jars.
The Avata makefile builds them from the Java sources under `jvm/avata/rt/`,
which requires a **Java 8 JDK** (`javac`; the makefile detects the host JDK and
defaults to `java-version := 8`).

You need the JDK if you want to:

- **run a wc=3-capable node** (the interpreter needs `rt.jar` at startup), or
- **run the JVM test targets**, or
- **verify reproducibility / pin `stdlib_hash` for wc=3 activation.**

```bash
# Debian/Ubuntu
sudo apt-get install -y openjdk-8-jdk-headless

# The CMake build regenerates the jars on demand; to build them directly:
make -C jvm/avata platform=linux arch=x86_64 process=interpret mode=fast \
  build/linux-x86_64/rt.jar
```

> **Reproducible `stdlib_hash`.** The consensus-binding runtime hash is only
> byte-stable on the pinned canonical toolchain — **Ubuntu 22.04 +
> `openjdk-8-jdk-headless`** (enforced by
> `.github/workflows/check-jvm-rt-determinism.yml` and
> `jvm/avata/Dockerfile.canonical-build`). `javac` output varies by JDK
> vendor/version, so a different JDK builds a *runnable* `rt.jar` that will
> **not** reproduce the canonical hash
> `ae4ff3b7e557a8acffe31e9b41959e811c67dea87b6c6c3e38129466e5ade765`. See
> [`doc/jvm/jvm-rt-reproducibility.md`](doc/jvm/jvm-rt-reproducibility.md) for the
> canonical build and [`scripts/jvm-testnet-genesis-rehearsal.sh`](scripts/jvm-testnet-genesis-rehearsal.sh)
> for an end-to-end jar-build + hash + zerostate rehearsal.

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

If liboqs is not found, CMake will abort with a `FATAL_ERROR` — configure will not succeed without it. Fix the liboqs path and re-run CMake.

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

## macOS Native Build (Apple Silicon)

The Linux prerequisites and Uno workchain prerequisites described above also apply on macOS, but the toolchain selection and a few environment details differ. The flow below mirrors `assembly/native/build-macos-shared.sh` and is the path used in CI.

### Verified macOS environment

- OS: macOS 26.4.1 (Darwin 25.4.0), Apple Silicon (M2, arm64), 16 GB RAM
- Xcode SDK: `MacOSX26.4.sdk`
- Compiler: Apple clang resolved via `xcrun --find clang(++)` — **not** Homebrew `llvm@21`
- Build system: `cmake` 3.29 + `ninja` 1.13

On macOS 15 and newer (which includes macOS 26.x), `assembly/native/build-macos-shared.sh` deliberately switches from Homebrew `llvm@21` to AppleClang. The Xcode toolchain links cleanly against the system SDK and avoids `libc++` divergence between two LLVM copies in the same binary.

### macOS Prerequisites

Install the Xcode command-line tools and the supporting Homebrew formulas:

```bash
xcode-select --install   # if not already installed

brew install \
  cmake \
  ninja \
  pkg-config \
  automake \
  autoconf \
  libtool \
  gnutls \
  gmp \
  secp256k1 \
  zstd \
  lz4 \
  readline
```

The bundled `third-party/openssl` is built in-tree by the top-level CMake against a pinned `enable-quic` configuration, so do **not** rely on Homebrew `openssl@3` for the QUIC path — `ngtcp2` links against the in-tree archive.

### Critical PATH ordering

On a typical Homebrew install, `/opt/homebrew/opt/binutils/bin` precedes `/usr/bin` in `PATH`. This puts GNU `ar`, `ranlib`, and `nm` from `binutils 2.45+` ahead of Apple's BSD-format equivalents.

**This breaks the macOS build.** The in-tree OpenSSL `Configure` script does not pin `AR` / `RANLIB`, so it picks up GNU `ar`. The resulting `libssl.a` and `libcrypto.a` use the GNU long-filename-table `/` extended-name member, which Apple's `ld64` cannot link, surfacing as:

```
ld: archive member '/' not a mach-o file in '.../third-party/openssl/lib/libssl.a'
```

That in turn fails the `ngtcp2` configure-time `check_symbol_exists(SSL_set_quic_tls_cbs ...)` link probe with the misleading top-level error:

```
Unable to build OpenSSL backend due to lack of QUIC support in
  .../third-party/openssl/lib/libssl.a;.../third-party/openssl/lib/libcrypto.a
```

Fix: ensure `/usr/bin` precedes any `binutils` directory **for the entire build session**, before invoking `cmake`:

```bash
export PATH="/usr/bin:$PATH"
which ar ranlib nm   # all three must resolve under /usr/bin
```

Apple's `ar` produces BSD-format archives that `ld64` accepts.

### liboqs on macOS

`uno_workchain` requires `liboqs` at the commit pinned in `uno/crypto/LIBOQS_VERSION.md`. Install to `$HOME/.local` (Path B from the Uno Workchain prerequisites above):

```bash
git clone https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs-src
cd /tmp/liboqs-src
git checkout 3cb781fd4737c900ad755ee0bb9e1949d0f68955

PATH="/usr/bin:$PATH" cmake -S . -B /tmp/liboqs-build \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_ENABLE_KEM_ML_KEM=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_INSTALL_PREFIX="$HOME/.local" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$(xcrun --find clang)"

PATH="/usr/bin:$PATH" cmake --build /tmp/liboqs-build -j 8
PATH="/usr/bin:$PATH" cmake --install /tmp/liboqs-build

test -f "$HOME/.local/lib/liboqs.a"            # ~14 MB
test -f "$HOME/.local/include/oqs/oqs.h"
```

The `PATH` prefix is required during this phase too — liboqs's CMake build also picks `ar`/`ranlib` from `PATH`.

### Rust toolchain on macOS

Identical to the Linux flow — install `rustup`, the workspace pins `1.91.1` via `tosctl/src/rust-toolchain.toml`. The Corrosion-driven `uno/plonky3-ffi` crate rides the same pin.

```bash
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
```

### macOS Configure

```bash
cd /path/to/tos
rm -rf build && mkdir build && cd build

export PATH="/usr/bin:$PATH"
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
export CC="$(xcrun --find clang)"
export CXX="$(xcrun --find clang++)"
export CCACHE_DISABLE=1

CMAKE_PREFIX_PATH="$HOME/.local" cmake -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_FLAGS="-nostdinc++ -isystem ${SDKROOT}/usr/include/c++/v1 -isystem ${SDKROOT}/usr/include" \
  -DCMAKE_SYSROOT="${SDKROOT}" \
  -DCMAKE_INSTALL_PREFIX="$(pwd)/install" \
  ..
```

The `-nostdinc++ -isystem ${SDKROOT}/usr/include/c++/v1` pair forces the build to use the SDK's `libc++`, neutralizing any stray Homebrew LLVM `libc++` headers that may otherwise leak in via `pkg-config` paths.

Look for these confirmation lines:

```
-- uno_workchain: found liboqs at /Users/.../.local/lib/liboqs.a
-- uno_workchain: liboqs exposes OQS_KEM_ml_kem_768_keypair_derand
-- uno_workchain: liboqs exposes OQS_KEM_ml_kem_768_encaps_derand
-- uno_workchain: Corrosion found — linking libuno_plonky3_ffi.a into uno_workchain
-- uno_workchain: using vendored avatar BLAKE3 at .../third-party/avatar-crypto
-- Found BLAS: .../Accelerate.framework
```

`Accelerate.framework` is Apple's BLAS implementation; it satisfies `silkworm-core`'s BLAS dependency without `libblas-dev`.

Two informational messages on macOS that are **not** errors:

- `Could NOT find Readline (this is NOT an error)` — the lite-client REPL falls back to a built-in line editor.
- `Could NOT find ccache` — only matters if you opted into ccache.

### macOS Build

The verified target list mirrors `assembly/native/build-macos-shared.sh`:

```bash
ninja \
  storage-daemon storage-daemon-cli blockchain-explorer \
  toslib toslibjson toslib-cli \
  validator-engine validator-engine-console \
  func tol fift \
  lite-client \
  generate-random-id json2tlo \
  dht-server dht-ping-servers dht-resolve \
  http-proxy rldp-http-proxy adnl-proxy \
  create-state create-hardfork tlbc \
  emulator proxy-liteserver
```

For a smoke check, build the keystone target alone — it transitively pulls in essentially the whole C++ tree (OpenSSL, ngtcp2, abseil, libff, evmone, silkworm-core, Plonky3 FFI, uno_workchain):

```bash
ninja validator-engine
```

Reference timing on M2 (8 physical cores, 16 GB):

| Step | Wall time |
|---|---:|
| `cmake` configure | ~45 s |
| `ninja validator-engine` (1239 nodes) | ~7 min |

Two link-time warnings to expect, both harmless:

- `ld: warning: ignoring duplicate libraries: ...` — CMake emits the same archive on multiple link lines; `ld64` deduplicates.
- `ld: warning: object file (...blake3_neon.o) was built for newer 'macOS' version (26.4) than being linked (26.0)` — the BLAKE3 NEON object inherits the SDK target while the parent target uses an older `OSX_TARGET`. Cosmetic.

### macOS Test

```bash
cd /path/to/tos/build
ctest --output-on-failure -j 8
```

The Uno test binaries also work without further env tweaks because `liboqs` is statically linked from `$HOME/.local/lib/liboqs.a` at build time:

```bash
./uno/test/test-uno-primitive-parity
./uno/test/test-uno-mandatory-negatives
./uno/test/test-uno-end-to-end
./uno/test/test-uno-parallel-verify
```

### Optional: drive the canonical script

`assembly/native/build-macos-shared.sh` automates everything above except the `PATH` fix and the `liboqs` install. After installing `liboqs` to `$HOME/.local` and prefixing `/usr/bin` on `PATH`, the script can be invoked directly:

```bash
PATH="/usr/bin:$PATH" CMAKE_PREFIX_PATH="$HOME/.local" \
  bash assembly/native/build-macos-shared.sh
```

Add `-t` to extend the target list with `all-tests`, `-a` to copy the deployable binaries into `./artifacts/`, or `-c` to enable `ccache`.

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

The macOS native flow has also been verified end-to-end:

```bash
export PATH="/usr/bin:$PATH"
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
CMAKE_PREFIX_PATH="$HOME/.local" cmake -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$(xcrun --find clang)" \
  -DCMAKE_CXX_COMPILER="$(xcrun --find clang++)" \
  -DCMAKE_CXX_FLAGS="-nostdinc++ -isystem ${SDKROOT}/usr/include/c++/v1 -isystem ${SDKROOT}/usr/include" \
  -DCMAKE_SYSROOT="${SDKROOT}" ..
ninja validator-engine
```

Observed result on macOS 26.4.1, Apple Silicon (M2, 8 cores):

- Configure: success in ~45 s
- Build: success in ~7 min, producing a 35 MB `validator-engine/validator-engine` Mach-O arm64 binary that runs `--help` cleanly

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

### CMake FATAL_ERROR: `liboqs is required for production validator builds but was not found`

liboqs is not installed or CMake cannot find it. Either install to `/usr/local` (sudo) or install to `$HOME/.local` and pass `CMAKE_PREFIX_PATH="$HOME/.local"` at configure time. See the Uno Workchain prerequisites above.

CMake will refuse to proceed without liboqs — the configure step aborts immediately. There is no silent fallback. If you are intentionally building a non-production binary without real ML-KEM (e.g. a skeleton CI job), pass `-DTOS_DEV_STUBS=ON` explicitly; see the warning in `uno/CMakeLists.txt` for the runtime consequences.

### Test binary aborts with "FFI symbol `uno_poseidon2_goldilocks_permute_t8` not linked"

The binary was built against the weak-symbol fallback in `uno/crypto/poseidon2.cpp` because corrosion wasn't active when CMake configured. Re-configure from a clean `build/` directory after confirming the Rust toolchain and `third-party/corrosion/` are in place.

### `ld: archive member '/' not a mach-o file in '.../libssl.a'` (macOS only)

The in-tree OpenSSL build was linked with GNU `ar` from Homebrew `binutils` instead of Apple's `ar`. The resulting GNU-format archive carries a `/` extended-name-table member that `ld64` rejects. This typically surfaces as the misleading `ngtcp2` error `Unable to build OpenSSL backend due to lack of QUIC support` at configure time.

Fix: prepend `/usr/bin` to `PATH` before invoking CMake configure, so OpenSSL's `Configure` script picks Apple's `ar`/`ranlib`:

```bash
rm -rf build
PATH="/usr/bin:$PATH" cmake -S . -B build ...
```

The `PATH` override must be in effect during the OpenSSL build phase (configure-time `execute_process`), not just at link time. See the **macOS Native Build → Critical PATH ordering** section above.

### `Unable to build OpenSSL backend due to lack of QUIC support in ...` (macOS only)

Almost always the same root cause as the previous entry — Apple `ld64` cannot link the GNU-format `libssl.a`, so `check_symbol_exists(SSL_set_quic_tls_cbs ...)` fails its link probe. Verify via:

```bash
nm /Users/.../build/third-party/openssl/lib/libssl.a | grep SSL_set_quic_tls_cbs
```

If the symbol is present in the archive but the link probe still fails, the issue is the archive format, not missing QUIC support. Apply the `PATH="/usr/bin:$PATH"` fix above.
