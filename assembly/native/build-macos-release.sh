#!/usr/bin/env bash
# Build the macOS release binaries for the architecture of the build host.
#
#   assembly/native/build-macos-release.sh <output dir> [jobs]
#
# Run from the root of a clean checkout of the commit to release, on macOS on
# Apple silicon or Intel with Xcode or the Command Line Tools. The recipe is the
# macOS build of BUILD.md (macOS Development Build) that CI tests, fixed for
# release:
#
#   Release, Apple clang with the selected macOS SDK, minimum macOS 15.0,
#   on Apple silicon TOS_ARCH = apple-m1 and RocksDB's PORTABLE = armv8-a,
#   on Intel TOS_ARCH and PORTABLE = x86-64-v2,
#   SOURCE_DATE_EPOCH = the commit time of HEAD, no compiler cache.
#
# The allocator is the system one. The macOS build and its CI run without
# jemalloc, so a macOS release built with it would not be the tested product.
# The fixed CPU level and minimum macOS keep the binaries from depending on the
# build host's CPU or operating system; every Mac of that architecture that
# runs macOS 15 or later can run them.
#
# The script refuses to finish unless the recipe is in effect: the configured
# cache holds these values and enables the architecture's hardware SHA-256
# backend, every Mach-O file it ships is built for that architecture alone,
# requires no macOS newer than 15.0, carries a valid
# signature and links only libraries under /usr/lib and /System/Library, and
# every binary with -V reports the commit it was built from.
#
# tosctl is built from the same commit in the same run, as the Linux node
# recipe builds it (assembly/native/build-node-binaries.sh):
#
#   cargo build --release --locked -p tosctl (in tosctl/src),
#   the Rust toolchain rust-toolchain.toml pins,
#   RUSTFLAGS = -C target-cpu at the same CPU level as the C++ build,
#   C sources of its dependencies compiled with Apple clang, no compiler wrapper.
#
# The output directory receives the node binaries, tosctl, the tools, the two
# libraries, the smartcont and lib directories the Fift tools read, and
# BUILD-INFO.

set -euo pipefail

die() { echo "build-macos-release: $*" >&2; exit 1; }

if [ $# -lt 1 ] || [ $# -gt 2 ]; then die "usage: $0 <output dir> [jobs]"; fi
OUT=$1
JOBS=${2:-$(sysctl -n hw.ncpu)}
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "jobs must be a positive integer"
[ "$(uname -s)" = Darwin ] || die "this script builds on macOS only"
if [ ! -f CMakeLists.txt ] || [ ! -d validator-engine ]; then die "run from the repository root"; fi
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "the checkout has local changes"
[ ! -e "$OUT" ] || die "$OUT already exists"

# The CPU level of each architecture, and the hardware SHA-256 backend its
# validators verify with (doc/Validator.md). apple-m1 is the baseline of every
# Apple silicon CPU; the top-level CMake file selects it on Apple silicon
# whatever TOS_ARCH says, so it is set here to be what the cache records.
# x86-64-v2 is the level the Intel CI build is fixed to. RocksDB reads its own
# level from PORTABLE.
case "$(uname -m)" in
  arm64)
    ARCH=arm64
    CPU=apple-m1
    ROCKSDB_CPU=armv8-a
    RUST_CPU=apple-m1
    SLHDSA_BACKEND=TOS_SLHDSA_ARMV8_SHA2
    ;;
  x86_64)
    ARCH=x86_64
    CPU=x86-64-v2
    ROCKSDB_CPU=x86-64-v2
    RUST_CPU=x86-64-v2
    SLHDSA_BACKEND=TOS_SLHDSA_SHA_NI
    ;;
  *) die "this script builds on arm64 or x86_64 only" ;;
esac
MACOS_MIN=15.0
REV=$(git rev-parse HEAD)
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export SOURCE_DATE_EPOCH
# The minimum macOS of every C, C++ and Rust object, read by clang, CMake,
# cargo and the cc crate alike.
export MACOSX_DEPLOYMENT_TARGET=$MACOS_MIN

# Homebrew's GNU ar (binutils) writes archives Apple's linker rejects, and
# Homebrew LLVM fails the QUIC library's OpenSSL probe: keep both, and GNU
# coreutils, off PATH, and put the system tools first.
PATH="$(echo "$PATH" | tr ':' '\n' | grep -v -E 'binutils|llvm|coreutils' | paste -sd: -)"
export PATH="/usr/bin:$PATH"
SDKROOT=$(xcrun --sdk macosx --show-sdk-path)
[ -d "$SDKROOT" ] || die "no macOS SDK"
export SDKROOT
CC=$(xcrun --find clang)
CXX=$(xcrun --find clang++)

# The Rust toolchain is checked before the long C++ build, so a host without
# the pinned one fails at once. RUSTC and its siblings would let another
# compiler stand in for the one checked here.
unset RUSTC CARGO_BUILD_RUSTC RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER
RUST_CHANNEL=$(awk -F'"' '/^channel[[:space:]]*=/ { print $2; exit }' rust-toolchain.toml)
[ -n "$RUST_CHANNEL" ] || die "rust-toolchain.toml pins no channel"
RUSTC_VERSION=$(cd tosctl/src && rustc --version)
CARGO_VERSION=$(cd tosctl/src && cargo --version)
[[ "$RUSTC_VERSION" == "rustc $RUST_CHANNEL "* ]] || die "rustc is '$RUSTC_VERSION', not the pinned $RUST_CHANNEL"
[[ "$CARGO_VERSION" == "cargo $RUST_CHANNEL "* ]] || die "cargo is '$CARGO_VERSION', not the pinned $RUST_CHANNEL"

# No compiler cache: a release binary is compiled from source, never taken
# from objects another run left behind.
export CCACHE_DISABLE=1
# The SHA-256 backend switches take their defaults from variables of the same
# names, in the CMake and the Cargo build alike; a release uses the defaults.
unset TOS_SLHDSA_SHA_NI TOS_SLHDSA_ARMV8_SHA2

# The shipped files, each as "<name>=<path in the build directory>". The node
# binaries are those of the Linux node recipe.
NODE_FILES=(
  validator-engine=validator-engine/validator-engine
  validator-engine-console=validator-engine-console/validator-engine-console
  lite-client=lite-client/lite-client
  generate-random-id=utils/generate-random-id
  tos-pq-consensus-key=crypto/pq/tos-pq-consensus-key
  dht-server=dht-server/dht-server
  tos-rpc=services/tos-rpc
  tos-wallet-index=services/tos-wallet-index
)
TOOL_FILES=(
  fift=crypto/fift
  func=crypto/func
  tol=tol/tol
  proxy-liteserver=utils/proxy-liteserver
  rldp-http-proxy=rldp-http-proxy/rldp-http-proxy
  http-proxy=http/http-proxy
  storage-daemon=storage/storage-daemon/storage-daemon
  storage-daemon-cli=storage/storage-daemon/storage-daemon-cli
  toslib-cli=toslib/toslib-cli
  tos-pq-vote=crypto/tos-pq-vote
  libtoslibjson.dylib=toslib/libtoslibjson.0.5.dylib
  libemulator.dylib=emulator/libemulator.dylib
)
# The ninja targets behind them; tos-pq-key is a separate CMake project below.
TARGETS=(validator-engine validator-engine-console lite-client generate-random-id
         tos-pq-consensus-key dht-server tos-rpc tos-wallet-index
         fift func tol proxy-liteserver rldp-http-proxy http-proxy storage-daemon
         storage-daemon-cli toslib-cli tos-pq-vote toslibjson emulator)
# The binaries with a -V option that prints the commit.
VERSIONED_TARGETS=(validator-engine validator-engine-console lite-client generate-random-id
                   dht-server fift storage-daemon)

BUILD=build-macos-release
rm -rf "$BUILD"

cmake -S . -B "$BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" -DCMAKE_SYSROOT="$SDKROOT" \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH" -DCMAKE_OSX_DEPLOYMENT_TARGET="$MACOS_MIN" \
  -DTOS_ARCH="$CPU" -DPORTABLE="$ROCKSDB_CPU" \
  -DTOS_USE_JEMALLOC=OFF
cmake --build "$BUILD" --parallel "$JOBS" --target "${TARGETS[@]}"

# The post-quantum key tool is a separate CMake project, so its signer stays out
# of every node target's link graph. It links the static OpenSSL the main build
# just produced and therefore needs no system libcrypto.
cmake -S crypto/pq/tools -B "$BUILD/pq-key" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" -DCMAKE_SYSROOT="$SDKROOT" \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH" -DCMAKE_OSX_DEPLOYMENT_TARGET="$MACOS_MIN" \
  -DOPENSSL_ROOT_DIR="$PWD/$BUILD/third-party/openssl" -DOPENSSL_USE_STATIC_LIBS=TRUE
cmake --build "$BUILD/pq-key" --parallel "$JOBS" --target tos-pq-key
TOOL_FILES+=(tos-pq-key=pq-key/tos-pq-key)

# The recipe, read back from what CMake configured.
cached() {
  awk -v key="$1" 'index($0, key ":") == 1 { sub(/^[^=]*=/, ""); print; exit }' "$BUILD/CMakeCache.txt"
}
[ "$(cached CMAKE_BUILD_TYPE)" = Release ] || die "CMAKE_BUILD_TYPE is not Release"
[ "$(cached TOS_ARCH)" = "$CPU" ] || die "TOS_ARCH is not $CPU"
[ "$(cached PORTABLE)" = "$ROCKSDB_CPU" ] || die "PORTABLE is not $ROCKSDB_CPU"
[ "$(cached CMAKE_OSX_DEPLOYMENT_TARGET)" = "$MACOS_MIN" ] || die "CMAKE_OSX_DEPLOYMENT_TARGET is not $MACOS_MIN"
[ "$(cached CMAKE_OSX_ARCHITECTURES)" = "$ARCH" ] || die "CMAKE_OSX_ARCHITECTURES is not $ARCH"
[ "$(cached CMAKE_CXX_COMPILER)" = "$CXX" ] || die "the C++ compiler is not Apple clang++"
[ "$(cached TOS_USE_JEMALLOC)" = OFF ] || die "TOS_USE_JEMALLOC is not OFF"
# The SLH-DSA check is priced for a hardware SHA-256 backend (doc/Validator.md).
# A node binary built without it would verify with the portable backend on
# every CPU, so it is not a validator's binary.
[ "$(cached "$SLHDSA_BACKEND")" = ON ] || die "$SLHDSA_BACKEND is not ON"

# A shipped Mach-O file: this architecture only, no newer macOS than the minimum,
# a valid signature (signed ad hoc below), and no library that a stock macOS
# does not provide.
check_macho() {
  local file=$1 archs minos id dep
  archs=$(lipo -archs "$file") || die "$file is not a Mach-O file"
  [ "$archs" = "$ARCH" ] || die "$file is built for '$archs', not $ARCH"
  minos=$(otool -l "$file" | awk '$1 == "cmd" { build = ($2 == "LC_BUILD_VERSION") } build && $1 == "minos" { print $2; exit }')
  [ "$minos" = "$MACOS_MIN" ] || die "$file requires macOS '$minos', not $MACOS_MIN"
  codesign --verify "$file" || die "$file has no valid signature"
  # otool -L lists a library's own install name first; that is not a dependency.
  id=$(otool -D "$file" | awk 'NR == 2')
  while read -r dep; do
    [ "$dep" = "$id" ] && continue
    case "$dep" in
      /usr/lib/*|/System/Library/*) ;;
      *) die "$file links $dep, which macOS does not provide" ;;
    esac
  done < <(otool -L "$file" | awk 'NR > 1 { print $1 }')
}

for t in "${VERSIONED_TARGETS[@]}"; do
  path=
  for entry in "${NODE_FILES[@]}" "${TOOL_FILES[@]}"; do
    [ "${entry%%=*}" = "$t" ] && path=${entry#*=}
  done
  [ -n "$path" ] || die "$t is not a shipped file"
  "$BUILD/$path" -V | grep -q "Commit: $REV" || die "$t -V does not report commit $REV"
done

# tosctl, with the toolchain rust-toolchain.toml pins and the committed
# Cargo.lock. RUSTFLAGS is set here, so flags from the environment or a cargo
# configuration file do not apply; the empty wrapper settings turn off a
# compiler cache configured on the build host.
TOSCTL_RUSTFLAGS="-C target-cpu=$RUST_CPU"
TOSCTL_TARGET=$PWD/$BUILD/tosctl-target
(
  cd tosctl/src
  export RUSTFLAGS="$TOSCTL_RUSTFLAGS" CARGO_TARGET_DIR="$TOSCTL_TARGET"
  export CC CXX
  export RUSTC_WRAPPER="" CARGO_BUILD_RUSTC_WRAPPER="" CARGO_INCREMENTAL=0
  unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_TARGET GIT_COMMIT GIT_COMMIT_DATE
  unset CFLAGS CXXFLAGS TARGET_CFLAGS TARGET_CXXFLAGS
  # tosctl --version embeds a branch name. A tag checkout has none and reports
  # HEAD; fixing it makes a build dispatched on a branch at the same commit
  # report the same.
  export GIT_BRANCH=HEAD
  cargo build --release --locked -p tosctl -j "$JOBS"
)
TOSCTL=$TOSCTL_TARGET/release/tosctl
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "the tosctl build changed the checkout"
"$TOSCTL" --version | grep -qx "COMMIT_ID: $REV" || die "tosctl --version does not report commit $REV"

mkdir -p "$OUT"
SHIPPED=()
for entry in "${NODE_FILES[@]}" "${TOOL_FILES[@]}"; do
  install -m 0755 "$BUILD/${entry#*=}" "$OUT/${entry%%=*}"
  SHIPPED+=("${entry%%=*}")
done
install -m 0755 "$TOSCTL" "$OUT/tosctl"
SHIPPED+=(tosctl)
# Apple silicon runs no unsigned code. Its linker signs ad hoc, but the Intel
# linker does not, so every shipped file is signed ad hoc here, on both, the
# same way. The identifier is the file name, so the signature, and the
# SHA-256 in BUILD-INFO, depend only on the file signed.
for name in "${SHIPPED[@]}"; do
  codesign --force --sign - "$OUT/$name" || die "cannot sign $name"
done
for name in "${SHIPPED[@]}"; do
  check_macho "$OUT/$name"
done
cp -R crypto/smartcont "$OUT/smartcont"
cp -R crypto/fift/lib "$OUT/lib"

{
  echo "tos_revision $REV"
  echo "source_date_epoch $SOURCE_DATE_EPOCH"
  echo "architecture $(uname -m)"
  echo "build_os macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
  echo "sdk $(xcrun --sdk macosx --show-sdk-version) $SDKROOT"
  echo "compiler $("$CXX" --version | head -1)"
  echo "flags CMAKE_BUILD_TYPE=Release TOS_ARCH=$CPU PORTABLE=$ROCKSDB_CPU CMAKE_OSX_DEPLOYMENT_TARGET=$MACOS_MIN TOS_USE_JEMALLOC=OFF"
  echo "slhdsa_sha256 $SLHDSA_BACKEND=$(cached "$SLHDSA_BACKEND")"
  echo "allocator system"
  echo "$RUSTC_VERSION"
  echo "$CARGO_VERSION"
  echo "rust_flags RUSTFLAGS=$TOSCTL_RUSTFLAGS MACOSX_DEPLOYMENT_TARGET=$MACOS_MIN cargo build --release --locked -p tosctl"
  for name in "${SHIPPED[@]}"; do
    id=$(otool -D "$OUT/$name" | awk 'NR == 2')
    echo "needed $name $(otool -L "$OUT/$name" | awk -v id="$id" 'NR > 1 && $1 != id { print $1 }' | sort | tr '\n' ' ' | awk '{ $1 = $1; print }')"
  done
  (cd "$OUT" && shasum -a 256 "${SHIPPED[@]}") | awk '{ print "sha256 " $0 }'
} >"$OUT/BUILD-INFO"
cat "$OUT/BUILD-INFO"
