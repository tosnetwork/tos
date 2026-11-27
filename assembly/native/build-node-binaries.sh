#!/usr/bin/env bash
# Build the node binaries a release publishes, with the production node recipe.
#
#   assembly/native/build-node-binaries.sh <output dir> [jobs]
#
# Run from the root of a clean checkout of the commit to release. The recipe is
# the one the testnet hosts build on themselves:
#
#   Release, clang-21, TOS_USE_JEMALLOC=ON, TOS_STATIC_GSL=ON,
#   TOS_ARCH = PORTABLE = x86-64-v2 (x86-64) or armv8-a (arm64),
#   SOURCE_DATE_EPOCH = the commit time of HEAD.
#
# A validator's memory behaviour depends on jemalloc, so a node binary built
# without it is not the tested product. The fixed CPU level, rather than
# -march=native, keeps a binary from stopping with SIGILL on an older CPU; the
# fixed SOURCE_DATE_EPOCH keeps third-party build timestamps from varying.
# GSL is linked from its static archive: its soname differs between Ubuntu
# releases (libgsl.so.27 on 24.04, libgsl.so.28 on 26.04), and every other
# library the binaries need keeps its soname across them. The release
# publishes the corresponding source of exactly one libgsl-dev version
# (THIRD_PARTY_NOTICES.md), so the build refuses any other.
#
# The script refuses to finish unless the recipe is in effect: the configured
# cache holds these values, the binaries that link jemalloc load it,
# validator-engine allocates through it, no binary needs the GSL shared
# library while validator-engine carries the GSL functions RLDP uses, and every
# binary with -V reports the commit it was built from.
#
# tosctl, the Rust tool an operator drives the node with, is built from the
# same commit in the same run:
#
#   cargo build --release --locked -p tosctl (in tosctl/src),
#   the Rust toolchain rust-toolchain.toml pins,
#   RUSTFLAGS = -C target-cpu=x86-64-v2 (x86-64) or generic (arm64),
#   C sources of its dependencies compiled with clang-21, no compiler wrapper.
#
# --locked keeps cargo to the committed Cargo.lock. The fixed target CPU also
# keeps a dependency's build script from enabling instructions it finds on the
# build host. The script refuses to finish unless rustc is the pinned version,
# the build left the checkout unchanged and tosctl --version reports the
# commit.
#
# The output directory receives the eight node binaries, tosctl, BUILD-INFO,
# and the repository's LICENSE and THIRD_PARTY_NOTICES.md.
set -euo pipefail

die() { echo "build-node-binaries: $*" >&2; exit 1; }

if [ $# -lt 1 ] || [ $# -gt 2 ]; then die "usage: $0 <output dir> [jobs]"; fi
OUT=$1
JOBS=${2:-$(nproc)}
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "jobs must be a positive integer"
if [ ! -f CMakeLists.txt ] || [ ! -d validator-engine ]; then die "run from the repository root"; fi
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "the checkout has local changes"
[ ! -e "$OUT" ] || die "$OUT already exists"

case "$(uname -m)" in
  x86_64) CPU=x86-64-v2 RUST_CPU=x86-64-v2 ;;
  aarch64|arm64) CPU=armv8-a RUST_CPU=generic ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

REV=$(git rev-parse HEAD)
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export SOURCE_DATE_EPOCH
# The Rust toolchain is checked before the long C++ build, so a host without
# the pinned one fails at once. RUSTC and its siblings would let another
# compiler stand in for the one checked here.
unset RUSTC CARGO_BUILD_RUSTC RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER
RUST_CHANNEL=$(sed -nE 's/^channel[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' rust-toolchain.toml)
[ -n "$RUST_CHANNEL" ] || die "rust-toolchain.toml pins no channel"
RUSTC_VERSION=$(cd tosctl/src && rustc --version)
CARGO_VERSION=$(cd tosctl/src && cargo --version)
[[ "$RUSTC_VERSION" == "rustc $RUST_CHANNEL "* ]] || die "rustc is '$RUSTC_VERSION', not the pinned $RUST_CHANNEL"
[[ "$CARGO_VERSION" == "cargo $RUST_CHANNEL "* ]] || die "cargo is '$CARGO_VERSION', not the pinned $RUST_CHANNEL"
# The GSL archive linked in must be the one whose source the release publishes;
# the node-binaries workflow pins the same version.
GSL_PACKAGE_VERSION=2.7.1+dfsg-6ubuntu2
command -v dpkg-query >/dev/null || die "dpkg-query is missing; the recipe needs the Ubuntu libgsl-dev package"
GSL_VERSION=$(dpkg-query -W -f '${Version}' libgsl-dev 2>/dev/null) || die "libgsl-dev is not installed"
[ "$GSL_VERSION" = "$GSL_PACKAGE_VERSION" ] \
  || die "libgsl-dev is $GSL_VERSION, not the pinned $GSL_PACKAGE_VERSION"
# No compiler cache: a release binary is compiled from source, never taken
# from objects another run left behind.
export CCACHE_DISABLE=1
# The SHA-256 backend switches take their defaults from variables of the same
# names, in the CMake and the Cargo build alike; a release uses the defaults.
unset TOS_SLHDSA_SHA_NI TOS_SLHDSA_ARMV8_SHA2

TARGETS=(validator-engine validator-engine-console lite-client generate-random-id
         tos-pq-consensus-key dht-server tos-rpc tos-wallet-index)
declare -A PATHS=(
  [validator-engine]=validator-engine/validator-engine
  [validator-engine-console]=validator-engine-console/validator-engine-console
  [lite-client]=lite-client/lite-client
  [generate-random-id]=utils/generate-random-id
  [tos-pq-consensus-key]=crypto/pq/tos-pq-consensus-key
  [dht-server]=dht-server/dht-server
  [tos-rpc]=services/tos-rpc
  [tos-wallet-index]=services/tos-wallet-index
)
# The targets that link jemalloc: validator-engine and dht-server list
# JEMALLOC_LIBRARIES themselves; tos-rpc and tos-wallet-index get it through
# tos_db, which links it PUBLIC.
JEMALLOC_TARGETS=(validator-engine dht-server tos-rpc tos-wallet-index)
# The targets with a -V option that prints the commit. tos-pq-consensus-key,
# tos-rpc and tos-wallet-index have no -V; BUILD-INFO records their digests.
VERSIONED_TARGETS=(validator-engine validator-engine-console lite-client generate-random-id dht-server)

BUILD=build-node
rm -rf "$BUILD"
cmake -S . -B "$BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21 \
  -DTOS_ARCH="$CPU" -DPORTABLE="$CPU" \
  -DTOS_STATIC_GSL=ON \
  -DTOS_USE_JEMALLOC=ON
cmake --build "$BUILD" --parallel "$JOBS" --target "${TARGETS[@]}"

# The recipe, read back from what CMake configured.
cached() { sed -n "s/^$1:[A-Z]*=//p" "$BUILD/CMakeCache.txt"; }
[ "$(cached CMAKE_BUILD_TYPE)" = Release ] || die "CMAKE_BUILD_TYPE is not Release"
[ "$(cached TOS_USE_JEMALLOC)" = ON ] || die "TOS_USE_JEMALLOC is not ON"
[ "$(cached TOS_STATIC_GSL)" = ON ] || die "TOS_STATIC_GSL is not ON"
[ "$(cached TOS_ARCH)" = "$CPU" ] || die "TOS_ARCH is not $CPU"
[ "$(cached PORTABLE)" = "$CPU" ] || die "PORTABLE is not $CPU"
[ "$(basename "$(cached CMAKE_CXX_COMPILER)")" = clang++-21 ] || die "the C++ compiler is not clang++-21"
# The SLH-DSA check is priced for a hardware SHA-256 backend (doc/Validator.md).
# A node binary built without the one for its architecture would verify with
# the portable backend on every CPU, so it is not a validator's binary.
case "$(uname -m)" in
  x86_64) SLHDSA_BACKEND=TOS_SLHDSA_SHA_NI ;;
  *) SLHDSA_BACKEND=TOS_SLHDSA_ARMV8_SHA2 ;;
esac
[ "$(cached "$SLHDSA_BACKEND")" = ON ] || die "$SLHDSA_BACKEND is not ON"
JEMALLOC_LIB=$(cached JEMALLOC_LIBRARIES)
[ -n "$JEMALLOC_LIB" ] || die "CMake found no jemalloc library"

for t in "${JEMALLOC_TARGETS[@]}"; do
  bin="$BUILD/${PATHS[$t]}"
  readelf -d "$bin" | grep -q 'NEEDED.*\[libjemalloc\.so' || die "$t does not link jemalloc"
done
# GSL is in the binaries, not a dependency of them: RLDP's loss estimate is
# compiled with it (TOS_HAVE_GSL), and the archive's functions are linked in.
for t in "${TARGETS[@]}"; do
  bin="$BUILD/${PATHS[$t]}"
  readelf -d "$bin" >/dev/null || die "readelf cannot read $t"
  if readelf -d "$bin" | grep 'NEEDED.*\[libgsl' >/dev/null; then die "$t needs the GSL shared library"; fi
done
# The function RLDP's send estimate calls; --exclude-libs makes the archive's
# symbols local (t). grep reads all of nm's output, so a pipefail cannot come
# from nm's SIGPIPE.
nm --defined-only "$BUILD/${PATHS[validator-engine]}" | grep -E ' [Tt] gsl_cdf_negative_binomial_P$' >/dev/null \
  || die "validator-engine does not carry the GSL functions"
# Linked is not the same as used: jemalloc prints its statistics at exit only
# when it is the allocator the process ran with.
MALLOC_CONF=stats_print:true "$BUILD/${PATHS[validator-engine]}" -V >"$BUILD/jemalloc-stats.txt" 2>&1 \
  || die "validator-engine -V failed"
grep -q 'jemalloc statistics' "$BUILD/jemalloc-stats.txt" \
  || die "validator-engine does not allocate through jemalloc"
for t in "${VERSIONED_TARGETS[@]}"; do
  "$BUILD/${PATHS[$t]}" -V | grep -q "Commit: $REV" || die "$t -V does not report commit $REV"
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
  export CC=clang-21 CXX=clang++-21
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
for t in "${TARGETS[@]}"; do
  install -m 0755 "$BUILD/${PATHS[$t]}" "$OUT/$t"
done
install -m 0755 "$TOSCTL" "$OUT/tosctl"
install -m 0644 LICENSE THIRD_PARTY_NOTICES.md "$OUT/"
{
  echo "tos_revision $REV"
  echo "source_date_epoch $SOURCE_DATE_EPOCH"
  echo "architecture $(uname -m)"
  echo "compiler $(clang++-21 --version | head -1)"
  echo "flags CMAKE_BUILD_TYPE=Release TOS_ARCH=$CPU PORTABLE=$CPU TOS_USE_JEMALLOC=ON TOS_STATIC_GSL=ON"
  echo "slhdsa_sha256 TOS_SLHDSA_SHA_NI=$(cached TOS_SLHDSA_SHA_NI) TOS_SLHDSA_ARMV8_SHA2=$(cached TOS_SLHDSA_ARMV8_SHA2)"
  echo "$RUSTC_VERSION"
  echo "$CARGO_VERSION"
  echo "rust_flags RUSTFLAGS=$TOSCTL_RUSTFLAGS CC=clang-21 cargo build --release --locked -p tosctl"
  echo "jemalloc $JEMALLOC_LIB"
  if command -v dpkg-query >/dev/null; then
    package=$(dpkg -S "$(readlink -f "$JEMALLOC_LIB")" 2>/dev/null | cut -d: -f1 || true)
    echo "jemalloc_package ${package:-unknown} $(dpkg-query -W -f '${Version}' "${package:-none}" 2>/dev/null || true)"
  fi
  echo "gsl_package libgsl-dev $GSL_VERSION"
  if [ -r /etc/os-release ]; then
    # shellcheck source=/dev/null
    echo "build_os $(. /etc/os-release && echo "$PRETTY_NAME")"
  fi
  for t in "${TARGETS[@]}" tosctl; do
    echo "needed $t $(readelf -d "$OUT/$t" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | sort | tr '\n' ' ' | sed 's/ $//')"
  done
  (cd "$OUT" && sha256sum "${TARGETS[@]}" tosctl) | sed 's/^/sha256 /'
} >"$OUT/BUILD-INFO"
cat "$OUT/BUILD-INFO"
