#!/usr/bin/env bash
# Build the node binaries a release publishes, with the production node recipe.
#
#   assembly/native/build-node-binaries.sh <output dir> [jobs]
#
# Run from the root of a clean checkout of the commit to release. The recipe is
# the one the testnet hosts build on themselves:
#
#   Release, clang-21, TOS_USE_JEMALLOC=ON,
#   TOS_ARCH = PORTABLE = x86-64-v2 (x86-64) or armv8-a (arm64),
#   SOURCE_DATE_EPOCH = the commit time of HEAD.
#
# A validator's memory behaviour depends on jemalloc, so a node binary built
# without it is not the tested product. The fixed CPU level, rather than
# -march=native, keeps a binary from stopping with SIGILL on an older CPU; the
# fixed SOURCE_DATE_EPOCH keeps third-party build timestamps from varying.
#
# The script refuses to finish unless the recipe is in effect: the configured
# cache holds these values, validator-engine and dht-server load jemalloc and
# allocate through it, and every binary reports the commit it was built from.
# The output directory receives the six binaries and BUILD-INFO.
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
  x86_64) CPU=x86-64-v2 ;;
  aarch64|arm64) CPU=armv8-a ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

REV=$(git rev-parse HEAD)
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export SOURCE_DATE_EPOCH
# No compiler cache: a release binary is compiled from source, never taken
# from objects another run left behind.
export CCACHE_DISABLE=1

TARGETS=(validator-engine validator-engine-console lite-client generate-random-id
         tos-pq-consensus-key dht-server)
declare -A PATHS=(
  [validator-engine]=validator-engine/validator-engine
  [validator-engine-console]=validator-engine-console/validator-engine-console
  [lite-client]=lite-client/lite-client
  [generate-random-id]=utils/generate-random-id
  [tos-pq-consensus-key]=crypto/pq/tos-pq-consensus-key
  [dht-server]=dht-server/dht-server
)
# The targets that link jemalloc (their CMake targets list JEMALLOC_LIBRARIES).
JEMALLOC_TARGETS=(validator-engine dht-server)
# The targets with a -V option that prints the commit.
VERSIONED_TARGETS=(validator-engine validator-engine-console lite-client generate-random-id dht-server)

BUILD=build-node
rm -rf "$BUILD"
cmake -S . -B "$BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21 \
  -DTOS_ARCH="$CPU" -DPORTABLE="$CPU" \
  -DTOS_USE_JEMALLOC=ON
cmake --build "$BUILD" --parallel "$JOBS" --target "${TARGETS[@]}"

# The recipe, read back from what CMake configured.
cached() { sed -n "s/^$1:[A-Z]*=//p" "$BUILD/CMakeCache.txt"; }
[ "$(cached CMAKE_BUILD_TYPE)" = Release ] || die "CMAKE_BUILD_TYPE is not Release"
[ "$(cached TOS_USE_JEMALLOC)" = ON ] || die "TOS_USE_JEMALLOC is not ON"
[ "$(cached TOS_ARCH)" = "$CPU" ] || die "TOS_ARCH is not $CPU"
[ "$(cached PORTABLE)" = "$CPU" ] || die "PORTABLE is not $CPU"
[ "$(basename "$(cached CMAKE_CXX_COMPILER)")" = clang++-21 ] || die "the C++ compiler is not clang++-21"
JEMALLOC_LIB=$(cached JEMALLOC_LIBRARIES)
[ -n "$JEMALLOC_LIB" ] || die "CMake found no jemalloc library"

for t in "${JEMALLOC_TARGETS[@]}"; do
  bin="$BUILD/${PATHS[$t]}"
  readelf -d "$bin" | grep -q 'NEEDED.*\[libjemalloc\.so' || die "$t does not link jemalloc"
done
# Linked is not the same as used: jemalloc prints its statistics at exit only
# when it is the allocator the process ran with.
MALLOC_CONF=stats_print:true "$BUILD/${PATHS[validator-engine]}" -V >"$BUILD/jemalloc-stats.txt" 2>&1 \
  || die "validator-engine -V failed"
grep -q 'jemalloc statistics' "$BUILD/jemalloc-stats.txt" \
  || die "validator-engine does not allocate through jemalloc"
for t in "${VERSIONED_TARGETS[@]}"; do
  "$BUILD/${PATHS[$t]}" -V | grep -q "Commit: $REV" || die "$t -V does not report commit $REV"
done

mkdir -p "$OUT"
for t in "${TARGETS[@]}"; do
  install -m 0755 "$BUILD/${PATHS[$t]}" "$OUT/$t"
done
{
  echo "tos_revision $REV"
  echo "source_date_epoch $SOURCE_DATE_EPOCH"
  echo "architecture $(uname -m)"
  echo "compiler $(clang++-21 --version | head -1)"
  echo "flags CMAKE_BUILD_TYPE=Release TOS_ARCH=$CPU PORTABLE=$CPU TOS_USE_JEMALLOC=ON"
  echo "jemalloc $JEMALLOC_LIB"
  if command -v dpkg-query >/dev/null; then
    package=$(dpkg -S "$(readlink -f "$JEMALLOC_LIB")" 2>/dev/null | cut -d: -f1 || true)
    echo "jemalloc_package ${package:-unknown} $(dpkg-query -W -f '${Version}' "${package:-none}" 2>/dev/null || true)"
  fi
  if [ -r /etc/os-release ]; then
    # shellcheck source=/dev/null
    echo "build_os $(. /etc/os-release && echo "$PRETTY_NAME")"
  fi
  for t in "${TARGETS[@]}"; do
    echo "needed $t $(readelf -d "$OUT/$t" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | sort | tr '\n' ' ' | sed 's/ $//')"
  done
  (cd "$OUT" && sha256sum "${TARGETS[@]}") | sed 's/^/sha256 /'
} >"$OUT/BUILD-INFO"
cat "$OUT/BUILD-INFO"
