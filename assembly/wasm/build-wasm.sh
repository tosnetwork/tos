#!/usr/bin/env bash
# Build the Fift and FunC tools and the transaction emulator for WebAssembly.
#
#   assembly/wasm/build-wasm.sh <emsdk dir> <output dir> [jobs]
#
# Run from the root of a clean checkout, with an activated emsdk at <emsdk dir>
# (.github/workflows/build-tos-wasm-emscripten.yml installs the pinned one).
# The node and the validator are not built for WebAssembly: this build covers
# the libraries that compile and test contracts in a browser or under Node.js.
#
# Every third-party library is built from third-party/ with Emscripten, as the
# native build builds them. The WebAssembly build does not run the code
# generators (tlbc and the Fift smart-contract envelopes), so a native build of
# fift and smc-envelope first writes their output into the source tree.
#
# The output directory receives:
#   funcfiftlib.js, funcfiftlib.wasm      FunC compiler and Fift assembler
#   fift.js, fift.wasm, func.js, func.wasm, tlbc.js, tlbc.wasm
#   emulator-emscripten.js, emulator-emscripten.wasm
#   smartcont/, lib/                       the sources the Fift tools read

set -euo pipefail

die() { echo "build-wasm: $*" >&2; exit 1; }

if [ $# -lt 2 ] || [ $# -gt 3 ]; then die "usage: $0 <emsdk dir> <output dir> [jobs]"; fi
EMSDK_DIR=$(cd "$1" && pwd)
OUT=$2
JOBS=${3:-$(getconf _NPROCESSORS_ONLN)}
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "jobs must be a positive integer"
if [ ! -f CMakeLists.txt ] || [ ! -d crypto/funcfiftlib ]; then die "run from the repository root"; fi
[ ! -e "$OUT" ] || die "$OUT already exists"
[ -f "$EMSDK_DIR/emsdk_env.sh" ] || die "$EMSDK_DIR is not an emsdk"

REV=$(git rev-parse HEAD)
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export SOURCE_DATE_EPOCH
export CCACHE_DISABLE=1

# The generators' output, from a native build.
NATIVE=build-wasm-native
rm -rf "$NATIVE"
cmake -S . -B "$NATIVE" -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "$NATIVE" --parallel "$JOBS" --target fift smc-envelope

# shellcheck source=/dev/null
. "$EMSDK_DIR/emsdk_env.sh"
command -v emcmake >/dev/null || die "emsdk_env.sh did not put emcmake on PATH"
# The native compilers chosen for the generators must not reach the Emscripten build.
unset CC CXX

BUILD=build-wasm
rm -rf "$BUILD"
emcmake cmake -S . -B "$BUILD" -G Ninja -DUSE_EMSCRIPTEN=ON -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD" --parallel "$JOBS" --target funcfiftlib fift func tlbc emulator-emscripten

mkdir -p "$OUT"
for f in crypto/funcfiftlib crypto/fift crypto/func crypto/tlbc emulator/emulator-emscripten; do
  for ext in js wasm; do
    [ -f "$BUILD/$f.$ext" ] || die "$BUILD/$f.$ext was not built"
    cp "$BUILD/$f.$ext" "$OUT/"
  done
done
cp -R crypto/smartcont "$OUT/smartcont"
cp -R crypto/fift/lib "$OUT/lib"

# The libraries load and work under Node.js, and report the commit.
node test/wasm/smoke-test.js "$OUT" "$REV"

{
  echo "tos_revision $REV"
  echo "source_date_epoch $SOURCE_DATE_EPOCH"
  echo "emscripten $(emcc --version | head -1)"
  (cd "$OUT" && sha256sum ./*.js ./*.wasm) | awk '{ print "sha256 " $0 }'
} >"$OUT/BUILD-INFO"
cat "$OUT/BUILD-INFO"
