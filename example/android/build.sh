#!/usr/bin/env bash
# Build the toslib JNI library for Android and its Java API.
#
#   ANDROID_NDK_ROOT=/path/to/ndk example/android/build.sh [ABI...]
#
# ABI is any of arm64-v8a armeabi-v7a x86_64 x86; with none, all four are built.
# Run from anywhere; everything is written under example/android:
#
#   build-host/            a native build of this project. It generates the TL,
#                          TL-B and contract sources a cross build cannot make,
#                          the Java API, and a host libnative-lib for the JVM
#                          smoke test in test/android/.
#   build-<ABI>/           the cross build for each ABI.
#   toslib-android/        the result: libs/<ABI>/libnative-lib.so (stripped),
#                          src/ with Client.java and the generated TosApi.java,
#                          and BUILD-INFO with the commit and each file's SHA-256.
#
# The NDK is the one ANDROID_NDK_ROOT names; CI pins its version
# (.github/workflows/build-toslib-android.yml).

set -euo pipefail

die() {
  echo "build.sh: $*" >&2
  exit 1
}

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
JOBS=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}
# API 24 is the lowest level the NDK's 64-bit and 32-bit toolchains share with
# the proof verifier build (scripts/build-embedded-proof-android.py).
API=${ANDROID_API:-24}

[ -n "${ANDROID_NDK_ROOT:-}" ] || die "ANDROID_NDK_ROOT is not set"
TOOLCHAIN=$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake
[ -f "$TOOLCHAIN" ] || die "no Android toolchain at $TOOLCHAIN"
case "$(uname -s)" in
  Linux) NDK_HOST=linux-x86_64 ;;
  Darwin)
    NDK_HOST=darwin-x86_64
    # The host build's third-party configure steps call the compiler outside
    # CMake, where it finds the system headers only through SDKROOT.
    SDKROOT=${SDKROOT:-$(xcrun --sdk macosx --show-sdk-path)}
    export SDKROOT
    ;;
  *) die "unsupported build host $(uname -s)" ;;
esac
STRIP=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$NDK_HOST/bin/llvm-strip
[ -x "$STRIP" ] || die "no llvm-strip at $STRIP"

if [ $# -eq 0 ]; then
  set -- arm64-v8a armeabi-v7a x86_64 x86
fi
for abi in "$@"; do
  case "$abi" in
    arm64-v8a | armeabi-v7a | x86_64 | x86) ;;
    *) die "unknown ABI $abi (use arm64-v8a, armeabi-v7a, x86_64 or x86)" ;;
  esac
done

HOST=$HERE/build-host
OUT=$HERE/toslib-android
rm -rf "$OUT"

echo "[build.sh] host build in $HOST"
cmake -S "$HERE" -B "$HOST" -G Ninja -DCMAKE_BUILD_TYPE=Release -DTOS_ONLY_TOSLIB=ON
cmake --build "$HOST" --parallel "$JOBS" --target prepare_cross_compiling smc-envelope native-lib

SMARTCONT_AUTO=$HOST/tos/crypto/smartcont/auto
shopt -s nullglob
GENERATED=("$SMARTCONT_AUTO"/*.cpp)
shopt -u nullglob
[ ${#GENERATED[@]} -gt 0 ] || die "the host build generated no contract sources in $SMARTCONT_AUTO"
JAVA_API=$HERE/src/org/tos/toslib/TosApi.java
[ -s "$JAVA_API" ] || die "the host build did not generate $JAVA_API"

for abi in "$@"; do
  BUILD=$HERE/build-$abi
  echo "[build.sh] $abi in $BUILD (android-$API)"
  cmake -S "$HERE" -B "$BUILD" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI="$abi" \
    -DANDROID_PLATFORM="android-$API" \
    -DANDROID_NDK="$ANDROID_NDK_ROOT" \
    -DCMAKE_BUILD_TYPE=Release \
    -DTOS_ONLY_TOSLIB=ON \
    -DTOS_ARCH=
  mkdir -p "$BUILD/tos/crypto/smartcont/auto"
  cp "${GENERATED[@]}" "$BUILD/tos/crypto/smartcont/auto/"
  cmake --build "$BUILD" --parallel "$JOBS" --target native-lib
  mkdir -p "$OUT/libs/$abi"
  "$STRIP" --strip-unneeded -o "$OUT/libs/$abi/libnative-lib.so" "$BUILD/libnative-lib.so"
done

mkdir -p "$OUT/src/org/tos/toslib"
cp "$HERE/src/org/tos/toslib/Client.java" "$JAVA_API" "$OUT/src/org/tos/toslib/"

REV=$(git -C "$ROOT" rev-parse HEAD)
{
  echo "tos_revision $REV"
  echo "ndk $(awk -F' *= *' '$1 == "Pkg.Revision" { print $2 }' "$ANDROID_NDK_ROOT/source.properties")"
  echo "android_api $API"
  (cd "$OUT" && find libs src -type f | LC_ALL=C sort | while read -r f; do
    if command -v sha256sum >/dev/null; then sha256sum "$f"; else shasum -a 256 "$f"; fi
  done) | awk '{ print "sha256 " $1 "  " $2 }'
} >"$OUT/BUILD-INFO"
cat "$OUT/BUILD-INFO"
