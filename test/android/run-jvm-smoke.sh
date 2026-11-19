#!/usr/bin/env bash
# Run ToslibJniSmokeTest against the host build example/android/build.sh made.
#
#   test/android/run-jvm-smoke.sh [example/android/build-host]

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HOST=${1:-$ROOT/example/android/build-host}
SRC=$ROOT/example/android/src/org/tos/toslib

[ -s "$SRC/TosApi.java" ] || { echo "run-jvm-smoke.sh: run example/android/build.sh first" >&2; exit 1; }
LIB=$(find "$HOST" -maxdepth 1 \( -name 'libnative-lib.so' -o -name 'libnative-lib.dylib' \) | head -n 1)
[ -n "$LIB" ] || { echo "run-jvm-smoke.sh: no host libnative-lib in $HOST" >&2; exit 1; }

CLASSES=$(mktemp -d)
trap 'rm -rf "$CLASSES"' EXIT
javac -d "$CLASSES" "$SRC/Client.java" "$SRC/TosApi.java" "$ROOT/test/android/ToslibJniSmokeTest.java"
java -Xcheck:jni -Djava.library.path="$(dirname "$LIB")" -cp "$CLASSES" ToslibJniSmokeTest
