#!/usr/bin/env bash
# run-libfuzzer.sh — drive the coverage-guided fuzz harnesses.
#
# One harness is gated behind -DTOS_BUILD_LIBFUZZER=ON and a clang
# toolchain (the libFuzzer + AddressSanitizer combo is a clang-only
# feature):
#
#   - test-boc-libfuzzer  — exercises the BoC primitives
#                           (`std_boc_deserialize` and
#                           `std_boc_deserialize_from_file_bounded`).
#
# Operational guidance:
#   Run for at least 1 hour daily in CI (e.g. duration_seconds=3600).
#   Any crash file written by libFuzzer (named `crash-*` in the corpus
#   directory) MUST be reported to the security team along with the
#   binary's stderr output — a crash represents a violation of the
#   noexcept / no-abort contract on a public-facing API.
#
# Usage:
#   bash scripts/run-libfuzzer.sh [boc] [duration_seconds]
#
# Defaults:
#   target = boc
#   duration_seconds = 30   (smoke; production CI should pass >= 3600)
#
# LeakSanitizer is disabled by default for this harness because the linked
# tree contains process-lifetime singletons/static Status sentinels and the
# libFuzzer driver itself also leaves small intentional allocations at exit.
# Those exit-time leaks are not input-dependent BoC failures and otherwise
# make every bounded smoke run finish with a synthetic "crash". Set
# TOS_LIBFUZZER_DETECT_LEAKS=1 and provide explicit ASAN_OPTIONS/LSAN_OPTIONS
# if you are investigating leak behavior specifically.
#
# Required configure step (once):
#   cmake -S . -B build-libfuzzer \
#       -DTOS_BUILD_LIBFUZZER=ON \
#       -DCMAKE_C_COMPILER=clang \
#       -DCMAKE_CXX_COMPILER=clang++
#   cmake --build build-libfuzzer --target test-boc-libfuzzer
#
# Override the build directory by exporting BUILD_DIR before running.

set -euo pipefail

target="${1:-boc}"
duration_seconds="${2:-30}"
build_dir="${BUILD_DIR:-build-libfuzzer}"

case "$target" in
    boc)
        ;;
    *)
        echo "ERROR: unknown target '$target' (expected 'boc')" >&2
        exit 2
        ;;
esac

# Validate that duration_seconds is a non-negative integer. libFuzzer
# treats `-max_total_time=0` as "run forever", which is fine — but a
# malformed value (e.g. "abc") would fail silently inside the binary
# and is better caught here.
if ! [[ "$duration_seconds" =~ ^[0-9]+$ ]]; then
    echo "ERROR: duration_seconds must be a non-negative integer (got '$duration_seconds')" >&2
    exit 2
fi

binary="$build_dir/evm/test/test-${target}-libfuzzer"
if [ ! -x "$binary" ]; then
    cat >&2 <<EOF
ERROR: $binary not built.

Configure with libFuzzer enabled and a clang toolchain, then build:

    cmake -S . -B $build_dir \\
        -DTOS_BUILD_LIBFUZZER=ON \\
        -DCMAKE_C_COMPILER=clang \\
        -DCMAKE_CXX_COMPILER=clang++
    cmake --build $build_dir --target test-${target}-libfuzzer

EOF
    exit 1
fi

corpus_dir="$build_dir/libfuzzer-corpus-$target"
mkdir -p "$corpus_dir"

if [ "${TOS_LIBFUZZER_DETECT_LEAKS:-0}" = "0" ]; then
    export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=0"
    export LSAN_OPTIONS="${LSAN_OPTIONS:+$LSAN_OPTIONS:}detect_leaks=0"
fi

echo "running $binary for ${duration_seconds}s with corpus $corpus_dir"
exec "$binary" \
    -max_total_time="$duration_seconds" \
    -print_final_stats=1 \
    "$corpus_dir"
