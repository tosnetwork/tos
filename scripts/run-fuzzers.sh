#!/usr/bin/env bash
# Run the coverage-guided fuzz targets of test/fuzz for a bounded time each.
#
#   scripts/run-fuzzers.sh <build-dir> <seconds-per-target> <work-dir> [target ...]
#
# <build-dir> was configured with -DTOS_BUILD_FUZZERS=ON (see test/fuzz/CMakeLists.txt)
# and built with --target fuzzers. Each target starts from the committed seeds in
# test/fuzz/corpus/<target> plus whatever <work-dir>/corpus/<target> already holds, and
# writes the inputs it finds there; the committed seeds are only read. A crash, leak,
# timeout or out-of-memory input lands in <work-dir>/artifacts/<target>/ and makes the
# script exit non-zero after every target has run. FUZZ_JOBS targets run at a time
# (default: the number of CPUs).
#
# Without target names every target runs.

set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: run-fuzzers.sh <build-dir> <seconds-per-target> <work-dir> [target ...]" >&2
  exit 2
fi

build_dir="$1"
seconds="$2"
work_dir="$3"
shift 3

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
seeds_root="$source_root/test/fuzz/corpus"

all_targets=(
  fuzz-boc
  fuzz-ext-message
  fuzz-state-import
  fuzz-finality-signatures
  fuzz-simplex-certificate
  fuzz-fec
  fuzz-rldp2
  fuzz-slhdsa-verify
)
if [ "$#" -gt 0 ]; then
  targets=("$@")
else
  targets=("${all_targets[@]}")
fi

[[ "$seconds" =~ ^[0-9]+$ ]] && [ "$seconds" -gt 0 ] || {
  echo "run-fuzzers: seconds-per-target must be a positive integer" >&2
  exit 2
}

# The largest input each target takes: an SLH-DSA input is a key, a 7856-byte signature
# and a message; everything else is a bag of cells or a sequence of network datagrams.
max_len_of() {
  case "$1" in
    fuzz-slhdsa-verify) echo 16384 ;;
    *) echo 65536 ;;
  esac
}

jobs="${FUZZ_JOBS:-$(nproc)}"
mkdir -p "$work_dir/corpus" "$work_dir/artifacts" "$work_dir/logs"

run_one() {
  local target="$1"
  local binary="$build_dir/fuzz/$target"
  local corpus="$work_dir/corpus/$target"
  local artifacts="$work_dir/artifacts/$target"
  local log="$work_dir/logs/$target.log"
  if [ ! -x "$binary" ]; then
    echo "run-fuzzers: $binary is missing; build the 'fuzzers' target" >&2
    echo "missing" > "$work_dir/logs/$target.status"
    return 0
  fi
  if [ ! -d "$seeds_root/$target" ]; then
    echo "run-fuzzers: no committed seeds for $target" >&2
    echo "missing-seeds" > "$work_dir/logs/$target.status"
    return 0
  fi
  mkdir -p "$corpus" "$artifacts"
  local status=0
  "$binary" \
    -max_total_time="$seconds" \
    -max_len="$(max_len_of "$target")" \
    -timeout=30 \
    -rss_limit_mb=4096 \
    -print_final_stats=1 \
    -artifact_prefix="$artifacts/" \
    "$corpus" "$seeds_root/$target" > "$log" 2>&1 || status=$?
  echo "$status" > "$work_dir/logs/$target.status"
}

for target in "${targets[@]}"; do
  while [ "$(jobs -rp | wc -l)" -ge "$jobs" ]; do
    wait -n || true
  done
  run_one "$target" &
done
wait

failed=0
printf '%-28s %-8s %14s %10s %s\n' target result executions corpus artifacts
for target in "${targets[@]}"; do
  status="$(cat "$work_dir/logs/$target.status" 2>/dev/null || echo missing)"
  log="$work_dir/logs/$target.log"
  executions="$(grep -ao 'stat::number_of_executed_units: [0-9]*' "$log" 2>/dev/null | awk '{print $2}' | tail -n 1)"
  corpus_size="$(find "$work_dir/corpus/$target" -type f 2>/dev/null | wc -l)"
  artifact_count="$(find "$work_dir/artifacts/$target" -type f 2>/dev/null | wc -l)"
  result=ok
  if [ "$status" != 0 ] || [ "$artifact_count" -gt 0 ]; then
    result=FAIL
    failed=1
  fi
  printf '%-28s %-8s %14s %10s %s\n' "$target" "$result" "${executions:-?}" "$corpus_size" "$artifact_count"
done

if [ "$failed" -ne 0 ]; then
  for target in "${targets[@]}"; do
    status="$(cat "$work_dir/logs/$target.status" 2>/dev/null || echo missing)"
    if [ "$status" != 0 ]; then
      echo "::group::$target (exit $status)"
      tail -n 80 "$work_dir/logs/$target.log" 2>/dev/null || true
      echo "::endgroup::"
    fi
  done
  exit 1
fi
