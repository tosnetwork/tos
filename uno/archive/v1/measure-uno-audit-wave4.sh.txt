#!/usr/bin/env bash
# Test-only serial measurement matrix. No configuration or schema activation.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo "usage: measure-uno-audit-wave4.sh BUILD_DIRECTORY NEW_OUTPUT_DIRECTORY" >&2
  exit 2
fi
build_dir=$(realpath "$1")
source_dir=$(cd "$(dirname "$0")/.." && pwd)
output_dir=$2
# Refuse to overwrite an earlier measurement or accidentally concatenate runs.
mkdir "$output_dir"
output_dir=$(realpath "$output_dir")
git -C "$source_dir" rev-parse HEAD > "$output_dir/commit.txt"
git -C "$source_dir" status --short > "$output_dir/worktree.txt"
uname -a > "$output_dir/kernel.txt"
lscpu > "$output_dir/cpu.txt"
cat /proc/loadavg > "$output_dir/load-start.txt"
date -u +%FT%TZ > "$output_dir/start.txt"
rg 'CMAKE_BUILD_TYPE:|CMAKE_CXX_COMPILER:|CMAKE_CXX_FLAGS_RELEASE:|TOS_UNO_' "$build_dir/CMakeCache.txt" > "$output_dir/build.txt"
"$build_dir/measure-uno-input-admission" --self-test > "$output_dir/input-self.txt"
"$build_dir/measure-uno-input-admission" --anchor-self-test > "$output_dir/anchor-self.txt"
"$build_dir/measure-uno-partition-state" --self-test > "$output_dir/partition-self.txt"
"$build_dir/uno/crypto/test-uno-crypto-cost" --self-test > "$output_dir/crypto-self.txt"
"$build_dir/test-uno-storage-measurement" --filter CapacityGateInstrumentSelfCheck > "$output_dir/storage-self.txt" 2>&1
for leaves in 512 4096 16384 32768; do
  "$build_dir/measure-uno-input-admission" "$leaves" > "$output_dir/input-$leaves.jsonl"
done
"$build_dir/measure-uno-input-admission" --anchors > "$output_dir/anchors.jsonl"
base64 --decode "$source_dir/doc/measurements/uno-wave4-funding.bin.b64" > "$output_dir/funding.bin"
base64 --decode "$source_dir/doc/measurements/uno-wave4-spend.bin.b64" > "$output_dir/spend.bin"
sha256sum "$output_dir/funding.bin" "$output_dir/spend.bin" > "$output_dir/fixture-hashes.txt"
RAYON_NUM_THREADS=48 "$build_dir/uno/crypto/test-uno-crypto-cost" --measure \
  "$output_dir/funding.bin" "$output_dir/spend.bin" > "$output_dir/crypto.jsonl" 2> "$output_dir/crypto.log"
for mode in single pages16; do
  for entries in 0 1024 8192 32768 65536; do
    for scenario in idle insert prefix split duplicate refund; do
      "$build_dir/measure-uno-partition-state" "$mode" "$scenario" "$entries" 3 45 \
        > "$output_dir/partition-$mode-$entries-$scenario.csv" \
        2> "$output_dir/partition-$mode-$entries-$scenario.metrics"
    done
  done
done
for entries in 1000 8000 32000; do
  for sample in 1 2 3; do
    TOS_UNO_STORAGE_KEYS=$entries "$build_dir/test-uno-storage-measurement" --filter SnapshotStages \
      > "$output_dir/storage-$entries-$sample.log" 2>&1
    # No matching row is a failed instrument, not an empty successful result.
    rg '^STORAGE_CSV,' "$output_dir/storage-$entries-$sample.log" > "$output_dir/storage-$entries-$sample.csv"
  done
done
cat /proc/loadavg > "$output_dir/load-end.txt"
date -u +%FT%TZ > "$output_dir/end.txt"
echo "Measured data retained at $output_dir"
