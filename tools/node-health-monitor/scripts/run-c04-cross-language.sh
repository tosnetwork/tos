#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
pair_dir="${1:?usage: run-c04-cross-language.sh PAIR_DIR OUTPUT_DIR}"
output_dir="${2:?usage: run-c04-cross-language.sh PAIR_DIR OUTPUT_DIR}"
native_binary="${3:-}"
test -d "$pair_dir"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
NHM_C04_PAIR_DIR="$pair_dir" NHM_C04_OUTPUT_DIR="$output_dir" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
  cargo test --manifest-path "$root/Cargo.toml" --locked -p tos-health-services \
  --test native_v2_producer_pair -- --ignored --exact actual_cpp_publisher_pairs_and_negatives
if test -n "$native_binary"; then
  "$root/.contract-venv/bin/python" "$root/tests/check-c04-producer-pair.py" \
    --pair-dir "$pair_dir" --edge-snapshot "$output_dir/edge-snapshot-producer-v2.json" \
    --native-binary "$native_binary"
else
  "$root/.contract-venv/bin/python" "$root/tests/check-c04-producer-pair.py" \
    --pair-dir "$pair_dir" --edge-snapshot "$output_dir/edge-snapshot-producer-v2.json"
fi
