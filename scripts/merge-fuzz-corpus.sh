#!/usr/bin/env bash
# Minimise the corpora scripts/run-fuzzers.sh grew, so the kept corpus stays the
# smallest set with the same coverage instead of every input a run ever added.
#
#   scripts/merge-fuzz-corpus.sh <build-dir> <work-dir> [target ...]
#
# For each target with a corpus under <work-dir>/corpus/<target>, the fuzzer's
# -merge=1 mode picks the inputs that keep its coverage (the committed seeds count as
# already covered and are not copied), and the corpus is replaced by that set.
# A target whose merge fails keeps its corpus as it was and makes the script exit
# non-zero.

set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: merge-fuzz-corpus.sh <build-dir> <work-dir> [target ...]" >&2
  exit 2
fi

build_dir="$1"
work_dir="$2"
shift 2

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
seeds_root="$source_root/test/fuzz/corpus"

if [ "$#" -gt 0 ]; then
  targets=("$@")
else
  targets=()
  for dir in "$work_dir"/corpus/*/; do
    [ -d "$dir" ] && targets+=("$(basename "$dir")")
  done
fi

failed=0
for target in "${targets[@]}"; do
  corpus="$work_dir/corpus/$target"
  binary="$build_dir/fuzz/$target"
  if [ ! -d "$corpus" ] || [ ! -x "$binary" ]; then
    continue
  fi
  merged="$work_dir/merged/$target"
  rm -rf "$merged"
  mkdir -p "$merged" "$work_dir/logs"
  # Inputs already in the output directory count as covered, so starting it with
  # the committed seeds keeps only what the run found beyond them.
  cp "$seeds_root/$target"/* "$merged"/
  before="$(find "$corpus" -type f | wc -l)"
  if "$binary" -merge=1 -max_len=65536 -timeout=30 -rss_limit_mb=4096 \
      "$merged" "$corpus" > "$work_dir/logs/$target.merge.log" 2>&1; then
    for seed in "$seeds_root/$target"/*; do
      rm -f "$merged/$(basename "$seed")"
    done
    rm -rf "$corpus"
    mv "$merged" "$corpus"
    echo "$target: $before -> $(find "$corpus" -type f | wc -l) inputs"
  else
    echo "$target: merge failed, corpus kept (see logs/$target.merge.log)" >&2
    failed=1
  fi
done
rm -rf "$work_dir/merged"
exit "$failed"
