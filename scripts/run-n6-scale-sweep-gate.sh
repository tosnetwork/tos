#!/usr/bin/env bash
set -euo pipefail

source_root=${1:?source root is required}
build_root=${2:?build root is required}
profile=${3:?latency profile is required}
base_port=${4:?base port is required}

mkdir -p "$build_root/n6-scale-sweep-gates" "$build_root/n6-cluster-gates"
artifact_dir=$(mktemp -d "$build_root/n6-scale-sweep-gates/minimum-bft.XXXXXX")
rmdir "$artifact_dir"

(
  flock 9
  cd "$source_root"
  uv run test/tostester/generate_tl.py
) 9>"$build_root/n6-cluster-gates/tl-generation.lock"

cd "$source_root"
exec uv run python scripts/pq-n6-scale-sweep.py \
  --build-dir "$build_root" \
  --artifact-dir "$artifact_dir" \
  --profile "$profile" \
  --scales 4 \
  --base-port "$base_port"
