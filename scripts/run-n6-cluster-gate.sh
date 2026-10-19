#!/usr/bin/env bash
set -euo pipefail

source_root=${1:?source root is required}
build_root=${2:?build root is required}
scenario=${3:?scenario is required}
base_port=${4:?base port is required}

mkdir -p "$build_root/n6-cluster-gates"
artifact_dir=$(mktemp -d "$build_root/n6-cluster-gates/${scenario}.XXXXXX")
rmdir "$artifact_dir"

# The generated Python TL package is a shared source-tree artifact. Serialize
# that one generation step; validator databases, ports, logs, traces and
# resource outputs remain disjoint and the node processes may run concurrently.
(
  flock 9
  cd "$source_root"
  uv run test/tostester/generate_tl.py
) 9>"$build_root/n6-cluster-gates/tl-generation.lock"

cd "$source_root"
exec uv run python scripts/pq-n6-cluster.py \
  --build-dir "$build_root" \
  --artifact-dir "$artifact_dir" \
  --scenario "$scenario" \
  --base-port "$base_port"
