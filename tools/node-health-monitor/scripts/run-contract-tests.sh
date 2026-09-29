#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
"$root/scripts/bootstrap-contract-env.sh"
python="$root/.contract-venv/bin/python"
runtime_outputs="$(mktemp -d)"
trap 'rm -rf -- "$runtime_outputs"' EXIT
"$python" "$root/scripts/check-contracts.py"
NHM_CONTRACT_OUTPUT_DIR="$runtime_outputs" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-16}" \
  cargo test --manifest-path "$root/Cargo.toml" --locked -p tos-health-services \
    --test http all_six_success_handlers_emit_runtime_dtos -- --exact
NHM_CONTRACT_OUTPUT_DIR="$runtime_outputs" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-16}" \
  cargo test --manifest-path "$root/Cargo.toml" --locked -p tos-health-services \
    --test http runtime_coverage_aggregation_is_bounded_and_schema_ready -- --exact
NHM_CONTRACT_OUTPUT_DIR="$runtime_outputs" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-16}" \
  cargo test --manifest-path "$root/Cargo.toml" --locked -p tos-health-services \
    --test http edge_heartbeat_and_capabilities_emit_bounded_typed_wire -- --exact
NHM_CONTRACT_OUTPUT_DIR="$runtime_outputs" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-16}" \
  cargo test --manifest-path "$root/Cargo.toml" --locked -p tos-health-services \
    --test native_typed typed_sampler_and_edge_read_only_cache -- --exact
"$python" "$root/scripts/check-contracts.py" --runtime-output-dir "$runtime_outputs"
"$root/scripts/check-production-refusal.sh"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-16}" \
  cargo test --manifest-path "$root/Cargo.toml" --workspace --locked
