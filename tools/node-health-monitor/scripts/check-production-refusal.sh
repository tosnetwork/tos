#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
output="$(mktemp)"
trap 'rm -f -- "$output"' EXIT
set +e
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-16}" cargo run --quiet \
  --manifest-path "$root/Cargo.toml" --locked --bin health-contract-check -- \
  "$root/config/resource-profile.json" "$root/config/acceptance-evidence.json" >"$output"
status=$?
set -e
if [[ $status -eq 0 ]]; then
  echo "production doctor unexpectedly accepted placeholder evidence" >&2
  exit 1
fi
"$root/.contract-venv/bin/python" - "$output" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]))
assert value["actual_host_verification"] is False
required={"contiguous_work_budget","source_admission","summary_only","independent_watchdog","mtls_acl","effective_resources","validator_core","observer_coverage","performance","zero_upstream","failure_domains"}
assert required == set(value["missing"]), value
print("PASS: production doctor refused 11 unverified gates (exit nonzero)")
PY
