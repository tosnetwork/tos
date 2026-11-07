#!/usr/bin/env bash
# Red/green controls and native replay for the attested Service Actor gas tests.
#
#   test/service-actor/attested_gas_controls.sh controls
#       Applies attested-gas-mutation.patch to the sandbox test, builds once and
#       runs the two attested tests five times: unmutated (must pass), with the
#       asserted allowance shrunk for the attested admission, the response and
#       the refund (each must fail its headroom assertion), and with the
#       negative control signed by the attestor itself (must fail because the
#       refused response succeeds). Restores the test file on exit.
#   test/service-actor/attested_gas_controls.sh replay <empty-trace-dir> <libemulator.so>
#       Records the two attested tests' transactions, requires exactly six
#       admission/response records and four payout records, and replays them
#       in the native engine.
#
# Needs FUNC_PATH and FIFT_PATH (the solvency fixture compiles the contract).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_FILE=tosctl/src/node-control/contracts/tests/service_actor_sandbox.rs
ADMISSION=solvency_attested_gas_at_capacity_with_sparse_ids_and_wide_accounting
PAYOUTS=solvency_attested_payout_gas_at_capacity_with_sparse_ids_and_wide_coins

run_attested() {
  (cd "$ROOT/tosctl/src" && env "$@" cargo test -p contracts --test service_actor_sandbox \
    -- --test-threads=1 --exact "$ADMISSION" "$PAYOUTS")
}

expect_red() {
  local name=$1 message=$2 log
  shift 2
  log=$(mktemp)
  if run_attested "$@" >"$log" 2>&1; then
    echo "$name: passed but must fail" >&2
    exit 1
  fi
  if ! grep -qF "$message" "$log"; then
    echo "$name: failed without the expected message: $message" >&2
    tail -20 "$log" >&2
    exit 1
  fi
  echo "$name: red as expected ($message)"
  rm -f "$log"
}

case "${1:-}" in
  controls)
    git -C "$ROOT" diff --quiet -- "$TEST_FILE" || { echo "$TEST_FILE has local changes" >&2; exit 1; }
    trap 'git -C "$ROOT" checkout -- "$TEST_FILE"' EXIT
    git -C "$ROOT" apply "$ROOT/test/service-actor/attested-gas-mutation.patch"
    run_attested CONTROL=1 >/dev/null 2>&1 || { echo "unmutated control failed" >&2; exit 1; }
    echo "control: green"
    expect_red admission "admit-attested/new-caller: measured execution cost must leave at least 25% allowance headroom" \
      SHRINK_LABEL=admit-attested SHRINK_TO=62000000
    expect_red respond "respond-attested/new-caller: measured execution cost must leave at least 25% allowance headroom" \
      SHRINK_LABEL=respond-attested SHRINK_TO=65000000
    expect_red refund "refund-attested: measured execution cost must leave at least 25% allowance headroom" \
      SHRINK_LABEL=refund-attested SHRINK_TO=47000000
    expect_red negative-control "expected first transaction to be aborted, but it succeeded" \
      SWAP_NEGATIVE=1
    echo "ATTESTED_GAS_CONTROLS_OK"
    ;;
  replay)
    trace=${2:?empty trace directory}
    emulator=${3:?path to libemulator.so}
    mkdir -p "$trace"
    [[ -z "$(ls -A "$trace")" ]] || { echo "$trace is not empty" >&2; exit 1; }
    run_attested SERVICE_ACTOR_TRACE_DIR="$trace"
    python3 - "$trace" "$ADMISSION" "$PAYOUTS" <<'PY'
import pathlib
import sys

trace, admission, payouts = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
files = sorted(path for path in trace.rglob("*") if path.is_file())
admitted = sorted((trace / admission).glob("*.json"))
paid = sorted((trace / payouts).glob("*.json"))
if len(admitted) != 6 or len(paid) != 4 or files != sorted(admitted + paid):
    sys.exit(f"trace population is {len(admitted)}+{len(paid)} of {len(files)} files, not exactly 6+4")
print("TRACE_POPULATION_OK 6+4")
PY
    python3 "$ROOT/scripts/replay-token-bridge-trace.py" "$trace" --emulator "$emulator"
    ;;
  *)
    sed -n '2,16p' "${BASH_SOURCE[0]}" >&2
    exit 2
    ;;
esac
