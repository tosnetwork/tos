#!/usr/bin/env bash
# Run the tos31 persistent-state / CellDb state-sync verification suite.
#
# Default mode runs the deterministic CI-sized checks. Release-candidate
# mode can opt into the full 16 GiB catch-up via env:
#
#   TOS_RUN_16GIB_CATCHUP=1 bash scripts/run-tos31-state-sync-verification.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
ARTIFACT_DIR="${TOS_VERIFY_ARTIFACT_DIR:-$ROOT/build/tos31-state-sync-$(date -u +%Y%m%dT%H%M%SZ)}"

mkdir -p "$ARTIFACT_DIR"

exec > >(tee "$ARTIFACT_DIR/driver.log") 2>&1

run_step() {
  local name="$1"
  shift
  echo
  echo "### $name"
  echo "+ $*"
  "$@" 2>&1 | tee "$ARTIFACT_DIR/${name//[^A-Za-z0-9_.-]/_}.log"
}

echo "tos31 state-sync verification"
echo "root=$ROOT"
echo "build_dir=$BUILD_DIR"
echo "artifact_dir=$ARTIFACT_DIR"
echo "git_commit=$(git -C "$ROOT" rev-parse HEAD)"
echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
uname -a
df -h "$ROOT" "$ARTIFACT_DIR" || true

run_step build-download-state-budget \
  cmake --build "$BUILD_DIR" --target test-download-state-budget
run_step build-celldb-streaming-import \
  cmake --build "$BUILD_DIR" --target test-celldb-streaming-import
run_step build-celldb-actor-restart \
  cmake --build "$BUILD_DIR" --target test-celldb-actor-restart
run_step celldb-fatal-invariant-audit \
  bash -c 'root="$1"; rg -n "CELDB_LEGACY_FATAL_INVARIANT" "$root/validator/db/celldb.cpp"' _ "$ROOT"
run_step test-download-state-budget \
  "$BUILD_DIR/test-download-state-budget"
run_step test-celldb-streaming-import \
  "$BUILD_DIR/test-celldb-streaming-import"
run_step test-celldb-actor-restart \
  "$BUILD_DIR/test-celldb-actor-restart"

if [ "${TOS_RUN_16GIB_CATCHUP:-0}" != "0" ] && [ -n "${TOS_RUN_16GIB_CATCHUP:-}" ]; then
  run_step test-download-state-budget-16gib \
    env TOS_FAST_TESTS=1 TOS_RUN_16GIB_CATCHUP=1 "$BUILD_DIR/test-download-state-budget"
else
  echo
  echo "### test-download-state-budget-16gib"
  echo "SKIPPED: set TOS_RUN_16GIB_CATCHUP=1 to run the real 16 GiB mmap catch-up test"
fi

cat > "$ARTIFACT_DIR/summary.txt" <<EOF
tos31 state-sync verification completed
commit: $(git -C "$ROOT" rev-parse HEAD)
artifacts: $ARTIFACT_DIR

required default checks:
- celldb-fatal-invariant-audit
- test-download-state-budget
- test-celldb-streaming-import
- test-celldb-actor-restart

optional RC checks:
- TOS_RUN_16GIB_CATCHUP=1
EOF

echo
echo "tos31 state-sync verification completed: $ARTIFACT_DIR"
