#!/usr/bin/env bash
set -euo pipefail

# Runs the upstream TVM-level bridge tests against the vendored contract tree,
# using the TOS func/fift toolchain. The upstream Node harness swallows child
# process failures, so success is asserted on the harness's own success marker.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT/crosschain/legacy-toncoin-bridge"
TOOLDIR="$(cd "$(dirname "${FUNC:-$ROOT/build/crypto/func}")" && pwd)"
FIFT_PATHS="$ROOT/crypto/fift/lib:$ROOT/crosschain/fift-compat"

if ! command -v node >/dev/null; then
  echo "node is required to run the upstream bridge tests" >&2
  exit 2
fi
if [[ ! -x "$TOOLDIR/func" || ! -x "$TOOLDIR/fift" ]]; then
  echo "func/fift not found in $TOOLDIR; build them with: cmake --build build --target func fift" >&2
  exit 2
fi

declare -A upstream_for=(
  [ethereum]="tvm-ethereum"
  [bsc]="tvm-bsc"
)

work_root="$(mktemp -d -t tos-toncoin-test.XXXXXX)"
trap 'rm -rf "$work_root"' EXIT

total=0
for network in ethereum bsc; do
  stage="$work_root/$network"
  mkdir -p "$stage/func" "$stage/test"
  cp "$PROJECT/tvm/$network"/*.fc "$stage/func/"
  cp "$PROJECT/upstream/${upstream_for[$network]}/test"/*.js "$stage/test/"
  for test_js in "$stage"/test/*.js; do
    name="$(basename "$test_js")"
    [[ "$name" == "funcer.js" ]] && continue
    output="$(cd "$stage" && PATH="$TOOLDIR:$PATH" FIFTPATH="$FIFT_PATHS" node "test/$name" 2>&1)" || {
      echo "$output" | tail -20 >&2
      echo "FAIL ($network): $name (node exited non-zero)" >&2
      exit 1
    }
    if ! grep -q "All tests passed" <<<"$output"; then
      echo "$output" | tail -20 >&2
      echo "FAIL ($network): $name (missing success marker)" >&2
      exit 1
    fi
    total=$((total + 1))
    echo "PASS ($network): $name"
  done
done

echo "All $total upstream TVM bridge tests passed under the TOS toolchain."
