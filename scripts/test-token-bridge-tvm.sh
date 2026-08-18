#!/usr/bin/env bash
set -euo pipefail

# Runs the TVM-level token-bridge tests against the vendored contract tree,
# using the TOS func/fift toolchain. The Node harness swallows child process
# failures, so success is asserted on the harness's own success marker.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT/crosschain/token-bridge"
TOOLDIR="$(cd "$(dirname "${FUNC:-$ROOT/build/crypto/func}")" && pwd)"
FIFT_PATHS="$ROOT/crypto/fift/lib"

if ! command -v node >/dev/null; then
  echo "node is required to run the TVM bridge tests" >&2
  exit 2
fi
if [[ ! -x "$TOOLDIR/func" || ! -x "$TOOLDIR/fift" ]]; then
  echo "func/fift not found in $TOOLDIR; build them with: cmake --build build --target func fift" >&2
  exit 2
fi

work_root="$(mktemp -d -t tos-token-bridge-test.XXXXXX)"
trap 'rm -rf "$work_root"' EXIT

total=0
for network in ethereum bsc polygon; do
  stage="$work_root/$network"
  mkdir -p "$stage/func" "$stage/test"
  cp "$PROJECT/tvm/contracts"/*.fc "$stage/func/"
  cp "$PROJECT/tvm/params/$network.fc" "$stage/func/params.fc"
  cp "$PROJECT/tvm/tests"/*.js "$stage/test/"
  cp "$ROOT/crosschain/tvm-test-harness/funcer.js" "$stage/test/"

  # Each network reads its own ConfigParam slot and asserts its own chain id.
  case "$network" in
    ethereum) slot=79; chain=1 ;;
    bsc)      slot=81; chain=56 ;;
    polygon)  slot=82; chain=137 ;;
  esac
  for js in "$stage"/test/*.js; do
    [[ "$(basename "$js")" == "funcer.js" ]] && continue
    CONFIG_SLOT="$slot" CHAIN_ID="$chain" python3 - "$js" <<'PY'
import os, re, sys
path = sys.argv[1]
with open(path) as handle:
    text = handle.read()
text = re.sub(r"^  79: \[", f"  {os.environ['CONFIG_SLOT']}: [", text, flags=re.M)
text = text.replace('"uint32", 1,          // EVM chain id',
                    f'"uint32", {os.environ["CHAIN_ID"]},          // EVM chain id')
with open(path, "w") as handle:
    handle.write(text)
PY
  done

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

echo "All $total TVM token-bridge tests passed under the TOS toolchain."
