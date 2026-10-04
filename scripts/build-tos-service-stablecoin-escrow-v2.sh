#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# These defaults are only a convenience for a developer invoking this script
# directly. CMake's frozen-artifact rule passes its just-built target paths.
FUNC_BIN=${FUNC_BIN:-"$REPO_ROOT/build/crypto/func"}
FIFT_BIN=${FIFT_BIN:-"$REPO_ROOT/build/crypto/fift"}
OUTPUT=${1:-"$REPO_ROOT/crypto/smartcont/artifacts/tos-service-stablecoin-escrow-v2.boc"}
EXPECTED_CODE_HASH=5a2ee6f907a03738d2eef3586ece125ebd6e10b8dbd91408e0fa4a3fd2bf51ba
EXPECTED_BOC_SHA256=324f7d5fca5edd0a00728daad9e59bf15e158545cc4a39dae17aab2f0f12e9a7
EXPECTED_BOC_BYTES=2864

for binary in "$FUNC_BIN" "$FIFT_BIN"; do
  [[ -x "$binary" ]] || { echo "required compiler is unavailable: $binary" >&2; exit 1; }
done
mkdir -p "$(dirname "$OUTPUT")"
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT
"$FUNC_BIN" -W "$OUTPUT" -AP -o "$BUILD_DIR/escrow-v2.fif" \
  "$REPO_ROOT/crypto/smartcont/stdlib.fc" \
  "$REPO_ROOT/crypto/smartcont/tos-service-stablecoin-escrow-v2.fc"
FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" "$BUILD_DIR/escrow-v2.fif"
HASH_OUTPUT=$(FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" -s \
  "$REPO_ROOT/crypto/smartcont/hash-code-boc.fif" "$OUTPUT")
ACTUAL_CODE_HASH=$(printf '%s\n' "$HASH_OUTPUT" | sed -n 's/^tvm-cell-sha256:\([0-9a-f]*\).*/\1/p')
ACTUAL_CODE_HASH=$(printf '%064s' "$ACTUAL_CODE_HASH" | tr ' ' 0)
read -r ACTUAL_BOC_SHA256 ACTUAL_BOC_BYTES < <(python3 - "$OUTPUT" <<'PY'
import hashlib, pathlib, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
print(hashlib.sha256(raw).hexdigest(), len(raw))
PY
)
[[ "$ACTUAL_CODE_HASH" == "$EXPECTED_CODE_HASH" ]]
[[ "$ACTUAL_BOC_SHA256" == "$EXPECTED_BOC_SHA256" ]]
[[ "$ACTUAL_BOC_BYTES" == "$EXPECTED_BOC_BYTES" ]]
printf 'code_hash=tvm-cell-sha256:%s\nboc_sha256=sha256:%s\nboc_bytes=%s\noutput=%s\n' \
  "$ACTUAL_CODE_HASH" "$ACTUAL_BOC_SHA256" "$ACTUAL_BOC_BYTES" "$OUTPUT"
