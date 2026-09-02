#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FUNC_BIN=${FUNC_BIN:-"$REPO_ROOT/build/crypto/func"}
FIFT_BIN=${FIFT_BIN:-"$REPO_ROOT/build/crypto/fift"}
OUTPUT=${1:-"$REPO_ROOT/crypto/smartcont/artifacts/tos-service-stablecoin-escrow-v2.boc"}
EXPECTED_CODE_HASH=8bb0b7c809b9abfc8c3446a6a283f8cf4278c31dadc7f3bbd377d984e7d27544
EXPECTED_BOC_SHA256=cb6ca9b958230c55222d521e29c7222cb24121fdc48e9add1edc696f2860b2f0
EXPECTED_BOC_BYTES=2609

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
