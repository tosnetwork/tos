#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FUNC_BIN=${FUNC_BIN:-"$REPO_ROOT/build/crypto/func"}
FIFT_BIN=${FIFT_BIN:-"$REPO_ROOT/build/crypto/fift"}
OUTPUT=${1:-"$REPO_ROOT/crypto/smartcont/artifacts/atos-stablecoin-escrow-v1.boc"}
EXPECTED_CODE_HASH=c16bdd617d0f60aa071bcdc985af4ffa7b53d93aba983901961418302d58b3eb
EXPECTED_BOC_SHA256=5ceb9728ccfdb8691c2c84c01e0141fe44d314b8de913d48d3e95957c9ec2ec5
EXPECTED_BOC_BYTES=1971

for binary in "$FUNC_BIN" "$FIFT_BIN"; do
  if [[ ! -x "$binary" ]]; then
    echo "required compiler is unavailable: $binary" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "$OUTPUT")"
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

"$FUNC_BIN" -W "$OUTPUT" -AP -o "$BUILD_DIR/atos-stablecoin-escrow-v1.fif" \
  "$REPO_ROOT/crypto/smartcont/stdlib.fc" \
  "$REPO_ROOT/crypto/smartcont/atos-stablecoin-escrow-v1.fc"
FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" \
  "$BUILD_DIR/atos-stablecoin-escrow-v1.fif"

HASH_OUTPUT=$(FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" -s \
  "$REPO_ROOT/crypto/smartcont/hash-code-boc.fif" "$OUTPUT")
ACTUAL_CODE_HASH=$(printf '%s\n' "$HASH_OUTPUT" | sed -n 's/^tvm-cell-sha256:\([0-9a-f]*\).*/\1/p')
ACTUAL_CODE_HASH=$(printf '%064s' "$ACTUAL_CODE_HASH" | tr ' ' 0)
read -r ACTUAL_BOC_SHA256 ACTUAL_BOC_BYTES < <(python3 - "$OUTPUT" <<'PY'
import hashlib
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_bytes()
print(hashlib.sha256(raw).hexdigest(), len(raw))
PY
)

[[ "$ACTUAL_CODE_HASH" == "$EXPECTED_CODE_HASH" ]] || { echo "code hash mismatch: $ACTUAL_CODE_HASH" >&2; exit 1; }
[[ "$ACTUAL_BOC_SHA256" == "$EXPECTED_BOC_SHA256" ]] || { echo "BOC SHA-256 mismatch: $ACTUAL_BOC_SHA256" >&2; exit 1; }
[[ "$ACTUAL_BOC_BYTES" == "$EXPECTED_BOC_BYTES" ]] || { echo "BOC size mismatch: $ACTUAL_BOC_BYTES" >&2; exit 1; }

printf 'code_hash=tvm-cell-sha256:%s\n' "$ACTUAL_CODE_HASH"
printf 'boc_sha256=sha256:%s\n' "$ACTUAL_BOC_SHA256"
printf 'boc_bytes=%s\n' "$ACTUAL_BOC_BYTES"
printf 'output=%s\n' "$OUTPUT"
