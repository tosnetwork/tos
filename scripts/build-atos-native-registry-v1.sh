#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FUNC_BIN=${FUNC_BIN:-"$REPO_ROOT/build/crypto/func"}
FIFT_BIN=${FIFT_BIN:-"$REPO_ROOT/build/crypto/fift"}
OUTPUT=${1:-"$REPO_ROOT/crypto/smartcont/artifacts/atos-native-registry-v1.boc"}
EXPECTED_CODE_HASH=600f2fda83462bc86a1c32af930c35a4fc8f80f1d2966f5593ceba217a91ffa0
EXPECTED_BOC_SHA256=e9845e6d7acda368f1d5ba8e7d32aa0f21022d36816ca33ec31e1b21348a6fcc
EXPECTED_BOC_BYTES=3763

for binary in "$FUNC_BIN" "$FIFT_BIN"; do
  if [[ ! -x "$binary" ]]; then
    echo "required compiler is unavailable: $binary" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "$OUTPUT")"
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

"$FUNC_BIN" -W "$OUTPUT" -AP -o "$BUILD_DIR/native-registry-v1.fif" \
  "$REPO_ROOT/crypto/smartcont/stdlib.fc" \
  "$REPO_ROOT/crypto/smartcont/native-registry-code.fc"
FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" \
  "$BUILD_DIR/native-registry-v1.fif"

HASH_OUTPUT=$(FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" -s \
  "$REPO_ROOT/crypto/smartcont/hash-code-boc.fif" "$OUTPUT")
ACTUAL_CODE_HASH=$(printf '%s\n' "$HASH_OUTPUT" | sed -n 's/^tvm-cell-sha256:\([0-9a-f]*\).*/\1/p')
ACTUAL_CODE_HASH=$(printf '%064s' "$ACTUAL_CODE_HASH" | tr ' ' 0)
BOC_METADATA=$(python3 - "$OUTPUT" <<'PY'
import hashlib
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_bytes()
print(hashlib.sha256(raw).hexdigest(), len(raw))
PY
)
read -r ACTUAL_BOC_SHA256 ACTUAL_BOC_BYTES <<< "$BOC_METADATA"

if [[ "$ACTUAL_CODE_HASH" != "$EXPECTED_CODE_HASH" ]]; then
  echo "code hash mismatch: $ACTUAL_CODE_HASH" >&2
  exit 1
fi
if [[ "$ACTUAL_BOC_SHA256" != "$EXPECTED_BOC_SHA256" ]]; then
  echo "BOC SHA-256 mismatch: $ACTUAL_BOC_SHA256" >&2
  exit 1
fi
if [[ "$ACTUAL_BOC_BYTES" != "$EXPECTED_BOC_BYTES" ]]; then
  echo "BOC size mismatch: $ACTUAL_BOC_BYTES" >&2
  exit 1
fi

printf 'code_hash=tvm-cell-sha256:%s\n' "$ACTUAL_CODE_HASH"
printf 'boc_sha256=sha256:%s\n' "$ACTUAL_BOC_SHA256"
printf 'boc_bytes=%s\n' "$ACTUAL_BOC_BYTES"
printf 'output=%s\n' "$OUTPUT"
