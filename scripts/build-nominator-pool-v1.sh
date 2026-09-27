#!/usr/bin/env bash
set -euo pipefail

# Compiles the multi-nominator staking pool from source and pins the result.
#
# A nominator hands custody of their principal to whatever bytecode sits at the
# pool address, so the only thing that makes the arrangement auditable is being
# able to rebuild that bytecode from this repository and compare hashes. The
# expected values below are the lock: a source change that alters the compiled
# code fails this script until the new hashes are reviewed and recorded here,
# and the same values gate the node's contract recognition table and the
# operator tool's embedded copy.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# These defaults are only a convenience for a developer invoking this script
# directly. This tree has no CMake frozen-artifact rule for the nominator pool;
# callers that require a particular toolchain must pass both paths explicitly.
FUNC_BIN=${FUNC_BIN:-"$REPO_ROOT/build/crypto/func"}
FIFT_BIN=${FIFT_BIN:-"$REPO_ROOT/build/crypto/fift"}
OUTPUT=${1:-"$REPO_ROOT/crypto/smartcont/artifacts/nominator-pool-v1.boc"}
EXPECTED_CODE_HASH=df8be95f5b48a3731445d0a33aa92e349677de01556e597713025599da14e61d
EXPECTED_BOC_SHA256=72371e4c5b24555d0903d912ba1ccd105dafb8bf9fa1333f7c1b4a3d97761a14
EXPECTED_BOC_BYTES=2593

for binary in "$FUNC_BIN" "$FIFT_BIN"; do
  if [[ ! -x "$binary" ]]; then
    echo "required compiler is unavailable: $binary" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "$OUTPUT")"
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

# pool.fc includes its own bundled stdlib.fc, so it compiles standalone from
# its source directory.
(
  cd "$REPO_ROOT/crypto/smartcont/nominator-pool"
  "$FUNC_BIN" -W "$OUTPUT" -AP -o "$BUILD_DIR/nominator-pool-v1.fif" pool.fc
)
FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" \
  "$BUILD_DIR/nominator-pool-v1.fif"

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

python3 - "$OUTPUT" "${OUTPUT}.hex" <<'PY'
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_bytes()
pathlib.Path(sys.argv[2]).write_text(raw.hex() + "\n")
PY

printf 'code_hash=tvm-cell-sha256:%s\n' "$ACTUAL_CODE_HASH"
printf 'boc_sha256=sha256:%s\n' "$ACTUAL_BOC_SHA256"
printf 'boc_bytes=%s\n' "$ACTUAL_BOC_BYTES"
printf 'output=%s\n' "$OUTPUT"
printf 'hex=%s\n' "${OUTPUT}.hex"
