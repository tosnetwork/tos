#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT=${1:?output C++ path is required}
NAME=${2:-tos-service-stablecoin-escrow-v1}

"$REPO_ROOT/scripts/test-tos-service-stablecoin-escrow-v1.sh" >/dev/null
ENCODED=$(tr -d '[:space:]' < "$REPO_ROOT/crypto/smartcont/tos-service-stablecoin-escrow-v1.boc.base64")
printf 'with_tvm_code("%s", "%s");\n' "$NAME" "$ENCODED" > "$OUTPUT"
