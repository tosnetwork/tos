#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT=${1:?output C++ path is required}
NAME=${2:-native-registry}

"$REPO_ROOT/scripts/test-tos-service-native-registry-v1.sh" >/dev/null
ENCODED=$(tr -d '[:space:]' < "$REPO_ROOT/crypto/smartcont/tos-service-native-registry-v1.boc.base64")
printf 'with_tvm_code("%s", "%s");\n' "$NAME" "$ENCODED" > "$OUTPUT"
