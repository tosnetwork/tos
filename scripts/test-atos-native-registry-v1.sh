#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

"$REPO_ROOT/scripts/build-atos-native-registry-v1.sh" "$TEST_DIR/first.boc" >/dev/null
"$REPO_ROOT/scripts/build-atos-native-registry-v1.sh" "$TEST_DIR/second.boc" >/dev/null
cmp "$TEST_DIR/first.boc" "$TEST_DIR/second.boc"
base64 --decode "$REPO_ROOT/crypto/smartcont/atos-native-registry-v1.boc.base64" > "$TEST_DIR/frozen.boc"
cmp "$TEST_DIR/first.boc" "$TEST_DIR/frozen.boc"

python3 - "$REPO_ROOT/crypto/smartcont/atos-native-registry-v1.release.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert manifest["schema"] == "tos.contract.release.v1"
assert manifest["protocol"] == "atos_native_v1"
assert manifest["code_hash"] == "tvm-cell-sha256:189c292404fe59293001c70ec568d8d38cd938d8bef92c7867e3268000808d1f"
assert manifest["boc_sha256"] == "sha256:a89aee64c9cfe924809fa4bd939c804842c86075d519bc81870b016d0d7fa56f"
assert manifest["boc_bytes"] == 3774
PY

printf 'ATOS Native Registry v1 reproducible build: PASS\n'
