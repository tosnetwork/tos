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
assert manifest["code_hash"] == "tvm-cell-sha256:c4af55e476c296c8a1dc7985e82db42218475b9e3864b7c733351bab526ab23d"
assert manifest["boc_sha256"] == "sha256:09f08082798e4637eee982812c41001e8062805298790f8d1d596e4dbc40bb27"
assert manifest["boc_bytes"] == 2685
PY

printf 'ATOS Native Registry v1 reproducible build: PASS\n'
