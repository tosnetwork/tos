#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

"$REPO_ROOT/scripts/build-tos-service-native-registry-v1.sh" "$TEST_DIR/first.boc" >/dev/null
"$REPO_ROOT/scripts/build-tos-service-native-registry-v1.sh" "$TEST_DIR/second.boc" >/dev/null
cmp "$TEST_DIR/first.boc" "$TEST_DIR/second.boc"
python3 - "$REPO_ROOT/crypto/smartcont/tos-service-native-registry-v1.boc.base64" "$TEST_DIR/frozen.boc" <<'PY'
import base64
import pathlib
import sys

encoded = b"".join(pathlib.Path(sys.argv[1]).read_bytes().split())
pathlib.Path(sys.argv[2]).write_bytes(base64.b64decode(encoded, validate=True))
PY
cmp "$TEST_DIR/first.boc" "$TEST_DIR/frozen.boc"

python3 - "$REPO_ROOT/crypto/smartcont/tos-service-native-registry-v1.release.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert manifest["schema"] == "tos.contract.release.v1"
assert manifest["protocol"] == "tos_service_v1"
assert manifest["code_hash"] == "tvm-cell-sha256:d3bb66d0011a1f362dd0be8408ed688f4e740d096a0e2dc2a79fc0ffc628b28a"
assert manifest["boc_sha256"] == "sha256:dcf41afaa7da7761839f3d26955ebab8dcd8adfe1d428b89229780c6647cdb9b"
assert manifest["boc_bytes"] == 4143
PY

printf 'TOS Native Service Registry v1 reproducible build: PASS\n'
