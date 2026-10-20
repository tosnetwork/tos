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
assert manifest["code_hash"] == "tvm-cell-sha256:c7958fb62e0a9d3c802e8171fe532b7fa260e10c4d85bba45e76d412701f6032"
assert manifest["boc_sha256"] == "sha256:85187bf23c9ebb2a2ead6b761234eea520c18044d9b6aa905859409e2ae7424b"
assert manifest["boc_bytes"] == 4027
PY

printf 'TOS Native Service Registry v1 reproducible build: PASS\n'
