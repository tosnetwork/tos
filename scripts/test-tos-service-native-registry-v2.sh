#!/usr/bin/env bash
set -euo pipefail

# pwd -W gives a Windows path under Git Bash, which the native Windows compilers
# and FIFTPATH need; elsewhere the plain path is used.
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && { pwd -W 2>/dev/null || pwd; })
PYTHON3=${PYTHON3:-python3}
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

"$REPO_ROOT/scripts/build-tos-service-native-registry-v2.sh" "$TEST_DIR/first.boc" >/dev/null
"$REPO_ROOT/scripts/build-tos-service-native-registry-v2.sh" "$TEST_DIR/second.boc" >/dev/null
cmp "$TEST_DIR/first.boc" "$TEST_DIR/second.boc"
"$PYTHON3" - "$REPO_ROOT/crypto/smartcont/tos-service-native-registry-v2.boc.base64" "$TEST_DIR/frozen.boc" <<'PY'
import base64
import pathlib
import sys

encoded = b"".join(pathlib.Path(sys.argv[1]).read_bytes().split())
pathlib.Path(sys.argv[2]).write_bytes(base64.b64decode(encoded, validate=True))
PY
cmp "$TEST_DIR/first.boc" "$TEST_DIR/frozen.boc"

"$PYTHON3" - "$REPO_ROOT/crypto/smartcont/tos-service-native-registry-v2.release.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert manifest["schema"] == "tos.contract.release.v1"
assert manifest["protocol"] == "tos_service_v1"
assert manifest["code_hash"] == "tvm-cell-sha256:688537813d5e089a3caae0f9607141c917b222da5437f91187a9b38c38f2212a"
assert manifest["boc_sha256"] == "sha256:5e2b64f29e31d2898141c1b176be37b06bc8c15dfb90f20f77cc0113f6918bf1"
assert manifest["boc_bytes"] == 4302
PY

printf 'TOS Native Service Registry v2 reproducible build: PASS\n'
