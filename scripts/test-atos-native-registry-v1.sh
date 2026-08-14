#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

"$REPO_ROOT/scripts/build-atos-native-registry-v1.sh" "$TEST_DIR/first.boc" >/dev/null
"$REPO_ROOT/scripts/build-atos-native-registry-v1.sh" "$TEST_DIR/second.boc" >/dev/null
cmp "$TEST_DIR/first.boc" "$TEST_DIR/second.boc"
python3 - "$REPO_ROOT/crypto/smartcont/atos-native-registry-v1.boc.base64" "$TEST_DIR/frozen.boc" <<'PY'
import base64
import pathlib
import sys

encoded = b"".join(pathlib.Path(sys.argv[1]).read_bytes().split())
pathlib.Path(sys.argv[2]).write_bytes(base64.b64decode(encoded, validate=True))
PY
cmp "$TEST_DIR/first.boc" "$TEST_DIR/frozen.boc"

python3 - "$REPO_ROOT/crypto/smartcont/atos-native-registry-v1.release.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert manifest["schema"] == "tos.contract.release.v1"
assert manifest["protocol"] == "atos_native_v1"
assert manifest["code_hash"] == "tvm-cell-sha256:600f2fda83462bc86a1c32af930c35a4fc8f80f1d2966f5593ceba217a91ffa0"
assert manifest["boc_sha256"] == "sha256:e9845e6d7acda368f1d5ba8e7d32aa0f21022d36816ca33ec31e1b21348a6fcc"
assert manifest["boc_bytes"] == 3763
PY

printf 'ATOS Native Registry v1 reproducible build: PASS\n'
