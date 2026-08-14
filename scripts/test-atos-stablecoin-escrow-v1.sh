#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

"$REPO_ROOT/scripts/build-atos-stablecoin-escrow-v1.sh" "$TEST_DIR/first.boc" >/dev/null
"$REPO_ROOT/scripts/build-atos-stablecoin-escrow-v1.sh" "$TEST_DIR/second.boc" >/dev/null
cmp "$TEST_DIR/first.boc" "$TEST_DIR/second.boc"
python3 - "$REPO_ROOT/crypto/smartcont/atos-stablecoin-escrow-v1.boc.base64" "$TEST_DIR/frozen.boc" <<'PY'
import base64
import pathlib
import sys

encoded = b"".join(pathlib.Path(sys.argv[1]).read_bytes().split())
pathlib.Path(sys.argv[2]).write_bytes(base64.b64decode(encoded, validate=True))
PY
cmp "$TEST_DIR/first.boc" "$TEST_DIR/frozen.boc"

python3 - "$REPO_ROOT/crypto/smartcont/atos-stablecoin-escrow-v1.release.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert manifest["schema"] == "tos.contract.release.v1"
assert manifest["protocol"] == "atos_native_stablecoin_escrow_v1"
assert manifest["code_hash"] == "tvm-cell-sha256:c9df2f743534978ad5b521aab8c09c081ff56769769c00ee9e68eac7c681a685"
assert manifest["boc_sha256"] == "sha256:fdbb52a25b9e43f50cd27e03bbd2020245e2d8b31b76b5ff203454bfbc645048"
assert manifest["boc_bytes"] == 2020
PY

printf 'ATOS stablecoin escrow v1 reproducible build: PASS\n'
