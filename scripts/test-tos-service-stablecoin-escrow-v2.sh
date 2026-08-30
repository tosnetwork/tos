#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT
"$REPO_ROOT/scripts/build-tos-service-stablecoin-escrow-v2.sh" "$TEST_DIR/first.boc" >/dev/null
"$REPO_ROOT/scripts/build-tos-service-stablecoin-escrow-v2.sh" "$TEST_DIR/second.boc" >/dev/null
cmp "$TEST_DIR/first.boc" "$TEST_DIR/second.boc"
python3 - "$REPO_ROOT/crypto/smartcont/tos-service-stablecoin-escrow-v2.boc.base64" "$TEST_DIR/frozen.boc" <<'PY'
import base64, pathlib, sys
encoded = b"".join(pathlib.Path(sys.argv[1]).read_bytes().split())
pathlib.Path(sys.argv[2]).write_bytes(base64.b64decode(encoded, validate=True))
PY
cmp "$TEST_DIR/first.boc" "$TEST_DIR/frozen.boc"
python3 - "$REPO_ROOT/crypto/smartcont/tos-service-stablecoin-escrow-v2.release.json" <<'PY'
import json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert manifest["schema"] == "tos.contract.release.v1"
assert manifest["protocol"] == "tos_service_stablecoin_escrow_v2"
assert manifest["code_hash"] == "tvm-cell-sha256:7404d4d631ee2af261816b90890c4e0ae6488b52c18f1aa64a55e5d1fb6af75d"
assert manifest["boc_sha256"] == "sha256:3bd234faf4c9163ce4f44d7fc1de0c952bab165efa2f568371f0b44de188c0fd"
assert manifest["boc_bytes"] == 2485
assert manifest["accepted_quote_schema"] == 2
assert manifest["initial_state"] == "pending_acceptance"
PY
printf 'TOS Service Protocol stablecoin escrow v2 reproducible build: PASS\n'
