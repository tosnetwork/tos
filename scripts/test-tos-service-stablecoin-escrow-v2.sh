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
assert manifest["code_hash"] == "tvm-cell-sha256:b4a6bb10b9771b7a6fecec890c25c5f18e049db0e22997d37ca7c0a434cec4fe"
assert manifest["boc_sha256"] == "sha256:0e04680d011887f6ab4dfd059bd96b2ba647463170473356fccd6b4caab30e5e"
assert manifest["boc_bytes"] == 2589
assert manifest["accepted_quote_schema"] == 2
assert manifest["initial_state"] == "pending_acceptance"
PY
printf 'TOS Service Protocol stablecoin escrow v2 reproducible build: PASS\n'
