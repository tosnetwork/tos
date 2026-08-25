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
assert manifest["code_hash"] == "tvm-cell-sha256:889f7254f37c21735a4da33f902f70b08d01b9393e6b5bc4cf78d85406afd9ce"
assert manifest["boc_sha256"] == "sha256:63f4fa1cedebcd20c99d340ebe451703001d612109dbaa5050e57f84d695aac7"
assert manifest["boc_bytes"] == 2347
assert manifest["accepted_quote_schema"] == 2
assert manifest["initial_state"] == "pending_acceptance"
PY
printf 'TOS Service Protocol stablecoin escrow v2 reproducible build: PASS\n'
