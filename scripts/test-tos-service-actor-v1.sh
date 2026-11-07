#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FUNC_BIN=${FUNC_BIN:-"$REPO_ROOT/build/crypto/func"}
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

"$REPO_ROOT/scripts/build-tos-service-actor-v1.sh" "$TEST_DIR/first.boc" > "$TEST_DIR/first.txt"
"$REPO_ROOT/scripts/build-tos-service-actor-v1.sh" "$TEST_DIR/second.boc" >/dev/null
cmp "$TEST_DIR/first.boc" "$TEST_DIR/second.boc"
python3 "$REPO_ROOT/scripts/tos_service_actor_release.py" \
  "$TEST_DIR/first.boc" "$TEST_DIR/first.txt" "$FUNC_BIN"

printf 'TOS Service Actor v1 reproducible build: PASS\n'
