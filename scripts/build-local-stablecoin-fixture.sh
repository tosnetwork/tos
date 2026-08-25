#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUTPUT=${1:?usage: build-local-stablecoin-fixture.sh <master-code.boc>}
FUNC_BIN=${FUNC_BIN:-"$REPO_ROOT/build/crypto/func"}
FIFT_BIN=${FIFT_BIN:-"$REPO_ROOT/build/crypto/fift"}
SOURCE="$REPO_ROOT/crypto/smartcont/reference/usdt-jetton-master/contracts"
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

build_one() {
  local target=$1
  "$FUNC_BIN" -SPA "$SOURCE/jetton-minter.fc" -W "$target" -o "$TEST_DIR/master.fif"
  "$FIFT_BIN" -I "$REPO_ROOT/crypto/fift/lib" "$TEST_DIR/master.fif"
}

build_one "$TEST_DIR/first.boc"
build_one "$TEST_DIR/second.boc"
cmp "$TEST_DIR/first.boc" "$TEST_DIR/second.boc"
install -m 0600 "$TEST_DIR/first.boc" "$OUTPUT"
