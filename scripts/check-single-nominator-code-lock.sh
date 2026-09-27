#!/usr/bin/env bash
set -euo pipefail

# Verifies that every copy of the single-nominator contract's bytecode is the one its
# source compiles to.
#
# Three copies of the same fact exist in the tree: the FunC source, the checked-in hex
# artifact, and the hex the operator tool embeds when it derives an address or builds a
# deployment. A change to the source that is not carried to the other two deploys a
# different contract than the one the tests exercise, at an address derived from code
# nobody ran -- and nothing else in the tree notices.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FUNC_BIN=${FUNC_BIN:-"$REPO_ROOT/build/crypto/func"}
FIFT_BIN=${FIFT_BIN:-"$REPO_ROOT/build/crypto/fift"}

for binary in "$FUNC_BIN" "$FIFT_BIN"; do
  if [[ ! -x "$binary" ]]; then
    echo "required compiler is unavailable: $binary" >&2
    exit 1
  fi
done

BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

# Compiled against the tree's stdlib, which is the one the sandbox suite uses: a contract
# built against other definitions is another contract.
(
  cd "$REPO_ROOT/crypto/smartcont/single-nominator-pool"
  "$FUNC_BIN" -W "$BUILD_DIR/single-nominator.boc" -AP \
    -o "$BUILD_DIR/single-nominator.fif" ../stdlib.fc single-nominator-code.fc
)
FIFTPATH="$REPO_ROOT/crypto/fift/lib" "$FIFT_BIN" "$BUILD_DIR/single-nominator.fif"

BUILT_HEX=$(python3 - "$BUILD_DIR/single-nominator.boc" <<'PY'
import pathlib
import sys

print(pathlib.Path(sys.argv[1]).read_bytes().hex())
PY
)

status=0

ARTIFACT="$REPO_ROOT/crypto/smartcont/single-nominator-pool/single-nominator-code.hex"
ARTIFACT_HEX=$(tr -d '[:space:]' < "$ARTIFACT" | tr 'A-F' 'a-f')
if [[ "$ARTIFACT_HEX" != "$BUILT_HEX" ]]; then
  echo "the checked-in artifact is not what the source compiles to" >&2
  echo "  $ARTIFACT" >&2
  status=1
fi

RUST_SOURCE="$REPO_ROOT/tosctl/src/node-control/contracts/src/nominator/single_nominator.rs"
EMBEDDED_HEX=$(python3 - "$RUST_SOURCE" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text()
match = re.search(r'CODE_V1_1:\s*&\'static str\s*=\s*"([0-9a-fA-F]*)"', source)
print(match.group(1).lower() if match else "")
PY
)

if [[ -z "$EMBEDDED_HEX" ]]; then
  echo "CODE_V1_1 not found in $RUST_SOURCE" >&2
  status=1
elif [[ "$EMBEDDED_HEX" != "$BUILT_HEX" ]]; then
  echo "operator tool embeds bytecode that does not match the compiled source" >&2
  echo "  embedded ${#EMBEDDED_HEX} hex chars, compiled ${#BUILT_HEX}" >&2
  status=1
fi

if [[ "$status" -eq 0 ]]; then
  printf 'single-nominator code lock verified: %s bytes\n' "$(( ${#BUILT_HEX} / 2 ))"
fi

exit "$status"
