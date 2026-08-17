#!/usr/bin/env bash
set -euo pipefail

# Regenerates the nominator pool bytecode the operator tool embeds.
#
# The hex constant exists because the tool derives pool addresses and builds
# deployment state-init offline, without a node. Keeping it hand-edited would
# let the deployed contract drift from the source everyone audits, so it is
# generated from the pinned build artifact instead.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUST_SOURCE=${1:-"$REPO_ROOT/tosctl/src/node-control/contracts/src/contract_codes.rs"}

BUILD_OUTPUT=$("$REPO_ROOT/scripts/build-nominator-pool-v1.sh")
HEX_FILE=$(printf '%s\n' "$BUILD_OUTPUT" | sed -n 's/^hex=\(.*\)$/\1/p')

python3 - "$RUST_SOURCE" "$HEX_FILE" <<'PY'
import pathlib
import re
import sys

target = pathlib.Path(sys.argv[1])
code_hex = pathlib.Path(sys.argv[2]).read_text().strip().lower()
source = target.read_text()
updated, count = re.subn(
    r'(NOMINATOR_POOL_CODE:\s*&str\s*=\s*")[0-9a-fA-F]*(")',
    lambda m: m.group(1) + code_hex + m.group(2),
    source,
)
if count != 1:
    raise SystemExit(f"expected exactly one NOMINATOR_POOL_CODE definition, found {count}")
if updated != source:
    target.write_text(updated)
    print(f"updated {target}")
else:
    print(f"{target} already current")
PY
