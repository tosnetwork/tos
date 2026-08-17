#!/usr/bin/env bash
set -euo pipefail

# Verifies that every place which claims to know the nominator pool's bytecode
# agrees with what the source actually compiles to.
#
# Three copies of the same fact exist in the tree: the compiled artifact, the
# hex the operator tool embeds when it deploys or address-derives a pool, and
# the code hash the node uses to decide whether an account is presented to
# users as a staking pool. If they drift apart, a nominator can be shown a
# "nominator pool" that is not the contract in this repository.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_OUTPUT=$("$REPO_ROOT/scripts/build-nominator-pool-v1.sh")

CODE_HASH=$(printf '%s\n' "$BUILD_OUTPUT" | sed -n 's/^code_hash=tvm-cell-sha256:\(.*\)$/\1/p')
HEX_FILE=$(printf '%s\n' "$BUILD_OUTPUT" | sed -n 's/^hex=\(.*\)$/\1/p')
BUILT_HEX=$(tr -d '[:space:]' < "$HEX_FILE")

RUST_SOURCE="$REPO_ROOT/tosctl/src/node-control/contracts/src/contract_codes.rs"
CPP_SOURCE="$REPO_ROOT/validator-engine/json-rpc-server-account-capability.cpp"

status=0

EMBEDDED_HEX=$(python3 - "$RUST_SOURCE" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text()
match = re.search(r'NOMINATOR_POOL_CODE:\s*&str\s*=\s*"([0-9a-fA-F]*)"', source)
print(match.group(1).lower() if match else "")
PY
)

if [[ -z "$EMBEDDED_HEX" ]]; then
  echo "NOMINATOR_POOL_CODE not found in $RUST_SOURCE" >&2
  status=1
elif [[ "$EMBEDDED_HEX" != "$BUILT_HEX" ]]; then
  echo "operator tool embeds bytecode that does not match the compiled source" >&2
  echo "  embedded ${#EMBEDDED_HEX} hex chars, compiled ${#BUILT_HEX}" >&2
  echo "  run: scripts/embed-nominator-pool-v1.sh" >&2
  status=1
fi

REGISTERED=$(python3 - "$CPP_SOURCE" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text()
print("\n".join(sorted(
    hash_hex.lower()
    for hash_hex in re.findall(r'\{"([0-9A-Fa-f]{64})",\s*"nominator pool[^"]*"\}', source)
)))
PY
)

if [[ "$REGISTERED" != "$CODE_HASH" ]]; then
  echo "node recognizes a nominator pool code hash set that is not exactly the compiled one" >&2
  echo "  compiled:   $CODE_HASH" >&2
  echo "  registered: ${REGISTERED:-<none>}" >&2
  echo "  every registered hash must be reproducible from crypto/smartcont/nominator-pool" >&2
  status=1
fi

if [[ "$status" -eq 0 ]]; then
  printf 'nominator pool code lock verified: %s\n' "$CODE_HASH"
fi

exit "$status"
