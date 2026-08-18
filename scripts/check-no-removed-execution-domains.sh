#!/usr/bin/env bash
set -euo pipefail

# Regression guard for ROADMAP.md's "Keep scans in CI to prevent removed
# execution domains from reappearing." This repo was stripped down to the
# native TVM execution path only (see doc/workchain-execution-registry.md);
# no other execution engine (e.g. EVM, Uno) should be reintroduced as a
# shortcut for AI actor / agent integration work.
#
# crosschain/ and its import/build/verify scripts are excluded: they vendor
# bridge contracts whose EVM half runs on external counterparty chains
# (Ethereum/BSC/...), not inside the TOS node. They register no execution
# engine and add no workchain descriptor; the TOS-side half is native TVM.

root="${1:-.}"
pattern='\b(evm|uno)\b'

matches="$(git -C "$root" ls-files -z -- \
    . \
    ':(exclude)third-party/**' \
    ':(exclude)crosschain/**' \
    ':(exclude)scripts/import-legacy-jusdt-bridge.py' \
    ':(exclude)scripts/verify-legacy-jusdt-bridge.py' \
    ':(exclude)scripts/build-legacy-jusdt-bridge.sh' \
    ':(exclude)scripts/import-legacy-toncoin-bridge.py' \
    ':(exclude)scripts/verify-legacy-toncoin-bridge.py' \
    ':(exclude)scripts/build-legacy-toncoin-bridge.sh' \
    ':(exclude)scripts/test-legacy-toncoin-bridge.sh' \
    ':(exclude)scripts/test-legacy-toncoin-bridge-evm.sh' \
    ':(exclude).github/workflows/legacy-jusdt-bridge.yml' \
    ':(exclude)scripts/check-no-removed-execution-domains.sh' \
    ':(exclude).github/workflows/no-removed-execution-domains-scan.yml' \
  | xargs -0 -r grep -InE "$pattern" || true)"

if [[ -n "$matches" ]]; then
  echo "$matches" >&2
  echo "removed-execution-domain scan failed: found a reference to a previously removed execution domain (EVM/Uno) outside third-party/." >&2
  echo "See doc/workchain-execution-registry.md for the native-TVM-only policy." >&2
  exit 1
fi

echo "removed-execution-domain scan passed"
