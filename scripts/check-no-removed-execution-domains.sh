#!/usr/bin/env bash
set -euo pipefail

# Regression guard for ROADMAP.md's "Keep scans in CI to prevent removed
# execution domains from reappearing." This repo was stripped down to the
# native TVM execution path only (see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/workchain-execution-registry.md);
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
    ':(exclude)scripts/verify-token-bridge.py' \
    ':(exclude)scripts/build-token-bridge.sh' \
    ':(exclude)scripts/verify-coin-bridge.py' \
    ':(exclude)scripts/build-coin-bridge.sh' \
    ':(exclude)scripts/test-coin-bridge-tvm.sh' \
    ':(exclude)scripts/test-coin-bridge-evm.sh' \
    ':(exclude)scripts/test-token-bridge-tvm.sh' \
    ':(exclude)scripts/test-token-bridge-tron.sh' \
    ':(exclude).github/workflows/bridge-validation.yml' \
    ':(exclude)scripts/check-no-removed-execution-domains.sh' \
    ':(exclude).github/workflows/no-removed-execution-domains-scan.yml' \
  | xargs -0 -r grep -InE "$pattern" || true)"

if [[ -n "$matches" ]]; then
  echo "$matches" >&2
  echo "removed-execution-domain scan failed: found a reference to a previously removed execution domain (EVM/Uno) outside third-party/." >&2
  echo "See https://github.com/tosnetwork/doc/blob/main/tos-blockchain/workchain-execution-registry.md for the native-TVM-only policy." >&2
  exit 1
fi

echo "removed-execution-domain scan passed"
