#!/bin/bash
# Run live integration tests against local TOS node.
#
# Usage:
#   ./scripts/test-live.sh
#
# Optional env vars:
#   TEST_MNEMONIC       - 24-word mnemonic for wallet tests (space-separated)
#   TEST_JETTON_MINTER  - raw address of a deployed JettonMinter contract
#
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Testing against local node at http://localhost:8081..."
echo ""

pnpm vitest run 'packages/client/src/__tests__/live'
