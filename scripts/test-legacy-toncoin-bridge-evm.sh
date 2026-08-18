#!/usr/bin/env bash
set -euo pipefail

# Compiles the vendored Toncoin bridge Solidity plane and runs the upstream
# Truffle test suite against a local throwaway dev chain.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVM="$ROOT/crosschain/legacy-toncoin-bridge/evm"
GANACHE_PORT="${GANACHE_PORT:-8545}"

cd "$EVM"
npm install --ignore-scripts --no-audit --no-fund
npm install --ignore-scripts --no-audit --no-fund --no-save ganache@7.9.2

npx ganache --chain.networkId 666 --port "$GANACHE_PORT" \
  --wallet.mnemonic 'uphold wide shed another couch focus hidden soup lazy top salon salute' \
  >/dev/null 2>&1 &
ganache_pid=$!
trap 'kill "$ganache_pid" 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  if node -e "require('net').connect($GANACHE_PORT, '127.0.0.1').on('connect', () => process.exit(0)).on('error', () => process.exit(1))"; then
    break
  fi
  sleep 1
done

npx truffle test
echo "Toncoin bridge EVM contracts compiled and upstream Truffle tests passed."
