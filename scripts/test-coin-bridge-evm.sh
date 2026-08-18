#!/usr/bin/env bash
set -euo pipefail

# Compiles the coin-bridge Solidity plane and runs its Truffle test suite
# against a local throwaway dev chain.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVM="$ROOT/crosschain/coin-bridge/evm"
GANACHE_PORT="${GANACHE_PORT:-8545}"

cd "$EVM"
npm ci --ignore-scripts --no-audit --no-fund

npx --no-install ganache --chain.networkId 666 --port "$GANACHE_PORT" \
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

npx --no-install truffle test
echo "Coin-bridge EVM contracts compiled and Truffle tests passed."
