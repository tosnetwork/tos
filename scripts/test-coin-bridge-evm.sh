#!/usr/bin/env bash
set -euo pipefail

# Compiles the coin-bridge Solidity plane and runs its Truffle test suite
# against a local throwaway dev chain.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVM="$ROOT/crosschain/coin-bridge/evm"
GANACHE_PORT="${GANACHE_PORT:-8545}"
CHAIN_A_PORT="${CHAIN_A_PORT:-8546}"
CHAIN_B_PORT="${CHAIN_B_PORT:-8547}"

cd "$EVM"
npm ci --ignore-scripts --no-audit --no-fund

npx --no-install ganache --chain.chainId 666 --chain.networkId 666 --port "$GANACHE_PORT" \
  --wallet.mnemonic 'uphold wide shed another couch focus hidden soup lazy top salon salute' \
  >/dev/null 2>&1 &
ganache_pid=$!
ganache_a_pid=""
ganache_b_pid=""
cleanup() {
  kill "$ganache_pid" ${ganache_a_pid:+"$ganache_a_pid"} ${ganache_b_pid:+"$ganache_b_pid"} 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
  local port="$1"
  for _ in $(seq 1 30); do
    if node -e "require('net').connect($port, '127.0.0.1').on('connect', () => process.exit(0)).on('error', () => process.exit(1))"; then
      return
    fi
    sleep 1
  done
  echo "Ganache did not start on port $port" >&2
  exit 1
}

require_running() {
  local pid="$1"
  local label="$2"
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "$label exited before its RPC endpoint became ready" >&2
    exit 1
  fi
}

wait_for_port "$GANACHE_PORT"
require_running "$ganache_pid" "Ganache regression chain"

npx --no-install truffle compile --all
npx --no-install truffle test --compile-none

npx --no-install ganache --chain.chainId 7001 --chain.networkId 7001 --port "$CHAIN_A_PORT" \
  --wallet.mnemonic 'uphold wide shed another couch focus hidden soup lazy top salon salute' \
  >/dev/null 2>&1 &
ganache_a_pid=$!
npx --no-install ganache --chain.chainId 7002 --chain.networkId 7002 --port "$CHAIN_B_PORT" \
  --wallet.mnemonic 'uphold wide shed another couch focus hidden soup lazy top salon salute' \
  >/dev/null 2>&1 &
ganache_b_pid=$!
wait_for_port "$CHAIN_A_PORT"
wait_for_port "$CHAIN_B_PORT"
require_running "$ganache_a_pid" "Ganache chain A"
require_running "$ganache_b_pid" "Ganache chain B"

CHAIN_A_RPC="http://127.0.0.1:$CHAIN_A_PORT" \
CHAIN_B_RPC="http://127.0.0.1:$CHAIN_B_PORT" \
  node test/chainid-domain-separation.js

echo "Coin-bridge EVM contracts, Truffle suites, replay rejection, and golden vectors passed."
