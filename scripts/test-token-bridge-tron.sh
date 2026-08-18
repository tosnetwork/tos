#!/usr/bin/env bash
set -euo pipefail

# Executes the token-bridge counterparty contracts inside Tron's virtual
# machine, using a throwaway local node. The Hardhat suite cannot cover this:
# it runs an EVM, and the questions here — what CHAINID returns to a contract
# and whether ecrecover behaves as the signature checker requires — only have
# answers on Tron.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVM="$ROOT/crosschain/token-bridge/evm"
# Pinned by digest: a floating tag would let the node image change under
# a green run, and these tests exist to measure that node's behaviour.
IMAGE="${TRON_TRE_IMAGE:-tronbox/tre@sha256:f4332e11df12a9f360639a4546fd046593909630fda48af00b30410c144342f0}"
PORT="${TRON_TRE_PORT:-9090}"

if ! command -v docker >/dev/null; then
  echo "docker is required to run a local Tron node" >&2
  exit 2
fi

# Start an unnamed container and clean up by the id docker returns, so a
# same-named container on the developer's machine is never touched. The RPC is
# published on the loopback interface only: it is a throwaway node holding
# published keys, and nothing on the network needs to reach it.
CONTAINER="$(docker run -d -p "127.0.0.1:$PORT:9090" "$IMAGE")"
trap 'docker rm -f "$CONTAINER" >/dev/null 2>&1 || true' EXIT

echo "waiting for the local Tron node to produce blocks..."
# The node answers HTTP before it finishes printing its funded accounts, so
# wait for the banner too rather than racing it.
ready=0
for _ in $(seq 1 90); do
  # Capture the log before matching: piping docker logs into grep -q lets grep
  # exit early, and under pipefail a truncated writer would read as not-ready.
  banner="$(docker logs "$CONTAINER" 2>&1 || true)"
  if curl -sf -X POST "http://127.0.0.1:$PORT/wallet/getnowblock" \
        -H 'Content-Type: application/json' >/dev/null 2>&1 \
     && [[ "$banner" == *"Private Keys"* ]]; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" -ne 1 ]]; then
  docker logs "$CONTAINER" 2>&1 | tail -20 >&2
  echo "the local Tron node did not come up" >&2
  exit 1
fi

# The image prints its funded accounts and their keys on startup. They exist
# only inside this container and are destroyed with it.
banner="$(docker logs "$CONTAINER" 2>&1)"
# A read loop rather than mapfile, which needs Bash 4; macOS still ships 3.2.
addresses=()
while IFS= read -r line; do
  [[ -n "$line" ]] && addresses+=("$line")
done < <(grep -oE '\(([0-9])\) T[1-9A-HJ-NP-Za-km-z]{33}' <<<"$banner" \
  | awk '{print $2}' | head -3 || true)
deployer_key="$(grep -A4 'Private Keys' <<<"$banner" \
  | grep -oE '\(0\) [0-9a-f]{64}' | awk '{print $2}' | head -1 || true)"

if [[ "${#addresses[@]}" -lt 3 || -z "$deployer_key" ]]; then
  echo "could not read funded accounts from the node's startup banner" >&2
  docker logs "$CONTAINER" 2>&1 | tail -30 >&2
  exit 1
fi

cd "$EVM"
npm ci --ignore-scripts --no-audit --no-fund

TRON_PRIVATE_KEY="$deployer_key" \
BRIDGE_ORACLES="$(IFS=,; echo "${addresses[*]}")" \
BRIDGE_DISABLED_TOKENS= \
TRON_DEVELOPMENT_HOST="http://127.0.0.1:$PORT" \
  npx tronbox test --network development

echo "Token-bridge contracts executed and verified inside Tron's virtual machine."
