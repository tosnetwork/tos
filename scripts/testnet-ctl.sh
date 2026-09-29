#!/usr/bin/env bash
# Manage local PQ validators, observers and the standalone lite-client.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
UNITS=(tos-pq-dht tos-pq-validator@1 tos-pq-validator@2 tos-pq-validator@3 tos-pq-validator@4 tos-pq-observer@5 tos-pq-observer@6 tos-pq-lite-client)
[[ ! -f /data/configs/node-7.json ]] || UNITS+=(tos-pq-validator@7 tos-pq-elections)
[[ ! -f /data/configs/transfer-test.json ]] || UNITS+=(tos-pq-transfers)
[[ ! -f /data/configs/privacy-test.json ]] || UNITS+=(tos-pq-privacy)
case "${1:-status}" in
    install) sudo systemctl daemon-reload; sudo systemctl enable "${UNITS[@]}" ;;
    start) sudo systemctl start "${UNITS[@]}" ;;
    stop) sudo systemctl stop "${UNITS[@]}" ;;
    restart) sudo systemctl restart "${UNITS[@]}" ;;
    status)
        for unit in "${UNITS[@]}"; do
            state=$(systemctl is-active "$unit" 2>/dev/null || true)
            printf '%-26s %s\n' "$unit" "$state"
        done
        if [[ -f /data/shielded-pool/deployment.json ]]; then
            python3 - <<'POOL'
import json
p=json.load(open('/data/shielded-pool/deployment.json'))
print('Shielded pool:', p['address'], '(local development key)')
POOL
        else echo 'Shielded pool: no verified deployment receipt'; fi ;;
    check) cd "$REPO"; uv run python scripts/local_pq_testnet.py check ;;
    deploy-pool) cd "$REPO"; sudo "$(command -v uv)" run python scripts/local_pq_testnet.py deploy ;;
    logs)
        node="${2:-1}"
        [[ "$node" =~ ^[1-6]$ ]] || { echo 'Node must be 1..6'; exit 2; }
        sudo tail -n 50 -F "/data/testnet/node$node/log" ;;
    uninstall)
        sudo systemctl disable --now "${UNITS[@]}"
        sudo rm -f /etc/systemd/system/tos-pq-dht.service /etc/systemd/system/tos-pq-validator@.service /etc/systemd/system/tos-pq-observer@.service /etc/systemd/system/tos-pq-lite-client.service
        sudo systemctl daemon-reload ;;
    *) echo "Usage: $0 {install|start|stop|restart|status|check|deploy-pool|logs [1..6]|uninstall}"; exit 2 ;;
esac
