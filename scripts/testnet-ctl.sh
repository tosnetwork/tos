#!/usr/bin/env bash
# Manage the four persistent local PQ validators independently.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
UNITS=(tos-pq-dht tos-pq-validator@1 tos-pq-validator@2 tos-pq-validator@3 tos-pq-validator@4)
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
        [[ "$node" =~ ^[1-4]$ ]] || { echo 'Node must be 1..4'; exit 2; }
        sudo tail -n 50 -F "/data/testnet/node$node/log" ;;
    uninstall)
        sudo systemctl disable --now "${UNITS[@]}"
        sudo rm -f /etc/systemd/system/tos-pq-dht.service /etc/systemd/system/tos-pq-validator@.service
        sudo systemctl daemon-reload ;;
    *) echo "Usage: $0 {install|start|stop|restart|status|check|deploy-pool|logs [1..4]|uninstall}"; exit 2 ;;
esac
