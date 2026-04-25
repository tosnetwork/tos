#!/usr/bin/env bash
#
# setup-testnet.sh - Set up a local 4-node TOS testnet using the tested Python infrastructure.
#
# Usage:  sudo ./scripts/setup-testnet.sh [--clean]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO_ROOT/build"
DATA="/data"
LOCKFILE="/tmp/tos-setup.lock"
INSTALL_BIN="/usr/local/bin"
INSTALL_SHARE="/usr/local/share/tos"

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run with sudo"; exit 1; }
exec 200>"$LOCKFILE"
flock -n 200 || { echo "ERROR: another setup is running"; exit 1; }

for bin in validator-engine/validator-engine dht-server/dht-server \
           validator-engine-console/validator-engine-console \
           lite-client/lite-client utils/generate-random-id; do
    [ -x "$BUILD/$bin" ] || { echo "ERROR: $BUILD/$bin not found. Run ninja."; exit 1; }
done

# ── Clean ─────────────────────────────────────────────────────────
if [ "${1:-}" = "--clean" ]; then
    echo "Stopping services..."
    "$REPO_ROOT/scripts/testnet-ctl.sh" stop 2>/dev/null || true
    echo "Cleaning $DATA/..."
    for d in zerostate dht tos1 tos2 tos3 tos4 testnet; do rm -rf "${DATA:?}/$d"; done
    rm -f "${DATA:?}/tos-global.json"
fi

# ── System user ───────────────────────────────────────────────────
id -u tos &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin tos
echo "System user 'tos' ready."

# ── Install binaries ──────────────────────────────────────────────
echo "Installing binaries to $INSTALL_BIN..."
install -m0755 "$BUILD/validator-engine/validator-engine"                "$INSTALL_BIN/tos-validator-engine"
install -m0755 "$BUILD/dht-server/dht-server"                           "$INSTALL_BIN/tos-dht-server"
install -m0755 "$BUILD/validator-engine-console/validator-engine-console" "$INSTALL_BIN/tos-validator-console"
install -m0755 "$BUILD/lite-client/lite-client"                          "$INSTALL_BIN/tos-lite-client"
install -m0755 "$BUILD/utils/generate-random-id"                         "$INSTALL_BIN/tos-genkey"

mkdir -p "$INSTALL_SHARE/fift/lib" "$INSTALL_SHARE/smartcont/auto"
cp -r "$REPO_ROOT/crypto/fift/lib"/* "$INSTALL_SHARE/fift/lib/"
cp "$REPO_ROOT/crypto/smartcont"/*.fif "$INSTALL_SHARE/smartcont/" 2>/dev/null || true
cp "$REPO_ROOT/crypto/smartcont"/auto/* "$INSTALL_SHARE/smartcont/auto/" 2>/dev/null || true
cp "$REPO_ROOT/crypto/smartcont"/stdlib.fc "$INSTALL_SHARE/smartcont/" 2>/dev/null || true

# ── Run Python setup (uses the tested network.py infrastructure) ──
echo ""
echo "Running network setup via Python..."
mkdir -p "$DATA/testnet"
chown tos:tos "$DATA" "$DATA/testnet"

# Python script that uses the tested tostester infrastructure
cd "$REPO_ROOT"
UV=$(which uv 2>/dev/null || echo "$HOME/.local/bin/uv")
if [ ! -x "$UV" ]; then
    echo "ERROR: uv not found. Install with: pip install uv"
    exit 1
fi
$UV run python3 <<'PYEOF'
import asyncio, json, os, sys, base64, hashlib
from pathlib import Path
from ipaddress import IPv4Address

from tostester.install import Install
from tostester.network import Network, FullNode

REPO = Path(os.environ.get("REPO_ROOT", Path.home() / "tos"))
BUILD = REPO / "build"
DATA = Path("/data")
TESTNET = DATA / "testnet"

install = Install(BUILD, REPO)

async def setup():
    async with Network(install, TESTNET) as network:
        # Create DHT node
        dht = network.create_dht_node(threads=2)

        # Create 3 validators
        nodes = []
        for _ in range(4):
            node = network.create_full_node(threads=4)
            node.make_initial_validator()
            node.announce_to(dht)
            nodes.append(node)

        # Trigger zerostate generation
        zs = network._get_or_generate_zerostate()
        print(f"Zero state generated:")
        print(f"  root_hash: {base64.b64encode(zs.masterchain.root_hash).decode()}")
        print(f"  file_hash: {base64.b64encode(zs.masterchain.file_hash).decode()}")

        # Prepare each node's directory (without starting the processes)
        # This creates keyring, static symlinks, config files
        for i, node in enumerate(nodes):
            # Populate static dir
            static_dir = node._directory / "static"
            static_dir.mkdir(exist_ok=True)
            for state in (zs.masterchain, zs.shardchain, zs.evmchain, zs.unochain):
                link = static_dir / state.file_hash.hex().upper()
                if not link.exists():
                    link.symlink_to(state.file)

        from tosapi import tos_api

        # Build global config (for validator-engine)
        global_config = tos_api.Config_global(
            dht=tos_api.Dht_config_global(
                static_nodes=tos_api.Dht_nodes(nodes=[dht._signed_address]),
                k=6, a=3,
            ),
            validator=zs.as_validator_config(),
        )

        # Convert to dict and manually add liteservers (for lite-client compatibility)
        gc_dict = json.loads(global_config.to_json())
        ip_int = int(IPv4Address("127.0.0.1"))
        gc_dict["liteservers"] = [
            {
                "ip": ip_int,
                "port": n._liteserver_addr.port,
                "id": {"@type": "pub.ed25519", "key": base64.b64encode(n._liteserver_key.public_key.key).decode()},
            }
            for n in nodes
        ]
        gc_path = DATA / "tos-global.json"
        gc_path.write_text(json.dumps(gc_dict, indent=2))

        # Export per-node configs
        for i, node in enumerate(nodes):
            idx = i + 1
            svc_dir = DATA / f"tos{idx}"
            svc_dir.mkdir(exist_ok=True)

            # Symlink keyring and static
            for item in ["keyring", "static"]:
                src = node._directory / item
                dst = svc_dir / item
                if dst.is_symlink():
                    dst.unlink()
                if not dst.exists():
                    os.symlink(src, dst)

            # Write local config
            (svc_dir / "config.json").write_text(node._local_config.to_json())

            # Console pub key
            node._engine_console_server_key.write_pub_key_file(svc_dir / "console-server.pub")

            print(f"  tos{idx}: dir={node._directory}")
            print(f"    validator:  127.0.0.1:{node._addr.port}")
            print(f"    liteserver: 127.0.0.1:{node._liteserver_addr.port}")
            print(f"    console:    127.0.0.1:{node._engine_console_addr.port}")
            print(f"    json-rpc:   127.0.0.1:{8010 + idx}  (eth_*)")

        # DHT node config
        dht_dir = DATA / "dht"
        dht_dir.mkdir(exist_ok=True)
        if not (dht_dir / "keyring").exists():
            os.symlink(dht._directory / "keyring", dht_dir / "keyring")
        (dht_dir / "config.json").write_text(dht._local_config.to_json())

        # Port info for systemd generation. EVM JSON-RPC ports are 8011..8014
        # (allocated in the bash side after this Python block).
        port_info = {"dht_port": dht._addr.port, "nodes": [
            {"idx": i+1, "validator_port": n._addr.port,
             "liteserver_port": n._liteserver_addr.port,
             "console_port": n._engine_console_addr.port,
             "jsonrpc_port": 8010 + i + 1}
            for i, n in enumerate(nodes)
        ]}
        (DATA / "testnet-ports.json").write_text(json.dumps(port_info, indent=2))

        print(f"\n  Global config: {gc_path}")
        print(f"  DHT config: {dht_dir / 'config.json'}")

asyncio.run(setup())
PYEOF

echo ""
echo "Setting permissions..."
chown -R tos:tos "$DATA"
# Lock down keyrings
find "$DATA" -name keyring -type d -exec chmod 0700 {} \;
find "$DATA" -name keyring -type d -exec sh -c 'chmod 0600 "$1"/*' _ {} \;
chmod 0644 "$DATA/tos-global.json"

# ── Generate systemd units from port info ─────────────────────────
echo "Generating systemd service files..."

PORTS=$(cat "$DATA/testnet-ports.json")
DHT_PORT=$(echo "$PORTS" | python3 -c "import json,sys; print(json.load(sys.stdin)['dht_port'])")

# DHT service
cat > /etc/systemd/system/tos-dht.service <<SVCEOF
[Unit]
Description=TOS DHT Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tos
Group=tos
UMask=0077
WorkingDirectory=/data/dht
ExecStart=$INSTALL_BIN/tos-dht-server \\
  --global-config /data/tos-global.json \\
  --local-config /data/dht/config.json \\
  --db /data/dht \\
  --threads 2
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVCEOF

# Validator services
for i in 1 2 3 4; do
    NODE_DIR="$DATA/tos$i"
    TESTNET_NODE_DIR=$(echo "$PORTS" | python3 -c "import json,sys; d=json.load(sys.stdin); n=[x for x in d['nodes'] if x['idx']==$i][0]; print(n)")

    # JSON-RPC HTTP port for eth_* methods (one per validator: 8011..8014)
    JSONRPC_PORT=$((8010 + i))

    cat > "/etc/systemd/system/tos-validator@${i}.service" <<SVCEOF
[Unit]
Description=TOS Validator Node $i
After=network-online.target tos-dht.service
Wants=network-online.target tos-dht.service

[Service]
Type=simple
User=tos
Group=tos
UMask=0077
# UNO dev-mode mining target = 2^252 (BE byte[0]=0x10, others=0). Semantics:
# hash < target is valid, so LARGER target means EASIER. 2^252 gives ~1/16
# probability per Poseidon2 hash — a single CPU thread finds a valid nonce
# in microseconds. Matches kDevMineTargetBE in uno/core/mine_constants.h.
#
# NOTE: This env var is ONLY honored by validator binaries built with
# -DUNO_DEVNET_ALLOW_ENV_TARGET=ON. Production builds (the default) ignore
# it and select the target from the zerostate global_id via
# select_init_mine_target() — which already returns kDevMineTargetBE for
# global_id == 3 (the local-dev id). For most local testnets you do not
# need this env line at all; rebuild with the dev flag only if you must
# override the target outside the dev global_id.
#
# NEVER set this on mainnet — it would let anyone mint all 21 M UNO instantly
# (and an env-honoring binary would never have shipped to mainnet anyway).
Environment=UNO_INIT_MINE_TARGET_HEX=1000000000000000000000000000000000000000000000000000000000000000
WorkingDirectory=$NODE_DIR
ExecStart=$INSTALL_BIN/tos-validator-engine \\
  -C /data/tos-global.json \\
  -c $NODE_DIR/config.json \\
  -D $NODE_DIR \\
  -f $INSTALL_SHARE/fift/lib \\
  --initial-sync-delay 5 \\
  --session-logs $NODE_DIR/session-logs \\
  --quic-flood-control -1 \\
  --json-rpc-address 127.0.0.1:$JSONRPC_PORT \\
  -l $NODE_DIR/log \\
  -t 4
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVCEOF
done

systemctl daemon-reload
systemctl enable tos-dht tos-validator@1 tos-validator@2 tos-validator@3 tos-validator@4

echo ""
echo "=========================================="
echo " Setup complete!"
echo ""
echo " Start:   ./scripts/testnet-ctl.sh start"
echo " Stop:    ./scripts/testnet-ctl.sh stop"
echo " Status:  ./scripts/testnet-ctl.sh status"
echo " Logs:    ./scripts/testnet-ctl.sh logs"
echo ""
echo " Lite client:"
echo "   tos-lite-client -C $DATA/tos-global.json"
echo "=========================================="

flock -u 200
