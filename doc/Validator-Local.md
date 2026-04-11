# Local 3-Node TOS Testnet (Production-Style)

A production-style local testnet with 1 DHT node + 3 validators, managed as systemd services.

## Directory Layout

```
/data/
  tos-global.json                 # shared global config
  zerostate/                      # genesis state
    zerostate.boc / basestate0.boc
    *.fhash / *.rhash
    main-wallet.pk / .addr
    config-master.pk / .addr
  dht/                            # DHT bootstrap node
    keyring/ config.json db/
  tos1/                           # validator 1
    keyring/                      # Ed25519 private keys
    static/                       # symlinks to .boc by file hash
    db/                           # RocksDB persistent state
    config.json                   # local node config
    console-server.pub            # console public key
    keys.json                     # key metadata (for reference)
    log                           # node log
    session-logs                  # consensus stats
  tos2/                           # validator 2 (same structure)
  tos3/                           # validator 3 (same structure)
```

## systemd Services

| Service | Description |
|---------|-------------|
| `tos-dht` | DHT bootstrap server |
| `tos-validator@1` | Validator node 1 |
| `tos-validator@2` | Validator node 2 |
| `tos-validator@3` | Validator node 3 |

## Prerequisites

```bash
# Build from source (Clang 21 required)
cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21 ..
ninja
```

## Quick Start

```bash
# One-time setup: create /data/*, generate keys, zero state, configs, install services
sudo ./scripts/setup-testnet.sh

# Start the testnet
./scripts/testnet-ctl.sh start

# Check status
./scripts/testnet-ctl.sh status

# View logs
./scripts/testnet-ctl.sh logs       # all nodes
./scripts/testnet-ctl.sh logs 1     # validator 1 only

# Stop
./scripts/testnet-ctl.sh stop

# Clean restart
sudo ./scripts/setup-testnet.sh --clean
./scripts/testnet-ctl.sh start
```

## Management Commands

```bash
./scripts/testnet-ctl.sh install    # install systemd unit files
./scripts/testnet-ctl.sh start      # start dht + 3 validators
./scripts/testnet-ctl.sh stop       # graceful stop all
./scripts/testnet-ctl.sh restart    # stop + start
./scripts/testnet-ctl.sh status     # show service status
./scripts/testnet-ctl.sh logs [N]   # tail journald logs
./scripts/testnet-ctl.sh uninstall  # stop + remove services
```

Or use systemctl directly:

```bash
sudo systemctl start tos-dht
sudo systemctl start tos-validator@1
sudo systemctl stop tos-validator@2
sudo systemctl restart tos-validator@3
sudo journalctl -u tos-validator@1 -f
```

## Verifying the Network

```bash
# Connect with lite-client
./build/lite-client/lite-client -C /data/tos-global.json

# Inside lite-client:
> last                  # latest masterchain block
> getconfig 34          # current validator set (should show 3)
> getconfig 15          # election parameters
```

## Validator Console

```bash
./build/validator-engine-console/validator-engine-console \
  -a 127.0.0.1:<console-port> \
  -k /data/tos1/keyring/<console-client-key-id> \
  -p /data/tos1/console-server.pub
```

Console port for each node is in `keys.json` and printed during setup.

## Network Parameters

| Parameter | Value |
|-----------|-------|
| `global_id` | 3 (dev) |
| Validators | 3 |
| IP | 127.0.0.1 |
| DHT port | 3001 |
| Node 1 | port=3011, liteserver=3012, console=3013 |
| Node 2 | port=3021, liteserver=3022, console=3023 |
| Node 3 | port=3031, liteserver=3032, console=3033 |

## What setup-testnet.sh Does

1. Creates `/data/{zerostate,dht,tos1,tos2,tos3}` directory trees
2. Generates 5 Ed25519 keypairs per node (fullnode, validator, liteserver, console_server, console_client)
3. Writes keys to each node's `keyring/` in binary format (4-byte magic + 32-byte privkey)
4. Generates genesis zero state via `create-state` with:
   - `global_id = 3` (dev network)
   - All 3 validator public keys embedded
   - Standard smart contracts (wallet, elector, config)
5. Creates `static/` symlinks (file hash -> .boc)
6. Generates DHT signed address for peer discovery
7. Writes `/data/tos-global.json` with DHT nodes, zero_state hash, liteservers
8. Writes per-node `config.json` with ports, key IDs, validator config
9. Installs systemd services (`tos-dht`, `tos-validator@{1,2,3}`)

## Key Formats

**Keyring files** (`/data/tosN/keyring/<HEX_ID>`):
- Filename: uppercase hex of 32-byte short key ID
- Content: `\x17\x23\x68\x49` (4-byte magic) + 32-byte Ed25519 private key

**Console public key** (`/data/tosN/console-server.pub`):
- Content: `\xc6\xb4\x13\x48` (4-byte magic) + 32-byte Ed25519 public key

**keys.json** (reference only, not used by nodes):
- Maps role names to base64-encoded private/public/short_id

## Resetting the Network

```bash
./scripts/testnet-ctl.sh stop
sudo ./scripts/setup-testnet.sh --clean
./scripts/testnet-ctl.sh start
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Service fails immediately | Missing /data directories | Run `setup-testnet.sh` |
| `last` shows no blocks | Validators not synced yet | Wait 10-15 seconds |
| Connection refused | DHT not started | `systemctl start tos-dht` first |
| `getconfig 34` empty | Zero state issue | Reset with `--clean` |
| Port in use | Previous instance | `testnet-ctl.sh stop` then retry |

## Files

| File | Purpose |
|------|---------|
| `scripts/setup-testnet.sh` | One-time setup (keys, genesis, configs, services) |
| `scripts/testnet-ctl.sh` | Service management (start/stop/status/logs) |
| `scripts/tos-dht.service` | systemd unit for DHT node |
| `scripts/tos-validator@.service` | systemd template unit for validators |

## Related Docs

- [Validator.md](Validator.md) — Production validator operation
- [FullNode.md](FullNode.md) — Full node setup
