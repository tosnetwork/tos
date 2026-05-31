# Local 3-Node TOS Testnet Setup Guide

This document records the exact steps used to configure and run a production-style local TOS testnet with 3 validator nodes on a single machine. This setup serves as the reference for future production deployments. The cluster size is chosen to match the canonical BFT-2/3 quorum (`tos/quorum.h`): 2 of 3 votes are sufficient to reach consensus, so the network keeps producing blocks while one validator is offline.

## Three-chain topology

The local testnet carries **three independent workchains** under one validator set and one masterchain:

| wc  | Chain                        | vm_version                      | Role                              | Total supply | Distribution                                           |
|-----|------------------------------|---------------------------------|-----------------------------------|--------------|--------------------------------------------------------|
| `-1` | **masterchain**              | (reserved)                      | Consensus / config                | —            | —                                                      |
| `0` | **TOS** (native TVM)         | `-1` (TVM)                      | Primary smart-contract chain      | 100 M TOS    | 10 × PoW Givers + ~3 K TOS system reserve              |
| `1` | **eTOS** (EVM)               | `0x45564D` ("EVM") = `4544077`  | Ethereum-compatible chain (evmone)| 100 M eTOS   | 10 genesis EToSPoWGiver contracts (10 M each); `chainId=0x544F53` (5 525 331); JSON-RPC at `127.0.0.1:801N` |
| `2` | **UNO** (privacy / STARK)    | `0x554E4F31` ("UNO1") = `1431195441` | Zcash/Penumbra-style privacy payments with Plonky3 STARK proofs, Bitcoin-clone halving | 21 M UNO | **Empty at genesis — 0 pre-funded accounts, all UNO mined.** Mining via `tosctl-uno mine` (CPU Poseidon2, 600 s target, 50 UNO/solve, halving every 210 K solves) |

> **wc=3 (Avata JVM) is intentionally absent from this local testnet.** The
> tostester pipeline that `setup-testnet.sh` drives uses its own zerostate
> template (`test/tostester/src/tostester/zerostate.py`) which wires only
> wc=0/1/2. The production generator `crypto/smartcont/gen-zerostate.fif`
> *does* register wc=3 (empty, `stdlib_hash = 0`) via `add-jvm-workchain`, but
> the tostester path does not. So this local cluster runs three chains; see
> [`jvm-mainnet-activation.md`](jvm-mainnet-activation.md) for the wc=3 bring-up.

All three chains share the **same validator set**, the **same catchain consensus**, and the **same** `/data/tos-global.json`. Deployment is a single `setup-testnet.sh` invocation — no per-chain activation flag is needed; wc=1 and wc=2 are wired into the zerostate from birth (via `add-evm-workchain-v2` + `add-uno-workchain-v2` in `test/tostester/src/tostester/zerostate.py`). Verify post-genesis with:

```bash
tos-lite-client -C /data/tos-global.json -v 0 -c "getconfig 12" -c "quit" \
  | grep -E "vm_version"
# Expect three leaves:
#   vm_version:-1          → wc=0 TVM
#   vm_version:4544077     → wc=1 EVM      (0x45564D)
#   vm_version:1431195441  → wc=2 UNO1     (0x554E4F31)
```

Production deployments may deliberately use a staged workchain rollout instead
of this local-testnet all-at-genesis layout. EVM (`wc=1`), Uno (`wc=2`), and JVM
(`wc=3`) can be activated in separate `ConfigParam 12` updates at different
masterchain heights. The effective switch is the block where the accepted config
update becomes active and the descriptor is present with `active=true`; the
current runtime does not use `enabled_since` as an automatic future-height
scheduler. Before each activation, all validators that may be assigned to the
target shard must already run a binary containing the matching engine, must have
the matching workchain zerostate/static files available, and must have any
engine-specific params staged (`vm_mode` chain id for EVM, ConfigParam 84 for
Uno, ConfigParam 85 for JVM). See
[workchain-execution-registry.md](workchain-execution-registry.md#staged-workchain-activation)
and [ConfigParam.md](ConfigParam.md#activation-semantics).

Per-chain details are at [EVM Workchain (Workchain 1)](#evm-workchain-workchain-1) and [UNO Workchain (Workchain 2)](#uno-workchain-workchain-2) below.

## Architecture

```
                          ┌────────────────────────┐
                          │  /data/tos-global.json  │  shared global config
                          │  (DHT + zero_state +    │  (used by all nodes
                          │   liteservers)          │   and lite-client)
                          └───────────┬────────────┘
                ┌──────────────┬──────┴──────┬──────────────┐
                │              │             │              │
        ┌───────▼────────┐  ┌──▼────────────┐  ┌────────────▼───┐
        │  tos-validator  │  │ tos-validator │  │ tos-validator  │
        │      @1         │  │     @2        │  │      @3        │
        │  /data/tos1/    │  │  /data/tos2/  │  │  /data/tos3/   │
        │  UDP:2002       │  │  UDP:2005     │  │  UDP:2008      │
        │  LS:2003        │  │  LS:2006      │  │  LS:2009       │
        │  Console:2004   │  │  Console:2007 │  │  Console:2010  │
        └─────────────────┘  └───────────────┘  └────────────────┘
                │                  │                  │
                └──────────────────┼──────────────────┘
                          ┌────────▼────────────────┐
                          │     DHT bootstrap       │
                          │  node0 (port 2001)      │
                          │  (runs as part of       │
                          │   validator @1 process) │
                          └─────────────────────────┘
```

All nodes bind to `127.0.0.1`. The DHT bootstrap node runs inside the validator @1 process. Node 1 also acts as the DHT seed for peer discovery.

## Directory Layout

The setup creates two directory trees:

**Working tree** (generated by Python `tostester.Network` class):
```
/data/testnet/
  state/                          # zero state .boc files
  node0/                          # DHT node (keyring only)
    keyring/
  node1/                          # validator 1 working data
    keyring/                      # Ed25519 private keys (binary)
    static/                       # symlinks: file_hash -> .boc
  node2/                          # validator 2
  node3/                          # validator 3
```

**Service tree** (symlinked from working tree, used by systemd):
```
/data/
  tos-global.json                 # global config (DHT + zero_state + liteservers)
  testnet-ports.json              # port mapping reference
  dht/
    keyring -> ../testnet/node0/keyring
    config.json                   # DHT local config
  tos1/
    keyring -> ../testnet/node1/keyring
    static -> ../testnet/node1/static
    config.json                   # validator local config
    console-server.pub            # console server public key
    log                           # node log (runtime)
    session-logs                  # consensus stats (runtime)
    db/                           # RocksDB state (runtime)
    ...                           # other runtime dirs created by validator-engine
  tos2/                           # same structure
  tos3/                           # same structure
```

## Port Allocation

| Node | UDP (validator) | TCP (liteserver) | TCP (console) |
|------|-----------------|------------------|---------------|
| DHT  | 2001            | -                | -             |
| tos1 | 2002            | 2003             | 2004          |
| tos2 | 2005            | 2006             | 2007          |
| tos3 | 2008            | 2009             | 2010          |

Ports are auto-assigned by the `tostester.Network` class starting from base port 2000.

All three workchains (wc=0 TVM, wc=1 EVM, wc=2 UNO) share the same per-node UDP/TCP ports above — they are separated by workchain id inside the validator, not by network port. Chain-specific access surfaces:

| Chain | Access surface          | Port per node (nodes 1..3) |
|-------|-------------------------|----------------------------|
| wc=0  | Liteserver (lite-client)| 2003 / 2006 / 2009         |
| wc=1  | Liteserver **and** Ethereum-compatible JSON-RPC (`eth_*`) | Liteserver 2003 / 2006 / 2009; JSON-RPC 8011 / 8012 / 8013 |
| wc=2  | Liteserver only (no dedicated UNO RPC surface yet — `tosctl-uno` talks via the standard liteserver / a companion RPC daemon; see §UNO Workchain below) | 2003 / 2006 / 2009         |

## systemd Services

| Service | Unit File | Description |
|---------|-----------|-------------|
| `tos-dht` | `/etc/systemd/system/tos-dht.service` | DHT bootstrap (runs dht-server) |
| `tos-validator@1` | `/etc/systemd/system/tos-validator@1.service` | Validator node 1 |
| `tos-validator@2` | `/etc/systemd/system/tos-validator@2.service` | Validator node 2 |
| `tos-validator@3` | `/etc/systemd/system/tos-validator@3.service` | Validator node 3 |

Service unit files are generated per-instance (not templates) because each node has unique ports and paths. All services run as system user `tos` with the following hardening:

```ini
User=tos
Group=tos
UMask=0077
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
LimitNOFILE=65536
Restart=on-failure
RestartSec=5
```

## Prerequisites

**Build from source:**
```bash
# Clang 21 required
mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21 ..
ninja
```

**Python tooling:**
```bash
uv sync --no-dev
uv run test/tostester/generate_tl.py
```

## Step-by-Step Setup Procedure

### Step 1: Run the setup script

```bash
sudo REPO_ROOT=$(pwd) ./scripts/setup-testnet.sh --clean
```

The `--clean` flag stops any running services and removes previous `/data/` contents.

### Step 2: What the script does internally

1. **Creates system user** `tos` (nologin shell, no home directory)

2. **Installs binaries** to `/usr/local/bin/`:
   | Source | Installed as |
   |--------|-------------|
   | `build/validator-engine/validator-engine` | `tos-validator-engine` |
   | `build/dht-server/dht-server` | `tos-dht-server` |
   | `build/validator-engine-console/validator-engine-console` | `tos-validator-console` |
   | `build/lite-client/lite-client` | `tos-lite-client` |
   | `build/utils/generate-random-id` | `tos-genkey` |

3. **Installs Fift libraries** to `/usr/local/share/tos/fift/lib/` and `/usr/local/share/tos/smartcont/`

4. **Runs Python setup** using `uv run` with the `tostester.Network` class:
   - Creates 1 DHT node + 3 full nodes via `network.create_dht_node()` and `network.create_full_node()`
   - Marks all 3 as initial validators via `node.make_initial_validator()`
   - Each node announces itself to the DHT node via `node.announce_to(dht)`
   - Triggers zero state generation via `network._get_or_generate_zerostate()`

5. **Zero state generation** (inside Python):
   - Uses `crypto/smartcont/gen-zerostate-test.fif` template
   - Sets `global_id = 3` (dev network)
   - Embeds 3 validator public keys via `add-validator`
   - Runs `build/crypto/create-state` with Fift include paths
   - Produces the four BoC blobs the network needs, plus their hash files and deterministic wallet / elector / config addresses:
     | File                 | Contents                                               |
     |----------------------|--------------------------------------------------------|
     | `zerostate.boc`      | Masterchain (wc=-1) zerostate                          |
     | `basestate0.boc`     | wc=0 TVM shardstate (TOS)                              |
     | `evmstate1.boc`      | wc=1 EVM shardstate (eTOS) — activated by `add-evm-workchain` |
     | `unostate2.boc`      | wc=2 UNO shardstate (privacy) — activated by `add-uno-workchain` (tostester, commit `b3bf82b26`) |

   Per-workchain wiring:

   | wc | vm_version                         | Total supply   | Genesis distribution                                                                 |
   |----|------------------------------------|----------------|--------------------------------------------------------------------------------------|
   | 0  | `-1` (TVM)                         | 100 M TOS      | PoW Giver skeleton + `TM$3000` system reserve (elector / config / stage wallets)     |
   | 1  | `0x45564D` ("EVM") = `4544077`     | 100 M eTOS     | 10 genesis EToSPoWGiver contracts × 10 M eTOS each; no public Hardhat accounts in production genesis |
   | 2  | `0x554E4F31` ("UNO1") = `1431195441` | 21 M UNO max  | **Empty shardstate — 0 pre-funded accounts.** All 21 M must be mined (CPU Poseidon2 PoW, 600 s target, 50 UNO/solve, Bitcoin-clone halving every 210 K solves). `mkemptyShardState` in `gen-zerostate.fif:69`. |

   All three supplies are economically independent — no on-chain bridge between any pair. See [Zerostate.md §Initial Token Supply](Zerostate.md#initial-token-supply-per-workchain-issuance) for configuration points — supply values live in `gen-zerostate.fif:94` (TOS), `evm/core/init.cpp::kSeedAmountETos` (eTOS), and `uno/core/genesis.h::kGenesisTotalSupplyNano` (UNO).

6. **Key generation** (per node, inside Python):
   - 5 Ed25519 keypairs per node: fullnode, validator, liteserver, console_server, console_client
   - Generated via `build/utils/generate-random-id -m id`
   - Private keys written to `keyring/` as binary: `\x17\x23\x68\x49` (4-byte magic) + 32-byte seed
   - Filenames: uppercase hex of sha256(TL-serialized public key)

7. **DHT signed address** (for peer discovery):
   - Generated via `generate-random-id -m dht -k <keyfile> -a <address_list_json>`
   - Produces a signed DHT node entry with public key, address, and Ed25519 signature

8. **Global config** (`/data/tos-global.json`):
   - Format matches [tos.network/global-config.json](https://tos.network/global-config.json)
   - Contains: `dht` (with signed static_nodes), `validator` (with zero_state block ID), `liteservers` (array of ip+port+pubkey)
   - `liteservers` field is added manually (not part of TL `config.global` type, but needed by lite-client)

9. **Local configs** (`/data/tosN/config.json`):
   - TL type: `engine.validator.config`
   - Contains: `addrs`, `adnl` (fullnode + validator IDs), `dht`, `validators` (with temp_keys and adnl_addrs), `fullnode`, `liteservers`, `control` (console server + allowed clients)
   - Generated by `tostester.Network.FullNode` class which correctly populates all TL-required fields

10. **Sets permissions**:
    - All `/data/` owned by `tos:tos`
    - All `keyring/` directories: `0700`
    - All key files inside keyrings: `0600`
    - Global config: `0644`

11. **Generates systemd unit files** directly into `/etc/systemd/system/` and enables them

### Step 3: Start the network

```bash
./scripts/testnet-ctl.sh start
```

Output:
```
Starting TOS testnet...
All services started.
  tos-dht                  active
  tos-validator@1          active
  tos-validator@2          active
  tos-validator@3          active
```

### Step 4: Verify block production

```bash
tos-lite-client -C /data/tos-global.json -v 0 -c "time" -c "last" -c "quit"
```

Expected output (after ~5 seconds):
```
server version is 1.1, capabilities 7
latest masterchain block known to server is (-1,8000000000000000,N)
  created at <timestamp> (X seconds ago)
```

The `time` command forces an initial connection. The `last` command shows the latest masterchain block with an increasing seqno.

### Step 5: Verify validator set

```bash
tos-lite-client -C /data/tos-global.json -v 0 -c "time" -c "getconfig 34" -c "quit"
```

Expected output includes:
```
cur_validators:(validators_ext ... total:3 main:3 total_weight:51
  ... weight:17
  ... weight:17
  ... weight:17
```

All 3 validators active with equal weight. Quorum threshold (`tos::quorum_threshold(51)`) is `34`, so any 2 of 3 validators (combined weight 34) are sufficient to reach consensus.

## Management

### Service control

```bash
./scripts/testnet-ctl.sh start      # start DHT + 3 validators
./scripts/testnet-ctl.sh stop       # graceful stop (validators first, then DHT)
./scripts/testnet-ctl.sh restart    # stop + start
./scripts/testnet-ctl.sh status     # show active/inactive for each service
./scripts/testnet-ctl.sh logs       # tail all service logs via journalctl
./scripts/testnet-ctl.sh logs 2     # tail validator 2 only
./scripts/testnet-ctl.sh uninstall  # stop + disable + remove unit files
```

### Direct systemctl

```bash
sudo systemctl status tos-validator@1
sudo systemctl restart tos-validator@2
sudo journalctl -u tos-validator@3 -f --no-pager
```

### Restarting one validator for upgrades

Stopping a single validator for a binary upgrade or config reload is
safe — TOS does not auto-slash for downtime, and the remaining 2 of 3
nodes still meet the BFT-2/3 quorum so the chain keeps producing
blocks. See [Validator.md → Maintenance and Graceful Shutdown](Validator.md#maintenance-and-graceful-shutdown)
for the full operator procedure and the rationale.

### Lite-client

```bash
tos-lite-client -C /data/tos-global.json
```

Inside lite-client:
```
> last                  # latest masterchain block
> time                  # server time
> getconfig 34          # current validator set
> getconfig 15          # election parameters
> getconfig 0           # config smart contract address
```

### Validator console

The console command for each node is printed during setup. General form:

```bash
tos-validator-console \
  -a 127.0.0.1:<console-port> \
  -k /data/testnet/nodeN/keyring/<console-client-key-hex> \
  -p /data/tosN/console-server.pub
```

## Global Config Format

The global config follows the same structure as [tos.network/global-config.json](https://tos.network/global-config.json):

```json
{
  "@type": "config.global",
  "dht": {
    "@type": "dht.config.global",
    "k": 6,
    "a": 3,
    "static_nodes": {
      "@type": "dht.nodes",
      "nodes": [
        {
          "@type": "dht.node",
          "id": { "@type": "pub.ed25519", "key": "<base64>" },
          "addr_list": {
            "@type": "adnl.addressList",
            "addrs": [{ "@type": "adnl.address.udp", "ip": <int32>, "port": <port> }],
            "version": 0, "reinit_date": 0, "priority": 0, "expire_at": 0
          },
          "version": -1,
          "signature": "<base64>"
        }
      ]
    }
  },
  "liteservers": [
    {
      "ip": <int32>,
      "port": <port>,
      "id": { "@type": "pub.ed25519", "key": "<base64>" }
    }
  ],
  "validator": {
    "@type": "validator.config.global",
    "zero_state": {
      "workchain": -1,
      "shard": -9223372036854775808,
      "seqno": 0,
      "root_hash": "<base64>",
      "file_hash": "<base64>"
    }
  }
}
```

Notes:
- `ip` is a signed 32-bit integer. `127.0.0.1` = `2130706433`.
- `dht.node.signature` is produced by `generate-random-id -m dht`.
- `liteservers` is not part of the TL `config.global` type but is added for lite-client compatibility.
- For production, add `init_block` and `hardforks` fields under `validator`.

## Local Config Format (per node)

TL type: `engine.validator.config`. Key fields:

```json
{
  "@type": "engine.validator.config",
  "out_port": 0,
  "addrs": [{ "@type": "engine.addr", "ip": <int32>, "port": <udp_port>, "categories": [0] }],
  "adnl": [
    { "@type": "engine.adnl", "id": "<fullnode_short_id_b64>", "category": 0 },
    { "@type": "engine.adnl", "id": "<validator_short_id_b64>", "category": 0 }
  ],
  "dht": [{ "@type": "engine.dht", "id": "<fullnode_short_id_b64>" }],
  "validators": [{
    "@type": "engine.validator",
    "id": "<validator_short_id_b64>",
    "temp_keys": [{ "key": "<validator_short_id_b64>", "expire_at": 2147483647 }],
    "adnl_addrs": [{ "id": "<validator_short_id_b64>", "expire_at": 2147483647 }],
    "expire_at": 2147483647
  }],
  "fullnode": "<fullnode_short_id_b64>",
  "liteservers": [{ "@type": "engine.liteServer", "id": "<liteserver_short_id_b64>", "port": <tcp_port> }],
  "control": [{
    "@type": "engine.controlInterface",
    "id": "<console_server_short_id_b64>",
    "port": <tcp_port>,
    "allowed": [{ "@type": "engine.controlProcess", "id": "<console_client_short_id_b64>", "permissions": 15 }]
  }]
}
```

All IDs are base64-encoded 32-byte values = sha256 of TL-serialized public key (`\xc6\xb4\x13\x48` + 32-byte Ed25519 pubkey).

## Key Format

**Keyring files** (in `keyring/` directories):
- Filename: uppercase hex of short key ID (64 hex chars)
- Content: `\x17\x23\x68\x49` (4-byte magic) + 32-byte Ed25519 private key
- Permissions: `0600`, owned by `tos:tos`
- Directory permissions: `0700`

**Public key files** (`.pub`):
- Content: `\xc6\xb4\x13\x48` (4-byte magic) + 32-byte Ed25519 public key

**Short key ID computation:**
```python
import hashlib, base64
tl_serialized = b'\xc6\xb4\x13\x48' + public_key_bytes  # 36 bytes
short_id = hashlib.sha256(tl_serialized).digest()          # 32 bytes
hex_id = short_id.hex().upper()                             # keyring filename
b64_id = base64.b64encode(short_id).decode()                # config.json value
```

## Network Parameters

| Parameter | Value | Config location |
|-----------|-------|----------------|
| `global_id` | 3 (dev) | zero state (`setglobalid`) |
| Validators | 3 | zero state (`config.validators!`) |
| Election period | 2400s elected-for, 800s start-before | zero state (`config.election_params!`) |
| Min stake | 10,000 TOS | zero state (`config.validator_stake_limits!`) |
| Block gas limit | 1,000,000 | zero state (`config.gas_prices!`) |
| Catchain lifetime | 250 (mc), 250 (shard) | zero state (`config.catchain_params!`) |

## Resetting the Network

```bash
./scripts/testnet-ctl.sh stop
sudo REPO_ROOT=$(pwd) ./scripts/setup-testnet.sh --clean
./scripts/testnet-ctl.sh start
```

This generates new keys, new zero state, and fresh databases. All previous chain data is lost.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `setup-testnet.sh` fails with "another setup is running" | Lock file held | Remove `/tmp/tos-setup.lock` |
| Service exits with status=2 | Invalid local config format | Verify `config.json` has all TL-required fields |
| `time` works but `last` times out on first try | lite-client picked a not-yet-ready node | Run `time` first, or retry — lite-client rotates liteservers |
| ADNL timeout on all nodes | Missing `--initial-sync-delay` or `--quic-flood-control` launch params | Verify systemd ExecStart includes both flags (see below) |
| "missing file" in log for static/ | Zero state .boc not in static dir | Check symlinks in `static/` point to valid .boc files |
| DHT "failed to get from dht" | Nodes haven't discovered each other yet | Wait 5-10 seconds, DHT needs time to propagate |
| Nodes not producing blocks | < 2/3 validators online | Ensure at least 2 of 3 validator services are active (any 2 satisfy `tos::quorum_threshold(51)=34`); when only 1 is up, no quorum is possible |

## Files

| File | Purpose |
|------|---------|
| `scripts/setup-testnet.sh` | One-time setup: user, binaries, keys, zero state, configs, systemd |
| `scripts/testnet-ctl.sh` | Service management: start/stop/status/logs/uninstall |
| `scripts/tos-dht.service` | Reference systemd unit (actual units generated by setup script) |
| `scripts/tos-validator@.service` | Reference systemd template (actual units generated by setup script) |
| `test/tostester/src/tostester/network.py` | Python network orchestration class (tested, canonical) |
| `test/tostester/src/tostester/zerostate.py` | Zero state generation via Fift |
| `test/tostester/src/tostester/key.py` | Ed25519 key generation and keyring management |

## Critical Launch Parameters

The following parameters are **required** for validator-engine to accept external connections. Without them, nodes appear active but all ADNL handshakes time out.

```ini
ExecStart=tos-validator-engine \
  ...
  --initial-sync-delay 5 \
  --quic-flood-control -1 \
  ...
```

| Parameter | Value | Why required |
|-----------|-------|--------------|
| `--initial-sync-delay` | `5` | Gives the node 5 seconds to complete initial state sync before starting validation. Without this, the ADNL layer fails to initialize properly, causing all liteserver and console connections to time out with "Connection reset by peer". |
| `--quic-flood-control` | `-1` | Disables QUIC flood control. In local/small networks, the default flood control can block peer-to-peer communication. Without this, nodes cannot discover each other or complete consensus. |

These parameters are set automatically by `setup-testnet.sh` in the generated systemd units. If you create units manually, ensure they are included.

## EVM Workchain (Workchain 1)

The local testnet supports an EVM workchain at `workchain_id = 1` (alongside masterchain `-1` and basechain `0`). When enabled, validators execute Ethereum-compatible transactions via the embedded evmone EVM and expose a standard `eth_*` JSON-RPC surface.

### Architecture

```
EVM transaction (via MetaMask, ethers.js, etc.)
   │
   ├── eth_sendRawTransaction (HTTP JSON-RPC, ports 8011-8013)
   │      ↓
   │   handle_eth_sendRawTransaction → build ext_in_msg cell
   │      ↓
   │   liteServer_sendMessage → ExtMessagePool (workchain==1: skips TVM validation)
   │      ↓
   │   Collator picks up message → routes to evm_workchain dispatch
   │      ↓
   │   evm-compute-phase.cpp executes via evmone
   │      ↓
   │   CellEvmState commits to TOS CellDb (single atomic WriteBatch)
   │      ↓
   │   Block produced → EVM state included in TOS state_hash
   │
   └── eth_getBalance / eth_getTransactionReceipt / eth_call (read-only)
          ↓
       global_evm_state (in-memory cell dict, optionally persisted to BoC)
```

### Constants

| Item | Value | Source |
|------|-------|--------|
| `workchain_id` | `1` | `crypto/block/evm-workchain/evm-workchain.h` (`kWorkchainId`) |
| `chainId` (Ethereum) | `0x544F53` (5,525,331) | stored in ConfigParam 12 `vm_mode`; exposed via `eth_chainId` |
| `vm_version` | `0x45564D` ("EVM") | `kVmVersion` — used in WorkchainDescr |
| `vm_mode` | EVM `chainId` | consensus-bound; validators reject `wc=1` descriptors whose `vm_mode` is zero or mismatched |

### Initialization in validator-engine

`validator-engine.cpp` calls `evm_workchain::init_evm_workchain(db_root_)` at startup. This:

1. Constructs a `CellEvmState` (cell-native, no separate RocksDB)
2. Loads any prior state from `{db_root}/evm-state.boc` if present
3. Registers the EVM compute-phase handler with the host-chain dispatch
4. Initializes the global `IncrementalTrieCalculator` for Ethereum-format MPT stateRoot computation

No additional CLI flags are needed — EVM workchain is built in.

### Activating the EVM Workchain on the Network

The EVM workchain (`wc=1`) is **already wired into the build**: `gen-zerostate.fif` registers it via `add-evm-workchain` (CreateState.fif), and the tostester pipeline used by `setup-testnet.sh` produces the matching `evmstate1.boc`. The bash setup script symlinks all three workchain states (master, base, evm) into each node's `static/` directory and adds `--json-rpc-address 127.0.0.1:801N` to the systemd ExecStart.

**To deploy from scratch (clean network — destroys existing state):**

```bash
# 0. Build and install the latest binaries
cd ~/tos
cmake --build build -j$(nproc) --target validator-engine create-state lite-client dht-server
sudo install -m755 build/validator-engine/validator-engine /usr/local/bin/tos-validator-engine
sudo install -m755 build/lite-client/lite-client /usr/local/bin/tos-lite-client
sudo install -m755 build/dht-server/dht-server /usr/local/bin/tos-dht-server
sudo install -m755 build/crypto/create-state /usr/local/bin/tos-create-state
# (and any other binaries used by the systemd units)

# 1. Stop existing testnet (if any)
sudo ./scripts/testnet-ctl.sh stop || true

# 2. Wipe old chain state (zerostate + per-node DBs)
sudo rm -rf /data/testnet /data/dht /data/tos1 /data/tos2 /data/tos3 \
            /data/tos-global.json /data/testnet-ports.json
# If migrating from a previous 4-node deployment, also wipe the legacy
# tos4 working dir so a leftover state file does not confuse setup:
sudo rm -rf /data/tos4

# 3. Re-run setup — this regenerates zerostate WITH wc=1 and writes new
#    systemd units that include --json-rpc-address.
sudo ./scripts/setup-testnet.sh

# 4. Start
sudo ./scripts/testnet-ctl.sh start

# 5. Wait ~10 s for sync, then verify (see "Verification" below)
```

**To activate on an existing chain (no reset, governance path):**

A masterchain proposal containing the new ConfigParam 12 with the EVM workchain descriptor. This is the production path; it does not require a zerostate reset. The `WorkchainDescr` cell can be built by `crypto/block/evm-workchain/evm-config-param.cpp::build_evm_workchain_descr()` and submitted via the standard config update flow. Validators must already be running the binary that contains the `evm_workchain` module.

### Verification

After the network is running with EVM enabled:

```bash
# Sanity: chain ID
curl -s -X POST http://127.0.0.1:8011 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
# Expected: {"jsonrpc":"2.0","id":1,"result":"0x544f53"}

# Latest block on the EVM workchain
curl -s -X POST http://127.0.0.1:8011 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Get balance of an address (zero for unfunded)
curl -s -X POST http://127.0.0.1:8011 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x0000000000000000000000000000000000000001","latest"],"id":1}'
```

### Devnet-Only Hardhat Fixture Accounts

Production/local production-style genesis no longer funds public Hardhat accounts. wc=1 eTOS supply is seeded into 10 `EToSPoWGiver` contracts under `crypto/smartcont/etos-pow-givers.fif`.

The following Hardhat / Anvil keys are only for explicit devnet fixtures built with `TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS=1`. The keys are public and well-known across the Ethereum tooling ecosystem; never assume they are funded outside that devnet fixture mode. eTOS is the wc=1 EVM native token, distinct from TOS on wc=0; the two have independent supplies and there is no on-chain bridge — 1:1 swap is conceptual, executed by external markets.

**Mnemonic:** `test test test test test test test test test test test junk`
**Derivation path:** `m/44'/60'/0'/0/N` (BIP-44 standard)

| # | Address | Private Key |
|---|---------|-------------|
| 0 | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` | `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` |
| 1 | `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` | `0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d` |
| 2 | `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC` | `0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a` |
| 3 | `0x90F79bf6EB2c4f870365E785982E1f101E93b906` | `0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6` |
| 4 | `0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65` | `0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a` |
| 5 | `0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc` | `0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba` |
| 6 | `0x976EA74026E726554dB657fA54763abd0C3a0aa9` | `0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e` |
| 7 | `0x14dC79964da2C08b23698B3D3cc7Ca32193d9955` | `0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356` |
| 8 | `0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f` | `0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97` |
| 9 | `0xa0Ee7A142d267C1f36714E4a8F75612F20a79720` | `0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6` |

The devnet fixture seeding is idempotent — if account #0 already has any state from a prior run, the seeding is skipped. To re-seed, wipe `/data/tos*/` and restart the devnet fixture build.

Production deployments must not define `TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS`; the production path has no `seed_test_accounts` call to remove.

#### Quick test with cast (Foundry)

```bash
# Devnet fixture only: send 1 eTOS from account #0 -> account #1.
# Requires a build/run with TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS=1.
cast send 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
  --value 1ether \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --rpc-url http://127.0.0.1:8011

# Check #1's balance
cast balance 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
  --rpc-url http://127.0.0.1:8011
```

### Connecting MetaMask

1. **Add custom network** in MetaMask → Settings → Networks → Add Network → Add manually:
   - Network name: `TOS EVM Local`
   - RPC URL: `http://127.0.0.1:8011` (or 8012 / 8013)
   - Chain ID: `5525331`
   - Currency symbol: `eTOS`

2. **Devnet fixture only: import a pre-funded test account** → Account menu → Import account → Private Key:
   - Paste any private key from the test accounts table above (start with #0: `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`)
   - This balance exists only when the chain was explicitly started with `TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS=1`.

3. **Send a transaction** — works with any standard wallet flow.

### Persistent State

EVM state is part of the TOS ShardState cell tree (atomic with TOS state) once the collator integration lands. In the current implementation:

- During node operation: `CellEvmState` keeps the cell-native state in memory
- On clean shutdown: state can be serialized to `{db_root}/evm-state.boc` (development mode)
- On restart: the BoC is loaded if present

The atomic single-WriteBatch commit (TOS + EVM together) is the production target.

### Troubleshooting EVM

| Symptom | Cause | Fix |
|---------|-------|-----|
| `eth_chainId` returns nothing | JSON-RPC server not enabled | Add `--json-rpc <port>` to validator-engine CLI |
| Transaction stays pending | EVM workchain not in ConfigParam 12 | Activate via Path A or Path B above |
| `state_hash` mismatch on validators | Some nodes have EVM enabled, others don't | All validators must run the same evm-workchain binary version |
| BoC load failure on restart | Schema mismatch | Delete `{db_root}/evm-state.boc` to start fresh |

## UNO Workchain (Workchain 2)

The local testnet supports the UNO privacy workchain at `workchain_id = 2` (alongside masterchain `-1`, TOS basechain `0`, and EVM `1`). UNO is a Zcash/Penumbra-style shielded-payments chain: all values, recipients, and senders are hidden inside Plonky3 STARK proofs over the Goldilocks field. There is no VM — transactions are verified by the generic compute-phase dispatcher, which routes by the tx-body byte-0 discriminator (`0x01` Transfer / `0x02` MineUno) to the `uno_plonky3_ffi` verifier (ABI v4). UNO's native coin is distributed **solely by mining** (CPU-only Poseidon2 PoW, 600 s target interval, 50 UNO/solve initial reward, halving every 210 000 solves); no genesis airdrop, no pre-funded test accounts.

Consensus status: the MineUno tx-kind landed end-to-end as of Phase 3d (commits `12837af7f..17b1ddd11`); tostester wiring that materialises `unostate2.boc` into the local zerostate landed in `b3bf82b26`.

### Architecture

```
UNO tx (Transfer or MineUno, built by tosctl-uno)
   │
   ├── tosctl-uno mine  (CPU Poseidon2 PoW search)
   │      ↓  nonce found + Plonky3 prove_mine_uno (~30–60 s CPU)
   │   MineUno tx body = 0x02 ‖ schema-v1 ‖ public_inputs(92 B) ‖ proof+PI blob(~255 KiB; BoC ~264 KiB)
   │      ↓
   │   liteServer_sendMessage (port 2003/2006/2009/2012) → ExtMessagePool (wc==2)
   │      ↓
   │   Collator picks up message → uno_workchain dispatcher
   │      ↓
   │   compute-phase.cpp byte-0 discriminator dispatch:
   │        0x01 → Transfer compute-phase → uno_plonky3_verify
   │        0x02 → MineUno   compute-phase → verify_mine_uno_chain_checks
   │                                       → uno_mine_uno_verify (FFI v4)
   │                                       → apply_mine_uno (verify-before-mutate)
   │      ↓
   │   UnoShardState mutated: commitment_tree.append(output_cm);
   │                          mine_remaining -= value; mine_epoch += 1;
   │                          halving_era recomputed from epoch
   │      ↓
   │   Block produced → UNO state included in wc=2 shardstate root hash
   │
   └── (Transfer path: user wallets scan via ivk; no public RPC surface yet)
```

### Constants

| Item                              | Value                                             | Source |
|-----------------------------------|---------------------------------------------------|--------|
| `workchain_id`                    | `2`                                               | `uno/core/workchain.h` (`kWorkchainId`) |
| `vm_version`                      | `0x554E4F31` ("UNO1") = `1431195441`              | `uno/core/workchain.h` (`kVmVersion`) |
| `vm_mode`                         | `0`                                               | `uno/core/workchain.h` (`kVmMode`) |
| `chain_id` (testnet)              | `0x554E4F54` ("UNOT")                             | `uno/core/workchain.h` (`kChainIdTestnet`) |
| `chain_id` (mainnet)              | `0x554E4F4D` ("UNOM")                             | `uno/core/workchain.h` (`kChainIdMainnet`) |
| Total supply (cap)                | **21 000 000 UNO** (= 2.1 × 10¹⁶ nano-UNO)        | `uno/core/genesis.h` (`kGenesisTotalSupplyNano`) / `uno/core/mine_constants.h` (`kMineSupplyNano`) |
| Initial mining reward (era 0)     | **50 UNO** (5 × 10¹⁰ nano-UNO)                    | `uno/core/mine_constants.h` (`kInitMineReward`) |
| Halving period                    | **210 000 solves** per era (Bitcoin-clone)        | `uno/core/mine_constants.h` (`kEraSize`) |
| Target solve interval             | **600 s** (Bitcoin 10-min block time)             | `uno/core/mine_constants.h` (`kTargetSolveSeconds`) |
| Retarget factor bounds            | `[3/4, 4/3]` (more aggressive than TOS's `[7/8, 9/8]`) | `uno/core/mine_constants.h` (`kRetargetMin/MaxNum/Den`) |
| Initial PoW target                | `2^219` (big-endian 32-byte, byte[4] = `0x08`)    | `uno/core/mine_constants.h` (`kInitMineTargetBE`) |
| Hash algorithm                    | Poseidon2 over Goldilocks (PQ-native; CPU-only)   | `kMineHashTag = "uno-mine-v1"` |
| Proof system                      | Plonky3 STARK + FRI, ABI v4                       | `uno/plonky3-ffi/include/uno_plonky3_ffi.h` |
| Expected proof size               | ~200 KB                                           | local-test target; production sizing is in [uno-workchain.md](uno-workchain.md) |
| `uno_plonky3_abi_version()`       | `4`                                               | `uno/crypto/plonky3-verifier.h` (`kExpectedAbiVersion`) |

### Initialization in validator-engine

`validator-engine.cpp:2338` calls `uno_workchain::init_uno_workchain(db_root_)` at startup (immediately after `evm_workchain::init_evm_workchain`). This:

1. Constructs a `LiveUnoState` singleton (nullifier set + commitment tree + anchor window + mining-state cells)
2. Warms the nullifier-set LRU (1 M entries by default — §5.9 / §10.2)
3. Registers the Uno compute handler with the generic workchain dispatcher — subsequent compute-phase calls for wc=2 land in `uno/core/compute-phase.cpp`'s byte-0 discriminator, which forwards to `verify_mine_uno_chain_checks` + `apply_mine_uno` for MineUno txs and to the Plonky3 Transfer verifier for Transfer txs
4. Defers Plonky3 FRI-parameter materialization to the first verify call (v1 unit tests that never verify don't pay the cost)

No additional CLI flags are needed — the UNO workchain is built in.

### Activating the UNO Workchain on the Network

The UNO workchain (`wc=2`) is **already wired into the build**: `gen-zerostate.fif:53-84` registers it via `add-uno-workchain` (analog of `add-evm-workchain`), and the tostester pipeline used by `setup-testnet.sh` produces the matching `unostate2.boc`, `.fhash`, and `.rhash`. Each node's `static/` directory gets a symlink to the UNO zerostate alongside TOS and EVM.

**To deploy from scratch (clean network — destroys existing state):**

```bash
# 0. Build and install the latest binaries
cd ~/tos
cmake --build build -j$(nproc) --target validator-engine create-state lite-client dht-server
sudo install -m755 build/validator-engine/validator-engine /usr/local/bin/tos-validator-engine
sudo install -m755 build/lite-client/lite-client /usr/local/bin/tos-lite-client
sudo install -m755 build/dht-server/dht-server /usr/local/bin/tos-dht-server
sudo install -m755 build/crypto/create-state /usr/local/bin/tos-create-state

# 1. Stop existing testnet (if any) and wipe state
sudo ./scripts/testnet-ctl.sh stop || true
sudo rm -rf /data/testnet /data/dht /data/tos1 /data/tos2 /data/tos3 \
            /data/tos-global.json /data/testnet-ports.json
# If migrating from a previous 4-node deployment, also wipe the legacy
# tos4 working dir so a leftover state file does not confuse setup:
sudo rm -rf /data/tos4

# 2. Re-run setup — this regenerates zerostate WITH wc=2 (tostester b3bf82b26+)
sudo REPO_ROOT=$(pwd) ./scripts/setup-testnet.sh

# 3. Start
sudo ./scripts/testnet-ctl.sh start

# 4. Wait ~10 s for sync, then verify (see below)
```

**To activate on an existing chain (no reset, governance path):**

A masterchain proposal containing the updated ConfigParam 12 with a new `workchain_v2` leaf for wc=2, `vm_version = 0x554E4F31`, `vm_mode = 0`. **No dedicated builder helper exists yet** — the analog of `build_evm_workchain_descr()` (from `crypto/block/evm-workchain/evm-config-param.cpp`) would need to live in `crypto/block/uno-workchain/` or be reused out of the existing `add-uno-workchain` Fift primitive. Submit via the standard config-update flow. All validators must already be running a binary that includes the `uno_workchain` module (FFI ABI v4 or later) before the proposal goes live — otherwise they will diverge on the first wc=2 block.

### Verification

After the network is running with UNO enabled:

```bash
# 1. Confirm the wc=2 WorkchainDescr is present in ConfigParam 12
tos-lite-client -C /data/tos-global.json -v 0 -c "getconfig 12" -c "quit" \
  | grep -E "vm_version" 
# Expect three hits: vm_version:-1 (TOS), vm_version:4544077 (EVM),
#                    vm_version:1431195441 (UNO1 = 0x554E4F31)

# 2. Confirm a wc=2 shard descriptor exists post-genesis (shards list).
#    Three leaves total are expected: wc=0 (shard_descr_new, advancing),
#    wc=1 (shard_descr_new, advancing), wc=2 (shard_descr, seq_no:0 until
#    the first MineUno tx advances it).
tos-lite-client -C /data/tos-global.json -v 0 -c "allshards" -c "quit" \
  | grep -cE "leaf:\(shard_descr"
# Expect: 3

# 3. Bootstrap progress (server should show increasing masterchain seqno)
tos-lite-client -C /data/tos-global.json -v 0 -c "last" -c "quit"
```

Full end-to-end flow (mining + tx submission) is in **Mining Quick Start** below.

### Pre-Funded Accounts (UNO)

**Zero.** Like production wc=1 EVM, the UNO zerostate does not fund public Hardhat-style accounts. UNO uses an empty shardstate: `gen-zerostate.fif:69` calls `2 mkemptyShardState` — no notes, no balances, no test recipients. The entire 21 M UNO supply comes from mining only.

This is intentional:
- Privacy coins with pre-mined distributions expose launch participants' holdings (Zcash's 20 % Founders' Reward was widely criticised).
- UNO's positioning is "PQ-native Bitcoin" — a 0 % pre-mine matches Bitcoin's original distribution.
- Genesis wiring for a future non-empty zerostate (60 % airdrop / 25 % treasury / 15 % team per `uno/core/genesis.h:111-138`) exists in code but is **not** used by the local testnet — the comment at `gen-zerostate.fif:58-67` explicitly documents the TODO.

The local testnet uses mining-only issuance with no pre-funded UNO accounts.

### Mining Quick Start

The `tosctl-uno` binary (built out of `tosctl/uno/`) exposes the UNO CLI. The mine subcommand takes a **recipient-address JSON** produced by `tosctl-uno address` (not a raw key file — the address is a 1259-byte `diversifier ‖ pk_d ‖ ivk_commitment ‖ pk_mlkem` payload).

```bash
# 0. Build tosctl-uno
cd ~/tos
cargo build --release --bin tosctl-uno -p tosctl-uno

# 1. Generate a FVK from a BIP-39 mnemonic (or --from-tos-seed <PATH>)
./target/release/tosctl-uno keygen \
  --seed "test test test test test test test test test test test junk" \
  --out /tmp/alice-fvk.json

# 2. Derive a diversified recipient address (testnet HRP = "uno1")
./target/release/tosctl-uno address \
  --fvk /tmp/alice-fvk.json --random --hrp uno1 \
  > /tmp/alice-recipient.json

# 3. Mine: search for a valid Poseidon2 nonce, generate a Plonky3 MineUno
#    proof, and submit it via the node's RPC endpoint.
./target/release/tosctl-uno mine \
  --recipient /tmp/alice-recipient.json \
  --node http://127.0.0.1:8080 \
  --threads 4 \
  --max-time 1800

# 4. Verify the chain advanced — the wc=2 shard leaf (previously at seq_no:0
#    with file_hash matching unostate2.fhash) should now show a non-zero
#    seq_no and a different root_hash.
tos-lite-client -C /data/tos-global.json -v 0 -c "allshards" -c "quit" \
  | grep -E "leaf:\(shard_descr" | tail -1
```

Notes on flags:
- `tosctl-uno mine` takes `--recipient`, `--node`, `--threads`, `--max-time` — there is **no** `--target-bits` flag (difficulty is read live from chain state, not forced by the miner) and no `--key-file` flag (the miner only needs the public recipient bytes; the secret is held by the wallet).
- `--threads` defaults to `num_cpus::get()` (all logical CPUs).
- If your node does not yet expose an HTTP RPC at port 8080, the miner will fail at the chain-state poll step. Direct `tos-lite-client -c "sendfile <boc>"` submission requires a pre-built MineUno BoC; the `tosctl-uno mine` binary is the canonical submitter.

Difficulty hint: for local single-miner smoke tests you can lower the zerostate target manually in `uno/core/mine_constants.h` (`kInitMineTargetBE`) — e.g., from `2^219` to `2^40` — and rebuild + reset. The genesis `2^219` target assumes ~150 M Poseidon2 ops/s total network hashrate and will not solve in reasonable wall-clock time on a single box.

### Persistent State (UNO)

UNO shardstate is a standard TOS cell tree — there is **no** separate per-node `.boc` file (unlike EVM's optional `evm-state.boc` dev-mode checkpoint). The root cell layout (`uno/core/state.h` + `uno/core/cell-state.cpp`) carries four refs:

| ref | Contents                                                                 |
|-----|--------------------------------------------------------------------------|
| 0   | Commitment tree (append-only Poseidon2 Merkle tree, 32-depth)            |
| 1   | Nullifier set (256-bit keyed dict; spent-note markers)                   |
| 2   | MetaCell (anchor window + stats + **mining-state sub-ref** at ref 2)     |
| 3   | Reserved for v1.1 / Phase 1 extensions                                   |

The mining-state sub-ref (added in uno-mine-v1 Phase 2, bumped `kMetaRefCount` 2 → 3 in `uno/core/workchain.h:143`) stores 384 bits inline:

- `mine_remaining` (u64) — nano-UNO still available to mint; starts at `kMineSupplyNano` = 21 M × 10⁹
- `mine_epoch` (u32) — cumulative accepted MineUno solves
- `mine_target` (32 B big-endian) — current PoW target (auto-retargeted per solve)
- `halving_era` (u32) — cached `= mine_epoch / kEraSize`

Old 2-ref MetaCells (pre-Phase-2) deserialize with zeroed mining fields for backward compatibility. Chain state is fully reconstructable from the masterchain + wc=2 block history; no sidecar files needed.

### Troubleshooting UNO

| Symptom                                                   | Cause                                                                                           | Fix                                                                                           |
|-----------------------------------------------------------|-------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| MineUno tx rejected with `unknown-tx-kind` (VerifyResult 46) | Tx-body byte 0 is not `0x01` Transfer / `0x02` MineUno; binary / schema mismatch between miner and validator. | Rebuild both `tosctl-uno` and the validator from the same tree; confirm ABI via `uno_plonky3_abi_version() == 4`. |
| `epoch-race-detected` (VerifyResult 41)                   | Another miner's MineUno tx landed for the same `mine_epoch`; your proof's `epoch` field is now stale. | Poll chain state, re-fetch `(epoch, target, remaining_pre)`, rebuild proof, resubmit. `tosctl-uno mine` does this automatically on the next loop iteration. |
| `remaining-race-detected` (VerifyResult 42)               | The supply drained concurrently (another miner mined while you were proving).                   | Same as above — refresh chain state; if `mine_remaining < mine_reward_for_era(era_from_epoch(epoch))`, mining is over. |
| `invalid-halving-reward` (VerifyResult 44)                | `value` in your proof doesn't match `mine_reward_for_era(era_from_epoch(epoch))`.               | Check the halving table in `uno/core/mine_constants.h`; the Rust mirror is in `tosctl/uno/src/mine_constants.rs` — the two must stay byte-identical. |
| `bad-mine-conservation` (VerifyResult 45)                 | `remaining_pre − value ≠ remaining_post` in the public inputs.                                  | Off-circuit bug in the miner; resync chain state before the prove step. |
| `bad-plonky3-proof` (VerifyResult 15)                     | FFI v4 verifier rejected the proof bytes (tampered, wrong ABI, or built against different field params). | Verify `uno_plonky3_abi_version()` matches on both sides — expected value: `4`. Rebuild either the validator or tosctl-uno if they disagree. |
| wc=2 shard doesn't advance after submitting MineUno tx    | Tx was rejected by compute-phase before block inclusion.                                        | `sudo journalctl -u tos-validator@1 --since "1 min ago" \| grep -E "mine_uno\|VerifyResult"` — the exit reason is logged with the matching `verify_result_name()` string. |
| Miner spins forever, no proof found                       | `kInitMineTargetBE = 2^219` is the mainnet-calibration target; a single local box ≈ 25 Mops/s can't meet it in under a day. | For local dev, patch `kInitMineTargetBE` to `2^40` (byte[28] = 0x01 rest zero) and rebuild + reset the testnet; or run multiple high-CPU miners. |

## Production Deployment Notes

For production, the following changes are needed:

1. **global_id**: Change from `3` (dev) to `1` (mainnet) or `-3` (testnet) in `gen-zerostate.fif`
2. **IP addresses**: Replace `127.0.0.1` with public IPs; each validator on a separate machine
3. **Separate machines**: Run each validator on its own server with dedicated storage
4. **init_block**: Add `init_block` to global config after network is running (for faster sync)
5. **Monitoring**: Enable `--exporter-address` for metrics, `--collect-validator-telemetry`
6. **Log rotation**: Configure logrotate for `/data/tosN/log`
7. **Backup**: Regular backup of `/data/tosN/keyring/` (keys are irreplaceable)
8. **Firewall**: Open only UDP validator ports and TCP liteserver ports
9. **Key rotation**: Rotate validator keys periodically via validator console
10. **JSON-RPC**: If running the embedded JSON-RPC HTTP server, use ports 8011-8013 (one per validator) to avoid collisions with the validator port range

## Related Docs

- [Validator.md](Validator.md) — Production validator operation
- [FullNode.md](FullNode.md) — Full node setup
- [ConfigParam.md](ConfigParam.md) — Blockchain configuration parameters
- [uno-workchain.md](uno-workchain.md) — UNO workchain architecture (privacy model, AIR, key hierarchy, compute-phase flow)
- [Zerostate.md](Zerostate.md) — Per-workchain zerostate layout (how `zerostate.boc` / `basestate0.boc` / `evmstate1.boc` / `unostate2.boc` fit together)
