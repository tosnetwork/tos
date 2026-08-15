# tosctl -- TOS Node Operator Tool

`tosctl` is the operator CLI and automation daemon for TOS validator nodes. It replaces legacy operator shells and the scattered collection of shell scripts, Python utilities, and standalone binaries with a single Rust tool.

`tosctl` manages nodes, wallets, pools, elections, voting, backups, alerts, and observability from one configuration file and one binary.

## Prerequisites

- A running TOS `validator-engine` with `--json-rpc-address` enabled (typically `127.0.0.1:2011`)
- The validator-engine control server port accessible from the host running `tosctl`
- A secrets vault (file-backed or HashiCorp Vault) for key storage
- Rust toolchain (for building from source) or the published Docker image

## Installation

### Build from source

```bash
cd src
cargo build --release -p tosctl
```

Binary location:

```
src/target/release/tosctl
```

### Docker

```bash
docker pull ghcr.io/gtosnetwork/tos-rust-node/tosctl:v0.1.1
```

Shell alias for convenience:

```bash
alias tosctl='docker run --rm \
  -v "$(pwd)/tosctl-config.json":/tosctl/config.json \
  -e VAULT_URL="$VAULT_URL" \
  -e CONFIG_PATH="/tosctl/config.json" \
  ghcr.io/gtosnetwork/tos-rust-node/tosctl:v0.1.1 \
  tosctl'
```

If using the file-backed vault, also mount the vault file:

```bash
alias tosctl='docker run --rm \
  -v "$(pwd)/tosctl-config.json":/tosctl/config.json \
  -v "$(pwd)/vault.json":/tosctl/vault.json \
  -e VAULT_URL="file:///tosctl/vault.json?master_key=$MASTER_KEY" \
  -e CONFIG_PATH="/tosctl/config.json" \
  ghcr.io/gtosnetwork/tos-rust-node/tosctl:v0.1.1 \
  tosctl'
```

## Quick Start

```bash
# 1. Generate a default configuration file
tosctl config generate --output tosctl-config.json
export CONFIG_PATH=./tosctl-config.json

# 2. Set up vault and create keys
tosctl key add --name "node0-adnl-key" --extractable
tosctl key add --name "wallet0-key"

# 3. Add your node (control server endpoint + public key)
tosctl config node add \
  --name node0 \
  --control-server-endpoint 127.0.0.1:2004 \
  --control-server-pubkey "kGViQgAAAAB..." \
  --control-client-secret-name "node0-adnl-key"

# 4. Add a validator wallet
tosctl config wallet add \
  --name wallet0 \
  --secret-name "wallet0-key" \
  --version V3R2 \
  --workchain -1

# 5. Point chain RPC at the validator-engine JSON-RPC server
tosctl config chain-rpc set --url "http://127.0.0.1:2011/"

# 6. Bind wallet to node
tosctl config bind add --node node0 --wallet wallet0

# 7. Deploy the wallet contract (needs >= 0.1 TOS balance)
tosctl deploy wallet --node wallet0 --all

# 8. Enable elections and start the daemon
tosctl config elections enable node0
tosctl service -c tosctl-config.json
```

## Configuration

tosctl reads its config from `tosctl-config.json` by default. Override the path with:

- `--config` / `-c` flag on any command
- `CONFIG_PATH` environment variable

### Config structure

```json
{
  "nodes": {
    "node0": {
      "server_address": "127.0.0.1:2004",
      "server_key": { "type_id": 1209251014, "pub_key": "<base64>" },
      "client_key": { "name": "node0-adnl-key" },
      "timeouts": 5
    }
  },
  "wallets": {
    "wallet0": {
      "key": { "name": "wallet0-key" },
      "version": "V3R2",
      "subwallet_id": 42,
      "workchain": -1
    }
  },
  "pools": {
    "pool0": {
      "kind": "snp",
      "address": "-1:pool_contract_address",
      "owner": "-1:owner_address"
    }
  },
  "bindings": {
    "node0": {
      "wallet": "wallet0",
      "pool": "pool0",
      "enable": true
    }
  },
  "chain_rpc": {
    "urls": ["http://127.0.0.1:2011/"],
    "api_key": null
  },
  "elections": {
    "policy": "split50",
    "policy_overrides": {},
    "max_factor": 3.0,
    "tick_interval": 40
  },
  "http": {
    "bind": "0.0.0.0:8080",
    "enable_swagger": true,
    "auth": {
      "operator_token_ttl": 2592000,
      "nominator_token_ttl": 86400,
      "min_password_length": 8
    }
  },
  "log": {
    "level": "INFO",
    "output": "console",
    "path": "logs/service.log",
    "rotation": "daily",
    "max_size_mb": 50,
    "max_files": 10
  },
  "tick_interval": 40
}
```

### Key sections

| Section | Purpose |
|---------|---------|
| `nodes` | ADNL control server connections to validator-engine instances |
| `wallets` | Validator wallets with keys stored in vault or inline |
| `pools` | Single-nominator (`snp`) or core pool configurations |
| `bindings` | Links a node to a wallet and optional pool for elections |
| `chain_rpc` | JSON-RPC endpoint URLs (validator-engine embedded server) |
| `elections` | Stake policy, max factor, tick interval |
| `http` | REST API bind address, Swagger, JWT auth |
| `log` | Logging level, rotation, output target |

Wallet key values can be either a hex private key string or a vault reference (`{ "name": "secret-name" }`). Node client keys follow the same pattern.

## Command Reference

### `tosctl config` -- Declarative configuration management

Manage the `tosctl-config.json` file without editing JSON by hand.

```
config generate          Generate a new default config file
config node add|ls|rm    Manage node control server entries
config wallet add|ls|rm  Manage wallet entries
config wallet send       Send TOS from a configured wallet
config pool add|ls|rm    Manage pool entries
config bind add|ls|rm    Link nodes to wallets and pools
config chain-rpc set     Set JSON-RPC endpoint URL
config elections ...     Enable/disable elections, set stake policy
config log ls|set        View and update logging settings
```

### `tosctl host` -- Host lifecycle, modes, and settings

Manage the local host environment, runtime modes, and operator settings.

```
host about               Version and environment info
host status              Host and node summary
host settings get|set    Read/write local operator settings
host mode status         Active runtime modes
host mode enable|disable Toggle validator, liteserver, collator modes
host update              Refresh package/source metadata
host upgrade             Perform host-side upgrade
host archive download    Download archive blocks
host benchmark           Run performance benchmarks
```

### `tosctl backup` -- Backup and recovery

```
backup create            Create a node backup
backup restore           Restore from a backup
backup verify            Verify backup integrity
```

### `tosctl wallet` -- Wallet operations

Imperative wallet lifecycle and transfers (separate from declarative `config wallet`).

```
wallet create            Create a new wallet
wallet activate          Activate a wallet on-chain
wallet ls                List wallets with balances
wallet import            Import an existing keypair
wallet mnemonic-generate Generate a recoverable TOS mnemonic and TVM address
wallet mnemonic-import   Recover a wallet from a TOS mnemonic
wallet sign              Sign exact bytes with a configured Ed25519 wallet
wallet verify            Verify an Ed25519 signature over exact bytes
wallet test-fixture      Write real test-only identities to a mode-0600 JSON file
wallet test-fixture-import Import one fully verified test-fixture role into custody
wallet export            Export a wallet key (expert only)
wallet rm                Remove a wallet
wallet set-version       Migrate wallet contract version
wallet send              Send TOS to an address
wallet send --via-proxy  Send through a proxy contract
wallet broadcast-prepared Broadcast the exact BOC emitted by send --build-only
```

Automation that needs a crash-safe broadcast boundary can first use
`wallet send --build-only` to construct and sign an external message, validate
the returned versioned JSON, then submit those exact bytes with
`wallet broadcast-prepared --message-boc <BASE64> --yes`. The broadcast command
does not rebuild or sign the transaction. Treat a transport error after calling
it as ambiguous and reconcile against finalized chain state before any retry.

### `tosctl pool` -- Staking pool management

```
pool ls                  List configured pools
pool rm                  Remove a pool from config
pool import              Import an existing deployed pool
pool get                 Query on-chain pool data
pool nominator ...       Nominator pool: create, activate, deposit, withdraw
pool single ...          Single-nominator pool: create, activate, withdraw
pool liquid ...          Liquid staking controller operations
```

### `tosctl vote` -- Validator governance

```
vote offer ls            List config change proposals
vote offer diff          Diff a proposal against current config
vote offer cast          Vote on proposals
vote complaint ls        List complaints
vote complaint cast      Vote on complaints
vote election ls         List election entries
vote election cast       Submit election entry
```

### `tosctl node` -- Live node control

Operate against running validator-engine instances via ADNL control protocol.

```
node status              Node sync and health status
node ping                Control server connectivity check
node probe               Deep probe of node state
node collator ...        Manage collator lists and lifecycle
node collator-config ... Set, refresh, show collation config
node collation-whitelist ...  Manage validator allowlist
node overlay ...         Add, list, remove custom overlays
```

### `tosctl account` -- Account inspection and interaction

```
account status           Account state and balance
account txs              Transaction history
account run-method       Run a get-method on a smart contract
account send-boc         Send a raw BOC message to the blockchain
account bookmark add|ls|rm  Manage address bookmarks
```

### `tosctl observe` -- Monitoring, alerts, and metrics

```
observe validators       Current validator set
observe efficiency       Validator efficiency stats
observe alert setup      Configure Telegram/webhook bot
observe alert enable|disable|ls|test  Manage alerts
observe metrics push|show  Prometheus metric export
```

### `tosctl admin` -- Expert operations

Dangerous or rarely-used workflows separated from the normal operator path.

```
admin hardfork create    Create a hardfork
admin block dump         Dump block data
admin block adjust       Block adjustments
```

### Additional existing commands

These commands ship today and remain stable:

```
tosctl key add|import|ls|rm   Vault key management
tosctl auth add|ls|rm|revoke  REST API user management
tosctl auth set ttl           Configure token TTL per role
tosctl deploy wallet          Deploy wallet contracts on-chain
tosctl deploy pool            Deploy single-nominator pool contracts
tosctl deploy contract        Deploy any smart contract from a BOC file
tosctl service                Start the daemon (elections, voting, REST API)
tosctl api health|elections|validators|task|stake-policy|login  Service API client
tosctl config-param <ID>      Get chain config parameter (legacy alias)
```

## Common Workflows

### Setting up a new validator

```bash
# Generate config and keys
tosctl config generate -o tosctl-config.json
export CONFIG_PATH=./tosctl-config.json
tosctl key add --name "node0-adnl-key" --extractable
tosctl key add --name "wallet0-key"

# Register node, wallet, and binding
tosctl config node add -n node0 -e 127.0.0.1:2004 \
  -p "kGViQgAAAAB..." -s "node0-adnl-key"
tosctl config wallet add -n wallet0 -s "wallet0-key" -v V3R2 -w -1
tosctl config chain-rpc set -u "http://127.0.0.1:2011/"
tosctl config bind add -n node0 -w wallet0

# Fund the wallet (external transfer), then deploy
tosctl deploy wallet --node wallet0 --all --verbose

# Set stake policy and enable elections
tosctl config elections stake-policy --minimum
tosctl config elections enable node0

# Start the daemon
tosctl service -c tosctl-config.json
```

### Managing wallets

```bash
# Create and list
tosctl wallet create --name wallet0
tosctl wallet ls

# Generate a recoverable TVM identity, then recover it into the vault
tosctl wallet mnemonic-generate --words 24 --version V3R2 --workchain 0 --subwallet-id 0
tosctl wallet mnemonic-import --name wallet1 --mnemonic-file mnemonic.txt --workchain 0 --subwallet-id 0

# Generate actual signed test identities instead of placeholder key material
tosctl wallet test-fixture --output tos-service-test-identities.json \
  --unsafe-test-secrets

# Sign or verify exact protocol bytes (text, hex, and file inputs are exclusive)
tosctl wallet sign --name wallet0 --message-hex deadbeef
tosctl wallet verify --public-key <64-hex> --signature <128-hex> --message-hex deadbeef

# Send TOS
tosctl config wallet send --from wallet0 --to "-1:abc123..." --amount 10.0

# Send with bounce disabled (to undeployed address)
tosctl config wallet send --from wallet0 --to "EQDrjaLahLk..." --amount 5.0 --bounce false

# Check balance via chain RPC
tosctl config-param -c tosctl-config.json 34
```

### Deploying a single-nominator pool

```bash
# Add pool to config with the owner address
tosctl config pool add --name pool0 --owner "-1:owner_address"

# Bind pool to node
tosctl config bind add --node node0 --wallet wallet0 --pool pool0

# Deploy pool contract (sends TOS from the wallet)
tosctl deploy pool --node node0 --owner "-1:owner_address" --amount 1.5 --verbose

# Verify pool state
tosctl pool get
```

### Deploying an arbitrary smart contract

```bash
# Deploy a compiled contract BOC to the blockchain
tosctl deploy contract /tmp/my_contract.boc

# Deploy and wait for it to become active
tosctl deploy contract /tmp/my_contract.boc --wait --address "0:abc...def"

# Output as JSON
tosctl deploy contract /tmp/my_contract.boc -f json
```

### Running a get-method on a contract

```bash
# Call 'seqno' on the elector contract
tosctl account run-method --address "-1:333...333" seqno

# Call a method with stack arguments
tosctl account run-method --address "0:abc...def" get_pool_data '["num","0"]'

# Output as JSON
tosctl account run-method --address "-1:333...333" active_election_id -f json
```

### Sending a raw BOC message

```bash
# Send a pre-built BOC message to the blockchain
tosctl account send-boc /tmp/external_message.boc

# JSON output
tosctl account send-boc /tmp/message.boc -f json
```

### Monitoring node status

```bash
# Check service health
tosctl api health

# Get elections snapshot
tosctl api elections

# Get current validators
tosctl api validators

# Control elections participation
tosctl api elections --exclude node0
tosctl api elections --include node0

# Task control
tosctl api task elections restart
```

### Backup and restore

```bash
tosctl backup create
tosctl backup verify
tosctl backup restore
```

### Managing collators

```bash
# List, add, remove collators on a validator
tosctl node collator ls --node node0
tosctl node collator add --node node0
tosctl node collator rm --node node0

# Collation whitelist management
tosctl node collation-whitelist add --node node0
tosctl node collation-whitelist ls --node node0

# Collator config
tosctl node collator-config show --node node0
tosctl node collator-config set --node node0
```

### Stake policy management

```bash
# Default for all nodes: minimum stake
tosctl config elections stake-policy --minimum

# Fixed stake (1000 TOS)
tosctl config elections stake-policy --fixed 1000

# Split50 (half of available balance each round)
tosctl config elections stake-policy --split50

# Per-node override
tosctl config elections stake-policy --node node0 --fixed 500

# Remove per-node override (falls back to default)
tosctl config elections stake-policy --node node0 --reset

# Change policy on a running daemon (no restart needed)
tosctl api stake-policy --minimum
tosctl api stake-policy --node node0 --fixed 500000000000
```

## JSON-RPC Integration

`tosctl` connects to two separate interfaces on the validator-engine:

1. **ADNL control protocol** (e.g., `127.0.0.1:2004`) -- used for live node operations: key generation, validator registration, collator management, overlay configuration. This is the same protocol that `validator-engine-console` uses. Keys for this connection are stored in the vault and referenced by `client_key` in the node config.

2. **HTTP JSON-RPC** (e.g., `127.0.0.1:2011`) -- used for chain reads and transaction submission. This is the embedded JSON-RPC server enabled by starting validator-engine with `--json-rpc-address 127.0.0.1:2011`. It replaces the external `tos-http-api` service entirely.

The chain RPC URL is set once:

```bash
tosctl config chain-rpc set --url "http://127.0.0.1:2011/"
```

The JSON-RPC server currently supports 21 methods including `getMasterchainInfo`, `getAddressInformation`, `runGetMethod`, `sendBoc`, `getTransactions`, `lookupBlock`, `getBlockTransactions`, and others. It also exposes `GET /healthcheck` and `GET /readyz` for liveness and readiness probes.

Optional runtime flags on the validator-engine side:

| Flag | Purpose |
|------|---------|
| `--json-rpc-address` | Bind address for the JSON-RPC server |
| `--json-rpc-readonly` | Disable `sendBoc` and other write methods |
| `--json-rpc-cors-origin` | Set allowed CORS origin |
| `--json-rpc-readyz-threshold` | Sync lag seconds before readyz fails |

## Alert System

`tosctl` supports operator alerts through Telegram bots and webhooks.

```bash
# Set up the alert bot (Telegram token and chat ID)
tosctl observe alert setup

# Enable/disable specific alerts
tosctl observe alert enable
tosctl observe alert disable

# List configured alerts
tosctl observe alert ls

# Send a test alert to verify configuration
tosctl observe alert test
```

Alerts cover validator efficiency drops, missed elections, node sync issues, and stake recovery events.

## REST API

When running in daemon mode (`tosctl service`), an HTTP REST API is exposed for monitoring and automation.

Default bind: `0.0.0.0:8080`. Swagger UI available at `/swagger` when `enable_swagger` is true.

### Authentication

Authentication is **enabled by default** with an empty user list (all protected endpoints return 401 until a user is created).

```bash
# Create an operator user
tosctl auth add --username admin --role operator

# Login and export token
tosctl api login admin
export TOSCTL_API_TOKEN="<token>"

# All subsequent api commands use the token automatically
tosctl api elections
tosctl api validators
```

Roles:

- `operator` -- full access (elections control, task management, stake policy)
- `nominator` -- read-only access (elections snapshot, validators snapshot)

To disable auth entirely, remove the `http.auth` section from config.

**Security note:** tosctl serves plain HTTP. If the API is reachable outside your trusted network, terminate TLS at a reverse proxy.

## Architecture

The TOS operator stack is split between two directories:

```
~/tos         validator-engine, C++ node binaries, embedded JSON-RPC
~/tos/tosctl  operator tool (Rust), config, vault integration, automation
```

`validator-engine` owns:
- Block production and validation
- ADNL networking and control server
- Embedded JSON-RPC HTTP server for chain reads
- Liteserver protocol

`tosctl` owns:
- Operator configuration (`tosctl-config.json`)
- Key and secret management via SecretsVault (`secrets-vault` crate)
- Wallet and pool lifecycle
- Election automation and stake policy
- REST API for monitoring and remote control
- Alert and observability integrations

The control-client connects to validator-engine over **ADNL** (binary protocol, port 2004 by default). The chain-rpc-client connects over **HTTP** to the JSON-RPC server (port 2011 by default). These are independent connections -- the ADNL path is used for privileged node operations, while JSON-RPC handles chain state queries and transaction broadcast.

### Key crates

| Crate | Location | Purpose |
|-------|----------|---------|
| `tosctl` (nodectl) | `src/node-control/` | CLI, daemon, REST API, elections |
| `secrets-vault` | `src/secrets-vault/` | Key storage (file, HCP Vault) |
| `control-client` | `src/node-control/control-client/` | ADNL control protocol client |
| `chain-rpc-client` | `src/node-control/chain-rpc-client/` | JSON-RPC HTTP client |
| `contracts` | `src/node-control/contracts/` | Wallet and pool contract wrappers |
| `elections` | `src/node-control/elections/` | Election automation logic |

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `CONFIG_PATH` | Path to `tosctl-config.json` (avoids `-c` on every command) |
| `VAULT_URL` | SecretsVault connection URL |
| `RUST_LOG` | Override log level (`error`, `warn`, `info`, `debug`, `trace`) |
| `TOSCTL_API_TOKEN` | JWT token for `tosctl api` commands |

## Debugging

```bash
# Verbose logging for any command
RUST_LOG=debug tosctl service -c tosctl-config.json

# Check control server connectivity
tosctl node ping --node node0

# Verify chain RPC reachability
tosctl api health

# Inspect current config
tosctl config node ls --format json
tosctl config wallet ls --format json
tosctl config bind ls --format json
tosctl config elections show --format json
```

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
