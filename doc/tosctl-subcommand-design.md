# TOSCTL Subcommand Design

## Purpose

This document refines the tooling consolidation plan into a concrete `tosctl` command model.

It answers four questions:

1. What top-level command groups should `tosctl` expose?
2. Which current tools or scripts map into each group?
3. Which commands are user-facing versus internal wrappers over legacy binaries?
4. How should the current command tree evolve without breaking operators abruptly?

This design assumes the long-term TOS model:

- `validator-engine` owns node-native read APIs and embedded JSON-RPC
- `tosctl` owns operator workflows

It now also assumes an explicit migration goal:

- `tosctl` must fully cover the operator command surface that TOS operators currently get from `legacy operator shell`

Detailed parity mapping lives in:

- `doc/tosctl-legacy-operator-parity-design.md`

## Command Design Principles

- Top-level commands should reflect operator intent, not implementation detail.
- Commands should be grouped by workflow domain, not by historical code ownership.
- Read workflows should prefer stable API-backed commands over ad hoc interactive consoles.
- Existing operators must have a migration path from current commands and scripts.
- Legacy tools may remain callable internally, but should disappear from the normal operator path.

## Current State

The current `tosctl` command tree is still relatively small:

- `config-param`
- `api`
- `auth`
- `config`
- `deploy`
- `key`
- `service`

This covers part of the existing Rust control plane, but does not yet absorb:

- validator console workflows
- node install/bootstrap flows
- service lifecycle management for deployed nodes
- DNS and chain read workflows currently done via `lite-client` or `toslib-cli`
- network diagnostics
- RLDP/site operations
- observability and consensus inspection
- most imperative wallet and pool workflows
- backup and restore
- collator, overlay, alert, and host-mode workflows exposed by `legacy operator shell`

## Proposed Top-Level Command Tree

The proposed future command tree is:

```text
tosctl
  config
  key
  auth
  deploy
  service
  api
  host
  node
  install
  init
  backup
  wallet
  pool
  vote
  chain
  account
  dns
  site
  net
  observe
  admin
```

Not all groups must ship in the first phase. The tree is the target shape.

## Command Groups

### 1. `tosctl config`

Purpose:

- manage the operator configuration model
- remain the source of truth for nodes, wallets, pools, bindings, logs, elections, and RPC endpoints

Status:

- already exists
- should remain

Expected responsibilities:

- `config generate`
- `config node ...`
- `config wallet ...`
- `config pool ...`
- `config bind ...`
- `config elections ...`
- `config chain-rpc ...`
- `config log ...`

Notes:

- this command group should stay declarative
- it should not become a dumping ground for operational actions

### 2. `tosctl key`

Purpose:

- manage operator and wallet secrets in the vault
- eventually wrap node-related key workflows that are currently split between vault and console

Status:

- already exists
- should remain

Expected responsibilities:

- generate/import/list/remove vault keys
- manage wallet keys
- optionally create named control-plane client keys

Boundary:

- if a key is local operator secret material, it belongs here
- if a key must be registered on a node, that registration belongs under `node`

### 3. `tosctl auth`

Purpose:

- manage authentication for the `tosctl` service API

Status:

- already exists
- should remain

Expected responsibilities:

- local users
- token issuance
- revocation and access lifecycle

### 4. `tosctl deploy`

Purpose:

- deploy contracts and contract-backed operator components

Status:

- already exists
- should remain

Expected responsibilities:

- wallet deployment
- pool deployment
- future deployable operator helper contracts

Boundary:

- deployment is chain-facing contract creation
- node bootstrap belongs elsewhere

### 5. `tosctl service`

Purpose:

- run long-lived operator automation

Status:

- already exists
- should remain

Expected responsibilities:

- elections
- voting
- REST API
- automation runtime

Boundary:

- this is the daemon entrypoint, not host service lifecycle management

### 6. `tosctl api`

Purpose:

- interact with a running `tosctl service` instance

Status:

- already exists
- should remain

Expected responsibilities:

- health
- validator snapshots
- election snapshots
- task control
- runtime stake policy changes

### 6A. `tosctl host`

Purpose:

- absorb host-local lifecycle and operator-shell commands that `legacy operator shell` currently owns

Status:

- new
- P0

Expected responsibilities:

- host status
- host settings get/set
- runtime mode enable/disable/status
- update and upgrade workflows
- archive download helpers
- benchmark runners
- general environment/about information

Maps from current tooling:

- `legacy operator shell status`
- `legacy operator shell status_modes`
- `legacy operator shell status_settings`
- `legacy operator shell enable_mode`
- `legacy operator shell disable_mode`
- `legacy operator shell update`
- `legacy operator shell upgrade`
- `legacy operator shell about`
- `legacy operator shell download_archive_blocks`
- `legacy operator shell benchmark`

Boundary:

- `host` owns local machine and node-role lifecycle
- `node` owns live RPC/control-plane actions against configured nodes

### 7. `tosctl node`

Purpose:

- become the main operator-facing replacement for `validator-engine-console`

Status:

- new
- P0

This is the most important missing command group.

Expected subcommands:

```text
tosctl node add
tosctl node ls
tosctl node rm
tosctl node ping
tosctl node probe
tosctl node status
tosctl node config get
tosctl node key gen
tosctl node key export-pub
tosctl node validator add-perm
tosctl node validator add-temp
tosctl node validator add-adnl
tosctl node validator bind-adnl
tosctl node message send
tosctl node collator ...
tosctl node collator-config ...
tosctl node collation-whitelist ...
tosctl node overlay ...
```

Maps from current tooling:

- `validator-engine-console`
- ADNL control-client methods
- existing node config CRUD under `config node`

Recommended split:

- `config node ...` remains declarative config management
- `node ...` performs live operations against real nodes

Additional parity responsibilities:

- collator list mutation
- collator local lifecycle
- collation whitelist management
- collator config distribution
- custom overlay management

Examples:

```text
tosctl node ping --node node1
tosctl node status --node node1
tosctl node validator add-perm --node node1 --secret validator-perm-1 --election-date ... --expire-at ...
tosctl node config get --node node1
```

### 8. `tosctl install`

Purpose:

- replace shell-based installation and service file setup

Status:

- new
- P0

Expected subcommands:

```text
tosctl install layout
tosctl install binaries
tosctl install assets
tosctl install systemd
tosctl install all
```

Maps from current tooling:

- binary install steps from `setup-testnet.sh`
- Fift and smart contract asset installation
- service unit generation

Examples:

```text
tosctl install binaries --from ~/tos/build --prefix /usr/local
tosctl install systemd --network local-testnet
tosctl install all --from ~/tos/build
```

### 9. `tosctl init`

Purpose:

- replace bootstrap scripts and multi-step local/test network initialization

Status:

- new
- P0

Expected subcommands:

```text
tosctl init devnet
tosctl init testnet
tosctl init zerostate
tosctl init keys
tosctl init global-config
tosctl init local-config
```

Maps from current tooling:

- `setup-testnet.sh`
- Python `tostester.Network`
- `generate-random-id`
- `create-state`

Examples:

```text
tosctl init devnet --validators 3 --root /data/testnet
tosctl init zerostate --template local-testnet
tosctl init keys --node node1
```

Boundary:

- `init` creates or materializes state
- `install` places binaries/assets and service definitions on the host

### 10. `tosctl chain`

Purpose:

- absorb routine read-only chain inspection currently done with `lite-client`

Status:

- new
- P1

Expected subcommands:

```text
tosctl chain head
tosctl chain block get
tosctl chain block txs
tosctl chain config get
tosctl chain send-boc
tosctl chain run-get
```

Maps from current tooling:

- `lite-client`
- current `config-param`
- JSON-RPC adapter paths

Migration note:

- `config-param` can remain temporarily as a compatibility alias to `chain config get`

Examples:

```text
tosctl chain head
tosctl chain config get 34
tosctl chain run-get --address ... --method participant_list_extended
```

### 11. `tosctl wallet`

Purpose:

- absorb imperative wallet workflows that do not belong under declarative `config wallet`

Status:

- new
- P0

Expected subcommands:

```text
tosctl wallet create
tosctl wallet activate
tosctl wallet ls
tosctl wallet import
tosctl wallet export
tosctl wallet rm
tosctl wallet set-version
tosctl wallet send
```

Maps from current tooling:

- `legacy operator shell` wallet commands such as `nw`, `aw`, `wl`, `iw`, `ew`, `dw`, `mg`, `mgtp`
- part of the current `config wallet send` imperative surface

Boundary:

- `config wallet` remains declarative
- `wallet` owns local wallet lifecycle and transfers

### 12. `tosctl pool`

Purpose:

- absorb imperative pool lifecycle and validator staking workflows

Status:

- new
- P0

Expected subcommands:

```text
tosctl pool ls
tosctl pool rm
tosctl pool import
tosctl pool get
tosctl pool nominator ...
tosctl pool single ...
tosctl pool liquid ...
```

Maps from current tooling:

- `legacy operator shell` basic pool commands
- nominator-pool commands
- single-nominator commands
- liquid-staking controller commands

Boundary:

- `config pool` remains declarative inventory
- `pool` owns imperative on-chain pool actions

### 13. `tosctl vote`

Purpose:

- collect validator proposal, complaint, and election-entry actions in one explicit group

Status:

- new
- P0

Expected subcommands:

```text
tosctl vote offer ls
tosctl vote offer diff
tosctl vote offer cast
tosctl vote complaint ls
tosctl vote complaint cast
tosctl vote election ls
tosctl vote election cast
```

Maps from current tooling:

- `vo`
- `ve`
- `vc`
- `ol`
- `od`
- `el`
- `cl`

### 14. `tosctl account`

Purpose:

- provide account-centric state inspection and message workflows

Status:

- new
- P1

Expected subcommands:

```text
tosctl account get
tosctl account state
tosctl account txs
tosctl account send
```

Maps from current tooling:

- `lite-client getaccount`
- `validator-engine-console getaccount`
- wallet flows partially scattered across existing commands

Boundary:

- `account` is generic chain account interaction
- wallet-specific policy and config remain under existing wallet-related commands

This group should also absorb account bookmarks and account-history inspection from `legacy operator shell` utilities.

### 15. `tosctl dns`

Purpose:

- replace routine DNS inspection currently split between `lite-client` and `toslib-cli`

Status:

- new
- P1

Expected subcommands:

```text
tosctl dns root
tosctl dns resolve
tosctl dns trace
```

Maps from current tooling:

- `lite-client dnsresolve`
- `toslib-cli dns resolve root`

Examples:

```text
tosctl dns root
tosctl dns resolve example.tos --category 1
tosctl dns trace example.tos
```

### 16. `tosctl site`

Purpose:

- own RLDP site workflows through a structured operator interface

Status:

- new
- P1

Expected subcommands:

```text
tosctl site proxy start
tosctl site proxy stop
tosctl site expose
tosctl site check
```

Maps from current tooling:

- `rldp-http-proxy`
- manual DNS + RLDP preflight

Examples:

```text
tosctl site proxy start --port 8080 --global-config /data/tos-global.json
tosctl site expose --listen 0.0.0.0:3333 --domain mysite.tos
tosctl site check mysite.tos
```

### 17. `tosctl net`

Purpose:

- unify low-level network diagnostics

Status:

- new
- P1

Expected subcommands:

```text
tosctl net dht ping
tosctl net dht resolve
tosctl net adnl ping
tosctl net adnl proxy
tosctl net ls probe
```

Maps from current tooling:

- `dht-ping-servers`
- `dht-resolve`
- `adnl-proxy`
- lite server reachability checks

Examples:

```text
tosctl net dht ping --global-config /data/tos-global.json
tosctl net ls probe --address 127.0.0.1:2003 --pubkey-file liteserver.pub
```

### 18. `tosctl observe`

Purpose:

- own operational observability beyond simple health checks

Status:

- new
- P2

Expected subcommands:

```text
tosctl observe validators
tosctl observe elections
tosctl observe consensus
tosctl observe logs
tosctl observe efficiency
tosctl observe alert ...
tosctl observe metrics ...
```

Maps from current tooling:

- `consensus_explorer`
- `show-validator-set`
- session log parsing
- service snapshots
- `legacy operator shell check_ef`
- `legacy operator shell` alert-bot commands
- `legacy operator shell` Prometheus-related telemetry workflows

Examples:

```text
tosctl observe validators
tosctl observe consensus --stats-dir /data/tos1/session-logs
tosctl observe logs --node node1
```

### 19. `tosctl backup`

Purpose:

- isolate destructive and recovery-sensitive backup workflows

Status:

- new
- P0

Potential subcommands:

```text
tosctl backup create
tosctl backup restore
tosctl backup verify
```

Maps from current tooling:

- `create_backup`
- `restore_backup`

This group is intentionally separate from `host` and `install` because backup and restore have different safety requirements.

### 20. `tosctl admin`

Purpose:

- hold dangerous or rarely-used expert workflows that should not pollute the main operator path

Status:

- optional
- P2 or later

Potential subcommands:

```text
tosctl admin hardfork create
tosctl admin block dump
tosctl admin block adjust
```

This group is intentionally separated from the normal operational surface.

## Migration of Existing Commands

### Keep Without Renaming

- `config`
- `key`
- `auth`
- `deploy`
- `service`
- `api`

These already reflect stable workflow domains.

### Keep Temporarily as Compatibility Aliases

- `config-param`

Recommended alias target:

- `tosctl chain config get`

The alias can be retained for one or more releases while docs migrate.

### Add New Primary Groups

- `host`
- `node`
- `install`
- `init`
- `backup`
- `wallet`
- `pool`
- `vote`
- `chain`
- `account`
- `dns`
- `site`
- `net`
- `observe`

## UX Rules

### Prefer Named Node References

For live node operations, commands should prefer `--node <name>` from config over raw endpoint input.

Raw endpoint mode may remain available for diagnostics, but config-backed operation should be the default.

### Prefer Structured Output

Every operational command should support:

- `table`
- `json`

This avoids forcing operators back into raw console responses.

### Make Interactive Consoles Optional

Interactive console mode should not be required for routine operations.

If retained, it should exist as:

- a debug or expert mode
- not as the primary operator interface

### Separate Declarative and Imperative Actions

- declarative config edits belong under `config`
- imperative live node actions belong under `node`
- service daemon runtime actions belong under `api`

This prevents command sprawl and unclear ownership.

## Implementation Notes

### Wrapping Strategy

Early phases may wrap legacy binaries or protocol clients internally:

- `validator-engine-console`
- `generate-random-id`
- `create-state`
- `rldp-http-proxy`
- `show-validator-set`

That is acceptable as long as:

- `tosctl` owns the user-facing interface
- output is normalized
- configuration is centralized

### Backend Preference Order

For read operations, prefer:

1. `validator-engine` embedded JSON-RPC
2. configured chain RPC endpoint
3. legacy compatibility layer only when necessary

### Backward Compatibility

The first implementation phase should add new command groups without immediately deleting existing ones.

Recommended sequence:

1. add `node`, `install`, `init`
2. add `host`, `backup`, `wallet`, `pool`, `vote`
3. add `chain`, `account`, `dns`
4. move docs from script/binary workflows to `tosctl`
5. deprecate direct legacy UX and direct `legacy operator shell` dependency

## Recommended Delivery Order

### Phase 1

- `host`
- `node`
- `install`
- `init`
- `backup`
- `wallet`
- `pool`
- `vote`

### Phase 2

- `chain`
- `account`
- `dns`
- compatibility alias from `config-param`
- collator, overlay, and alert parity

### Phase 3

- `site`
- `net`
- metrics and liquid-staking parity

### Phase 4

- `observe`
- optional `admin`

## Summary

The future `tosctl` UX should be organized around operator intent:

- configure things with `config`
- manage secrets with `key`
- manage host lifecycle with `host`
- control live nodes with `node`
- bootstrap environments with `init`
- install host artifacts with `install`
- protect state with `backup`
- operate wallets with `wallet`
- operate pools with `pool`
- cast governance and validator actions with `vote`
- inspect chain state with `chain`, `account`, and `dns`
- operate network-facing services with `site` and `net`
- observe system behavior with `observe`

This command model gives TOS a coherent operator CLI instead of inheriting a fragmented legacy tool surface.
