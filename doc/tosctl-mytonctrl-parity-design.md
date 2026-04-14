# TOSCTL MyTonCtrl Parity Design

## Purpose

This document defines how `tosctl` should fully cover the operator command surface that TOS operators currently associate with `mytonctrl`.

The goal is not to preserve the old interactive Python shell. The goal is to preserve workflow coverage while migrating to a clearer Rust CLI model.

This document is the parity baseline for:

- command planning
- migration tracking
- future deprecation of direct `mytonctrl` usage in TOS environments

## Scope

This parity plan covers the public command surface registered by:

- `mytonctrl/mytonctrl.py`
- `mytonctrl/modules/*.py`

It covers both:

- commands with direct operational semantics
- feature areas that imply required `tosctl` support even when the original implementation was tightly coupled to `mytonctrl` internals

It does not require:

- reproducing the interactive REPL
- preserving short aliases like `vo`, `ve`, or `wl` as the primary UX
- preserving Python implementation boundaries

## Audit Status

This document has been cross-checked against the command names registered through `add_command(...)` in the current `mytonctrl` source tree.

Audit result at the time of writing:

- public command names discovered in source: `87`
- public command names covered in this document: `87`
- uncovered public command names: `0`

Audit method:

- extract the public command names from `mytonctrl/mytonctrl.py` and `mytonctrl/modules/*.py`
- verify that every discovered command has an explicit replacement path in the mapping tables below

This section should be updated whenever `mytonctrl` adds or removes public commands.

## Design Rules

- Every `mytonctrl` operator workflow must have a documented `tosctl` replacement path.
- `tosctl` primary commands should use descriptive names, not short console mnemonics.
- Old `mytonctrl` names may be retained as optional aliases where migration value is high.
- Declarative config editing should remain under `config`.
- Imperative host actions should live under `host`, `install`, `init`, or `backup`.
- Imperative live-node actions should live under `node`.
- Generic chain-facing wallet and pool actions should live under `wallet`, `pool`, `vote`, `account`, or `observe`.

## Target Command Model

The `tosctl` command tree should be extended so that `mytonctrl` parity does not distort existing command boundaries.

Target tree:

```text
tosctl
  config
  key
  auth
  deploy
  service
  api
  host
  install
  init
  backup
  node
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

## Domain Mapping

### 1. Host Lifecycle

Purpose:

- replace `mytonctrl` commands that manage node host state, installation state, runtime mode, and operator-local settings

Target groups:

- `tosctl host`
- `tosctl install`
- `tosctl init`

Primary subcommands:

```text
tosctl host about
tosctl host status
tosctl host settings get
tosctl host settings set
tosctl host mode status
tosctl host mode enable
tosctl host mode disable
tosctl host update
tosctl host upgrade
tosctl host archive download
tosctl host benchmark
tosctl node net quic set
tosctl install wizard
```

### 2. Backup and Recovery

Purpose:

- replace `mytonctrl` backup and restore workflows with explicit, auditable commands

Target group:

- `tosctl backup`

Primary subcommands:

```text
tosctl backup create
tosctl backup restore
tosctl backup verify
```

### 3. Wallet Operations

Purpose:

- separate imperative wallet operations from declarative `config wallet`

Target group:

- `tosctl wallet`

Primary subcommands:

```text
tosctl wallet create
tosctl wallet activate
tosctl wallet ls
tosctl wallet import
tosctl wallet export
tosctl wallet rm
tosctl wallet set-version
tosctl wallet send
tosctl wallet send --via-proxy
```

### 4. Pool Operations

Purpose:

- provide imperative lifecycle and fund-management actions for validator pools

Target group:

- `tosctl pool`

Primary subcommands:

```text
tosctl pool ls
tosctl pool rm
tosctl pool import
tosctl pool get
tosctl pool nominator create
tosctl pool nominator activate
tosctl pool nominator update-validator-set
tosctl pool nominator deposit
tosctl pool nominator withdraw
tosctl pool single create
tosctl pool single activate
tosctl pool single withdraw
tosctl pool liquid controller create
tosctl pool liquid controller update
tosctl pool liquid controller ls
tosctl pool liquid controller get
tosctl pool liquid controller add
tosctl pool liquid controller stop
tosctl pool liquid controller stop-withdraw
tosctl pool liquid controller deposit
tosctl pool liquid controller withdraw
tosctl pool liquid controller update-validator-set
tosctl pool liquid controller apr
tosctl pool liquid controller test-loan
tosctl pool liquid check
```

### 5. Validator Governance and Participation

Purpose:

- replace validator voting, complaint handling, and election-entry actions

Target group:

- `tosctl vote`

Primary subcommands:

```text
tosctl vote offer ls
tosctl vote offer diff
tosctl vote offer cast
tosctl vote complaint ls
tosctl vote complaint cast
tosctl vote election ls
tosctl vote election cast
```

### 6. Live Node Control and Collator Management

Purpose:

- replace console-driven validator and collator administration

Target group:

- `tosctl node`

Primary subcommands:

```text
tosctl node status
tosctl node ping
tosctl node probe
tosctl node collator ls
tosctl node collator local
tosctl node collator add
tosctl node collator rm
tosctl node collator reset
tosctl node collator setup
tosctl node collator stop
tosctl node collator-config set
tosctl node collator-config refresh
tosctl node collator-config show
tosctl node collation-whitelist add
tosctl node collation-whitelist rm
tosctl node collation-whitelist disable
tosctl node collation-whitelist ls
tosctl node overlay add
tosctl node overlay ls
tosctl node overlay rm
```

### 7. Account, Validator, and Diagnostics Views

Purpose:

- replace table-style status views and inspection helpers

Target groups:

- `tosctl account`
- `tosctl observe`

Primary subcommands:

```text
tosctl account status
tosctl account txs
tosctl account bookmark add
tosctl account bookmark ls
tosctl account bookmark rm
tosctl observe validators
tosctl observe efficiency
```

### 8. Alerts and Telemetry

Purpose:

- replace `mytonctrl` alert-bot lifecycle and expose telemetry as first-class operational features

Target group:

- `tosctl observe`

Primary subcommands:

```text
tosctl observe alert setup
tosctl observe alert enable
tosctl observe alert disable
tosctl observe alert ls
tosctl observe alert test
tosctl observe metrics push
tosctl observe metrics show
```

## Full Command Mapping

### Host Lifecycle and General Shell Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `about` | `tosctl host about` | Static version and environment info |
| `update` | `tosctl host update` | Refresh package or source metadata |
| `upgrade` | `tosctl host upgrade` | Perform host-side upgrade workflow |
| `installer` | `tosctl install wizard` | Interactive installer wrapper |
| `status` | `tosctl host status` | Host and node summary |
| `status_modes` | `tosctl host mode status` | Active runtime modes |
| `status_settings` | `tosctl host settings show` | Effective local settings |
| `enable_mode` | `tosctl host mode enable <mode>` | Validator, liteserver, collator, pool modes |
| `disable_mode` | `tosctl host mode disable <mode>` | Symmetric disable path |
| `get` | `tosctl host settings get <key>` | Local operator settings |
| `set` | `tosctl host settings set <key> <value>` | Local operator settings |
| `download_archive_blocks` | `tosctl host archive download` | Archive/history helper |
| `benchmark` | `tosctl host benchmark` | Preserve benchmarking workflow |
| `set_quic_port` | `tosctl node net quic set --port <port>` | Keep under live node/network control |

### Backup Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `create_backup` | `tosctl backup create` | Must preserve preflight and temp-dir handling |
| `restore_backup` | `tosctl backup restore` | Must preserve confirmation and safety checks |

### Wallet Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `nw` | `tosctl wallet create` | Replace short alias with explicit command |
| `aw` | `tosctl wallet activate` | Support single wallet or `--all` |
| `wl` | `tosctl wallet ls` | Table and JSON outputs |
| `iw` | `tosctl wallet import` | Import existing local keypair |
| `swv` | `tosctl wallet set-version` | Wallet version migration helper |
| `ew` | `tosctl wallet export` | Expert-only warning if secret export is allowed |
| `dw` | `tosctl wallet rm` | Keep confirmation prompt unless `--yes` |
| `mg` | `tosctl wallet send` | Generic transfer command |
| `mgtp` | `tosctl wallet send --via-proxy` | Explicit compatibility flag |

### Basic Pool Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `pools_list` | `tosctl pool ls` | Pool inventory and status |
| `delete_pool` | `tosctl pool rm` | Local pool config deletion |
| `import_pool` | `tosctl pool import` | Import existing deployed pool address |
| `get_pool_data` | `tosctl pool get` | Query on-chain pool data |

### Nominator Pool Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `new_pool` | `tosctl pool nominator create` | Create local nominator pool deployment bundle |
| `activate_pool` | `tosctl pool nominator activate` | Activate/deploy pool |
| `update_validator_set` | `tosctl pool nominator update-validator-set` | Imperative validator-set sync |
| `deposit_to_pool` | `tosctl pool nominator deposit` | Stake deposit path |
| `withdraw_from_pool` | `tosctl pool nominator withdraw` | Withdraw or pend-withdraw path |

### Single Nominator Pool Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `new_single_pool` | `tosctl pool single create` | Single-nominator pool creation |
| `activate_single_pool` | `tosctl pool single activate` | Deployment path |
| `withdraw_from_single_pool` | `tosctl pool single withdraw` | Withdraw path |

### Liquid Staking Controller Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `create_controllers` | `tosctl pool liquid controller create` | Create controller set |
| `update_controllers` | `tosctl pool liquid controller update` | Alias to same workflow or refresh variant |
| `controllers_list` | `tosctl pool liquid controller ls` | Controller inventory |
| `get_controller_data` | `tosctl pool liquid controller get` | Detailed controller data |
| `deposit_to_controller` | `tosctl pool liquid controller deposit` | Deposit funds |
| `withdraw_from_controller` | `tosctl pool liquid controller withdraw` | Withdraw funds |
| `calculate_annual_controller_percentage` | `tosctl pool liquid controller apr` | Analytics helper |
| `controller_update_validator_set` | `tosctl pool liquid controller update-validator-set` | Imperative sync |
| `stop_controller` | `tosctl pool liquid controller stop` | Stop controller participation |
| `stop_and_withdraw_controller` | `tosctl pool liquid controller stop-withdraw` | Compound operation |
| `add_controller` | `tosctl pool liquid controller add` | Add externally known controller |
| `check_liquid_pool` | `tosctl pool liquid check` | Liquid pool consistency check |
| `test_calculate_loan_amount` | `tosctl pool liquid controller test-loan` | Expert diagnostics |

### Validator Voting and Status Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `vo` | `tosctl vote offer cast` | Preserve multi-offer batch support |
| `ve` | `tosctl vote election cast` | Election-entry action |
| `vc` | `tosctl vote complaint cast` | Complaint vote action |
| `check_ef` | `tosctl observe efficiency` | Validator efficiency view |
| `ol` | `tosctl vote offer ls` | Offers list |
| `od` | `tosctl vote offer diff` | Offer diff viewer |
| `el` | `tosctl vote election ls` | Election entries list |
| `cl` | `tosctl vote complaint ls` | Complaints list |
| `vl` | `tosctl observe validators` | Validator list/table |

### Collator and Whitelist Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `add_collator` | `tosctl node collator add` | Validator-side collator list mutation |
| `delete_collator` | `tosctl node collator rm` | Remove collator from validator list |
| `print_collators` | `tosctl node collator ls` | Validator collator list |
| `reset_collators` | `tosctl node collator reset` | Clear configured list |
| `setup_collator` | `tosctl node collator setup` | Collator host and validator setup flow |
| `print_local_collators` | `tosctl node collator local` | Local node collator state |
| `stop_collator` | `tosctl node collator stop` | Stop one or all collators |
| `add_validator_to_collation_wl` | `tosctl node collation-whitelist add` | Validator allowlist mutation |
| `delete_validator_from_collation_wl` | `tosctl node collation-whitelist rm` | Validator allowlist mutation |
| `disable_collation_wl` | `tosctl node collation-whitelist disable` | Disable allowlist enforcement |
| `print_collation_whitelist` | `tosctl node collation-whitelist ls` | Show allowlist |

### Collator Config Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `set_collation_config` | `tosctl node collator-config set` | Accept local file or URL |
| `update_collation_config` | `tosctl node collator-config refresh` | Re-apply configured source |
| `print_collation_config` | `tosctl node collator-config show` | Display active config |

### Custom Overlay Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `add_custom_overlay` | `tosctl node overlay add` | Add static or dynamic overlay |
| `list_custom_overlays` | `tosctl node overlay ls` | Show configured overlays |
| `delete_custom_overlay` | `tosctl node overlay rm` | Delete overlay and reconcile validator-console |

### Account Utility Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `vas` | `tosctl account status` | Account status and code/data summary |
| `vah` | `tosctl account txs` | Account history |
| `nb` | `tosctl account bookmark add` | Bookmark helper |
| `bl` | `tosctl account bookmark ls` | Bookmark list |
| `db` | `tosctl account bookmark rm` | Bookmark delete |

### Alert Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `enable_alert` | `tosctl observe alert enable` | Per-alert or global enable |
| `disable_alert` | `tosctl observe alert disable` | Per-alert or global disable |
| `list_alerts` | `tosctl observe alert ls` | Alert inventory and state |
| `test_alert` | `tosctl observe alert test` | Fire test alert |
| `setup_alert_bot` | `tosctl observe alert setup` | Bot bootstrap and credentials |

### Expert and Integration Commands

| `mytonctrl` command | Target `tosctl` command | Notes |
|---|---|---|
| `remove_btc_teleport` | `tosctl admin btc-teleport rm` | Keep outside normal operator path |

## Feature Parity Beyond Direct Commands

Some `mytonctrl` modules matter even without their own public console commands.

### Liteserver Mode

`mytonctrl` has an explicit liteserver mode model. `tosctl` should cover this through:

- `tosctl host mode enable liteserver`
- `tosctl host mode disable liteserver`
- `tosctl install` support for liteserver-only deployment profiles

### Prometheus Integration

`mytonctrl` includes Prometheus-oriented metric export logic. `tosctl` should preserve the capability through:

- `tosctl observe metrics show`
- `tosctl observe metrics push`
- config-backed exporter settings

### TOS HTTP API, LS Proxy, and TOS Storage

`mytonctrl` installer manages sidecar services such as `tos-http-api`, liteserver proxy, and TOS storage. TOS should not clone these blindly, but the workflow must still exist:

- replace `tos-http-api` with embedded JSON-RPC in `validator-engine`
- expose proxy and storage sidecars through `tosctl install` and `tosctl host mode`
- keep sidecar lifecycle management inside `tosctl`, not in shell scripts

## Compatibility Policy

### Primary UX

The primary UX should use descriptive commands such as:

- `tosctl vote offer cast`
- `tosctl wallet ls`
- `tosctl node collator setup`

### Optional Aliases

Optional compatibility aliases may be added for high-traffic commands:

- `tosctl wl` -> `tosctl wallet ls`
- `tosctl vo` -> `tosctl vote offer cast`
- `tosctl ve` -> `tosctl vote election cast`
- `tosctl vc` -> `tosctl vote complaint cast`

Aliases are optional and should never replace descriptive commands in documentation.

## Delivery Phases

### Phase 1

- `host`
- `backup`
- `wallet`
- `pool`
- `vote`
- `node` basic status and collator list

This phase closes the most visible `mytonctrl` gap.

### Phase 2

- full collator and collation-config support
- overlays
- account utilities
- alert commands

### Phase 3

- liquid staking controller parity
- telemetry and metrics surfaces
- optional compatibility aliases

## Summary

`tosctl` is not yet at `mytonctrl` parity today. This document defines the target state where every operator-facing `mytonctrl` command has a first-class `tosctl` replacement.

The replacement should be:

- more structured
- better separated by workflow
- API-backed where possible
- compatible enough that TOS operators do not need to fall back to `mytonctrl`
