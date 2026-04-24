# TOSCTL Legacy Operator Shell Implementation Backlog

## Purpose

This document turns the `legacy operator shell` parity design into an implementation backlog for `tosctl`.

It answers:

1. which parity areas are already partially covered today
2. which command groups are still missing from the Rust CLI
3. how to break the work into reviewable milestones

This backlog is based on:

- `doc/tosctl-legacy-operator-parity-design.md`
- the current Rust CLI command tree under `src/node-control/commands/src/commands`

## Current Implementation Baseline

Current top-level `tosctl` commands:

- `config-param`
- `api`
- `auth`
- `config`
- `deploy`
- `key`
- `service`

Current state relative to `legacy operator shell` parity:

- declarative config management: partially covered
- service API and automation: partially covered
- wallet and pool deployment: partially covered
- host lifecycle parity: missing
- backup parity: missing
- imperative wallet parity: mostly missing
- imperative pool parity: mostly missing
- validator voting parity: mostly missing as CLI
- collator and overlay parity: missing
- alert parity: missing
- liquid-staking controller parity: missing

## Status Legend

- `Done`: already available as a first-class `tosctl` command
- `Partial`: some underlying capability exists, but command parity is incomplete or mapped to the wrong UX surface
- `Missing`: no first-class `tosctl` command exists yet

## Parity Status by Domain

### 1. Host Lifecycle

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl host about` | `about` | Missing | No `host` group exists yet |
| `tosctl host status` | `status` | Missing | Some status exists through `api` and `service`, but not host parity |
| `tosctl host mode status` | `status_modes` | Missing | Requires explicit mode model |
| `tosctl host settings show/get/set` | `status_settings`, `get`, `set` | Missing | No host-local settings UX exists |
| `tosctl host mode enable/disable` | `enable_mode`, `disable_mode` | Missing | Requires mode compatibility policy |
| `tosctl host update` | `update` | Missing | Needs installer/update strategy decision |
| `tosctl host upgrade` | `upgrade` | Missing | Needs package/source upgrade model |
| `tosctl host archive download` | `download_archive_blocks` | Missing | May depend on archive backend strategy |
| `tosctl host benchmark` | `benchmark` | Missing | Could wrap existing benchmark flows |
| `tosctl node net quic set` | `set_quic_port` | Missing | Belongs under live node operations |
| `tosctl install wizard` | `installer` | Missing | Needs installer UX design |

### 2. Backup and Recovery

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl backup create` | `create_backup` | Missing | No backup group exists |
| `tosctl backup restore` | `restore_backup` | Missing | Requires safety prompts and overwrite policy |
| `tosctl backup verify` | derived parity need | Missing | New TOS-added safety helper |

### 3. Wallet Operations

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl wallet create` | `nw` | Missing | `config wallet add` is declarative, not imperative creation |
| `tosctl wallet activate` | `aw` | Missing | Could reuse existing wallet/message helpers |
| `tosctl wallet ls` | `wl` | Partial | `config wallet ls` exists, but that is config inventory, not local wallet operational state |
| `tosctl wallet import` | `iw` | Missing | Key import exists under `key`, but not wallet parity UX |
| `tosctl wallet export` | `ew` | Missing | Needs explicit security policy |
| `tosctl wallet rm` | `dw` | Missing | `config wallet rm` is declarative, not local wallet deletion parity |
| `tosctl wallet set-version` | `swv` | Missing | No dedicated wallet version migration command |
| `tosctl wallet send` | `mg` | Partial | `config wallet send` exists, but should move to imperative `wallet` group |
| `tosctl wallet send --via-proxy` | `mgtp` | Missing | No proxy-send parity exists |

### 4. Basic Pool Operations

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl pool ls` | `pools_list` | Partial | `config pool ls` exists, but that is config inventory |
| `tosctl pool rm` | `delete_pool` | Partial | `config pool rm` exists, but parity semantics differ |
| `tosctl pool import` | `import_pool` | Missing | No imperative pool import surface |
| `tosctl pool get` | `get_pool_data` | Missing | No pool inspection command exists |

### 5. Nominator Pool Operations

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl pool nominator create` | `new_pool` | Missing | Different from current `deploy pool` |
| `tosctl pool nominator activate` | `activate_pool` | Missing | Needs local pool artifact handling |
| `tosctl pool nominator update-validator-set` | `update_validator_set` | Missing | No direct parity command exists |
| `tosctl pool nominator deposit` | `deposit_to_pool` | Missing | No imperative deposit command |
| `tosctl pool nominator withdraw` | `withdraw_from_pool` | Missing | No imperative withdraw command |

### 6. Single Nominator Pool Operations

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl pool single create` | `new_single_pool` | Missing | Not covered by current deploy surface |
| `tosctl pool single activate` | `activate_single_pool` | Missing | Needs explicit workflow |
| `tosctl pool single withdraw` | `withdraw_from_single_pool` | Missing | No parity command exists |

### 7. Liquid Staking Controller Operations

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl pool liquid controller create` | `create_controllers` | Missing | No liquid staking support today |
| `tosctl pool liquid controller update` | `update_controllers` | Missing | Same domain |
| `tosctl pool liquid controller ls` | `controllers_list` | Missing | Same domain |
| `tosctl pool liquid controller get` | `get_controller_data` | Missing | Same domain |
| `tosctl pool liquid controller deposit` | `deposit_to_controller` | Missing | Same domain |
| `tosctl pool liquid controller withdraw` | `withdraw_from_controller` | Missing | Same domain |
| `tosctl pool liquid controller apr` | `calculate_annual_controller_percentage` | Missing | Analytics helper |
| `tosctl pool liquid controller update-validator-set` | `controller_update_validator_set` | Missing | Same domain |
| `tosctl pool liquid controller stop` | `stop_controller` | Missing | Same domain |
| `tosctl pool liquid controller stop-withdraw` | `stop_and_withdraw_controller` | Missing | Same domain |
| `tosctl pool liquid controller add` | `add_controller` | Missing | Same domain |
| `tosctl pool liquid check` | `check_liquid_pool` | Missing | Same domain |
| `tosctl pool liquid controller test-loan` | `test_calculate_loan_amount` | Missing | Expert helper |

### 8. Validator Voting and Governance

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl vote offer ls` | `ol` | Missing | Current voting is service-side automation, not explicit CLI parity |
| `tosctl vote offer diff` | `od` | Missing | No parity command |
| `tosctl vote offer cast` | `vo` | Missing | No parity command |
| `tosctl vote complaint ls` | `cl` | Missing | No parity command |
| `tosctl vote complaint cast` | `vc` | Missing | No parity command |
| `tosctl vote election ls` | `el` | Missing | No parity command |
| `tosctl vote election cast` | `ve` | Missing | No parity command |
| `tosctl observe efficiency` | `check_ef` | Missing | No parity command |
| `tosctl observe validators` | `vl` | Partial | `api validators` exists, but not as broad operator parity surface |

### 9. Collator and Validator-Console Derived Operations

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl node collator add` | `add_collator` | Missing | No `node` group yet |
| `tosctl node collator rm` | `delete_collator` | Missing | Same |
| `tosctl node collator ls` | `print_collators` | Missing | Same |
| `tosctl node collator reset` | `reset_collators` | Missing | Same |
| `tosctl node collator setup` | `setup_collator` | Missing | Same |
| `tosctl node collator local` | `print_local_collators` | Missing | Same |
| `tosctl node collator stop` | `stop_collator` | Missing | Same |
| `tosctl node collation-whitelist add` | `add_validator_to_collation_wl` | Missing | Same |
| `tosctl node collation-whitelist rm` | `delete_validator_from_collation_wl` | Missing | Same |
| `tosctl node collation-whitelist disable` | `disable_collation_wl` | Missing | Same |
| `tosctl node collation-whitelist ls` | `print_collation_whitelist` | Missing | Same |
| `tosctl node collator-config set` | `set_collation_config` | Missing | Same |
| `tosctl node collator-config refresh` | `update_collation_config` | Missing | Same |
| `tosctl node collator-config show` | `print_collation_config` | Missing | Same |

### 10. Custom Overlay Operations

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl node overlay add` | `add_custom_overlay` | Missing | No overlay support yet |
| `tosctl node overlay ls` | `list_custom_overlays` | Missing | No overlay support yet |
| `tosctl node overlay rm` | `delete_custom_overlay` | Missing | No overlay support yet |

### 11. Account Utility Operations

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl account status` | `vas` | Missing | No generic account command group yet |
| `tosctl account txs` | `vah` | Missing | Same |
| `tosctl account bookmark add` | `nb` | Missing | Same |
| `tosctl account bookmark ls` | `bl` | Missing | Same |
| `tosctl account bookmark rm` | `db` | Missing | Same |

### 12. Alert and Telemetry Operations

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl observe alert enable` | `enable_alert` | Missing | No alert command group yet |
| `tosctl observe alert disable` | `disable_alert` | Missing | Same |
| `tosctl observe alert ls` | `list_alerts` | Missing | Same |
| `tosctl observe alert test` | `test_alert` | Missing | Same |
| `tosctl observe alert setup` | `setup_alert_bot` | Missing | Same |
| `tosctl observe metrics show` | Prometheus parity | Missing | Needed for telemetry parity |
| `tosctl observe metrics push` | Prometheus parity | Missing | Needed for telemetry parity |

### 13. Expert / Integration Operations

| Target `tosctl` command | Legacy Operator Shell source commands | Status | Notes |
|---|---|---|---|
| `tosctl admin btc-teleport rm` | `remove_btc_teleport` | Missing | Keep as admin-only |

## Recommended Delivery Milestones

### Milestone 1: Operator Shell Foundations

Goal:

- create the top-level command groups needed to stop further command sprawl

Deliver:

- `host`
- `backup`
- `wallet`
- `pool`
- `vote`
- `node`
- `account`
- `observe`
- `admin`

Patch breakdown:

1. extend `cli_cmd.rs` with new top-level groups
2. add empty module stubs under `commands/src/commands/`
3. add README sections for each new command family

Repository split:

| Repository | Tasks |
|---|---|
| `~/tos/tosctl` | add top-level command enums and module stubs, wire command dispatcher, add docs and help text, define shared output conventions |
| `~/tos` | none required for this milestone |

### Milestone 2: High-Value P0 Parity

Goal:

- cover the highest-frequency operator actions first

Deliver:

- `host about/status/mode/settings`
- `backup create/restore`
- `wallet ls/send/create/import/export/rm/set-version/activate`
- `pool ls/rm/import/get`
- `vote offer cast`, `vote complaint cast`, `vote election cast`
- `observe validators`, `observe efficiency`

Suggested file ownership:

- `host_cmd.rs`
- `backup_cmd.rs`
- `wallet_cmd.rs`
- `pool_cmd.rs`
- `vote_cmd.rs`
- `observe_cmd.rs`

Repository split:

| Repository | Tasks |
|---|---|
| `~/tos/tosctl` | implement `host`, `backup`, `wallet`, `pool`, `vote`, and `observe` CLI groups; reuse existing vault, chain-rpc-client, contracts, and service API clients; move imperative wallet send semantics out of `config wallet`; add README and setup docs |
| `~/tos` | only if a specific P0 command proves impossible without new node-side control or status exposure; default assumption is no `~/tos` patch is needed here |

### Milestone 3: Validator-Console Parity

Goal:

- move live validator and collator administration into `tosctl`

Deliver:

- `node collator ...`
- `node collation-whitelist ...`
- `node collator-config ...`
- `node net quic set`

Dependencies:

- control-client extensions for missing validator-console operations
- normalized output builders for console-derived data

Repository split:

| Repository | Tasks |
|---|---|
| `~/tos/tosctl` | implement `node collator`, `node collation-whitelist`, `node collator-config`, and `node net quic` command groups; extend `control-client` and command output normalization; document operator UX |
| `~/tos` | ✅ **No changes needed.** Investigation confirmed all operations have structured TL methods: `addCollator`, `delCollator`, `showCollatorsList`, `clearCollatorsList`, `setCollatorsList`, `collatorNodeSetWhitelistedValidator`, `collatorNodeSetWhitelistEnabled`, `showCollatorNodeWhitelist`, `setCollatorOptionsJson`, `getCollatorOptionsJson`, `addQuicAddr`, `delQuicAddr`, `getCollationManagerStats`. No text-console scraping required. |

### Milestone 4: Governance Inspection and Account Utilities

Goal:

- close the read/query gap around validators, accounts, and proposals

Deliver:

- `vote offer ls/diff`
- `vote complaint ls`
- `vote election ls`
- `account status/txs/bookmark ...`

Dependencies:

- embedded JSON-RPC or chain-rpc client support for needed account and history queries

Repository split:

| Repository | Tasks |
|---|---|
| `~/tos/tosctl` | implement `vote ... ls/diff`, `account status/txs/bookmark ...`, add bookmark persistence model, connect commands to chain-rpc client, add output formatters and docs |
| `~/tos` | ✅ **Done.** JSON-RPC now includes: `getTransactions` (account history), `getBlockTransactions`/`getBlockTransactionsExt` (block-level tx listing), `lookupBlock`, `getBlockHeader`, `getMasterchainInfo`, `shards`. Governance queries use existing `getConfigParam` (params 34, 36 for validators; param 11 for proposals) + `runGetMethod` on elector/config contracts. |

### Milestone 5: Alerts, Overlays, and Sidecar Parity

Goal:

- bring the remaining operator-experience features under `tosctl`

Deliver:

- `observe alert ...`
- `observe metrics ...`
- `node overlay ...`
- `host archive download`
- `host benchmark`

Repository split:

| Repository | Tasks |
|---|---|
| `~/tos/tosctl` | implement alert commands, metrics commands, overlay commands, archive/benchmark wrappers, sidecar lifecycle commands, configuration plumbing, and operator docs |
| `~/tos` | ✅ **Mostly done.** `/readyz` readiness endpoint added. Prometheus exporter already exists at `--exporter-address` with HTTP/QUIC metrics. `getStats` TL method provides sync state and block counters. Overlay TL methods (`addCustomOverlay`, `delCustomOverlay`, `showCustomOverlays`) already exist. Only gap: no node-side alert infrastructure (alerts are a `tosctl`-only concern). |

### Milestone 6: Liquid Staking and Expert Features

Goal:

- close the long tail of parity and keep advanced features out of the core UX

Deliver:

- `pool liquid ...`
- `admin btc-teleport rm`
- optional aliases for high-traffic `legacy operator shell` mnemonics

Repository split:

| Repository | Tasks |
|---|---|
| `~/tos/tosctl` | implement liquid-staking CLI groups, admin-only commands, aliases, advanced docs, and migration notes |
| `~/tos` | add missing contract/control/rpc support only if liquid-staking flows need new node-side or protocol-side capabilities beyond current `tosctl` libraries |

## Milestone-to-Repository Summary

> **Updated 2026-04-13 with `~/tos` implementation results**

| Milestone | `~/tos/tosctl` scope | `~/tos` scope | `~/tos` status |
|---|---|---|---|
| 1. Operator Shell Foundations | New top-level command groups, CLI scaffolding, docs | None | N/A |
| 2. High-Value P0 Parity | Main CLI implementation for host/backup/wallet/pool/vote/observe | Only if a P0 command lacks existing node-side exposure | ✅ JSON-RPC read APIs now available (`getMasterchainInfo`, `lookupBlock`, `getTransactions`, etc.) |
| 3. Validator-Console Parity | Control-client extensions, `node ...` UX, formatting, docs | Control-plane additions and structured node status surfaces | ✅ **No `~/tos` changes needed.** All collator/whitelist/config/QUIC/overlay operations already have structured TL methods. |
| 4. Governance Inspection and Account Utilities | Vote inspection, account queries, bookmarks, docs | JSON-RPC/read API additions in `validator-engine` as needed | ✅ `getTransactions`, `getBlockTransactions`, `getBlockHeader`, `getConfigParam`, `runGetMethod` all available for governance queries |
| 5. Alerts, Overlays, and Sidecar Parity | Alert UX, metrics UX, overlay UX, wrappers | Metrics/overlay node capabilities if missing | ✅ `/readyz` endpoint added; `getStats` TL method and Prometheus exporter already exist; overlay TL methods already exist |
| 6. Liquid Staking and Expert Features | Liquid CLI, admin CLI, aliases, docs | Protocol/control support only if libraries are insufficient | ⚠️ ControllerWrapper trait + impl built. 13 CLI commands registered (6 ✅ Full, 1 ⚠️ Partial, remainder TBD). |

## Practical Rule of Thumb

Use this rule when deciding where a task belongs:

- if the task is primarily CLI structure, config plumbing, workflow orchestration, output formatting, migration UX, or documentation, it belongs in `~/tos/tosctl`
- if the task requires new node-native HTTP/JSON-RPC methods, new validator control-plane methods, new structured node status exposure, or changes inside `validator-engine`, it belongs in `~/tos`
- if a `tosctl` command can be implemented cleanly by reusing existing `control-client`, `chain-rpc-client`, or contract wrappers, prefer keeping the work entirely in `~/tos/tosctl`

## Implementation Priority

Most P0, P1, P2 items have been implemented, but not all are fully functional. See [next-steps.md](next-steps.md) for the unified remaining work list.

### P0 — Mostly complete (some partial/guided)

- `host` (12): 7 ✅ Full (about, status, mode status, settings show/get/set, benchmark), 2 ⚠️ Partial (mode enable/disable — VALIDATOR works, LITESERVER/COLLATOR prints guidance only), 3 📋 Guided (update, upgrade, archive download)
- `backup` (3): ✅ All 3 Full
- `wallet` (8): ✅ All 8 Full
- `pool` basic (4): ✅ All 4 Full
- `pool single` (3): ✅ All 3 Full
- `pool nominator` (5): 3 ✅ Full (update-validator-set, deposit, withdraw), 1 ⚠️ Partial (create — saves config only), 1 📋 Guided (activate — prints BOC guidance)
- `vote` cast (3): 1 ⚠️ Partial (election cast — dry-run only), 2 📋 Guided (offer cast, complaint cast — explain flow, defer)
- `node` collator (20): ✅ All 20 Full

### P1 — ✅ All complete

- vote list/diff, account utilities, collator config/whitelist, overlays, alerts

### P2 — Mostly complete

- liquid staking (13): 6 ✅ Full, 1 ⚠️ Partial (controller create — saves placeholders), remaining TBD
- benchmark: ✅ Full
- archive download: 📋 Guided (prints wget commands)
- admin btc-teleport: status TBD

## Suggested Acceptance Criteria

Parity should not be considered complete until all of the following are true:

1. every `legacy operator shell` public command has a documented `tosctl` replacement path
2. every replacement path exists as a first-class `tosctl` command or a documented compatibility alias
3. operator docs no longer require `legacy operator shell` for routine TOS workflows
4. at least the P0 and P1 command families have table and JSON output modes where applicable

## Summary

`tosctl` already has useful building blocks, but today it only covers a small part of `legacy operator shell` as an operator shell.

This backlog is the execution layer for closing that gap. The intended implementation order is:

1. add missing command groups
2. implement P0 operator workflows
3. implement validator-console-derived parity
4. close remaining inspection, alerting, and liquid-staking gaps

## `~/tos` Node-Side Readiness (2026-04-13)

The `~/tos` side of the parity plan is now substantially complete. All milestones 1–5 have their `~/tos` dependencies resolved:

| Milestone | `~/tos` status | Blocker for `tosctl`? |
|---|---|---|
| 1. Operator Shell Foundations | N/A (no `~/tos` work) | No |
| 2. High-Value P0 Parity | ✅ JSON-RPC read APIs available | No |
| 3. Validator-Console Parity | ✅ All TL methods exist | No |
| 4. Governance Inspection | ✅ Block/tx/config APIs available | No |
| 5. Alerts, Overlays, Sidecar | ✅ Readyz, metrics, overlay TL | No |
| 6. Liquid Staking | Not yet assessed | Possibly |

**legacy operator shell parity implementation is substantially started.** All 87 public commands have tosctl subcommand registrations, but not all are fully functional: 78 are full end-to-end implementations, 5 are partial (do some real work but key parts are missing), 6 are guided (print instructions but do not perform the operation), and install wizard is not implemented.

### Implementation status (2026-04-13)

- ✅ **Milestone 1** — 9 command groups, 89 subcommands registered
- ⚠️ **Milestone 2** — most P0 commands implemented: wallet full lifecycle (✅ Full), pool basics (✅ Full), pool single (✅ Full), pool nominator (3 ✅ Full, 1 ⚠️ Partial create, 1 📋 Guided activate), host about/status/mode/settings (6 ✅ Full, 2 ⚠️ Partial mode enable/disable non-VALIDATOR), host update/upgrade (2 📋 Guided), node status/ping/probe (✅ Full), backup (✅ Full), vote cast (1 ⚠️ Partial election cast, 2 📋 Guided offer/complaint cast)
- ✅ **Milestone 3** — control-client 13+ TL methods, all collator/whitelist/config/overlay/quic commands wired (✅ Full)
- ⚠️ **Milestone 4** — vote offer ls/diff (✅ Full), election ls (✅ Full), complaint ls (✅ Full), account status/txs/bookmark (✅ Full). Cast commands: see Milestone 2.
- ⚠️ **Milestone 5** — alert system (✅ Full), overlay TL (✅ Full), host benchmark (✅ Full), host archive download (📋 Guided), observe metrics (✅ Full)
- ⚠️ **Milestone 6** — ControllerWrapper trait + impl, liquid staking commands (6 ✅ Full, 1 ⚠️ Partial controller create, pool liquid check ✅ Full)
- ✅ **Staking contracts** — 3 suites TOS-adapted, FunC compiled, BOC hex in tosctl
- ✅ **Contract wrappers** — SingleNominator + NominatorPool + LiquidController
- ✅ **Tests** — 47 contract unit tests passing

### What's next

> **See [next-steps.md](next-steps.md) for the unified priority list.**

The parity gap is mostly closed but 5 partial and 6 guided commands still need completion. The next phase includes both **finishing implementations** and **production hardening**:
1. Complete partial commands: host mode enable/disable for LITESERVER/COLLATOR, vote election cast (actual bid submission), pool nominator create (deployment), pool liquid controller create (deployment)
2. Complete guided commands: host update/upgrade, host archive download, vote offer/complaint cast, pool nominator activate
3. Implement install wizard
4. On-chain staking contract verification (P0 #1)
5. End-to-end testing on TOS testnet (P0 #2)
6. JSON-RPC request timeout to prevent hung HTTP server (P0 #3)
7. Operator documentation (P1 #4)
8. JSON output mode for all commands (P1 #5)
