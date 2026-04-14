# TOS Tooling Consolidation Design

## Goal

TOS inherited a fragmented operator toolchain from the legacy ecosystem. Core operational workflows are currently split across:

- standalone C++ binaries in `~/tos`
- Python test and bootstrap utilities
- shell scripts for installation and service control
- an external legacy-style HTTP API service
- the Rust operator tool `~/tos/tosctl`

The goal is to consolidate operator-facing workflows into two primary surfaces:

1. `validator-engine` for node-native read APIs and embedded JSON-RPC
2. `tosctl` for operator control, bootstrap, deployment, diagnostics, and automation

This document defines what should be absorbed, what should remain as low-level implementation detail, and what should remain expert-only tooling.

An additional explicit goal is now required:

3. `tosctl` must reach functional coverage of the operator command surface that TOS operators currently expect from `mytonctrl`

This does not mean copying the original interactive UX or preserving every short alias verbatim. It means:

- every operational workflow exposed by `mytonctrl` must have a first-class `tosctl` path
- routine validator operations must not require switching back to `mytonctrl`
- legacy `mytonctrl` command names may exist as compatibility aliases, but the primary UX should follow the `tosctl` command model

The detailed parity mapping is tracked in:

- `doc/tosctl-mytonctrl-parity-design.md`

## Design Principles

- Operator-facing workflows must have one obvious entrypoint.
- Standalone legacy binaries should not remain the default user experience.
- Node-native functionality should live in `validator-engine` when it depends on local node state and should be exposed over stable APIs.
- Multi-step operational procedures should move into `tosctl`.
- Low-level developer tools may remain standalone, but should not be required for routine validator operations.
- `mytonctrl` parity should be evaluated by workflow coverage, not by whether the old short command aliases survive.
- Declarative configuration, live node control, host lifecycle, and chain-facing contract actions should be separated cleanly even when `mytonctrl` mixed them together.

## Current Fragmentation

The current TOS operator experience is spread across the following categories.

### Node Control

- `validator-engine-console`
- raw ADNL control protocol flows
- manual key and validator configuration operations

### Read-Only Chain Inspection

- `lite-client`
- external TOS-compatible HTTP API deployments
- partial overlap with `toslib-cli`

### Bootstrap and Deployment

- `scripts/setup-testnet.sh`
- `scripts/testnet-ctl.sh`
- Python `tostester.Network` setup logic
- direct `systemd` unit generation
- manual copying of binaries and Fift libraries

### Key, Config, and Zerostate Generation

- `generate-random-id`
- `create-state`
- Fift include path management
- ad hoc global and local config generation

### DNS and Site Operations

- `lite-client`
- `toslib-cli`
- `rldp-http-proxy`

### Diagnostics and Observability

- DHT and ADNL helper binaries
- consensus explorer Python UI
- `show-validator-set`
- log parsing and validator-set inspection tools

### Legacy Operator Surface

- `mytonctrl` host lifecycle commands
- wallet and pool management commands
- validator voting and complaint workflows
- collator and collation-whitelist commands
- backup and restore commands
- alert-bot, overlay, and telemetry workflows

This is the most important remaining operator-experience gap. Even when TOS-specific architecture differs internally, operators still expect this surface to exist.

## Consolidation Target

### A. Absorb into `validator-engine`

These capabilities belong inside the node because they are node-native read services or should be exposed through an embedded API surface.

#### 1. Embedded JSON-RPC

`validator-engine` should expose the standard read path that currently requires an external TOS-compatible HTTP API process.

Expected scope:

- chain state queries
- config parameter queries
- account inspection
- `runGetMethod`
- message broadcast
- health and readiness endpoints

Result:

- external `tos-http-api` becomes optional or deprecated for normal deployments
- node operators no longer need a separate Python/Docker bridge just to expose HTTP/JSON-RPC

#### 2. Read-Only Lite Query Backend

`lite-client` should stop being the primary operator interface for routine read operations.

Its protocol logic may still survive internally, but the user-facing path should move to:

- embedded JSON-RPC in `validator-engine`
- higher-level `tosctl` commands

#### 3. Native Health and Export Surfaces

Node-native telemetry and readiness should be served by `validator-engine`, not reconstructed through shell wrappers or ad hoc probing.

Expected scope:

- sync state
- liteserver readiness
- control-plane readiness
- validator role status
- metrics/exporter integration

### B. Absorb into `tosctl`

These capabilities are operator workflows and should be unified under the Rust operations tool.

#### 1. Control Plane Operations

`validator-engine-console` functionality should be wrapped and progressively replaced by `tosctl`.

Expected `tosctl` ownership:

- node registration and connectivity checks
- key generation and export through the control plane
- validator permanent/temp key workflows
- ADNL address registration
- validator config fetch and status inspection
- node maintenance operations now exposed only through console commands

`validator-engine-console` may remain as a low-level fallback tool, but should no longer be the primary UX.

#### 2. Bootstrap and Installation

The workflows in `setup-testnet.sh` and `testnet-ctl.sh` should move into `tosctl`.

Expected `tosctl` ownership:

- install binaries and shared assets
- initialize working directories
- generate and write configs
- create and manage `systemd` services
- start/stop/restart/status/logs
- local devnet and testnet bootstrap

This removes the current shell plus Python dependency chain for normal operator setup.

The same `tosctl` surface should also absorb the host-oriented install and mode-management workflows that TOS operators currently perform through `mytonctrl`.

#### 3. Key, Zerostate, and Config Generation

The current composition of `generate-random-id`, `create-state`, Fift libraries, and Python orchestration should be wrapped by `tosctl`.

Expected `tosctl` ownership:

- node key generation
- liteserver and console key generation
- DHT signed address generation
- global config generation
- local validator config generation
- zerostate creation for local/dev/test environments

Low-level binaries may remain internal dependencies, but operators should not have to compose them manually.

#### 4. DNS, Account, and Chain Inspection

High-level functions currently split between `lite-client` and `toslib-cli` should become first-class `tosctl` commands.

Expected command families:

- `tosctl chain ...`
- `tosctl dns ...`
- `tosctl account ...`
- `tosctl config-param ...`

This should cover the common read workflows that operators use today in `lite-client`.

#### 5. Site and RLDP Operations

`rldp-http-proxy` should be controlled through `tosctl`, even if it remains a separate runtime binary.

Expected `tosctl` ownership:

- local proxy startup
- site exposure configuration
- DNS and RLDP preflight checks
- persistent config and service management for proxy mode

#### 6. Network Diagnostics

DHT and ADNL helper binaries should be surfaced through structured `tosctl` commands.

Expected command families:

- `tosctl net dht ...`
- `tosctl net adnl ...`
- `tosctl node ping`
- `tosctl node probe`

#### 7. Consensus and Validator Observability

The Python `consensus_explorer` and helper binaries such as `show-validator-set` should be consolidated into `tosctl`-owned observability workflows.

Target outcome:

- `tosctl observe consensus`
- `tosctl observe validators`
- structured log/session analysis
- optional dashboard integration

The current Python test-tool placement under `test/` is not an appropriate long-term home for operator observability.

#### 8. MyTonCtrl Workflow Parity

`tosctl` should absorb the practical command families that make `mytonctrl` the de facto TOS operator shell today.

Required parity domains:

- host update, upgrade, install, status, settings, and mode toggles
- wallet creation, activation, import/export, deletion, and transfers
- pool creation, activation, deposit, withdraw, import, and inspection
- validator voting, complaints, offers, election-entry, and efficiency checks
- collator list, setup, stop, whitelist, and config management
- backup and restore
- custom overlays
- alert-bot setup and alert lifecycle
- liquid staking controller workflows

Parity does not require a one-to-one clone of `mytonctrl` internals. It does require a documented `tosctl` replacement path for every operator-visible command.

## Keep as Low-Level Internal Tools

These tools may remain standalone binaries, but should not be required for routine validator operations.

- `lite-client`
- `validator-engine-console`
- `generate-random-id`
- `create-state`
- `rldp-http-proxy`
- `show-validator-set`
- `dht-ping-servers`
- `dht-resolve`
- `adnl-proxy`

They should be treated as implementation detail, emergency fallback, or developer support tools.

## Keep as Expert/Developer Tools

These are not primary operator workflows and do not need to be merged into `tosctl` as first-class UX.

- `fift`
- `func`
- `tolk`
- `tlbc`
- `dump-block`
- `adjust-block`
- `create-hardfork`
- `storage-cli`
- `pack-viewer`
- `opcode-timing`

They should remain available for protocol engineering, contract development, forensic debugging, and recovery procedures.

## Priority Plan

### P0

- embedded JSON-RPC in `validator-engine`
- `tosctl` wrappers for validator control-plane operations
- `tosctl` service management replacing `testnet-ctl.sh`
- `tosctl` bootstrap/install flow replacing `setup-testnet.sh`
- `tosctl` command families that replace the core `mytonctrl` validator, wallet, pool, backup, and status workflows

### P1

- `tosctl` chain/account/DNS commands replacing routine `lite-client` usage
- `tosctl` wrapping zerostate, key, and config generation
- `tosctl` support for RLDP/site operations
- `tosctl` parity for collator, overlay, governance, and alert workflows now carried by `mytonctrl`
- `tosctl` DHT/ADNL diagnostics

### P2

- consensus explorer migration into `tosctl` observability surface
- gradual deprecation of external `tos-http-api`
- rationalization of remaining legacy support binaries

## Proposed End State

### Primary operator entrypoints

- `validator-engine`
- `tosctl`

### Secondary internal tools

- low-level protocol and bootstrap binaries called by `tosctl`
- fallback debugging tools for advanced operators

### Deprecated as primary UX

- manual shell orchestration
- Python-based bootstrap as the normal install path
- direct `validator-engine-console` use for routine operations
- external TOS HTTP API as the default HTTP access layer
- routine dependence on `lite-client` for operator workflows

## Non-Goals

- eliminating all standalone binaries immediately
- rewriting developer contract tooling into Rust
- removing expert-only recovery and forensic tools
- changing protocol behavior solely for UX consolidation

## Summary

TOS should converge on a simple model:

- `validator-engine` serves node-native APIs
- `tosctl` owns operator workflows
- legacy helper binaries become hidden dependencies or fallback tools

This consolidation reduces operator error, removes duplicated interfaces, and makes TOS operationally coherent instead of inheriting a fragmented legacy tooling surface.
