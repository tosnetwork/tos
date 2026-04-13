# Phase 1 Migration Note — Operator-Facing Rename Completion

**Date:** 2026-04-12  
**Phase:** 1 of 8  
**Status:** Complete

---

## What Changed

### CLI Help Strings
- `"Send TON"` → `"Send TOS"` in wallet send command
- `"Fixed stake amount in TON"` → `"Fixed stake amount in TOS"` in elections and config commands

### Environment Variable
- `NODECTL_API_TOKEN` → `TOSCTL_API_TOKEN` in service API command

### Documentation
- **README.md**: all `config chain-rpc` references → `config chain-rpc`, `ton_http_api` config section → `chain_rpc`, removed third-party example URLs, updated section headers and table of contents
- **tosctl-setup.md**: "Configure TON HTTP API" section → "Configure Chain RPC", command examples updated
- **Code comments**: doc comments in `app_config.rs` and `chain_provider.rs` updated from `chain-rpc` to `chain-rpc`

### Config Files and Scripts
- **local_service.yaml**: `ton_http_api` section → `chain_rpc` with `urls` list format
- **build-tosctl-config.sh**: jq command updated to write `chain_rpc` section

---

## Files Changed

- `src/node-control/commands/src/commands/nodectl/config_wallet_cmd.rs`
- `src/node-control/commands/src/commands/nodectl/config_elections_cmd.rs`
- `src/node-control/commands/src/commands/nodectl/config_cmd.rs`
- `src/node-control/commands/src/commands/nodectl/service_api_cmd.rs`
- `src/node-control/README.md`
- `src/node-control/docs/tosctl-setup.md`
- `src/node-control/common/src/app_config.rs`
- `src/node-control/contracts/src/chain_provider.rs`
- `src/node-control/nodectl/configs/local_service.yaml`
- `src/node-control/build-tosctl-config.sh`

---

## Validation

- `cargo check -p tosctl` — passes
- No remaining operator-facing `NODECTL_API_TOKEN`, `chain-rpc` CLI commands, or `ton_http_api` config references in docs
- Remaining `nodectl` references in README are historical context only (origin description, architecture diagram filename)

---

## Remaining TON-Origin Names (Internal, Not Operator-Facing)

These internal names still carry TON-origin naming. They are not user-facing and are scheduled for later phases:

- `commands/src/commands/nodectl/` — module directory name (Phase 8)
- `chain-rpc-client` crate uses `chain_rpc_rs` dependency internally (Phase 2)
- `tosctl-migration-audit.md` and `tosctl-implementation-tasks.md` contain historical TON references as part of their audit/planning purpose
- `CHANGELOG.md` historical entries reference `chain-rpc` (kept as historical record)

---

## Known Risks

- None for this phase. All changes are naming-only in help strings, docs, config examples, and code comments.
