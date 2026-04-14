# Phase 6 Migration Note — Service Mode, API, and Snapshot Alignment

**Date:** 2026-04-12  
**Phase:** 6 of 8 (executed 6th per recommended order)  
**Status:** Complete

---

## What Changed

### REST API / Swagger

- **OpenAPI description** updated to: "TOS node operations service API. Validator management, monitoring, elections, and staking."
- **API title** was already `"tosctld API"` — no change needed
- All endpoint descriptions, response schemas, and error messages were already TOS-free

### Service Mode

- **No TON references found** in any service task, HTTP handler, auth module, or runtime config
- Previous phases already migrated `contracts_task.rs` (Phase 2) and `election_task.rs` (Phase 2/4)
- Snapshot structures updated to "nanotos" in Phase 4

### Audit Results

| Component | Status |
|-----------|--------|
| REST endpoints (`/health`, `/elections`, `/validators`, `/stake-policy`, etc.) | Clean — TOS-neutral |
| Swagger/OpenAPI spec | Updated — TOS-branded description |
| Authentication (JWT, login, user management) | Clean — network-agnostic |
| Service task management (enable/disable/restart) | Clean — network-agnostic |
| Runtime config reload | Clean — uses `chain_rpc` field |
| Snapshot store (`ElectionsSnapshot`, `ValidatorsSnapshot`) | Clean — "nanotos" units |

---

## Files Changed

- `src/node-control/service/src/http/http_server_task.rs` — OpenAPI description

---

## Validation

- `cargo check -p tosctl` — passes with zero warnings
- `cargo test` — **284 tests pass, 0 failures**
- No operator-facing TON references remain in service code
- All remaining "TON" in codebase are internal compatibility comments documenting the TON→TOS inheritance

---

## Remaining Internal TON Comments (Intentionally Kept)

These comments explain where TOS inherits from TON and what needs testnet verification:

- `chain_provider.rs` — "TON-compatible implementation" adapter docs
- `wallet_contract.rs` — "wallet code cells are from TON mainnet"
- `single_nominator.rs` — "contract code from TON"
- `runner.rs` — "fee assumes same elector gas costs as TON"
- `client_adnl.rs` — "same protocol as TON"
- `config_params.rs` — "param structure from TON"

These are documentation of the compatibility relationship, not operator-facing text.
