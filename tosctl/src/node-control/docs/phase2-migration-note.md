# Phase 2 Migration Note — RPC and Provider Abstraction

**Date:** 2026-04-12  
**Phase:** 2 of 8  
**Status:** Complete

---

## What Changed

### Provider Abstraction Completed

The `ChainProvider` trait (introduced earlier) is now the primary RPC abstraction used by service-level consumers:

- **`RuntimeConfig` trait** — added `chain_provider()` method returning `Arc<dyn ChainProvider>`
- **`RuntimeState`** — stores both `Arc<ClientJsonRpc>` (for backward compat) and `Arc<dyn ChainProvider>`
- **`DefaultChainProvider`** — the adapter wrapping `ClientJsonRpc`, satisfying both `ChainProvider` and `ContractProvider`

### Service Consumers Migrated

- **`contracts_task.rs`** — migrated from `Arc<ClientJsonRpc>` to `Arc<dyn ChainProvider>`. All direct RPC calls now go through the trait: `get_address_info()`, `send_boc()`, `run_get_method()`
- **`election_task.rs`** — migrated from `Arc<ClientJsonRpc>` to `Arc<dyn ChainProvider>`. Uses `contract_provider_from()` bridge to satisfy `ElectorWrapperImpl` which needs `ContractProvider`
- **`service/src/task/mod.rs`** — elections task now receives `chain_provider()` instead of `rpc_client()`

### Bridge Adapter Added

- **`contract_provider_from()`** — new function in `contracts::chain_provider` that converts `Arc<dyn ChainProvider>` → `Arc<dyn ContractProvider>`. This bridges the two trait layers without requiring trait upcasting.

### TON → TOS Naming in Code

- All `TON` references in `contracts_task.rs` comments and log messages updated to `TOS`

### Compatibility Decision Documented

- **`docs/tos-rpc-compatibility.md`** — documents the decision to use TON-compatible JSON-RPC as the temporary backend, lists all RPC methods used, compatibility assumptions, and migration path to a TOS-native RPC

---

## Files Changed

- `src/node-control/contracts/src/chain_provider.rs` — added `ContractProviderAdapter` + `contract_provider_from()`
- `src/node-control/contracts/src/lib.rs` — export `contract_provider_from`
- `src/node-control/service/src/runtime_config.rs` — added `chain_provider` to `RuntimeState`, `RuntimeConfig` trait, and all construction sites
- `src/node-control/service/src/contracts/contracts_task.rs` — migrated to `ChainProvider`
- `src/node-control/elections/src/election_task.rs` — migrated to `ChainProvider`
- `src/node-control/service/src/task/mod.rs` — updated election task wiring
- `src/node-control/service/src/task/task_manager.rs` — test mock updated
- `src/node-control/service/src/auth/user_store.rs` — test mock updated

---

## Validation

- `cargo check -p tosctl` — passes with zero warnings
- Provider abstraction is in place: higher-level code uses `ChainProvider`, not `ClientJsonRpc`
- Existing chain queries work through `DefaultChainProvider` adapter

---

## What Remains (Not in Phase 2 Scope)

- **Command-level migration**: CLI commands in `commands/src/commands/nodectl/` still instantiate `ClientJsonRpc` directly. These are standalone entry points (not service-mode), so they don't benefit from the trait abstraction until Phase 8 cleanup.
- **`open_wallet` / `open_nominator_pool`**: Still take `Arc<ClientJsonRpc>` and use `contract_provider!` macro. Can be migrated when `RuntimeConfig` fully drops `rpc_client()`.
- **TOS-native RPC backend**: Not implemented. The `ChainProvider` trait is ready for a new implementation when TOS defines its own RPC protocol.

---

## Known Risks

- The `rpc_client()` method on `RuntimeConfig` is kept for backward compatibility but should be deprecated in Phase 8.
- If TOS RPC diverges from TON JSON-RPC, only `DefaultChainProvider` and `ClientJsonRpc` need updating — no higher-level code is affected.
