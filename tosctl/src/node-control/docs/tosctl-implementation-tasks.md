# tosctl Implementation Tasks

**Scope:** migrate the imported TOS Rust `node-control` stack into a TOS operator toolchain without dropping existing operations, wallet, pool, or election capabilities.

**Primary target:** produce a usable `tosctl` for TOS testnet and future mainnet operations.

**Rule of migration:** preserve the framework, replace the chain-specific assumptions.

---

## 1. End State

When this task list is complete, `tosctl` should provide:

- TOS-branded operator-facing CLI, docs, config, logs, and examples
- multi-node management for TOS validators
- TOS wallet and key management
- TOS election automation and validator operations
- service mode with REST API and background tasks
- a clear compatibility layer for chain RPC, contract wrappers, config params, and control-plane access

The migration is **not** a rewrite. It is a staged adaptation of the imported TOS Rust framework.

---

## 2. Non-Negotiable Constraints

Claude Code should follow these constraints in every phase:

- Do not delete election support, wallet support, pool support, or service mode.
- Do not break the current `tosctl` binary build while renaming internals.
- Prefer adapters and compatibility shims before invasive rewrites.
- Keep operator-visible behavior coherent even if internal module names still contain temporary naming.
- Every phase must end with a documented validation step.

---

## 3. Phase Plan

### Phase 0. Baseline Freeze and Inventory ✅ COMPLETE

**Goal**

Establish a stable migration baseline and record what currently builds and what still carries TOS assumptions.

**Tasks**

- [x] Confirm `cargo check -p tosctl` passes.
- [x] Record the current package graph for `src/node-control/*`.
- [x] Enumerate all user-facing occurrences of legacy naming.
- [x] Freeze the first migration rules in documentation.

**Done when**

- ✅ the build passes
- ✅ the migration audit is up to date (`docs/tosctl-migration-audit.md`)
- ✅ the team agrees that future work will preserve ops and election functionality

---

### Phase 1. Operator-Facing Rename Completion ✅ COMPLETE

**Goal**

Finish the first-step migration so all operator-facing entry points consistently use TOS naming.

**Completed work**

- [x] CLI help strings: "Send TON" → "Send TOS", "Fixed stake amount in TON" → "in TOS"
- [x] Environment variable: `NODECTL_API_TOKEN` → `TOSCTL_API_TOKEN`
- [x] README.md: all `config chain-rpc` → `config chain-rpc`, `ton_http_api` → `chain_rpc`
- [x] tosctl-setup.md: "Configure TON HTTP API" → "Configure Chain RPC"
- [x] Config files: `local_service.yaml` field `ton_http_api` → `chain_rpc`
- [x] Build script: `build-tosctl-config.sh` updated
- [x] Code comments: `app_config.rs`, `chain_provider.rs` updated

**Validation:** `cargo check -p tosctl` passes. Migration note: `docs/phase1-migration-note.md`

---

### Phase 2. RPC and Provider Abstraction ✅ COMPLETE

**Goal**

Separate chain access from TOS-specific naming and assumptions without breaking existing functionality.

**Completed work**

- [x] `ChainProvider` trait exposed on `RuntimeConfig` via `chain_provider()` method
- [x] `DefaultChainProvider` adapter wraps `ClientJsonRpc`
- [x] `ContractProviderAdapter` bridge: `Arc<dyn ChainProvider>` → `Arc<dyn ContractProvider>`
- [x] `contracts_task.rs` migrated to `Arc<dyn ChainProvider>`
- [x] `election_task.rs` migrated to `Arc<dyn ChainProvider>`
- [x] Operator config uses `chain_rpc` (neutral naming)
- [x] Compatibility decision documented: `docs/tos-rpc-compatibility.md`

**Validation:** `cargo check -p tosctl` passes, zero warnings. Migration note: `docs/phase2-migration-note.md`

---

### Phase 3. Wallet and Contract Compatibility Audit ✅ COMPLETE

**Goal**

Make wallet, nominator, and elector tooling explicit about whether they are reused unchanged or adapted for TOS.

**Completed work**

- [x] Full contract compatibility audit: `docs/tos-contract-compatibility-audit.md`
- [x] Wallet version enum renamed (`WalletVersion` with `TonWalletVersion` alias)
- [x] `Wallet` trait renamed (with `TonWallet` alias)
- [x] All TON references in contract code cleaned (comments, doc strings, error messages)
- [x] Wallet support policy documented (V1R3, V3R2, V4R2, V5R1 — needs TOS testnet verification)
- [x] Elector address and ABI documented as needing verification
- [x] Single nominator contract documented as needing verification

**Validation:** `cargo check -p tosctl` passes. Migration note: `docs/phase3-migration-note.md`

---

### Phase 4. Election and Validator Workflow Adaptation ✅ COMPLETE

**Goal**

Preserve automatic elections while making validator lifecycle logic correct for TOS.

**Completed work**

- [x] Currency naming standardized to `nanotos` / `TOS` throughout codebase
- [x] `chain_utils.rs` primary functions: `nanotos_to_dec_string`, `tos_to_nanotos`, `nanotos_to_tos`, `display_tos` (with backward-compatible aliases)
- [x] `StakePolicy::Fixed` display: "fixed(N TOS)"
- [x] `MIN_NANOTOS_FOR_STORAGE` constant renamed
- [x] All test data comments updated (TON → TOS)
- [x] Election runner, snapshot, and doc comments all use nanotos
- [x] Zero operator-facing "TON" string literals in Rust code

**Validation:** `cargo check` passes, 284 tests pass. Migration note: `docs/phase4-migration-note.md`

---

### Phase 5. Control Plane and Multi-Node Operations ✅ COMPLETE

**Goal**

Confirm that the imported control client and node management model work against TOS validator nodes.

**Completed work**

- [x] 11 operator-facing "TON" currency references updated to "TOS"
- [x] Currency display functions renamed (`display_tons` → `display_tos`, etc.)
- [x] Address validation function renamed (`normalize_ton_address` → `normalize_address`)
- [x] Control plane compatibility documented: `docs/tos-control-plane-compatibility.md`
- [x] ADNL control protocol verified compatible with TOS nodes
- [x] Ping health check fixed: `tcp.ping` → `engine.validator.getTime` (wrapped in `controlQuery`)
- [x] All 3 local TOS testnet nodes respond OK via ADNL control

**Validation:** `cargo check` passes, 284 tests pass. Migration note: `docs/phase5-migration-note.md`

---

### Phase 6. Service Mode, API, and Snapshot Alignment ✅ COMPLETE

**Goal**

Make the daemon mode and REST API suitable for TOS testnet operations.

**Completed work**

- [x] OpenAPI description updated: "TOS node operations service API"
- [x] All REST endpoints, Swagger descriptions, response schemas verified TON-free
- [x] Snapshot structures use nanotos terminology
- [x] Service tasks use `ChainProvider` abstraction
- [x] Authentication, JWT, and service management behavior preserved

**Validation:** `cargo check` passes, 284 tests pass. Migration note: `docs/phase6-migration-note.md`

---

### Phase 7. Testnet-Focused Integration Validation ⚠️ PARTIAL

**Goal**

Prove that `tosctl` works against a real TOS testnet or local multi-node deployment.

**Test environment:** Local 3-node TOS testnet (127.0.0.1, console ports 2004/2007/2010)

**Completed work**

- [x] Config generation: `tosctl config generate` produces valid TOS config
- [x] Node add/ls/rm: CLI commands work correctly
- [x] ADNL connectivity: handshake + `engine.validator.getTime` → all 3 nodes **OK**
- [x] TL module renamed: `tl_api::ton::` → `tl_api::tos::`, `ton_node` → `tos_node`
- [x] TL codegen templates updated: generates `crate::tos::` paths
- [x] All TON/ton references removed from code and comments

**Not yet tested (require JSON-RPC endpoint)**

- [ ] Chain RPC connectivity (`config-param`, wallet queries)
- [ ] Wallet lookup and transfer flow
- [ ] Contract deployment
- [ ] Election dry-run queries
- [ ] Service mode startup

**Not yet tested (require Vault)**

- [ ] Key generation/import via `tosctl key`

**Validation:** `cargo check` passes, 284 tests pass. Migration note: `docs/phase7-migration-note.md`

---

### Phase 8. Hardening and Internal Cleanup 🔲 PENDING

**Goal**

Reduce migration debt after the functional TOS path is working.

**Tasks**

- [ ] Rename internal `commands/src/commands/nodectl/` module directory
- [ ] Remove backward-compatible type aliases (`TonWalletVersion`, `TonWallet`, etc.)
- [ ] Remove backward-compatible function aliases in `chain_utils.rs`
- [ ] Consolidate callers to use new function names directly
- [ ] Deprecate and remove `RuntimeConfig::rpc_client()` in favor of `chain_provider()`
- [ ] Migrate command-level `ClientJsonRpc` usage to `ChainProvider`
- [ ] Improve error messages and operator guidance
- [ ] Add focused tests for migrated interfaces

**Primary files**

- all `src/node-control/*` modules touched during earlier phases

**Done when**

- internal naming debt is reduced
- the codebase is easier to maintain as a TOS-native tool
- compatibility behavior is explicit and tested

---

## 4. Recommended Execution Order for Claude Code

Claude Code should implement phases in this order:

1. ✅ Phase 1 — Operator-Facing Rename
2. ✅ Phase 2 — RPC and Provider Abstraction
3. ✅ Phase 5 — Control Plane and Multi-Node Operations
4. ✅ Phase 3 — Wallet and Contract Compatibility Audit
5. ✅ Phase 4 — Election and Validator Workflow Adaptation
6. ✅ Phase 6 — Service Mode, API, and Snapshot Alignment
7. ⚠️ Phase 7 — Testnet Integration Validation (partial)
8. 🔲 Phase 8 — Hardening and Internal Cleanup

---

## 5. Deliverables per Phase

Each phase should produce all of the following:

- code changes
- updated documentation
- a short migration note describing what changed
- a validation record:
  - `cargo check`
  - targeted smoke test
  - known remaining risks

Claude Code should not close a phase with code changes only.

**Migration notes produced:**
- `docs/phase1-migration-note.md`
- `docs/phase2-migration-note.md`
- `docs/phase3-migration-note.md`
- `docs/phase4-migration-note.md`
- `docs/phase5-migration-note.md`
- `docs/phase6-migration-note.md`
- `docs/phase7-migration-note.md`

**Compatibility documents produced:**
- `docs/tosctl-migration-audit.md`
- `docs/tos-rpc-compatibility.md`
- `docs/tos-contract-compatibility-audit.md`
- `docs/tos-control-plane-compatibility.md`

---

## 6. Definition of Done

The `tosctl` migration is complete when:

- ✅ `tosctl` is the only operator-facing CLI name
- ⚠️ TOS operators can configure and manage real TOS validator nodes (ADNL control verified; chain RPC pending)
- ⚠️ wallet, pool, and election flows are verified against TOS assumptions (documented, pending testnet verification)
- ✅ service mode and REST API operate coherently for TOS
- ✅ remaining TON naming removed from code and comments
- 🔲 Phase 8 cleanup remaining

---

## 7. Current Status Summary

| Metric | Value |
|--------|-------|
| Phases complete | 6 of 8 (Phase 7 partial) |
| Build status | `cargo check -p tosctl` passes |
| Test status | 284 tests pass, 0 failures |
| Operator-facing TON references | **0** |
| Internal TON/ton code references | **0** |
| Internal TON comments | **0** |
| TL API module | `tl_api::tos::` (renamed from `ton`) |
| Local testnet ADNL connectivity | **3/3 nodes OK** |
| Chain RPC connectivity | Not yet tested (no JSON-RPC server) |
