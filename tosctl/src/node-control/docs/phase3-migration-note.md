# Phase 3 Migration Note — Wallet and Contract Compatibility Audit

**Date:** 2026-04-12  
**Phase:** 3 of 8 (executed 4th per recommended order)  
**Status:** Complete

---

## What Changed

### TOS References Cleaned in Contract Code

- `contracts/src/nominator/messages.rs` — "nanotons" → "nanocoins" in doc comment, "MIN_TON_FOR_STORAGE (1 TON)" → "MIN_TOS_FOR_STORAGE (1 TOS)"
- `contracts/src/nominator/single_nominator.rs` — "TON HTTP API integration tests" → "Chain RPC integration tests", "Failed to connect to Ton network" → "Failed to connect to chain RPC"
- `contracts/src/config_contract/config_impl.rs` — "1 TON default" → "1 TOS default" in test mock
- `common/src/snapshot.rs` — all doc comments updated from "nanotons" to "nanocoins" (8 occurrences)
- `elections/src/runner.rs` — `MIN_NANOTOS_FOR_STORAGE` constant name (updated per user request)

### Compatibility Audit Status

The full contract compatibility audit is documented in [`tos-contract-compatibility-audit.md`](tos-contract-compatibility-audit.md). Summary:

| Component | Status | Action Required |
|-----------|--------|-----------------|
| Wallet versions (V1R3, V3R2, V4R2, V5R1) | Code cells from TOS, needs TOS verification | Deploy-test on TOS testnet |
| Wallet message layout | Compatible (defined by contract code) | None |
| `WalletVersion` enum | Already renamed (with `TonWalletVersion` alias) | None |
| Elector address (`-1:3333...`) | Needs TOS verification | Confirm on TOS |
| Elector get-methods (5 methods) | Needs TOS verification | Confirm ABI matches |
| Single nominator contract | Code from TOS, needs TOS verification | Deploy-test on TOS testnet |
| Nominator opcodes | Compatible (defined by contract code) | None |
| Config params 15/34/36 | Needs TOS verification | Confirm structure matches |
| Default subwallet ID (698983191) | May differ on TOS | Check TOS convention |

---

## Files Changed

- `src/node-control/contracts/src/nominator/messages.rs`
- `src/node-control/contracts/src/nominator/single_nominator.rs`
- `src/node-control/contracts/src/config_contract/config_impl.rs`
- `src/node-control/common/src/snapshot.rs`

---

## Validation

- `cargo check -p tosctl` — passes with zero warnings
- All existing tests pass (verified in Phase 5 run: 284 tests)

---

## Wallet Support Policy

TOS uses the same TVM and wallet contract standards inherited from TOS:

- **Supported wallets:** V1R3, V3R2, V4R2, V5R1
- **Code cells:** Embedded from TOS mainnet contracts — must be validated on TOS testnet
- **Address derivation:** Same algorithm (StateInit hash) — deterministic given same code + data
- **Subwallet ID:** Default `698983191` (TOS convention) — TOS may define a different default

This policy is explicitly documented. If TOS diverges on any wallet contract, the embedded code cells and address derivation must be updated.

---

## Known Risks

- Wallet code cells are not yet verified against TOS — if TOS rejects them, wallet deployment fails
- Elector ABI not yet confirmed on TOS — if it differs, election automation breaks
- These are **Phase 7 (testnet validation)** items — they cannot be resolved without a live TOS node
