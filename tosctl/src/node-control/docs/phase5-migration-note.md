# Phase 5 Migration Note — Control Plane and Multi-Node Operations

**Date:** 2026-04-12  
**Phase:** 5 of 8 (executed 3rd per recommended order)  
**Status:** Complete

---

## What Changed

### Operator-Facing TON References Removed

All operator-visible "TON" currency references updated to "TOS":

- **config_wallet_cmd.rs** — 7 error/display messages: "Wrong amount TON", "Stake TON below minimum", "Already participating TON", "Insufficient balance TON", "Amount: TON", "Stake: TON", "Min Stake: TON"
- **config_pool_cmd.rs** — renamed `normalize_ton_address()` → `normalize_address()`, error message "invalid TON address" → "invalid address"
- **service_api_cmd.rs** — 3 table headers: "Stake TON", "Submitted TON", "Accepted TON"
- **deploy_cmd.rs** — 1 error message: "balance TON is too low"

### Currency Utility Functions Renamed

`common/src/chain_utils.rs` — all functions renamed from TON-specific to network-neutral:

| Old Name | New Name |
|----------|----------|
| `nanotons_to_dec_string` | `nanocoins_to_dec_string` |
| `tons_f64_to_nanotons` | `coins_to_nanocoins` |
| `nanotons_to_tons_f64` | `nanocoins_to_coins` |
| `display_tons` | `display_coins` |
| `display_tons_from_str` | `display_coins_from_str` |

Backward-compatible `#[doc(hidden)]` aliases preserve compilation of existing callers.

### Election Runner Constants

- `MIN_NANOTON_FOR_STORAGE` → `MIN_NANOCOIN_FOR_STORAGE`
- Doc comments updated from "nanotons" to "nanocoins"

### Control Plane Compatibility Documented

- **`docs/tos-control-plane-compatibility.md`** — documents all ADNL control methods, config param compatibility, gas fee constants, and divergence risk matrix

---

## Files Changed

- `src/node-control/common/src/chain_utils.rs` — function renames + aliases
- `src/node-control/commands/src/commands/nodectl/config_wallet_cmd.rs` — 7 TON→TOS fixes
- `src/node-control/commands/src/commands/nodectl/config_pool_cmd.rs` — function rename + error message
- `src/node-control/commands/src/commands/nodectl/service_api_cmd.rs` — 3 table header fixes
- `src/node-control/commands/src/commands/nodectl/deploy_cmd.rs` — 1 error message fix
- `src/node-control/elections/src/runner.rs` — constant rename + doc comments
- `src/node-control/elections/src/runner_tests.rs` — test references updated
- `src/node-control/service/src/contracts/contracts_task.rs` — test import fix

---

## Validation

- `cargo check -p tosctl` — passes with zero warnings
- `cargo test -p common -p elections -p contracts -p commands -p service` — **284 tests pass, 0 failures**
- No remaining operator-facing "TON" currency references in commands

---

## Known Risks

- Gas fee constants are inherited from TON and marked for TOS testnet verification
- TL schema compatibility assumed but not yet tested against live TOS nodes
- Config params 15, 34, 36 format assumed identical — documented for verification
