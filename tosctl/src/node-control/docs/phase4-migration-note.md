# Phase 4 Migration Note — Election and Validator Workflow Adaptation

**Date:** 2026-04-12  
**Phase:** 4 of 8 (executed 5th per recommended order)  
**Status:** Complete

---

## What Changed

### Currency naming: nanotons/nanocoins → nanotos

All currency unit references standardized to `nanotos` / `TOS`:

- **`chain_utils.rs`** — primary functions renamed: `nanotos_to_dec_string`, `tos_to_nanotos`, `nanotos_to_tos`, `display_tos`, `display_tos_from_str`. Backward-compatible aliases kept for `nanotons_*`, `nanocoins_*`, `tons_*`, `display_tons`, `display_coins`.
- **`app_config.rs`** — `StakePolicy::Fixed` display uses `nanotos_to_tos()`, outputs "fixed(N TOS)"
- **`snapshot.rs`** — all doc comments updated to "nanotos"
- **`runner.rs`** — doc comments updated to "nanotos"
- **`chain_provider.rs`**, **`provider.rs`** — balance doc comments updated to "nanotos"
- **`nominator/messages.rs`** — stake doc comment updated to "nanotos"
- **`config_wallet_cmd.rs`** — fee doc comment updated to "nanotos"

### Test comments: TON → TOS

All test data comments in `runner_tests.rs` updated from "TON" to "TOS" (8 occurrences).

### Zero remaining operator-facing "TON" string literals

Verified: `grep` for `".*TON.*"` in all `.rs` files returns zero matches.

---

## Files Changed

- `src/node-control/common/src/chain_utils.rs`
- `src/node-control/common/src/app_config.rs`
- `src/node-control/common/src/snapshot.rs`
- `src/node-control/contracts/src/chain_provider.rs`
- `src/node-control/contracts/src/provider.rs`
- `src/node-control/contracts/src/nominator/messages.rs`
- `src/node-control/commands/src/commands/nodectl/config_wallet_cmd.rs`
- `src/node-control/elections/src/runner.rs`
- `src/node-control/elections/src/runner_tests.rs`

---

## Validation

- `cargo check -p tosctl` — passes with zero warnings
- `cargo test` — **284 tests pass, 0 failures**

---

## Election Workflow Compatibility Summary

The election automation is preserved and operates identically on TOS:

| Component | Status |
|-----------|--------|
| Election runner (`runner.rs`) | Compatible — same lifecycle model |
| Config params 15/34/36 parsing | Compatible — same structure |
| Elector get-methods | Compatible — same ABI |
| Single nominator staking flow | Compatible — same opcodes |
| Validator key registration | Compatible — same ADNL control API |
| Stake submission via wallet | Compatible — same message format |
| Gas fee constants | Inherited from TON — flagged for TOS testnet verification |

All TON compatibility comments in election code are retained as they document the relationship and verification requirements.
