# Single Nominator Pool Contract

## Origin

FunC source from [Orbs Network](https://github.com/orbs-network/single-nominator), adapted for TOS.

## Purpose

Simplified staking pool for a single validator owner. Separates cold wallet (owner) from validator hot wallet.

- Owner: can withdraw, change validator address, emergency raw_msg, upgrade
- Validator: can only send/recover stake to/from elector
- No multi-nominator support, no reward distribution logic

## Files

| File | Purpose |
|---|---|
| `single-nominator-code.fc` | Main FunC source (223 lines) |
| `single-nominator.tlb` | TL-B type definitions |
| `single-nominator-code.hex` | Pre-compiled BOC (needs TOS verification) |
| `init.fif` | Contract initialization Fift script |
| `withdraw.fif` | Withdrawal message builder |
| Other `.fif` files | Helper scripts |

## TOS Compatibility

Audited 2026-04-13. Uses `store_coins()`/`load_coins()` which map to TOS `STTOMIS`/`LDTOMIS` (same binary opcode). Elector address read dynamically via `config_param(1)`. **Compatible as-is.**

Recommended: recompile with TOS FunC compiler and verify byte-level equivalence.
