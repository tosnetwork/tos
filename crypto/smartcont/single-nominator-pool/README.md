# Single Nominator Pool Contract

## Origin

FunC source from [Orbs Network](https://github.com/orbs-network/single-nominator), adapted for TOS.

## Purpose

Simplified staking pool for a single validator owner. Separates cold wallet (owner) from validator hot wallet.

- Owner: can withdraw, change validator address, emergency raw_msg, upgrade
- Validator: can only send/recover stake to/from elector
- Validator controller: the account a stake is relayed through on its way to the elector
- No multi-nominator support, no reward distribution logic

A stake no longer goes from here to the elector. It goes to the validator controller
named in storage, which relays it and states this contract as whose money it is. The
controller is part of the storage the contract's address is derived from, so it is chosen
before deployment and cannot be changed afterwards.

## Files

| File | Purpose |
|---|---|
| `single-nominator-code.fc` | Main FunC source (223 lines) |
| `single-nominator.tlb` | TL-B type definitions |
| `single-nominator-code.hex` | Pre-compiled BOC; regenerate from the source above when it changes |
| `init.fif` | Contract initialization Fift script |
| `withdraw.fif` | Withdrawal message builder |
| Other `.fif` files | Helper scripts |

## TOS Compatibility

Audited 2026-04-13. Uses `store_coins()`/`load_coins()` which map to TOS `STTOMIS`/`LDTOMIS` (same binary opcode). Elector address read dynamically via `config_param(1)`. **Compatible as-is.**

Recommended: recompile with TOS FunC compiler and verify byte-level equivalence.
