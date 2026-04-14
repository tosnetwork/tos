# Nominator Pool Contract (Multi-Nominator)

## Origin

FunC source from [TOS Blockchain](https://github.com/ton-blockchain/nominator-pool), copied from tos-c/crypto/func/auto-tests/legacy_tests/nominator-pool/.

## Purpose

Multi-nominator staking pool supporting up to ~40 nominators pooling funds for one validator.

- Supports multiple depositors (nominators)
- Validator takes configurable reward share percentage
- Remaining rewards distributed proportionally to nominators
- Manages deposit queues, withdrawal requests, and reward distribution
- Tracks validator set changes for staking cycle management

## Files

| File | Purpose |
|---|---|
| `pool.fc` | Main FunC source (746 lines) |
| `stdlib.fc` | FunC standard library (bundled for self-contained compilation) |

## Key Get-Methods

- `get_pool_data()` -- full pool state (nominators, stakes, config, queues)
- `get_nominator_data(addr)` -- individual nominator balance and pending deposit
- `has_withdraw_requests()` -- check if withdrawal queue is non-empty

## TOS Compatibility

Adapted for TOS. The contract uses `load_coins()`/`store_coins()` throughout (never raw
`load_grams`/`store_grams`), and the bundled `stdlib.fc` has been replaced with the TOS
system stdlib where these are aliased to `LDTOMIS`/`STTOMIS`. Constants renamed:
`ONE_TON` -> `ONE_TOS`, `MIN_TONS_FOR_STORAGE` -> `MIN_TOS_FOR_STORAGE`. No logic changes.

Compile with the TOS FunC compiler.
