# Liquid Staking Contract Suite

## Origin

- FunC source from the TOS liquid-staking contract suite.
- Fift deployment scripts from [igroman787/jetton_pool](https://github.com/igroman787/jetton_pool) (used by legacy ops tooling)

## Purpose

Liquid staking system where validators borrow from a pool to increase their stake. Depositors receive Jetton tokens as receipts (like Lido stETH).

### Architecture

- **Pool contract** (`pool.func`) -- manages the liquidity pool, issues Jetton tokens to depositors
- **Controller contract** (`controller.func`) -- per-validator loan management (2 controllers per validator, even/odd rotation)
- **Payout NFT** (`payout_nft/`) -- NFT-based payout distribution for reward claims
- **Supporting modules** -- address calculations, assertions, messages, governance, halting, versioning

### Contract Roles

- **Governor** -- protocol governance (parameter changes, halting)
- **Sudoer** -- emergency admin
- **Halter** -- can pause the protocol
- **Validator** -- borrows from pool, stakes via controller
- **Depositor** -- provides liquidity, receives Jetton tokens

## Files

### FunC Source (`*.func`)
| File | Purpose |
|---|---|
| `pool.func` | Main pool contract |
| `controller.func` | Validator controller contract |
| `pool_storage.func` | Pool state storage helpers |
| `pool_mint_helpers.func` | Jetton minting logic |
| `messages.func` | Message building utilities |
| `op-codes.func` | Operation code constants |
| `types.func` | Type definitions |
| `errors.func` | Error code constants |
| `asserts.func` | Assertion helpers |
| `address_calculations.func` | Address derivation |
| `network_config_utils.func` | Network config reading |
| `dao_params.func` | DAO parameter handling |
| `governor_requests.func` | Governor message handlers |
| `halter_requests.func` | Halter message handlers |
| `sudoer_requests.func` | Sudoer message handlers |
| `librarian.func` | Library management |
| `metadata_utils.func` | Metadata handling |
| `versioning.func` | Contract versioning |
| `payout_nft/*.func` | NFT collection and item contracts |

### Fift Scripts (pre-compiled BOCs)
| File | Purpose |
|---|---|
| `deploy_controller0.boc` | Deploy controller 0 |
| `deploy_controller1.boc` | Deploy controller 1 |
| `top-up.boc` | Deposit to controller |
| `recover_stake.boc` | Recover stake from elector |
| `return_unused_loan.boc` | Return unused loan to pool |
| `update_validator_hash.boc` | Update validator set hash |
| `deposit.boc` | Deposit to pool |
| `controller-elect-signed.fif` | Election entry via controller |
| `generate-loan-request.fif` | Generate loan request |
| `withdraw-controller.fif` | Withdraw from controller |

### Tests (`tests/*.ts`)
TypeScript test suite (requires Blueprint/TOS testing framework):
- Controller.spec.ts, ControllerPool.spec.ts
- Governor.spec.ts, Integrational.spec.ts
- SmokeNFT.spec.ts, DepositFees.spec.ts, WithdrawFees.spec.ts, etc.

## TOS Compatibility

Not yet audited. This is the most complex contract suite. Requires:
1. Recompile all `.func` files with TOS FunC compiler
2. Verify `load_coins()`/`store_coins()` mapping
3. Verify elector interface compatibility
4. Verify Jetton standard compatibility on TOS
5. Port TypeScript tests to TOS testing environment
