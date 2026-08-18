# TOS Token Bridge

> **Status: experimental, testnet-only.** The contracts are disabled for production until an independent audit, an oracle-key ceremony, rate limits/caps, monitoring, and TOS governance activation are complete.

The TOS token bridge carries ERC-20 tokens from external EVM chains onto TOS as bridge-controlled wrapped Jettons. Assets are locked in an EVM `Bridge` contract and represented on TOS by deterministic Jetton minter/wallet contracts; an oracle quorum authorizes minting and unlocking. The state machine derives from a market-proven upstream architecture (see `NOTICE.md` for provenance and licensing) and is maintained here as first-class TOS source code.

## Components

### TOS/TVM side (`tvm/contracts/`, per-network parameters in `tvm/params/`)

- `jetton-bridge.fc`: accepts exact mint-fee payments, validates oracle multisig execution, deploys deterministic wrapped-token minters, emits paid-swap and burn logs.
- `jetton-minter.fc`: bridge-only minting, deterministic wallet deployment, supply accounting, burn forwarding.
- `jetton-wallet.fc`: TEP-74-style transfers plus EVM destination payload on burn.
- `multisig.fc`: threshold oracle voting for TOS-side mint/governance messages.
- `votes-collector.fc`: collects EVM-compatible oracle signatures for burn/unlock.
- Shared configuration, message, opcode, error, utility, and Fift deployment sources.

### EVM side (`evm/`)

- `Bridge.sol`: ERC-20 lock/unlock custody contract, oracle-set governance, pause/denylist, replay protection, and actual-balance accounting.
- `SignatureChecker.sol`: low-`s` ECDSA verification and digest domain separation by EVM chain ID and bridge address.
- `TosUtils.sol`: the shared cross-chain transaction/signature structs.
- Hardhat tests and test token contracts.

No production oracle daemon ships with this directory: it completes the smart-contract plane and documents the oracle protocol, but oracle operation remains an independently implemented and audited service.

## Flow

### ERC-20 → TOS Jetton

1. The user calls EVM `Bridge.lock(token, amount, tosAddressHash)`.
2. The bridge measures the actual token balance increase and emits `Lock`.
3. The user pays the exact TOS mint fee to `jetton-bridge` with the event-derived query ID.
4. Oracles verify both events and vote through the TOS multisig.
5. Once quorum is reached, `jetton-bridge` deterministically deploys/calls the wrapped-token minter and credits the user's Jetton wallet.

### TOS Jetton → ERC-20

1. The user burns wrapped Jettons and supplies a 160-bit EVM destination address.
2. Wallet → minter → bridge messages validate ownership and deterministic sender addresses.
3. `jetton-bridge` emits the burn log.
4. Oracles sign the burn; `votes-collector` assembles signatures.
5. Anyone submits the signed burn to EVM `Bridge.unlock`; replay protection marks the digest finished before transfer.

## TOS configuration slots

| External network | TOS ConfigParam | EVM chain ID |
|---|---:|---:|
| Ethereum | 79 | 1 |
| BNB Smart Chain | 81 | 56 |
| Polygon | 82 | 137 |
| Tron | 83 | 728126428 |

The ConfigParam must contain the TOS bridge address, oracle multisig address/map, state flags, fee schedule, and external chain bridge address. No slot is enabled or populated by this directory.

Tron is not an EVM chain, but its virtual machine is close enough for this contract plane: addresses are 20 bytes inside the VM, so the 160-bit destination field needs no change, and `ecrecover` is available for the counterparty half. Its `CHAINID` differs — it yields the last four bytes of the genesis block id rather than a registered chain id — so the chain id above is that value for Tron mainnet and must be confirmed against the target network before the slot is populated. The counterparty contracts have not been deployed or exercised on Tron; treat the slot as unproven configuration.

## Build and test the TVM contracts

With `func`/`fift` built (`cmake --build build --target func fift`):

```bash
scripts/build-token-bridge.sh          # double-compile 5 contracts × 4 networks, assemble, hash
scripts/test-token-bridge-tvm.sh       # execute the compiled contracts in the TOS TVM
python3 scripts/verify-token-bridge.py # invariants + protocol model tests + naming gate
```

Outputs are written to `crosschain/token-bridge/artifacts/tvm/` and are not committed.

## Test the EVM contracts

```bash
cd crosschain/token-bridge/evm
npm ci
PRIVATE_KEY=0x0000000000000000000000000000000000000000000000000000000000000001 npm test
```

The dummy key satisfies config validation; tests run only against the in-process Hardhat network.

## Build the counterparty contracts for Tron

Tron runs the same Solidity plane, built with TronBox and `tron-solc` rather than Hardhat:

```bash
cd crosschain/token-bridge/evm
npm run compile-tron                 # no network needed; runs in CI
```

Deployment to Nile, Tron's public testnet, reads every value from the environment:

```bash
export TRON_PRIVATE_KEY=...          # a Nile account, funded from the faucet
export BRIDGE_ORACLES=T...,T...,T... # at least three reviewed oracle addresses
export BRIDGE_DISABLED_TOKENS=       # empty, or this deployment's wrapped coin
npm run deploy-bridge-nile
```

There is no mainnet network entry, deliberately.

### Execute them inside Tron's virtual machine

```bash
scripts/test-token-bridge-tron.sh   # starts a throwaway local Tron node in docker
```

The Hardhat suite runs an EVM, so it cannot answer the questions this slot rests on. These tests can, and they establish two of them:

- **`CHAINID` is the last four bytes of the genesis block id, and a contract can bind a digest to it.** The test derives that value from the node's genesis block and requires it to reproduce the digest the deployed contract computed. This is the rule ConfigParam 83's chain id is chosen by.
- **`ecrecover` behaves as `SignatureChecker` requires.** An oracle quorum's signatures verify through a real state-changing vote, and a non-oracle signature, a below-quorum vote, and a repeat all fail to move state.

One Tron-specific caveat the tests encode: a reverted state-changing call does **not** throw through TronBox — the transaction is reported as sent either way. Negative cases must assert on contract state, never on a thrown error, or they pass whether or not the contract rejected anything. For the same reason a `pure` function called constantly (`checkSignature` on its own) reverts on this path regardless of its arguments, which is why the quorum vote is the test that carries the evidence.

**Still unmeasured:** the chain id of Tron *mainnet* and *Nile* specifically (the rule is confirmed, the per-network value is not), the Energy cost of the lock and unlock paths, and any end-to-end flow against a public Tron network. Until a Nile deployment measures them, ConfigParam 83's chain id remains derived rather than observed.

## Production gates

Before any real funds are accepted, every item in `SECURITY.md` is mandatory. In particular: independent audits of the exact TOS build, isolated HSM-backed oracle keys, a 2/3-plus quorum with operational diversity, per-token exposure caps, timelocked governance, continuous balance/supply reconciliation, emergency pause drills, and a limited canary deployment.
