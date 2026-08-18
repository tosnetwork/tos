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

The ConfigParam must contain the TOS bridge address, oracle multisig address/map, state flags, fee schedule, and external EVM bridge address. No slot is enabled or populated by this directory.

## Build and test the TVM contracts

With `func`/`fift` built (`cmake --build build --target func fift`):

```bash
scripts/build-token-bridge.sh          # double-compile 5 contracts × 3 networks, assemble, hash
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

## Production gates

Before any real funds are accepted, every item in `SECURITY.md` is mandatory. In particular: independent audits of the exact TOS build, isolated HSM-backed oracle keys, a 2/3-plus quorum with operational diversity, per-token exposure caps, timelocked governance, continuous balance/supply reconciliation, emergency pause drills, and a limited canary deployment.
