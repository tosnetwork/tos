# TOS Legacy jUSDT Oracle Bridge

> **Status: experimental, testnet-only.** The contracts are disabled for production until an independent audit, an oracle-key ceremony, rate limits/caps, monitoring, and TOS governance activation are complete.

This directory brings the complete on-chain contract plane of TON's legacy ERC-20 ↔ Jetton bridge into the TOS monorepo. It preserves the upstream lock/mint and burn/unlock state machine while making the TVM side buildable with the TOS `func` compiler and selectable through TOS masterchain ConfigParams.

This is the old **jUSDT-style wrapped-token bridge**, not Tether's current native USDT-on-TON/USDT0 architecture. Assets are locked in an EVM `Bridge` contract and represented on TOS by bridge-controlled Jetton minter/wallet contracts. An oracle quorum authorizes minting and unlocking.

## Pinned upstreams

| Plane | Official repository | Pinned commit |
|---|---|---|
| TVM/FunC | `ton-blockchain/token-bridge-func` | `4e7ec44a651e6b455ce5a09ed1383535fae3a637` |
| EVM/Solidity | `ton-blockchain/token-bridge-solidity` | `ac5f58a6d28857d7b653d8f76f7d8ca58811a1c3` |

Both upstreams and TOS use GPL-3.0-compatible licensing. Exact source provenance and exclusions are recorded in `UPSTREAM.lock.json` and `SOURCE_MANIFEST.sha256`.

## Components

### TOS/TVM side

- `jetton-bridge.fc`: accepts exact mint-fee payments, validates oracle multisig execution, deploys deterministic wrapped-token minters, emits paid-swap and burn logs.
- `jetton-minter.fc`: bridge-only minting, deterministic wallet deployment, supply accounting, burn forwarding.
- `jetton-wallet.fc`: TEP-74-style transfers plus EVM destination payload on burn.
- `multisig.fc`: threshold oracle voting for TOS-side mint/governance messages.
- `votes-collector.fc`: collects EVM-compatible oracle signatures for burn/unlock.
- Shared configuration, message, opcode, error, utility, and Fift deployment sources.

### EVM side

- `Bridge.sol`: ERC-20 lock/unlock custody contract, oracle-set governance, pause/denylist, replay protection, and actual-balance accounting.
- `SignatureChecker.sol`: low-`s` ECDSA verification and digest domain separation by EVM chain ID and bridge address.
- `TonUtils.sol`: the upstream cross-chain transaction/signature structs. The historical name is retained to keep ABI/source compatibility.
- Upstream Hardhat tests and test token contracts.

The public TON repositories do not include a production oracle daemon. This directory therefore completes the **smart-contract plane** and documents the oracle protocol, but oracle operation remains an independently implemented and audited service.

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

The build generates contract bundles for the inherited TON-compatible bridge slots:

| EVM network | TOS ConfigParam | EVM chain ID |
|---|---:|---:|
| Ethereum | 79 | 1 |
| BNB Smart Chain | 81 | 56 |
| Polygon | 82 | 137 |

The corresponding ConfigParam must contain the TOS bridge address, oracle multisig address/map, state flags, fee schedule, and external EVM bridge address. No slot is enabled or populated by this branch.

## Reproducible import

```bash
python3 scripts/import-legacy-jusdt-bridge.py
python3 scripts/import-legacy-jusdt-bridge.py --check
python3 scripts/verify-legacy-jusdt-bridge.py
```

The import deliberately excludes historical TON mainnet/testnet BOCs, deployed addresses, oracle key lists, and mainnet deployment scripts. Those are not valid TOS configuration and are dangerous to reuse.

## Build the TVM contracts

First build TOS's native compiler:

```bash
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target func fift
```

Then compile all five contracts for all three external networks twice and compare the generated Fift:

```bash
scripts/build-legacy-jusdt-bridge.sh
```

Outputs are written to `crosschain/legacy-jusdt-bridge/artifacts/tvm/` and are not committed.

## Test the EVM contracts

```bash
cd crosschain/legacy-jusdt-bridge/evm
npm ci
npm test
```

## Production gates

Before any real funds are accepted, every item in `SECURITY.md` is mandatory. In particular: independent audits of the exact TOS build, isolated HSM-backed oracle keys, a 2/3-plus quorum with operational diversity, per-token exposure caps, timelocked governance, continuous balance/supply reconciliation, emergency pause drills, and a limited canary deployment.
