# TOS Coin Bridge

> **Status: experimental, testnet-only.** The contracts are disabled for production until an independent audit, an oracle-key ceremony, rate limits/caps, monitoring, and TOS governance activation are complete.

The TOS coin bridge carries native TOS to external EVM chains. Coins locked in the TOS-side bridge contract are represented externally as a wrapped ERC-20 (`WrappedTOS.sol`); an oracle quorum authorizes minting and unlocking. It complements `../token-bridge`, which carries ERC-20 tokens in the other direction. The state machine derives from a market-proven upstream architecture (see `NOTICE.md` for provenance and licensing) and is maintained here as first-class TOS source code.

## Components

### TOS/TVM side (per network under `tvm/ethereum/` and `tvm/bsc/`)

- `bridge_code.fc`: accepts native coins, deducts flat/network/percentage fees, tracks `total_locked`, emits swap logs, and pays out on oracle-approved unlocks.
- `multisig-code.fc`: `k`-of-`n` oracle voting with signer dedup bitmasks and expiring query IDs.
- `votes-collector.fc`: collects EVM-compatible oracle signatures for the reverse direction.
- Shared configuration, message/text utilities, and Fift deployment sources.
- `tvm/tests/`: TVM-level execution tests that compile the real contracts and drive them through the TOS TVM via a Fift harness.

### EVM side (`evm/`)

- `Bridge.sol` + `WrappedTOS.sol`: oracle-quorum minting of wrapped coins, vote-gated burning, oracle-set rotation, `finishedVotings` replay protection.
- `SignatureChecker.sol`: low-`s` ECDSA verification with digests bound to both the bridge contract address and EIP-1344 chain ID.
- Truffle tests plus same-address, dual-chain replay and legacy-format rejection tests.

No production oracle daemon ships with this directory; oracle operation remains an independently implemented and audited service.

## TOS configuration slots

| External network | TOS ConfigParam | Contract tree |
|---|---:|---|
| Ethereum | 71 | `tvm/ethereum/` |
| BNB Smart Chain | 72 | `tvm/bsc/` |

No slot is enabled or populated by this directory.

## Build and test the TVM contracts

With `func`/`fift` built (`cmake --build build --target func fift`):

```bash
scripts/build-coin-bridge.sh          # double-compile both networks, assemble, hash
scripts/test-coin-bridge-tvm.sh       # run the 22 TVM-level tests via TOS func/fift
python3 scripts/verify-coin-bridge.py # invariants + protocol model tests + naming gate
```

Outputs are written to `crosschain/coin-bridge/artifacts/tvm/` and are not committed.

## Build and test the EVM contracts

```bash
scripts/test-coin-bridge-evm.sh   # regression suite + dual-chain replay rejection
```

## Production gates

Before any real funds are accepted, every item in `SECURITY.md` is mandatory. The EVM chain-ID domain-separation change is implemented and tested, but it is not deployment approval: the production oracle signer must match the committed golden vectors, target chain IDs must be pairwise distinct, independent audits must pass, and live deployment state must be established from traceable node evidence.
