# TOS Legacy Toncoin Oracle Bridge

> **Status: experimental, testnet-only.** The contracts are disabled for production until an independent audit, an oracle-key ceremony, rate limits/caps, monitoring, and TOS governance activation are complete.

This directory vendors the complete on-chain contract plane of TON's legacy native-coin bridge into the TOS monorepo. It preserves the upstream lock/mint and burn/unlock state machine while making the TVM side buildable with the TOS `func` compiler and selectable through TOS masterchain ConfigParams.

This is the **native-coin bridge**: TOS locked on the TOS side is represented on an external chain as a wrapped ERC-20 (`WrappedTON.sol` upstream). It complements `../legacy-jusdt-bridge`, which carries ERC-20 tokens in the other direction.

## Pinned upstreams

| Plane | Official repository | Branch | Pinned commit |
|---|---|---|---|
| TVM/FunC (Ethereum) | `ton-blockchain/bridge-func` | `master` | `9b606d5b0c886a7b1bd4732a0ecaf0d5d2351354` |
| TVM/FunC (BSC) | `ton-blockchain/bridge-func` | `bsc` | `01b5a05e13b1dd735821dfe2b208ad5c2dd5dec2` |
| EVM/Solidity | `ton-blockchain/bridge-solidity` | `master` | `f78adaf8bee30133a6231d7cfe36c9b29dd28613` |

The FunC plane is GPL-3.0, the Solidity plane MIT. Exact source provenance and exclusions are recorded in `UPSTREAM.lock.json` and `SOURCE_MANIFEST.sha256`. The `upstream/` tree is a filtered byte-for-byte copy; `tvm/` and `evm/` are the TOS-facing build trees. The only source deltas in the build trees are toolchain-compatibility renames of assembler mnemonic strings (`STGRAMS`→`STTOMIS`, `LDGRAMS`→`LDTOMIS`; identical opcode bytes) and a version-agnostic `eth_sign` v-value fix in the test harness. Contract logic is unchanged.

## Components

### TOS/TVM side (per network under `tvm/ethereum/` and `tvm/bsc/`)

- `bridge_code.fc`: accepts native coins, deducts flat/network/percentage fees, tracks `total_locked`, emits swap logs, and pays out on oracle-approved unlocks.
- `multisig-code.fc`: `k`-of-`n` oracle voting with signer dedup bitmasks and expiring query IDs.
- `votes-collector.fc`: collects EVM-compatible oracle signatures for the reverse direction.
- Shared configuration, message/text utilities, and Fift deployment sources.

### EVM side (`evm/`)

- `Bridge.sol` + `WrappedTON.sol`: oracle-quorum minting of wrapped coins, vote-gated burning, oracle-set rotation, `finishedVotings` replay protection.
- `SignatureChecker.sol`: low-`s` ECDSA verification with digests bound to the bridge contract address.
- Upstream Truffle tests.

The public TON repositories do not include a production oracle daemon; oracle operation remains an independently implemented and audited service.

## TOS configuration slots

| External network | TOS ConfigParam | Contract tree |
|---|---:|---|
| Ethereum | 71 | `tvm/ethereum/` |
| BNB Smart Chain | 72 | `tvm/bsc/` |

No slot is enabled or populated by this directory.

## Reproducible import

```bash
python3 scripts/import-legacy-toncoin-bridge.py          # regenerate from pinned upstreams
python3 scripts/import-legacy-toncoin-bridge.py --check  # verify the committed tree matches
python3 scripts/verify-legacy-toncoin-bridge.py          # invariants + protocol model tests
```

The import deliberately excludes historical TON mainnet/testnet BOCs, deployed addresses, oracle key lists, prebuilt compile outputs, and mainnet deployment command files.

## Build and test the TVM contracts

With `func`/`fift` built (`cmake --build build --target func fift`):

```bash
scripts/build-legacy-toncoin-bridge.sh   # double-compile both networks, assemble, hash
scripts/test-legacy-toncoin-bridge.sh    # run the 22 upstream TVM-level tests via TOS func/fift
```

The TVM tests execute the real compiled contracts in the TOS TVM through the upstream Fift harness; `../fift-compat/TonUtil.fif` maps the upstream Fift library names onto the TOS ones.

## Build and test the EVM contracts

```bash
scripts/test-legacy-toncoin-bridge-evm.sh   # truffle compile + upstream tests on a local dev chain
```

## Production gates

Before any real funds are accepted, every item in `SECURITY.md` is mandatory — including the chain-ID domain-separation review specific to this historical contract generation.
