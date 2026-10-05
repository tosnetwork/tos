# TOS Token Bridge

> **Status: experimental, testnet-only.** The contracts are disabled for production until an independent audit, an oracle-key ceremony, rate limits/caps, monitoring, and TOS governance activation are complete.

The TOS token bridge carries ERC-20 tokens from external EVM chains onto TOS as bridge-controlled wrapped Jettons. Assets are locked in an EVM `Bridge` contract and represented on TOS by deterministic Jetton minter/wallet contracts; an oracle quorum authorizes minting and unlocking. The state machine derives from a market-proven upstream architecture (see `NOTICE.md` for provenance and licensing) and is maintained here as first-class TOS source code.

## Components

### TOS/TVM side (`tvm/contracts/`, per-network parameters in `tvm/params/`)

- `jetton-bridge.fc`: serves one pinned EVM bridge and source generation; accepts exact mint-fee payments for locks within its swap window, validates oracle multisig execution, deploys deterministic wrapped-token minters, decides each burn once and emits `LOG_BURN` with the decision.
- `jetton-minter.fc`: reserves supply and a credit number before a swap is consumed, opens holders' wallets, counts supply once per confirmed credit, admits burns, and strands a deleted wallet's obligations under the owner-approved scope.
- `jetton-wallet.fc`: TEP-74-style transfers; credits once per credit number; holds burned tokens until the burn is admitted and decided.
- `settlement.fc`: the settlement protocol's shared parts: channels, windows, descriptors, funding and logs (`SETTLEMENT-PROTOCOL.md`).
- `multisig.fc`: threshold oracle voting for TOS-side mint/governance messages; each signed query carries the deployment's `wallet_id` and the network's global id (ConfigParam 19), so queries cannot cross deployments or networks.
- `votes-collector.fc`: collects EVM-compatible oracle signatures for burn/unlock.
- Shared configuration, message, opcode, error, utility, and Fift deployment sources.

### EVM side (`evm/`)

- `Bridge.sol`: ERC-20 lock/unlock custody contract, oracle-set governance, pause/denylist, replay protection, actual-balance accounting, densely numbered locks under source generations, and the refund of a lock cancelled on TOS.
- `SignatureChecker.sol`: low-`s` ECDSA verification and digest domain separation by EVM chain ID and bridge address.
- `TosUtils.sol`: the shared cross-chain transaction/signature structs.
- Hardhat tests and test token contracts.

No production oracle daemon ships with this directory: it completes the smart-contract plane and documents the oracle protocol, but oracle operation remains an independently implemented and audited service.

## Flow

### ERC-20 → TOS Jetton

1. The user calls EVM `Bridge.lock(token, amount, tosAddressHash)`.
2. The bridge measures the actual token balance increase, numbers the lock `n` within the current source generation, and emits `Lock`.
3. The user pays the exact TOS mint fee to `jetton-bridge` for `(generation, n)`.
4. Oracles verify both events and vote through the TOS multisig.
5. Once quorum is reached, `jetton-bridge` asks the wrapped-token minter to reserve the mint; once reserved, it consumes the swap and the minter credits the user's Jetton wallet, which reports back. A lost message is recovered by a funded `advance` from the stored record.
6. A lock that is never paid or voted can be cancelled by an oracle vote (`cancel_lock`); after `LOG_SWAP_CANCELLED`, oracles may sign `Bridge.refundLock(n)` on the EVM side.

### TOS Jetton → ERC-20

1. The user burns wrapped Jettons and supplies a 160-bit EVM destination address; the wallet holds them.
2. The minter admits the burn (or durably refuses it, releasing the hold) and notifies the bridge; every message validates ownership, deterministic sender addresses and the participants' lives.
3. `jetton-bridge` decides the burn once and emits `LOG_BURN` with a RECORDED decision; a cancelled burn is refunded to the wallet instead.
4. Oracles sign the burn; `votes-collector` assembles signatures.
5. Anyone submits the signed burn to EVM `Bridge.unlock`; replay protection marks the digest finished before transfer.

## Refusals the contracts make

A mint whose fee nobody paid is refused (`error::swap_not_paid`, 396). The
bridge records the payment for `(generation, n)` and the vote consumes it, so
the oracle multisig never mints out of the bridge's own balance and one fee
pays for exactly one mint. A payment outside the swap window, or for a lock
already paid, consumed or cancelled, is refused and bounced.

This check cannot live in an oracle. Two operators disagreeing about whether a
payment counts produce no rejection, only a quorum that never forms.

A burn names where to release on the counterparty chain, and the zero address
is not a destination: the ERC-20 transfer that would release the tokens there
reverts, and by then the jettons are already destroyed. `jetton-wallet.fc`
refuses it (`error::zero_destination`, 397) at the burn entry, which is the
last point at which the user still has their tokens.

This belongs in the contract rather than in an oracle. An oracle applying it
would apply it *after* the burn, when refusing only strands the user — and a
rule one operator applies and another does not produces a quorum that never
forms rather than a rejection.

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
scripts/test-token-bridge-tvm.sh       # execute the multisig in the TOS TVM
python3 scripts/verify-token-bridge.py # invariants + protocol model tests + naming gate
```

The settlement protocol runs in the token-bridge sandbox, and every
transaction it executes is replayed in the native engine:

```bash
TOKEN_BRIDGE_TRACE_DIR=/tmp/trace cargo test --manifest-path tosctl/src/Cargo.toml \
    -p contracts --locked --test token_bridge_sandbox
python3 scripts/replay-token-bridge-trace.py /tmp/trace
python3 scripts/token-bridge-mutations.py   # every guard removed: its test must fail
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
- **Oracles must sign with the Ethereum message prefix** — in TronWeb, `Trx.signString(digest, key, false)`. The default `signMessageV2` uses a TRON prefix and produces signatures this contract cannot recover, and passing it a third argument does not change that. The tests pin all three cases. See `SECURITY.md`.
- **`ecrecover` behaves as `SignatureChecker` requires.** An oracle quorum's signatures verify through a real state-changing vote, while a non-oracle signature, a below-quorum vote, and a resubmission of a completed vote all leave state untouched.

One Tron-specific caveat the tests encode: a reverted state-changing call does **not** throw through TronBox — the transaction is reported as sent either way. Negative cases must assert on contract state, never on a thrown error, or they pass whether or not the contract rejected anything. For the same reason a `pure` function called constantly (`checkSignature` on its own) reverts on this path regardless of its arguments, which is why the quorum vote is the test that carries the evidence.

**Still unmeasured:** the chain id of Tron *mainnet* and *Nile* specifically (the rule is confirmed, the per-network value is not), the Energy cost of the lock and unlock paths, and any end-to-end flow against a public Tron network. Until a Nile deployment measures them, ConfigParam 83's chain id remains derived rather than observed.

## Production gates

Before any real funds are accepted, every item in `SECURITY.md` is mandatory. In particular: independent audits of the exact TOS build, isolated HSM-backed oracle keys, a 2/3-plus quorum with operational diversity, per-token exposure caps, timelocked governance, continuous balance/supply reconciliation, emergency pause drills, and a limited canary deployment.
