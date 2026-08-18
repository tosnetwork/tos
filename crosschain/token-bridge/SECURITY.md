# Security policy and deployment gates

## Security model

This bridge is not trustless. Safety depends on all of the following remaining true:

1. At least the configured oracle quorum validates each cross-chain event honestly.
2. Oracle keys are independent, protected, and not exposed to one shared control plane.
3. TOS ConfigParams point to the intended bridge, multisig, oracle map, fees, and EVM contract.
4. The EVM bridge address and EVM chain ID domain-separate every signed action.
5. The TOS and EVM contracts, compiler versions, deployment BOCs/bytecode, and constructor/config cells match audited artifacts.
6. Locked ERC-20 balances and wrapped Jetton supply are continuously reconciled.
7. Every deployment satisfies the hard constraints below. The zero forward amount is enforced by the contract; the mint-path fee budget is still an operational responsibility.

A source fork does **not** inherit an upstream deployment's audit, operational controls, or safety record.

## Preserved contract controls

- EVM locking starts disabled.
- EVM calls use `SafeERC20` and `ReentrancyGuard`.
- Lock accounting uses the actual bridge balance delta.
- Wrapped supply is bounded by `2^120 - 1` token units.
- Oracle signatures must meet the upstream quorum formula, be authorized, and be strictly sorted (preventing duplicates).
- EVM vote digests include `address(this)` and `block.chainid`.
- Completed EVM votes cannot be replayed, and an uncompleted governance vote cannot be held back and used later: rotations are bound to the set they replace, and lock/disable nonces must strictly increase.
- Oracle-set updates reject zero and duplicate members.
- TOS mint and burn require exact configured fees.
- TOS supports independent suspension of burns, swaps, governance, and collector signature removal.
- TOS validates deterministic minter/wallet sender addresses before accepting mint/burn transitions.

## Hard deployment constraints

These are not future work. A deployment that violates one of them is misconfigured and must not be used.

### The signed forward amount must be zero — enforced by `jetton-bridge`

`jetton-bridge` rejects any swap whose `forward_coins_amount` is non-zero (`error::forward_amount_not_zero`, 398). Oracle daemons must therefore sign swaps with a zero forward amount; a message carrying any other value cannot execute.

The mint spans three transactions — bridge, minter, wallet — and TVM gives no atomicity across them. `jetton-minter` commits `total_supply += amount` in its own transaction and then relies on a later wallet transaction to create the matching balance. If that wallet transaction fails, supply is inflated with no credit behind it, the multisig query is already spent, and the depositor's locked ERC-20 is stranded until a new quorum signs a different query. `jetton-minter` ignores bounced messages, so nothing reconciles this. (Note that this cannot be fixed by reordering the send and the state write: `send_raw_message` only appends to the action list, and c4 and c5 commit together at the end of a successful compute phase.)

A zero forward amount closes the reachable half of that window, which is why the contract now requires it rather than leaving it to operational discipline. `jetton-wallet`'s `receive_tokens` has no insufficient-value guard in its compute phase — unlike `send_tokens`, it does not `throw_unless(error::not_enough_tos, ...)` — so its only failure path is the action phase, and the only action it can fail on is the forward notification, which it emits solely when `forward_coins_amount` is non-zero. With a zero forward amount the wallet emits at most the excesses message, which carries `SEND_MODE_IGNORE_ERRORS`.

The residual case is a compute-phase failure of the wallet, which means the fee budget could not deploy and run it. That is covered by the fee-budget constraint below, and its complete resolution is tracked as pre-mainnet work.

### Oracles signing for Tron must use the Ethereum message prefix

`SignatureChecker` recomputes `"\x19Ethereum Signed Message:\n32"`. TronWeb's default signer (`signMessageV2`) applies a TRON prefix instead and produces a different signature for the same digest, which this contract cannot recover. An oracle wired with TronWeb defaults therefore produces signatures that are rejected however many of them sign — unlocks and governance votes would simply never execute.

Oracles serving a Tron deployment must sign with the Ethereum prefix. In TronWeb that is:

```js
const {Trx} = require("tronweb");
const signature = Trx.signString(digest, privateKey, false);  // false = no TRON header
```

Note that `signMessageV2` cannot be corrected by an argument: it takes `(message, privateKey)` and silently ignores a third one, so `signMessageV2(digest, key, false)` still produces a TRON-prefixed signature and still fails. `test-tron/tron_vm.js` pins all three behaviours: `Trx.signString(..., false)` and an ethers signer both carry a vote, while a full quorum from `signMessageV2` moves no state.

### The configured fee budget must cover the whole mint path

`jetton-bridge` checks only `bridge_mint_fee > forward_coins_amount`. It does not verify that `bridge_mint_fee` also covers `minter_min_tos_for_storage`, wallet deployment, `wallet_min_tos_for_storage`, and `wallet_gas_consumption`. Before enabling a ConfigParam, compute that budget against the deployed contract sizes on the target network, add margin for storage-rent accrual on the minter between mints, and verify it end to end on testnet. Re-verify after any fee, contract, or network gas-price change.

## Mandatory pre-mainnet work

- [ ] Resolve burn-path partial execution. `jetton-minter` decreases `total_supply` and then notifies `jetton-bridge` with a **non-bounceable** message. If that notification is not processed — the bridge throws, or its ConfigParam is unavailable in the asynchronous window — the depositor's jettons are already burned and supply already reduced, but no burn log is emitted, so no unlock can ever be signed on the EVM side. Unlike the mint direction, no bounce is even available to compensate. The same pending/finalize treatment applies.
- [ ] Resolve mint-path partial execution so the bridge no longer depends on the fee-budget constraint above. Rejecting a non-zero forward amount closes the wallet's action-phase failure, but a compute-phase failure remains possible whenever the fee budget cannot deploy and run the wallet. `jetton-minter` increases `total_supply` when it dispatches `internal_transfer` and ignores bounces, and `jetton-bridge` has already marked the multisig query processed by then. Bounce handling alone is not sufficient and not trivial: a wallet action-phase failure produces no bounce at all, and the bounced body carries only the first 256 bits of the original message, which excludes the destination — so the minter cannot prove a bounce came from one of its own wallets without tracking pending mints by query ID. Prefer an acknowledgement protocol that reports completion only after the wallet is credited, and validate the whole fee budget in the contract rather than in operations.
- [ ] Two independent audits covering FunC/Fift, Solidity, deployment/config scripts, compiler output, and oracle protocol.
- [ ] Property/fuzz tests and adversarial cross-chain state-machine tests.
- [ ] Formal or machine-checked supply-conservation and replay-safety properties.
- [ ] Per-token, per-transaction, hourly, and daily exposure caps. The historical upstream contracts do not provide sufficient economic rate limiting by themselves.
- [ ] Timelocked, publicly observable oracle/governance changes.
- [ ] HSM-backed keys with separate operators, clouds, regions, RPC providers, and release pipelines.
- [ ] A documented oracle quorum-loss and key-compromise recovery procedure.
- [ ] Independent TOS/EVM indexers reconciling locked balances, minted supply, burns, unlocks, and pending events.
- [ ] Emergency pause automation plus quarterly manual pause/recovery drills.
- [ ] Token allowlisting and behavioral review; fee-on-transfer/rebasing/blacklisting ERC-20s require explicit analysis.
- [ ] Small canary limits and a staged increase approved through TOS governance.
- [ ] Public bug bounty before increasing limits.

## Deployment prohibitions

Do not reuse the source chain's production addresses, oracle sets, generated BOCs, or deployment command files. Do not deploy the same deterministic EVM address/oracle configuration as another bridge deployment. Do not enable EVM locking until the TOS ConfigParam and oracle observers are verified from independent nodes.

## Incident default

When an invariant cannot be independently confirmed, pause the affected direction first and investigate second. Availability is never more important than custody safety.
