# Security policy and deployment gates

## Security model

This bridge is not trustless. Safety depends on all of the following remaining true:

1. At least the configured oracle quorum validates each cross-chain event honestly.
2. Oracle keys are independent, protected, and not exposed to one shared control plane.
3. TOS ConfigParams point to the intended bridge, multisig, oracle map, fees, and EVM contract.
4. The EVM bridge address and EVM chain ID domain-separate every signed action.
5. The TOS and EVM contracts, compiler versions, deployment BOCs/bytecode, and constructor/config cells match audited artifacts.
6. Locked ERC-20 balances and wrapped Jetton supply are continuously reconciled.
7. Every deployment satisfies the hard constraints below. The zero forward amount and the completion fee budget are enforced by the contracts; the fees configured still decide whether mints and burns go through at all.

A source fork does **not** inherit an upstream deployment's audit, operational controls, or safety record.

## Preserved contract controls

- EVM locking starts disabled.
- EVM calls use `SafeERC20` and `ReentrancyGuard`.
- Lock accounting uses the actual bridge balance delta.
- Wrapped supply is bounded by `2^120 - 1` token units.
- Oracle signatures must meet the upstream quorum formula, be authorized, and be strictly sorted (preventing duplicates).
- EVM vote digests include `address(this)` and `block.chainid`.
- Every signed TOS multisig query names both the deployment (`wallet_id`, exit code 42 on mismatch) and the network it was signed for (a 32-bit signed global id compared against ConfigParam 19 via `GLOBALID`, exit code 44 on mismatch), so a query signed on one TOS network cannot be replayed on another that shares the same StateInit, addresses, and oracle keys.
- Completed EVM votes cannot be replayed, and an uncompleted governance vote cannot be held back and used later: rotations are bound to the set they replace, and lock/disable nonces must strictly increase.
- Oracle-set updates reject zero and duplicate members.
- TOS mint and burn require exact configured fees.
- TOS supports independent suspension of burns, swaps, governance, and collector signature removal.
- TOS validates deterministic minter/wallet sender addresses before accepting mint/burn transitions.

## Hard deployment constraints

These are not future work. A deployment that violates one of them is misconfigured and must not be used.

### The signed forward amount must be zero — enforced by `jetton-bridge`

`jetton-bridge` rejects any swap whose `forward_coins_amount` is non-zero (`error::forward_amount_not_zero`, 398). Oracle daemons must therefore sign swaps with a zero forward amount; a message carrying any other value cannot execute.

The receiving wallet's only action on a credit from the minter is its confirmation (see below), so a non-zero forward amount would add a second action whose failure the protocol does not report. The minter refuses such a credit as well.

### Oracles signing for Tron must use the Ethereum message prefix

`SignatureChecker` recomputes `"\x19Ethereum Signed Message:\n32"`. TronWeb's default signer (`signMessageV2`) applies a TRON prefix instead and produces a different signature for the same digest, which this contract cannot recover. An oracle wired with TronWeb defaults therefore produces signatures that are rejected however many of them sign — unlocks and governance votes would simply never execute.

Oracles serving a Tron deployment must sign with the Ethereum prefix. In TronWeb that is:

```js
const {Trx} = require("tronweb");
const signature = Trx.signString(digest, privateKey, false);  // false = no TRON header
```

Note that `signMessageV2` cannot be corrected by an argument: it takes `(message, privateKey)` and silently ignores a third one, so `signMessageV2(digest, key, false)` still produces a TRON-prefixed signature and still fails. `test-tron/tron_vm.js` pins all three behaviours: `Trx.signString(..., false)` and an ethers signer both carry a vote, while a full quorum from `signMessageV2` moves no state.

## Completion of mints and burns

A mint spans three transactions (bridge, minter, wallet) and a burn spans three (wallet, minter, bridge), and TVM gives no atomicity across them. `settlement.fc` describes the protocol that reports each outcome back:

- **Mint.** The bridge records the mint under a mint id before sending it, and keeps the record until the wallet's confirmation reaches it through the minter. The minter counts the amount in `total_supply` only when the wallet confirms the credit, so supply never exceeds what the wallets hold. A credit the wallet refuses bounces to the minter, which reports `mint_failed`; a mint the minter refuses bounces to the bridge. Either way the bridge marks the mint failed (`LOG_MINT_FAILED`), and anyone may send it again with `retry_mint` by paying the mint fee. The oracle vote that authorised it is not needed a second time, and a mint still in flight cannot be retried.
- **Burn.** The minter takes the amount out of supply, records the burn under a burn id and sends the notification bounceable. The bridge emits `LOG_BURN` and answers `burn_recorded` in the same action phase, so either both happen or the notification bounces. On a bounce the minter credits the tokens back to their owner. A refund it cannot fund is recorded as failed (`LOG_BURN_REFUND_FAILED`), and anyone may retry it with `retry_refund`. A burn still awaiting the bridge cannot be refunded.
- **Fees.** Each step's gas is declared in `settlement.fc` and priced with `GETGASFEE` at the network's current prices. Forwarding is priced with `GETFORWARDFEE` on the size of the actual message (a credit with its wallet StateInit, a burn notification, the `LOG_BURN` event), built with the largest value a message can carry. The minter refuses a credit or a burn notification that cannot fund every later step and the report back, including the refund a bounced burn needs. A refusal leaves the funds where they were: the mint stays retryable, and the burning wallet keeps its tokens.
- **No completion action can fail for funds.** Credits and burn notifications fix their value in the compute phase and pay forwarding on top (mode 1). The wallet's confirmation and the bridge's answer are priced inside the value they forward. Afterwards the sender still holds at least its reserve, because declared gas and priced fees are never below the real ones. The bridge pays `LOG_BURN` out of the notification, not out of its own balance.
- **Operating reserve versus completion.** Completion is paid for by the caller's fee. The contracts' own balances pay only for records: `LOG_MINT_ON_MINTER`, `LOG_BURN_ON_MINTER`, `LOG_MINT_FAILED` and `LOG_BURN_REFUND_FAILED` are sent with mode 2 and are skipped when the balance cannot pay for them. The minter's reports to the bridge are also mode 2, because they run on messages that cannot bounce: a report that cannot be sent is lost, but it never undoes the supply change it reports.
- **Evidence.** The token-bridge sandbox measures every step on a bridge and minter aged to 65,536 unresolved entries and fails if any exceeds its declaration. It tests each budget at its exact threshold and one unit below, with the minter at its bare reserve and a new wallet. Every transaction it runs is replayed in the production C++ engine (`scripts/replay-token-bridge-trace.py`), which must produce the same exit codes, action results, bounces, outgoing messages with values and fees, and final balances.
- **Supply bound.** Supply plus every credit in flight stays within `2^120 - 1`, so a confirmation never reaches a minter that cannot store it.

What remains:

- **A sustained gas price rise between steps.** A budget priced at one moment cannot fund every later step at any later price. If prices rise far enough while a mint or burn is in flight (the sandbox needed roughly a 300-fold rise), a step can run out of gas with nothing left to report, and the record stays in flight. Supply is not inflated by this: an unconfirmed credit is never counted. However, a mint stuck in flight cannot be retried safely without knowing whether its credit landed, so recovering one needs an operator decision.
- **A removed or replaced ConfigParam.** The minter reads the bridge address from the ConfigParam. A minter transaction that cannot read it refuses, and a wallet's confirmation refused that way is lost (it is not bounceable), leaving that mint in flight with the tokens credited but not yet counted. Changing the bridge address in the ConfigParam while mints or burns are in flight is therefore an operational hazard. A burn notification sent to an address with nothing deployed bounces and is credited back. One that the previous bridge still logs is released normally, but the minter refuses that bridge's answer, so the burn stays recorded as awaiting the bridge.
- **Fees still decide liveness.** A configured fee too small for the budget makes every mint or burn refuse. That is safe, but nothing goes through until the fee is raised.

## Mandatory pre-mainnet work

- [x] Resolve burn-path partial execution: a burn the bridge does not log is credited back to its owner (see Completion of mints and burns).
- [x] Resolve mint-path partial execution: supply counts a mint only once its wallet confirms the credit, a failed mint stays retryable without a new vote, and the completion fee budget is validated in the contract (see Completion of mints and burns).
- [x] Decide the operator procedure for a mint left in flight by a sustained gas price rise or a ConfigParam change (see Incident procedure: an operation left in flight). The procedure contains the incident; it does not recover the operation.
- [ ] Production-grade recovery for an operation left in flight: authenticated, request-specific evidence of the outcome of each step, so that a stuck mint or burn can be resolved without inferring delivery from balances or elapsed time.
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

## Incident procedure: an operation left in flight

This procedure covers a mint or burn whose record stays in flight (see What remains). It contains the incident. It is not a recovery mechanism, and none exists for this release: the contracts cannot tell a credit that landed but whose confirmation was lost from one that never landed, and neither can an operator who looks only at balances or elapsed time.

Standing rules, which apply before any incident:

- **No production activation while the pre-mainnet checklist above is incomplete.** Populating a configuration slot, enabling EVM locking, or giving oracle daemons production keys is activation.
- **By default, leave ConfigParam 79 (or the slot of the affected network) unchanged while any affected mint or burn is unresolved.** The minter and wallets read the bridge address, fees and flags from it on every step; a change made while a record is in flight can make the confirmation that would have closed it unreadable, which turns a delayed operation into a lost one. This includes changes intended as a fix.
- **Contain with EVM governance and oracle signing first.** The first response uses controls outside the ConfigParam (step 1 below).
- **A suspension-only ConfigParam change is an exception, reviewed separately.** The TOS-side suspension flags (`state_flags`) live in the same ConfigParam. Setting them requires a separate review of every outstanding completion path (each in-flight mint and burn, and whether the change would refuse the confirmation or answer that closes it), and the change must alter `state_flags` alone: it must never be bundled with a change to the bridge address, fees, oracle set or any other field.

When a mint stays in flight (`get_pending_mint` reports status 0 past the expected completion time), or a burn stays awaiting the bridge (`get_pending_burn` reports status 0 the same way):

1. **Contain the affected direction with controls that leave the ConfigParam untouched.** For EVM to TOS (mints): disable locking on the EVM bridge (`voteForSwitchLock(false, nonce, ...)`), or disable the affected token (`voteForDisableToken(true, token, nonce, ...)`), and instruct oracle operators to stop producing new swap votes for that network. For TOS to EVM (burns): instruct oracle operators to stop signing unlocks for that network. Record the governance transactions and the time each oracle operator confirmed.

   This contains new authorization and new exposure; it is **not a complete on-chain halt**. Burns on TOS are permissionless and continue to be accepted while the TOS-side burn flag is clear, and stopping signing does not invalidate signatures already produced: a quorum of votes or an unlock signature collected before the stop can still be submitted. Record which signatures were produced and not yet used, and treat them as live during reconciliation. Halting TOS burns on chain needs the suspension-only ConfigParam change above, under its separate review.
2. **Freeze the evidence.** Record the affected mint or burn ids, the bridge, minter and wallet addresses, their current state from independent nodes, and the ConfigParam cell (its hash) at the time of the incident.
3. **Reconcile the original transaction chain.** Starting from the transaction that created the record (the oracle vote or `retry_mint` for a mint; the wallet burn for a burn), follow every outgoing message through the bridge, minter and wallet transactions, from at least two independently operated nodes. For each step establish whether it executed, its compute and action phase results, and whether it bounced. Compare the wallet's balance history and the minter's `get_in_flight` against the records.
4. **Classify the result:**
   - **Authenticated failure.** The chain contains the bounce or failure report the protocol defines (the minter's `mint_failed`, the bounce of a mint to the bridge, or a burn notification's bounce) and the record moved to failed accordingly. Only this state may be retried, through the protocol's own operation (`retry_mint`, `retry_refund`), and only once the cause (fee schedule, gas prices) no longer prevents the step from completing.
   - **Completed but unrecorded.** The chain shows the credit landed (the wallet's credit transaction executed) and the confirmation was lost. The tokens exist in the wallet; supply has not counted them. Do not mint, refund or retry. Record it and remain paused; closing such a record needs a release that can act on authenticated evidence.
   - **Unresolved.** The chain does not establish either outcome, or the nodes disagree. **The procedure concludes "unresolved; remain paused".** That is an acceptable outcome of this procedure.
5. **Never act on time alone.** Do not clear a swap's consumption, remint, issue a compensating refund or unlock, or mark a record failed because a timer expired or an operation has been pending for long. Elapsed time is not evidence of failure, and any of those actions can pay the same transfer twice.
6. **Resume only after every affected record is closed by the protocol itself**, the cause is removed, and the reconciliation is written down with the transaction hashes it relied on. Re-enable in the reverse order of step 1.

## Incident default

When an invariant cannot be independently confirmed, pause the affected direction first and investigate second. Availability is never more important than custody safety.
