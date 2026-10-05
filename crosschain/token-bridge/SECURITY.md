# Security policy and deployment gates

## Security model

This bridge is not trustless. Safety depends on all of the following remaining true:

1. At least the configured oracle quorum validates each cross-chain event honestly.
2. Oracle keys are independent, protected, and not exposed to one shared control plane.
3. TOS ConfigParams point to the intended bridge, multisig, oracle map, fees, and EVM contract.
4. The EVM bridge address and EVM chain ID domain-separate every signed action.
5. The TOS and EVM contracts, compiler versions, deployment BOCs/bytecode, and constructor/config cells match audited artifacts.
6. Locked ERC-20 balances and wrapped Jetton supply are continuously reconciled.
7. Every deployment satisfies the hard constraints below. The contracts price every settlement step themselves; the fees configured still decide whether new mints and burns are accepted at all.

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
- A swap payment and a burn require the configured mint and burn fees exactly.
- TOS supports independent suspension of burns, swaps, governance, and collector signature removal.
- TOS validates deterministic minter/wallet sender addresses, and the life of each participant, before accepting a settlement message.

## Hard deployment constraints

These are not future work. A deployment that violates one of them is misconfigured and must not be used.

### The bridge is listed in ConfigParam 31, and minters are monitored

The bridge must be listed in ConfigParam 31 on every network before activation. A listed bridge pays no storage and is exempt from the account size limit, so the chain never freezes or deletes it for debt. Unlisted, a storage-price rise can freeze it (the sandbox shows both: `t_y7_t_z5_a_listed_bridge_is_exempt_from_rent_and_an_unlisted_one_is_not`). Each minter has a reserve target and an alert threshold, and is topped up with plain non-bounceable messages; a frozen minter is restored from its frozen state. Both are operational obligations of the bridge operator.

### Each TOS bridge serves exactly one EVM bridge and one source generation

`new-bridge.fif` pins the EVM chain id and the EVM bridge address in the bridge's initial data, and the bridge accepts no business until an oracle vote activates a source generation naming its own address and life. That generation must first be created on the EVM side with `voteForNewGeneration`, naming the same bridge address and life (see the incident procedure for the order). A different EVM bridge needs a different TOS bridge.

### Oracles signing for Tron must use the Ethereum message prefix

`SignatureChecker` recomputes `"\x19Ethereum Signed Message:\n32"`. TronWeb's default signer (`signMessageV2`) applies a TRON prefix instead and produces a different signature for the same digest, which this contract cannot recover. An oracle wired with TronWeb defaults therefore produces signatures that are rejected however many of them sign — unlocks and governance votes would simply never execute.

Oracles serving a Tron deployment must sign with the Ethereum prefix. In TronWeb that is:

```js
const {Trx} = require("tronweb");
const signature = Trx.signString(digest, privateKey, false);  // false = no TRON header
```

Note that `signMessageV2` cannot be corrected by an argument: it takes `(message, privateKey)` and silently ignores a third one, so `signMessageV2(digest, key, false)` still produces a TRON-prefixed signature and still fails. `test-tron/tron_vm.js` pins all three behaviours: `Trx.signString(..., false)` and an ethers signer both carry a vote, while a full quorum from `signMessageV2` moves no state.

## Completion of mints and burns

`SETTLEMENT-PROTOCOL.md` specifies the protocol and `settlement.fc` implements its shared parts. In short:

- **Durable records at every participant.** The bridge, the minter and the wallet each record an operation, under an identity bound to a canonical descriptor (the swap or burn number, amount, recipient or destination, and the pinned participants), before any message about it leaves. A repeated message returns the recorded result without repeating the effect; a reused identity with other fields is refused.
- **Dense numbers and windows.** Every channel between two participants numbers its operations densely and holds at most a window of them; acknowledged floors let both sides compact what is finished, and a late duplicate below the floor gets the channel's default answer, never a new effect. Admission refuses before any effect when a window, a limit or the account cell limit has no room.
- **Mint.** The minter reserves supply capacity and a credit number for the holder before the bridge consumes the swap; the wallet credits once per number and reports back; the minter counts supply once and reports completion to the bridge. A lost message is never read as failure: anyone may fund an `advance` that rebuilds the message from the stored record alone.
- **Burn.** The wallet holds the tokens and asks the minter to admit the burn; a refusal is durable and releases the hold. An admitted burn reaches the bridge, which decides RECORDED or CANCELLED once per notice and emits `LOG_BURN` only with RECORDED, in the same transaction. A cancelled burn is refunded to the wallet once; `LOG_BURN` and a refund are mutually exclusive.
- **Source side.** EVM locks are numbered densely under a source generation. `cancel_lock` is an oracle vote that makes an unpaid or paid lock terminally CANCELLED and logs `LOG_SWAP_CANCELLED` once; only then may oracles sign the EVM `refundLock`.
- **No completion reads ConfigParam 79**, and none is stopped by the suspension flags; only new business reads them.
- **Funding.** Every leg prices its own step and everything after it with `GETGASFEE` and `GETFORWARDFEE` at current prices, and spends only its incoming value, never the contract's reserve. Every protocol send fixes its value in the compute phase (mode 0 or 1, never `+2`), so a leg commits its record and its messages together or not at all.
- **Evidence.** The sandbox suite (`tosctl/src/node-control/contracts/tests/token_bridge_sandbox.rs`) runs the test matrix of `SETTLEMENT-PROTOCOL.md` section 15 against an independent model that checks the ledger after every transaction, and replays every transaction in the production C++ engine (`scripts/replay-token-bridge-trace.py`). `scripts/token-bridge-mutations.py` removes each guard and records the test that fails for its named reason. The worst-case state sizes and the limits chosen from them are recorded beside the constants in `settlement.fc`.

### Owner-approved stranding scope (option Y, 2026-10-05)

The closing condition requires every consumed swap to be recoverable to exactly one credit, and every accepted burn to one release or one refund. That condition is **narrowed** for one case, by the owner's ruling: **when the chain deletes a participant's history, that participant's unfinished obligations are not completed. They are stranded.**

- A deleted wallet: mints bound to it that were reserved or crediting, and refunds still owed to it, are stranded. Its burns the bridge has not decided are still decided; a recorded one completes, a cancelled one is stranded.
- A deleted minter: its token family becomes terminal; the bridge and every wallet refuse its new life. Swaps it consumed but did not complete, and burns it admitted but the bridge did not decide, are stranded.
- A deleted bridge (possible only after it leaves ConfigParam 31): the minters refuse its new life, its unfinished operations are stranded, and `LOG_BURN` is never emitted twice.

Every stranded record emits `LOG_LIABILITY_STRANDED` with its full descriptor, in mode 0, in the leg that strands it, at most `FOLD_LIMIT` per transaction, and its amount stays counted in the minter's `stranded` reservation. Reconciliation of stranded liabilities is off-chain. No settlement effect is ever repeated after any deletion, of one participant or several.

What remains:

- **Stranded liabilities need off-chain reconciliation**, from `LOG_LIABILITY_STRANDED`, under the scope above.
- **Liveness, not safety, depends on execution and funding.** A step over the gas limit, a cell limit lowered below a live deployment's measured worst case, a frozen participant that is not restored, or absent funding stops completion until it is remedied; nothing is repeated meanwhile. Governance must not lower ConfigParam 43 below the measured worst case of a live deployment.
- **The mandatory logs' rollback is not exercised end to end in the sandbox.** A mandatory log rolls its leg back if it cannot be sent, but the sandbox engine never refuses an oversized message (its message-size count stops at the limit), and every leg's funding leaves the reserve to pay its logs, so no test can make a mandatory log fail; the mode-0 rule is pinned by `scripts/verify-token-bridge.py` instead.
- **Fees still decide liveness for new business.** A configured fee too small makes new mints or burns refuse. That is safe, but nothing new goes through until the fee is raised.

## Mandatory pre-mainnet work

- [x] Durable, authenticated, idempotent settlement at every participant, with permissionless funded retransmission (see Completion of mints and burns).
- [ ] A deployment inventory of every operated network before activation: the history of ConfigParams 79 and 81 to 83 since genesis, and a code-hash search for every built bridge, minter and wallet.
- [ ] The bridge listed in ConfigParam 31 on each network, and minter monitoring in operation, before activation.
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

## Incident procedure

### Activating a source generation

A TOS bridge accepts no business until a source generation names it. Generations exist on the EVM side, where TOS storage rules cannot delete them. To activate one, after the bridge is deployed, listed in ConfigParam 31 and configured:

1. **Locking is disabled** on the EVM bridge (`voteForSwitchLock(false, ...)`). It starts disabled; after a bridge deletion it must be disabled before anything else.
2. **Read the TOS bridge's address and life** (`get_bridge_state`, the first value) from at least two independent nodes.
3. **Create the generation on the EVM side**: `voteForNewGeneration(g + 1, bridge_hash, life, nonce, signatures)`. It starts at the next lock nonce, above every lock already allocated.
4. **Activate it on TOS**: an oracle vote `activate_generation(bridge_hash, life, g + 1, start)` with the start the EVM event recorded. The bridge accepts it once, and only if it names its own address and life.
5. **Enable locking** on the EVM bridge (`voteForSwitchLock(true, ...)`).

Locks of an earlier generation are never acted on by the new bridge. Those the old bridge cancelled (`LOG_SWAP_CANCELLED` in TOS history) may still be refunded once with `refundLock`; those it consumed never; those neither consumed nor cancelled when it was deleted are stranded under the scope above.

### An operation that does not complete

Nothing here infers an outcome. Every operation has a durable record at the participant that holds it, and the protocol completes it once execution resumes and funding is supplied.

1. **Find the record.** `get_swap` and `get_pending_mint` at the bridge, `get_mint` and `get_burn` at the minter, `get_settlement_state` and `get_burn` at the wallet.
2. **Fund its advance** at the participant holding the unfinished step, at the quote from `get_advance_cost`. A window held full is drained by `sync` the same way. Anyone may do this; the caller chooses nothing but the identifier and the funding.
3. **If the advance is refused**, the refusal names the cause: underfunded (raise the funding), a cell limit below the declared worst case (restore ConfigParam 43), or a terminal relationship (a participant was deleted and recreated; its obligations are stranded and logged).
4. **A lock that is never paid or voted** blocks the payment window; the oracles cancel it with `cancel_lock`, after which it may be refunded on the EVM side.
5. **A frozen participant** is restored from its own state with a message that pays its debt; it keeps its life and its records.
6. **Never act on time alone.** Do not remint, refund, unlock or clear a record because time passed. Elapsed time is not evidence, and any of those can pay the same transfer twice.

## Incident default

When an invariant cannot be independently confirmed, pause the affected direction first and investigate second. Availability is never more important than custody safety.
