# Security policy and deployment gates

## Security model

This bridge is not trustless. Safety depends on all of the following remaining true:

1. At least the configured oracle quorum validates each cross-chain event honestly. The EVM quorum is a ceiling two-thirds majority of the current oracle set at every set size.
2. Oracle keys are independent, protected, and not exposed to one shared control plane.
3. The TOS masterchain ConfigParam (71 for Ethereum, 72 for BSC) points to the intended bridge, collector, and oracle set.
4. The TOS and EVM contracts, compiler versions, deployment bytecode, and initial storage match the pinned, reviewed release artifacts.
5. Locked native TOS and minted wrapped-token supply are continuously reconciled.

A source fork does **not** inherit an upstream deployment's review, operational controls, or safety record. The historical Solidity plane predates the token bridge and originally bound vote digests to `address(this)` but not the EVM chain ID. That inherited format allowed replay at the same bridge address when signatures from one chain contained at least the other chain's current quorum (`ceil(2n/3)`). The implementation now binds all three digests to `chainid()` as well; [`docs/chain-id-domain-separation.md`](docs/chain-id-domain-separation.md) records the exact format, tests, TVM analysis, signer constraint, and remaining deployment blockers.

## Preserved contract controls

- Wrapped-token burning starts disabled and requires an oracle vote to enable.
- Oracle signatures must meet the quorum, be authorized members of the current set, and be strictly sorted (preventing duplicates).
- The quorum is a ceiling two-thirds majority at every set size, and every set installed on any path holds at least three distinct non-zero members.
- Governance votes carry strictly increasing oracle-set hashes and burn-status nonces, so a signed-but-unexecuted vote cannot be held back and used to undo a later one. Oracle daemons must issue these values in increasing order.
- Completed EVM votes cannot be replayed (`finishedVotings`).
- EVM vote digests bind both the bridge address and EIP-1344 chain ID; all target chain IDs must be pairwise distinct.
- ECDSA signatures are checked for low-`s` and canonical `v` values.
- Oracle-set updates reject sets shorter than three and duplicate members.
- The TOS side tracks `total_locked`, applies flat/network/percentage fees, and supports suspending TOS→EVM transfers via state flags.
- Swaps to the zero external address are refused on both sides: the TVM bridge rejects a zero destination (exit code 307) and `WrappedTOS` burns require a non-zero TOS address hash and an amount within the 64-bit release range.
- A fee vote cannot install a network fee below the fixed 0.1 swap receipt plus headroom (exit code 392), so no configuration makes swaps drain the bridge balance backing `total_locked`.
- Bridge migration conserves locked funds: the migrating bridge zeroes `total_locked` when the transfer leaves, the receiving bridge credits `total_locked` on the `0xf00d` transfer (so the funds are locked, not sweepable by a reward vote), and a rejected transfer bounces back and is re-credited on the old bridge.
- The TOS multisig requires `k` of `n` oracle signatures, deduplicates signers via a signature bitmask, and tracks pending queries by expiring query IDs.
- The multisig can only vote. A quorum query may send nothing but an internal, bounceable message, in send mode 0 to 3, of at most `MAX_VOTE_VALUE` (10 TOS) with no extra currencies and no StateInit, to a masterchain bridge listed in the multisig's own StateInit (exit codes 46 to 50, one per rule, each checked once, when the query is proposed). The list is fixed with the address and never read from ConfigParam, so a missing or changed configuration cannot widen it, and an empty list builds no multisig (51). A compromised quorum can still vote against the bridges it lists, but cannot pay out the multisig's balance, deploy contracts, or reach any other account.
- The reward vote (operation 5) pays the address it names, a non-zero basechain or masterchain account (exit code 308), never the multisig, and keeps `total_locked` plus 100 TOS in the bridge.
- `lock_until` in the multisig's data is inert (always 0, read by nothing); activation is gated by the validators' ConfigParam vote that names the multisig.
- Every signed multisig query names both the deployment (`wallet_id`, exit code 42 on mismatch) and the network it was signed for (a 32-bit signed global id compared against ConfigParam 19 via `GLOBALID`, exit code 44 on mismatch), so a query signed on one TOS network cannot be replayed on another that shares the same StateInit, addresses, and oracle keys.

## Hard deployment constraints

### The oracle multisig lists every bridge it must vote to

The allowlist is part of the multisig's StateInit, so it is chosen once, with the address. List the bridge ConfigParam 71 or 72 names. To migrate, the multisig ConfigParam names as the oracle account must list both the old bridge, which receives the migration vote, and the new one; since the list cannot grow, that means building a multisig for the pair with `new-multisig.fif` and naming it in the same configuration change that names the new bridge.

### The oracle multisig is verified by its address, not by its allowlist

`get_allowed_bridges` alone proves nothing. A hand-built StateInit with this code, these owners and this allowlist can also start with a pending query that never passed the guards, for instance a mode-128 transfer anywhere, already approved by `k - 1` owners; one more approval executes it. Only the address commits to the whole initial state. Before the parameter vote that names a multisig:

1. Run `new-multisig.fif` with the reviewed wallet id, `k`, owner keys and bridge list, for workchain -1. It builds the StateInit from this build's code and the data `create_init_state` returns (no pending queries, `last_cleaned` 0, `lock_until` 0) and prints its address.
2. Compare that address, byte for byte, with the oracle account the proposed ConfigParam names. Any difference is another contract: do not vote for it.
3. From at least two independent nodes, check that the deployed account runs this build's code, that `get_allowed_bridges` returns the reviewed list and that `get_messages_unsigned` is empty.

`bridge_multisig_sandbox` (`a_preseeded_pending_query_is_caught_by_the_deployment_check`) executes such a planted transfer on one approval while the allowlist looks right, and shows both the address and `get_messages_unsigned` exposing it.

### Fund the oracle multisig for gas only

Coins leave the multisig only as the value of its votes, at most `MAX_VOTE_VALUE` each and only to listed bridges, and as the change it returns to whoever relays a query. Nothing pays its balance out, so whatever it holds beyond the gas its queries need stays there.

## Mandatory pre-mainnet work

- [x] Bind all three EVM vote digests to the EIP-1344 chain ID and bridge address; update test signers, commit golden vectors, reject cross-chain and legacy-format signatures, and record the upstream delta. Bind every TVM multisig query to the network's global id (ConfigParam 19 via `GLOBALID`, exit code 44) in addition to the existing `wallet_id`/destination binding, with an executed replay test per network. See [`docs/chain-id-domain-separation.md`](docs/chain-id-domain-separation.md). The external production signer remains a separate open deployment gate.
- [ ] Property/fuzz tests and adversarial cross-chain state-machine tests.
- [ ] Formal or machine-checked supply-conservation and replay-safety properties.
- [ ] Per-transaction, hourly, and daily exposure caps. The historical upstream contracts do not provide economic rate limiting by themselves.
- [ ] Timelocked, publicly observable oracle/governance changes.
- [ ] HSM-backed keys with separate operators, clouds, regions, RPC providers, and release pipelines.
- [ ] A documented oracle quorum-loss and key-compromise recovery procedure.
- [ ] Independent TOS/EVM indexers reconciling locked balances, minted supply, burns, and pending swaps.
- [ ] Emergency pause automation plus quarterly manual pause/recovery drills.
- [ ] Small canary limits and a staged increase approved through TOS governance.
- [ ] Public bug bounty before increasing limits.

## Deployment prohibitions

Do not reuse the source chain's production addresses, oracle sets, generated BOCs, or deployment command files. Do not share one oracle set between deployments or networks. Do not enable transfers until the TOS ConfigParam and oracle observers are verified from independent nodes.

## Incident default

When an invariant cannot be independently confirmed, pause the affected direction first and investigate second. Availability is never more important than custody safety.
