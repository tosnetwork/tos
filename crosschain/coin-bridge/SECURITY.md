# Security policy and deployment gates

## Security model

This bridge is not trustless. Safety depends on all of the following remaining true:

1. At least the configured oracle quorum validates each cross-chain event honestly. The EVM quorum is a ceiling two-thirds majority of the current oracle set at every set size.
2. Oracle keys are independent, protected, and not exposed to one shared control plane.
3. The TOS masterchain ConfigParam (71 for Ethereum, 72 for BSC) points to the intended bridge, collector, and oracle set.
4. The TOS and EVM contracts, compiler versions, deployment bytecode, and initial storage match audited artifacts.
5. Locked native TOS and minted wrapped-token supply are continuously reconciled.

A source fork does **not** inherit an upstream deployment's audit, operational controls, or safety record. The historical Solidity plane predates the token bridge: its vote digests include `address(this)` but **not** the EVM chain ID, so the same bridge contract address must never exist on two networks with an overlapping oracle set — a signature for one chain would replay on the other.

## Preserved contract controls

- Wrapped-token burning starts disabled and requires an oracle vote to enable.
- Oracle signatures must meet the quorum, be authorized members of the current set, and be strictly sorted (preventing duplicates).
- The quorum is a ceiling two-thirds majority at every set size, and every set installed on any path holds at least three distinct non-zero members.
- Governance votes carry strictly increasing oracle-set hashes and burn-status nonces, so a signed-but-unexecuted vote cannot be held back and used to undo a later one. Oracle daemons must issue these values in increasing order.
- Completed EVM votes cannot be replayed (`finishedVotings`).
- ECDSA signatures are checked for low-`s` and canonical `v` values.
- Oracle-set updates reject sets shorter than three and duplicate members.
- The TOS side tracks `total_locked`, applies flat/network/percentage fees, and supports suspending TOS→EVM transfers via state flags.
- The TOS multisig requires `k` of `n` oracle signatures, deduplicates signers via a signature bitmask, and tracks pending queries by expiring query IDs.

## Mandatory pre-mainnet work

- [ ] Two independent audits covering FunC/Fift, Solidity, deployment/config scripts, compiler output, and oracle protocol.
- [ ] A dedicated review of the missing chain-ID domain separation above, with a decision to either enforce unique bridge addresses per network or upgrade the digest scheme before any deployment. A proposed fix (bind `block.chainid` into the vote digests), its cross-plane coordination, and a test plan are written up in [`docs/chain-id-domain-separation.md`](docs/chain-id-domain-separation.md); it awaits review and a decision.
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
