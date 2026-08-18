# Security policy and deployment gates

## Security model

This bridge is not trustless. Safety depends on all of the following remaining true:

1. At least the configured oracle quorum validates each cross-chain event honestly.
2. Oracle keys are independent, protected, and not exposed to one shared control plane.
3. TOS ConfigParams point to the intended bridge, multisig, oracle map, fees, and EVM contract.
4. The EVM bridge address and EVM chain ID domain-separate every signed action.
5. The TOS and EVM contracts, compiler versions, deployment BOCs/bytecode, and constructor/config cells match audited artifacts.
6. Locked ERC-20 balances and wrapped Jetton supply are continuously reconciled.

A source fork does **not** inherit an upstream deployment's audit, operational controls, or safety record.

## Preserved contract controls

- EVM locking starts disabled.
- EVM calls use `SafeERC20` and `ReentrancyGuard`.
- Lock accounting uses the actual bridge balance delta.
- Wrapped supply is bounded by `2^120 - 1` token units.
- Oracle signatures must meet the upstream quorum formula, be authorized, and be strictly sorted (preventing duplicates).
- EVM vote digests include `address(this)` and `block.chainid`.
- Completed EVM votes cannot be replayed.
- Oracle-set updates reject zero and duplicate members.
- TOS mint and burn require exact configured fees.
- TOS supports independent suspension of burns, swaps, governance, and collector signature removal.
- TOS validates deterministic minter/wallet sender addresses before accepting mint/burn transitions.

## Mandatory pre-mainnet work

- [ ] Resolve mint-path partial execution. `jetton-minter` increases `total_supply` when it dispatches `internal_transfer` and ignores bounces, and `jetton-bridge` has already marked the multisig query processed by then. A wallet-side failure therefore leaves supply inflated with no wallet credit, and the vote cannot be replayed. Add bounce handling that authenticates the deterministic wallet sender and rolls the pending amount back, or an acknowledgement protocol that reports completion only after the wallet is credited. Validate the whole configured fee budget (minter and wallet storage, gas, forwarding) before minting rather than only `bridge_mint_fee > forward amount`.
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
