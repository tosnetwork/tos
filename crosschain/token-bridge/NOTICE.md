# Upstream notice

The contracts in this directory derive from the official TON Foundation token bridge repositories:

| Plane | Repository | Commit | License |
|---|---|---|---|
| TVM/FunC | `ton-blockchain/token-bridge-func` | `4e7ec44a651e6b455ce5a09ed1383535fae3a637` | GPL-3.0 |
| EVM/Solidity | `ton-blockchain/token-bridge-solidity` | `ac5f58a6d28857d7b653d8f76f7d8ca58811a1c3` | GPL-3.0 |

The upstream code was developed by RSquad by order of the TON Foundation and is distributed under GPL-3.0. TOS preserves the upstream licenses and this attribution. The sources have been renamed to TOS semantics (identifiers, assembler mnemonics, file names, and documentation); opcodes, state layout, fee checks, quorum rules, and signed payload structures are unchanged.

## Reviewed deltas against the pinned upstream

Everything below is a deliberate change; anything else appearing in a diff against the pinned commits is unreviewed and must be investigated.

1. Renames to TOS semantics: identifiers, file names, and comments. Assembler mnemonic strings `STGRAMS`→`STTOMIS` and `LDGRAMS`→`LDTOMIS` resolve to the same opcodes (`0xFA02`, `0xFA00`) in the TOS assembler.
2. `stdlib.fc`: removed a duplicate `load_coins`/`store_coins` declaration pair that the mnemonic rename collapsed onto the existing one.
3. `jetton-minter.fc`: the wrapped-token metadata URI prefix is now `https://bridge.tos.network/token/`. This literal is compiled into the minter code, so **the minter code hash and every state-init-derived minter address differ from the upstream artifacts by design**. Deployment tooling must derive addresses from this build, never from upstream expectations.
4. Removed operator entry points that embedded upstream deployed addresses or oracle sets: `scripts/deploy-mainnet-bridge.ts` and `scripts/call-unlock.ts` (with its `tonweb` dependency). `scripts/deploy-bridge.ts` and `scripts/call-lock.ts` now read every deployment-specific value from the environment.
5. `Bridge.sol`: governance votes are now bound to live state. A rotation must name the set it replaces (`oracleSetHash == keccak256(abi.encode(oracleSet))`), and lock-status and per-token disable nonces must strictly increase. Upstream checked only `finishedVotings`, which stops a digest that already executed but leaves a signed-but-unexecuted vote valid forever — so a stale rotation could undo a newer one whenever the two sets overlap enough to keep meeting quorum. The signed payloads already carried these values, so the signing format is unchanged.
6. `jetton-bridge.fc`: a swap whose `forward_coins_amount` is non-zero is rejected outright (`error::forward_amount_not_zero`, a new code 398). Upstream only required `bridge_mint_fee > forward_coins_amount`. A non-zero forward amount is the sole action the receiving wallet can fail on, and the mint spans three transactions with no atomicity, so such a failure inflates supply with no wallet credit and no way to reconcile.
7. `Bridge.sol`: the constructor takes the initially disabled tokens as a parameter instead of compiling in the upstream deployment's wrapped-coin addresses, which named contracts this repository does not control. Deployments must name their own coin-plane wrapped token.
8. **New network semantics, not a rename.** The pinned upstream ships one configuration slot (`build-config79.fif`, Ethereum). `tvm/params/bsc.fc`, `tvm/params/polygon.fc` and `tvm/params/tron.fc` — ConfigParams 81, 82 and 83 — are added here. Slot 83 and its Tron chain id have no upstream counterpart at all: the schema entry in `crypto/block/block.tlb` is new, and no counterparty contract has ever run on Tron. `tronbox.js` and `migrations-tron/` build the same Solidity plane with `tron-solc`, and `test-tron/` executes it inside Tron's virtual machine on a throwaway local node. Deployment to a public Tron network, and the chain id of that network specifically, remain unverified. They follow the upstream parameter shape, but no upstream artifact covers them, so they carry no upstream deployment history and must be reviewed as new configuration.

Historical upstream network BOCs, deployed addresses, oracle key sets, and mainnet deployment commands are intentionally excluded and must not be reused for TOS.
