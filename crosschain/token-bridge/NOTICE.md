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
5. **New network semantics, not a rename.** The pinned upstream ships one configuration slot (`build-config79.fif`, Ethereum). `tvm/params/bsc.fc` and `tvm/params/polygon.fc` — ConfigParams 81 and 82, EVM chain IDs 56 and 137 — are added here. They follow the upstream parameter shape, but no upstream artifact covers them, so they carry no upstream deployment history and must be reviewed as new configuration.

Historical upstream network BOCs, deployed addresses, oracle key sets, and mainnet deployment commands are intentionally excluded and must not be reused for TOS.
