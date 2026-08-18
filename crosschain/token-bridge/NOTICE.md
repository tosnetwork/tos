# Upstream notice

The contracts in this directory derive from the official TON Foundation token bridge repositories:

| Plane | Repository | Commit | License |
|---|---|---|---|
| TVM/FunC | `ton-blockchain/token-bridge-func` | `4e7ec44a651e6b455ce5a09ed1383535fae3a637` | GPL-3.0 |
| EVM/Solidity | `ton-blockchain/token-bridge-solidity` | `ac5f58a6d28857d7b653d8f76f7d8ca58811a1c3` | GPL-3.0 |

The upstream code was developed by RSquad by order of the TON Foundation and is distributed under GPL-3.0. TOS preserves the upstream licenses and this attribution. The sources have been renamed to TOS semantics (identifiers, assembler mnemonics, file names, and documentation); opcodes, state layout, fee checks, quorum rules, and signed payload structures are unchanged.

Historical upstream network BOCs, deployed addresses, oracle key sets, and mainnet deployment commands are intentionally excluded and must not be reused for TOS.
