# Upstream notice

The contracts in this directory derive from the official TON Foundation coin bridge repositories:

| Plane | Repository | Branch | Commit | License |
|---|---|---|---|---|
| TVM/FunC (Ethereum) | `ton-blockchain/bridge-func` | `master` | `9b606d5b0c886a7b1bd4732a0ecaf0d5d2351354` | GPL-3.0 |
| TVM/FunC (BSC) | `ton-blockchain/bridge-func` | `bsc` | `01b5a05e13b1dd735821dfe2b208ad5c2dd5dec2` | GPL-3.0 |
| EVM/Solidity | `ton-blockchain/bridge-solidity` | `master` | `f78adaf8bee30133a6231d7cfe36c9b29dd28613` | GPL-3.0 |

TOS preserves the upstream licenses and this attribution. The sources have been renamed to TOS semantics (identifiers, assembler mnemonics, file names, and documentation); opcodes, state layout, fee checks, quorum rules, and signed payload structures are unchanged. The Fift test harness additionally normalizes `eth_sign` recovery values across dev-chain generations.

Historical upstream network BOCs, prebuilt compile outputs, deployed addresses, oracle key sets, and mainnet deployment command files are intentionally excluded and must not be reused for TOS.
