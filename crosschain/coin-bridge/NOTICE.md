# Upstream notice

The contracts in this directory derive from the official TON Foundation coin bridge repositories:

| Plane | Repository | Branch | Commit | License |
|---|---|---|---|---|
| TVM/FunC (Ethereum) | `ton-blockchain/bridge-func` | `master` | `9b606d5b0c886a7b1bd4732a0ecaf0d5d2351354` | GPL-3.0 |
| TVM/FunC (BSC) | `ton-blockchain/bridge-func` | `bsc` | `01b5a05e13b1dd735821dfe2b208ad5c2dd5dec2` | GPL-3.0 |
| EVM/Solidity | `ton-blockchain/bridge-solidity` | `master` | `f78adaf8bee30133a6231d7cfe36c9b29dd28613` | GPL-3.0 |

TOS preserves the upstream licenses and this attribution. The sources have been renamed to TOS semantics (identifiers, assembler mnemonics, file names, and documentation); opcodes, state layout, fee arithmetic, and signed payload structures are unchanged.

## Reviewed deltas against the pinned upstream

Everything below is a deliberate change; anything else appearing in a diff against the pinned commits is unreviewed and must be investigated.

1. Renames to TOS semantics: identifiers, file names, and comments. Assembler mnemonic strings `STGRAMS`→`STTOMIS` and `LDGRAMS`→`LDTOMIS` resolve to the same opcodes (`0xFA02`, `0xFA00`) in the TOS assembler.
2. `Bridge.sol`: the constructor now rejects an initial oracle set of fewer than three members, matching the bound `voteForNewOracleSet` already enforced on rotation. Upstream accepted any size, so a one- or two-member deployment started with a `floor(2n/3)` threshold of zero or one. The vote arithmetic itself is unchanged.
3. `migrations/` and the test suites deploy a three-member development set accordingly, and the test utilities gained a `sortedSignatures` helper so multi-signature votes satisfy the strict signer ordering rule.
4. The test harness normalizes `eth_sign` recovery values, which upstream assumed to be `0`/`1`, across dev-chain generations.
5. Named-network deployment branches carrying upstream oracle sets were removed: an oracle set is a custody decision that must come from a reviewed deployment manifest.

Historical upstream network BOCs, prebuilt compile outputs, deployed addresses, oracle key sets, and mainnet deployment command files are intentionally excluded and must not be reused for TOS.
