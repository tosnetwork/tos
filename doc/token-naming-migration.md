# TOS Token naming migration

## Scope and compatibility decision

The active fungible-token API is named **Token**. This is a breaking source,
SDK, JSON API, and contract-getter migration, not a display-only rebrand.
There are no deprecated Jetton exports, getter aliases, RPC field aliases, or
scaffolding aliases. TEP-74 compatibility is not an acceptance requirement.
The native currency remains **TOS**; this change does not create a new native
currency and does not replace the VM or the consensus algorithm.

The implementation preserves the asynchronous master/wallet architecture and
existing financial arithmetic, authorization checks, bounce handling, message
layouts, and numeric message operation tags. Those integers are contract
message discriminators, not newly introduced VM instructions. Keeping a
well-tested discriminator does not create an obligation to support an old API.
The generic `get_wallet_data` and `get_wallet_address` names remain valid.

## Public names

| Previous name | Active name |
| --- | --- |
| Jetton Master / JettonMinter | Token Master / TokenMaster |
| JettonWallet | TokenWallet |
| `@stdlib/jetton` | `@stdlib/token` |
| `jetton-minter.tol` | `token-minter.tol` |
| `jetton-wallet.tol` | `token-wallet.tol` |
| `get_jetton_data()` | `get_token_data()` |
| `JETTON_MINTER_CODE_HEX` | `TOKEN_MASTER_CODE_HEX` |
| `JETTON_WALLET_CODE_HEX` | `TOKEN_WALLET_CODE_HEX` |
| `JettonData` (contract result) | `FungibleTokenData` |
| `TokenKind::Jetton` | `TokenKind::Fungible` |

`TokenData` already denotes an SDK union that includes NFT data. The separate
`FungibleTokenData` name avoids duplicate exports and does not conflate fungible
balances with NFT ownership. The stored `TokenKind` discriminants remain 0 for
fungible tokens and 1 for NFTs.

The implicit getter method ID changes from 106029 to 84418. SDKs, RPC method
selection, fixtures with explicitly declared IDs, and freshly compiled master
contracts must agree on the new ID. Merely changing a TypeScript export while
reusing old embedded master bytecode is not a valid migration.

## Source coverage and provenance

The rename covers owned contracts and helpers, TOL scaffolds and standard
library manifests, SDK contracts and hooks, bridge code, node indexing and RPC,
configuration serializers, build wiring, and active tests and examples.

Copyright and license text, original source URLs, commit-pinned citations,
changelogs, captured evidence, and the frozen X02 input manifest retain their
original wording. License files move with a renamed source directory without
changing their bytes. These historical/provenance occurrences are not runtime
compatibility aliases. The migration script and its tests necessarily contain
the old spelling as input and as a rejection control.

The Token naming validation workflow is read-only. It independently compiles
both the pinned baseline and the candidate, reverts the getter ID and interface
identifiers in a disposable copy, and requires the original hashes to return.
The checked-in SDK BOCs and compiler goldens must reproduce without rewriting
files or pushing commits from CI.

## Generated artifacts are a separate acceptance boundary

Recompile both SDK-embedded contracts from the renamed source. Recompile the
changed FunC golden fixtures and verify the previous source against its previous
hash before updating an expected hash. Do not patch binary BOCs or blindly
replace hashes until a test becomes green. Rebuild the native master/wallet BOC
fixtures so tests execute candidate code, not stale artifacts.

The migration tool changes source and paths only. Its passing tests do **not**
prove the contracts, SDK, node, or bridge are correct. Those boundaries require
their own build and execution evidence.

## Existing deployments and operator impact

This PR does not deploy contracts, submit transactions, move balances, upgrade
existing accounts, or delete a live index. A source rename does not alter code
already stored on-chain. Existing bytecode is not prohibited from executing by
this API change, but updated tooling makes no promise to recognize its old ABI.

A changed compiled code cell changes the corresponding StateInit-derived
address for a new deployment. Existing balances do not migrate automatically.
Operators must explicitly choose a redeployment or asset-migration plan before
using this on a network with funded contracts. SDK test-account addresses,
checked-in deployment caches, and wallet-index caches must be regenerated or
rebuilt for the selected network; do not relabel an old address and assume that
it implements the new getter. Do not run live deployment scripts as unit tests.

## Required validation

| Boundary | Evidence required |
| --- | --- |
| Rename mechanics | `python3 scripts/test-token-naming.py`; path collisions, legal preservation, symlinks, exact getter ID and a failing legacy-name control |
| Active source inventory | `python3 scripts/migrate-token-naming.py --check` |
| SDK | Build, typecheck and offline unit tests; no duplicate `TokenData` exports |
| Embedded code | Recompile/reproduce the SDK BOCs and changed compiler goldens |
| Contracts | Native master/wallet execution, fee-profile and replay tests with a nonempty test inventory |
| Node and serializers | Relevant C++ and Rust builds, RPC/index and config serializer regressions |
| Bridge | Offline protocol-model tests and native bridge sandbox regressions |
| Static analysis | The repository's required two-build differential analysis gate |

A pending, skipped, unavailable, or failed check is not a passing result. The PR
must remain unmerged until all relevant acceptance boundaries and protected
branch checks have adequate evidence.
