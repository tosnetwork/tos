# TOS cross-chain bridge contracts

This directory gathers the market-proven TON bridge smart-contract planes into the TOS monorepo as vendored source code, pinned by upstream commit and rebuilt with the TOS toolchain. Nothing here is enabled on any TOS network; every bridge is gated by its own `SECURITY.md`.

| Directory | Bridge | Upstreams |
|---|---|---|
| `legacy-jusdt-bridge/` | ERC-20 ↔ wrapped Jetton token bridge (the jUSDT architecture) | `ton-blockchain/token-bridge-func`, `ton-blockchain/token-bridge-solidity` |
| `legacy-toncoin-bridge/` | Native coin ↔ wrapped ERC-20 bridge | `ton-blockchain/bridge-func` (`master` + `bsc` branches), `ton-blockchain/bridge-solidity` |
| `fift-compat/` | Fift library name shims (`TonUtil.fif` → `TosUtil.fif` and coin-word aliases) used to run upstream Fift sources under the TOS toolchain | — |

Each bridge directory contains:

- `upstream/` — filtered byte-for-byte copies of the pinned upstream repositories (deployed BOCs, addresses, oracle key sets, and mainnet deployment commands are excluded).
- `tvm/`, `evm/` — the TOS-facing build trees. The only deltas against `upstream/` are documented toolchain-compatibility renames; contract logic is unchanged.
- `UPSTREAM.lock.json`, `SOURCE_MANIFEST.sha256` — provenance and integrity records.
- `tests/` — dependency-free protocol model tests for the cross-plane invariants.
- `README.md`, `SECURITY.md`, `NOTICE.md`.

Regeneration, drift checking, building, and testing are driven by the `scripts/import-legacy-*.py`, `scripts/verify-legacy-*.py`, `scripts/build-legacy-*.sh`, and `scripts/test-legacy-*.sh` entry points at the repository root, and run in CI via `.github/workflows/legacy-jusdt-bridge.yml`.

The EVM halves of these bridges target external counterparty chains (Ethereum, BNB Smart Chain, Polygon). Vendoring them does not add an execution engine to the TOS node — see `doc/workchain-execution-registry.md`.
