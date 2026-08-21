# TOS cross-chain bridge contracts

This directory contains the complete smart-contract planes of the TOS cross-chain bridges as first-class TOS source code. The state machines derive from a market-proven upstream bridge architecture (provenance and licenses are recorded in each bridge's `NOTICE.md`), fully renamed to TOS semantics and built, assembled, and tested with the TOS toolchain. Nothing here is enabled on any TOS network; every bridge is gated by its own `SECURITY.md`.

| Directory | Bridge | Direction |
|---|---|---|
| `token-bridge/` | ERC-20 ↔ wrapped Jetton token bridge | external ERC-20 locked, Jetton minted on TOS |
| `coin-bridge/` | Native coin ↔ wrapped ERC-20 bridge | native TOS locked, wrapped ERC-20 minted externally |

`tvm-test-harness/` holds the shared Fift driver that both bridges' `tvm/tests/` suites use to execute compiled contracts in the TOS TVM.

Each bridge directory contains:

- `tvm/` — the FunC/Fift contract plane, compiled with the TOS `func` compiler and selected through TOS masterchain ConfigParams.
- `evm/` — the Solidity contract plane deployed on external counterparty chains, with its full test suite.
- `tests/` — dependency-free protocol model tests for the cross-plane invariants (quorum, replay protection, supply conservation).
- `tvm/tests/` — TVM-level tests that compile the contracts and run them, so security-critical behavior is proven by execution rather than by matching source text.
- `README.md`, `SECURITY.md`, `NOTICE.md`.

Building, testing, and invariant verification are driven by the `scripts/build-*-bridge.sh`, `scripts/test-*-bridge-*.sh`, and `scripts/verify-*-bridge.py` entry points at the repository root, and run in CI via `.github/workflows/bridge-validation.yml`. The verify scripts also enforce that no legacy source-chain naming reappears in these trees.

The EVM halves of these bridges target external counterparty chains (Ethereum, BNB Smart Chain, Polygon). Vendoring them does not add an execution engine to the TOS node — see [`workchain-execution-registry.md`](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/workchain-execution-registry.md).
