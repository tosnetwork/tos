# TVM Model for Solidity Developers

TVM contracts receive cells, parse slices, and write storage back to
`c4`. There is no implicit ABI dispatcher unless the Tol compiler
synthesizes one from `contract { receive(...) }`.

Key differences:

- Message bodies are bit-level cells, not ABI-encoded calldata.
- `queryId` is a protocol correlation field, not a transaction nonce.
- Outbound messages are explicit actions; wallet-v5 C5 action lists are
  intentionally raw.
- Storage is a serialized struct cell; `save(...)` is the write boundary.
- Bounce and unknown-opcode policy must be explicit in the contract.

Slice 3 scaffolds expose these details through generated source,
manifests, opcode maps, error maps, and replay traces.
