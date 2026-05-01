# Slice 3 Compatibility Matrix

| Surface | Slice 1 | Slice 2 | Slice 3 |
| --- | --- | --- | --- |
| Internal body layout | `opcode:uint32 query_id:uint64 payload` via Envelope policy | Preserved by `contract receive(...)` lowering | Preserved by stdlib helpers and scaffolds |
| Unknown opcode policy | Hand-written per contract | `@unknown_throw`, `@unknown_silent_drop`, or `UnknownOpcode` receiver | Same syntax; Stage 7 warns when policy is implicit |
| Storage model | Manual load/save | Single `storage:` struct, optional state lowering | Same, plus pattern helper structs |
| State machines | Manual | `states:`, `@initial`, `become`, `keep_state`, `@on` checks | Stage 7 receive-exhaustiveness warnings over state/message cells |
| Query-id propagation | Warning pass for replies | Per-receiver scoping and wallet-v5 external exception | Manifest-backed reply table key `(expected_responder, query_id, expected_reply_opcode?)` |
| External messages | Hand-written | `receive_external` for Slice 2 contracts | Wallet-v5 raw signed body shape preserved; no internal preflight |
| Stdlib domain patterns | Not available | Not available | Ownable, Jetton, NFT, wallet-v5, multisig |
| Scaffolding | Not available | Not available | `tol new --pattern jetton/nft/wallet/multisig` |
| Replay/property fixtures | Ad hoc | Existing tol-tester/emulator fixtures | Slice 3 replay schema plus release-package examples |
| Wire compatibility | Baseline | Required by §6.1 | No new TL-B constructor, TVM opcode, or bounce-body constructor |

## Migration Guidance

Slice 1 contracts can keep raw Tol/FunC code. Slice 2 contracts can
adopt Slice 3 helpers incrementally when the helper preserves their
wire bytes. Slice 3 scaffolds are the recommended starting point for
new Jetton/NFT/wallet/multisig work, but they are not a new protocol
mode.
