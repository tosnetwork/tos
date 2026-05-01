# Slice 6 Compatibility Matrix

| Surface | Wire / protocol impact | Default status | Compatibility rule |
| --- | --- | --- | --- |
| Delivery id helpers | TL-B scaffold only | Stdlib available | Legacy sends unchanged |
| BackPressureAdvice | Payload validation only | Production emission gated | `ErrorClass.BackPressure` remains reserved |
| Scheduled messages | Masterchain-seqno shape | Stdlib/model available | Validator activation requires separate gate |
| `@stdlib/time` | No new legacy entrypoint | Available | No caller-controlled `msg.now` scheduling |
| `OP_MONITOR_DOWN` | System opcode `0x00000010` | Available | Not encoded as `OP_ERROR` |
| `extra_flags` bit 3 | None | Reserved/invalid | No mask widening in Slice 6 baseline |
| Supervision strategies | Contract-level stdlib | Available | Non-atomic best-effort recovery |
| Capability handles | Contract-level stdlib | Available | Public grants, no bearer secrets, pubkey grants require signature path |
| Failure traces | Off-chain artifact schema | Available | Bounded, payer-labelled records |

Slice 6 repo-side code is additive for existing Slice 1-5 contracts. The
release checker enforces this by scanning for `msg.now` scheduling,
`extra_flags` bit-3 activation, reusable public bearer capability tokens,
and missing budget surfaces.
