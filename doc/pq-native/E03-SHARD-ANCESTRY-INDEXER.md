# E03: shard-head-only indexing omitted deployed contracts

Status: implementation locally tested; E03 retained-route acceptance remains OPEN until an exact committed-tree run completes.

The retained `14ced1f18` run failed at `all seeded contracts discovered chain-wide` after 180 seconds. Its report is `test/integration/.e03-localnet-14ced1f18-20260925/report.json` (SHA-256 `2c5e86502b796487f77caf021b71c0dd48a1fa3d713d2bb830d590997ad95859`). The explorer DB had masterchain blocks 1–136, but only 134 of workchain-0 shard blocks 2–313. The old indexer scanned only each masterchain block's reported shard *head*, then moved its checkpoint to that head.

The saved chain was resumed read-only for RPC diagnosis, without repeating any deploy command. The three absent contracts have successful, nonaborted deploy transactions in precisely the skipped shard blocks:

| Contract | Address prefix | Deploy LT | Exact wc0 shard block | Adjacent indexed blocks |
| --- | --- | ---: | ---: | --- |
| Agent Account | `0:aa9b9c50` | 124000003 | 123 | 122, 124 |
| Capability Registry | `0:698a8a73` | 134000003 | 133 | 131, 134 |
| Task Escrow | `0:4c80e3eb` | 153000003 | 152 | 151, 153 |

This is direct evidence for the indexer omission; it is not evidence that those deployments failed on chain. Service Actor and Dispute, whose deployment blocks were indexed, were discoverable.

The fix exports proof-derived exact `prev_blocks` from `getBlockHeader` and walks those block IDs back to already indexed ancestors, including split and both merge parents, then scans in ancestor-before-descendant order. The block transaction page must match each exact ancestor ID. A hash conflict at an indexed coordinate resets the canonical index and requires replay. A missing predecessor, mismatched header/page, or ancestry bound failure stops advancement rather than guessing a predecessor from seqno. Schema v10 replays databases produced by the head-only indexer: it clears stale block/transaction identities and block checkpoints, but preserves accumulated contract and economic records that current-state RPC cannot reconstruct historically.

The first saved-chain `getBlockHeader` probe of shard block 123 exposed a wire-format error in this new code: the C++ unsigned shard bits emitted `9223372036854775808`, which Rust cannot parse as `i64`. After casting to the signed shard representation and rebuilding `validator-engine`, the same block returned parent seqno 122 with shard `-9223372036854775808`, plus exact root/file hashes. This validates the actual header-proof extraction and wire type on the retained chain, not merely the scripted Rust provider.

Local controls:

- `cargo test --manifest-path tosctl/src/Cargo.toml -p service --lib indexer --locked`: 67 passed. Includes MC head 2→5 with a deployment transaction in intermediate block 4; split/merge parent traversal; reorg reset; v9 replay.
- Temporary head-only mutation, `let ancestry = NewShardHistory::Blocks(vec![shard.clone()]);`, made `masterchain_head_jump_indexes_intermediate_deployment_block` fail on absent block 3 (exit 101). Restoring the exact-parent walk made it pass. The mutation was not committed.
- `cmake --build build --target validator-engine -j 4` and `cargo build --manifest-path tosctl/src/Cargo.toml -p tosctl --locked`: exit 0.

These checks do **not** yet establish that a fresh TOSCAN run discovers all five contracts within its deadline. That needs a committed source tree, its actual binary hashes, full raw route output and terminal report. E03 remains OPEN.
