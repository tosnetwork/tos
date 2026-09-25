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

## Exact-tree route at `75eaae8ab`

`test/integration/.e03-localnet-75eaae8ab-20260925/report.json` (SHA-256 `2980c0fc4e929934f441edb4ef6749ddbe57af52739d30833e03e7ea9bad88f8`) records demo exit 0 and route FAIL. Before the failure, workchain-0 shard blocks 1–187 were all present in the explorer index (187/187); all five Agent Economy contract kinds and the Nominator Pool were classified. Thus this run confirms the missing-block fix in a real local chain, but not the full E03 route.

The new stop was the seed's `pool nominator deposit --amount 2`: the CLI's 15-second seqno poll timed out after seven reads of seqno 2, with its final observed references MC81/shard187. The original proxy trace is `toscan/tosctl-http-transcript.jsonl` (SHA-256 `8b9ee94ede2a182612a104065277af9547e955fe5578fa7bddd0ece205db76be`). The retained chain was reopened **without resending**; `toscan/pool-deposit-forensic.json` (SHA-256 `14c22fc9ac73bd153a8f48ff45faf5e7a8b983654f1ae94ed20e9e7bb9d913c4`) binds the last `sendBoc` external hash `whMwAX/fDlc6OpkJfkz/fH2ePi6wKWCC/PbwjUl1zoU=` to successful wallet transaction LT190000001 in shard189, its one outgoing message to the pool, and the pool's successful inbound transaction LT192000001 in MC82. Reopened wallet seqno was 3. The on-chain `utime` alone does not establish when the JSON-RPC head first exposed the transaction; the exact observed shard references show why the seven polls did not see it.

The follow-up change makes this pool deposit reuse the bounded exact-hash wallet confirmation already used for deployments. It broadcasts once, checks wallet action success and destination with paginated transaction history, and retains the hash on an ambiguous timeout. A test uses the public retained wallet transaction BOC; it refuses a wrong hash, wrong destination and the existing aborted/read-error controls. It does not assert pool contract acceptance by itself; the seed's subsequent delegation check remains the effect assertion. A new exact-tree full route is still required.
