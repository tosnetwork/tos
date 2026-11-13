# Archive replay

`replay/archive-replay.cpp` (target `conformance-archive-replay`) replays archived chain history offline,
the way an offline replay of a whole ledger does: every masterchain and shard block in order, every
transaction re-executed, every result compared with the chain. The chain is the only oracle; nothing is
frozen from a C++ run.

## What one block goes through

1. Identity: the archive entry name `block_(wc,shard,seqno):ROOT:FILE` must equal the SHA-256 of the
   bytes, the root hash of the BOC and the header's workchain, shard and seqno.
2. Parent: the header's `prev_ref` must be the block replayed just before it (the zero state for seqno 1).
3. State: the Merkle update must start from the replayed state hash. In `full` mode it is applied to the
   complete previous state and the result must have the declared new state root; the new state is complete
   again. A masterchain block's registered shard top must be the archived shard block of that seqno.
4. Execution: every transaction is re-executed with `emulator::TransactionEmulator` (the path of
   `test-epoch-replay`): configuration and previous-block context from the masterchain state the block
   names (`prev_ref` for a masterchain block, `master_ref` for a shard block), the block's random seed and
   logical time. The transaction hash and the new account hash must be the on-chain ones, and in `full`
   mode the account after the block's last transaction must be the one stored in the new state (a
   nonexistent account is not stored).

Order: after masterchain block N, every shard block whose `master_ref` is at most N is replayed, so a shard
block always finds its exact masterchain state (a window of 1024 states is kept).

Without a starting state (a source that starts inside history, or after a gap), the tool runs in
`hydrated` mode: each block's update tree is completed from original cells (the last complete state, every
earlier update tree, the proofs of key-block packages, supplied BOCs), accepted only by level-zero hash, so
no value can change. The parent link and the update's start hash are still checked against the previous
block. A read of a cell that stays pruned is a refusal (`missing data: ...`), counted per block and per
transaction. When hydration yields a complete state, replay continues in `full` mode.

Every indexed block ends in exactly one class: `ok`, `mismatch`, `refused`, or `not replayed` with a
reason; seqnos missing from every package are `absent` ranges. Every on-chain transaction ends matched,
mismatched, refused, skipped after its account diverged, or not executed (the block stopped early). After
`--max-mismatches` (default 5) mismatch events the source is given up and the rest is counted as such.

## Outputs

`--out DIR` gets `blocks.jsonl` (one record per block, one per absent range), `summary.json`, and for the
k-th mismatch `mismatch-00k/`: `record.json` (block id, kind, predecessor state hash, chain and replay
hashes), `block.boc`, `predecessor-state.boc` (complete states up to 64 MiB) and, for a transaction,
`txn-context.jsonl`: the first diverging transaction as a `txn` harness context with its chain hashes.

`--export DIR --export-from A --export-to B [--export-limit N]` writes every transaction of masterchain
steps A..B as `txn` contexts (`contexts.jsonl`, BOCs over 2048 base64 characters in
`contexts.blobs.json`, the runner's blob format), each with its on-chain transaction and account hash.
Any implementation with the `txn` line protocol runs the same history:

```
python3 test/conformance/migrate/archive.py chain <target> <export dir>
```

## Driver

```
python3 test/conformance/migrate/archive.py replay --tool build/test/conformance/conformance-archive-replay \
  --out OUT --source NAME --packs ROOT=SHA256LIST[=GLOB] [--cell-packs ROOT=SHA256LIST=GLOB] \
  --zerostate zerostate.boc --basestate basestate0.boc [--export DIR --export-from A --export-to B]
```

Every `.pack` under ROOT must be in the list and equal its SHA-256, and every listed package must exist, or
the run stops. `OUT/manifest.json` records the package sets (count, bytes, digest of the sorted list), the
states, the tool's SHA-256, the summary and the times. `docs/archive-manifest.json` is the committed copy of
the full runs below.

## Tests (label `conformance-archive`)

- `conformance-archive-rel02`: the committed REL-02 corpus (366 blocks, 576 transactions) replayed without
  a starting state; every block's root, file and state hashes and the transaction count must equal the
  corpus oracle (`manifest.json` `expected`).
- `conformance-archive-epoch5-slice`, `-epoch6-slice`: masterchain 1..2000 of each network from its zero
  state (packages verified), then every exported context through `conformance-ref-cli txn` against the
  chain. They exit 77, shown by ctest as `Skipped`, when the archives (cache variables
  `CONFORMANCE_ARCHIVE_EPOCH5`, `_EPOCH6`, `_INPUTS`) are not on the host.

`ctest -L` takes a regular expression, so `-L conformance` also selects these; `-L '^conformance$'` does not.

## Full runs (2026-11-13)

Replay commit `9d335a2d9`; inputs and outputs in `docs/archive-manifest.json`.

| | epoch 5 | epoch 6 |
|---|---|---|
| packages (verified) | 4,872 node (a) + 293 node (b), 3.996 GB | 10,860, 8.429 GB |
| masterchain blocks replayed | 256,782 (242,333 full, 14,449 hydrated) | 540,999 (all full) |
| shard blocks replayed | 257,980 (257,979 full, 1 hydrated) | 547,567 (all full) |
| absent | mc 242,334–248,300 (5,967), shard 243,423–249,420 (5,998) | none |
| on-chain transactions | 530,098 | 1,116,278 |
| matched | 526,422 | 1,116,278 |
| mismatches | 0 | 0 |
| refused transactions | 3,676 (all in node (b)'s hydrated range) | 0 |
| refused blocks | mc 2,046, shard 2 | 0 |
| new-state account checks | 484,982 | 1,082,302 |
| exported `txn` contexts | 562 (mc 117,700–117,950) | 4,124 (mc 1–2,000) |
| `chain` with `conformance-ref-cli` | 562/562 equal | 4,124/4,124 equal |
| wall time (one process) | 380 s replay + 5 s SHA-256 check | 264 s replay + 16 s SHA-256 check |

Epoch-5 refusals are missing data, not divergence: node (b)'s packages start at masterchain 248,301 with
no state, so its blocks run hydrated, and cells written in the absent range and never rewritten stay pruned
(1,500 blocks: previous-block context; 547: an account; 2 shard blocks: their masterchain context 248,300
is in the absent range). The basechain state became complete after one hydrated block.

## Controls

- A transaction context with `lt + 1` in an exported slice: `chain` reports 1 difference (exit 1), on both
  exports.
- `crypto/block/transaction.cpp` compute phase `gas_used + 1`, rebuilt: the replay reports a `transaction`
  mismatch from masterchain block 1, gives up after 5 with every other block counted
  `not replayed: gave up`, writes 5 reproductions; `chain` reports 103/103 differences; the first
  reproduction's context also differs. Restored and rebuilt: replay exit 0, the reproduction matches the
  chain, `ctest -L conformance` passes.
- A flipped byte inside a block entry of a copied package: `block_id` mismatch (file hash).
- The epoch-6 zero state for epoch-5 packages: `parent` and `old_state` mismatches on both chains.
- The new-state account check found the first full epoch-6 run's two false mismatches (accounts that stay
  nonexistent are not stored); the check was corrected and both re-runs are clean.

## Not covered

Split and merge blocks (refused; neither network ever split), other workchains (counted under
`other_shards`, none present), the epoch-5 range 242,334–248,300 (in no package) and pruned cells in the
hydrated range. Persistent states are not in the archives; the replay starts from the published zero
states.
