# wc0 Event Index — Global Retention (P1)

## Problem

The wc=0 wallet event index (`${db_root}/wc0-index`, a derived, non-consensus
RocksDB) stores one row per wc=0 transaction: key `0x12 | account(32) | ~lt_be(8)`
→ the full transaction cell (`wallet-index.cpp:22,90-94`, `put_event` at
`:274-286`). PR #72 added `trim_events()` (`wallet-index.cpp:288-347`), which the
writer calls once per touched account per block (`wallet-index-writer.cpp:512`).

`trim_events()` is **per account only**: it scans the prefix `0x12 | account(32)`
and keeps the newest `kMaxEventsPerAccount = 10000` rows for *that account*
(`:319-345`). There is **no global bound** — no total count, total bytes,
seqno/time TTL, or cross-account retention. The function's own comment concedes
a companion time index would be needed to reach old rows and that none exists.

So the total on-disk size of the index grows with **(number of distinct accounts
ever touched) × (transaction size)**, without bound:

```
account A1 → 1 tx → 1 event, kept forever  (1 < 10000, per-account trim never fires)
account A2 → 1 tx → 1 event, kept forever
...
account A_N → 1 tx → 1 event, kept forever
```

One-transaction accounts never re-enter `index_block_walk()`, so there is no
lazy cleanup either. Because this is a **derived RPC index** (explicitly not
consensus state — it never contributes to a state hash and can be pruned/rebuilt
without a hardfork, per `wallet-index.h:1-13`), unbounded growth here is
**invalid storage growth**, not legitimate chain-state growth. The existing
wallet-index test only exercises the hot-account case (many events for one
account), which is exactly why this dimension was missed.

Severity: **P1**, to fix before a long-lived public JSON-RPC mainnet node runs.

## Proposed fix — companion age index + bounded per-block prune

Add a second, non-consensus namespace that lets the index drop *whole accounts'*
old rows, aligned to the archive retention window.

### New key namespace (tag `0x14`, currently free; tags used are `0x10`–`0x13`, `0x1E`)

```
event      (existing): 0x12 | account(32) | ~lt_be(8)      -> tx cell
event-age  (new):      0x14 | gen_utime_be(4) | account(32) | lt_be(8) -> sentinel(1)
```

Key the age index by the block's **`gen_utime` (wall-clock seconds)**, not by
seqno. Rationale: retention is defined in time (align to `archive_ttl`, default
7 days), and wc=0 is sharded — a bare seqno is not unique across shards
(split/merge reuse), while `gen_utime` is monotonic-enough and shard-agnostic.
`gen_utime` is read from the block's `BlockInfo` during the walk the writer
already does. Storing plain `lt` (not `~lt`) in the age key lets the pruner
reconstruct the exact event key `0x12 | account | ~lt`.

### Writer changes (`wallet-index-writer.cpp`, all inside the existing per-block batch)

1. For every `put_event(account, lt, tx)` the walk writes, also write the
   companion `event-age` row for `(gen_utime, account, lt)`. (Thread `gen_utime`
   into `index_block_walk`; it is already parsed for the block.)
2. Once per block, after the walk, run a **bounded** prune: compute
   `cutoff = latest_gen_utime - kEventRetentionSeconds`; range-scan
   `[0x14 | 0, 0x14 | cutoff)` for at most `kEventPruneBudgetPerBlock` entries;
   for each, delete both the `event-age` row and its reconstructed `0x12` event
   row, in the same batch. A backlog drains over successive blocks; steady-state
   per-block work is bounded. Use the block's own `gen_utime` as "latest" (do not
   trust wall clock, which would prune differently across replay).

`kMaxEventsPerAccount` stays as the per-account cap (defence in depth for a hot
account within the window). `kEventRetentionSeconds` (default `7 * 86400`) and
`kEventPruneBudgetPerBlock` are declared in the header next to the existing
constants so the test can assert the exact bound.

### Consistency / safety

- The index is already **best-effort, off the consensus path** (a failed write
  only degrades RPC for that block; it never blocks consensus —
  `wallet-index.h:10-11`). The prune inherits this: a failed prune logs and does
  not fail the block.
- All age writes and prunes join the **existing per-block `WriteBatch`** under
  `write_mutex()`, so they are atomic with the event writes and the
  incomplete-block marker delete (`wallet-index-writer.cpp:559-625`).
- Deleting an event row whose age row is being pruned is idempotent (RocksDB
  delete of an absent key is a no-op), so a crash between writing the event and
  its age row, or vice versa, cannot corrupt state — at worst it leaves one
  orphan row that the next matching prune or a rebuild removes.

### Migration (schema bump + forward rebuild, no complex backfill)

`open()` (`wallet-index.cpp:110-126`) has no schema-version key today. Add one
(`0x00 | "schema"` → `version_be`). On open:

- If the stored version is absent or below the version that introduces the age
  index, **range-delete the `0x12` event namespace and the `0x14` age namespace**
  and write the new version. The index then rebuilds **forward** as new blocks
  are indexed; it does not attempt to replay archive history (a derived index;
  clients can fall back to liteserver/archive for pre-upgrade history). This is
  cheap and avoids carrying pre-existing unbounded one-tx-account rows across the
  upgrade. Pre-mainnet (genesis 2026-09-15) there is no meaningful history to
  lose.
- Jetton/NFT/nft-owner namespaces (`0x10`/`0x11`/`0x13`) are unaffected by the
  migration (they already have erase paths and current-owner reconciliation).

An optional bounded archive backfill of the recent window is explicitly **out of
scope** for this PR.

## Test (falsifiable — must go red without the global bound)

The existing test covers the hot-account case; add the case that exposes the
global gap:

```
for seqno in 0..1000:
    account = fresh_unique_hash(seqno)      # a brand-new account each block
    put_event(account, lt=1, tx)            # exactly 1 event per account
    put_event_age(gen_utime(seqno), account, 1)
    prune(cutoff = gen_utime(seqno) - retention)
assert total 0x12 rows <= bound implied by retention window   # not ~1000
```

With the age index + prune, once `gen_utime` advances past the retention window
the oldest accounts' single events are deleted, so the total stays bounded by the
retention window, **not** by account count. Reverting the prune (or the age
writes) leaves ~1000 rows and the assertion fails. Also assert: a within-window
account's event is still present; the prune budget bounds per-call work; and an
event row is actually gone after its age row is pruned (reconstructed-key
correctness).

## Out of scope (tracked separately per the audit)

Telemetry JSONL rotation (P2), the all-shards rotation consensus-DB orphan window
(P2, needs an independent `pending_consensus_db_cleanup` queue), the Rust
incinerator / unbounded-channel latent risks, and the nightly LSan + RSS-slope
soak CI. `TsFileLog` rotation (the reviewer's item 2) is already fixed in the
open PR #87.
