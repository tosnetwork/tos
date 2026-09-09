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

## Codex review outcome (2026-09-10) — revised design

Codex (read-only) confirmed the **problem is AUTHENTIC** and the approach
**SOUND-WITH-CHANGES**. The design below supersedes the sketch above with the
six required changes:

1. **Proportional prune budget (not fixed).** A fixed budget `B` lets storage
   grow when a block adds more than `B` fresh-account events. Use
   `budget = age_rows_added_this_block + kEventPruneDrainPerBlock`, mirroring the
   existing per-account `trim_events` (`wallet-index.cpp:314`): a pass always
   removes at least what the block added, so growth cannot outrun it; the drain
   shrinks any backlog. The prune counts **all** age rows in `[0x14|0, 0x14|cutoff)`,
   including orphans whose event was already removed.
2. **Persisted non-decreasing watermark for the cutoff.** Blocks can arrive out
   of timestamp order (recovery path, concurrent shard actors), so the cutoff must
   never regress. Persist `max_gen_utime` in a meta key; each block sets
   `wm = max(wm, block.gen_utime)` and `cutoff = wm > kEventRetentionSeconds ? wm - kEventRetentionSeconds : 0`
   (saturating). The range scan upper bound is exclusive, so an event exactly at
   `cutoff` is retained — the test asserts that boundary. Late blocks that insert
   already-expired age rows are cleaned by the same block's prune (their rows are
   `< cutoff`, and the proportional budget covers the rows just added).
3. **Writer atomicity / error handling.** Age and event rows go into the same
   per-block `WriteBatch` (atomic, `sync=true`), so no half-pair survives a crash.
   But: (a) bail if `begin_batch()` fails (today the walk proceeds before the
   `batch_open` check); (b) a failed age/event enqueue must abort the batch and
   leave the incomplete-block marker, not log-and-continue with the marker
   cleared; (c) per-account `trim_events` still deletes only `0x12` — its `0x14`
   sentinels (≤ a hot account's within-window count, one byte each) are reclaimed
   by the time-prune at expiry. This is intentional and documented, and the global
   bound still holds because the prune budget is proportional to age inserts.
4. **Migration.** In `open()` add a schema-version meta key. If below the version
   that introduces the age index, in **one WAL-synced batch before exposing the
   singleton**, range-delete exactly `[0x12,0x13)` and `[0x14,0x15)` and write the
   version; leave `0x10/0x11/0x13/0x1E` untouched; **reject** an unknown newer
   version (leave the singleton null) rather than misinterpret it. The index then
   rebuilds forward. This removes all pre-upgrade event history (recent included);
   document that the event RPC does not fall back to archive
   (`json-rpc-server-wc0index.cpp:317`). Retention awareness also applies to the
   incomplete-block recovery path. (Range delete is logical; physical reclaim is
   at compaction.)
5. **Test** drives the production writer end to end (not `put_event_age` directly),
   uses explicit `gen_utime`s spanning more than the retention window, asserts
   literal counts on **both** the `0x12` and `0x14` namespaces and actual event
   absence, and covers: insert rate > drain, equal timestamps, backward arrival,
   the exact `cutoff` boundary, saturating underflow, hot-account age remnants,
   batch abort/reopen, and migration preserving `0x10/0x11/0x13/0x1E`. It must go
   red when age-insertion and pruning are each disabled.
6. **Liveness wording.** The hook runs synchronously on the apply path
   (`apply-block.cpp:286`) under `write_mutex()`; it does not touch the consensus
   state tree and a failure only degrades RPC, but it is not free of apply
   latency. Work per block is bounded (proportional budget). A dedicated bounded
   worker for isolation is possible but deferred; an absolute count/byte ceiling
   (vs the time window alone) is also deferred and noted.

## Out of scope (tracked separately per the audit)

Telemetry JSONL rotation (P2), the all-shards rotation consensus-DB orphan window
(P2, needs an independent `pending_consensus_db_cleanup` queue), the Rust
incinerator / unbounded-channel latent risks, and the nightly LSan + RSS-slope
soak CI. `TsFileLog` rotation (the reviewer's item 2) is already fixed in the
open PR #87.
