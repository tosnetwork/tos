# Safety and performance audit of `node-health-monitor` (2026-09-30/10-01)

Owner request: audit the branch for validator-side risk, with emphasis on
validator performance, anonymous memory growth and disk growth. Scope: the
engine-side diff against `main` (37 files under `metrics/`, `validator/`,
`tddb/`, `tdutils/`, `validator-engine/`, about 3.5 k lines) and the monitor
processes that run on the same host. Method: code reading with file:line
evidence (engine part delegated to a second reader, results in §2), plus
the live measurements this host produced today. A parallel review by the
Codex agent is expected; its findings are appended in §5 when received.

## 1. Where the memory and disk growth actually comes from

Measured, not inferred:

| Observation | Source | Reading |
| --- | --- | --- |
| Validator RSS grows ~1.4–1.5 GiB/h from process start, observers ~0.5 GiB/h | soak records 14:33–22:15 (old network) and 22:17–23:38 (rotating network) | growth is linear in time on both networks, independent of block rate changes |
| Growth continues with the health instrumentation **disabled** | A/C rounds: profile A (engine started without `--health-*`, `health::enabled=false`) 6.49 → 7.67 GiB over its 30-minute window | the instrumentation is not the source |
| Health edge processes stay at ~2 MiB RSS, 1.6 m-core each; M 71 MiB and 11 m-core; Q 82 MiB and 17 m-core (7 nodes) | soak 22:17–23:38 | monitoring cost on the host is negligible next to the nodes |
| Garbage collection has not advanced on either network | `try_advance_gc_masterchain_block` needs `gc seqno < last key block seqno` **and** `< state_serializer_masterchain_seqno_` (`validator/manager.cpp`); no persistent state has been serialized yet (first one after the first key block past the 2^17 s boundary, 2026-10-01 06:38:56 UTC) | every applied state stays resident; this is the node's own behaviour and identical to upstream TON |
| Node database grows ~2.5 GB/h per validator (`/data/testnet/node1` 4.2 GB after 1.6 h) | `du` on the rotating network | chain data without GC; same cause |

Conclusion for this section: the anonymous memory and disk growth seen today
are properties of the validator (no state garbage collection before the
first persistent state) and are not caused by the health instrumentation.
The instrumentation is statically sized (see §2) and the monitor processes
are small and flat. The `state_gc_lag_blocks` and `persistent_state_seqno`
facts added tonight make this visible to the monitor itself; until the
first persistent state the validators need the raised 16 GiB ceiling.

## 2. Engine-side instrumentation (hot paths, bounds, safety)

Read in full: every file under `metrics/` the branch touches, the consensus
hooks in `validator/consensus/simplex/{pool,consensus,db,state-resolver}.cpp`,
`validator/manager.{cpp,hpp}`, `tddb/td/db/RocksDb.cpp`, the exporter and the
engine option wiring; RocksDB's own source for the property the probe reads.
A size probe compiled from the headers measured the static objects.

What holds:

- **Ordering is preserved.** Every observation is placed after the business
  step it labels (`pool.cpp` intent persist → `IntentCommitted`; sign →
  `Signed`; signed persist → `SignedCommitted`; `handle_vote` →
  `LocalApplied`; publish → `BroadcastEnqueued`); no observation result feeds
  a branch. Same on the proposal and replay paths.
- **Failure isolation holds.** No new `CHECK`, `LOG(FATAL)`, throw or
  `.ensure()`; exhaustion of any ledger, pending table or registry only sets
  an `incomplete` bit; exporter bind and diagnostic-IPC setup failures log
  and disable themselves.
- **Nothing grows with time.** All shared stats are fixed-size globals:
  ≈ 477 KB always resident (largest item the 16 × 26.6 KB action ledger
  banks), exporter cache ≤ 1 MiB, typed snapshot ≤ 64 KiB, per-observation
  frames 32–40 bytes on the coroutine stack. The 4 MiB budget holds without
  diagnostics; with `--health-diagnostic` the 2.1 MB producer ring was
  missing from the deduction (fixed tonight).
- **Scrape surface is bounded.** One collection per 15 s with a 2 s work
  budget, single waiter, 30 s cache, ≤ 1 MiB body, 8 connections; the typed
  snapshot ≤ 256 KiB; external scrapers cannot trigger unbounded work.
  Loopback-only routes fail closed on a non-loopback bind.
- **No private material is published.** Session ids, block hashes, seqnos,
  validated aliases and counters only; the diagnostic IPC carries phase
  codes and clocks over a uid-owned socket with peer credentials.

Findings (severity, then what was done):

| # | Sev | Finding | Action |
| --- | --- | --- | --- |
| M1 | Medium | `publish_health_node_state` (added tonight) ran on the manager actor every second **with the health flags off**, walking the waiter maps and calling `statvfs` (a syscall that can block on a hung device) | **Fixed**: gated on `health::enabled`; `statvfs` at most every 10 s; comment corrected (it is a second pass over the waiter maps, not a free ride on the timer sweep) |
| M2 | Medium | The RocksDB write-stop probe (added this afternoon) ran on **every** synchronous commit of **every** RocksDB instance, ungated, and takes the DB-wide mutex; its comment called it lock-free | **Fixed**: gated on `td::storage_health.enabled` (set by `--health-core-metrics`), at most one probe per second per instance; comment states the mutex, the sampling and that the gauge is process-wide ("some database is stopped") |
| M3 | Medium | `lifecycle_verified` has no writer, so `instrumentation_complete` is false on every v2/v3 snapshot forever; shard sessions are also marked `ScopeUnapproved`; the flag is truthful but carries no information | **Fixed** (owner delegated the decision): the flag is set by the observation itself the first time a session is seen through the whole drain boundary (stop requested → database closed → bus released → observation closed), which is the boundary the C06 commit guarantees; a close without a requested stop does not count. A node whose sessions never rotate keeps it false, truthfully. Test added to `test-health-ledger` |
| M4 | Medium | Commit `6245329e7` ("Drain consensus observations before bus stop signal") changed validator-group teardown in `validator/consensus/bridge.cpp`: the DB close is now wrapped, the bus always released, and a `stop()` is called on the error path before `RocksDb::destroy`. Arguably a fix (it guarantees the health session closes), but it is business behaviour shipped inside the monitoring branch | **Reviewed, accepted**: the change is strictly safer than before (the bus handle is always released, the DB directory is never destroyed after a failed close, the group stops instead of continuing half torn down), and the fault-injection test already exists: `test-health-actions close-error` fails the DB close and asserts the bus handle is released and the observation drained before the stop promise; all 18 modes pass on this tree |
| M5 | Medium | 4 MiB budget arithmetic omitted the 2,105,424-byte diagnostic producer ring when `--health-diagnostic` is on | **Fixed**: deducted at both budget call sites |
| L1 | Low | Four double-read readers (chain anchor seqlock, context rows, two `oldest_started_ns`) used an acquire *load* where an acquire *fence* is needed; harmless on x86, torn reads possible on weak memory | **Fixed**: `atomic_thread_fence(acquire)` before the confirming re-read |
| L2 | Low | `SessionObservation` fields (`context_`, ledger bank pointer) were plain and touched from Pool, BlockProducer and Bridge actors; one window (destroy right after create) was a formal race | **Fixed**: both are atomics now (acquire/release), ledger and action tests unchanged and green |
| L3 | Low | Per-vote table scans of up to 1024/512 rows with `compare_exchange` (RMW even on failure); bounded, no allocation, a few µs worst case against a ~100 µs ML-DSA sign, gated by the flags | Not changed; optional free-list hint |
| L4 | Low | `dropped_updates_` jumped to `UINT64_MAX` after 8 contended CAS attempts, destroying the count while the comment promised a lower bound | **Fixed**: single `fetch_add`, saturate only at the top |
| L5 | Info | `CoreRegistry` dynamic slots are dead in production (`approved_production_name` is always false); 3.5 KiB | Noted |
| L6 | Info | A collector that hangs without answering leaves `/metrics` at 503 after the cache expires; by design, but operators must know a permanent 503 means a stuck source | Noted in the deploy README |
| I1 | Info | `X-TOS-Process-Epoch` on a possibly public `/metrics` is a stable per-process fingerprint | Noted; harmless on loopback |

Residual cost with both health flags off, after the fixes: two relaxed loads
per observation site, one 32-byte key copy per vote, the chain-anchor publish
(≈ 200 relaxed atomics per masterchain block and per second), and one
timestamp per registered waiter. No syscalls, no locks, no allocation.

## 3. Monitor-side storage growth on this host

| Store | Growth | Bound | Verdict |
| --- | --- | --- | --- |
| M `evidence.db` | ~48 MB/h with 7 nodes | 6 h age retention, 2 h floor, newest-8 per source; quota 2 GiB; steady state ≈ 300 MB | bounded; the first deleting pass ran live at 17:05 and removed 36,506 rows with Q unaffected |
| M `retention_seals` | one row per (node, scope, process_epoch, source_epoch, source) identity | grows only with new epochs (restarts, catalog/run changes); never pruned | Low: hundreds of rows per day at most; a prune of seals older than the window is a follow-up |
| M `control.db` | 472 KB after 12 h | incident timeline + outbox; outbox drained on delivery | Low |
| Q `query-ledger.db` | 7 MB after 1.6 h, 12.8 MB after 11 h on the old network (sublinear) | `query_evidence` is kept to a fixed window of rows (`DELETE … WHERE store_seq < first_live` on every import), terminal grants compacted by age | Low: bounded; the earlier reading of this row as unbounded was wrong |
| Judge journals (`verdicts.jsonl` 9.1 MB in 12 h, `model-verdicts.jsonl` 1 MB, `notifications.jsonl` 0.3 MB) | ~18 MB/day | none | **Medium**: private development files, but a production unit needs rotation or a size cap |
| Private Codex home for the model turn | 191 MB (plugins/cache 57 MB, `logs_2.sqlite` 15 MB, sessions 6 MB) | Codex's own | Low: development only; grows per turn |
| journald, user units | ~1 MB/h, mostly the minute timer's start/stop lines and the judge's stdout copy of its report | journald caps | Low: stop printing the report to stdout when `--journal` is set |
| Runtime archives from network rebuilds | 215 MB per rebuild | manual | Low |

## 4. Findings and fixes

Consolidated across §2 (engine reader), §3 (host) and §5 (Codex). Every
item below is either fixed with a test that was shown red against the
audited behaviour, or listed as a residual with its bound.

| Area | Finding | Status |
| --- | --- | --- |
| Validator hot path | M1/SEC-02 node-state publication ungated on the manager actor; M2/SEC-01 RocksDB probe on every commit | fixed: both behind `health::enabled`, node state on the one-second waiter gate, `statvfs` every ten seconds, probe at most once a second per instance |
| Validator correctness | M3 lifecycle never verified; M4 teardown ordering; L1 fences; L2 plain fields across actors; L4 counter destroyed on contention | fixed (M4 reviewed and accepted with its fault test) |
| Validator residual | L3 bounded per-vote scans with `compare_exchange` | accepted as bounded (≤ 1024 rows, no allocation); not changed |
| Monitor memory | SEC-03 Q charged JSON length but kept decoded trees | fixed: resident charge is the larger of bytes and decoded footprint, payloads over 4096 nodes refused |
| Monitor disk | SEC-05 retention stopped at the first page without candidates; SEC-06 grant ledger capped forever and never compacted; SEC-07 Q ledger without page quota or WAL checkpoint; §3 judge and receiver journals unbounded | fixed (§6, `360657385`, `e261f3f87`) |
| Monitor availability | SEC-04 M's retention could delete a parent Q retains and lock Q; a deleted cursor anchor stopped Q at start; a Q outage was visible to nobody | fixed (§6): seal-aware expiry, seal-aware re-anchor, doctor gate `query_broker` |
| Monitor ingress | SEC-08 body window before the budget check | partly fixed: health GET routes refuse any body with 413 up front; the collector's pre-allocation bound is a residual |
| Model lane | the diagnosis contract held at most six findings while the judge demands one observed finding per non-healthy node | fixed (`d913d30f6`): cap follows the 32-target inventory bound; a too-small contract is refused as `diagnosis_contract_capacity` before the model runs |

Growth attribution stands as in §1: the validators' anonymous memory and
disk growth is the absence of state garbage collection before the first
persistent state, measured identical with the instrumentation off.

## 5. Codex agent review (received 2026-10-01, baseline `371a2ae4f`)

Memo: `node-health-monitor/SAFETY-PERF-AUDIT-20261001.md`. Nine findings;
mapping to this note and what was done:

| Codex | Here | Status |
| --- | --- | --- |
| SEC-01 P1 RocksDB probe takes the DB mutex on every commit, ungated | M2 | fixed before the report arrived (`b4bdc7e2e`): gated by the health flag, ≤ 1 probe/s per instance, comment corrected |
| SEC-02 P1 ungated `statvfs` + waiter walk on the manager actor; alarm can fire more often than once a second | M1 | fixed (`b4bdc7e2e`) and, on Codex's addendum, moved onto the one-second waiter gate so an alarm wake-up never runs it (`360657385`) |
| SEC-03 P1 Q evidence cache charges JSON length, keeps the decoded tree (44.8 MB of Values for 3.3 MB charged) | new | fixed (`360657385`): the resident charge is `max(json bytes, decoded footprint) + 2048`, payloads over 4096 nodes are refused; test with the audit's 7000-zero payload |
| SEC-04 P1 M retention can delete a parent Q still retains; Q then locks as `manager_conflicted` | sub-agent's "no cross-process fence" | fixed on the Q side: a missing parent whose generation is covered by M's retention seal is an expiry, Q evicts the dependent evidence and continues; no seal or a generation above the seal still refuses (see §6) |
| SEC-05 P2 retention stops at the first page without candidates; cursor restarts at 0 | new | fixed: pages continue to the tail or the budget, resume cursor across passes, `complete` only at the tail (see §6) |
| SEC-06 P2 Q grants capped at 4096 rows forever; `compact_terminal` never called | new | fixed: cap counts resident grants, compaction runs on Q's 15 s tick and prunes compacted rows older than 30 days (see §6) |
| SEC-07 P2 no unified disk budget for main/WAL/logs; Q has no page quota; seals accumulate | partly new | Q gets `max_page_count` and `wal_autocheckpoint` like M (see §6); M's WAL gate, seal pruning and a declared total budget remain follow-ups |
| SEC-08 P2 collector allocates before the budget check; HTTP body window per connection | new | the health GET routes refuse any request body (413) up front (`360657385`); the collector pre-allocation bound stays a follow-up |
| SEC-09 P2 model output fully buffered; JSONL never rotates; receiver has no deadline or concurrency bound | partly my §3 | fixed (`360657385`, `e261f3f87`): capped streamed child output with kill, journal rotation for judge and receiver, receiver read deadline 10 s and 8 concurrent connections |

Codex's boundary statement agrees with §1: nothing attributes the validator
RSS growth to the monitor; with SEC-01/02 fixed the flags-off comparison is
now a clean one.

## 6. M/Q ledger fixes (SEC-04/05/06/07) and what deploying them exposed

Landed in `86032a5a4` (05:47 UTC), each with a test shown red first:

- **SEC-04**: a retained parent that M's retention deleted no longer locks Q
  as `manager_conflicted`. When the missing parent's generation is covered by
  M's retention seal for that identity, Q evicts the dependent rows from its
  ledger and memory and continues; no seal, or a generation above the seal,
  still refuses, because then the row vanished for a reason retention does
  not account for.
- **SEC-05**: a retention pass scans past pages without candidates and stops
  only at the tail, the page limit or the time budget; it resumes from its
  cursor on the next pass and reports `complete` only at the tail. Live after
  deploy: 1,937 rows deleted in the first pass of the 6-hour window.
- **SEC-06**: the grant ledger's resident bound counts only grants that still
  carry a body; terminal compaction runs on Q's own 15-second tick (with or
  without a manager database) and prunes compacted rows older than 30 days.
- **SEC-07**: Q's ledger opens with the same page quota and WAL
  autocheckpoint as M's evidence store.

Deploying them found three more defects, all on the Q side (`776e42f13`):

1. **Q had been down since 00:19 UTC and nothing said so.** The release
   binary copied into the runtime was built without the `mcp` feature while
   the unit passes an MCP socket, so Q exited at start 1,985 times over five
   and a half hours. Every live gate stayed green because none looked at Q.
   The deploy script now refuses a binary without the feature, and the doctor
   has a `query_broker` gate that fails when the broker's ledger (main file
   or WAL) has not been written for longer than its import period allows
   (`--query-ledger-db`, `--query-max-idle-seconds`, default 300 s).
2. With the right build, Q refused its own ledger as `invalid restored
   evidence`: rows written under the earlier resident charge now exceeded the
   SEC-03 bound. Restore evicts the oldest rows or skips a payload over the
   node bound instead of refusing to start, so the watermark stays continuous.
3. Then `M projection anchor changed`: during the outage M's retention had
   swept the row at Q's cursor anchor. A missing anchor is now accepted as
   an expiry only when a retention seal records deletions at or beyond its
   sequence; a present anchor with another hash, or a missing anchor without
   such a seal, is still a rewrite and refused (`M projection anchor missing`).

Q restarted at 05:57:58 UTC, imported to the current watermark within a
minute, 76 MiB resident, ledger 7.9 MB, and the doctor's new gate reads
`query ledger written 14 s ago`.

The doctor also surfaced a fourth defect that is not in either audit: from
03:41 UTC, when `state_gc_lag` degraded all seven nodes, every model turn was
rejected on schema. The diagnosis contract capped `findings` at six while the
judge requires an observed finding for every non-healthy node, so a correct
answer for seven nodes could not exist; `ai_unavailable` opened and the
`ai_lane` gate failed. Fixed in `d913d30f6` (cap 32 = inventory target bound,
capacity refusal before the model runs, the model may group nodes sharing a
cause); the next turn was accepted with three grouped findings and the
incident closed as recovered.

### Residuals (bounded, not fixed)

| Residual | Bound today | Why it waits |
| --- | --- | --- |
| M's WAL has no explicit size gate of its own | `wal_autocheckpoint` plus a passive checkpoint after every retention pass; page quota covers the main file | needs a declared total budget for main + WAL + logs per process, a config change rather than a code fix |
| Retention seals are kept for the life of the database | one row per (identity, pass) that deleted something; a few hundred bytes each | pruning a seal reopens the replay window it closed; needs a rule for when a seal is provably unreachable |
| Collector pre-allocates before the budget check (SEC-08) | per-connection body window, bounded connections, GET routes already refuse bodies | the remaining window is the connection count times the window size; small on this host, to be bounded by a shared counter |
| L3 per-vote scans | ≤ 1024 rows, no allocation, microseconds | accepted |
| Validator memory before the first persistent state | 16 GiB ceiling on validators, 8 GiB on observers | the node's own behaviour; `state_gc_lag` reports it and should clear after 06:38:56 UTC |

## 7. Independent re-review (memo `SAFETY-PERF-REVIEW-20261001.md`, frozen at `4163236b7`) and its closure

The reviewer rebuilt controls against the real stores and found that several
of the §4 fixes stopped short. Every gap below now has a test that was run
red against the previous code before the fix.

| Item | Reviewer's finding | What changed | Evidence |
| --- | --- | --- | --- |
| SEC-01 | gate and rate limit hold; the comment still said "lock-free" | comment states the mutex and the off-path return | engine `…-80d22e8ac358e541` |
| SEC-02 | `statvfs` still synchronous on the manager actor; a second waiter traversal per second | disk query on a short-lived thread, one in flight, writing lock-free gauges; waiter sample folded into the existing one-second sweep | engine `…-80d22e8ac358e541`, nine health test binaries green, 18/18 action modes, rolled onto all seven nodes |
| SEC-03 | footprint used `len`, not capacity; 3000 decoded scalars → 4096 slots; 85 rows charged 8.34 MB for 11.14 MB of slots | records shrunk on insert and charged by real capacity (array slots, string capacity, map nodes, identity strings); no tree clone; `MAX_RECORD_RESIDENT_BYTES` derived from the node bound for validation probes; Q's resident bound stated as 32 MiB of real footprint | `resident_charge_covers_the_real_allocation_of_decoded_payloads`, red with length-based charging |
| SEC-04 | a global max deleted sequence proves nothing about this anchor; generation seals cannot see holes; `evict_expired_origins` ignored active grants | retention writes a tombstone (seq, hash) per deleted row, newest 262,144 kept; anchor and retained parent accept only an exact tombstone; eviction deferred while a grant of this boot is active | `unrelated_legitimate_deletions_do_not_excuse_a_removed_anchor` and `a_kept_parent_below_the_sealed_generation_that_vanishes_is_not_an_expiry`, both red against the seal check; `expired_parents_are_deferred_while_a_grant_of_this_boot_is_active` |
| SEC-05 | passes | unchanged | reviewer's own run |
| SEC-06 | foreign-boot grants kept their bodies and the resident slot forever | compacted on the tick regardless of expiry; seals carry a wall-clock stamp used only for pruning after 30 days | reviewer's bootA/bootB probe as a test, red at `compacted 0` |
| SEC-07 | main quota is not a main+WAL+logs bound | **not changed**; residual | — |
| SEC-08 | collector still allocates before the budget check; transport still buffers a body stage | **not changed**; two residuals, listed separately | — |
| SEC-09 | blocking stdin write before the deadline; TLS handshake in the accept path | deadline before spawn, stdin pumped from the selector loop, process-group kill; handshake in the connection thread under a 5 s bound, admission before it | reviewer's two Python probes as tests: red (watchdog kill / handshake timeout), green |

### What deploying the closure exposed

Deploying the fixed broker refused its persisted cursor with `M projection
anchor missing`, correctly: the anchor row had been deleted before tombstones
existed, so no proof could exist. Reading the ledger to confirm showed
something worse: Q's cursor stood at 36,270 while M was at 184,694, with zero
retained parents, and not one line in the journal. Q had imported twelve
pages after its 05:58 restart and then retried the same page every fifteen
seconds for an hour and forty minutes. Cause: the retained-parent bound
(4096 parents, 8 MiB of bodies) fills before the resident byte bound, is
classed recoverable, and nothing ever released it; import errors were
discarded (`let _ =`); and the doctor's `query_broker` gate read the ledger's
mtime, which the compaction tick refreshes whether or not imports progress.
Three fixes: the parent bound now drives eviction of the oldest derived rows
under the same grant pin as the byte bound (test red at `M parent retention
full`); every distinct import failure is printed when it starts, once a
minute while it lasts, and when it clears; and the broker imports up to
sixteen pages or three seconds per tick while behind. The doctor's
`query_broker` gate reads Q's own projection health over its control socket
(`caught_up`, `lagging` within 1024 rows, else fail), and the mtime check is
demoted to `query_ledger_activity`, documented as liveness only.

Q's ledger was then reset (archived, re-projected from M's current boundary),
which is the operator action the fail-closed anchor rule requires.

Live after the closure: Q re-projected from M's boundary and caught up (lag 61 rows at 08:14 UTC after a 140,000-row catch-up in eight minutes, 543 retained parents, 115 MiB resident, 0 import errors since 08:06:28); doctor `pass 16 fail 0 not_run 3 (physical_separation, soak_72h, cert_rotation) at 08:14 UTC`; branch head `88e3783e9`.

### Residuals after the re-review

| Residual | Bound today | Why it waits |
| --- | --- | --- |
| SEC-07: no unified main+WAL+logs budget for M or Q; a long reader can hold WAL frames past the checkpoint | page quota on each main file, `wal_autocheckpoint`, M's pre-write WAL length gate, passive checkpoint per retention pass | needs a declared per-process total and a reader-age bound; config and design, not a local fix |
| SEC-08 collector: `collect_with_budget` defaults to collect-then-measure | bounded collectors, static tables, no per-request allocation growth beyond one sample | requires a pre-sized output path through every collector |
| SEC-08 transport: the HTTP inbound connection still enters its payload stage before the handler's 413 is seen | per-connection body window, bounded connection count | lives in the shared HTTP layer, not the exporter |
| Retention seals kept for life; tombstones bounded by count, not by Q's actual horizon | seals a few hundred bytes each; tombstones ≤ 262,144 rows | pruning a seal reopens the replay window it closed |
| Process-group kill covers descendants only while they stay in the child's session | the bridge's app-server stays in it | a helper calling `setsid` escapes; not reproduced |
| Validator memory before the first persistent state | 16 GiB / 8 GiB ceilings; `state_gc_lag` reports it | node behaviour; first persistent state has now landed, restarts take seconds instead of a genesis replay |

## 8. Second independent re-review (memo `SAFETY-PERF-REVIEW2-20261001.md`, frozen at `3d81171f5`) and its closure

The reviewer re-ran 129 targeted controls, passed SEC-01/03/04/05/06, and
named what was still open. Everything below is landed on the branch with a
test that was red first, and the engine carrying the C++ parts is on all
seven nodes (`…-2f99220c9f152551`).

| Item | Reviewer's remaining finding | What changed | Evidence |
| --- | --- | --- | --- |
| SEC-02 | `check_timers` walked each waiter vector and the health sample walked it again; a stale disk sample could ride under a fresh observation clock | the timer sweep's own pass counts survivors and keeps their earliest creation time (no second traversal); a disk sample older than 30 s makes the storage position unknown | `a6ebd21aa`; nine health binaries, 18/18 action modes |
| SEC-09 | with a 4 KiB pipe the blocking stdin write still overran the deadline | stdin pipe is non-blocking; a would-block keeps the rest pending for the next writable wake-up inside the deadline | small-pipe test: red in blocking mode (10 s), green in 0.4 s; full delivery through the same pipe checked by hash |
| SEC-07 | no declared total; Q had no WAL gate; long readers pin WAL frames | capacity table (README "Disk budget"); Q refuses growing writes with `disk_backpressure` when frames it cannot checkpoint exceed a 64 MiB mark, one passive checkpoint first, nothing deleted; both ledgers set `journal_size_limit` so the WAL truncates once readers let go; M state and Q projection health report main/WAL bytes and refusals | `c13d91e09`; long-reader test red without the gate (5,000 writes accepted), green refusing at 465 KB vs a 256 KB test mark with cursor/evidence/grants unchanged and recovery after the reader commits |
| SEC-08 A | the exporter's 413 did not stop the transport from reading the body | `HttpServer::Limits::reject_request_bodies`: 413 and close at header time when a non-zero Content-Length or a Transfer-Encoding is announced, before any payload reader exists; `Content-Length: 0` is not a body; the health listener turns it on | `a6ebd21aa`; HTTP contract test announces 100 KB it never sends and requires 413 + close; with the policy off it saw a 200 |
| SEC-08 B | collectors built first and were measured after; an unbudgeted child ran unbounded | every child declares a reservation derived from an existing constant; the multi-collector checks it against the remaining budget before `collect`, refuses as an explicit shed, publishes shed reasons and `tos_exporter_health_collection_complete`; quic/overlay/JSON-RPC/HTTP/exporter children declare theirs | `b2ea10991`; `test-health-collector-budget` red against construct-then-refuse and again when a production stand-in stops declaring; live: every node reports `tos_exporter_health_collection_complete 1`, no shed family, quic families present |

### The workflow that had never passed

The `Node health monitor` workflow had failed on every run since
2026-09-30 13:03. Regenerating the contracts dropped the hand-frozen
native definitions (the generator now carries them from a frozen sidecar
and the two envelope contracts are regenerated byte-identically in JSON,
canonical key order); the exporter answered 413 before 405; one native
mutant could never be observed because the collector actor's own in-flight
guard masked it (removed, with the unit test that covers the lease named);
and the Rust-side mutation scripts the workflow never reached had anchors
matching nothing or several typed-record versions (re-anchored, every case
compiling and killed). `d5064d11f`, `e07befe32`.

### Still residual after the second review

| Residual | Bound today | Why it waits |
| --- | --- | --- |
| Filesystem or project quota as the hard disk boundary | software water marks and page quotas only | provisioning, outside this software |
| M's size-based `wal_budget` has no long-reader test | gate exists, `journal_size_limit` set, refusals counted | needs ≥ 4 MiB of FULL-sync commits per run |
| quic per-path mode declares no reservation | `build_per_path` is a compile-time `false` | by design it sheds if enabled |
| Process-group kill covers descendants only while they stay in the child's session | the bridge's app-server stays in it | unchanged |
