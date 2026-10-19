# Closing the must-be-100 % items (2026-09-30, afternoon and evening)

Owner order (first-principles list, approved as given): external witness →
evidence retention → AI availability fact + notification receiver → RocksDB
write-stop gauge → production doctor → conclusive performance rounds and a
soak that crosses a retention pass. Decisions on problems were to be made by
first principles without asking. Everything below is on `node-health-monitor`
(branch head recorded at the end); the live network is the rebuilt local
development network.

## 1. External witness — `observer_disagreement` (commit `03505d216`)

`health-witness-compare` reads M's archived `native-core-v3` chain anchors
(read-only, its own SQLite connection) every 15 s and compares each node
against the observers: a fork is the same masterchain seqno with a different
root hash in any sample pair; isolation is lagging every fresh observer head
by more than 150 blocks; being ahead of the observers is not a fault. The
fact is posted under its own source `witness`, bound to the node's native
epoch. No fresh anchor from the node and at least one observer → no fact →
the rule stays **unknown**, never good. Four unit tests (agreement, fork, lag
vs ahead, stale/missing witnesses).

Live: `good` on all six nodes on a live chain. During the afternoon's chain
halt (below) it went unknown for the halted nodes and `suspended_unknown`
for the two replaying validators that had been under a witness incident —
which exposed the defect fixed in §7.

## 2. Evidence retention (sub-agent, branch `cc/retention`, merged `7d2d58229`)

Bounded age retention in M with replay seals; 10 + 3 + 2 tests on real
SQLite; three compiled mutations red. Full record:
`RETENTION-AND-DOCTOR.md`. Deployed at 14:20 UTC with
`evidence_retention_ms = 21600000` (6 h) and `witness_retention_ms = 604800000`
(7 d); the 6 h window was chosen so that today's soak crosses a pass that
really deletes rows (the store began at ~11:00 UTC, so the first deleting
pass lands at ~17:00 UTC). The state endpoint reported the first pass within
a minute (`passes 1`, `deleted 0`, `oldest_retained_age 3.4 h`).

## 3. AI availability fact and notification receiver (commit `03505d216`)

- The judgement posts an `ai_optional` frame for the `monitor` target after
  every model attempt (1 = validated explanation produced, 0 = anything
  else), epoch and generation persisted privately. The local Codex was "at
  capacity" for most of the afternoon, so `ai_unavailable` was **bad/open**
  on `monitor` — the correct reading of a silent AI lane, and the reason the
  doctor's `ai_lane` gate fails honestly below.
- `scripts/local-notification-receiver.py` is an independent HTTPS receiver
  (bearer token, payload hash echoed as the receipt M verifies, private
  journal). M delivers to it; the doctor's `notification_receiver` gate saw a
  live receipt 28 s old.

## 4. RocksDB write-stop gauge (commit `03505d216`, engine `…-3fd4164d7687edf3`)

`tddb/td/db/RocksDb.cpp` records `rocksdb.is-write-stopped` after every
synchronous commit into `td::storage_health` (`tdutils/td/utils/StorageHealth.h`,
relaxed atomics); the exporter publishes `tos_health_storage_write_stopped`,
`_total` and `commits_observed_total`; `health-native-poll` adds the fact to
the `native_gauges` frame (strict 0/1 parse, absent otherwise, frame marked
incomplete). Inventory revision `development-native-facts-6` binds the rule
(Positive, two bad samples, 60 s hold). Live: `good` on validators 1–3
(new engine), unknown on the nodes still rolling.

## 5. Production doctor (sub-agent, `fecdc67ca`)

`scripts/doctor.py`, 17 gates, 16 tests. First run against the live state at
14:35 UTC, read-only, with the example receipts file:

```
manager_state           pass
rule_inputs_usable      fail   (unknown inputs while three nodes replay and three await the gauge engine)
no_quarantined_sources  pass
evidence_retention      pass   (window 6 h, last pass 43 s ago)
notification_receiver   pass   (live receipt 28 s ago)
ai_lane                 fail   (ai_unavailable active on monitor)
physical_separation     not_run
performance_round_a..f  not_run
soak_72h                not_run
token/cert rotation, rollback_drill  not_run
pass 4  fail 2  not_run 11  -> FAIL
```

That is the truthful state of a development host at that minute. The final
run is recorded in §11.

## 6. The chain halt the rollout caused (13:50–~15:00 UTC), recorded honestly

The gauge-engine rollout script restarted validator1, waited for its
`/readyz` to say ready, and moved to validator2. "Ready" was not "at the
head": on this network **a restarted node replays the chain from genesis**
(no persistent state, see §8), so validator1 was still replaying when
validator2 went down, leaving two of four validators → the chain halted at
seqno 26201 (13:50:40 UTC). I stopped the script after validator3 had also
been restarted. The three validators replayed at ~6.3 blocks/s and the chain
resumed when two of them reached the head. The monitor's reading during the
halt: `local_chain_stalled` bad on validator4 (correct), applied/served gap
bad on the replaying validator1 (correct), the two replaying validators
unhealthy, observers degraded. The rollout script was rewritten
(`rollout-engine-v2`): restart only while the chain is live and every
validator is at the head; proceed only after the restarted node is back at
the head; the reference observer is never the one being restarted.

## 7. Defect found by the halt: the anchor vanished exactly when it mattered (commit `45a366bb7`)

The v3 publisher dropped its chain anchor 30 s after the last applied
block. A halted chain therefore lost `applied_served_gap`,
`observer_disagreement` (the one rule that guards against a self-reported
lie) and raised `telemetry_unavailable` on every node — reading like a
monitoring failure instead of a consensus halt. Fix: the validator manager
re-observes the anchor every second; the first observation of an already
applied block starts the stall clock at the block's own time; the publisher
keeps the anchor while it is being refreshed and drops it only when nobody
refreshed it for 30 s or its clocks are malformed. The stall age is derived
from the two clocks by the consumers (`chain_progress_age_ms`), which is
where a halt belongs. Three new assertions in `test-health-native-snapshot`
(halted anchor kept with the old clock; unrefreshed anchor dropped;
applied-advance clock ahead of observation refused). Engine
`validator-engine-nhm-cc-db5cdeaa53103994` carries this plus the gauge.

## 8. Finding for the owner: this network cannot restart cheaply

`AsyncStateSerializer::need_serialize` saves a persistent state only for a
**key block** whose time crosses a 2^17 s boundary. The local network's
last key block is the zero state (`getconfig` reports its key block as
seqno 0), its validator set is fixed until 1793357624 (30 days) and nothing
changes the config, so no key block and no persistent state will ever be
produced. Every restart replays from genesis: ~1.9 h at today's 26 k
blocks, ~17 h by tomorrow at ~2.5 blocks/s produced. The earlier note that
the first boundary would fall at ~2026-10-01 00:02 UTC was wrong (a boundary
without a key block saves nothing). One config change or a validator-set
rotation would create the key block. This is a node/network property, not a
monitor defect, but it changes what an operator can do with the network.

### 8b. Same root, second symptom: validators grow ~1.4 GiB/h

The soak samplers show every validator's cgroup memory growing linearly since
genesis (1.85 GiB at 11:34, 3.25 at 12:34, 7.7 at 16:30 UTC; observers stay
near 1 GiB). Validator garbage collection advances with persistent states,
and there is none, so nothing is ever released. At 16 GiB the four validators
would have been killed together around 22:00 UTC and replayed for hours. At
16:35 UTC I raised the ceiling to 22 GiB at runtime for the four validator
units (`systemctl set-property --runtime`, host has 125 GiB; the installed
unit files stay at 16 GiB), which buys until roughly 01:30 UTC. The monitor's
`memory_growth_unexplained` rule is bound at 4 GiB per 15 minutes and does
not see a 0.35 GiB/15 min trend; the trend is visible in the soak record and
in the process samples Q serves. The durable fix is the key block (§8); the
threshold is an owner decision.

## 9. Derived epochs bound to the deriving run (commit `baf4dfba8`)

Redeploying the pollers and the witness comparer quarantined `native_facts`
and `process_facts` on five nodes: a restarted poller re-derives the same
archived generation with fresh in-memory state (growth window, observation
gap), and the restarted comparer counted generations from zero again; both
collided with their own earlier frames. Derived source epochs now carry the
run's identity (`…:facts-v2:<start-ms>-<pid>`), so a restart is a new epoch.
The seven stale rows were cleared by operator action with a receipt
(`runtime/quarantine-clear-2026-09-30T142551Z.json`); after the deploy: 0
refusals in 150 s, `quarantined_sources []`.

## 10a. Third defect: a replay left two validators at "storage unusable" for good (commit `83a2d8f3d`)

After validator1 and validator4 had caught up, both sat at critical
`storage_ack_failure`. Cause: the publisher's bounded work-observation
ledger (512 rows) overflows during a replay, latches the storage
commit-ack capability to `observation_incomplete` for the rest of the
process, and the `storage_usable` fact read that latch as "no
acknowledgement ever" (0). The fact now follows the node's own counters
within its epoch: new vote storage requests with no new commit acknowledgement
since the previous sample → unusable; acknowledged commits → usable; idle →
usable; proven capability → usable. Deployed to the six pollers at 15:33 UTC:
`storage_ack_failure` good on all six within one hold. The publisher still
reports its coverage gap; that is what `diagnostic_coverage_reduced` is for.

## 10b. Fourth defect: the AI fact expired between model turns (commit below)

The doctor's `ai_lane` and `rule_inputs_usable` gates failed at 18:44 UTC
with `ai_unavailable` **unknown** although the model lane had been producing
accepted explanations every ten minutes since 17:46. The catalog bounds a
source ttl at 180 s (an attempt to set 900 s made M refuse the inventory,
`invalid source catalog`; the previous revision was restored within a
minute), while the fact was posted only by the ten-minute model turn, so it
was fresh for three minutes in ten. The minute judgement now posts the fact
from the model journal (accepted and younger than 15 min → 1), the model run
no longer posts it (one writer, no generation race), and the unit files are
updated. `ai_unavailable` read good on the next minute.

## 10. Performance rounds and soak

Design re-frozen in `perf/CC-ONE-HOUR-GATE.md` ("Conclusive rounds,
re-frozen"): three alternating 30-minute rounds on validator4 toggling the
health edge (C attached / A detached) without a restart, because a restart
now costs hours (§8) and would leave the chain on three validators for a
day. Soak: `soak-long` sampler, 10 hours from 14:33 UTC, one record per
minute with node/edge/M/Q accounting, the verdict, observer lag and M's
retention counters, so the record shows the first deleting pass.

Results:

- **A/C rounds** (15:28–18:40 UTC, six 30-minute windows, all verified at the
  head): C 1310.6 / 1313.0 / 1316.0 s, A 1227.3 / 1312.1 / 1341.8 s; mean
  difference +19.5 s (+1.5 %) with a 109 s spread → inconclusive by the frozen
  rule; the edge-serving cost is below the ~±4 % window-to-window noise of a
  validating node. Full table and reading in `perf/CC-ONE-HOUR-GATE.md`.
- **Retention crossed live**: the first deleting pass ran at ~17:05 UTC; by
  18:42 M reported 51 passes, 9,822 observation rows deleted, oldest retained
  row 6.06 h, 0 failed passes, 0 quarantined sources, evidence DB 179 MiB.
  Q kept serving throughout (retained parents inside the 2 h floor).
- **Soak**: running to 00:33 UTC; final numbers in §11.

## 11. Owner decision: rotating rebuild and a key block fact (evening)

Asked whether the missing key block was an operational or a design problem,
the answer was both: upstream TON has the identical code (persistent state
only at a key block, GC only up to the last key block, key blocks only on a
configuration change) and relies on elections to keep changing the
configuration; its zero state gives the bootstrap set 3000 s. Our local
generator gives it 30 days unless `--rotate` is passed, and this morning's
rebuild was not rotating, so nothing ever changed. Design gap worth keeping:
a chain whose configuration legitimately never changes never checkpoints.

Owner chose plan 1 (rebuild with `--rotate`) plus a `key_block_age` fact.

- **Engine** (`7178a25d7`): the chain anchor carries the last known key
  block (seqno, time); `test-health-native-snapshot` covers present, null and
  malformed clocks. Engine `validator-engine-nhm-cc-77a7010af929ce40`.
- **Monitor**: `KeyBlockAgeMs` fact, source `native_key_block`, rule
  `key_block_stale` (Above; 19-rule catalog now), manager pair, poller frame,
  parse compatibility with publishers that lack the field (the exact-bytes
  hash holds for a missing and for a null anchor; tests in
  `native_v3_chain.rs`).
- **Network**: old network stopped at 22:00 UTC (soak record closed at 7.7 h,
  445 samples, retention had deleted 36,506 rows); `setup-testnet.sh --clean
  --rotate` finished at 22:05 with validators 1,2,3,4,7, two observers and
  `tos-pq-elections`; monitoring rebound to network
  `99599bf0ef8f…` with validator7 added to every lane and inventory
  revision `development-native-facts-7`.
- **Two deploy-half misses, both caught live and fixed within minutes**: the
  edges were still the previous build and refused every snapshot (503) until
  rebuilt and recreated (`health-edge-cc-f63aed6541cfd6b7`); the judge units
  carried the old network id in their command line (rebind rewrites JSON
  configs only) so the AI fact was refused until the units were rewritten.
  Both are now in the deploy README.
- **Result**: the first election ran on schedule; **key block 1434 at
  22:15:44 UTC**, seen by all seven nodes within a poll; `key_block_stale`
  good ×7, verdict healthy ×7 at 22:17:06, doctor 13 pass / 1 transient
  fail / 3 not_run at 22:17. The elections service had exited once (HTTP 500
  while the rebind restarted its node); restarted, `Restart=no` noted.
- **Soak**: owner capped development soaks at 2 hours; a 2-hour soak on the
  rotating network started 22:17 UTC. Final numbers below.

## 12. Owner request: duties, queues and storage as native observations (commit `bb721096d`)

The model explanation kept saying `local_duties`, `queue_state` and
`storage_state` could not be assessed, which was true. The engine now
publishes a `node_state` section once per second and the coverage reads
`complete`:

- **Duties**: membership (any validator group running) and the leader
  windows the collator schedule assigned to this node (`is_expected_collator`
  is the protocol's own assignment, so it is an honest denominator), with
  the two protocol reasons an assigned window ends before production
  (superseded, finality behind). `duty_windows_missed` = assigned − started
  − superseded − suppressed; rule `duty_missed` (Increase), validators only.
- **Queues**: the manager's three real waiter queues, counted in the sweep
  that already checks their timers, each waiter now stamped at creation.
  `queue_oldest_ms` drives `queue_stall` (Above 5 min); the PQ signer still
  has no queue and none was invented (R4-04).
- **Storage**: `statvfs` of the database root and the GC / persistent-state
  seqnos. `disk_used_permille` → `storage_space_low` (Above 900 ‰);
  `state_gc_lag_blocks` = applied − gc → `state_gc_lag` (Above 50,000).

Contract: schemas name `key_block` and `node_state` as required members of
the current v3 payload (the checker insists on closed schemas), the Rust
parser still accepts older publishers (outer `None`, exact-bytes hash kept),
22 rules, `check-contracts` PASS, C++ and Rust tests for present, null,
stale, lying-coverage and malformed sections. Engine
`validator-engine-nhm-cc-27a1496dee7a25ca`; deployed after the 2-hour soak
so the soak record stays clean. Live result in §13.

## 13. Two-hour soak on the rotating network (22:17–00:16 UTC) and final doctor

Owner cap: development soaks are at most two hours.

| What | Result |
| --- | --- |
| Verdict continuity | 118 minute records in the window, no gap over 90 s; **all seven nodes healthy in every one of 119 samples**, no degraded, unhealthy or unknown entry |
| Chain | 13 elections, a key block every ten minutes (last 19477), observer6 sync lag ≤ 1 s in every sample, no node restart |
| Model lane | accepted analyses every ten minutes, consistent with the verdict ("All seven nodes are healthy … detailed diagnostic coverage remains incomplete" — the three node-state fields, deployed right after this soak) |
| Monitoring cost (7 nodes) | edges 2.1–2.3 MiB RSS and 1.6–1.7 m-core each; M 98 MiB, 10.7 m-core; Q 82 MiB, 18.7 m-core |
| Node cost | validators 0.63–0.66 core, observers 0.67–0.70 core; validator RSS +2.8 GiB over the window (3.4 GiB at the end), observers +1.0 GiB — the node's own growth without state garbage collection (no persistent state yet; see the audit note §1) |
| M evidence store | 35,488 rows, 92 MB, 27 retention passes, 0 deletions yet (oldest row 2.2 h, window 6 h) |
| Final doctor (00:17 UTC, live state, receipts file) | **14 pass, 0 fail, 3 not_run** (physical separation, 72-hour soak, certificate rotation — none of them run on this host, said so) |

## 14. Final state (2026-10-01 00:32 UTC)

Node-state engine `validator-engine-nhm-cc-326b11c8166d427c` (node state +
the audit fixes of `b4bdc7e2e`) rolled onto all seven nodes between 00:19:53
and 00:21:39 UTC, one node at a time, each back at the head within seconds
(replay from the last key block is cheap now). Two deploy defects were hit
and fixed on the spot:

1. The manager refused inventory revision 8 with `invalid target`: a target
   could bind at most 18 rules, a number frozen when the catalog had 18. M
   was down for about four minutes until the previous revision was
   restored; the bound is now a constant equal to the catalog size, pinned
   by a test against the manifest (`2509f40aa`).
2. The edges recreated by the rollout answered 503 for eight minutes with
   nothing in the journal; the native sampler discarded its error. It now
   names each refusal (`6d0df8ba2`). Root cause, found on the second
   occurrence at 01:40: the rollout script carried the **old network id** as
   a constant and bound every recreated edge to it, so each edge refused its
   node's samples (network mismatch). The script now reads the zero-state root
   from the network's own file and the newest installed edge build; the deploy
   README records the rule.

## 15. Owner delegation: decide by first principles (01:40–02:00 UTC)

- **M3 fixed**: `lifecycle_verified` is earned by observation (first session
  seen through stop → close) and reported in the present tense instead of
  latched; validators now show `incomplete_reasons: ["scope_unapproved"]`
  only (they validate shard 0, whose typed progress is by contract not an
  approved input), observers `["session_lifecycle_unverified"]` truthfully
  (they run no session). The judgement passes the reasons to the model with
  a glossary, so an explanation names the reason instead of calling coverage
  unspecified (`e261f3f87`, `cb2fd7a6e`).
- **M4 accepted**: the teardown change is safer than its predecessor and its
  fault-injection test already exists (`test-health-actions close-error`),
  all 18 modes green.
- **L2 fixed**: observation context index and ledger bank pointer are atomics.
- **Q**: the evidence projection was already bounded (fixed row window); the
  audit's earlier "unbounded" reading was wrong and is corrected.
- **Judge journals** rotate at 64 MiB; a journaled run prints one summary
  line to journald instead of the whole report.
- Ten stale `nhm-c09-functional*` unit files (pointing at deleted worktrees,
  all inactive) removed.
- Engine `validator-engine-nhm-cc-3bcffe6990d82400` rolled onto all seven
  nodes at 01:5x UTC with the corrected script; verdict healthy ×7 at 02:00.

Live after the deploy: coverage `complete` with no missing field on every
node; 20 rules per validator, 16 per observer, **every input good, verdict
healthy ×7**, 0 refusals, 0 quarantined sources. The new facts read, for
validator1: member 1, leader windows assigned 136 = started 136, missed 0;
queue depth 0, oldest wait 0; disk used 445 ‰; state GC lag 21,964 blocks
(GC seqno 0: the node has not collected a single state yet, exactly what the
audit note §1 says; `state_gc_lag` will trip at 50,000 blocks in about three
hours unless the first persistent state after 06:38:56 UTC lets GC start).
The native snapshot's own `instrumentation_complete` stays false because
`lifecycle_verified` has no writer (audit finding M3), so the model
explanation may keep calling diagnostic coverage incomplete even though the
three fields it named are now present.

Branch head `6d0df8ba2`, pushed; memo updated.

## 16. Codex audit mapped and closed out (02:00–06:10 UTC)

- Codex's nine findings (`SAFETY-PERF-AUDIT-20261001.md` in the memo) mapped
  onto the audit note §5; SEC-01/02/03/08/09 were already fixed or fixed in
  `360657385`; SEC-04/05/06/07 landed in `86032a5a4`.
- Deploying them exposed that Q had been crash-looping since 00:19 UTC on a
  build without the `mcp` feature, unseen by every live gate. Fixed the build
  rule, the restore, the swept-anchor case and added the doctor's
  `query_broker` gate (`776e42f13`). Q back at 05:57:58 UTC, caught up.
- The doctor then failed `ai_lane`: since 03:41 UTC every model turn was
  rejected because the diagnosis contract held six findings and seven nodes
  were degraded. Cap now follows the inventory bound, a too-small contract
  is refused before the model runs (`d913d30f6`); the next turn was accepted
  and the incident closed as recovered.
- Final doctor (06:0x UTC): 15 pass, 0 fail, 3 not_run (`physical_separation`,
  `soak_72h`, `cert_rotation`: all honestly not established on one host).
- Live: 7 nodes, key block seqno 71743 at age ≈ 60–80 s, applied age 0 s,
  every rule good except `state_gc_lag` (warning, true: GC seqno 0 until the
  first persistent state after 06:38:56 UTC). Audit note §4 and §6 written.

## 17. Independent re-review closed (07:00–08:14 UTC)

- Codex's re-review (`SAFETY-PERF-REVIEW-20261001.md`) could not close SEC-01/02/03/04/06/07/08/09.
  SEC-01/02/03/04/06/09 fixed with the reviewer's own controls turned into
  red-then-green tests (audit note §7); SEC-07/08 stay residuals, listed
  separately as the reviewer asked.
- Engine `…-80d22e8ac358e541` (disk query off the actor, single waiter traversal)
  rolled onto all seven nodes; restarts now take about six seconds because
  the first persistent state exists.
- Deploying exposed a second silent Q outage: a parent bound that only
  refused, swallowed import errors and a doctor gate reading a file
  timestamp. All three fixed; the gate now reads Q's projection health.
- Final: Q re-projected from M's boundary and caught up (lag 61 rows at 08:14 UTC after a 140,000-row catch-up in eight minutes, 543 retained parents, 115 MiB resident, 0 import errors since 08:06:28); doctor `pass 16 fail 0 not_run 3 (physical_separation, soak_72h, cert_rotation) at 08:14 UTC`. Head `88e3783e9`.

## 18. Second re-review closed; the never-green workflow repaired (08:15–09:20 UTC)

- Codex's second re-review passed SEC-01/03/04/05/06 and left SEC-02 (second
  traversal), SEC-09 (4 KiB pipe), SEC-07 and SEC-08 (directions given).
  All four landed with red-first tests (audit note §8); engine
  `…-2f99220c9f152551` on all seven nodes, `tos_exporter_health_collection_complete 1`
  everywhere.
- The `Node health monitor` workflow had been red on every run for a day:
  generator drift, 413-before-405, an unobservable mutant and rotted
  mutation anchors. All repaired; the CI runs for these commits were in
  progress at the time of writing.
- Operations: the elections service died at the 07:24 rollout (HTTP 500
  during a validator restart, `Restart=no`) and on two restarts was refused
  by the elector (`0xEE6F454C`, reason 0) submitting at the election's close.
  No key block since 07:25; the monitor reports `key_block_stale` open on
  all seven nodes past the one-hour threshold, which is correct.

## 19. Third review closed; workflow green at `8f80101d7` (09:20–11:30 UTC)

- Third review's SEC-07/08 gaps fixed by the reviewer at the owner's
  direction and reviewed here as correct (audit note §9); one stale unit test
  corrected (`f582f4832`). Engine `…-a42c226db949b93f` on all seven nodes;
  M and Q redeployed on the merged build.
- `Node health monitor` workflow: first full green at `8f80101d7`; the
  reviewer's commits re-reddened one unit test, fixed in `f582f4832`.
- Elections: the script now skips a closed election instead of dying and
  the unit is active, but no new election has opened since 07:25
  (`active_election_id` stays on the finished one); key block age past
  three hours, `key_block_stale` open on every node. Chain-side follow-up.
