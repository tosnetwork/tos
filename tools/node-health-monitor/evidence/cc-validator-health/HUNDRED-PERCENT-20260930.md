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

## 10. Performance rounds and soak

Design re-frozen in `perf/CC-ONE-HOUR-GATE.md` ("Conclusive rounds,
re-frozen"): three alternating 30-minute rounds on validator4 toggling the
health edge (C attached / A detached) without a restart, because a restart
now costs hours (§8) and would leave the chain on three validators for a
day. Soak: `soak-long` sampler, 10 hours from 14:33 UTC, one record per
minute with node/edge/M/Q accounting, the verdict, observer lag and M's
retention counters, so the record shows the first deleting pass.

Results are appended below when the runs complete.

## 11. Final state

(appended when the rollout, rounds and soak complete)
