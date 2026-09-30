# C09 live-profile 72-hour soak admission and sampling draft

Drafted 2026-09-30 UTC from read-only inspection. This plan does not start,
extend or accept a soak. It does not authorize changing business nodes or the
running Manager, collector, Edge or QueryService units. Authority: R4 design
§§16.1, 17 and C06–C09 execution order §C09.

## Frozen candidate and current observation

- Six `nhm-local-collector-*` user services poll every 15 seconds; all were
  active with unchanged PIDs in the inspected 167-row sample. Collector binary
  SHA-256: `e2fb3b99413bd2a128d1f618b76d259588eee04121395f138fb461f84fd4b57b`.
- Private `nhm-local-query.service` runs binary SHA-256
  `e37f9c4353bb80f5ae8acd3a941d7eeb21b5f116a448448adb79588fb94cf8ee`,
  bound by the local deployment receipt to source `31fc2f615ec3325d0e6bfe69f37f692068786bc0`.
  This is a successor to the earlier all-history projection binary. The
  source's incremental page/cursor path must still be verified against the
  deployed digest before admission. The QueryService PID changed during the
  existing sample stream; only samples after the final deployment qualify.
- The existing one-shot sampler writes up to 8 KiB per row at nominal 60-second
  intervals, with a 40,000,000-byte file cap. It reads service state, process
  source age, M evidence DB/WAL sizes and an authenticated private Q projection
  status. Its first Q-aware row was `2026-09-30T00:38:14.298976Z` (one-based
  row 154). Earlier rows cannot count toward Q continuity.
- Read-only inspection at about `2026-09-30T00:51Z`: 167 total rows, no sampler
  error, stale node or inactive unit rows; inter-row spacing 5.2–72.4 seconds,
  with no gap over 120 seconds. Only 14 rows include the Q probe; its lag was
  at most 20 M sequences in that short window. M evidence main DB grew from
  14,987,264 to 72,454,144 bytes across the inspected stream. These are
  observations, not 72-hour evidence or a performance comparison.

## Admission before declaring a new 72-hour window

1. Supervisor signs a frozen local profile: exact source/binary/config,
   genesis, six roles, effective quotas, current Q ledger schema and cursor,
   M evidence schema/retention, sampler and probe hashes, and disabled model
   API. Verify current `/proc/<PID>/exe` hashes and unit PIDs against it.
2. Freeze one Q-aware start row with wall UTC, boot identity, service PIDs,
   Q source identity/anchor and a successful authenticated probe. A restart,
   source conflict, missing sample, lost Q probe, changed binary/config or
   broken anchor is an explicit interruption or inconclusive interval; never
   splice a new epoch onto the old one. Absolute UTC plus boot identity is
   used for the soak calendar; cross-process timestamps are not paired to
   manufacture a raw operation duration.
3. The present `nhm-c09-soak-stop.timer` targets `2026-10-02T21:56:43Z`, while
   72 hours after the first Q-aware row is `2026-10-03T00:38:14Z`. The current
   timer cannot establish a full Q-aware 72 hours. The supervisor must set a
   reviewed end boundary after a newly frozen start; this draft changes no
   timer. A signed-off integrated candidate and local test plan remain required.
4. Admit only if there is room for the finite caps below, source ages are
   within 0–180 seconds, M/Q identities agree, Q conflict is false, units are
   active, and no sample error exists. A Q `lagging` result is recorded with
   its exact sequence lag; persistent or growing lag needs a predeclared
   threshold and cannot be called caught-up. Do not silently reset incidents.

## Finite sampling and resource envelope

| Item | Frequency / cap | Evidence and escalation |
|---|---|---|
| Existing M/Q/unit sample | Nominal 60 seconds; maximum one 8 KiB row; at most 4,320 scheduled rows in 72h, 35,389,440 bytes before jitter/manual rows; absolute writer cap 40,008,192 bytes | Preserve raw JSONL, count expected/actual rows, gaps >120 seconds, errors, nonfresh nodes, Q lag/conflicts, PID/restart changes; hash the sealed file. At the cap, stop collection and mark incomplete, never discard old rows. |
| Six collectors | Existing 15-second cadence; each CPU 50%, memory 256 MiB, tasks 32, no swap | Existing systemd counters plus M source generation/age; no extra on-demand Edge reads. |
| QueryService | Existing 15-second import; CPU 50%, memory 512 MiB, tasks 48, no swap | Q cursor/anchor and projection lag, ledger DB/WAL, grants/revocation and no scheduled upstream reads from MCP. Current CLI/model API remains off. |
| Sampler | CPU 10%, memory 64 MiB, tasks 16, no swap | Check its natural exit and file growth each review; it is a read-only observer. |
| M evidence storage | Proposed 2 GiB ceiling aligned with R4 evidence quota; separate WAL watch at 256 MiB | Current main DB about 69 MiB; observed growth about 19 MiB/hour projects roughly 1.5 GiB at 72h. If three-hour rolling growth exceeds 25 MiB/hour or WAL reaches 256 MiB, pause acceptance and investigate retention/checkpoint; do not delete evidence to keep the gate green. |
| Q ledger and raw file | Proposed 512 MiB ledger ceiling; sampler cap above; reserve at least 4 GiB free for these bounded artifacts | Current Q ledger about 11 MiB and host filesystem about 562 GiB free. Record actual DB, WAL, free bytes and inodes every review. |

The seven live QueryService/collector units plus sampler have aggregate configured
ceilings of 3.6 CPU cores and 2.063 GiB memory. Edge, Manager, observer,
validator and any workload budgets are additional and must be inventoried
before high/max-load admission; these ceilings do not prove actual resource
consumption or physical failure-domain independence.

## Review rhythm and terminal evidence

- Every 15 minutes: check timer/sampler exits, file cap, seven unit states,
  six source ages, Q identity/conflict/lag, DB/WAL/free space and alert state.
  Every hour: append a sealed summary with raw-file offset/hash, sample count,
  gap count, maximum memory/CPU deltas, restart counts and unresolved incidents.
  Every six hours: inspect storage slope, retention/checkpoint behavior and
  query ledger growth. Preserve all raw exits and prior red evidence.
- At the reviewed end boundary: stop only the sampler under the supervisor's
  lifecycle, seal hashes and summarize all expected/actual rows and epochs.
  Short, interrupted or missing Q-aware evidence is `inconclusive` or `fail`
  under the frozen rule; it is never called a 72-hour pass.
- This soak watches long-term memory, queue/retention and rotation. Backup/
  restore, credential/receiver rotation, rollback and independent failure
  exercises require separate controlled evidence. A–F normal/high/maximum
  approved profiles still require three alternating 30-minute rounds with
  common raw monotonic native start/end hooks. The current external RTT tool
  has no such native hooks: internal-stage p99, V CPU <=1%, p99 <=3% and
  production doctor remain `not_run`/`inconclusive`, never a soak inference.
