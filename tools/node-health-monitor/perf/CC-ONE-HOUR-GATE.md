# One-hour development gate (owner-shortened from the R4 72-hour soak)

Frozen before the runs on 2026-09-30. Scope: the rebuilt local development
network (zerostate `3bd997b3…6c50e`), six nodes on
`validator-engine-nhm-cc-2821eae2401fc82f`, monitoring at branch head
`bd05e0ee3`. This is a development gate; it is not the R4 production
performance or 72-hour result.

## Populations and instruments

| What | Instrument | Window |
| --- | --- | --- |
| Verdict continuity | `nhm-local-judge.timer`, one record per minute, journal `verdicts.jsonl` | 60 min |
| Resource accounting | `soak-sampler`: `CPUUsageNSec`, `MemoryCurrent`, `NRestarts` of the six node units, the six edge units, M and Q every 30 s | 60 min |
| Chain progress | observer6 `/readyz` sync lag every 30 s | 60 min |
| Fault/restore matrix | token rotation on one edge; control-DB backup/restore with an active incident; manager rollback (not_run: no previous build retained) | inside the hour |
| Profile A vs C on one validator | node cgroup CPU seconds over fixed 10-minute windows after a 2-minute warm-up, two alternating rounds: C (health flags on), A (flags off), C, A | 48 min |

Profile A is the engine started without `--health-*` flags; profile C is the
current full fixed collection (core metrics + native v3 + edge/M/O lanes).
Only validator4 is toggled; its edge is stopped before each node restart and
recreated after, so no two edges sample one epoch. The comparison population
is `CPUUsageNSec` of the node's systemd cgroup; resolution is the kernel's
cgroup CPU accounting (µs). Two rounds cannot establish the R4 1 % bound —
with fewer than three rounds or a between-round spread larger than the A/C
difference the result is **inconclusive** and is reported as such, not as a
pass.

## Pass/fail statement

- Verdict continuity: no minute without a verdict record; nodes not under a
  drill stay `healthy`; drilled nodes move through the expected states and
  return to `healthy`.
- Resource accounting: no node restarts outside the drills; monitoring RSS
  and CPU reported as absolute numbers, not judged.
- Fault matrix: each drill records its observed state transitions; a drill
  that could not run is `not_run`.
- A vs C: reported as the mean CPU-second difference per 10-minute window
  with both rounds shown; conclusive only if the difference exceeds the
  between-round spread.

## Conclusive rounds, re-frozen 2026-09-30 14:34 UTC (edge toggle)

The three alternating 30-minute rounds the R4 bound asks for cannot be run by
restarting validator4 any more: the local network has produced no key block
since genesis, so there is no persistent state and every restart replays the
whole chain (hours, growing daily). Restarting a validator six times would
also leave the chain on three validators for most of a day.

The rounds therefore toggle the *serving* side without a restart:
profile C = the health edge attached and sampling every 15 s (node serves
`/metrics` and `/health-snapshot`, M/O lanes live); profile A = the edge
stopped, nothing scrapes the node. The in-process accumulators (a few relaxed
atomics per block, per PQ operation and per storage commit) stay armed in
both profiles; the only restart-based flags-off measurement is the two-round
result above (inconclusive). Window: 30 minutes after a 2-minute settle,
three rounds C/A/C/A/C/A, population `CPUUsageNSec` of the node cgroup, and a
window counts only if validator4 stayed within 5 blocks of observer6's head
on a live chain for all 30 minutes (`at_head_throughout`). Conclusive only if
the mean difference exceeds the between-round spread; reported as measured.
While the edge is stopped the monitor correctly reports validator4 as
unobservable; that is a drill, not a fault.

### Result (2026-09-30, validator4, engine `…-db5cdeaa53103994`, chain ~2.4 blocks/s)

| Round | C: edge attached | A: edge detached | C − A |
| --- | --- | --- | --- |
| 1 | 1310.6 s | 1227.3 s | +83.2 s |
| 2 | 1313.0 s | 1312.1 s | +1.0 s |
| 3 | 1316.0 s | 1341.8 s | −25.8 s |

Mean C 1313.2 s vs A 1293.7 s per 30-minute window: **+19.5 s (+1.5 %)**,
per-round differences +83.2 / +1.0 / −25.8 s, spread 109 s. Every window was
verified against the one-minute soak samples: validator4 within 5 blocks of
the highest seqno any node reported at every sample, 4220–4388 blocks per
window. By the frozen rule the result is **inconclusive**: the run-to-run
noise of a validating node (about ±4 % between windows of the same profile)
is several times any edge-serving cost, and one round even ran cheaper with
the edge attached. What the three rounds do establish is a ceiling: the
serving cost is not distinguishable from zero at 30-minute resolution, and
the +1.5 % mean is dominated by the first round's outlier. The R4 1 % bound
cannot be proven on this host with this method; a longer series or a
lower-noise host would be needed, and the restart-based flags-off comparison
stays at its two inconclusive rounds. Validator4's memory grew from 6.5 to
10.6 GiB across the rounds regardless of profile (see the evidence note on
the missing key block). Raw records: `ac-rounds-edge-20260930T*.jsonl` in
the private judge state directory; the 10-hour soak record carries the
per-minute seqno and memory series.
