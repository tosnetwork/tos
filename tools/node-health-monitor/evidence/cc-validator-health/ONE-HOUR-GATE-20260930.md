# One-hour development gate: results (2026-09-30, 11:34–12:34 UTC)

Plan: `perf/CC-ONE-HOUR-GATE.md` (frozen before the runs). Raw journals are
private under `$HOME/.local/state/nhm-cc-judge/` (`soak-1h-20260930T113427Z.jsonl`,
`drills-20260930T113733Z.jsonl`, `ac-rounds-20260930T114507Z.jsonl`,
`verdicts.jsonl`, `model-verdicts.jsonl`); `gate-summary.txt` is the
generated summary quoted below. Owner-shortened from the R4 72-hour soak;
this is a development result, not production acceptance.

## Verdict continuity (58 one-minute records in the hour)

| Node | healthy | degraded | unhealthy | unknown | Explanation |
| --- | --- | --- | --- | --- | --- |
| validator1 | 58 | | | | |
| validator2 | 57 | | | 1 | one transient unknown minute |
| validator3 | 58 | | | | |
| validator4 | 26 | 29 | 1 | 2 | A/C profile rounds: 2×10 min without health flags → telemetry unavailable, as designed |
| observer5 | 58 | | | | |
| observer6 | 54 | 3 | | 1 | drill: edge stopped 2.5 min → degraded, recovered |

No minute without a record. Nodes not under a drill stayed healthy.

## Resources (cgroup accounting over the hour)

| Unit | CPU seconds / h | Peak memory | Restarts |
| --- | --- | --- | --- |
| validator1/2/3 | 2494 / 2475 / 2472 (≈0.69 core each) | 3.25 GiB | 0 |
| validator4 | n/a (restarted 5× by the A/C rounds) | 2.43 GiB | 0 outside the rounds |
| observer5/6 | 2364 / 2364 | 0.98 GiB | 0 |
| six edges | 1.5 – 5.7 each | < 1 MiB RSS | — |
| M (`health-state`) | 5.9 | 23 MiB | 1 (drill restart) |
| Q (`tos-observability`) | 145.3 | 292 MiB | 0 |

Chain: observer6 sync lag ≤ 2 s in all 119 samples; consensus never lost
quorum (validator4 alone was restarted, one at a time).

## Fault / restore / rotation drills

| Drill | Observed |
| --- | --- |
| Edge token rotation (edge-1, three client lanes) | edge active on the new token, 0 refusals, all six healthy |
| Active incident then control-DB backup → restore → manager restart | `telemetry_unavailable` for observer6 opened as episode 2; after restore it was `suspended_unknown` (retained, not cleared); after the edge returned it went `closed_recovered` |
| Manager binary rollback to the previous build | the previous build refused the current inventory (`rule adapter unavailable: local_chain_stalled`) and never became active; rolling forward restored service with the incident history intact. A binary rollback needs its matching inventory revision — fail-closed, no data loss |

## Profile A vs C on validator4 (10-minute CPU windows, 2-minute warm-up)

| Round | C (health on) | A (health off) |
| --- | --- | --- |
| 1 | 423.8 s | 420.7 s |
| 2 | 419.7 s | 412.2 s |

Mean C 421.7 s vs A 416.4 s: **+5.3 s (+1.3 %)**, but the between-round
spread is 8.5 s, larger than the difference. By the frozen rule this is
**inconclusive**: two rounds on a validator that was restarted between windows
cannot separate a ~1 % instrumentation cost from run-to-run noise. The R4
1 % bound needs the three alternating 30-minute rounds it specifies.

## Model explanation (local Codex through the AURA bridge)

Two accepted `analysis` answers during the hour, both consistent with the
deterministic verdict and citing delivered evidence ids only: 11:42 UTC
(observer6 unhealthy during its drill) and 12:05 UTC (validator4 degraded
during an A round, "archived zero failure counters do not establish current
health"). Eight timer runs were `unavailable`: the unit lacked a `PATH` for
the spawned app-server (fixed) and a reused thread grew past the timeout
(fixed by one thread per turn, `9599bd14b`).
