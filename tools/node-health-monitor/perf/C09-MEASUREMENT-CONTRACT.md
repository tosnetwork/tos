# C09 raw monotonic measurement contract (review candidate)

Source baseline: `origin/node-health-monitor@ad97425d6e3d1a2c1b9f8c06939ce3e5b40eb87b`.
Authority: R4 design §16.1 and work order C09, 2026-09-29. This is an
instrument and run-plan contract, not a production performance result.

## Source-backed measurement boundary

- `validator/measurement/measurement-contract.cpp::sample_clocks` samples
  `std::chrono::steady_clock` and wall time. Its JSONL sink writes per-stage
  points, flushes synchronously, and does not encode process identity or a
  clock-domain ID. Points from separate processes cannot be subtracted.
- `validator/consensus/block-producer.cpp::generate_candidates` emits
  `candidate_generated` only after an actual candidate is produced.
- `validator/consensus/simplex/pool.cpp::cast_our_vote` awaits vote intent,
  signing and signed-vote persistence separately. Existing trace points do not
  bracket these operations. No internal-stage duration is inferred from an
  HTTP request or from unrelated trace points.
- `tools/node-health-monitor/config/resource-profile.json` is a component
  resource budget, not a measured CPU/RSS/IO/network ledger. The existing
  `acceptance-evidence.json` has `performance_profile_passed=false`.

The first implementation measures only operations whose start and finish are
sampled by one process using the same explicitly named clock domain. Its
direct HTTP probe durations, if used, are `external_request_rtt`, never
consensus-stage latency. Native internal stages remain `not_run` until a
bounded native hook emits both ends with process and clock identity. A
cross-process pair, clock-domain mismatch, end before start, missing endpoint,
or process-epoch change is rejected. UTC is for display and ordering only.

## Frozen run requirements

Profiles A–F follow R4 exactly: A approved baseline; B core enabled; C B plus
fixed edge/M/O collection; D C plus optional diagnostics; E C or D plus maximum
approved external AI queries; F development colocated AI only. Every profile
records source/binary/config/dependency hashes, role and host inventory,
process epochs, clock ID and resolution, capture population, capacity and
dropped counts, raw evidence hash, effective resource quotas and measured
CPU seconds/RSS/IO/network for V, edge, M, O and A. Unavailable resources are
explicitly `not_run`. No value is silently zero.

Before real rounds, freeze warmup, 30-minute measurement windows, at least
three alternating rounds per normal/high/maximum-approved workload, node and
scope population, instrumentation cost, missing-sample policy, and statistical
method. Also capture completed work, deadline exceedance, oldest queue age,
typed progress and maximum contiguous actor occupancy. CPU <=1% and key p99
<=3% are evaluated only when noise, resolution, samples and coverage support
them; otherwise the gate is `inconclusive`. A 72-hour soak has a separate gate.
Synthetic unit fixtures can reject bad records; they cannot turn these gates
green or stand in for a node run.

## Exact proposed change list

1. `tools/node-health-monitor/perf/C09-MEASUREMENT-CONTRACT.md` — this source
   and run contract.
2. `tools/node-health-monitor/perf/raw_monotonic.py` — bounded raw capture,
   strict identity/domain validation, resource ledger and evidence hashes.
3. `tools/node-health-monitor/perf/c09_profiles.py` — A–F frozen profile and
   run-manifest validation, with missing native stages marked `not_run`.
4. `tools/node-health-monitor/tests/test_c09_raw_monotonic.py` — targeted
   rejection and boundedness tests, including a deliberately red control.

No C07/C08 shared source, business node, service unit, or existing C09 runtime
tree is part of this change list.
