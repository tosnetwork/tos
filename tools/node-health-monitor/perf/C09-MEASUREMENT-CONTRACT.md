# C09 raw monotonic duration capture: review contract

Source base: `origin/node-health-monitor@8f2797a90e53a69c06effc71150b1641a4b4d4c1`.
Authority: [R4 design §16.1](/home/tomi/memo/node-health-monitor/TOS-NODE-HEALTH-MONITOR-DESIGN-20260929.md) and [C06–C09 execution order](/home/tomi/memo/node-health-monitor/C06-C09-EXECUTION-ORDER-20260929.md). This is measurement preparation, not C09 acceptance.

## Source boundary and measured population

`validator/measurement/measurement-contract.cpp::sample_clocks` writes individual `std::chrono::steady_clock` and wall-clock trace points; the sink does not attach a process/clock-domain identity or give paired start and finish for every internal stage. `validator/consensus/block-producer.cpp::generate_candidates` records generated candidates after production. `validator/consensus/simplex/pool.cpp::cast_our_vote` awaits vote-intent persistence, signing, and signed-vote persistence as separate operations. We cannot subtract their unrelated trace points to manufacture stage durations. `tools/node-health-monitor/config/acceptance-evidence.json` still has `performance_profile_passed=false`; `config/resource-profile.json` is a budget, not measured CPU/RSS/IO/network evidence.

The capture code will measure only an **external HTTP GET time to first response byte**, from immediately before `open` to immediately after reading one byte or receiving an error/timeout, in the same observer process. It may target only an explicitly configured numeric loopback address and fixed cache-only GET path; no target is called by tests except an owned fixture. It will disable proxies and redirects. This population is named `external_http_first_byte`, never a validator consensus stage or complete request/response latency. Every attempted request has a sequence and outcome (`ok`, `http_error`, `error`, `timeout`); the primary population includes all attempts, including failures. A success-only secondary analysis, if later approved, must retain the original failure count and denominator.

Start and finish are raw `CLOCK_MONOTONIC_RAW` nanoseconds captured in one process. Every sample carries exact decimal-string start, finish, duration, process epoch, and clock-domain ID. The domain binds clock name, Linux boot ID, and time namespace; the epoch additionally binds PID and `/proc/self/stat` start ticks. The verifier refuses a changed domain/epoch, reversed pair, unbounded duration, noncanonical integer, duplicate/out-of-order sequence, missing sample, or changed population. UTC is display metadata only. No cross-process subtraction or receipt-time substitution is allowed. Native internal stages stay `not_run` until both endpoints are emitted by a bounded same-process hook with a verifiable domain and population.

## Frozen run, completeness, and limits

Before a real run, freeze A–F profile toggles, source/binary/config/dependency/genesis/workload hashes, effective quotas, roles, node/scope population, warmup, window, schedule, outcome policy, and instrument-cost/noise method. A is approved baseline; B adds core; C adds fixed collection; D adds optional diagnostics; E adds maximum approved external AI queries to C/D; F is development colocated AI only. A real comparison needs three alternating rounds of at least 30 minutes per normal, high, and maximum approved workload. Preserve completed work, deadlines, oldest queues, typed progress, longest actor occupancy, and V/Edge/M/O/A CPU/RSS/IO/network as separate evidence. Missing fields are `not_run`, never zero.

A capture is bounded by 65,536 attempted records, 16 MiB raw output, 512 bytes per row, 30 seconds per request, and a 3,600-second capture deadline. A new private output file is created exclusively; raw rows are not replaced or summarized away. Header/trailer or manifest records the requested/attempted/retained/dropped counts, source plan hash, clock resolution and identity, and raw SHA-256. A missing completion marker, capacity drop, invalid record, or stopped-early run is incomplete, not a smaller successful population. Synthetic fixture tests establish rejection and resource bounds only. They do not claim a 3% p99 result, 1% CPU result, production gate, or 72-hour soak. No histogram interpolation is used.

## Exact file list submitted for review

1. `tools/node-health-monitor/perf/C09-MEASUREMENT-CONTRACT.md` — this source-backed contract and scope.
2. `tools/node-health-monitor/perf/c09_profiles.py` — strict A–F plan freeze and explicit `not_run` run evidence.
3. `tools/node-health-monitor/perf/raw_monotonic.py` — bounded same-process samples, exclusive output and verifier, numeric-loopback first-byte probe.
4. `tools/node-health-monitor/tests/test_c09_raw_monotonic.py` — targeted real fixture, malformed-domain/counter/capacity/refusal controls, and intended-failure mutations in isolated copies.

Raw runtime data goes to an operator-selected private directory outside this repository. No deployed node, C09 runtime tree, C07/C08 file, business path, or service unit is modified by these four files.
