# C09 bounded catch-up cost and grant availability witness

Source: `dfec289e28fdf6a9194e2edd14798b0286e40a99` plus an opt-in,
read-only test change. No running M, Q, Edge, collector, or business process was
changed. The test reads the local M SQLite file and writes only a disposable
query ledger under a unique temporary directory. The M data continued growing
between runs; results below are point-in-time development measurements, not a
production throughput or 72-hour availability gate.

At 2026-09-30 UTC, available memory was 112 GiB. With the already-built
`CARGO_TARGET_DIR=/home/tomi/nhm-c09-anchor-build`, the exact
`pre_cursor_ledger_with_active_grant_catches_up_over_4096_history` test
finished naturally: 1 passed, exit 0, test duration 8.20 seconds, command
wall time 8.66 seconds (`/usr/bin/time -p`). It creates 4097 historical process
observations, reopens a pre-cursor Q ledger with an active fixed-W grant, and
tests bounded page/capacity behavior. This duration includes fixture setup and
SQLite writes; it does not isolate projection CPU.

The opt-in `live_read_only_projection_cost_witness` then used the current
read-only local M DB and a disposable Q ledger. A first run (before adding
grant assertions) reached M global watermark 16839 in 15 pages: first page
357 ms, tight-loop catch-up test 6.27 seconds, final empty page 240 ms,
command wall time 6.48 seconds. With explicit availability assertions, a second
run reached global M watermark 16920 in 15 pages: first page 351 ms,
new-grant response **503** while uncaught, cumulative catch-up 7323 ms,
then grant **200**, explicit revoke **200**, empty-page 226 ms; test exit 0,
command wall time 9.69 seconds including compilation. A restored rerun after
the sensitivity mutation reached watermark 17081 in 15 pages: first page
349 ms, 503 while uncaught, catch-up 6231 ms, 200 after catch-up and 200 on
revoke, empty page 224 ms; test exit 0.

The changed-property control removed only the grant handler's
`!manager_caught_up` refusal. The opt-in test compiled and exited 101 at the
intended `503` assertion: actual 200 versus expected 503, after a successful
first page. The condition was restored; source SHA-256 for `observability.rs`
is `ee8097797892c1329ae0c4de258d103d52ef87a27c3eb1d16f39871cce847919`.
The strengthened test SHA-256 is
`1712ca52970405f48515651c088c655665dda5be2590ce6110a204f3e950087a`.

This tight-loop witness is not the deployed scheduler. `refresh_manager` imports
one page per 15-second tick, while startup imports only its first page before
opening listeners. For this 15-page snapshot, **without grant attempts or other
imports**, the remaining 14 scheduled ticks imply roughly 210 seconds before
new grants become available; this is a source-derived estimate, not a measured
service restart. A grant attempt imports one page but returns 503 until fully
caught up. Existing fixed-W grants are governed by the separate ledger rules.

The generic `QueryLedger::insert_bound` clones the whole `EvidenceStore` per
call, but the M catch-up path uses `insert_projection_page`, which clones it
**once per 256-row page**, not once per projected row. Every page still
revalidates retained parents, so this 15-page measurement does not prove
larger-backlog or 72-hour latency. No row/byte cap, freshness threshold, or
timeout was increased.
