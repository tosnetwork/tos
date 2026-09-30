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

The original pre-batch implementation cloned the `EvidenceStore` per projected
row. That is **historical**, not an explanation of this rebased run: current
`insert_projection_page` stages one store clone and one SQLite transaction per
bounded page. The 15-page historical measurement and the newer 37-page run
are point-in-time observations on different source/data states; neither proves
larger-backlog or 72-hour latency. No production row/byte cap, freshness
threshold, or timeout was increased.

## Isolated rebase on `31fc2f615` (2026-09-30 UTC)

The historical measurements above are not results from this rebased source.
The first opt-in run against the now-larger live M file compiled but exited
101 at the test's old 32-page measurement ceiling. It had already witnessed
the expected pre-catch-up grant 503 and continued importing bounded 256-row
pages; the red was the test's `manager_caught_up` assertion at page 32, not a
source-conflict or production Q refusal. This failed run remains lineage.

Only the **opt-in test ceiling** changed from 32 to 128 pages, with an explicit
ceiling failure message. Production page, resident, timeout and grant limits
are unchanged. The restored opt-in run read M only, used a disposable Q ledger,
and exited 0: 37 pages to global M sequence 35423, `caught_up_ms=20003`,
grant 503 before catch-up, grant 200 after catch-up, explicit revoke 200,
and an empty steady page in 241 ms. These are development observations, not
a scheduled-service or 72-hour availability pass.

On this rebased test source, a compiled mutation of only the
`!manager_caught_up` grant guard exited 101 at the intended assertion:
the initial refused grant became HTTP 200 instead of 503 after a real first
page. The guard was restored byte-for-byte before handoff; this red is not a
compiler or fixture failure.
After restoring the guard, the exact-source opt-in rerun exited 0 at global M
sequence 35632 in 37 pages: 503 before catch-up, `caught_up_ms=18077`, grant
200 after catch-up, revoke 200, and an empty steady page in 225 ms. Restored
`observability.rs` SHA-256 is
`ee8097797892c1329ae0c4de258d103d52ef87a27c3eb1d16f39871cce847919`;
rebased test SHA-256 is
`12d5b2ab10384472d60b7b2e13b19f46bdb81564609230c3a33a23eedba7902d`.

The source-bound raw receipts under this evidence directory are:

| Raw file | SHA-256 | Result |
| --- | --- | --- |
| `PERF-OPTIN-32PAGE-RED.raw.log` | `1b40b7bf473bb79cb5279dd2dfde9031be5609d98b43e23dcbc62a907781dc2a` | compiled; old test-only ceiling exit 101 |
| `PERF-OPTIN-GRANT-MUTANT.raw.log` | `a110f3647854ab85d16a0523b78af1454d53c686014efd14bc670c6c49ead0de` | compiled; grant gate bypass exit 101 at 200-versus-503 assertion |
| `PERF-OPTIN-RESTORED.raw.log` | `95d1b3bc46bbb7b5ba43381635b746cb81a1e4e63c1344fb90ca6113e62e9c75` | restored exit 0, 38 pages to M seq 36242, `caught_up_ms=19117`, then grant/revoke 200 |

The live M file advanced between receipts; these are not byte-identical input
snapshots or a continuous-Q-service test. The final empty-page read saw M seq
36245 after catch-up. The raw paths and hashes bind the claims above; no
production QueryService was restarted for these measurements.

## Selected integration on `node-health-monitor`

Only the opt-in test, this corrected note, and the raw receipts were selected
from the isolated branch. The historical error-classification note was not
imported because the current shared source has a separately reviewed typed
BUSY/LOCKED/FULL and Capacity policy. On the combined test source SHA-256
`13b46efbb65f3754bda8f0880549f0e4df34662f7ec59aa1e782b4d62f3f9d1d`,
the opt-in read-only M witness ran 39 pages to global sequence 36585 in
19,816 ms, returned 503 before catch-up, then grant and revoke 200. The final
empty page read was 223 ms. Raw log `PERF-OPTIN-MERGED.raw.log` has SHA-256
`ce04d2596b6e630e0d9180d3edf970204ea84c069c46d4d91b80965279b7c16b`.
The shared production source was not deployed by this integration; this one
tight-loop run does not prove scheduled availability or the 72-hour gate.
