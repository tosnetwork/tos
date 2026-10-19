# C09 global-row page shared-tip candidate

Base: `c3252939b47cf5b36d718a09d624fef96e92fed6` (`node-health-monitor`, unchanged).
This isolated port changes only the incremental M reader and its existing
`manager_query_source` control. It preserves the base's cursor shape, exact
global-boundary verification, retained-parent checks, and mixed
process→diagnostic boundary rewrite regression. It has not been deployed.

The SQL scans `observations` in global `store_seq` order using the integer
primary key, fetches at most 257 rows, and commits at most 256 actual rows
per page. Only eligible process bodies count toward the process-body budget;
every scanned global row's hash is validated. A non-process last row is a
boundary witness, not a process projection. `store_seq` may have gaps, so
the numeric cursor difference is **not** claimed to be ≤256.

The strengthened test inserts 4097 diagnostic rows followed by one process:
page one has no process, and the process appears once on page 17. For each
page it counts actual rows in the cursor interval and requires 1–256. After
deleting 201 intermediate rows, it still requires 1–256 actual rows/page,
observes a numeric sequence jump over 256, and finds the one process.
`EXPLAIN QUERY PLAN` requires the global primary-key search. A compiled
mutant adding `AND o.source='process'` to the global page query exited 101 at
the intended actual-row-count assertion (test line 1631); the restored
targeted test exited 0.

Exact restored source SHA-256:

- `crates/health-services/src/manager_query_source.rs`: `d7fde76d5ec14d1930fc11efbab33b9fdff7aa4536b486430d1590015968fd98`
- `crates/health-services/tests/manager_query_source.rs`: `8551244d8af0e363764fe6925fb552e2557391501a2e3d1bc15496eeb93cb79d`
- compiled mutant production source: `1e4f3e44d662c3cfd7d1467eb94453d438a7e4a41e8482fa031584f1a4aeaf4a`

`CARGO_TARGET_DIR=$HOME/nhm-c09-global-page-build cargo test --locked -j 2 -p tos-health-services`
exited 0 on this exact port. Its `manager_query_source` executable reported
22 passed, 1 opt-in ignored. `cargo fmt --all -- --check` exited 0. Strict
`cargo clippy --locked -j 2 -p tos-health-services --all-targets -- -D warnings`
exited 0. This is source-bound
development evidence, not a live five-second control or 72-hour soak pass;
C09 remains RED.
