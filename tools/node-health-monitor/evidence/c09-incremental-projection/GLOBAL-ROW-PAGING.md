# C09 bounded global M row paging (isolated candidate)

The incremental QueryService reader previously asked SQLite for 257
`source='process'` rows after its durable M cursor. M has a `store_seq` integer
primary key but no `(source,store_seq)` index. `LIMIT` bounded returned process
rows, not the diagnostic/edge-probe rows SQLite might inspect to find them.

The reader now takes at most 257 **global** `store_seq` rows using the M primary
key and only then projects eligible, non-quarantined process rows. Each
committable page consumes at most 256 global rows. Its cursor and hash identify
the actual final global row, including a diagnostic row; a non-process page
may advance the durable cursor without fabricating process evidence. The M
connection remains read-only and in one SQLite snapshot. No row, byte,
freshness or deadline cap was increased.

`unsupported_diagnostic_population_does_not_consume_process_scan_or_quarantine_cap`
now exercises the incremental entrypoint on 4097 diagnostic rows followed by
one process row: 17 pages, each cursor step at most 256 global rows, zero
process projections on the first 16 pages, one on the final page. Its
`EXPLAIN QUERY PLAN` control requires the global range to use
`observations`' integer primary key. The old full-scan helper remains a
separate historical control and is not counted as incremental-page evidence.

Exact restored source SHA-256:

- `crates/health-services/src/manager_query_source.rs`: `b31218e1d6b25a670d8eb75942631d48efbfad4de0a25328cb45689da7438f58`
- `crates/health-services/tests/manager_query_source.rs`: `246761a689c3e20708a8ae10141bbeef0f579c5a51ba2ecdeaa02f1bc1499a64`

The final-source baseline test exited 0. A compiled changed-property mutant
put `AND o.source='process'` back into the global page SQL; it exited 101 at
the intended `cursor.watermark - prior <= 256` assertion, not compilation or
fixture setup. Restored source exited 0. Raw logs in `raw/global-page/`:

| Log | Exit | SHA-256 |
| --- | ---: | --- |
| `baseline-plan.log` | 0 | `3d55b0facb108a1b915120253bd7757fa130fbd03d3012b178fca473e229f56b` |
| `mutant-process-filter-plan.log` | 101 | `fe557239c2b4b697b5f8f7678c90d36fc47036859fb1014485adcd77a74e35f7` |
| `restored-plan.log` | 0 | `5c97af52ec8e8d04d392ad6520e1baab2d98f07b4705591e26e624a2e68bc3bd` |
| `full-relevant-suite.log` | 0, 19 passed/2 opt-in ignored | `52443c99d88b4de68ed3c99ab9a706f47602f37f3a0610f89e86b0e79af9a626` |
| `fmt.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `clippy.log` | 0 | `15f025380dfa211b838985871c15409cb30a5478a1e6d6da435139a61b916727` |

The earlier no-`EXPLAIN` baseline/mutant/restored raw logs remain in the same
directory as historical lineage; they are not used as final-source proof.
This bounded local test does not establish 72-hour availability or the live
broker's five-second control latency. C09 remains open to those gates.
