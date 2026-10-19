# C09 projection-copy hypothesis: measured before any further change

No production code or runtime configuration was changed for this profile. The committed isolated source remained `540c976530bf9f3230ae6efa417777043b2490bd` and was restored byte-for-byte after a temporary, no-secret phase timer (`observability.rs` restored SHA-256 `3945b6dc34da71589b4826dac1901e77afe0b19e908a2e417c5c6f17dae61687`). The temporary instrumented source SHA-256 was `071e99f0316e145214c1063d4e6126b944967bd7188d0912a874bd549bed6989`.

The hypothesis is correct for the **older** `9a6a79519b84fdfb79eef7f7036a644bd4af12e3` path: `observability.rs` called `QueryLedger::insert_projection` for each row, which reached `insert_bound` and cloned `EvidenceStore` each time. `fc067e1c9` subsequently introduced `insert_projection_page`; the current importer calls it once for a page, and that method clones the store once, stages up to 256 records, checks fixed-W eviction/idempotent parent bindings, commits original parents and derived rows in one FULL SQLite transaction, and commits the M cursor **after** parent publication. `insert_bound` remains for other single-record operations; its presence is not proof that current manager catch-up calls it per row.

The opt-in profile used the running local M SQLite database **read-only** and a separate private temporary QueryLedger. It traversed 99 bounded global pages to `store_seq=25171` in 36.60 seconds, with 2,479 retained parents at peak. The slowest full page was 503 ms, the slowest concurrently routed new grant was 3 ms, and a caught-up grant/revoke returned 200/200. On the 54 nonempty pages with at least 2,000 retained parents, phase timings from the raw log were:

| Phase | Mean | Maximum |
| --- | ---: | ---: |
| Read durable Q cursor and retained parents | 91.0 ms | 109 ms |
| Revalidate retained parents/read one M page | 154.6 ms | 295 ms |
| Publish the page through the one-clone/one-transaction path | 99.8 ms | 117 ms |
| Commit the M cursor after parent publication | 0.8 ms | 3 ms |

The raw `raw/profile/live-phase-profile.log` exited 0 and has SHA-256 `730e6dade4d18cac64bd12e53677a29e91fc4b8d381b15e52aa00156645260d6`. Command: `NHM_C09_PROFILE_IMPORT=1 NHM_C09_READONLY_M_DB=<local read-only M evidence.db> NHM_C09_NETWORK=<public network hash> timeout 400s cargo test --locked -p tos-health-services --test manager_query_source live_read_only_projection_cost_witness -- --ignored --nocapture`. The environment switch existed only in the temporary instrumented source and is **not** present in the restored candidate. The 400-second bound applies only to the offline test process; the service's five-second control connection deadline was not changed.

Conclusion: the measured current page cost is distributed across retained-parent/Q read, M validation and page publication; it does not show an O(page × store) clone loop in the current import path. A smaller page is not justified by this measurement and could increase page count/backlog. The earlier reported 5.735/6.128-second pages remain valid **historical old-source** evidence, not the current candidate's timing. This one read-only local run is not a deployed Unix-listener latency gate or a 72-hour soak pass. C09 stays RED/open; do not deploy `9a6a7951` on the basis of this profile.
