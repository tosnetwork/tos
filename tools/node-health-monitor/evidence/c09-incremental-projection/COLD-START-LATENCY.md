# C09 cold-start catch-up timing (isolated, not deployed)

Source base: `85936f5164610d0bcab7683e1bb3da157c2be2db`. The only change in
this successor is an ignored, opt-in timing test. It constructs 1500 and 4000
valid synthetic process rows in separate temporary M databases, then starts
QueryService with a fresh temporary Q ledger. Fixture construction is outside
the timed region. Each case imports one page at startup and calls the bounded
importer until the cursor reaches the exact M watermark. The command has a
60-second outer timeout; it does not run business nodes or the deployed broker.

Final restored run on 2026-09-30 UTC (hot isolated test build):

| M process rows | Startup first page | Total pages | Tight-loop caught up | Slowest refresh page |
| ---: | ---: | ---: | ---: | ---: |
| 1500 | 248 ms | 6 | 1823 ms | 479 ms |
| 4000 | 181 ms | 16 | 5891 ms | 532 ms |

The exact opt-in test exited 0 (1 passed, 9.33-second test duration for both
fixtures including creation). A prior natural run of the preceding timing-only test version produced
1500: 175/2137/472 ms and 4000: 231/5812/521 ms for first-page/total/max
page respectively. A compiled changed-property mutant forced `manager_caught_up`
true after the first page; the test exited 101 at the intended cursor assertion
(actual 256 versus expected 1500), not at compilation or fixture setup. The
source was restored before the final run.

The exact warm `manager_query_source` suite on this source finished naturally:
19 passed, 2 opt-in witnesses ignored, test 9.50 seconds. Individually timed
on the preceding production-equivalent source, the parent-count progression
test took 7.84 seconds (command wall 8.05 seconds) and the >4097 pre-cursor
active-grant test took 9.82 seconds (wall 10.00 seconds). A subsequent full
suite before this timing-only test finished in 8.31 seconds (wall 8.75 seconds).
The independently observed >85-second, ~107%-CPU process was not still
running when inspected; this isolated run did not reproduce it. It remains a
historical observation, not a latency pass or a finding disproved by one run.

The deployed refresh loop schedules only **one 256-row page every 15 seconds**
after its startup page. Without extra grant attempts/imports, 1500 rows need
5 remaining ticks (about 75 seconds), while 4000 need 15 (about 225 seconds)
before a new grant can be issued. These are schedule-derived availability
windows, **not measured deployed restart times**. A separate read-only local M
witness in `STARTUP-CATCHUP-COST.md` observed new-grant 503 while behind and
200/revocation after catching up. The sub-second isolated *per-page* times do
not establish the 5-second live control deadline under contention, nor do the
5.9-second tight-loop totals establish 72-hour service availability.

The M importer uses `insert_projection_page`, cloning `EvidenceStore` once per
page. The generic per-row `insert_bound` is not the M batch path. Retained
parents are still revalidated for each page, so larger or contended histories
need operational measurement. No cap, timeout, or freshness rule was raised.

Test-source SHA-256: `ffe384def5bbec5fb647571eedf755e2d8a8a6e00d7cb04a29d46c34ef968163`.
Production-source SHA-256: `observability.rs`
`ee8097797892c1329ae0c4de258d103d52ef87a27c3eb1d16f39871cce847919`,
`query_ledger.rs`
`ecc81887de516215b5351c73a7756f9ddee5a05d6f3b83dd4d67c0f81ec2cf1e`.
Locked Clippy `--all-targets -- -D warnings`, fmt, and diff checks exited 0.
