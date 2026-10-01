# C09 slow-import/control separation — isolated successor, RED

This successor to `23f70487e4b84c6ff92ca60d883ce3d9b5ecff1f` has **not** been deployed. The shared `node-health-monitor` tree and business services were not changed. C09 remains RED until independent review, query-service rollout, actual private Unix control-latency evidence, and the remaining soak/performance gates.

The previous local M cost observation on the older `9a6a7951` path included pages taking 5.735 and 6.128 seconds, longer than the unchanged five-second control connection deadline. This successor serializes background imports on a separate gate, reads the bounded retained-parent set and the M SQLite snapshot **without** holding QueryService `Data` or `QueryLedger`, then holds them only for projection publication/cursor commit. New grants do not import; under a busy publication lock they fail promptly with 503. Fixed old-W grants are not revoked merely for catch-up lag. The private projection-health route likewise takes non-waiting state locks, performs source-head I/O on a bounded blocking task, and reports a same-W `data_version` change as lagging rather than falsely caught-up. No production page, memory, freshness, or five-second connection limit was raised.

The restored synthetic control uses an actual M page with 2,561 retained parents. A source-phase atomic witness proves the importer was **inside** the M read while `Data` was available; concurrent grant was 1.43 ms and private control-health was 1.13 ms. A separate held-Data control returned 503 in 2.42 ms. A compiled mutant that held `Data` across the source read failed at the intended phase/lock assertion (exit 101); its initial predecessor **survived** because the earlier test only observed the overall import gate, and that historical green is retained. A second compiled mutant suppressing the health `data_version` comparison failed at the intended `caught_up` versus `lagging` assertion (exit 101). Restored focused manager-query tests: 20 passed, two opt-in timing tests ignored.

The final-source opt-in test opened the **running local M database read-only** while writing only to its own temporary private Q ledger. It traversed 97 bounded global pages through M `store_seq=24498` in 36.05 seconds. At peak, 2,479 original M parents were retained; the slowest page took 639 ms and the slowest grant concurrently invoked through the real control router took 3 ms. The test reached a matching M high-water, then observed grant 200/revoke 200. This is a measured source/route concurrency witness, not a claim that the deployed Unix listener or sustained broker has passed its five-second deadline. The earlier opt-in red logs are retained: first 32 pages did not reach peak, a later test incorrectly required an old-implementation five-second page, and a live M update raced a one-shot caught-up grant. The corrected test keeps the exact-head gate and uses at most eight bounded revalidations when live collectors advance M; it does not accept a stale grant.

Restored source SHA-256 (under `tools/node-health-monitor/`):

| File | SHA-256 |
| --- | --- |
| `crates/health-services/src/observability.rs` | `3945b6dc34da71589b4826dac1901e77afe0b19e908a2e417c5c6f17dae61687` |
| `crates/health-services/tests/manager_query_source.rs` | `5dd6d1a08814c2c3a175e13b0bb5ae7e47ebbe3be630a12649b55ef21b46e45a` |

Raw logs under `raw/live-concurrent/` are immutable lineage; SHA-256 and natural exits:

| Log | Exit/result | SHA-256 |
| --- | --- | --- |
| `live-readonly-concurrent.log` | 101, first 32 pages did not reach peak | `19d269f77f7321bd42c0120314bb2e8f99967d05cfa98e58aadb249d9169bb59` |
| `live-readonly-concurrent-deep.log` | 101, obsolete ≥5-second-page test predicate | `c5dbb29ac23706b512e45d3ae563672774fe0e8d12e9b725e77f124bd2450289` |
| `live-readonly-final-source.log` | 101, live M advanced between catch-up and one-shot grant | `bf0e50d38e561482a2f5f39fa9f370d3f30d2870eea642af7e027370b6ddad9d` |
| `live-readonly-concurrent-final.log` | 0, pre-source-phase test | `2329b7e7abb6967fca89d8b9dbc784d04b775e24efa051bc5465e248d26f726c` |
| `live-readonly-successor.log` | 0, pre-health correction | `480b849195480a8be766659e56be84bf05ffd772c18666ff1a1ffd1bea7f7234` |
| `live-readonly-restored-exact.log` | 0, final source | `07a66b237855ff39e3295aa79369fec41e3c350312b5bd3f18126d0ab51430bd` |
| `synthetic-baseline.log` | 0, pre-source-phase test | `06387caf52b5bee62c3d4cf8f0f4ac320bbf78eb36d73ef86093c4548c973d89` |
| `data-held-mutant.log` | 0, retired survivor before precise phase witness | `af82e80e1e6623d0975562554cb1eafd7e974eadeb2d5b98a1a5094efcc9ca5f` |
| `source-phase-baseline.log` | 0 | `de4a454ab48e81efe9b91751e740967c5166b94eafe0530bec60c600ede90cfb` |
| `source-phase-data-held-mutant.log` | 101, intended real-read/Data-lock assertion | `6e9be34a49291321febad8cf0b24f3ce043082be7dc255629f95a5cdf190abd2` |
| `health-version-mutant.log` | 101, intended same-W false caught-up assertion | `df29e7d79c63897745d55a0b187ff853503df3ba506128025e91611045055f12` |
| `health-restored.log` | 0 | `09bb31d9e9450acb2386897b134c5a838a1c9ba80124217d3964abae131d55c3` |
| `manager-query-final.log` | 0, 20 passed/2 opt-in ignored | `8aa126a55af83b49e4059764d8e31f111cb89ceeea0dcb85c16aa8e6d2e06f9e` |
| `workspace-restored.log` | 0, pre-health correction | `d9fef1c8595d6d1b9d11865cb81da336fdce427843cd0766d2771bb3fb4b3eaa` |
| `workspace-final.log` | 0, final source | `775b3025fcb2b3fdc40078722b15cd5855440c9bfd6d7f5c9e838015d3e38a54` |
| `fmt-final.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `clippy-final.log` | 0 | `fc46ab72bb731c466b16ec65d298d29649d4514b62d90d148e32860f6f505385` |

Commands: `cargo test --locked --workspace`; `cargo clippy --locked -p tos-health-services --tests -- -D warnings`; `cargo fmt --all -- --check`; focused baseline/mutant/restored `cargo test --locked -p tos-health-services --test manager_query_source <test> -- --nocapture`; live opt-in `NHM_C09_READONLY_M_DB=<local M evidence.db> NHM_C09_NETWORK=<public network hash> timeout 400s cargo test --locked -p tos-health-services --test manager_query_source live_read_only_projection_cost_witness -- --ignored --nocapture`. The `timeout 400s` is a test-process bound for traversing live history, not a changed service deadline. `git diff --check` was clean for code and report; raw tool logs retain their original blank lines.
