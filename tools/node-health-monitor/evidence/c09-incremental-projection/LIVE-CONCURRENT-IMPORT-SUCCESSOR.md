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
| `live-readonly-concurrent.log` | 101, first 32 pages did not reach peak | `0719ecc1129a15b84d423ca4f2cd86c52d1052bfe69132f9e3c3374f9e933b90` |
| `live-readonly-concurrent-deep.log` | 101, obsolete ≥5-second-page test predicate | `ba7014ed5554287c8cf368bea569e580d8cb46440163572a35e7a7c3ce2c6395` |
| `live-readonly-final-source.log` | 101, live M advanced between catch-up and one-shot grant | `932a2d9bceff94789cb295895f5b10890290ede49f18bf75817d683bafb5e21c` |
| `live-readonly-concurrent-final.log` | 0, pre-source-phase test | `07c4a88f5335ace287f241cd7664e89df7c7d13c54ce434e4cbbe5866c6edab6` |
| `live-readonly-successor.log` | 0, pre-health correction | `8162356e9823a420aeda9b87ffda8575432c2bf4bedfdf4ecc01dfdfc7383b47` |
| `live-readonly-restored-exact.log` | 0, final source | `07a66b237855ff39e3295aa79369fec41e3c350312b5bd3f18126d0ab51430bd` |
| `synthetic-baseline.log` | 0, pre-source-phase test | `cef434e83b0394cf3e6b47c544598f8052dee36ed79ea5117e8fa1d7052ca1e3` |
| `data-held-mutant.log` | 0, retired survivor before precise phase witness | `4831d8f7f5ad2a1cb3d4a517d57bb777b4386209b1bf90139ae7f36bf705578c` |
| `source-phase-baseline.log` | 0 | `55770ce93f2e7eb7f8fdfac07b1293e3e5d53a2017bf42fb6c1bf65919c64289` |
| `source-phase-data-held-mutant.log` | 101, intended real-read/Data-lock assertion | `485868f6d471d377b9043a11179cfa0b54b6d47b9bd15b34bb85b114d2b77b57` |
| `health-version-mutant.log` | 101, intended same-W false caught-up assertion | `2b29f4c2b3695617b606edc9e1cc3ec3c7dd522fb55ef4245ded6987a8571c89` |
| `health-restored.log` | 0 | `00e499616cde98c15479dc3741cecf4807de7924a4cded3a704b0f54edfbf7a4` |
| `manager-query-final.log` | 0, 20 passed/2 opt-in ignored | `48f2ad7547ed1275651b47411eea754ee780c42238b391c950a6c4da91317f4d` |
| `workspace-restored.log` | 0, pre-health correction | `a1dadeb5954d12f1844cd13b486fe664cb63e9f7aff21cf6b864c906a18d2001` |
| `workspace-final.log` | 0, final source | `e610ac634275f6c394611b1707ad72629c5f0a0bb5b5a2f0d8a18d31fa6c00d3` |
| `fmt-final.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `clippy-final.log` | 0 | `a4c4da5c06b0c71ae2b2a469ac05cd24179ff45515f7b126aa932ea827e35d9c` |

Commands: `cargo test --locked --workspace`; `cargo clippy --locked -p tos-health-services --tests -- -D warnings`; `cargo fmt --all -- --check`; focused baseline/mutant/restored `cargo test --locked -p tos-health-services --test manager_query_source <test> -- --nocapture`; live opt-in `NHM_C09_READONLY_M_DB=<local M evidence.db> NHM_C09_NETWORK=<public network hash> timeout 400s cargo test --locked -p tos-health-services --test manager_query_source live_read_only_projection_cost_witness -- --ignored --nocapture`. The `timeout 400s` is a test-process bound for traversing live history, not a changed service deadline. `git diff --check` was clean for code and report; raw tool logs retain their original blank lines.
