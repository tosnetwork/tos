# C09 isolated grant latency and same-W change witness

Scope: isolated `nhm/c09-anchor-integration` candidate, based on `74763f299c7ee74d5628108234cf3153ec54e63d`. No business-node or deployed QueryService change. C09 remains open to deployed five-second control latency and continuous availability/soak review.

The grant route no longer imports a process projection page. It reads M's global high-water and database identity on a bounded blocking task, refuses if the projection is not caught up to that exact head, and uses non-waiting locks for the long-lived importer state and query ledger. A stable read-only SQLite connection's `data_version` distinguishes an M change at the *same* global `store_seq` (notably an old-parent quarantine) from a still-valid background validation. A changed version refuses a new grant until background revalidation; it does not renew or revoke an already fixed grant merely for lag. No deadline, capacity or freshness threshold was raised.

`pre_cursor_ledger_with_active_grant_catches_up_over_4096_history` deterministically reaches active-W retention pause with 2,561 retained M parents, holds the importer Data mutex on another thread, and bounds the actual control-router grant call at five seconds. Restored calls returned 503 in 2.16 ms under contention and a successful grant in 3.66 ms after catch-up. A compiled mutant that changes the grant's `try_lock` to `lock` failed the intended elapsed-time assertion after 3.00 seconds. This is an isolated route/lock test, **not** a measurement of the deployed Unix listener or the complete broker at peak workload.

`grant_refuses_quarantine_without_new_m_row_until_background_validation` first grants at a caught-up W, then quarantines its original M process source without adding an observation. A second grant returns 503. A compiled mutant that bypasses the `data_version` comparison instead returned 200 and failed that exact assertion. Both mutants compiled; neither red is a setup or compiler failure. The original source was restored and both controls returned 0.

The first full-workspace attempt retained below exited 101 because two older synthetic witness fixtures had fixed 2026-09-29 role windows and ran after that date. Their test-only, dynamic-window corrections were copied exactly from the clean shared `node-health-monitor` tree; the two focused tests and the final full workspace then exited 0. This is not a product change or a silent deletion of historical red evidence.

Restored source SHA-256:

| File under `tools/node-health-monitor/` | SHA-256 |
| --- | --- |
| `crates/health-services/src/observability.rs` | `9736ed55d55d5818c46c4356e6961a09671f2f2eb4375ab32c542c1773372c30` |
| `crates/health-services/tests/manager_query_source.rs` | `ad197cd9d83557724f7f15169fe4c3d143a4a8c6dff255b1ae127bce80ddee96` |
| `crates/health-services/tests/witness_archive.rs` | `42e2b5bf68cad2ab4ffcfa07d05acabc10642bd2dded5e7a6e2035a9a11fed9b` |
| `crates/health-services/tests/witness_cache.rs` | `97b0ab12cea3cc81d0c132a3c030b85fba3963cd9223de9b8d29bd55fdc021a7` |

All paths below are relative to `raw/grant-latency/`. `cargo test --locked --workspace` ran with no test filter; `cargo clippy --locked -p tos-health-services --tests -- -D warnings` and `cargo fmt --all -- --check` passed. The two changed-property sequences each used `cargo test --locked -p tos-health-services --test manager_query_source <named-test> -- --nocapture` for baseline, mutant and restored source. The witness files used corresponding focused `cargo test --locked -p tos-health-services --test <test-file> <named-test>` commands.

| Raw log | Exit | SHA-256 |
| --- | ---: | --- |
| `grant-baseline.log` | 0 | `0aeba58c0b0225b9b2ce4887254dd7f22d7e6d6584fa34bca9df00a6a2022aa1` |
| `grant-lock-mutant.log` | 101, intended elapsed assertion | `1746680709c4fdfdf2bd157c04ce472ac19ec7bc06bf962bbf53add4d20d386e` |
| `grant-restored.log` | 0 | `0b7edcf9e62d6e7331c7c8349aa191401bca63faddbb3c0fb366b0d72a0fb975` |
| `change-baseline.log` | 0 | `56984563af6a9a53ca4c135a4debed319fe3d764b7226e68f6a4ee34c440dbd2` |
| `change-version-mutant.log` | 101, intended same-W quarantine assertion | `9d1204895862278f18fa95767f342d71a90340cfa714b42f19698dbbb8160ba4` |
| `change-restored.log` | 0 | `da3e59dddcd9229a4b705a9a3822a0eb3517f12c2173967b76105896fa17b6cf` |
| `workspace-restored.log` | 101, historical fixed-date witness fixture | `96c7d54c6a7def1a635a39c0c5e5228a4c83dfc506ff60de28976ed6e1962981` |
| `witness-role-window-restored.log` | 0 | `552b29675d5b1d5852aa30df1ea4e7766140ac888a1b2cd6309ce15b0b602b90` |
| `witness-cache-role-window-restored.log` | 0 | `444310717c0bb25088939d15c1d02bd5e64e615cae6af7ac74d7e3cd0769c497` |
| `workspace-final.log` | 0 | `1592c71bb66f72d3b30054e9527e35933362a3032c62c42b7d2e46e50ff99677` |
| `clippy.log` | 0 | `adaccb721bf85e148bdb9fc8bccfd4dde32e26201c67424d190eb26a90608f25` |
| `fmt-final.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

An earlier pre-final `fmt.log` was also 0; `fmt-final.log` is the final-source receipt. `git diff --check` was clean. The measured times are local and not a production performance gate. The current service has not been switched to this candidate; no claim of 72-hour pass, model diagnosis or production readiness follows from these tests.
