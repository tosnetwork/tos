# C09 late same-W quarantine window (isolated characterization)

This is a **RED safety characterization**, not a fix or permission to deploy the isolated grant candidate. It uses a disposable M database, disposable Q ledger and actual Axum control/query routers; no live M/Q or business service was changed.

The restored source is `observability.rs` SHA-256 `e93cf55e490ca0a2be7db28720e7850b49724decf03e6608fada56531851748b` and `tests/manager_query_source.rs` SHA-256 `f758d39e306d46a9d4b520f19a8fd2aac61005a7c81f6e5edb032e5b30c78ed6`. The new `#[cfg(test)]` fixture and interleaving hook are absent from production builds. `GRANT_HOOK_TEST_SERIAL` prevents two tests from racing over that hook.

Two distinct controls pass on restored code:

1. An actual process parent is projected and a fixed-W grant issued. M then quarantines that original parent without adding an observation row. Before the next importer pass, an actual `node-snapshot` request on the **old** grant still returns HTTP 200, process `rss_bytes=4096`, and the original M evidence ID. A **new** grant returns 503 because its version witness changed. After the importer detects quarantine, the old query returns 503.
2. A test-only hook commits the matching M quarantine **after** a new grant's version and Q cursor checks but **before** durable Q grant creation. The actual grant returns 200 and leaves one unrevoked durable grant even though M's version has changed; the subsequent importer detects quarantine and marks the manager conflicted.

Commands from `tools/node-health-monitor`, with `CARGO_TARGET_DIR=$HOME/nhm-c09-grant-lock-build`:

```sh
cargo test --locked -p tos-health-services --test manager_query_source grant_refuses_quarantine_without_new_m_row_until_background_validation -- --exact --nocapture
cargo test --locked -p tos-health-services --lib quarantine_after_version_and_cursor_checks_can_precede_grant_commit -- --nocapture
cargo test --locked -p tos-health-services
cargo fmt --all -- --check
cargo clippy --locked -p tos-health-services --all-targets -- -D warnings
```

The restored targeted tests, full package, format check, strict Clippy and diff check all exited 0. An initial lib command accidentally used `--exact` with an unqualified test name and selected **zero** tests; it is not counted. The corrected lib command selected one test and passed.

Two temporary compiled diagnostic mutations proved the assertions are sensitive, then were removed:

- A second M version read immediately after the hook made the late-quarantine grant test exit 101 at `late quarantine reached durable grant`: actual HTTP 503 versus expected 200. This second read is **not** a complete fix because quarantine may commit after it.
- A query-time M version check made the old-grant exposure test exit 101 at its HTTP assertion: actual 503 versus expected 200. This would also reject ordinary M writes and is **not** adopted as a production fix.

The current importer checks retained parents in one M snapshot. A quarantine committed later does not synchronously set `manager_conflicted` or revoke grants; a version change only makes `manager_caught_up=false`. `query()` checks `manager_conflicted`, not the version. Therefore existing fixed-W cached parents can remain readable until a later successful import detects the quarantine. This interval is **not bounded to 15 seconds**: import backlog, failure or scheduling delay may extend it. A new grant also has a post-version-check/pre-commit TOCTOU window. An immediate same-W revocation guarantee requires a stronger invalidation/transactional design; a cheap single revision read before commit alone cannot close the final gap, and no on-demand M read on every query was introduced here.
