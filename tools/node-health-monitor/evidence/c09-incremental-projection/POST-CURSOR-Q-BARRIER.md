# C09 post-cursor Q-lock interleaving control (isolated)

This is a sharper control than the pre-entry held-Q test in `GRANT-LEDGER-LOCK-CANDIDATE.md`. An actual `control_router` grant reaches the point **after** its `manager_cursor()` check. A unit-test-only hook then starts a competing thread that attempts `QueryLedger::try_lock`; if it succeeds, that thread holds Q for two seconds. The hook is behind `#[cfg(test)]` and is not present in a production library/binary build. The test reads a disposable empty M database and writes only a disposable Q ledger in a 0700 temporary directory.

Restored `observability.rs` SHA-256: `ddceec8fbaabfa61044e79ada0f0e94b1c22ffad9e6f54e382978450a9897cca`. Run from `tools/node-health-monitor` with `CARGO_TARGET_DIR=/home/tomi/nhm-c09-grant-lock-build`:

```sh
cargo test --locked -j2 -p tos-health-services --lib grant_cursor_interleaving_tests -- --nocapture
```

Restored baseline and final runs compiled and exited 0. In the final run the competitor could not acquire Q after cursor validation, the actual grant returned 200 in 3.852441 ms, and one active grant was present both in memory and in the disposable durable Q ledger. The existing pre-entry held-Q route test separately requires prompt 503/no side effect and a normal 200 after release.

Changed-property mutation restored the exact old two-lock shape: a temporary `try_lock().manager_cursor()` followed later by blocking `lock().create()` while Data is held. Mutant source SHA-256 `511154f9d941f3865306a1e6da38d4136bf1181dfa8b4a8a1091500af187cfbd`; it compiled and exited 101 at `Q was free after cursor validation` (source line 833). The competitor had acquired and held Q in the TOCTOU interval. This is the intended assertion, not a compile failure or unrelated timeout. The mutation was restored byte-for-byte; no running Q or M service was changed.

The restored full locked `tos-health-services` package exited 0 (library 19 passed; manager-query-source 22 passed/4 explicit opt-ins ignored; all other unignored package tests passed), as did `cargo fmt --all -- --check`, strict `cargo clippy --locked -j2 -p tos-health-services --all-targets -- -D warnings`, and `git diff --check`.

Scope remains isolated. This proves that the repaired grant path does not release Q between cursor validation and durable creation; it does **not** prove a five-second bound on SQLite fsync, ordinary-M-write availability, or a 72-hour run. `LIVE-M-GRANT-CADENCE.md` and `DISPOSABLE-M-ORDINARY-CADENCE.md` document the independent availability RED. No shared-branch integration or deployment is authorized by this result alone.
