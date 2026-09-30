# C09 live M cadence / disposable Q grant witness (RED)

This opt-in measurement ran against the already-running M SQLite file **read-only**. It made a transactionally consistent `VACUUM INTO` copy of the running Q SQLite file inside a fresh 0700 temporary directory, changed only that 0600 copy, and removed it at the end. It did not contact the running Q socket or change M, Q, business services, or credentials. The isolated candidate was `nhm/c09-grant-ledger-lock` at `d5ad7497efc8ffa9b84849d70b8c2f65d4d6f7d7` plus the opt-in test; no production Rust changed after that commit.

One stable Python SQLite read-only connection sampled M's `PRAGMA data_version` once per second for 76 samples: 30 version changes, with global M observation sequence 43208 → 43311. This measures commits visible to that connection (approximately one change per 2.5 seconds), not their type. It does not claim every change was a process row or a quarantine.

The first actual `control_router`/disposable-Q run sampled 46 seconds with imports at seconds 0, 15, 30, and 45: grant HTTP 200 = 10, HTTP 503 = 36. Every 200 grant was immediately revoked in the private Q copy. A first setup attempt failed before routing because SQLite `VACUUM INTO` made a 0644 file; the application correctly requires a private Q ledger. That temporary copy was removed, file mode was fixed to 0600, and the live control was rerun; the setup red is not product evidence.

The instrumented second 46-second run sampled both stable M `data_version` and global M head before/after each actual grant request, plus Q's durable cursor. It produced grant HTTP 200 = **1**, HTTP 503 = **45**. Of the 45 refused requests, **all 45** had both a version mismatch and `Q.cursor.watermark != M.global_m_seq` while the before/after source readings were stable; no single-guard-only case occurred. Imports at seconds 15, 30, and 45 raced a new M commit, so `manager_caught_up=false` and no second 200 window opened. This demonstrates a real availability failure under current M write cadence. It does **not** isolate `data_version` as the sole cause: the head-equality gate independently rejects ordinary appended M rows, and the caught-up flag can be lost during a racing import.

Exact opt-in command (from `tools/node-health-monitor`; M/Q paths are existing local files, no token is supplied):

```sh
CARGO_TARGET_DIR=/home/tomi/nhm-c09-grant-lock-build \
NHM_C09_READONLY_M_DB=/home/tomi/nhm-supervision/c09-local/runtime/evidence/evidence.db \
NHM_C09_READONLY_Q_DB=/home/tomi/nhm-supervision/c09-local/runtime/query/query-ledger.db \
NHM_C09_NETWORK=b7fba4bda348db54717b7930da7b874289d88642a4d3990fb41d03e0cb006004 \
cargo test --locked -j2 -p tos-health-services --test manager_query_source \
  live_m_commit_cadence_vs_disposable_q_grants -- --exact --ignored --nocapture
```

Both 46-second restored runs exited 0. Source SHA-256 of `tests/manager_query_source.rs`: `92b40082cdd01fef027750ce914130f6dd4120d0e3e24fc361cf1f641f29cd78`. The normal manager-query-source test binary passed 22/22 unignored tests; three opt-in tests were ignored. `cargo fmt --all -- --check`, strict package Clippy, and `git diff --check` exited 0. The already-running M and Q PIDs were still 4127758 and 3847778 afterward. This is a diagnostic witness, not a new availability threshold or acceptance pass.

Security boundary: the retained-parent body/hash, quarantine, invalid-middle-row, and grant-after-quarantine regressions remain green. Simply removing `data_version` comparison would **not** close this availability failure, because the current M-head equality rejects every append since the last import. Nor may both checks be bypassed without an independent guarantee that retained parents and quarantine state remain valid. A reviewed design must distinguish append-only advancement from integrity-relevant mutation while keeping existing fixed-W grants and source-conflict revocation safe. Until then C09 remains RED and this candidate must not be deployed as a 5-second or 72-hour availability solution.
