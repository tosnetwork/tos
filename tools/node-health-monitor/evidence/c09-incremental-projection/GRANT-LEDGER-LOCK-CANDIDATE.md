# C09 grant/Q-ledger contention candidate (isolated; not deployed)

Base: `4a8b50ceece5c9315a45aa831c71daa0a2d59c19` in `nhm/c09-grant-ledger-lock`. Shared `node-health-monitor` was `c3252939b47cf5b36d718a09d624fef96e92fed6` during this test. This candidate must be reviewed and selectively integrated; it does not change the running M or Q binary.

The grant handler now retains one non-waiting Q-ledger mutex guard from cursor validation through durable `create`. It no longer drops the guard and reacquires it with a blocking `lock`. Revoke already uses a non-waiting Data/Q lock pair; the new actual control-router test covers both handlers while a separate thread holds Q. It observes fast HTTP 503, no in-memory or durable grant/revocation side effect, then normal HTTP 200 after release. The grant/revoke refusal timings in the restored focused run were 3.051 ms/0.395 ms; uncontended create/revoke were 2.228 ms/1.261 ms. These are isolated measurements, not a bound on SQLite commit/fsync or live 5-second control availability.

Source SHA-256: `observability.rs` `053f5799f1a48c2e7eec011c4d0b69e7a3b7eb82b93ac50e4967689fd2e101cc`; `tests/manager_query_source.rs` `b013ce6322e5ade9ced3c55eb79055b8d008ff697093d3b8ddeba59f9e3e916b`.

Changed-property controls used the same dedicated target directory `/home/tomi/nhm-c09-grant-lock-build` and compiled successfully:

- Grant mutation `try_lock` → blocking `lock`: source SHA-256 `d3d532ff65e42c9e76e6a0568922c770311d40b68c8379e36b6f1360230eef5f`; focused test exit 101 at line 402, actual 200 vs required 503. The holder released after its two-second bound. This is an intended behavior assertion, not a compiler error.
- Revoke mutation `try_lock` → blocking `lock`: source SHA-256 `637508455e8b242913e7d83cd887f3ef8a217b39f12aeac6a6b1facc0383972b`; focused test exit 101 at line 441, actual 200 vs required 503. Again compiled and failed at the intended assertion.
- Restored source digest equals the original `053f5799...`; `cargo test --locked -j2 -p tos-health-services --test manager_query_source held_query_ledger_refuses_grant_and_revoke_without_side_effects -- --exact --nocapture` exited 0 (1 passed).

Restored `cargo test --locked -j2 -p tos-health-services` exited 0 (all unignored package tests passed; manager-query-source 22 passed/2 opt-in ignored). `cargo fmt --all -- --check`, strict `cargo clippy --locked -j2 -p tos-health-services --all-targets -- -D warnings`, and `git diff --check` exited 0. Commands ran from `tools/node-health-monitor` with `CARGO_TARGET_DIR=/home/tomi/nhm-c09-grant-lock-build` for Cargo tests/checks.

Historical setup failure: first focused test request used RFC3339 `+00:00`, rejected with HTTP 400 by the existing strict UTC-Z parser. The test was corrected to `to_rfc3339_opts(..., true)` before the sensitivity runs; that first red is not product evidence. A first mutation command was mistakenly run above the Cargo workspace and failed to find `Cargo.toml`; it was rerun from the workspace root.

Limit: the test directly exercises Q-lock occupancy at request entry and the source structure removes the cursor-to-create reacquisition window. It does **not** prove a 5-second bound for SQLite `create`/`revoke` transaction or fsync while Data/Q guards are held, nor cold-start/import latency. C09 remains RED; do not deploy this candidate as a 5-second availability or 72-hour acceptance claim.
