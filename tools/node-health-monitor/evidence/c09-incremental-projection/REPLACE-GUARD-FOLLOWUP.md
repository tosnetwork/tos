# C09 immutable M observation guard — isolated follow-up

**Review candidate only; not integrated or deployed. C09 remains RED.** This addendum follows `INTEGRITY-REVISION-PROTOTYPE.md`. Its earlier source hashes remain historical. The shared branch and running M/Q/business services were not changed.

SQLite's default `recursive_triggers=OFF` means an `INSERT OR REPLACE` can delete an existing observation without firing the existing `AFTER DELETE` integrity-revision trigger. That could rewrite an M parent while leaving both the revision and global sequence unchanged. The v2 M schema now installs and verifies an exact `BEFORE INSERT` trigger that aborts collisions on either `store_seq` or the immutable source-record tuple. Ordinary new observation inserts still leave the integrity revision unchanged. The v1→v2 migration installs this trigger transactionally; v2 reopen and read-only Q source reads refuse a missing or changed trigger.

Restored source SHA-256 (relative to `tools/node-health-monitor`):

| Path | SHA-256 |
|---|---|
| `crates/health-services/src/durable.rs` | `b90d1aa5116aab3b6f0416de3906dbaa8577e8ec75721f16284ff079a16fd255` |
| `crates/health-services/tests/manager_query_source.rs` | `e94e338f0634f9398f78ed4d65cec1bfaf2ebc359ae91ba1b9f5f02a51fe8036` |
| `crates/health-services/src/manager_query_source.rs` | `d88e1f558b1c6cb63aef180bf19445e1e8cc01d38804d544782eea1987986769` |
| `crates/health-services/src/observability.rs` | `6d99aaa7b73a2cea7542c6ebf5662f913984c33823dcf2543edab05ca6e63545` |

The focused test verified `recursive_triggers=0`, rejected both a same-sequence `REPLACE` and a same-source-tuple `REPLACE`, and checked the original body, revision zero and global W remained unchanged after each refusal. Dropping the new trigger made both the read-only Q head and M reopen refuse. The legacy migration control drops the trigger while constructing the v1 fixture, then verifies migration.

Actual commands on the restored source, all natural exit 0:

```sh
CARGO_TARGET_DIR=$HOME/nhm-c09-grant-lock-build cargo test --locked -j2 -p tos-health-services
CARGO_TARGET_DIR=$HOME/nhm-c09-grant-lock-build cargo test --locked -j2 -p tos-health-services --test manager_query_source
CARGO_TARGET_DIR=$HOME/nhm-c09-grant-lock-build cargo clippy --locked -j2 -p tos-health-services --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
```

The exact-source `manager_query_source` target reported 24 passed, 4 opt-in ignored. The full package and doc-tests finished with exit 0. A compiled diagnostic mutant changed the new trigger predicate to `WHERE 0 AND (...)` (mutated `durable.rs` SHA-256 `af026673bcdfc3ae50a3b205521d0ecef7fbd7696d1839ae9880f0a9`) and exited 101 at the intended `REPLACE must not bypass immutable M parent identity` assertion; the source was then restored and retested. This red is not a compiler failure.

This guard does **not** close the cross-M/Q linearization gap: quarantine may commit after the last M revision check and before Q durably creates a new grant; an already active fixed-W grant also remains readable until background detection. A ruling on the required strictness was requested. Do not call this a strict post-quarantine grant guarantee. The live M remains on the older schema and needs a reviewed disposable-copy migration, backup and rollback before any M-only rollout. Retention, concurrent control latency, and the 72-hour gate also remain open.
