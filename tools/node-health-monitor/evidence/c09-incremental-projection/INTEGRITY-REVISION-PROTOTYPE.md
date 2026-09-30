# C09 fixed-W append/integrity-revision prototype — isolated review candidate

**Not integrated or deployed. C09 remains RED.** This prototype is on `nhm/c09-grant-ledger-lock`, built in the isolated `/home/tomi/nhm-c09-grant-lock-build` target. The shared `node-health-monitor` tree and running M/Q/business services were not changed. The deployed M database is still the older schema; this source must not be pointed at it as a production rollout without backup, explicit M-only migration, rollback and disposable-copy controls.

R4 design §10 and §14.3 require an immutable grant W and every tool to read only `store_seq<=W`; they do not require W to equal M's newest global sequence at grant creation. The C06–C09 order requires the W to represent an approved immutable package. This candidate distinguishes an import stopped on a partial page (new grants refuse) from a completed import followed solely by ordinary immutable observation appends (new grants freeze the last validated W; later rows remain outside the run).

Source SHA-256 after restoration:

| Path relative to `tools/node-health-monitor` | SHA-256 |
|---|---|
| `crates/health-services/src/durable.rs` | `6ec6131bf628b93dc3eaff023329e4a408b88dfea138d538a2895434930a8fce` |
| `crates/health-services/src/manager_query_source.rs` | `d88e1f558b1c6cb63aef180bf19445e1e8cc01d38804d544782eea1987986769` |
| `crates/health-services/src/observability.rs` | `6d99aaa7b73a2cea7542c6ebf5662f913984c33823dcf2543edab05ca6e63545` |
| `crates/health-services/tests/manager_query_source.rs` | `a3cfdca30961e89a621f72bf6826ddc9db91a62d44a520a342a75594be8d90c3` |
| `crates/health-services/tests/durable.rs` | `1e410005b7e0b8a19ab0d607ec71cbff7ff0eccc828c6b678641b510e28dadde` |

M EvidenceDb now migrates evidence schema v1→v2 transactionally. The v2 singleton `integrity_revision` is incremented (with signed-64 overflow refusal) by exact checked SQLite triggers on quarantine INSERT/UPDATE/DELETE and original observation UPDATE/DELETE. Ordinary observation INSERT does not increment it. A v2 reopen checks the exact required trigger definitions and refuses a missing/changed one instead of silently repairing it. A read-only M projection head or page checks schema/revision in its source snapshot. Q import binds the page revision to pre/post import revision reads; the grant compares the last completed validated revision with the M head's revision and allows `cursor.W<=M.head` while still binding M network/device/inode. The Q cursor and immutable parent read are otherwise unchanged. The existing isolated single Q `try_lock` guard remains held from cursor validation through durable `create`.

Focused actual controls (all natural exit 0 on restored code):

- A **31-second actual control-router** test inserts 15 valid unique process rows every two seconds, imports at seconds 0/15/30 and asks for a grant each second with a five-second per-request deadline. It got **31 HTTP 200, 0 HTTP 503, zero quarantines**, and each issued grant's M W equalled the last completed import W, not the newer tail. It made no on-demand projection read in the grant handler. This is an isolated functional success-rate control, not a live 72-hour or fsync latency pass.
- An M revision test checks ordinary INSERT leaves revision unchanged; quarantine INSERT advances; ignored duplicate does not; quarantine UPDATE/DELETE and observation UPDATE advance; a rolled-back quarantine does not publish; observation DELETE advances; signed-64 overflow refuses the entire quarantine; dropping a required trigger makes both read-only head and v2 reopen refuse.
- A v1→v2 disposable migration control retains the original observation `store_seq` and evidence ID while installing the revision schema. `durable.rs` future-version refusal was updated from version 2 to version 3; the first unchanged historical test failed as expected after the version bump, then the corrected test passed. ControlDb continues to accept only its v1 schema.
- Existing actual-router same-W quarantine refusal, retained-parent and partial-page/restart tests pass. The pre-existing late-quarantine characterization still passes: a quarantine committed after grant validation can precede durable creation, and a previously active grant remains readable until detection. The revision does **not** eliminate that window.

Compiled diagnostic mutations, both restored after the intended exit 101:

1. Remove the grant's validated-revision comparison. The same-W quarantine router test fails at `same-W quarantine cannot issue a new grant from stale validation`: actual HTTP 200 versus required 503.
2. Replace trigger `revision=revision+1` with `revision=revision`. The revision test fails on the first quarantine: actual 0 versus required 1. Neither red is a compile failure.

Restored `cargo test --locked -p tos-health-services` exited 0, as did `cargo fmt --all -- --check`, `cargo clippy --locked -p tos-health-services --all-targets -- -D warnings`, and `git diff --check`. The opt-in 31-second test command was:

```sh
CARGO_TARGET_DIR=/home/tomi/nhm-c09-grant-lock-build cargo test --locked \
  -p tos-health-services --test manager_query_source \
  ordinary_m_appends_preserve_fixed_w_grants_between_fifteen_second_imports \
  -- --exact --ignored --nocapture
```

Open gates are material: v2 M migration/backup and rollback against a disposable copy of the **actual** local M database; running-Q compatibility and control availability under M migration; source-age/package freshness under long ordinary-tail lag; trigger overhead and full 5-second control latency under retained-parent peak; live ordinary-write grant pass rate; no immediate active-grant quarantine revocation or elimination of the final post-check/pre-create race; retention/72-hour soak; full review of schema/trigger tamper trust assumptions. Old binaries refuse a v2 evidence DB, so rollback requires a reviewed database restore path, not merely binary replacement. No source here claims production acceptance.
