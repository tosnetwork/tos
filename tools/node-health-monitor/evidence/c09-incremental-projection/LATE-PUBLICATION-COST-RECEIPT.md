# C09 late-publication cost witness (2026-09-30)

Scope: isolated branch `nhm/c09-anchor-integration`, base `f7ad53ee06213d1ee13bc5d8f205fcc9af9f8cbd`. Only `manager_query_source.rs` test instrumentation changed. The test opens the running M SQLite database read-only and writes a disposable Q ledger; it does not change M, deploy, or exercise AURA. Five-second control deadline and page size are unchanged.

Source SHA-256: test `349d7f18b0a5c51b42d2f4e2a87badc285fddf0d7edd8b798327b106dcd6b2b2`; restored `observability.rs` `3945b6dc34da71589b4826dac1901e77afe0b19e908a2e417c5c6f17dae61687`; restored test binary `8c5a1dee0f93caffb3826184a4b1aec3cb19c23b459dc9ffca2810da115dd82b`. M source: `/home/tomi/nhm-supervision/c09-local/runtime/evidence/evidence.db`, network `b7fba4bda348db54717b7930da7b874289d88642a4d3990fb41d03e0cb006004`.

Command (both baseline and restored):

```sh
NHM_C09_READONLY_M_DB=/home/tomi/nhm-supervision/c09-local/runtime/evidence/evidence.db NHM_C09_NETWORK=b7fba4bda348db54717b7930da7b874289d88642a4d3990fb41d03e0cb006004 timeout 400s cargo test --locked -p tos-health-services --test manager_query_source live_read_only_projection_cost_witness -- --ignored --nocapture
```

The test observed real importer source-read completion followed by a held Data lock at >=2,000 retained parents. It sent grant and projection-health together at that point; both returned 503. The reported late-control time is the **combined completion bound** for the two concurrent requests, not separate per-request timing. Baseline natural exit 0: 101 pages, 2,479 peak retained parents, 668 ms maximum page, 3 ms maximum grant during M read, 2 ms maximum combined late-control completion, 39.61 s total. Restored natural exit 0: 102 pages, 2,479 peak retained parents, 659 ms maximum page, 4 ms maximum grant during M read, 2 ms maximum combined late-control completion, 42.82 s total. M grew between runs; page totals are not a controlled A/B throughput comparison.

Changed-property control: replacing only projection-health's Data `try_lock` with blocking `lock` compiled, then exited 101 at the intended late-lock assertion (`200` rather than expected `503`); production source was restored byte-for-byte and the full live witness rerun. Mutant source SHA-256 `1edc2311029559bf25ef64993450d109f6eb6919bb7f2d6ccbc9fae045a4f681`.

Separate restored controls, each natural exit 0: `durable_parent_before_cursor_replays_exactly_once_after_restart` (parent committed before cursor, idempotent restart replay); `pre_cursor_ledger_with_active_grant_catches_up_over_4096_history` (old fixed-W grant retention while catching up; 2,561 retained, 559.7 ms peak import); `projection_or_cursor_commit_failure_revokes_old_grant_and_replays_on_restart` (third-row transaction rollback and unexpected cursor-write failure). The last test's fail-closed revocation is for unexpected write failure, not a known bounded backlog/capacity refusal.

Raw SHA-256:

| Raw log | SHA-256 |
| --- | --- |
| `raw/late-publication/live-readonly-exact.log` | `ce1864b0dd9e351118e4d4a3e3a1cd63f1335ef77dc41cf73852760b5ad018dd` |
| `raw/late-publication/blocking-health-mutant.log` | `472d5c5d0d35c417cf6c762da722582cca417afadbeba9043ae4834290261448` |
| `raw/late-publication/live-readonly-restored.log` | `e8cc830a799d5349dcaaa22aba8ff1e446e136604777d3a0149bb2ef3a385162` |
| `raw/late-publication/replay-parent-before-cursor.log` | `ffa3ddcd011a32ccc682a36eeaecdab206f156597cba00b40c03b222705ef74b` |
| `raw/late-publication/active-w-retention.log` | `05acbc2ef6b3f03789b628b389d9510771c2e45c3ff379a34982eeeb5c6c4b4c` |
| `raw/late-publication/third-row-and-cursor-failure.log` | `9c708fe3ce84aa36e711f9dc4e1d9fe102aff25db0dd0a75d7e037d7fb6c3938` |

This is a cost and lock-overlap witness, not C09 acceptance. Cursor/global-W integrity and underlying global-row scan work are separate open review items; no production deployment or 72-hour claim follows from these timings.
