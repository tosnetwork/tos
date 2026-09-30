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

## Source-bound companion controls

At restored source commit `4b3cb7526d05dbe20802b1dfc95bdf7efe622104` (which contains document-only `af74eca30be3ab02f0e6418af86b6bdb6f655d7d` in its ancestry), the `manager_query_source` test target ran natural 0: 20 passed and two explicitly opt-in cost tests ignored, 8.57 s. Three focused controls then ran on the same source without edits:

* `diagnostic_only_boundary_is_anchored_and_tampered_cursor_refuses_startup`: 1/1 natural 0. A legitimate diagnostic-only prefix carries the global-row anchor; a forged no-anchor or old-anchor cursor over a process row is refused on restart.
* `unsupported_diagnostic_population_does_not_consume_process_scan_or_quarantine_cap`: 1/1 natural 0. The 4,097-diagnostic control exercises bounded global-`store_seq` paging and its SQLite query plan, rather than a `LIMIT` on filtered process results.
* `tests::eight_idle_control_connections_are_bounded_and_expire` in the real `tos-observability` Unix listener: 1/1 natural 0, 5.01 s. This proves the unchanged five-second connection lifetime for eight idle connections. It is **separate** from the live M importer overlap test above, which calls the actual control router in-process; a full socket/import overlap is not claimed.

The first socket test invocation added `--exact` without the `tests::` prefix and ran **zero tests**; its log is retained but is not evidence. The corrected invocation removed `--exact` and ran one test.

Source SHA-256 for these controls: `manager_query_source.rs` `b31218e1d6b25a670d8eb75942631d48efbfad4de0a25328cb45689da7438f58`; `query_ledger.rs` `c329dcfa073b7c0c95b1bba2e37dbad50716b6ca4833b95bf29dff66be2efccb`; `observability.rs` `3945b6dc34da71589b4826dac1901e77afe0b19e908a2e417c5c6f17dae61687`; `tos-observability.rs` `548e1fad19abb1a0b6a10753ecbba17093853f6e7bcde10bee842cc43a7187eb`; test `manager_query_source.rs` `349d7f18b0a5c51b42d2f4e2a87badc285fddf0d7edd8b798327b106dcd6b2b2`.

| Raw log | SHA-256 | Result |
| --- | --- | --- |
| `raw/source-bound-closure/anchor-restart.log` | `8386c69162e1c9d04092b3926938ad72ae5adcd37055c819fc8d7e0feac6e467` | 1/1 passed |
| `raw/source-bound-closure/diagnostic-heavy-global-page.log` | `d62aae2860fc10b2f1d3029804ecc2eeb64461376ac9253741f8d68499b899cb` | 1/1 passed |
| `raw/source-bound-closure/control-socket-five-second-actual.log` | `69ff3e56566c7ea8037b5df4f801eae42baafbd085112f28eb68d7b5575286bd` | 1/1 passed |
| `raw/source-bound-closure/manager-query-source-target.log` | `d058db7b7cd875bde3a01185320d81793792d29886adcceb07fe95a2686946c5` | 20 passed, 2 opt-in ignored |
| `raw/source-bound-closure/control-socket-five-second.log` | `29681983afb1ba2cd7b17577b0650a2f0fe695022da8cf677920f0060ce25fe0` | 0 tests; not counted |

These controls establish current source behavior in isolation, not sustained live-broker availability or stage acceptance. Do not promote the faster disposable-ledger page timings to deployed performance evidence.
