# C09 bounded M projection candidate (2026-09-29)

Scope: isolated QueryService source change only. The deployed M, six collectors, local broker, AURA adapter, and business nodes were not changed by this work. C09 remains **RED/open** until an integrated deployment, measured performance, and the 72-hour gate pass.

The previous importer rescanned M's complete process history on every import and refused after 4096 rows or 8 MiB. This candidate persists a separate last-consumed *global M observation sequence* in the query ledger. Each import projects at most 256 process rows (and probes one more for page completion) from one read-only M SQLite snapshot, together with its global high-water mark and exact retained-parent/quarantine checks. A page commits each idempotent derived parent before advancing the cursor. A partial catch-up refuses new grants without treating the lag as a source conflict; source identity, retained-parent, insertion, or cursor-commit failure latches refusal and revokes existing grants. Query-ledger W and per-run grant watermarks remain separate from the M cursor. No cap, freshness threshold, or production timeout was increased.

The tests cover 4097 historical process rows across pages and restart, sparse non-process global sequences, a pre-cursor ledger with an active grant, both replay windows, partial-page no-grant, exact retained-parent mutation/missing/quarantine, an invalid middle row, and injected projection/cursor commit failures with old-grant refusal. This is bounded isolated evidence, not a 72-hour continuity result. The old full-scan read helper remains for legacy tests; the running QueryService import path uses the new page reader.

## Source identity and raw results

Source SHA-256: `manager_query_source.rs` `b924353656bdc9d02591a1b80e7454d1b5df84c5038b14b432c285a0cf799385`; `query_ledger.rs` `38154602b2f948c3e1ac2c6b821b4c4219148b6ceccb751f8b780b6d9ce157c3`; `observability.rs` `a524b1e2047b2e29cb2fd37e0f0ce87571a4717d158db426809f8160a42602d8`; `tests/manager_query_source.rs` `d6e4c95727bca711d24796544c717ff40a6c56b969c716c0f02b9b440d1a4a28`. Logs are under `$HOME/nhm-c08-mcp-evidence/` and were generated with `script -q -e`; the test build root was `$HOME/nhm-c09-projection-build` with `cargo --locked -j2`.

| Raw log | SHA-256 | Natural result |
| --- | --- | --- |
| `c09-incremental-projection-final-targeted.log` | `b86732e6cfd9c71eb4158dd769ed4e0a8ae717d933b188652c24d680dc856753` | `cargo test -p tos-health-services --test manager_query_source`: 14 passed, exit 0 |
| `c09-incremental-projection-workspace-final.log` | `cd575c931cece4ffb50b204589185210691ab91cc96be778422fb7064c06448e` | `cargo test --workspace`: natural exit 0; default-ignored tests remain ignored |
| `c09-incremental-projection-fmt-clippy-successor.log` | `dfc039217feb0f3eef33051a6a3fdd243b9c9645a5b17cacff859c6ec68d9cb7` | `cargo fmt --all --check` and `cargo clippy --locked -j2 -p tos-health-services --tests -- -D warnings`: exit 0 |
| `c09-incremental-cursor-baseline.log` | `b145760815d9bf97a0872792fb934f4f719a3bec8218da4932bc734799defbd5` | targeted baseline compiled, exit 0 |
| `c09-incremental-cursor-mutant.log` | `e60fe165f908744fee8bec0d580e723e46243ff3ea3436d6eb8c819ace290ef2` | compiled `store_seq >= cursor` mutant, exit 101 at intended 511-versus-512 cursor assertion; not a setup/compiler red |

The mutant source SHA-256 was `853864595d5e55d12ca0bfb81c5fe0030de38d481a05cffd3306d2157146e09f`; restored source SHA-256 returned to `b924353656bdc9d02591a1b80e7454d1b5df84c5038b14b432c285a0cf799385` before both final green test runs. `git diff --check` passed. Earlier failed style/test attempts remain historical and are not counted as these results.

Remaining gates: independent exact-commit review; deployment/rollback of the QueryService binary by the authorized operator; measured live catch-up/read cost under the existing resource profile; credential/receiver rotation, restore exercises, and 72-hour soak. The existing six-node AURA point-in-time bridge does not prove continuous monitoring or model diagnosis.
