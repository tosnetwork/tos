# Quantum PR CI investigation, 2026-10-08

Reviewed PR #138 head: `9c90e928ed5f240ce2237d4632d648d3e851bf15`.

Confirmed code/integration failures:

- Rust formatting: job 112844140260 in run 37636540099 reports formatting
  differences in three Rust files. Applied repository-pinned `cargo fmt`;
  `cargo fmt --manifest-path tosctl/src/Cargo.toml --all -- --check` passes.
- C++ changed-line formatting: hygiene job 112844136229 in run 37636539742
  reports clang-format differences. Applied clang-format 21.1.8 with the
  workflow's base `6da705c8ad6e5a1dd118f11de819e0e542416540`, extensions and
  path exclusions. Its repeated read-only diff reports no formatting changes.
- Source guards: job 112844113949 in run 37636529491 ran 52 guards; only
  `docker-validator-role` failed. The engine registers the explicit optional
  `ext-message-work-profile`, but the Docker argument table omitted it after
  integration with main. Added it to the argument-taking table. The exact
  failing `RoleTest.test_option_table_matches_the_engine` now passes locally.

Separately, failed jobs with empty step lists report that they were not started
because acquisition failed five times. These are runner scheduling failures,
not executed test failures. Their missing log blobs are consistent with the
job metadata; no test success is inferred from missing logs.

Local Docker full-suite execution is limited by macOS `/bin/bash` 3.2 rejecting
`${id,,}` in this Linux-oriented script. The full Linux suite must pass CI;
the isolated option-table test does not clear its remaining runtime cases.

The repair does not change default admission settings or bypass CI gates.
Final-head remote CI remains required before merge.

## Second CI round: head 0d2bce93e

The completed round exposed three additional integration failures:

- Python hygiene: 31 Ruff errors, followed by formatting differences. Applied
  import fixes and formatting to the workflow's changed-file selection; Ruff
  check now passes.
- Both release-parity platforms rejected the review manifest's file identities.
  Renaming and formatting changed source bytes without refreshing that frozen
  manifest. Regenerated it only after asserting identical code, configuration,
  format and candidate acceptance status. Full bundle reproduction and its
  targeted corruption/refusal controls pass locally; comparison was not relaxed.
- The configuration-contract sandbox refused current genesis code
  `8291930aa0bf0b6939d8086c9ad9b0d63dbc65e4ca85af081eb80da82af82cb8`.
  ConfigParam 48 monotonic-policy validation changed code while leaving proposal
  storage unchanged. Retained the prior known-code hash and added this specific
  reviewed hash; regenerated the exact code BOC fixture from native gen_fif
  output. All 12 `config_list_proposals_sandbox` tests pass, including exact
  genesis fixture matching, large-state fallback and unknown-code refusal.

The sanitizer job was again never acquired by a runner. The dependent
`determinism` gate correctly failed because that required job did not succeed;
its prerequisite gate is unchanged. Final-head remote checks still must pass.
