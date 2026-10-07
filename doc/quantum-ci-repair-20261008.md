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
