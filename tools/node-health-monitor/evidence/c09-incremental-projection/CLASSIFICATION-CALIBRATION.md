# C09 capacity versus unknown-write classification

This note supersedes the withdrawn `0950ccd6f` candidate. The successor
`68e06b6579d3f37d01c77a4285bcc7ebb0e2151a` reverts its attempted
preservation of fixed grants after an unexpected SQLite cursor-write failure.
There was no service deployment or change to the shared branch.

At the shared base `a1a833e3a61e6f196aad22da809e6abed18b6e98`,
`active grant evidence retention` and `M parent retention full` are the two
explicit, known bounded-capacity refusals. They leave the old cursor/fixed-W
evidence available while blocking new grants until catch-up. The >4097 test
requires `assert!(paused_for_grant)`, checks the old grant after saturation,
and checks that the cursor does not advance. It cannot pass by skipping the
capacity branch.

The injected projection-insert and cursor-commit SQLite errors are *not*
classified as known capacity. The importer revokes existing grants and latches
`manager_conflicted`, because this path does not establish that the unexpected
storage failure left a trustworthy durable state. The injected-failure test
asserts old-grant refusal and replay after restart; preserving those grants
would require a separate validated storage-state protocol. Verified retained
parent change, quarantine, malformed source, and cursor invariant failures
remain fail-closed.

The separate global-boundary change on this branch requires a valid anchored
M observation for every nonzero persisted watermark, including diagnostic-only
history. SQL-tampered `watermark=1, anchor=NULL` is refused at startup before
any grant. No source refusal is weakened to achieve grant preservation.

After the revert, exact locked `manager_query_source` suite: 18 passed,
1 ignored, exit 0. `cargo fmt --all --check`, locked Clippy for
`tos-health-services --all-targets -- -D warnings`, and `git diff --check`:
exit 0. The opt-in read-only M catch-up measurement and compiled grant-gate
sensitivity control are recorded separately in `STARTUP-CATCHUP-COST.md`.
C09 remains open for integrated review, deployment, and 72-hour availability;
this note is not a production gate pass.
