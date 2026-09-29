# C08 durable HTTP cursor restart checkpoint (isolated synthetic evidence)

The actual HTTP router ingests three synthetic event rows, grants a fixed W,
and returns page one with a limit-one cursor. The query service and durable
SQLite ledger are then dropped and reopened. A fourth row is ingested after
reopen; using the original cursor returns rows two and three in order, never
the post-grant row. The restored durable ledger records three charged query
attempts. This composes the existing ledger restart and HTTP pagination
controls at the real route boundary; it is not a production event adapter.

The first draft of this new test failed compilation because its local
sequence variable was inferred as `i32` while the observed timestamp is
`i64`. After making the fixture sequence type explicit, the targeted test
passed. That compile failure was a test-fixture typo, not a runtime negative
or a changed-property mutation; no source behavior claim is based on it.

Final test source `crates/health-services/tests/http.rs` SHA-256:
`5f508238f217345625f7697fe9c2008ba866cfe7ce99cef9a85c6db671c93f9f`.
Production query and ledger sources are unchanged from the previous
checkpoint.

Raw files under `/home/tomi/nhm-c08-mcp-evidence/`:

- `c08-cursor-restart-final-http.log`: `cargo test --locked -p
  tos-health-services --test http`, natural exit 0, 19 passed; SHA-256
  `7a370106fc0522cd37a19a8c5f49b93ab26141a1b2d258af1ded262fcbc2dd97`.
- `c08-cursor-restart-final-clippy.log`: `cargo clippy --locked --workspace
  --all-targets --features mcp -- -D warnings`, natural exit 0; SHA-256
  `3a600d9de9ee2192a067344320031d6430add15f0218ce5de170730b76118923`.
- `c08-cursor-restart-final-workspace.log`: `cargo test --locked --workspace`,
  natural exit 0; 219 passed across 37 test targets, none failed; SHA-256
  `7cfec23aa2aebad97c85665c65cc177356314eda2bb0fc09dbc567012aab0f61`.

This closes only the isolated durable HTTP continuation control. C08 still
needs approved AURA transport/provider wiring, model subprocess termination,
and independent V/O network-counter and broader refusal evidence before
production or stage acceptance.
