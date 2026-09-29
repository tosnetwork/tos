# C07 typed package restore checkpoint — development only

The saved fixed-W process package now has one typed, unknown-field-denying
validator on both write and restore. It binds the run/network/two watermarks,
requires canonical numeric strings, checks each process item against the grant
node/scope/window and frozen sequence bounds, and requires exactly one of a
process item or an explicit missing item for every approved node/scope pair.
Evidence and parent IDs must be lowercase SHA-256-shaped strings. This closes
the prior top-level-only shape check; it does **not** prove a recomputed,
well-formed payload's provenance independently of the retained M/query
evidence chain. The actual package producer still builds only from verified
retained process projections, and no model/provider has been enabled.

The ledger test now rejects omitted/foreign source partitions, extra fields,
noncanonical observed time and an invalid process identity at save. It also
alters the nested missing scope in the stored BLOB and recomputes SHA-256;
restore refuses despite the matching digest. The existing actual M writer and
HTTP grant test still verifies the valid package and frozen/late-arrival
behavior.

Final source SHA-256:

- `fixed_package.rs`: `15d0660fce0ead091439f98e49f4e916cb341febf080f136a7b0215eebcc7e4f`
- `query_ledger.rs`: `6da5bf1f95bb597d4a925da8969026d717da918f3e158495b026ad3caf8e2904`
- `tests/query_ledger.rs`: `347c6798b828c0c056f6785f7d76b411019dd14e7e8643b116ce8596efebba76`

Final commands and raw logs (natural exit 0):

- `cargo test --locked --workspace --all-targets`: 216 passed, one optional
  C04 indexed-pair test ignored without that directory. Raw
  `/home/tomi/nhm-c08-mcp-evidence/c07-package-typed-final-workspace.log`,
  SHA-256 `ef618d904e876496367e2bf3e276621e59e68258807b518f287603c86eb0447c`.
- `cargo test --locked -p tos-health-services --test query_ledger --test
  manager_query_source`: 14 passed. Raw
  `/home/tomi/nhm-c08-mcp-evidence/c07-package-typed-final-targeted.log`,
  SHA-256 `8622b47910bb374e671b61e41b1973f72575a28d9e5a421383dfb6e4f5e2e1a5`.
- `cargo fmt --all -- --check` and
  `cargo clippy --locked --workspace --all-targets --features mcp -- -D warnings`:
  exit 0. Clippy raw
  `/home/tomi/nhm-c08-mcp-evidence/c07-package-typed-final-clippy.log`,
  SHA-256 `dd621e9ff7c9eac161c730aa8a79332dd68698435a7a84d044d9ad39dfa1f5d2`.

This is a scoped checkpoint, not C07/C08 or production acceptance. Actual
tokenizer/context budgeting, AURA child lifecycle/cancellation, approved
private provider selection, semantic entailment and performance isolation
remain open.
