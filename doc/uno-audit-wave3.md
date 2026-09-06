# Audit wave 3 — proposals only

The corresponding memo proposals cover retirement/configuration dry-run,
validator execution readiness, distinct no-candidate/local-failure/new-block
results, wallet public-field normalization, and user-facing privacy limits.
No manager, host, consensus schema, Reserve, partition layout or wallet rule is
changed by this wave. Proposed tests are requirements, not executed evidence.

Two source-level dependencies must not be hidden by integration:

- `crypto/smartcont/config-code.fc::accept_proposal` changes one parameter.
  Separate proposals do not establish an atomic descriptor/ingress transition.
  A dry-run tool cannot substitute for a reachable, validated on-chain update.
- The consensus block validator accepts a reference-only empty candidate when
  it names the parent block. That does not produce a new UNO block or discharge
  height-based/system-message progress obligations.

All implementation/activation findings covered by these proposals remain open
pending owner decisions and real-path validation. Publishing a user notice
does not implement cross-domain unlinkability or a post-quantum profile.
