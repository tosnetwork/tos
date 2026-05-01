# Slice 5 Release Candidate Notes

This repo-side release candidate contains:

- ABI manifest validator and golden fixture comparison.
- `@stdlib/auction` with bounded postponement reuse.
- `@stdlib/governance` with policy-typed action validation.
- `@stdlib/oracle` with fixed-at-deploy reporter sets and median rounds.
  Post-trial hardening moves round-start authorization into the stdlib
  config and supports bounded reporter sets up to 255 reporters.
- `@stdlib/payment-channel` with signed-state cell-hash verification.
- `tol new --pattern` scaffolds for all four second-wave patterns.
- Generated examples under `examples/slice5/`.
- ABI freeze hashes in `doc/slice-5-abi-freeze-record.json`.
- External author trial record for `DexPriceOracle`, the first
  production-intent adoption candidate. The second-round oracle trial
  passed and added golden coverage for 5-reporter median finalization,
  running-median outlier anchoring, even-median truncation, and imported
  contract tests.
- External author trial record for `TosStreamChannel`, the second
  production-intent adoption candidate, using `@stdlib/payment-channel`.
  The trial added coverage for cooperative/challenge close, challenge
  supersede, seqno rollback rejection, and imported contract tests.

External adoption remains a Slice 5 release gate: Stage 7 records the
repo-side ABI freeze and explicitly leaves the three external production
contract requirement pending until one additional production contract
are recorded.
