# Slice 5 Release Candidate Notes

This repo-side release candidate contains:

- ABI manifest validator and golden fixture comparison.
- `@stdlib/auction` with bounded postponement reuse.
- `@stdlib/governance` with policy-typed action validation.
- `@stdlib/oracle` with fixed-at-deploy reporter sets and median rounds.
- `@stdlib/payment-channel` with signed-state cell-hash verification.
- `tol new --pattern` scaffolds for all four second-wave patterns.
- Generated examples under `examples/slice5/`.

External adoption remains a Slice 5 release gate: Stage 7 records the
repo-side ABI freeze and explicitly leaves the three external production
contract requirement pending unless real evidence is available.
