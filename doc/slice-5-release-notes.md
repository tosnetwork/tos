# Slice 5 Release Candidate Notes

This repo-side release candidate contains:

- ABI manifest validator and golden fixture comparison.
- `@stdlib/auction` with bounded postponement reuse. Post-trial
  hardening adds trusted bidder/time binding helpers, seller guard
  helpers, auction-level queue-full rethrowing, and a payout emission
  helper.
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
- External author trial record for `TosCouncilFund`, the third
  production-intent adoption candidate, using `@stdlib/governance`. The
  trial added coverage for sender-bound voter/proposer authorization,
  quorum and threshold boundaries, replay/cancel/expiry paths, and
  invalid action rejection.
- External author trial record for `TosEscrowedAuction`, an additional
  production-intent adoption candidate using `@stdlib/auction`. The
  trial added coverage for sender-bound bidder identity, chain-time
  auction decisions, seller-only close/settle, queue-full monitoring,
  pending payout accounting, and imported contract tests.
- External author trial record for `TosReportBondOracle`, an additional
  production-intent oracle candidate. The trial added coverage for
  bonded report submission, sender-derived reporter identity, chain-time
  freshness, multi-send refund dispatch, and receive-handler emulator
  integration.

External adoption is now complete: Stage 7 records the repo-side ABI
freeze, the three required external production-intent contracts, and the
additional auction and bonded-oracle candidates.
