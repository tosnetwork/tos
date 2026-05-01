# Slice 5 External Author Trials

## DexPriceOracle

- **Date:** 2026-04-30
- **Pattern:** `@stdlib/oracle`
- **Contract:** `examples/slice5/dex-price-oracle/src/dex-price-oracle.tol`
- **Status:** accepted as external production-intent candidate 1 of 3
- **Tests:** `examples/slice5/dex-price-oracle/tests/dex-price-oracle-positive.tol`

The external author built a TOS/USDC spot price oracle using the Slice 5
oracle helper surface. The trial found five issues:

- Round-start authorization was not enforced by the stdlib helper.
  Disposition: `Slice5OracleConfig.roundStarter` and
  `slice5OracleStartRound(..., starter)` now enforce the sender check in
  the stdlib helper.
- Outlier checks anchored on the first report. Disposition:
  `@stdlib/oracle` now uses the running accepted-value anchor for later
  reports.
- Inline oracle aggregation is capped at three reports. Disposition:
  the stdlib now stores reports in a map and computes deterministic
  median/outlier anchors from the map, supporting bounded reporter sets
  up to 255 reporters.
- Two-value median truncates. Disposition: documented in the ABI guide.
- tol-tester cannot import a contract block into another test file
  without entrypoint collision. Disposition: the compiler now lowers
  contract blocks only in the entrypoint file, so imported contract
  sources expose constants/types/helpers without emitting duplicate
  entrypoints.

This records one external production-intent adoption candidate. Slice 5
still needs two more external production contracts before the external
adoption release gate is complete.

## Round 2 Trial Result

- **Date:** 2026-05-01
- **Status:** passed; `DexPriceOracle` remains accepted as external
  production-intent candidate 1 of 3.
- **Tests:** `dex-price-oracle-import-positive.tol` passed 2 cases;
  `dex-price-oracle-positive.tol` passed 16 cases; combined gas
  `608254`.

The second external trial verified the post-hardening oracle surface:

- unauthorized round starters fail with
  `SLICE5_ORACLE_THROW_UNAUTHORIZED_STARTER`;
- a 5-reporter fixed-at-deploy set with 3-of-5 quorum finalizes a
  deterministic sorted median;
- the running-median outlier anchor accepts a third report that the old
  first-report anchor would reject;
- two-report median truncation is encoded as a golden regression;
- tests can import `src/dex-price-oracle.tol` without a generated
  entrypoint collision.

Two residual observations were documentation/specification issues rather
than stdlib logic bugs:

- quorum `2` cannot provide first-report-compromise resistance for
  `maxDeviation`, because the second report has only one prior accepted
  value to compare against. The author guide, ABI note, and audit
  checklist now require quorum `>= 3` when that protection is relied on.
- even-count oracle median uses integer truncation. The ABI note and
  audit checklist now state the cross-language rule for every even
  accepted report count, not only the two-value example.

## Round 2 Trial Request

The second trial should re-run `DexPriceOracle` against the updated
`@stdlib/oracle` surface and explicitly verify:

- unauthorized round starters fail with
  `SLICE5_ORACLE_THROW_UNAUTHORIZED_STARTER`;
- 5-7 reporter fixed-at-deploy sets can finalize a deterministic median;
- a compromised first reporter no longer anchors all later outlier
  checks;
- two-value medians still use the documented truncating convention;
- tests can import `src/dex-price-oracle.tol` without a generated
  entrypoint collision.
