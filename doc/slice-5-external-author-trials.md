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
