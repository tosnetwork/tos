# Slice 5 Audit Checklist

Before shipping a Slice 5 contract:

- Run `python3 scripts/check-slice-5-abi-manifests.py`.
- Run `python3 scripts/check-slice-5-release-package.py` for generated
  project coverage.
- Confirm ABI manifests list all messages, get methods, public errors,
  signed cells, and manual/raw fixtures.
- Confirm no new helper emits active `ErrorClass.BackPressure`.
- Confirm governance actions cannot update code/data unless an explicit
  manifest exception and expected hash are present.
- Confirm oracle reporter lifecycle is fixed-at-deploy or otherwise
  documented by a later policy revision.
- Confirm oracle round-start receive handlers authenticate the starter
  before calling `slice5OracleStartRound`.
- Confirm oracle deployments accept the three-report inline aggregation
  cap, or use a reviewed contract-specific larger-set design.
- Confirm FunC/Tol reimplementations use the same truncating
  two-value median convention.
- Confirm payment-channel signatures verify the signed-state cell hash
  and that seqno replay and premature settlement tests exist.
