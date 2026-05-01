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
- Confirm oracle round-start receive handlers pass `in.senderAddress` to
  `slice5OracleStartRound` and that `Slice5OracleConfig.roundStarter`
  is the intended starter address.
- Confirm oracle reporter sets stay within the stdlib's bounded
  255-reporter map-aggregation limit.
- Confirm oracle deployments that rely on `maxDeviation` for data
  quality use quorum `>= 3`, or explicitly accept that quorum `2`
  anchors the second report on the first report.
- Confirm FunC/Tol reimplementations use the same truncating median
  convention for every even accepted report count.
- Confirm payment-channel signatures verify the signed-state cell hash
  and that seqno replay and premature settlement tests exist.
- Confirm payment-channel receive handlers do not expose
  `cooperativeCloseVerified` or `challengeCloseVerified` to untrusted
  messages unless signature verification has already happened in a
  trusted adapter.
- Confirm payment-channel payout dispatch is explicit: helper calls save
  closed state before sending funds, or the contract documents why
  payout is settled off-chain.
