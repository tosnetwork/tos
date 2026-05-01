# Slice 5 Audit Checklist

Before shipping a Slice 5 contract:

- Run `python3 scripts/check-slice-5-abi-manifests.py`.
- Run `python3 scripts/check-slice-5-release-package.py` for generated
  project coverage.
- Confirm ABI manifests list all messages, get methods, public errors,
  signed cells, and manual/raw fixtures.
- Confirm no new helper emits active `ErrorClass.BackPressure`.
- Confirm auction bid receive handlers override caller-provided
  `msg.bidder` with `in.senderAddress` by using
  `receiveTrustedBid(...)` / `slice5AuctionTrustedBid(...)`.
- Confirm auction receive handlers use `blockchain.now()` for bid,
  close, and expire time checks; `msg.now` is caller-controlled wire
  data and must not drive production time-sensitive decisions.
- Confirm auction close and settle handlers check seller identity before
  calling stdlib close/settle helpers. Expire may be open to any sender
  because it only cooperatively removes stale postponed bids.
- Confirm auction payout dispatch is explicit after settled state is
  saved, or the contract documents an off-chain settlement process.
- Confirm auction deployments either accept the default bounded
  postponement budget or use `slice5AuctionConfigWithBudget(...)` with
  a documented storage/gas budget.
- Confirm governance actions cannot update code/data unless an explicit
  manifest exception and expected hash are present.
- Confirm governance receive handlers bind `in.senderAddress` to the
  canonical proposer/voter key before calling stdlib helpers; message
  fields `proposerKey` and `voterKey` are not authorization by
  themselves.
- Confirm governance treasury payout dispatch is explicit after
  execution state is saved, or the contract documents an off-chain
  disbursement process.
- Confirm governance storage with several addresses uses refs where
  needed to stay under the 1023-bit TVM cell limit.
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
