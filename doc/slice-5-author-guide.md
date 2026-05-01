# Slice 5 Author Guide

Slice 5 adds four second-wave stdlib patterns:

- `@stdlib/auction`
- `@stdlib/governance`
- `@stdlib/oracle`
- `@stdlib/payment-channel`

Start a project with:

```sh
tol new --pattern auction --output my-auction
tol new --pattern governance --output my-governance
tol new --pattern oracle --output my-oracle
tol new --pattern payment-channel --output my-channel
```

Each generated project includes source, a smoke test, deploy skeleton,
replay stub, opcode map, method-id map, error-code map, ABI manifest
pointer, and behaviour-conformance pointer. The generated source is a
small scaffold; production contracts should import the relevant stdlib
package and then follow the focused examples under `examples/slice5/`.

Compatibility rules:

- Keep opcode-bearing messages at 32-bit opcodes with `queryId`
  immediately after the opcode when request/reply correlation applies.
- Do not emit `ErrorClass.BackPressure` from new Slice 5 code.
- Auction bid receive handlers must bind the bidder to
  `in.senderAddress`. Use `state.receiveTrustedBid(config, msg,
  in.senderAddress)` or build with `slice5AuctionTrustedBid(...)`;
  `msg.bidder` is the wire field and is not authentication by itself.
- Auction time-sensitive handlers must use `blockchain.now()`, not
  `msg.now`. The `now` field remains in the wire ABI for compatibility
  and deterministic fixtures, but production receive handlers should
  discard it.
- Auction close and settle handlers must verify the seller with
  `state.requireSeller(config, in.senderAddress)` before state changes.
  `Slice5AuctionExpire` may remain open to any sender; it is a
  cooperative cleanup mechanism for stale postponed bids.
- Auction settlement records or returns the winning bid amount but does
  not by itself prove that funds have reached the seller. Either call
  `slice5AuctionEmitPayout(config.seller, amount)` after saving the
  settled state, or explicitly document an off-chain payout process.
- `slice5AuctionDefaultBudget()` is intentionally bounded for ordinary
  auctions. Use `slice5AuctionConfigWithBudget(...)` for high-traffic
  pre-open auctions and record the storage/gas tradeoff in the manifest
  or audit notes.
- Payment-channel signed states use Ed25519 over
  `Slice5PaymentSignedState.toCell().hash()`, not raw source bytes.
- Payment-channel `cooperativeClose` and `settle` helpers return the
  `balanceB` payout amount after updating helper state. They do not
  send funds by themselves; production receive handlers must save the
  closed state first and then dispatch the payout to `config.partyB`, or
  explicitly document an off-chain settlement policy.
- Payment-channel `cooperativeCloseVerified` and
  `challengeCloseVerified` skip Ed25519 verification but still enforce
  channel binding, balance conservation, expiry, closed-state, and
  seqno checks. Use them only in deterministic tests or in a trusted
  adapter that already verified both signatures over the state cell
  hash; untrusted receive handlers should call `cooperativeClose` or
  `challengeClose`.
- Governance action lists are policy-typed. `SetCode`, `SetData`,
  reserve, and library actions are rejected by default.
- Governance `proposerKey` and `voterKey` are protocol keys, not sender
  authentication. Production receive handlers must bind
  `in.senderAddress` to the canonical proposer/voter key before calling
  the stdlib helper; do not trust `msg.proposerKey` or `msg.voterKey`
  as authorization by themselves.
- Governance execute helpers approve and return policy-validated actions;
  they do not dispatch treasury funds by themselves. Production
  contracts must make payout dispatch explicit after the executed state
  is saved, or document an off-chain disbursement process.
- Large governance address sets should be stored behind refs. Several
  inline `address` fields can exceed the 1023-bit TVM cell limit; use a
  nested `Cell<T>` for voter lists or other multi-address state.
- Oracle examples use fixed-at-deploy reporter sets; each round records
  the reporter-set hash snapshot.
- Oracle round starts are ordinary contract messages, not protocol
  wakeups. `Slice5OracleConfig.roundStarter` is enforced by
  `slice5OracleStartRound`; pass `in.senderAddress` to the helper.
- Slice 5 oracle helpers support bounded reporter sets up to 255
  reporters. Median and outlier-anchor calculations iterate over the
  report map deterministically, so larger fixed-at-deploy reporter sets
  do not require a contract fork.
- Oracle `maxDeviation` outlier protection needs quorum `>= 3` when it
  is intended to resist a compromised first reporter. With quorum `2`,
  the second accepted report can only be checked against the single
  first report because no majority anchor exists yet; use quorum `2`
  only when that trust tradeoff is acceptable.
- Oracle median for an even number of accepted reports uses integer
  truncation of the average of the two middle sorted values. For the
  two-value case this is `(value1 + value2) / 2`.

Testing note: importing a `.tol` file that contains a `contract` block
into a tol-tester unit is supported for constants, types, and helper
logic. The compiler lowers only the entrypoint file's contract block, so
imported contract entrypoints do not collide with the test runner. Tol
imports are explicit rather than transitive: if a test imports a
contract source that itself imports `@stdlib/payment-channel`, the test
must still import `@stdlib/payment-channel` before using those stdlib
symbols directly.
