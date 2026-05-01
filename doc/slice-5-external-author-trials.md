# Slice 5 External Author Trials

## DexPriceOracle

- **Date:** 2026-05-01
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

## TosStreamChannel Round 3 Result

- **Date:** 2026-05-01
- **Pattern:** `@stdlib/payment-channel`
- **Contract:** `examples/slice5/tos-stream-channel/src/tos-stream-channel.tol`
- **Status:** accepted as external production-intent candidate 2 of 3.
- **Tests:** `tos-stream-channel-positive.tol` passed 12 cases;
  `tos-stream-channel-import-positive.tol` passed 2 cases; combined gas
  `74033`.

The external author built a two-party streaming payment channel for DEX
margin settlement, pay-per-call API micropayments, and subscription
escrow. The trial verified Ed25519-over-cell-hash signing material,
channel-id binding, monotonic seqno and replay rejection,
cooperative/challenge close state transitions, challenge supersede,
premature settlement rejection, duplicate close rejection, and malformed
balance rejection.

The trial found four friction points:

- Payout dispatch is outside the helper. Disposition: documented as an
  explicit integration step; helpers return `balanceB` after state
  update and production handlers must save closed state before sending
  funds, or document off-chain settlement.
- `cooperativeClose` lacked a signature-bypassed test helper while
  `challengeCloseVerified` already existed. Disposition:
  `cooperativeCloseVerified` now mirrors the challenge helper and
  bypasses only Ed25519 verification, not channel binding, expiry,
  balance, closed-state, or seqno checks.
- Tol imports are not transitive. Disposition: documented as expected
  Tol behavior; tests importing contract sources must explicitly import
  any stdlib symbols they use directly.
- Contract-specific golden fixture copies were ceremony when reusing
  the exact stdlib wire body. Disposition: ABI fixture references now
  support `wire_reuse_of`, so `TosStreamChannel` can point at the
  checked payment-channel fixtures without duplicate JSON copies.

This records the second external production-intent adoption candidate.
Slice 5 still needs one more external production contract before the
external adoption release gate is complete.

## TosCouncilFund Round 4 Result

- **Date:** 2026-05-01
- **Pattern:** `@stdlib/governance`
- **Contract:** `examples/slice5/tos-council-fund/src/tos-council-fund.tol`
- **Status:** accepted as external production-intent candidate 3 of 3.
- **Tests:** `tos-council-fund-positive.tol` passed 12 cases;
  `tos-council-fund-import-positive.tol` passed 2 cases; combined gas
  `78747`.

The external author built a three-voter governance-controlled treasury
for council-voted grant disbursements and on-chain budget approvals. The
trial verified: unauthorized voter rejection before stdlib is reached,
canonical voter-key derivation from sender address, unauthorized proposer
rejection, duplicate vote prevention, quorum boundary, threshold boundary,
execute-success (returns approved action value), expiry, cancel-then-vote
rejection, execute replay, SET_CODE disallowed, and action value limit.

The trial found four issues:

- `@stdlib/governance` voterKey in `Slice5GovernanceVote` is an
  unchecked message field — any sender can supply any voterKey without
  validation at the stdlib level. Disposition: documented as a mandatory
  contract-level obligation in the author guide and audit checklist.
  TosCouncilFund ignores `msg.voterKey` entirely; it derives the
  canonical key from `in.senderAddress` via `councilResolveVoterKey`,
  which throws `COUNCIL_THROW_UNAUTHORIZED_VOTER` (0x1001) for any
  sender not in the stored voter set.
- Four inline `address` fields in a single struct exceed the 1023-bit
  TVM cell limit (estimated 1068 bits). Disposition: the author guide
  now explicitly warns that three or more inline `address` fields fill a
  cell; contract authors must pack excess addresses into a nested
  `Cell<T>` ref. TosCouncilFund splits voter addresses into
  `TosCouncilVoters` stored as `Cell<TosCouncilVoters>`.
- Execute handler does not dispatch approved funds; fund dispatch is
  outside the stdlib helper pattern. Disposition: documented as an
  explicit integration step consistent with the payment-channel settle
  disposition. Production operators must read the executed proposal state
  and dispatch funds in a follow-up transaction.
- Governance stdlib has no built-in proposer-address enforcement; the
  stdlib uses `proposerKey: uint256` with no link to the message sender.
  Disposition: documented as a mandatory contract-level obligation.
  TosCouncilFund checks `in.senderAddress == storage.proposerAddress`
  before delegating to `slice5GovernanceCreateProposal`; the canonical
  key (1) is an internal sentinel only.

This records the third and final external production-intent adoption
candidate. The Slice 5 external adoption release gate is now complete
(3 of 3 candidates accepted).

## TosEscrowedAuction Trial Result

- **Date:** 2026-05-01
- **Pattern:** `@stdlib/auction`
- **Contract:** `examples/slice5/tos-escrowed-auction/src/tos-escrowed-auction.tol`
- **Status:** accepted with fixes as an additional production-intent
  auction candidate.
- **Tests:** `tos-escrowed-auction-positive.tol` passed 24 cases;
  `tos-escrowed-auction-import-positive.tol` passed 2 cases before
  repo-side hardening.
- **Full report:**
  `examples/slice5/tos-escrowed-auction/TRIAL-REPORT.md`.

The external author built an escrowed English auction for on-chain
assets using `@stdlib/auction`. The trial verified normal bids,
postponed pre-open bids, close/drain/settle, low-bid rejection,
stale-close and duplicate-settle rejection, unknown opcode handling,
imported contract tests, and production-level workarounds for bidder
identity and timestamp integrity.

The trial found nine issues:

- `Slice5AuctionBid.bidder` was caller-controlled and accepted by the
  raw helper. Disposition: `@stdlib/auction` now provides
  `slice5AuctionTrustedBid(...)`,
  `slice5AuctionTrustedBidAt(...)`, `receiveTrustedBid(...)`, and
  `receiveTrustedBidAt(...)`. The reference auction example now uses
  `receiveTrustedBid(config, msg, in.senderAddress)`.
- `msg.now` was caller-controlled and the auction example passed it to
  time-sensitive helpers. Disposition: trusted bid helpers bind time to
  `blockchain.now()`, and the reference example uses `blockchain.now()`
  for close and expire.
- The auction example did not enforce seller identity on close/settle.
  Disposition: `Slice5AuctionState.requireSeller(...)` and
  `SLICE5_AUCTION_THROW_UNAUTHORIZED_SELLER` were added; the reference
  example checks seller identity before close/settle.
- `SLICE5_AUCTION_THROW_QUEUE_FULL` was a dead constant because the
  postponement layer threw `SLICE4_POSTPONEMENT_THROW_QUEUE_FULL`.
  Disposition: `postponeBid` now rethrows queue-full as the auction
  error code.
- Auction settlement had no fund-dispatch helper or scaffolded flow.
  Disposition: `slice5AuctionPayoutMessage(...)` and
  `slice5AuctionEmitPayout(...)` were added, and the author guide/audit
  checklist now require explicit payout dispatch or documented off-chain
  settlement.
- Production receive handlers could not be exercised directly in
  tol-tester with injected `in.senderAddress` and `blockchain.now()`.
  Disposition: repo-side hardening added
  `SmartContract::Args.set_sender_address(...)` and a Slice 5
  receive-context emulator fixture so real lowered `receive` handlers
  can be tested with trusted sender/time context.
- `slice5AuctionDefaultBudget()` was too tight for popular pre-open
  auctions. Disposition: the default budget now allows 16 postponed
  items and the docs point high-traffic auctions at
  `slice5AuctionConfigWithBudget(...)`.
- ABI manifests did not have a first-class `caller_controlled` field
  annotation for values like `now`. Disposition: the Slice 5 ABI schema
  and validator now accept `caller_controlled`, require it to be `true`
  for every inbound message field, and all Slice 5 ABI manifests record
  the annotation.
- `Slice5AuctionExpire` access model was undocumented. Disposition: the
  author guide and audit checklist now state that expire may be called
  by any sender as cooperative cleanup.

This records an additional external production-intent adoption
candidate. The Slice 5 external adoption release gate was already
complete at 3/3; this trial extends coverage to the auction pattern.

## TosReportBondOracle Trial Result

- **Date:** 2026-05-01
- **Pattern:** `@stdlib/oracle`
- **Contract:** `examples/slice5/tos-report-bond-oracle/src/tos-report-bond-oracle.tol`
- **Status:** accepted as an additional production-intent bonded-oracle
  candidate.
- **Tests:** `tos-report-bond-oracle-positive.tol` passed 19 cases;
  `tos-report-bond-oracle-import-positive.tol` passed 4 cases; the
  integrated emulator fixture brings `test-emulator` to 33 passed cases.
- **Full report:**
  `examples/slice5/tos-report-bond-oracle/TRIAL-REPORT.md`.

The external author built a bond-backed oracle where each reporter locks
1 TON per accepted report. The contract deliberately omits `reporterKey`
and `now` from the report wire body, derives reporter identity from
`in.senderAddress`, gates submission with `in.valueCoins`, and uses
`blockchain.now()` for all freshness checks.

The trial exposed pre-existing production-candidate defects:

- `TosStreamChannel` used caller-controlled `msg.now` for cooperative
  close, challenge close, and settle. Disposition: the contract now uses
  `blockchain.now()` and the release checker rejects production
  candidates that access `msg.now`.
- `DexPriceOracle` trusted caller-controlled `msg.reporterKey` and
  `msg.now`. Disposition: the contract now stores reporter addresses,
  derives the canonical reporter key from `in.senderAddress`, uses
  `blockchain.now()`, and records ABI compatibility exceptions for the
  retained wire fields.
- `TosCouncilFund` used caller-controlled `msg.now` in vote, execute,
  and cancel. Disposition: those handlers now pass `blockchain.now()` to
  the governance helpers.
- `TosStreamChannel` recorded closed state but did not dispatch payout.
  Disposition: `@stdlib/payment-channel` now provides
  `slice5PaymentPayoutMessage(...)` and
  `slice5PaymentEmitPayout(...)`; the production candidate saves closed
  state first and then emits the `balanceB` payout.

The new bonded oracle also produced three implementation lessons:

- Emulator fixtures need to be CMake-integrated to count. Disposition:
  `TosReportBondOracle` now has an `@deploy` path and
  `emulator/test/tos-report-bond-oracle-fixture.cpp` runs through the
  shared `test-emulator` target.
- Multiple refund sends are a gas/action-count budget surface.
  Disposition: docs and audit checklist call out the maximum-send budget;
  this candidate emits at most three refunds after finalized state is
  saved.
- `map<uint256, coins>` storage is not yet documented as an audited
  pattern. Disposition: the candidate stores nanoTON bonds as `uint64`
  and records that exception in its ABI manifest.

This records a fifth production-intent candidate and the second oracle
candidate. The release gate was already complete; this trial hardens the
production-candidate acceptance bar by making trusted receive context a
release-checker invariant.
