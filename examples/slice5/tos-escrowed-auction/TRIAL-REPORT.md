# External Author Trial Report — TosEscrowedAuction

**Branch:** `actor-layer`
**Date:** 2026-05-01
**Author role:** External production-intent smart contract author evaluating Tol and the Slice 3/4/5 stdlib.

---

## Maintainer disposition after repo hardening

Accepted as an additional Slice 5 production-intent auction candidate.
The report below is the external author's original finding log; the repo
has since closed the high-impact items in code/docs:

- F-001 / F-002: `@stdlib/auction` now exposes trusted bid helpers that
  bind bidder identity to `in.senderAddress` and production time to
  `blockchain.now()`. The reference auction example uses them.
- F-003: the reference auction example now checks seller identity before
  close/settle using `Slice5AuctionState.requireSeller(...)`.
- F-004: queue-full now rethrows as
  `SLICE5_AUCTION_THROW_QUEUE_FULL` (`0x0b03`), so monitoring can use
  the auction-level error.
- F-005 / F-007 / F-009: payout, budget, and expire-access obligations
  are closed in code and docs. This contract now saves settled state and
  emits the seller payout through `slice5AuctionEmitPayout(...)`; the
  release checker requires that direct-payout pattern. The stdlib also
  raises the default queued-bid budget to 16 and documents open
  `Slice5AuctionExpire` as cooperative cleanup.

Post-trial hardening closed F-006 at the emulator layer:
`SmartContract::Args.set_sender_address(...)` now injects
`in.senderAddress`, `set_now(...)` injects `blockchain.now()`, and
`emulator/test/slice-5-receive-context-fixture.cpp` exercises real
lowered `receive` handlers with forged body fields and trusted VM
context. The tol-tester cases remain useful helper-level simulations.
F-008 is also closed: the checked-in contract annotations now mark every
inbound message field as `caller_controlled: true`.

---

## 1. Contract Summary

| Field | Value |
|---|---|
| **Contract name** | TosEscrowedAuction |
| **Intended production use** | English auction for on-chain assets (NFTs, token lots, governance items). Bidders compete with increasing bids; the seller collects the winning bid at settlement. Real-world targets: in-game item sales, DAO treasury asset auctions, NFT primary sales. |
| **Stdlib package(s) used** | `@stdlib/auction` (backed by `@stdlib/postponement`) |
| **Files created** | `examples/slice5/tos-escrowed-auction/src/tos-escrowed-auction.tol` (152 lines), `tests/tos-escrowed-auction-positive.tol` (26 cases), `tests/tos-escrowed-auction-import-positive.tol` (2 cases), `manifest.json`, `artifacts/opcodes.json`, `artifacts/method-ids.json`, `artifacts/error-codes.json` |
| **Would deploy with real funds?** | **Yes, after repo-side hardening.** Bidder identity and time are bound to trusted VM context, seller-only close/settle is enforced, settlement emits the seller payout directly with bounce-on-action-fail semantics, and the release checker gates these properties. |

---

## 2. Verification Results

**Build/check commands run:**

```sh
# compiler check-only on all three source files
/home/tomi/tos/build/tol/tol --check-only src/tos-escrowed-auction.tol
/home/tomi/tos/build/tol/tol --check-only tests/tos-escrowed-auction-positive.tol
/home/tomi/tos/build/tol/tol --check-only tests/tos-escrowed-auction-import-positive.tol

# full test suite
cd examples/slice5/tos-escrowed-auction && \
  FIFTPATH=/home/tomi/tos/crypto/fift/lib \
  FIFT_EXECUTABLE=/home/tomi/tos/build/crypto/fift \
  TOL_EXECUTABLE=/home/tomi/tos/build/tol/tol \
  python3 /home/tomi/tos/tol-tester/tol-tester.py tests

# whitespace gate
git diff --check
```

| Check | Result |
|---|---|
| `--check-only` on contract source | Clean (no output) |
| `--check-only` on both test files | Clean (no output) |
| tol-tester full run | **2 test files: 2 import cases + 26 positive cases, gas 434,811 — all pass** |
| `git diff --check` | Clean |

**Skipped verification:**

- **Replay fixtures** — not created during the external trial. Post-trial hardening added emulator receive-context coverage with injected `in.senderAddress` and `blockchain.now()`. See F-006.
- **Emulator integration tests** — not run during the external trial. Post-trial hardening added `Slice5ReceiveContext` emulator coverage for production receive handlers with injected `in.senderAddress` and `blockchain.now()`. Tests T510–T512 and T530–T540 remain helper-level simulations. See F-006.

---

## 3. Test Matrix

| Test ID | Scenario | Expected result | Actual result | Security property covered |
|---------|----------|-----------------|---------------|---------------------------|
| T501 | First valid bid accepted; state updated | `highestBid=600` | `600` | Bid acceptance |
| T502 | Second higher bid replaces first | `highestBid=700`, bidder2 | `700` | Bid ordering |
| T503 | Close then settle; winner payout returned | `settled`, payout=`800` | `800` | Payout correctness |
| T504 | Bid exactly at `minBid` accepted | `highestBid=500` | `500` | Boundary value |
| T505 | Postponed bid drains on `closeAndDrain` | `drained=1` | `1` | Postponement queue |
| T506 | Settle returns highest bid amount | `payout=900` | `900` | Payout correctness |
| T510 | Unauthorized close (intruder sender) — seller guard | `4353` | `4353` | Authorization |
| T511 | Authorized close (seller sender) — seller guard | `0` (allowed) | `0` | Authorization |
| T512 | Unauthorized settle (intruder sender) — seller guard | `4353` | `4353` | Authorization |
| T520 | Bid below `minBid` rejected | `2817` (LOW_BID) | `2817` | Bid validation |
| T521 | Bid not higher than current highest rejected | `2817` (LOW_BID) | `2817` | Bid ordering |
| T522 | Bid after auction closes rejected | `2821` (ALREADY_CLOSED) | `2821` | State machine |
| T523 | Close before `closesAt` deadline rejected | `2820` (STALE_CLOSE) | `2820` | Time boundary |
| T524 | Settle before close rejected | `2823` (NOT_CLOSED) | `2823` | State machine |
| T525 | Duplicate settle rejected | `2822` (ALREADY_SETTLED) | `2822` | Replay protection |
| T526 | Duplicate close rejected | `2821` (ALREADY_CLOSED) | `2821` | Replay protection |
| T527 | Exact immediate bid replay rejected without state change | `2817` (LOW_BID) | `2817` | Replay protection |
| T530 | Raw helper accepts caller-provided bidder — production wrapper must override | `1` (forged wins) | `1` | Raw-helper boundary documented; release checker gates production wrappers |
| T531 | Contract bidder override: real sender (`in.senderAddress`) wins | `1` (safe) | `1` | Authorization |
| T540 | `msg.now` spoofing to force early close — safe vs. vulnerable paths | `1` (safe path rejected) | `1` | **Time integrity** |
| T550 | Bid at exactly `closesAt` boundary rejected | `2821` (ALREADY_CLOSED) | `2821` | Boundary value |
| T551 | Close at exactly `closesAt` (boundary) accepted | `1` | `1` | Boundary value |
| T552 | Queue full rethrows auction-level code | `2819` (0x0b03) | `2819` | Queue bound |
| T553 | Oversized postponed bid body rejected without queue mutation | `2308` (0x0904) | `2308` | Storage bound |
| T560 | Unknown opcode yields `0xffff` | `65535` | `65535` | Unknown opcode |
| T570 | Invalid config (`closesAt ≤ opensAt`) rejected at construction | `2824` | `2824` | Config validation |
| T580 | Contract error constants accessible from importer | `1` | `1` | Import |
| T581 | Storage struct fields accessible from importer | `1` | `1` | Import |

> **Note on T552.** The initial trial expected `2819`
> (`SLICE5_AUCTION_THROW_QUEUE_FULL`) and observed `2307` from the
> postponement layer. Post-trial hardening fixed this: queue full now rethrows
> the auction-level code, while T553 separately covers the lower-level
> body-size storage bound (`2308`).

---

## 4. Production-Readiness Findings

### F-001 — `msg.bidder` is completely unchecked in the stdlib

- **Severity:** BLOCKER
- **Area:** security model / stdlib
- **Description:** `Slice5AuctionBid.bidder` is caller-supplied and is never validated against `in.senderAddress` by any stdlib helper. Any sender can forge the `bidder` field and have their bid recorded under an arbitrary address — including the seller's own address, another bidder's address, or the zero address.
- **Why this matters in production:** The winning bidder address is the entity entitled to the auctioned item or refund. If it can be freely forged, the auction outcome is not binding. Test T530 demonstrates that the stdlib `applyBid` function silently accepts a forged address.
- **Workaround used:** Override `msg.bidder` with `in.senderAddress` before calling `state.receiveBid(config, trueBid)`. Applied in the production `receive(msg: Slice5AuctionBid)` handler:
  ```tol
  val trueBid = Slice5AuctionBid {
      queryId: msg.queryId,
      bidder:  in.senderAddress,          // OVERRIDE
      amount:  msg.amount,
      now:     blockchain.now() as uint32, // OVERRIDE (see F-002)
  };
  state.receiveBid(config, trueBid);
  ```
- **Post-trial disposition:** closed. `@stdlib/auction` exposes trusted bid helpers, the standalone auction reference example uses `receiveTrustedBid(...)`, and the Slice 5 release checker rejects production/reference examples that trust `msg.bidder`.

---

### F-002 — `msg.now` is caller-controlled in every Slice 5 message struct

- **Severity:** HIGH
- **Area:** security model / stdlib / docs
- **Description:** Every Slice 5 auction message struct carries `now: uint32` as a caller-supplied field. The stdlib's `closeAndDrain`, `receiveBid`, `settle`, and `expireQueued` all trust this value for every time-sensitive check. A malicious sender can supply `now = 9999999` to close the auction before its deadline, or `now = 0` to force postponement of a bid that should be accepted immediately. `blockchain.now()` is available in Tol (`crypto/smartcont/tol-stdlib/common.tol:403`) and costs nothing to use.
- **Why this matters in production:** Timestamp manipulation is the most exploited DeFi vulnerability class. An auction closed early allows a seller's colluder to be the highest bidder at an artificially low price. The pattern affects all four Slice 5 stdlib packages (auction, oracle, governance, payment-channel); all of them pass `msg.now` directly to time-sensitive helpers.
- **Post-trial disposition:** closed for production/reference paths. The wire fields remain for ABI compatibility, but production/reference examples use `blockchain.now() as uint32`, and the Slice 5 release checker rejects `msg.now` trust in production-intent sources.

---

### F-003 — Seller identity is not enforced in the stdlib auction example

- **Severity:** HIGH
- **Area:** security model / docs / examples
- **Description:** `Slice5AuctionExample.receive(msg: Slice5AuctionClose)` and `receive(msg: Slice5AuctionSettle)` do not check `in.senderAddress`. Any sender can close or settle the auction. `Slice5AuctionExample` is the primary reference an author studies before writing their own contract.
- **Why this matters in production:** Without seller-identity enforcement, any third party can trigger the auction outcome. A griefing attacker can close immediately at `closesAt` before the seller is ready. More critically, `settle()` writes the final state — if called by a non-seller before the seller's intended post-inspection window, the outcome is irrevocable.
- **Workaround used:** Added `if (in.senderAddress != config.seller) throw ESCROWED_AUCTION_THROW_UNAUTHORIZED_SELLER;` at the top of both Close and Settle handlers. Tests T510–T512 verify this guard.
- **Post-trial disposition:** closed. The standalone auction reference example checks seller identity before close/settle, and the author guide/audit checklist require that pattern.

---

### F-004 — `SLICE5_AUCTION_THROW_QUEUE_FULL` (0x0b03) originally was not thrown

- **Severity:** MEDIUM
- **Area:** stdlib / ABI
- **Description:** During the first trial, a full postponement queue threw `SLICE4_POSTPONEMENT_THROW_QUEUE_FULL` (value `0x0903 = 2307`) from deep inside the postponement layer instead of the auction-level `SLICE5_AUCTION_THROW_QUEUE_FULL` (value `0x0b03 = 2819`). Discovered when test T552 was initially written expecting `2819` and failed with `2307`.
- **Why this matters in production:** On-chain error monitoring, off-chain indexers, and client SDK error matchers should subscribe to the auction ABI's own queue-full error code, not a lower-layer implementation detail.
- **Workaround used:** Historical only. The trial initially updated T552 to expect `2307`; post-trial hardening restored the intended auction-level code.
- **Post-trial disposition:** closed. `postponeBid` now catches `SLICE4_POSTPONEMENT_THROW_QUEUE_FULL` and rethrows `SLICE5_AUCTION_THROW_QUEUE_FULL`, making the auction-level error code observable.

---

### F-005 — Payout dispatch has no stdlib support and no scaffold

- **Severity:** MEDIUM
- **Area:** stdlib / docs
- **Description:** In the original trial, `settle()` returned the winning bid amount as `coins` but provided no mechanism to send the funds. The production contract had to record the amount in storage, and fund dispatch was entirely the integrator's responsibility — triggered by reading a getter off-chain and issuing a separate transaction.
- **Why this matters in production:** There is no enforcement that payout ever happens. The auction can reach `settled = true` with funds permanently locked in the contract if the integrator omits the dispatch step. A team unfamiliar with TOS's async action model will implement this incorrectly or incompletely.
- **Workaround used:** Historical only. The first artifact added `pendingPayout: coins` and `payoutDone: bool` fields plus a `getPendingPayout()` getter.
- **Post-trial disposition:** closed. `@stdlib/auction` exposes `slice5AuctionEmitPayout(...)`; the standalone auction reference example and this production-intent external candidate now save the settled state and then emit the seller payout through that helper. The release checker requires the direct-payout path for the external auction candidate.

---

### F-006 — Production receive handlers cannot be exercised in tol-tester

- **Severity:** MEDIUM
- **Area:** tests
- **Description:** The tol-tester runs Tol methods as standalone functions. There is no TVM message context, so `in.senderAddress` and `blockchain.now()` are unavailable. The three most important security properties of this contract — bidder identity, seller identity, and time integrity — live inside receive handlers and cannot be unit-tested directly. Tests T510–T512 and T530–T540 use inline simulation logic instead of calling the actual handlers.
- **Why this matters in production:** The properties least testable are the properties most likely to be wrong. A test that simulates the guard with inline `if (addr != config.seller)` does not prove the handler actually throws — it only proves the arithmetic is correct.
- **Workaround used:** Inline simulation tests with prominent comments: *"exercised via inline logic since the contract entry point cannot be called from tol-tester."*
- **Recommended fix:** The tol-tester should support a message-injection mode that provides a configurable `in.senderAddress` and a simulated `blockchain.now()` for receive handler tests. Until then, add emulator integration tests to the Slice 5 release checklist as a mandatory gate for contracts that use `in.senderAddress` in security-critical paths.
- **Post-trial disposition:** Closed through the SmartContract emulator API rather than tol-tester's get-method runner. `set_sender_address(...)` and `set_now(...)` now populate c7 `INMSG_*` / `NOW` context, and `Slice5ReceiveContext` proves real lowered receive handlers can reject forged body fields while accepting trusted VM context.

---

### F-007 — auction queue budget must be explicit for high-traffic auctions

- **Severity:** LOW
- **Area:** stdlib / docs
- **Description:** The original default postponement budget hardcoded `maxItems: 4`. A production auction with a pre-open marketing phase can easily receive more than four bids before `opensAt`.
- **Why this matters in production:** A popular auction could silently reject valid bids during its pre-open period, causing bidder confusion and potential legal disputes over whether a bid was accepted.
- **Workaround used:** Used `slice5AuctionConfigWithBudget(...)` instead of `slice5AuctionConfig(...)` for deployments expecting more than 4 pre-open bids.
- **Post-trial disposition:** closed for the default path. `slice5AuctionDefaultBudget()` now uses `maxItems: 16`, queue-full rethrows the auction-level code `2819`, and T552 locks the capacity behavior. Authors with higher expected pre-open traffic should still use `slice5AuctionConfigWithBudget(...)` and explicitly budget storage.

---

### F-008 — The `now` field's security contract is invisible in ABI manifests

- **Severity:** LOW
- **Area:** docs / ABI
- **Description:** Every Slice 5 message struct with a `now: uint32` field appears in the ABI manifest as a normal `uint32` field. Nothing in the manifest schema expresses that this field is caller-controlled and must be ignored in production (replaced with `blockchain.now()`). The `wire_compatibility_exceptions` field had to be repurposed to document this.
- **Recommended fix:** Add an `is_caller_controlled: true` flag to the message field schema and require it on `now` fields.
- **Post-trial disposition:** Closed as `caller_controlled: true`. The Slice 5 ABI schema admits the field, the validator requires it for every inbound message field, and all checked-in Slice 5 ABI manifests now carry the annotation.

---

### F-009 — `Slice5AuctionExpire` access model was undocumented during the trial

- **Severity:** NIT
- **Area:** docs
- **Description:** The `Slice5AuctionExpire` handler can be called by any sender. This is correct by design (any party can cooperatively drain the queue), but the original trial could not find that rule in the guide. A first-reading author would assume it needs seller authorization and either restrict it (incorrect) or leave it open with no justification in code comments.
- **Post-trial disposition:** closed. The author guide states that `Slice5AuctionExpire` may remain open to any sender because it is a cooperative cleanup mechanism for stale postponed bids, not a privileged operation.

---

## 5. Documentation Gaps

| Gap | What I searched for | What finally answered it |
|-----|---------------------|--------------------------|
| Is `blockchain.now()` available as a replacement for `msg.now`? | Searched "now", "unix_time", "timestamp" in author guide, audit checklist, compatibility matrix | Closed: the author guide and release checker now require trusted VM time for production receive handlers. |
| Does `msg.bidder` need to be overridden with `in.senderAddress`? | Author guide, audit checklist, compatibility matrix, example source | Closed: the author guide, audit checklist, trusted bid helper, and release checker now require sender-derived bidder identity. |
| What error code does a full postponement queue produce? | Expected `SLICE5_AUCTION_THROW_QUEUE_FULL (0x0b03)` based on auction stdlib constants | Current answer: `2819`. The original trial observed `2307`; post-trial hardening now catches the postponement-layer code and rethrows the auction-level code. |
| How do I dispatch funds after `settle()`? | Author guide auction section | Closed: use `slice5AuctionEmitPayout(config.seller, winningBid)` after saving settled state; this contract and the reference example now use that pattern. |
| What do import-positive test files look like? | No tol-tester documentation for the `*-import-positive.tol` convention | Closed: Slice 5 author guide documents `*-import-positive.tol` as public import-surface smoke tests. |
| How does the tol-tester parse `@testcase` table rows? | Searched docs folder | Closed: Slice 5 author guide documents positive `@testcase` and negative `@compilation_should_fail` / `@stderr` rows. |
| What value does the `bits` field take for `coins` in ABI manifests? | Manifest schema | Closed: Slice 5 author guide and ABI validator doc state that `coins` is `VarUInteger 16`, so `bits: null`. |

---

## 6. API Friction Log

1. **`slice5AuctionConfigWithBudget` was not mentioned in the author guide** — closed. The guide now calls out high-traffic auctions and explicit storage/gas budget tradeoffs.
2. **`blockchain.now()` was not mentioned anywhere in policy docs or author guide** — closed for Slice 5. The guide now requires trusted VM time for production receive handlers and the release checker rejects `msg.now` trust.
3. **Test T552 failed on the first trial run** with `2307` instead of `2819` — required tracing `postponeBid -> queue.enqueueWithQueryId -> PostponedQueue.requireBudget -> SLICE4_POSTPONEMENT_THROW_QUEUE_FULL` through two stdlib files. Post-trial hardening now rethrows `2819`.
4. **ABI manifest `method_id` values** — closed. `scripts/tol-method-id.py` computes the compiler's auto-derived getter id (`crc16(name) | 0x10000`), and the release checker validates the helper.
5. **ABI manifest `bits: null` for variable-length types** — closed. The author guide and ABI validator doc now list when `bits` / `refs` are integers vs. `null`, including `coins`.
6. **No `tol new --pattern auction` in the tested build** — historical trial friction. The Slice 5 release checker now validates the generated auction scaffold.
7. **Error code table had to be assembled manually** from two separate stdlib files (`auction.tol` and `postponement.tol`) — mitigated by checked-in generated artifacts and the release-package validator.
8. **Import test must re-import stdlib dependencies** — closed for docs. The author guide documents explicit non-transitive imports and the `*-import-positive.tol` convention. A more tailored compiler diagnostic would be a future DX improvement, not a production blocker.

---

## 7. Security Review Checklist

| Property | Status | Notes |
|----------|--------|-------|
| **Authorization** | FIXED for production/reference paths | Seller checks use `in.senderAddress`; bidder identity uses `receiveTrustedBid(...)`. The Slice 5 release checker rejects production/reference sources that trust `msg.bidder`. |
| **Replay protection** | HANDLED by auction semantics | Duplicate close/settle throw `ALREADY_CLOSED`/`ALREADY_SETTLED` (T525, T526). Exact immediate bid replay is rejected as `LOW_BID` without state change (T527). Postponed duplicate query IDs are rejected by the Slice 4 queue index. A new higher amount with a reused queryId is treated as a new economic bid, not idempotent replay. |
| **Value transfer / payout correctness** | FIXED | `settle()` returns the highest bid amount. The standalone reference example and this external candidate now save settled state and emit seller payout with `slice5AuctionEmitPayout(...)`; the release checker gates the external candidate path. |
| **Duplicate messages** | HANDLED | Duplicate close/settle throw `ALREADY_CLOSED`/`ALREADY_SETTLED`. Duplicate bids are handled by bid-value comparison, not by `queryId` deduplication. |
| **Malformed messages** | HANDLED | Auto-deserialization via `lazy T.fromSlice` throws on malformed input at the Tol runtime layer. |
| **Expiry / staleness** | FIXED | `msg.now` is caller-controlled and untrustworthy. Production/reference contracts use `blockchain.now()` for all time checks, and the release checker rejects regression. |
| **Unknown opcodes** | HANDLED | `@unknown_throw(0xffff)` covers all unrecognized internal opcodes. |
| **Storage bounds** | FIXED | T553 covers the postponed bid body-size budget and proves an oversized queued body is rejected without mutating the queue. T552 covers queue item capacity. |
| **Bounce / failure behavior** | PROTOCOL DEFAULT | `@disclaim_query_id` on all handlers disables automatic query-id propagation. Failed receives rely on standard TVM bounce behavior; this contract has no custom bounce-only handler. |
| **ABI compatibility** | HANDLED with exceptions | Wire-compatible with `@stdlib/auction` ABI. Two documented exceptions in `wire_compatibility_exceptions`: (1) `msg.bidder` is ignored at the receive-handler layer; (2) `msg.now` is ignored at the receive-handler layer. Both are contract-layer decisions with no impact on wire encoding. |

---

## 8. Final Assessment

### Verdict: PRODUCTION-CANDIDATE AFTER HARDENING

The Tol compiler, `tol-tester`, stdlib, ABI manifest infrastructure, and release package checker all work correctly for this use case. Compilation is clean across all three source files, all 28 test cases pass, and all validator scripts pass.

The original off-chain payout obligation has been removed. Settlement now records the final state and emits the seller payout in the same receive path. Operators should subscribe to `2819` for auction queue-full alerts; `2307` remains the lower-level Slice 4 postponement code for direct postponement users.

---

### Top 3 changes that would most improve Tol for production authors

**1. Make trusted time/identity the default production path.**

Closed for production/reference code. Wire fields remain for compatibility, but trusted helper APIs and release checks make `in.senderAddress` / `blockchain.now()` the enforced production path.

**2. Provide a `slice5AuctionTrustedBid(msg, sender)` constructor that substitutes `bidder = sender` and `now = blockchain.now()`.**

Closed. The trusted bid helpers exist and are used by the standalone auction reference example.

**3. Provide a `slice5AuctionEmitPayout(state, to)` action builder that constructs and sends the winning-bid fund transfer.**

Closed. The payout helper exists, defaults to bounce-on-action-fail semantics, and is used by the standalone auction reference example after state is saved.

---

### Whether this contract should count as an external production-candidate adoption case

**Yes, for the auction pattern.**

The compatibility matrix now records this contract as an external production-intent adoption candidate. The three security findings and the queue-full error-code issue have been addressed in the stdlib, reference examples, docs, and release checker guardrails.
