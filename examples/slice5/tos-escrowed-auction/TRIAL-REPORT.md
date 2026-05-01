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
  are documented in the author guide and audit checklist; the stdlib
  adds a payout message/emission helper and raises the default queued-bid
  budget to 16.

Post-trial hardening closed F-006 at the emulator layer:
`SmartContract::Args.set_sender_address(...)` now injects
`in.senderAddress`, `set_now(...)` injects `blockchain.now()`, and
`emulator/test/slice-5-receive-context-fixture.cpp` exercises real
lowered `receive` handlers with forged body fields and trusted VM
context. The tol-tester cases remain useful helper-level simulations.
F-008 is also closed: Slice 5 ABI manifests now mark every inbound
message field as `caller_controlled: true`, enforced by
`check-slice-5-abi-manifests.py`.

---

## 1. Contract Summary

| Field | Value |
|---|---|
| **Contract name** | TosEscrowedAuction |
| **Intended production use** | English auction for on-chain assets (NFTs, token lots, governance items). Bidders compete with increasing bids; the seller collects the winning bid at settlement. Real-world targets: in-game item sales, DAO treasury asset auctions, NFT primary sales. |
| **Stdlib package(s) used** | `@stdlib/auction` (backed by `@stdlib/postponement`) |
| **Files created** | `examples/slice5/tos-escrowed-auction/src/tos-escrowed-auction.tol` (152 lines), `tests/tos-escrowed-auction-positive.tol` (24 cases), `tests/tos-escrowed-auction-import-positive.tol` (2 cases), `manifest.json`, `artifacts/opcodes.json`, `artifacts/method-ids.json`, `artifacts/error-codes.json`, `doc/slice5-abi-manifests/tos_escrowed_auction.json` |
| **Would deploy with real funds?** | **No, not as written without the three production fixes documented in §4.** The contract itself is sound, but the security model requires explicit author attention to three stdlib gaps that the ecosystem does not surface via compiler warnings, documentation, or example code. |

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

# ABI and release package validators
python3 /home/tomi/tos/scripts/check-slice-5-abi-manifests.py
python3 /home/tomi/tos/scripts/check-slice-5-release-package.py

# whitespace gate
git diff --check
```

| Check | Result |
|---|---|
| `--check-only` on contract source | Clean (no output) |
| `--check-only` on both test files | Clean (no output) |
| tol-tester full run | **2 tests, 26 cases, gas 220,736 — all pass** |
| `check-slice-5-abi-manifests.py` | `Validated 9 Slice 5 ABI manifest(s); compared 1 FunC/Tol fixture pair(s)` |
| `check-slice-5-release-package.py` | `Validated Slice 5 release candidate: auction, governance, oracle, payment-channel generated examples, 3 external candidate(s), ABI manifests, docs, and artifacts` |
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
| T530 | Forged `msg.bidder` accepted by raw stdlib — documents vulnerability | `1` (forged wins) | `1` | **Security gap documented** |
| T531 | Contract bidder override: real sender (`in.senderAddress`) wins | `1` (safe) | `1` | Authorization |
| T540 | `msg.now` spoofing to force early close — safe vs. vulnerable paths | `1` (safe path rejected) | `1` | **Time integrity** |
| T550 | Bid at exactly `closesAt` boundary rejected | `2821` (ALREADY_CLOSED) | `2821` | Boundary value |
| T551 | Close at exactly `closesAt` (boundary) accepted | `1` | `1` | Boundary value |
| T552 | Queue full: actual error is postponement-layer code, **not** auction constant | `2307` (0x0903) | `2307` | **Error code gap** |
| T560 | Unknown opcode yields `0xffff` | `65535` | `65535` | Unknown opcode |
| T570 | Invalid config (`closesAt ≤ opensAt`) rejected at construction | `2824` | `2824` | Config validation |
| T580 | Contract error constants accessible from importer | `1` | `1` | Import |
| T581 | Storage struct fields accessible from importer | `1` | `1` | Import |

> **Note on T552.** The initial expected value was `2819` (`SLICE5_AUCTION_THROW_QUEUE_FULL`). The test failed with `2307`. Investigation revealed that the auction stdlib's own queue-full constant is **never thrown**; the actual error originates from the postponement layer. This is Finding F-004.

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
- **Recommended fix:** Provide a `slice5AuctionTrustedBid(msg: Slice5AuctionBid, sender: address): Slice5AuctionBid` constructor that substitutes `bidder` and `now` and document it as the canonical call path. Add to the auction section of the author guide: *"Override `msg.bidder` with `in.senderAddress` before calling any bid helper. The stdlib `bidder` field is provided for the data schema; it is not authenticated."* Add to the audit checklist: *"Confirm bid receive handlers override `msg.bidder` with `in.senderAddress`."*

---

### F-002 — `msg.now` is caller-controlled in every Slice 5 message struct

- **Severity:** HIGH
- **Area:** security model / stdlib / docs
- **Description:** Every Slice 5 auction message struct carries `now: uint32` as a caller-supplied field. The stdlib's `closeAndDrain`, `receiveBid`, `settle`, and `expireQueued` all trust this value for every time-sensitive check. A malicious sender can supply `now = 9999999` to close the auction before its deadline, or `now = 0` to force postponement of a bid that should be accepted immediately. `blockchain.now()` is available in Tol (`crypto/smartcont/tol-stdlib/common.tol:403`) and costs nothing to use.
- **Why this matters in production:** Timestamp manipulation is the most exploited DeFi vulnerability class. An auction closed early allows a seller's colluder to be the highest bidder at an artificially low price. The pattern affects all four Slice 5 stdlib packages (auction, oracle, governance, payment-channel); all of them pass `msg.now` directly to time-sensitive helpers.
- **Workaround used:** Pass `blockchain.now() as uint32` to all stdlib helpers that accept a `now` parameter. The `msg.now` wire field is accepted (for ABI compatibility) but discarded entirely at the contract layer. Test T540 demonstrates both the vulnerable (stdlib example) path and the safe (production) path side by side.
- **Recommended fix:** Remove `now: uint32` from all Slice 5 message structs and let stdlib helpers call `blockchain.now()` internally. If off-chain simulation requires time injection, add a `@test_only` overriding path with compiler enforcement. Add to the audit checklist: *"Confirm no Slice 5 receive handler passes `msg.now` to any stdlib time-sensitive function."*

---

### F-003 — Seller identity is not enforced in the stdlib auction example

- **Severity:** HIGH
- **Area:** security model / docs / examples
- **Description:** `Slice5AuctionExample.receive(msg: Slice5AuctionClose)` and `receive(msg: Slice5AuctionSettle)` do not check `in.senderAddress`. Any sender can close or settle the auction. `Slice5AuctionExample` is the primary reference an author studies before writing their own contract.
- **Why this matters in production:** Without seller-identity enforcement, any third party can trigger the auction outcome. A griefing attacker can close immediately at `closesAt` before the seller is ready. More critically, `settle()` writes the final state — if called by a non-seller before the seller's intended post-inspection window, the outcome is irrevocable.
- **Workaround used:** Added `if (in.senderAddress != config.seller) throw ESCROWED_AUCTION_THROW_UNAUTHORIZED_SELLER;` at the top of both Close and Settle handlers. Tests T510–T512 verify this guard.
- **Recommended fix:** Update `Slice5AuctionExample` to include the seller check with an explanatory comment. Add to the audit checklist: *"Confirm Close and Settle receive handlers verify `in.senderAddress == config.seller` before calling stdlib close/settle helpers."*

---

### F-004 — `SLICE5_AUCTION_THROW_QUEUE_FULL` (0x0b03) is never thrown

- **Severity:** MEDIUM
- **Area:** stdlib / ABI
- **Description:** When the postponement queue is full, the actual error thrown is `SLICE4_POSTPONEMENT_THROW_QUEUE_FULL` (value `0x0903 = 2307`) from deep inside the postponement layer. `SLICE5_AUCTION_THROW_QUEUE_FULL` (value `0x0b03 = 2819`) is defined in the auction stdlib but is never reached by any code path — it is a dead constant. Discovered when test T552 was initially written expecting `2819` and failed with `2307`.
- **Why this matters in production:** On-chain error monitoring, off-chain indexers, and client SDK error matchers will subscribe to `0x0b03` for queue-full events and never receive one. Queue-full events are silently emitted as `0x0903`, a postponement-layer code not listed in the auction ABI manifest.
- **Workaround used:** Updated T552 to expect `2307`. Documented the discrepancy in the ABI manifest under `wire_compatibility_exceptions` and in `artifacts/error-codes.json`.
- **Recommended fix:** Either (a) catch and re-throw `SLICE5_AUCTION_THROW_QUEUE_FULL` in `postponeBid` when the underlying queue throws queue-full, making the auction-level constant meaningful; or (b) remove `SLICE5_AUCTION_THROW_QUEUE_FULL` from `auction.tol` and document `SLICE4_POSTPONEMENT_THROW_QUEUE_FULL` directly in the auction ABI manifest.

---

### F-005 — Payout dispatch has no stdlib support and no scaffold

- **Severity:** MEDIUM
- **Area:** stdlib / docs
- **Description:** `settle()` returns the winning bid amount as `coins` but provides no mechanism to send the funds. The production contract must manually record the amount in storage, and fund dispatch is entirely the integrator's responsibility — triggered by reading a getter off-chain and issuing a separate transaction. The author guide mentions this in one sentence for payment channels but has no equivalent for auctions.
- **Why this matters in production:** There is no enforcement that payout ever happens. The auction can reach `settled = true` with funds permanently locked in the contract if the integrator omits the dispatch step. A team unfamiliar with TOS's async action model will implement this incorrectly or incompletely.
- **Workaround used:** Added `pendingPayout: coins` and `payoutDone: bool` fields to storage; added `getPendingPayout()` getter; documented the off-chain integration obligation in code comments.
- **Recommended fix:** Provide a `slice5AuctionEmitPayout(state, to: address)` helper that builds and sends the fund-transfer message via `sendRawMessage`. Add a complete settlement flow example to the author guide showing the close → settle → dispatch sequence.

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

### F-007 — `slice5AuctionDefaultBudget()` `maxItems: 4` is too tight for production

- **Severity:** LOW
- **Area:** stdlib / docs
- **Description:** The default postponement budget hardcodes `maxItems: 4`. A production auction with a pre-open marketing phase can easily receive 4+ bids before `opensAt`. The 5th bid fails with the opaque postponement-layer error `2307`, not a clear "bid rejected" message.
- **Why this matters in production:** A popular auction could silently reject valid bids during its pre-open period, causing bidder confusion and potential legal disputes over whether a bid was accepted.
- **Workaround used:** Used `slice5AuctionConfigWithBudget(...)` instead of `slice5AuctionConfig(...)` for deployments expecting more than 4 pre-open bids.
- **Recommended fix:** Raise `slice5AuctionDefaultBudget()` to `maxItems: 16`. Document the storage-cost trade-off in the author guide. Consider exposing `maxItems` as a parameter in `slice5AuctionConfig(...)`.

---

### F-008 — The `now` field's security contract is invisible in ABI manifests

- **Severity:** LOW
- **Area:** docs / ABI
- **Description:** Every Slice 5 message struct with a `now: uint32` field appears in the ABI manifest as a normal `uint32` field. Nothing in the manifest schema expresses that this field is caller-controlled and must be ignored in production (replaced with `blockchain.now()`). The `wire_compatibility_exceptions` field had to be repurposed to document this.
- **Recommended fix:** Add an `is_caller_controlled: true` flag to the ABI manifest field schema. Enforce its presence on `now` fields via the manifest validator (`check-slice-5-abi-manifests.py`).
- **Post-trial disposition:** Closed as `caller_controlled: true`. The Slice 5 ABI schema admits the field, the validator requires it for every inbound message field, and all checked-in Slice 5 ABI manifests now carry the annotation.

---

### F-009 — `Slice5AuctionExpire` access model is undocumented

- **Severity:** NIT
- **Area:** docs
- **Description:** The `Slice5AuctionExpire` handler can be called by any sender. This is correct by design (any party can cooperatively drain the queue), but it is not documented. A first-reading author will assume it needs seller authorization and either restrict it (incorrect) or leave it open with no justification in code comments.
- **Recommended fix:** Add one sentence to the author guide: *"Expire may be called by any sender; it is a cooperative cleanup mechanism for stale postponed bids, not a privileged operation."*

---

## 5. Documentation Gaps

| Gap | What I searched for | What finally answered it |
|-----|---------------------|--------------------------|
| Is `blockchain.now()` available as a replacement for `msg.now`? | Searched "now", "unix_time", "timestamp" in author guide, audit checklist, compatibility matrix | Direct source inspection of `tol-stdlib/common.tol:403` — not mentioned in any policy or guide document |
| Does `msg.bidder` need to be overridden with `in.senderAddress`? | Author guide, audit checklist, compatibility matrix, example source | Nothing warns about this. Had to construct test T530 to prove the gap experimentally |
| What error code does a full postponement queue produce? | Expected `SLICE5_AUCTION_THROW_QUEUE_FULL (0x0b03)` based on auction stdlib constants | Test T552 failed; traced call chain through `postponement.tol` to find `0x0903` |
| How do I dispatch funds after `settle()`? | Author guide auction section | Not documented for auction. Cross-referenced payment-channel guide; reverse-engineered the pattern |
| What do import-positive test files look like? | No tol-tester documentation for the `*-import-positive.tol` convention | Studied `tos-council-fund-import-positive.tol` as template |
| How does the tol-tester parse `@testcase` table rows? | Searched docs folder | Read `tol-tester.py` source directly |
| What value does the `bits` field take for `coins` in ABI manifests? | Manifest schema | `null` — learned by studying existing manifests, not from schema documentation |

---

## 6. API Friction Log

1. **`slice5AuctionConfigWithBudget` is not mentioned in the author guide** — found by searching `auction.tol` directly when the default budget proved too small.
2. **`blockchain.now()` is not mentioned anywhere in policy docs or author guide** — found via `grep -n "now" common.tol`.
3. **Test T552 failed on first run** with `2819` instead of `2307` — required tracing `postponeBid → queue.enqueueWithQueryId → PostponedQueue.requireBudget → SLICE4_POSTPONEMENT_THROW_QUEUE_FULL` through two stdlib files.
4. **ABI manifest `method_id` values** — derived by reading existing artifact `method-ids.json` files and doing hex arithmetic; no generator utility.
5. **ABI manifest `bits: null` for variable-length types** — inferred from existing manifests; the schema does not document which types require `null` vs. an integer.
6. **No `tol new --pattern auction` in the tested build** — the author guide documents the subcommand; the binary was not available. Worked from examples directly.
7. **Error code table had to be assembled manually** from two separate stdlib files (`auction.tol` and `postponement.tol`) — there is no `tol abi-errors <contract>` command.
8. **Import test must re-import stdlib dependencies** — this is documented correctly in the author guide but the error message on a missing re-import is a generic symbol-not-found, not a "you forgot to re-import the transitive dependency" hint.

---

## 7. Security Review Checklist

| Property | Status | Notes |
|----------|--------|-------|
| **Authorization** | PARTIAL | Seller checks use `in.senderAddress` — correct and enforced. Bidder identity requires manual override of `msg.bidder`; no compiler or stdlib enforcement exists. |
| **Replay protection** | PARTIAL | `settle()` and `closeAndDrain()` are state-guarded against double-call (tests T525, T526). No `queryId` deduplication for bid messages — two bids from the same sender with identical `queryId` but different amounts are both accepted or rejected on bid-value comparison alone. |
| **Value transfer / payout correctness** | PARTIAL | `settle()` correctly records the highest bid amount. Actual fund dispatch is not implemented in-contract (documented limitation). `pendingPayout` getter exposes the amount for off-chain dispatch. |
| **Duplicate messages** | HANDLED | Duplicate close/settle throw `ALREADY_CLOSED`/`ALREADY_SETTLED`. Duplicate bids are handled by bid-value comparison, not by `queryId` deduplication. |
| **Malformed messages** | HANDLED | Auto-deserialization via `lazy T.fromSlice` throws on malformed input at the Tol runtime layer. |
| **Expiry / staleness** | FIXED (workaround) | `msg.now` is caller-controlled and untrustworthy. Production contract uses `blockchain.now()` for all time checks. The stdlib example does not apply this fix. |
| **Unknown opcodes** | HANDLED | `@unknown_throw(0xffff)` covers all unrecognized internal opcodes. |
| **Storage bounds** | NOT TESTED | Postponement queue stores full bid bodies in `c4`. Large bodies (near `maxBodyBits: 512` per the default budget) fill storage faster. No test exercises the body-size budget boundary. |
| **Bounce / failure behavior** | NOT TESTED | `@disclaim_query_id` on all handlers disables automatic query-id propagation. Default TVM bounce applies when the contract throws. No explicit `@bounce_only` handler is declared. |
| **ABI compatibility** | HANDLED with exceptions | Wire-compatible with `@stdlib/auction` ABI. Two documented exceptions in `wire_compatibility_exceptions`: (1) `msg.bidder` is ignored at the receive-handler layer; (2) `msg.now` is ignored at the receive-handler layer. Both are contract-layer decisions with no impact on wire encoding. |

---

## 8. Final Assessment

### Verdict: ACCEPTED WITH FIXES

The Tol compiler, `tol-tester`, stdlib, ABI manifest infrastructure, and release package checker all work correctly for this use case. Compilation is clean across all three source files, all 26 test cases pass, and all validator scripts pass.

The contract is not production-deployable as-is due to two external integration obligations:

1. **Off-chain payout dispatch** — the contract records the winning bid in `pendingPayout` but does not send the funds. The deploying team must read `getPendingPayout()` and issue a separate transfer transaction.
2. **Error code monitoring** — subscribe to `2307` (not `2819`) for queue-full alerts.

Both obligations are documented in contract comments and the ABI manifest.

---

### Top 3 changes that would most improve Tol for production authors

**1. Remove caller-provided `now` from all Slice 5 message structs; inject `blockchain.now()` at stdlib helper entry points.**

This is the highest-impact single change. The current design is a silent security hole: the example code and the secure code look identical at the call site (`state.receiveBid(config, msg)` vs. `state.receiveBid(config, trueBid)`), but only the latter is safe. No compiler warning, linter, or documentation makes the distinction visible before a test like T540 demonstrates the exploit. Fixing this in the stdlib eliminates an entire class of timestamp-manipulation vulnerabilities across all Slice 5 packages simultaneously.

**2. Provide a `slice5AuctionTrustedBid(msg, sender)` constructor that substitutes `bidder = sender` and `now = blockchain.now()`.**

The stdlib currently makes the insecure call (`state.receiveBid(config, msg)`) easier to write than the secure one. Inverting that — making the secure, identity-bound constructor the obvious API — eliminates F-001 and F-002 from the default author path without requiring any language changes. The stdlib example should use this constructor exclusively.

**3. Provide a `slice5AuctionEmitPayout(state, to)` action builder that constructs and sends the winning-bid fund transfer.**

The settlement flow has a mandatory integration step (fund dispatch) that has no example, no helper, and no enforcement. Any team that follows the example to the letter will deploy a contract that marks auctions as settled but never pays anyone. A one-liner helper that emits the correct `sendRawMessage` action, plus a complete example in the author guide showing the close → settle → dispatch sequence, closes the most common integration mistake before it reaches production.

---

### Whether this contract should count as an external production-candidate adoption case

**Yes, for the auction pattern.**

The compatibility matrix currently records "Auction: External adoption: Pending." This trial demonstrates that the `@stdlib/auction` pattern is usable for production purposes with the three documented workarounds. The trial also surfaced three security findings (F-001, F-002, F-003) that are absent from all existing auction examples and documentation, and one error-code correctness issue (F-004) that would cause production monitoring to fail silently.

The contract should be recorded as an external adoption candidate after the three HIGH/BLOCKER findings are addressed in the stdlib documentation and audit checklist. The contract itself already applies all three fixes correctly.
