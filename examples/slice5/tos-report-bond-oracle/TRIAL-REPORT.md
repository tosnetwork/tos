# External Author Trial Report — Slice 5 Second Trial

**Contract built:** `TosReportBondOracle`
**Pattern used:** `@stdlib/oracle`
**Trial date:** 2026-05-01
**Branch:** `actor-layer`
**Author role:** external production-intent contract author

---

## Executive Summary

This is the second external production-intent trial of the Slice 5 stdlib on the
`actor-layer` branch. The contract built is `TosReportBondOracle`, a bond-backed
price oracle where reporters must lock 1 TON per report submission. The contract
deliberately exercises `in.senderAddress`, `in.valueCoins`, and `blockchain.now()` — 
the three TVM context values that cannot be tested in tol-tester — and adds an
emulator fixture to verify all three.

During the pre-work phase (reading existing production-intent examples before
building), **three pre-existing CRITICAL/HIGH issues were found in already-shipped
contracts**: `TosStreamChannel` and `DexPriceOracle` used caller-controlled `msg.now`
for time-sensitive operations; `DexPriceOracle` used caller-controlled `msg.reporterKey`
for reporter identity. They are preserved below as historical findings and are now
closed by the repo-side hardening passes.

**Repo-side disposition:** all findings from this report are closed in the
follow-up hardening commit. Prior production candidates now use
`blockchain.now()` and sender-derived identity, payment-channel payout emission is
explicit, `TosReportBondOracle` is integrated into `test-emulator`, and
the production candidate checks reject contracts that trust `msg.now`,
`msg.reporterKey`, or raw regular-mode value dispatch. The same checks also
compile and validate the standalone Slice 5 reference examples, including safe
governance/oracle identity derivation and explicit auction/payment-channel
payout helpers.

---

## Scope

Files created in this trial:

```
examples/slice5/tos-report-bond-oracle/
  src/tos-report-bond-oracle.tol              (contract source)
  tests/tos-report-bond-oracle-positive.tol   (19 tol-tester tests)
  tests/tos-report-bond-oracle-import-positive.tol (4 import tests)
  manifest.json
  artifacts/opcodes.json
  artifacts/method-ids.json
  artifacts/error-codes.json
emulator/test/tos-report-bond-oracle-fixture.cpp (integrated SmartContract fixture)
```

Pre-existing files reviewed and found to have issues:

```
examples/slice5/tos-stream-channel/src/tos-stream-channel.tol
examples/slice5/dex-price-oracle/src/dex-price-oracle.tol
examples/slice5/tos-council-fund/src/tos-council-fund.tol
```

---

## Findings

### F-B001 — CRITICAL: `TosStreamChannel` uses caller-controlled `msg.now` for all time checks

**File:** `examples/slice5/tos-stream-channel/src/tos-stream-channel.tol`
**Lines:** 33, 43, 53

```tol
// Line 33 — cooperative close:
state.cooperativeClose(config, signedState, msg.signatureA, msg.signatureB, msg.now);
// Line 43 — challenge close:
state.challengeClose(config, signedState, msg.signatureA, msg.signatureB, msg.now);
// Line 53 — settle:
state.settle(msg.now);
```

The stdlib `cooperativeClose` calls `requireWellFormed(config, now)` which checks
`validUntil <= now` — if `msg.now` is spoofed small, a state with a past `validUntil`
is accepted. The stdlib `challengeClose` uses `now` to compute
`challengeExpiresAt = now + challengeWindow` — a caller who sets `msg.now` to a very
large value can extend the challenge window arbitrarily, locking out the counterparty
from settling. The stdlib `settle` checks `now < challengeExpiresAt` — a caller who
sets `msg.now` to a large value can bypass the challenge window and settle immediately.

**Impact:** An attacker with one valid signature set can replay stale signed states or
skip the challenge window entirely by choosing `msg.now` freely. Channel funds may be
drained or locked.

**Fix:** Replace all three `msg.now` arguments with `blockchain.now() as uint32`. The
`now` wire field in `Slice5PaymentCooperativeClose`, `Slice5PaymentChallengeClose`, and
`Slice5PaymentSettle` is caller-controlled and must not drive production time-sensitive
decisions. These messages should carry `blockchain.now()` as documentation only, or the
field should be annotated `wire_compatibility_exception: used_for_testing_only`.

**Post-trial disposition:** closed. `TosStreamChannel` now passes
`blockchain.now() as uint32` to cooperative close, challenge close, and settle. The
Slice 5 release checker rejects production candidates that trust `msg.now`.

---

### F-B002 — HIGH: `DexPriceOracle` uses caller-controlled `msg.reporterKey` and `msg.now`

**File:** `examples/slice5/dex-price-oracle/src/dex-price-oracle.tol`

```tol
// In the DexPriceReport receive handler:
val oracleReport = Slice5OracleReport {
    queryId: msg.queryId,
    roundId: msg.roundId,
    reporterKey: msg.reporterKey,  // caller-controlled
    value: msg.priceNano,
    now: msg.now,                  // caller-controlled
};
round.addReport(state.reporterSet, config, oracleReport);
```

`msg.reporterKey` is a caller-controlled wire field. Any sender can set it to any
authorized reporter key, submitting a report on behalf of another reporter. The oracle's
duplicate-reporter check fires on the key, not the sender, so an attacker who submits
with key `0x01` (reporter 1's key) before reporter 1 can block reporter 1 from ever
reporting in that round. With a 2-of-3 quorum, this can stall finalization.

`msg.now` is also caller-controlled and drives the round freshness check in `addReport`
and `finalize`. A caller who sets `msg.now = 0` bypasses the staleness check and
submits to an expired round.

The start-round handler passes `in.senderAddress` correctly to `slice5OracleStartRound`,
but the price report handler trusts `msg.reporterKey` — an inconsistency within the
same contract.

**Fix:** Derive reporter identity from `in.senderAddress` via a contract-level address
registry (as `TosCouncilFund` does for voters). The contract must maintain a
`reporterAddress → reporterKey` map. Use `blockchain.now()` for all time fields in the
`Slice5OracleReport` and `Slice5OracleFinalize` built internally.

**This trial's contract (`TosReportBondOracle`) demonstrates the correct approach:**
the `BondOracleSubmitReport` wire message has NO `reporterKey` or `now` field, making
it structurally impossible for callers to forge either value.

**Post-trial disposition:** closed. `DexPriceOracle` derives reporter identity from
`in.senderAddress`, uses `blockchain.now()`, and now routes through
`addTrustedReport(...)` / `finalizeTrusted(...)`. The Slice 5 release checker rejects
production oracle paths that trust `msg.reporterKey`, trust `msg.now`, or call raw
`addReport(...)` / `finalize(...)`.

---

### F-B003 — HIGH: `TosCouncilFund` uses `msg.now` in vote, execute, and cancel handlers

**File:** `examples/slice5/tos-council-fund/src/tos-council-fund.tol`

```tol
// Vote handler:
proposal.vote(voterKey, msg.support, msg.now);

// Execute handler:
proposal.execute(policy, msg.now);

// Cancel handler:
proposal.cancel(policy, COUNCIL_PROPOSER_KEY, msg.now);
```

The stdlib `requireActive(now)` checks `validUntil <= now`. If `msg.now` is spoofed to
zero, an expired proposal can be voted on, executed, or canceled regardless of the
actual blockchain time. If `msg.now` is spoofed large, a proposal that is still active
appears expired and cannot proceed.

The propose handler passes `now=0` to `createProposal`, making the only time check
`msg.validUntil > 0`. This means the proposer can set an arbitrarily long `validUntil`.
Combined with a spoofed `msg.now=0` in the vote handler, proposals never expire from
the voter's perspective.

**Fix:** Use `blockchain.now() as uint32` in all three handlers. The `validUntil`
parameter in `Slice5GovernancePropose` is caller-controlled (the proposer chooses the
deadline), which is acceptable by design — but the `now` parameter passed to lifecycle
helpers must be the chain time, not `msg.now`.

**Post-trial disposition:** closed. `TosCouncilFund` now uses `blockchain.now() as
uint32` for vote, execute, and cancel; it derives voter/proposer authority from
`in.senderAddress`. The standalone governance reference example was moved to the same
pattern and is now checked by the release package gate.

---

### F-B004 — HIGH: `TosStreamChannel` does not dispatch payout after cooperative close or settle

**File:** `examples/slice5/tos-stream-channel/src/tos-stream-channel.tol`
**Lines:** 33, 53

Both `cooperativeClose` and `settle` return `balanceB` (the amount owed to partyB), but
the contract discards the return value and never sends any funds:

```tol
// cooperativeClose returns balanceB — return value silently discarded:
state.cooperativeClose(config, signedState, msg.signatureA, msg.signatureB, msg.now);
save(TosStreamChannelStorage { config: storage.config, state: state.toCell() });

// settle returns balanceB — return value silently discarded:
state.settle(msg.now);
save(TosStreamChannelStorage { config: storage.config, state: state.toCell() });
```

After the close/settle transaction completes, partyB's funds remain locked in the
contract forever unless a separate off-chain mechanism dispatches them. The contract
comments say "Deployer must dispatch the balanceB payout to partyB after this call" but
there is no getter exposing `balanceB` or `partyB`, so the deployer has no way to read
these values without parsing raw contract storage.

At the time of the trial the ABI manifest lacked any off-chain settlement policy
entry (`tos_stream_channel.json` had `"wire_compatibility_exceptions": []`).

**Fix:** Either (a) use `slice5AuctionEmitPayout`-style explicit send after saving
state, or (b) add getters for `balanceB` and `config.partyB` and document the off-chain
settlement policy in `wire_compatibility_exceptions`.

**Post-trial disposition:** closed. `TosStreamChannel` stores `partyBAddress`, captures
the returned `balanceB`, saves the closed state, and then calls
`slice5PaymentEmitPayout(...)`. The standalone payment-channel reference example now
does the same and is checked by the release package gate.

---

### F-B005 — MEDIUM: Emulator fixture originally required manual CMake integration

**File:** `emulator/test/tos-report-bond-oracle-fixture.cpp`

The SmartContract emulator test fixture requires:
1. Moving the `.cpp` file to `emulator/test/`
2. Adding a CMake target that compiles the Tol contract to a `.boc` file
3. Defining the `TOS_REPORT_BOND_ORACLE_BOC` preprocessor constant

**Post-trial disposition:** closed. The fixture was moved to `emulator/test/`, the
contract BoC is built by the top-level CMake target, `TOS_REPORT_BOND_ORACLE_BOC` is
defined for `test-emulator`, and `examples/slice5/tos-report-bond-oracle/manifest.json`
declares the integrated emulator fixture. The Slice 5 release checker now validates
that declared emulator fixtures exist, are marked `integrated`, target `test-emulator`,
and are wired into `CMakeLists.txt`. The original reporter-set-hash blocker was
removed at the root: deployment builds `Slice5OracleConfig` inside Tol, so C++ no
longer hard-codes `reporterSetHash`.

---

### F-B006 — MEDIUM: Finalize handler sends up to 3 messages in one transaction — gas budget originally undocumented

**File:** `examples/slice5/tos-report-bond-oracle/src/tos-report-bond-oracle.tol`
**Line range:** finalize handler

After `round.finalize()` succeeds, the handler dispatches up to 3 bond refund messages
in the same transaction (one per reporter that submitted). TOS contracts pay gas for
each outgoing message. With 3 reporters all bonding 1 TON each and a contract balance
of ~5 TON, the action phase could generate 3 SEND actions totaling 3 TON + ~3× gas.

If the contract has insufficient balance to cover gas, the action phase may fail silently
(with `SEND_MODE_REGULAR`, failed sends are ignored — the error is not propagated to the
caller). Reporters could fail to receive their refunds without any on-chain signal.

**Fix options:**
1. Use `SEND_MODE_PAY_FEES_SEPARATELY` so each send's fee comes from the reporter's
   refund amount rather than the contract balance.
2. Add a `claimBond` handler so each reporter claims their refund individually
   (one message → one send per transaction).
3. Document the required minimum contract balance and add a getter for it.

**Post-trial disposition:** closed. `@stdlib/oracle` now exposes
`slice5OracleEmitBondRefund(...)`, defaulting to
`SEND_MODE_BOUNCE_ON_ACTION_FAIL`. `TosReportBondOracle` uses it for every bond
refund, and production candidate checks reject contracts that dispatch value
with raw regular-mode sends.

---

### F-B007 — MEDIUM: `coins` cannot be used as a `map` value type — bond stored as `uint64`

**File:** `examples/slice5/tos-report-bond-oracle/src/tos-report-bond-oracle.tol`

During implementation I attempted `bonds: map<uint256, coins>`. It is unclear from
the documentation whether `coins` is a valid map value type. Existing stdlib maps use
`map<uint256, bool>` and `map<uint256, uint64>` only. To be safe, the bond amount is
stored as `uint64` (nanoTON), limiting the representable bond to ~18,446 TON.

**Friction:** The `map<K, V>` type section in `common.tol` does not list which value
types are supported. A type error from using `coins` would appear at compile time, not
at write time — but it is not discoverable without running the compiler.

**Post-trial disposition:** closed. `map<uint256, coins>` is covered by the
compiler test suite (`maps-tests.tol` method 146) and documented in the Slice 5
author guide. `TosReportBondOracle` may still use `uint64` nanoTON deliberately
because it wants an explicit ~18,446 TON maximum.

---

### F-B008 — LOW: Oracle stdlib `addReport` uses `report.now` (caller-provided)

**File:** `crypto/smartcont/tol-stdlib/oracle.tol`
**Line:** 225

```tol
fun Slice5OracleRound.addReport(..., report: Slice5OracleReport): uint16 {
    self.requireOpen(report.now);  // uses caller-provided report.now
    ...
}
```

The `Slice5OracleReport` struct has a `now: uint32` field that the stdlib uses for the
freshness check. Any contract that builds a `Slice5OracleReport` from wire data
(including the `msg.now` wire field) without overriding `now` will have a callable
time bypass.

`DexPriceOracle` has this bug (F-B002). `TosReportBondOracle` avoids it by:
1. Removing the `now` wire field entirely from `BondOracleSubmitReport`
2. Building the `Slice5OracleReport` internally with `blockchain.now()`:

```tol
val trustedReport = Slice5OracleReport {
    ...
    now: blockchain.now() as uint32,
};
```

**Suggestion:** Add a `slice5OracleTrustedReport(msg, sender, now)` helper analogous to
`slice5AuctionTrustedBid(msg, sender)`, or deprecate the `now` field in
`Slice5OracleReport` in favor of a `slice5OracleReportWithNow` constructor that always
uses `blockchain.now()`.

**Post-trial disposition:** closed. `slice5OracleTrustedReport(...)`,
`Slice5OracleRound.addTrustedReport(...)`, `slice5OracleTrustedFinalize(...)`, and
`Slice5OracleRound.finalizeTrusted(...)` are present, and production candidates are
gated by the release checker against trusting `msg.now` or `msg.reporterKey`.

---

## What the TosReportBondOracle Contract Demonstrates

The contract was built specifically to exercise areas that no existing Slice 5 example
covers:

### 1. `in.valueCoins` as a hard gate (new, not in any prior example)

```tol
receive(msg: BondOracleSubmitReport) {
    if ((in.valueCoins as int) < BOND_ORACLE_MIN_BOND) {
        throw BOND_ORACLE_THROW_INSUFFICIENT_BOND;
    }
    ...
}
```

This is the first Slice 5 production-intent contract to gate state mutation on the
incoming message value. The emulator fixture verifies this with `set_amount()`.

**Post-trial disposition:** closed. The Slice 5 author guide now documents the
minimum-value gate idiom, including `(in.valueCoins as int) >= MIN_BOND`, and the
release checker validates that this guidance remains present.

### 2. Reporter identity from `in.senderAddress` with no `reporterKey` wire field

The `bondOracleResolveKey` helper maps `address → uint256` key exactly as
`councilResolveVoterKey` does for governance. By omitting `reporterKey` from the wire
message entirely, there is nothing for a caller to forge.

### 3. `blockchain.now()` replacing all `now` wire fields

All three message types (`BondOracleStartRound`, `BondOracleSubmitReport`,
`BondOracleFinalize`) have no `now` field. The contract builds stdlib structs
internally with `blockchain.now() as uint32`:

```tol
val trustedReport = Slice5OracleReport {
    queryId: msg.queryId,
    roundId: msg.roundId,
    reporterKey,
    value: msg.value,
    now: blockchain.now() as uint32,
};
```

### 4. Explicit payout dispatch after state save

Bond refunds are dispatched after `save()`:

```tol
save(TosReportBondStorage { ..., bonds: createEmptyMap<uint256, uint64>() });
// Dispatch after commit:
bondOracleRefundBond(bondsSnapshot, 1, addrs.reporter1);
bondOracleRefundBond(bondsSnapshot, 2, addrs.reporter2);
bondOracleRefundBond(bondsSnapshot, 3, addrs.reporter3);
```

---

## Emulator Coverage

The fixture in `tests/tos-report-bond-oracle-emulator.cpp` covers:

| Test | TVM context injected | What it proves |
|---|---|---|
| `InsufficientBondThrows` | `set_amount(kBelowMinBond)` | in.valueCoins gate works |
| `InsufficientBondThrows` (pass) | `set_amount(kMinBond)` | exact boundary accepted |
| `UnknownSenderThrowsUnauthorized` | `set_sender_address(attacker)` | sender gate works |
| `BlockchainNowControlsFreshness` (pass) | `set_now(69)` | report within window accepted |
| `BlockchainNowControlsFreshness` (fail) | `set_now(70)` | report at expiry is stale |
| `WrongStarterThrowsUnauthorized` | `set_sender_address(attacker)` | starter guard works |

**Post-trial disposition:** integrated. The fixture deploys through the real Tol
`@deploy` handler instead of hard-coding nested storage cells, so the reporter-set hash
is computed by the stdlib path under test. `test-emulator` runs this fixture as part of
the normal emulator gate.

---

## API Friction Log

1. **`coins` vs `int` comparison** — closed. `(in.valueCoins as int) < BOND_ORACLE_MIN_BOND`
   works and the author guide now shows the production minimum-value check pattern.

2. **`map<uint256, coins>` validity unknown** — closed. `map<uint256, coins>` is
   compiler-tested and documented as supported. This contract still uses `uint64`
   nanoTON intentionally to cap bonds at ~18,446 TON.

3. **Emulator storage initialization** — closed. The fixture sends the real deploy body
   and lets the Tol contract build `TosReportBondStorage`, avoiding manual nested-cell
   construction and reporter-set-hash constants.

4. **No `tol-tester` injection for `in.valueCoins`** — Tests T618 and T619 simulate
   the receive-handler guards inline because tol-tester cannot inject message value.
   Comments in those tests explain why the emulator fixture is the authoritative test.

5. **`save()` followed by `send()` pattern undocumented** — closed. The Slice 5
   author guide now states that `save(...)` may be followed by payout/refund actions
   and records the production order: validate → save finalized state → emit
   helper-backed outbound actions.

---

## Test Coverage Summary

| Test ID | Category | Expected result |
|---|---|---|
| T601 | Authorization | 4865 (UNAUTHORIZED) |
| T602–T604 | Authorization | 1, 2, 3 (key resolution) |
| T605 | Happy path | 1050 (2-of-3 quorum median) |
| T606 | Stale | 3332 (STALE_ROUND) |
| T607 | Duplicate | 3330 (DUPLICATE_REPORTER) |
| T608 | Unauthorized reporter | 3329 (UNAUTHORIZED_REPORTER) |
| T609 | Outlier | 3333 (OUTLIER) |
| T610 | Replay | 3334 (REPLAYED_ROUND) |
| T611 | Pre-quorum finalize | 3331 (INSUFFICIENT_QUORUM) |
| T612 | Double finalize | 3336 (ROUND_FINALIZED) |
| T613 | Wrong starter | 3338 (UNAUTHORIZED_STARTER) |
| T614 | Boundary quorum | 1050 (passes) |
| T615 | Three reporters | 1000 (median) |
| T616 | Truncating median | 1001 (floor division) |
| T617 | Boundary deviation | 2 (exactly at max) |
| T618 | Bond guard (inline) | 4866 (INSUFFICIENT_BOND) |
| T619 | No round guard (inline) | 4867 (NO_ACTIVE_ROUND) |
| T680–T683 | Import | 1, 2, 1, 1 |
| E1–E5 | Emulator | integrated in `test-emulator`; deploy/start, value gate, sender identity, trusted freshness, finalize refund cleanup |

---

## Maintainer Disposition Notes

| Finding | Severity | Recommendation |
|---|---|---|
| F-B001 TosStreamChannel msg.now | CRITICAL | Closed: production source uses `blockchain.now()` and release checker rejects `msg.now` trust |
| F-B002 DexPriceOracle msg.reporterKey + msg.now | HIGH | Closed: address-derived reporter identity plus trusted oracle helpers; release checker rejects raw oracle receive paths |
| F-B003 TosCouncilFund msg.now | HIGH | Closed: vote/execute/cancel use `blockchain.now()` and sender-derived authority |
| F-B004 TosStreamChannel no payout dispatch | HIGH | Closed: payment-channel payout helper dispatches after saved closed state; reference example is gated |
| F-B005 Emulator CMake workflow | MEDIUM | Closed: integrated CMake fixture declared in manifest and validated by release checker; reporter-set hash is computed by Tol deploy path |
| F-B006 Multi-send gas budget | MEDIUM | Closed: bond refunds use `slice5OracleEmitBondRefund(...)` with bounce-on-action-fail; release checker rejects raw `SEND_MODE_REGULAR` sends |
| F-B007 coins map value type | MEDIUM | Closed: `map<uint256, coins>` has compiler coverage and docs; bounded `uint64` remains an intentional contract choice |
| F-B008 stdlib addReport uses report.now | LOW | Closed: trusted report/finalize helpers exist and release checker rejects caller-controlled time/identity in production candidates |
