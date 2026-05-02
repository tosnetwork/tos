# VestingVault — External Developer Trial Report

**Branch:** actor-layer
**Date:** 2026-05-01
**Developer role:** External smart-contract author (no compiler internals knowledge assumed)

---

## What was built and why it's realistic

A **token vesting vault** that holds TOS coins and releases them to a beneficiary on a linear schedule with an optional cliff period. The owner can revoke before completion; every claim requires a Slice 6 capability grant signed by the owner, preventing an escaped beneficiary key from draining the vault.

This is a real DeFi primitive. Team token vesting, investor unlocks, DAO contributor grants — all use this pattern. The interesting Slice 6 aspects are:

- **State machine**: `Pending → Active → Closed` with separate receive paths per state.
- **`@stdlib/time`**: `Slice6WallClockBudget.requireDurationWithinBudget` used to validate that the vest period is within a sane wall-clock bound (≤ 3 years), without mixing seconds into masterchain-seqno scheduler fields.
- **`@stdlib/capability`**: `Slice6CapabilityRegistry.requireCapability` gates every claim. Single-use nonces prevent replay; handle revocation lets the owner invalidate a compromised grant.

## Post-trial hardening applied

The trial findings were converted into repo guardrails:

- `save({ ...storage, x: y })` now compiles and the vault source uses it
  for storage updates; `save(storage)` is used for state-only transitions.
- `blockchain.currentMcSeqno()` / `currentMcSeqno()` now expose the trusted
  TVM `PREVMCBLOCKS` masterchain seqno surface. The vault no longer feeds
  `blockchain.now()` into Slice 6 `*McSeqno` capability fields.
- `@stdlib/safe-payments` now provides payout, refund, and
  retained-balance helpers. The vault refunds funding excess, uses
  bounce-on-action-fail payout defaults, and checks retained balance before
  sending claim/revoke payouts.
- `@stdlib/time` now separates scheduler block budgets from wall-clock
  application duration budgets. The vault uses `Slice6WallClockBudget`
  for vesting seconds, and the Slice 6 release checker rejects regressing
  this external trial back to `Slice6TimerBudget.maxFutureHorizonBlocks`.
- State-qualified receives can now reuse the same wire message across
  different states. The compiler lowers them as one opcode branch with an
  inner state dispatch, while still rejecting duplicate handlers for the
  same `(opcode, state)` pair.
- The vault declares `@implicit_protocol_default;` and per-receiver
  `@disclaim_query_id` markers, so standalone `tol --check-only` is clean
  and the sparse state matrix is intentional rather than accidental.
- `slice6TimerBudget(...)` is marked `@pure`, and parameter defaults may now
  call helper functions at call-site evaluation time.
- Release-package guardrails now scan Slice 6 examples and external trials
  for Unix-time-to-mc-seqno misuse and unsafe `SEND_MODE_REGULAR` value
  dispatch.

---

## Files created

```
examples/external-trials/vesting-vault/
├── src/vesting-vault.tol            — contract source (332 lines)
├── tests/vesting-vault-positive.tol — test file (14 test cases)
├── manifest.json
├── artifacts/
│   ├── opcodes.json
│   └── error-codes.json
└── TRIAL-REPORT.md (this file)
tol-tester/tests/vesting-vault-positive.tol   — tol-tester entry point (imports from examples)
```

---

## Commands run and results

### 1. Build tol compiler
```
cmake --build /home/tomi/tos/build --target tol -j 32
```
Result: clean build, 4/4 steps.

### 2. Run tol-tester
```
cd /home/tomi/tos/tol-tester && \
  FIFTPATH=/home/tomi/tos/crypto/fift/lib \
  FIFT_EXECUTABLE=/home/tomi/tos/build/crypto/fift \
  TOL_EXECUTABLE=/home/tomi/tos/build/tol/tol \
  python3 tol-tester.py tests vesting-vault
```
Result: **14/14 cases pass, gas 132954.**

### 3. Standalone contract check
```
/home/tomi/tos/build/tol/tol --check-only \
  examples/external-trials/vesting-vault/src/vesting-vault.tol
```
Result: clean; zero errors and zero warnings.

### 4. Whitespace check
```
cd /home/tomi/tos && git diff --check
```
Result: clean (no output).

---

## Test list and pass count

| ID  | Test name                              | What it covers                                       | Result |
|-----|----------------------------------------|------------------------------------------------------|--------|
| 801 | vested_before_cliff_is_zero            | Happy path: zero before cliff                        | PASS   |
| 802 | vested_linear_after_cliff              | Happy path: linear vesting math                      | PASS   |
| 803 | vested_caps_at_total                   | Happy path: full vest cap                            | PASS   |
| 804 | claimable_minus_claimed                | Happy path: progressive claim accounting             | PASS   |
| 805 | wall_clock_budget_fields               | `@stdlib/time` wall-clock budget construction        | PASS   |
| 806 | cap_wrong_sender_rejected              | Authorization failure                                | PASS   |
| 807 | cap_nonce_replay_rejected              | Replay / duplicate handling                          | PASS   |
| 808 | cap_expired_rejected                   | Malformed input (time-expired grant)                 | PASS   |
| 809 | cap_revoked_handle_rejected            | Handle-level revocation                              | PASS   |
| 810 | horizon_rejects_too_long_vest          | Value/budget boundary: vest period too long          | PASS   |
| 811 | horizon_accepts_max_boundary           | Value/budget boundary: boundary is inclusive         | PASS   |
| 812 | cap_storage_full_rejected              | Registry storage exhaustion (budget guard)           | PASS   |
| 813 | cap_wrong_selector_rejected            | Malformed input: selector mismatch                   | PASS   |
| 814 | partial_claim_leaves_remainder         | Integration edge case: progressive partial claims    | PASS   |

**14 / 14 pass.**

---

## Original findings and closure status

| Finding | Original impact | Current status |
|---------|-----------------|----------------|
| `save({ ...storage, x: y })` rejected at `...` | Multi-field storage updates required full boilerplate copies. | **Closed.** Object-literal spread is implemented in lexer, AST, type inference, checks, and lowering; the vault source now uses spread saves. |
| `@pure` helper could not call `slice6TimerBudget(...)` | Pure fixture/config helpers had to drop `@pure`. | **Closed.** `slice6TimerBudget(...)` is now marked `@pure`; the hardening tests cover a pure helper that calls it. |
| Function default parameters rejected helper calls | Test fixtures needed no-arg wrapper boilerplate. | **Closed.** Parameter defaults may call global helpers at call-site evaluation time. Defaults still cannot capture the function's own parameters. |
| No trusted masterchain seqno surface | Authors used `blockchain.now()` as a semantic proxy for `*McSeqno` fields. | **Closed.** `blockchain.currentMcSeqno()` / `currentMcSeqno()` use TVM `PREVMCBLOCKS`; release checks reject `blockchain.now()` flowing into Slice 6 mc-seqno APIs. |
| Seconds were bounded with scheduler block budget fields | `Slice6TimerBudget.maxFutureHorizonBlocks` was reused for a vesting period measured in seconds, creating a silent unit confusion risk. | **Closed.** `Slice6WallClockBudget` now represents bounded application durations in seconds; VestingVault uses it, and the Slice 6 release checker rejects regression to scheduler block fields. |
| Same message type could not be used in multiple states | A realistic state machine needs `VaultRevoke` in both `Pending` and `Active`; ordinary duplicate-opcode rejection made the standalone contract fail. | **Closed.** The compiler now permits same-struct, state-qualified opcode overloads and lowers them to opcode-plus-state dispatch. Duplicate handlers for the same state still fail. |
| Funding excess locked in `VaultFund` | Overpayment stayed in the vault forever. | **Closed.** `@stdlib/safe-payments` provides `slice6RefundExcess*`; the vault refunds excess funding. |
| Claim/revoke payouts used `SEND_MODE_REGULAR` | Action-phase payout failure could silently lose value. | **Closed.** Safe payment helpers default to `SEND_MODE_BOUNCE_ON_ACTION_FAIL`; Slice 5 payout helpers now use the same safer default. |
| No minimum retained-balance guard | Repeated partial claims could starve rent. | **Closed.** `slice6RequireMinimumBalanceAfterPayout` and `slice6ReserveMinimumBalance` are documented and used before payouts. |
| `Cell<T>`, nested parsing, and trusted time docs required source-grepping | Authors had to infer patterns from stdlib source. | **Closed.** The Slice 6 author guide now documents typed cells, lazy parsing boundaries, and trusted time access. |
| Exhaustiveness warning suppression is O(states × messages) | Correct warnings are noisy for intentionally invalid state/opcode pairs. | **Closed.** `@implicit_protocol_for(Message, State)` handles precise pairs; `@implicit_protocol_default;` handles intentional sparse matrices; VestingVault uses the default marker and now checks cleanly standalone. |
| `contract.getAddress()` in `@deploy` is not available | Deploy handlers cannot self-reference without explicit input. | **Closed.** `contract.getAddress()` is explicitly supported in `@deploy` because it lowers to `MYADDR` and does not read c4; `contract-deploy-get-address-positive.tol` locks the behavior. |

---

## Where Tol felt better than Tact/FunC

1. **State machine compiler enforcement.** The `states: Pending, Active, Closed` + `receive(msg: X) on State` + `become`/`keep_state` pattern is genuinely ergonomic. The compiler catches missing transitions at compile time. In FunC this is 50 lines of manual flag-checking. In Tact there's no native state machine. This is Tol's strongest feature.

2. **Error classification built in.** `require(cond, ErrorClass.Authorization, 0x2001)` is cleaner than `throw_unless(0x2001, cond)` in FunC, and the class annotation means tooling can distinguish auth failures from protocol errors without parsing throw codes. The 3-arg form with explicit codes is exactly what a production contract needs.

3. **Capability stdlib completeness.** `Slice6CapabilityRegistry.requireCapability` is a high-quality one-call authorization check that handles sender binding, nonce replay, handle revocation, and epoch revocation. Writing this by hand in FunC would be 150+ lines. The API surface is well-designed.

4. **`@unknown_throw` annotation.** Being able to declare unknown-opcode behavior at the contract level rather than writing a manual `else throw 0xffff` at the bottom of every dispatch ladder is cleaner and less prone to accidental omission.

5. **Compile-time method_id collision detection.** The compiler caught a method_id collision in another test during the same session. FunC provides zero such checking.

---

## Remaining ergonomics below production ideal

1. **Exhaustiveness warning verbosity.** **Closed.** `@implicit_protocol_for(Message, State)` now suppresses one intentional known-opcode/wrong-state path, and `@implicit_protocol_default;` suppresses the whole sparse matrix for contracts that intentionally rely on the synthesized Protocol path.

2. **Deploy-time self-address ergonomics.** **Closed.** `contract.getAddress()` is supported inside `@deploy`; only storage/c4 reads remain banned before `loadData()`.

---

## Final verdict

**Post-hardening status: production-candidate.**

The contract compiles, all 14 VestingVault tests pass, and the original critical/high findings are closed in code, compiler checks, tests, or release checks.
