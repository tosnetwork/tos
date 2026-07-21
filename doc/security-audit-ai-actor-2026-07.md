# AI Actor Contract Family Security Audit (2026-07-21)

## Scope

Manual, file-by-file review of all six native AI-actor TVM contracts, driven by
[ai-actor-threat-model.md](ai-actor-threat-model.md),
[ai-actor-contract-guidelines.md](ai-actor-contract-guidelines.md), and
[ai-actor-testing-matrix.md](ai-actor-testing-matrix.md):

| Contract | File | Lines |
|---|---|---|
| Agent Account | `crypto/smartcont/agent-account-code.fc` | 308 |
| Task Escrow | `crypto/smartcont/task-escrow-code.fc` | 281 |
| Dispute | `crypto/smartcont/dispute-code.fc` | 190 |
| Service Actor | `crypto/smartcont/service-actor-code.fc` | 271 |
| Capability Registry | `crypto/smartcont/capability-registry-code.fc` | 208 |
| Proof Attestation | `crypto/smartcont/proof-attestation-code.fc` | 130 |

This is the dedicated review `doc/security-audit-native-2026-06.md` explicitly
excludes from its scope and that `doc/ai-actor-testing-matrix.md`'s Level-2
release gate lists as "security review complete" — not previously done.

Out of scope: Rust AI-actor tooling/indexers, off-chain agent runners,
`tosctl` wallet CLI, wc=2 (Uno) contracts.

## Remediation status

The 2026-07-21 follow-up closes H1, H2, M1, M2, and M3:

- Task Escrow `settle` and `resolve` require payout-bound attestor signatures;
  `resolve` additionally binds `dispute_hash`.
- Once configured, an attestor cannot be replaced or revoked while a Task
  Escrow or Dispute can still produce a protected outcome. Service Actor
  attestors are immutable because that contract has no terminal lifecycle
  state that proves no paid response remains outstanding.
- Service Actor refunds overpayment and records only `price_per_call` as
  revenue.
- Capability Registry accepts stake only from its owner.
- For a Task Escrow without a verifier, an unchallenged submitted result pays
  the budget to the agent when the review window expires; the creator can no
  longer obtain the result and recover the full budget by refusing to settle.

## Method

Read every contract in full; checked each `recv_internal`/`recv_external` op
against: access control, state-machine correctness, `end_parse()` trailing-data
checks, `bounced` handling, signature domain-binding, balance-vs-bookkeeping
consistency (`get_balance()` checks before payout), and integer bounds. Cross-
referenced every finding against the threat model and guideline docs to
distinguish genuine gaps from already-accepted, documented design choices.

## Findings

### H1 — Task Escrow `resolve()` never checks the attestor signature

**File:** `crypto/smartcont/task-escrow-code.fc:213-228`

When `has_attestor = 1`, `settle()` requires a valid attestor signature over
`result_hash` in addition to sender authorization (lines 143-155). `resolve()`
— the payout path reached via `dispute` → `resolve` — performs the same
`payout <= budget` / `payout <= get_balance()` checks but has **no attestor
check at all**, even when `has_attestor = 1`.

**Impact:** a creator (who alone can trigger `dispute`, `task-escrow-code.fc:203`)
and the verifier (who alone can call `resolve`, line 215) can jointly pay out
any amount without ever producing the attestor's signature — silently
bypassing the one control an agent may be relying on when it saw
`has_attestor = 1` and decided the task was safe to accept.

**Fix direction:** either mirror the `settle()` attestor check inside
`resolve()`, or document explicitly that `resolve()` is an unconditional
authority path that intentionally supersedes the attestor gate (verifier
authority already implies a stronger trust tier than a fast-path attestor
check) — a decision the team should make deliberately, not by omission.

### H2 — Attestor gate is unilaterally revocable by the party it is meant to check

**Files:**
`crypto/smartcont/task-escrow-code.fc:229-251` (`rotate_attestor_key`, `revoke_attestor`, creator-only)
`crypto/smartcont/service-actor-code.fc:240-263` (owner-only)
`crypto/smartcont/dispute-code.fc:160-183` (reviewer-only)

All three ops are gated only by sender identity — **no task/response/ruling
status restriction**. The creator (Task Escrow), owner (Service Actor), or
reviewer (Dispute) can call `revoke_attestor` or `rotate_attestor_key` at any
point in the lifecycle, including immediately before calling `settle`/`respond`/
`rule`, even after the counterparty already relied on `has_attestor = 1` to
decide whether to accept the task/call/case.

**Impact:** for Task Escrow specifically, this means a creator can advertise
an attestor at deploy time (to attract agents that require independent result
verification), then silently `revoke_attestor` right before `settle` and pay
out (or short-pay, or refuse) with no attestation at all. There is no on-chain
signal an agent can check *in advance* that guarantees the attestor
requirement will still be in force at settlement time — the "independent
check" is opt-in for the privileged party, not binding.

This is architecturally consistent (the code comments describe it as
intentional: *"reverts to sender-authorization-only"*), so this is reported
as a **trust-model disclosure gap**, not necessarily a code defect — but
`ai-actor-threat-model.md`'s "Fake Results or Evidence" threat category lists
*"optional verifier actor decision"* as a required control without noting
that it is revocable by the settling party. Agents/UIs that present "this
task has attestor protection" as a binding guarantee would be misleading
users. Recommend: either make attestor configuration immutable once set (or
lockable), or explicitly document in the threat model / message catalog that
`has_attestor` is advisory and revocable, so downstream tooling doesn't
misrepresent it.

**Untested in both directions:** none of `scripts/agent-task-escrow-e2e.py`,
`scripts/service-actor-e2e.py`, `scripts/dispute-e2e.py` exercise
`rotate_attestor_key` or `revoke_attestor` at all — H1 and H2 are both
currently unverified by the existing test suite in either the positive
(attestor correctly blocks unattested settlement) or negative
(revoke-then-settle bypass) direction.

### M1 — Task Escrow: agent has no recourse when `has_verifier = 0`

**File:** `crypto/smartcont/task-escrow-code.fc:134-139, 186-199`

`settle` requires `now() <= review_deadline`; once `review_deadline` passes,
only `timeout` is reachable from `status::result_submitted`, and it refunds
the **entire** budget to the creator regardless of whether the agent's result
was correct — there is no path for the agent to force payment. If
`has_verifier = 0` (no dispute/resolve path available either, since `dispute`
requires `has_verifier`), a creator can costlessly grief any agent by simply
never calling `settle`: submit nothing, let `review_deadline` elapse, reclaim
100% of the budget. `ai-actor-contract-guidelines.md` lists "timeout path is
deterministic" as a required check — it is deterministic, but deterministically
favors the creator with no counterweight when no verifier is configured.

**Recommendation:** at minimum, document this clearly for agent operators
("never accept a Task Escrow task without a configured verifier or attestor
you trust"), since the contract can't unilaterally fix an inherently
two-party trust gap without changing the economic model (e.g., a default
partial-payout-on-timeout policy, which has its own tradeoffs).

### M2 — Service Actor `call`: no refund of overpayment

**File:** `crypto/smartcont/service-actor-code.fc:138-156`

`throw_unless(err::insufficient_payment, msg_value >= price_per_call)` accepts
any `msg_value >= price_per_call`, and `total_revenue += msg_value` credits
the **full** amount — not `price_per_call` — to the owner, with no refund of
the excess to the caller. A caller who overpays (rounding, a wallet's gas-margin
padding, or a client bug) permanently loses the excess.

**Fix direction:** credit only `price_per_call` to `total_revenue` and refund
`msg_value - price_per_call` to the caller (mode 1, `msg_value - price_per_call`),
or explicitly document this as a "pay-what-you-send" model if intentional.

### M3 — Capability Registry `stake`: non-owner stakers have no withdrawal path

**File:** `crypto/smartcont/capability-registry-code.fc:118-127, 156-169`

`stake` is explicitly permissionless ("Anyone may top up the bond"), crediting
`msg_value` to `bond`. Only `withdraw_bond`/`deactivate`, both owner-gated, can
ever move funds back out. A third party who stakes on someone else's registry
entry (e.g. as a counterparty bond, or by mistake) has no way to reclaim their
own contribution — it becomes fully owner-controlled.

**Fix direction:** either restrict `stake` to `owner` only (matching the
"self-bond" framing implied elsewhere), or track per-staker contributions with
a staker-initiated withdrawal path.

### L1 — Agent Account `task_send`: non-bounceable outbound messages

**File:** `crypto/smartcont/agent-account-code.fc:267-275`

Outbound messages to `target` are built with `bounce = false`
(`store_uint(0x10, 6)`). `target` is an arbitrary address chosen in the
off-chain-signed payload with no on-chain validation that it exists or is
correct. A malformed/non-existent target causes silent, unrecoverable loss of
`value` (no bounce-back). Lower severity than a similar pattern also present
in the escrow-family contracts' `send_value` helpers (`task-escrow-code.fc:29-36`,
`service-actor-code.fc:114-121`, `capability-registry-code.fc:95-102`), since
those payout destinations (`creator`/`agent`/`owner`) are always addresses
that already interacted with the contract, not first-use arbitrary targets.

### L2 — Agent Account `policy.default_task_timeout` is decorative

**File:** `crypto/smartcont/agent-account-code.fc:14, 251-254`

`default_task_timeout` is stored in the policy cell and returned by
`get_agent_policy()`, but `recv_external`'s `valid_until` comes entirely from
the signed payload and is never cross-checked against it. If the field is
meant to cap how far in the future a controller-signed message can set
`valid_until`, it currently does not. If it's intentionally informational
(a hint for off-chain tooling constructing the signed payload), worth a
one-line comment saying so to avoid the field being mistaken for an
enforced cap during a future audit.

### L3 — Dispute contract ruling is not atomically linked to Task Escrow settlement

**File:** `crypto/smartcont/dispute-code.fc:1-11` (documented), `task-escrow-code.fc:213-228`

Dispute's own header comment already states it is "a pure adjudication ledger
... a subject contract's own settlement logic ... enforces whatever the
ruling here decides" — i.e. by design, nothing on-chain forces Task Escrow's
`resolve()` payout to match a Dispute contract's ruling for the same case; a
verifier could rule one way in Dispute and pay a different amount in Task
Escrow, since the contracts aren't atomically coupled. Recorded here only so
the operational implication (verifier honesty is still required even with a
Dispute contract deployed) is explicit in one place, alongside H1/M1.

### L4 — No owner-rotation path

Agent Account, Service Actor, and Capability Registry have no
"transfer ownership" op — `owner` is fixed at deploy time. Not a
vulnerability, but losing the owner key permanently locks every owner-gated
function (policy updates, withdrawals, deactivate/reactivate). Worth a
deliberate decision (redeploy-on-loss is acceptable vs. add a
timelocked-owner-rotation op) rather than an oversight.

## What Checked Out Clean

- All six contracts consistently ignore bounced messages (`flags & 1`) and
  call `end_parse()` on every op path — no missed trailing-garbage checks
  (the exact class of bug fixed in the earlier 2026-07 testnet-readiness pass).
- All five attestation/signature checks (Agent Account controller signature;
  Task Escrow, Service Actor, Dispute attestor signatures; Proof Attestation)
  consistently domain-bind to `my_address()` before `check_signature`,
  preventing cross-instance replay.
- `payout <= get_balance().pair_first()` (or the equivalent
  `amount <= get_balance()`) is checked before every value-moving op across
  all contracts (`settle`, `resolve`, `withdraw_revenue`, `withdraw_bond`) —
  the exact class of bug from the 2026-04-26 tos3 audit stays fixed here.
- Task Escrow's state machine has no double-payout path: every payout-capable
  op requires a specific pre-status that the same op transitions away from,
  and no terminal status is a valid precondition for any further payout op.
- `cancel` is restricted to `status::open` only, so accepted work cannot be
  bypassed via cancellation, matching the guideline requirement.
- No coins-overflow, no missing sender checks, no reentrancy risk (TVM's
  transaction model makes the classic EVM check-effects-interactions ordering
  concern moot — `send_raw_message` only enqueues actions dispatched after
  the whole transaction, including `set_data`, completes atomically).

## Recommendation

Do not treat this contract family as "audited" until H1 and H2 are resolved
(fix or explicit documented acceptance) and covered by tests, and M1-M3 are
at minimum documented as known trust-model tradeoffs in
`ai-actor-threat-model.md` and surfaced to agent/operator-facing tooling.
None of these are memory-safety or double-spend bugs — they are all either
missing symmetry in an existing control (H1) or privileged-party trust-model
gaps that are easy for a counterparty to misjudge (H2, M1-M3). That is a
materially better starting point than the 2026-04-26 tos3 EVM audit's open
Critical findings, but it is not yet a clean bill of health for a family that
directly custodies user funds.
