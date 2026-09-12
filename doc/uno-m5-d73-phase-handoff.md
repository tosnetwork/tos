# D73 phase-transition handoff

Specification: memo 45e8491e, SHA256
3b4413b390f43969fcee6d47cd80c6aee8c347a736d52a6a6bc9d7292526eb6d.
Read-only review plus prospective controls. No Native phase transition was run.
Existing frozen accounting predictions remain unchanged.

## Existing boundary and identified difference

`check_workchain_withdrawal_record` in
`crypto/block/workchain-withdrawal-codec.h:183-187` checks phase range,
phase-0 zero removal height, phase-1 removal height >= opened_height, and
checked settlement deadline capacity. It does not read an authenticated queue.
D73 requires a STRICTLY higher observation height: equality still passes the
current codec predicate and is insufficient for a valid transition under D73.
The host transition must enforce that relation; align the codec's structural
height check when implementing D73. This review does not change either check
or classify caller errors. Codec acceptance is not phase authorization.

`block.tlb:143` describes phase 0 as still queued. Treat phase 0 as the recorded
stage before authenticated removal observation, not proof that every later
queue snapshot still contains the payout. Late reporting is explicitly allowed.
No schema field asserting earliest removal is needed or justified.

## Observation slice and actual execution paths

Observe the authenticated, committed account control envelope/W record and the
actual Native outbound queue produced by the same prepare batch. Match the
exact payout message, custody source and recorded created_lt; an unrelated
message in the queue does not establish this record's prerequisite. An emitted
action or proposed effects entry is not by itself a committed enqueue.

Execute Native prepare including action/batch commit, then the actual phase-0
to phase-1 host transition against an authenticated queue observation at height
h1 strictly greater than opened height h0. Validate that the referenced queue
belongs to the asserted height and relevant shard context. Observe W record
phase, queue_removed_height and captured settlement_blocks after validation and
installation. Queue removal alone must not issue a receipt, advance the system
sequence or release W/P/N accounting; separately attributed settlement events
must not be confused with the phase transition.

The prepare pairing is established at creation, not reconstructed from absence
at phase 1. Historical availability/error classification remains the caller's
responsibility; do not convert unavailable queue data into authenticated absence.

## Construction carrier clarification (Coordinator ruling)

D73(a)'s prior-presence premise is carried by prepare's same-batch generation
of the payout message and W record, with the actual created_lt, rather than a
separate downstream assertion. No legal separated history has been identified:
a trusted orphan cannot be manufactured to claim an independent control.
Controls 1–2 below retain their original prospective wording; they do not
represent executed separated-presence controls. Later queue membership under
D73(b), including the observed `PHASE_QUEUE_BINDING` red, is a different property.

Construction regression coverage is still unestablished. The staged
`PHASE_PAIRED_ENQUEUE` observation reads the actual post-prepare queue and record,
but is not registered and has not rejected a real producer mutation that omits,
delays or changes the identity of that enqueue. It is therefore not a continuous
regression guard. Track this unguarded construction with the Coordinator's
appendix I.4 architecture gaps; do not treat the assertion's existence, a
synthetic observation mutation, or gap five's overlay reasoning as its discharge.
The phase slot remains open pending the remaining controls and combined run.

## Exact controls to attach to the Native fixture

1. **Paired creation:** commit a real prepare and verify its payout is in the
   produced authenticated outbound queue and its matching W record is installed
   in the same batch. Mutate preparation to retain the record but omit enqueue.
   The prepare pairing assertion must fail, before phase 1 or Paid is considered.
   Also abort the action/batch stage and verify no orphan W record is installed.
2. **Not absence alone:** feed an absent queue together with an orphan proposed
   record from control 1. It must not establish successful phase transition by
   treating absence as proof of prior enqueue. Reach the appropriate actual
   candidate validation boundary; do not install the orphan as trusted history
   using a test-only bypass and call that normal production reachability.
3. **Still present:** after genuine paired preparation, at h1>h0 keep that exact
   payout in the authenticated queue. Propose phase 1 with removal height h1.
   The queue-presence verification must reject the proposal. Removing that
   verification in isolation must make the designated negative assertion fail.
4. **Equal/earlier height:** propose h1=h0 and h1<h0 with otherwise suitable
   inputs. Require the strict-height check to reject. Change it to >= in an
   isolated implementation and require the equality control to turn red.
   Distinguish this from the current codec-only >= check identified above.
5. **True later observation:** establish paired prepare, then genuine absence
   at h1>h0, and separately at h2>h1. Each observation can support its own valid
   proposal starting from a phase-0 predecessor; no earliest-absence search is
   required. Do not mutate an already installed phase-1 record to postpone its
   deadline. Its origin record's settlement_blocks remains the captured value.
6. **Wrong observation:** a different message's absence, wrong queue root or
   wrong-height binding cannot establish this payout's absence. Mutate each
   association separately and require the corresponding validation assertion.
7. **Deadline:** compute checked(h_observed + recorded_settlement_blocks).
   A later truthful observation moves this prospective deadline later, never
   earlier. Overflow is an error. This is a settlement policy deadline, not a
   network delivery guarantee or proof of recipient credit.

Run each negative only after the corresponding valid setup reaches the actual
transition. Record exact failure stage, restore green, then disable the tested
oracle in isolation: its mutation driver must fail when the expected red is
lost. Missing host adapter is pending, not a passed control. Do not retire A's
prepare guard merely because settlement or phase-1 code has appeared.

## Relation to the sequence handoff

`uno-m5-sequence-handoff.md` assumes an authenticated associated open Attempt.
That prerequisite now explicitly includes control 1's paired prepare, rather
than a W record synthesized without its payout. For window-close Paid issuance,
controls 3-7 establish the phase/deadline prerequisite. Failed association still
uses its authenticated bounce/Attempt path; this addendum does not require
Paid-style window expiry before accepting an in-window Failed return.

These controls supplement, not replace, the six sequence successor tests. No
new mandatory CTest registration is claimed here while their Native adapters
remain unavailable. This is a precise implementation handoff, not evidence of
complete authenticated queue validation or M5 host compliance.

## D74 supplementary control 8: open record, expired window

Specification: memo 614abc00, SHA256
1df942bd8a8dae0b6a37de30e03041b4497daa06341cfb9ffe207ac94f06f6f2.
This supplements the earlier contract; it does not change its evidence version
or report a completed test. Paid evaluation occurs on the owner's next account
touch, not automatically at the deadline. Earlier references to window-close
Paid issuance must be read with that lazy trigger, not as a timer callback.

**Actual execution setup:** use control 1's paired Native prepare and a valid
D73 phase-1 transition. Read the authenticated record's removal height hr and
captured settlement interval L. Compute d=checked(hr+L), then choose an actual
bounce import height hb=checked(d+1). Missing configuration or arithmetic
overflow is not permission to invent a value. Do not include an owner-touch
operation between phase 1 and the observed bounce event. Independently read
that the Withdrawal record still exists immediately before importing the bounce.
Do not manufacture an orphan open record instead of running prepare.

Import at custody a genuinely associated bounced payout envelope with the
matching Attempt identity. All matching prerequisites other than arrival time
must succeed, so an identity mismatch cannot accidentally satisfy this test.
Use explicit authenticated policy and sufficient slots for the intended late
return path; observe and report any separate admission rejection rather than
counting it as evidence of temporal routing.

**Observation slice:** compare the committed matching W record (including its
original, consumed and refundable reserve amounts), W/P accounting and custody
branch result before/after this isolated bounce event. Require the outside-window
path, delta W=delta P=0, no reserve consumption/top-up and no Failed termination
of the still-open record. Do not assert that all account balances or pending
entries stay unchanged: a late return may legitimately issue a new system
receipt from its own carried value, with its own fees and sequence consumption.
It must not obtain funds from this record's reserve. Reconstruct these deltas
from authenticated artifacts, not merely a supplied branch label.

**Designated mutation:** in an isolated host source copy replace the height
comparison with "record is open" as the eligibility predicate for the in-window
return path. Preserve matching, fees and all other setup. Require the test to
reach the time-routing boundary and fail on the outside-window routing and/or
unchanged-W/P/reserve assertions. A build failure, unavailable history or earlier
unrelated admission failure does not count. Restore and require green; disable
the designated oracle in isolation and require the mutation driver to fail when
its expected red disappears.

**Separate owner-touch observation:** subsequently execute the owner's qualifying
operation to evaluate the still-open record. Attribute any Paid closure and
reserve issuance to that event, not retroactively to bounce arrival. If batching
both events in one test, retain their individual authenticated event cuts; a net
block delta cannot prove that the bounce itself left W/P unchanged. Reaching d
without owner action is not itself a Paid transition.

This control deliberately uses hb>d; it does not independently decide the
exact-deadline equality convention. Its pending status is unchanged until the
actual Native late-return and owner-touch adapters execute. No host implementation,
consensus classification or frozen accounting prediction is changed here.

## Supplementary control 9: authenticated Withdrawal operation-fee floor

Authority: coordinator instruction citing memo d8c6b463 / specification SHA256
prefix cf7f0f4569e2638e, D28 and D64. This is a prospective host acceptance
contract, not another cryptographic relation or a completed test. Implementer:
A; independent expected behavior: B. This adds to, not replaces, the six
sequence successor contracts and the preceding phase/late-return controls.

**Fixture:** execute the real Native Withdrawal prepare admission and candidate
validation paths on committed authenticated account/configuration roots. Supply
an explicit positive authenticated billing floor

    f_required = checked(f_state + checked(base_compute * withdrawal_billing_units))
    f_low = checked(f_required - 1)

Take each component from the active authenticated tariff, with Withdrawal's
no-pending state-fee rule (D65), not SEND's slot fee or proof-work units. The
fixture must identify the tariff's source/version and supply any conditionally
unfrozen inputs explicitly as test configuration; do not create defaults.
If these inputs or the real prepare adapter are absent, report NOT_READY rather
than substituting a standalone constructor test. Require f_required>0.

Choose a registered open account with sufficient balance, actual authenticated
owner key, unconsumed nonce, available Withdrawal capacity and valid destination.
Ensure checked T=x+q+b and both T+f_required and T+f_low fit the chosen balance
and existing relation bounds. Keep all other admission requirements valid. Build
a distinct valid proof for EACH fee using uno/prover and the corresponding new
balance/context. In particular, do not edit f in an existing proof: the changed
transcript would make it fail cryptographically, concealing the missing host
fee check. Both proofs must independently pass the existing kernel verifier.
This verifies a setup prerequisite; it does not authorize either fee at host.

**Two positive/negative routes:**

1. Against the same predecessor, the f_required candidate must pass the fee
   check and complete the otherwise valid prepare. Decode the actual custody
   payout and account update; record that the path was not bypassed.
2. The independently proof-valid f_low operation must be refused by the host
   authenticated-fee comparison, before publishing prepare state or sending
   payout. Record the named diagnostic and admission stage, not just is_error.
   Do not count a failed kernel proof, unrelated limit or unavailable state as
   this expected rejection.
3. Independently submit a candidate that CLAIMS successful execution of that
   underpriced prepare to validator reconstruction. It must not be accepted
   as a valid successful prepare. Under D28 this claimed execution is
   CandidateInvalid; distinguish it from a valid block representing a protocol
   rejection. Do not infer block invalidity merely from operation rejection.

**Observation slice:** authenticated account/control/pending roots and counts,
auth_nonce, new Withdrawal/Attempt records, W/P/R/N bookkeeping, custody and
coordinator Native balances, actual outbound queue/messages, and event-attributed
D32 fee components. For the refused prepare require no accepted prepare debit,
no nonce consumption by that refused operation, no W/P creation, no installed
Withdrawal, no pending installation and no emitted payout. Observe separately
any legitimate enclosing rejection effects; do not demand that unrelated block
activity vanish. An effects proposal or constructor fee() getter is not this
committed-state evidence. Capture both producer refusal and validator result.

**Exact red mutation:** in an isolated host source copy bypass ONLY the
comparison of submitted f with the independently reconstructed authenticated
floor. Keep proof verification, normal amount/payout checks and D32 routing.
The proof-valid f_low input must reach the removed comparison's successor. The
acceptance test must turn red because underpriced success is no longer refused,
or because the designated admission-stage assertion is missing. If a later
independent fee check still rejects it, record that redundant protection and
its exact stage; do not claim the entire fee requirement was removed or that
an arbitrary later error proves the original admission check ran.

Restore and require green. Disable the designated underpricing oracle in an
isolated test copy and require the mutation driver itself to fail when its
expected red disappears. The independent kernel checks must stay green through
this host-only mutation, demonstrating the distinction from proof-layer failure.

Register the real contract as `test-workchain-withdrawal-fee-admission` and its
mutation driver as `test-workchain-withdrawal-fee-admission-control` in default
CTest when the adapters land. Missing/disabled/skipped targets remain incomplete.
No such registration or execution is claimed by this document. The existing
prepare guard is not evidence that tariff authentication has been installed;
its retirement must not be used to silently mark this separate item complete.
