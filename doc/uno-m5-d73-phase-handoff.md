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
