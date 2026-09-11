# WITHDRAWAL-PREPARE fail-closed acceptance contract

Specification: memo 1de47f47, SHA256
45b20d8f6678edeb014136a1a60689616388d0b07c970cde02e4934f7ca65054.
Frozen before B observes A's Native prepare integration. This is a prospective
contract, not a host acceptance result. A owns implementation; B independently
reviews its observations. Existing predictions and earlier contracts are intact.

## Executable readiness check

```
python3 crypto/test/workchain-withdrawal-prepare-handoff.py --build BUILD_DIRECTORY
```

Nine exact default CTest names below are mandatory. Missing/disabled/skipped
names, test failures, missing observation markers or tool errors exit nonzero.
Each test must print `WITHDRAWAL-PREPARE_OBSERVED:<full-ctest-name>` only AFTER
its actual positive/negative observations and restoration controls complete.
A marker is an execution protocol, not proof of a test's honesty: review its
emission site and adapter provenance. A placeholder printing the marker is
not acceptable. No test registration or host behavior is implemented by this
runner. Do not label NOT_READY as a passing acceptance test or suppress it with
WILL_FAIL. Add the real tests to default CTest when A's adapters exist.

## Common real fixture and observation rules

Run registered wc=2 Native prepare through source-aware admission, engine
execution, candidate reconstruction and atomic publication, with authenticated
account and configuration arenas. Reuse real Native payout pricing, not a stub
that supplies the desired debit. Pin implementation/configuration commits and
identify the arena of every rejection. Missing config means ConfigInvalid;
unavailable local data is not a candidate content failure. Unknown code 0
remains unknown and must not be accepted as the expected diagnostic.

Choose explicit test policy with nonzero required fee, sufficient custody and
owner confidential funds, canonical keys, valid nonce, capacity and destination.
Do not populate unfrozen fields with local defaults or confuse billing units
with proof-work units. For ordinary controls use an owner with no matured W
record, so the prepare event is isolated. The cap case intentionally differs.

Read authentic predecessor/successor account roots, the full account-to-pending
cut (all accounts, user and system receipts, both counters), account control
records, custody/coordinator balances, N_book/R_book/W/P, D32 components, and
actual outbound queue/message artifacts. Distinguish proposed effects from
installed state, and in-memory stage from committed publication. Validate
proofs independently where a negative is meant to reach a post-proof check.

Each mutation is in an isolated shadow build of the SAME fixture. Record the
exact old/new source, admission/verification stage, named failed assertion and
exit code; compile errors, missing tools or earlier rejection do not count.
Restore source and require green. Never fix expectations to follow a mutation.
The names below use prefix `test-workchain-withdrawal-prepare-`.

## Nine test contracts

### debit

Fixture: distinct positive x, outgoing q, original reserve b and operation fee f;
checked T=x+q+b, sufficient old confidential balance a. Execute successful real
prepare and inspect both effects and authenticated installed artifacts.
Assertions: confidential debit exactly T+f; available after=a-T-f; effects retain
x/q/b/f separately. Record outward_fee_paid=q, original_reserve=b,
consumed_return_cost=0 and refundable_reserve=b. Custody decreases x+q+f for
this isolated operation; reserve b stays physically there. Independently check
D32 routing of f and actual priced q rather than trusting copied fields.
Mutation: omit q or b from confidential debit, or collapse/swap the separately
recorded amounts while preserving their sum. Failure must be the named debit
or component-equality assertion after valid setup, not proof mismatch caused
by editing a statement without regenerating its matching proof.

### overflow

Fixture: separately overflow x+q, then (x+q)+b with otherwise valid framing,
configuration and key. Observe the real host's checked-total boundary and a
narrow instrumented scalar/point-construction entry counter in the isolated
build. Require rejection at checked-total, with zero later construction calls
and no publication. No valid proof is needed for an input rejected before it.
Mutation: replace checked sum with explicit wrapping sum in isolation. The
ordering assertion must turn red when construction is reached, even if a later
proof/range check rejects. That later rejection is not evidence of overflow
protection. Include a nonoverflow positive case that reaches construction.

### no-pending

Fixture: valid prepare with pre-existing unselected user AND system receipts,
including another account's pending slice. Observe the complete authenticated
account-to-pending map and both counts before/after prepare, byte-for-byte;
available and W are allowed to change. Effects alone are not the oracle.
Mutation: actually install an extra user receipt, extra system receipt or alter
a pending counter in the produced candidate state. Require rejection by the
prepare no-pending validation/paired-cut assertion; prove the mutation reached
that boundary. A malformed cell rejected earlier does not qualify. This is
Native prepare coverage, not the prior standalone account-BOC file-write probe.

### record

Fixture: valid paired prepare. Enumerate the new account control envelope:
one new Withdrawal ID, singly derived Attempt ID, actual payout created_lt,
phase 0, zero removal height and captured settlement interval; identity/crypto/
pending references remain correctly bound. Compare stored count to dictionary
cardinality and enforce both Withdrawal-ID and created_lt uniqueness.
Assertions: delta W=x+b, delta P=x, delta N_book=-(x+q+b+f); R_actual/R_book
decrease x+q+f. Mutation: include q in W, release b from custody, or omit/misplace
the record while retaining payout. Fail the specific record/book pairing
assertion, not an unrelated serialization error. No new global W dictionary.

### cap

Fixtures: (1) authenticated config missing K_withdrawal; (2) count exactly K
with no expired record; (3) count exactly K with one genuinely due record and
owner-touch prepare. Use paired historical records and actual queue-removal
observations, not fabricated expiry. Supply enough funds and system slots for
any legitimate settlement refund. Case 1 must fail at configuration admission
as ConfigInvalid, never use a local fallback. Case 2 must reject new prepare
for capacity. Case 3 must execute due-record settlement BEFORE testing capacity,
then admit the replacement prepare if all other conditions pass.
Observe staged order and independently enumerated final records/count. Separate
the settlement event's legitimate pending issuance from prepare's no-pending
cut; comparing only whole-operation pending equality here would be wrong.
Mutations: supply a local fallback on missing config; bypass cap; move cap check
before due settlement. Respectively require config, cardinality and ordering/
positive-admission assertions to fail. If publication later aborts, no staged
settlement or new prepare record may leak into committed state.

### fee-admission

Use the earlier control 9: derive positive f_required from authenticated tariff,
then checked f_low=f_required-1. Generate separate matching proofs/new balances
for both fees; BOTH must pass the existing kernel verifier. Keep other inputs
admissible. Required-fee prepare passes; low-fee prepare fails specifically at
host authenticated fee-floor comparison, without payout or accepted prepare
state. A candidate claiming successful low-fee execution is independently
rejected as CandidateInvalid. An operation refusal does not by itself mean its
enclosing rejection block is invalid.
Mutation: bypass only the host fee-floor comparison. Require the designated
fee-admission oracle to turn red; retain proof validity and document any separate
later fee check instead of misreporting it as the removed check's result.

### enqueue

Run actual prepare publication. Decode the actual payout and require
extra_flags=3, correct custody source/destination/principal and actual created_lt
matching the W record. Both outbound-queue membership and W record must be
committed in the same batch (D73's prior presence), not merely an action emitted.
Mutation: use different flags; omit enqueue but retain W; retain enqueue but omit
W. Fail exact flags or paired publication assertions. Abort before publication
and verify neither side is installed. No absence-only phase-1 inference can
repair failed paired creation. This control does not claim recipient delivery.

### onoff

Run the same otherwise valid Native fixture ON and OFF using the existing
switch. ON must reach real execution/publication. OFF must identify the named
switch rejection point and observe zero engine execution, zero produced
transactions and no candidate export. A setup failure before the switch is
not OFF evidence. Mutation: bypass the switch and require the OFF oracle to
fail while the ON fixture remains viable. Do not introduce a second switch.

### oracle-control

For the preceding mutations retain the modified producer/validator but disable
its designated paired oracle in an isolated TEST copy. The mutation driver must
then exit nonzero because the expected designated red disappears. Record which
oracle was disabled and prove unrelated checks did not supply a substitute red.
A blanket expected-nonzero wrapper is insufficient. This meta-control passes
only when it demonstrates that loss of the oracle is itself detected; no
synthetic always-failing executable may replace any Native execution path.

## Handoff and limits

Current runner must report NOT_READY. Once A commits any prepare integration,
B first repeats the appropriate shadow/reversion experiment against that commit,
then runs its claimed green tests. Merely registering nine names does not close
this contract. No automatic expiry-baseline refresh, guard retirement or M5
acceptance is authorized by this document. A's current AST/BOC guard is not the
Native authenticated no-pending control above.

D62/D63/Failed integration remains a separate queue. This contract does not
validate recipient receipt, queue liveness, arbitrary-network delay, all fee
policies or cryptographic soundness. It only specifies the observed cuts and
actual execution paths above; arithmetic predictions are not host observations.
