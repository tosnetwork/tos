# M4 live sequence: invariants committed before observation

## Basis, timing, and independence

This is a symbolic prediction, not a run result. It is committed before B
receives results for the live sequence below. B has not read A's live fixture
files `test/m4-live-deposit.h`, `test/test-m3-live.cpp`, or
`test/m3-live-config.h` to derive it. Independence is behavioral, not structural:
implementation files may be present in the same worktree. Subsequent live
observations are to be supplied through the coordinator and attributed as such,
not described as direct observations by B.

Sources are the specification at `/home/tomi/memo/TOS_UNO_PRIVACY_WORKCHAIN_V2.md`,
sections 3.2, 5.1, 10, 11.1 and D25/D28/D32, and the coordinator's explicit
correction to the public cash book: subtract authorized confidential operation
fees from cumulative locked Deposits. The old section 3.2 sentence that
SEND/COLLECT do not change N_book is also incompatible with D32 when fees are
nonzero; this prediction uses D32's paired fee reduction, not that old sentence.
No implementation, tariff, or specification is changed by this document.

## Coordinator-confirmed input sequence

The coordinator confirmed the following sequence after the initial symbolic
prediction in `170b379c8`, still before the live observation:

Register A, register B; Deposit x1 to A, Deposit x2 to A; A COLLECTs the first
system receipt with k=1 while retaining the other; A COLLECTs the retained
receipt; A SENDs to B; B COLLECTs that user receipt; **close A**.
There are exactly three COLLECTs. Both Deposits target A's system_pending.
The first and second receipts below are labeled by collection order. Map these
roles to the authenticated account addresses when supplying observations;
a different flow is not this committed test sequence.

Inputs:

- x1, x2: successfully admitted Deposit principal, each within authenticated
  V_min/V_max and paid in addition to its slot fee. X = x1 + x2.
- p1, p2: externally paid Deposit slot fees at their respective authenticated
  configuration cuts; dA, dB: historical registration deposits actually paid.
- v: SEND amount A to B, fixed to X-q1-q2-h, not freely adjusted; it must
  satisfy V_min <= v <= V_max and all intermediate balance bounds.
- q1, q2, q3: public fees for the three COLLECTs; h: public SEND fee.
- Each operation uses its own authenticated price cut. Write
  qi = 3*bi + ti, and h = ps + bs + ts. There is no multiplication by receipt
  count or cryptographic proof-work units. ps is SEND's authenticated slot fee.
- G0: initial registered_accounts; L0: initial refundable-deposit bucket;
  O0: initial spendable coordinator operating budget.
- R0: initial custody backing and public cash book, equal to initial N_book.
  Any unrelated balances/receipts remain unchanged. D=P=W=0 at the initial
  boundary; this M4 sequence contains no Withdrawal or outstanding settlement.

For a fresh zero-backing instance R0=0 and G0=0. These are explicit input
conditions, not local defaults. All sums, products, and subtractions must be
checked integers; a negative available result is not an executable success.

## State after every successful committed step

In the table, Q is the common backing/liability increment: **R_actual = R0+Q,
R_book = R0+Q, N_book = R0+Q**. R_book includes the coordinator-approved fee
correction. D=0 at every listed committed boundary. Deposit may transiently
pass through D inside atomic admission; no committed intermediate D is allowed.
Available columns denote test-key-decrypted amounts, not public scalar fields.

| Committed step | Q | A available | B available | A system slots | A user slots | B system slots | B user slots | registered_accounts |
|---|---|---|---|---:|---:|---:|---:|---|
| Register A | 0 | 0 | not registered | 0 | 0 | n/a | n/a | G0+1 |
| Register B | 0 | 0 | 0 | 0 | 0 | 0 | 0 | G0+2 |
| Deposit x1 to A | x1 | 0 | 0 | 1 | 0 | 0 | 0 | G0+2 |
| Deposit x2 to A | X | 0 | 0 | 2 | 0 | 0 | 0 | G0+2 |
| A COLLECT first receipt, k=1 | X-q1 | x1-q1 | 0 | 1 | 0 | 0 | 0 | G0+2 |
| A COLLECT retained receipt, k=1 | X-q1-q2 | X-q1-q2 | 0 | 0 | 0 | 0 | 0 | G0+2 |
| A SEND v to B | X-q1-q2-h | X-q1-q2-h-v | 0 | 0 | 0 | 0 | 1 | G0+2 |
| B COLLECT SEND receipt | X-q1-q2-h-q3 | X-q1-q2-h-v | v-q3 | 0 | 0 | 0 | 0 | G0+2 |
| Close A | X-q1-q2-h-q3 | 0 (closed) | X-q1-q2-h-q3 | 0 | 0 | 0 | 0 | G0+2 |

At the first collection, the retained receipt still represents x2. Its complete
record (ID, authenticated origin, target/epoch, ciphertext and status) is
unchanged, not merely its count or hash reference. Only the selected system
slot is released. The second collection consumes that same retained receipt
and releases its slot. SEND creates one user slot, not a system slot. B's
collection releases that user slot. No collection releases an unrelated slot.

For every row, the new accounts' available amounts plus the amounts in their
pending receipts sum to Q. After SEND this includes B's pending v, even though
B's available is still zero. Thus R_actual=N_book and the conditional
N_book=N_hidden relation use each pending right exactly once.

## Fee sources and destinations

| Operation | Contribution to custody-funded S | C | T | F |
|---|---:|---|---|---|
| Registration A/B | none | none assigned by this transfer tariff | none assigned | not a custody fee |
| Deposit x1/x2 | none | Native/system costs are separate | none assigned | not a custody fee |
| First system COLLECT | 0 | 3*b1 | t1 | q1 |
| Retained system COLLECT | 0 | 3*b2 | t2 | q2 |
| SEND | ps | bs | ts | h |
| User-receipt COLLECT | 0 | 3*b3 | t3 | q3 |

The sequence's custody-funded total is Fsum = q1+q2+h+q3:

- Ssum = ps, credited by same-shard internal allocation to coordinator.
- Csum = 3*b1 + 3*b2 + bs + 3*b3.
- Tsum = t1 + t2 + ts + t3.
- This sequence's fees_collected increment from D32 is Csum+Tsum.
- Custody and N_book each lose Fsum, while receiving X from Deposits.
- With one unchanged static tariff: Fsum = ps + 10*b + ts + 3*tc.

Deposit slot fees p1+p2 also increase the coordinator's operating budget, but
come from external attached funds. They must not be charged again to custody
or subtracted from the admitted principal x1/x2. Registration deposits increase
the restricted refundable bucket, not Ssum, N_book, or spendable income.
These statements do not claim that registration/Deposit Native execution is
free. Actual Native fees and authorized system costs need their own inputs and
must not be mixed into the D32 fee total or paid from confidential backing.

If E is the explicitly accounted net operating-budget expenditure through a
step, and no other operating credits occur, spendable O equals
O0 + admitted Deposit slot fees + committed SEND state fee - E.
Before closure the refundable bucket is L0+dA+dB. Closing A reduces it by dA
to L0+dB. The refund output's value is historical dA, not today's
registration price; its Native forwarding costs belong in E, not in custody
or a reduced refund value. A successful push is not evidence of recipient
delivery. No bounce recredit or retained refund obligation is assumed.

Registration deposits and their refunds explicitly participate in **neither**
R_actual=R_book **nor** R_actual+P=D+N_book+W. They are public restricted
coordinator funds, not custody backing, confidential liabilities, or Deposit
principal. The Native coordinator debit and refund export still have to balance
in Native value flow; their exclusion from these two principal equations does
not exclude them from overall money conservation. The refund is a one-way
outbound value transfer, with fees from spendable operating budget.

## Fixed closure prerequisite and final balances

Let Z=X-q1-q2. The confirmed SEND amount is exactly v=Z-h. Consequently:

- A available after SEND and at closure = Z-h-v = 0.
- B available after its COLLECT = v-q3 = X-Fsum.
- Both accounts have zero system/user pending slots at closure.
- A is closed, B remains registered; registered_accounts remains G0+2
  (exactly 2 when G0=0).
- Final R_actual=R_book=N_book=R0+X-Fsum, and D=P=W=0.

Feasibility must be established from the actual input before treating a failure
as an implementation discrepancy. In particular require **v >= V_min** (also
v <= V_max), x1-q1 >= 0, 0 <= Z <= B_max, and 0 <= v-q3 <= B_max,
with the other authenticated amount/lifecycle/capacity constraints unchanged.
If v < V_min, the selected amounts make this sequence infeasible. Report that
input problem; do not adjust fees, insert a clearing/Withdrawal/test-funding
step, or change the transfer amount away from v=Z-h. The final zero balance
must be the result of SEND and its authorized fee, not an additional edit.

Closing retains the identity record, marks its lifecycle closed, preserves the
registration count, and does not change backing or confidential liabilities.
The no-settlement-obligation condition rests on the scoped structural premise
and expiry guard, not on a caller-supplied zero or an observed empty table.

## Invariants and observation inputs

- Deposit changes neither account's available, registered_accounts, nor user
  slot count. It increases backing, N_book, and one system receipt atomically.
- COLLECT changes backing and N_book by **minus its fee**; it is not a purely
  internal redistribution when its public fee is nonzero. Transfer principal
  moves from selected pending into available without a second issuance.
- SEND leaves total confidential principal unchanged except for its fee; v
  moves to B's pending in the same commit. It does not consume a system slot.
- Registration/closure do not mint, burn, or move confidential principal.
  Closure refunds public restricted funds; registered_accounts never decreases.
- An uncommitted/failed atomic step installs none of the successful-step
  receipt, counter, balance, or D32 fee changes. Native processing of a rejected
  inbox event is a separate protocol event, not a successful Deposit row.
- The three formerly missing choices are now fixed: three COLLECTs, both
  Deposits to A followed by A-to-B SEND, and closure of A with v=X-q1-q2-h.
  Supply actual amounts, authenticated prices and addresses to instantiate
  these equations; do not choose a different sequence after observing results.
- Total block fees/final coordinator Native balance additionally require actual
  Native/system fee inputs; the D32 tariff alone cannot determine them.

No live sequence result, fee implementation correctness, or M4 acceptance is
claimed here. Later observations must be compared to this committed document
with their input configuration, operation list, and commit identity supplied.
