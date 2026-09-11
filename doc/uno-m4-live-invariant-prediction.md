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

## Required interpretation of the input sequence

The written sequence contains **three COLLECT operations**, not two:
first system receipt, retained system receipt, and the receipt created by SEND.
The fee-count instruction saying two COLLECTs therefore cannot describe that
same sequence. This document predicts the explicitly enumerated sequence.

For role-based notation, A is the newly registered account receiving both
Deposits and subsequently sending to newly registered B. These roles must be
mapped to the actual authenticated addresses before comparing a run; they are
not inferred from a fixture. With initially empty accounts, the first k=1
collection can retain the second receipt only if both Deposits reached A.
If the actual sequence uses other destinations or pre-existing receipts, report
that different input rather than silently applying this table.

Inputs:

- x1, x2: successfully admitted Deposit principal, each within authenticated
  V_min/V_max and paid in addition to its slot fee. X = x1 + x2.
- p1, p2: externally paid Deposit slot fees at their respective authenticated
  configuration cuts; dA, dB: historical registration deposits actually paid.
- v: SEND amount A to B, satisfying the authenticated amount bounds.
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
| Close a qualifying zero-balance account | unchanged | unchanged | unchanged | 0 | 0 | 0 | 0 | G0+2 |

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
Before closure the refundable bucket is L0+dA+dB. On closing account J it
becomes L0+dA+dB-dJ. The refund output's value is historical dJ, not today's
registration price; its Native forwarding costs belong in E, not in custody
or a reduced refund value. A successful push is not evidence of recipient
delivery. No bounce recredit or retained refund obligation is assumed.

## Closure prerequisite and final balances: missing inputs must remain visible

The instruction does not name the account to close. Let Z=X-q1-q2.
Immediately before closure:

- A available = Z-h-v.
- B available = v-q3.
- Both pending collections are empty; registered_accounts remains G0+2.

If A is closed, its zero-balance prerequisite requires v=Z-h. B then holds
X-Fsum. If B is closed, its prerequisite requires v=q3. A then holds X-Fsum.
Both conditions must also respect all amount/range/fee constraints. Neither is
silently chosen here. If neither zero condition holds, the listed sequence
cannot end in a successful closure without another explicitly authorized step.
Do not clear a nonzero balance or invent a Withdrawal/test-funding step to make
the observation fit. Both balances can be zero only if X=Fsum and the individual
operation constraints also hold; that is not an assumed input condition.

Closing retains the identity record, marks its lifecycle closed, preserves the
registration count, and does not change backing or confidential liabilities.
The no-settlement-obligation condition rests on the scoped structural premise
and expiry guard, not on a caller-supplied zero or an observed empty table.

## Invariants and items requiring coordinator input

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
- Required missing sequence inputs: confirm three rather than two COLLECTs;
  map the Deposit/SEND roles to actual accounts; identify the closing account
  and a feasible v satisfying its zero-balance condition. These are input
  omissions/inconsistencies, not yet evidence of a new specification defect.
- Total block fees/final coordinator Native balance additionally require actual
  Native/system fee inputs; the D32 tariff alone cannot determine them.

No live sequence result, fee implementation correctness, or M4 acceptance is
claimed here. Later observations must be compared to this committed document
with their input configuration, operation list, and commit identity supplied.
