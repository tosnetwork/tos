# D71 applicability and symbolic criteria

Specification: memo 0d96690f, SHA256
b01d284b511b16078294d1e6e8d3eb67ef9593c768252fe2cdce007a7d7d05bc.
D71 resolves the two questions in `uno-m5-d70-accounting-addendum.md`.
That earlier prospective document and all frozen predictions remain unchanged.
This addendum is algebra and a future observation contract, not host evidence.

## Inputs and distinct units

For one potential system receipt, let s be its authenticated slot fee,
beta the current authenticated base_compute, and u the authenticated issuance
billing units (no local numeric value). Define g = checked(beta * u) and
h = checked(s + g). D72's per-member proof-work constants are a different
quantity; neither a constant of seven nor a byte length supplies u.
All arithmetic in an executable adapter must be checked, including these sums.

Use the prior prediction's isolated initial state R_actual=R_book=N_book=R0,
D=P=W=0. Principal x, outgoing fee q, reserve b and prepare operation fee f
remain separate. After prepare:

    Rp = R0 - x - q - f
    Np = R0 - x - q - b - f
    R_actual = R_book = Rp; N_book = Np; W = x+b; P = x; D = 0

No prepare equation changes under D71. The following assumes all other
association, lifecycle and capacity conditions for settlement are satisfied.

## Settlement threshold and destinations

For Failed use m = checked(y+b), where y is the actual bounce receipt.
For Paid use m = b. Comparison against h occurs before issuance.

| Condition | New pending amount | Coordinator income | Event fees_collected | Issued receipts / sequence increments |
| --- | --- | --- | --- | --- |
| m > h | z = checked(m-h) | s | g | 1 / 1 |
| 0 <= m <= h | none | m | 0 | 0 / 0 |

The second row includes both m<=s and the newly specified s<m<=s+g band,
including equality m=h. No separate allocation rule exists inside that band.
g is only a prospective threshold component there: issuance does not happen,
so it is not charged or credited to validators. Do not execute issuance and
then discard its output. This does not claim all other settlement work is free.
No source signs or publishes a sequence increment for this no-receipt event.

Funded Failed terminal state:

    R_actual = R_book = Rp + y - h
    N_book = Np + y + b - h
    W = P = D = 0

No-receipt Failed terminal state:

    R_actual = R_book = Rp + y - m = Rp - b = Np
    N_book = Np; W = P = D = 0

Funded Paid terminal state:

    R_actual = R_book = Rp - h
    N_book = Np + b - h
    W = P = D = 0

No-receipt Paid terminal state:

    R_actual = R_book = Rp - b = Np
    N_book = Np; W = P = D = 0

Thus both R_actual=R_book and R_actual+P=D+N_book+W hold in all four
listed terminal branches. The no-receipt branch does not create an unpaid
shortfall record or require operating-budget compensation. Native bounce loss
is already included in y; never deduct it again. Coordinator protected holdings
(refundable deposits and unexpected holdings) do not change in these isolated
settlement rows. D60 slack rises by s on issuance and by m otherwise.

## Funded type-2 sweep: split the fee

For gross bucket value y>h and successful admission, let t=checked(y-h).
At the same committed batch boundary require:

    delta custody = delta R_book = delta N_book = t
    delta coordinator = -t-g = -y+s
    delta bucket holdings = -y
    delta event fees_collected = g
    delta refundable deposits = delta W = delta P = delta D = 0

State revenue s stays at coordinator; compute revenue g does not. No part of
h takes a round trip through custody. D60 slack increases by s, not h.
These rows resolve the formerly conditional D32 routing in the D70 addendum.
They do not invent a new disposition for a bucket entry whose sweep admission
fails: bucket return/terminal rules remain separately applicable.

## Observation slice, paths and reserved red controls

Observe actual committed coordinator/custody roots, event-attributed validator
fees, the full authenticated account/pending dictionary and both slot counters,
plus deposit_sequence and W/P closure. Execute the real custody Failed path,
window-close Paid path and successful type-2 sweep, once their adapters exist.
No proposed effects list alone substitutes for these observations. Unrelated
block income must be separated so it cannot hide a wrong fee destination.

Extend the D70 control contract with these exact comparisons:

* Test m=s, m=h, and, when the explicitly supplied g permits it, an interior
  s<m<h value. Each must produce no receipt, no issuance call, no sequence
  increment, zero issuance compute revenue and coordinator income m. Test the
  smallest representable value above h for positive issuance, subject to other
  applicable admission rules. Never select a protocol default to populate it.
* In isolation restore the old threshold m>s. A case in s<m<=h must reach the
  no-issuance observation and fail there; an unrelated rejection is not evidence.
* Redirect g to coordinator in a funded issuance/sweep while preserving the
  total fee. Component-route assertions must fail even if R and N still agree.
* Publish a counter increment or charge issuance compute on a no-receipt row.
  Fail the committed sequence/receipt or event-revenue assertion respectively.
* Restore green after each mutation. Remove its designated assertion in an
  isolated oracle and require the mutation driver to fail for losing its red.

These controls are specified, not run. No production code, A-owned guard or
existing assertion implementation is changed here. The old synthetic slot-only
sweep test remains pre-D70 evidence, not validation of the new split fee.
