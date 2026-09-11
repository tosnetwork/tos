# D68 shortfall prediction before host observations

Specification commit `f3c0e841`, SHA256
`817dbacecc6171b4bcf504b04777746d85cbdc2fd4a5047f94678a5b2ccfc7a6`.
This adds a branch to the frozen prediction in `48dca2c42`; it does not
rewrite that artifact or its covered-case precondition. No A shortfall
implementation, fixture, expected result or observation was read for this
prediction. Independence is behavioral, not structural. Future observations
relayed by the coordinator must be labeled as such.

## Inputs and applicable branch

Use the earlier symbols: principal x, outgoing fee q, original return reserve
b, protocol fee f, initial custody/book/rights R0, source available a0,
coordinator balance O0, refundable deposits Q0 and bucket holdings U0.
Prepare debits x+q+b+f from the source. All inputs and arithmetic are checked;
no tariff, window or reserve defaults are supplied here.

A matching bounce arrives within the window, with actual value y, 0<=y<=x.
Let c=x-y be the actual Native loss, already reflected in y. Let s be the
applicable authenticated system slot fee. For the direct receipt branch assume
an available slot and otherwise satisfied receipt admission. Define:

    m = checked(y+b)
    d = min(s,m)
    z = checked(m-d)

D65 sends d to coordinator operating income. If m>s, install one system
pending receipt of value z. If m<=s, transfer all m, create no receipt, and
z=0. These are complete batch boundaries, not intermediate snapshots.
D68's deficient branch is z<x. In the receipt case it is equivalently
c+s>b (mathematical integers; do not perform an unchecked u64 c+s).
The stricter case c>b already falls short even before the slot charge.

In particular, s<=b and c>b provides a shortfall case in which the slot fee
is wholly covered by the original reserve, independently of any question
about slot fees exhausting that reserve. No operating-budget subsidy occurs.
The dust rule is D65's existing m<=s rule, not an invented subsidy or loan.

## Committed-state prediction

| Boundary | R_actual = R_book | N_book | W | P | D |
| --- | --- | --- | --- | --- | --- |
| Initial | R0 | R0 | 0 | 0 | 0 |
| Prepare, payout and protocol fee settled | R0-x-q-f | R0-x-q-b-f | x+b | x | 0 |
| Waiting with no related event | unchanged | unchanged | unchanged | unchanged | 0 |
| Matching Failed, shortfall disposition completed | R0-x-q-f+y-d | R0-x-q-b-f+z | 0 | 0 | 0 |

At the final boundary both first and second entries simplify to
`R0-q-f-c-d`. Source available remains `a0-x-q-b-f`; adding the new pending
right z gives source total rights `a0-q-f-c-d`. The returned right is z<x;
there is no additional claim for x-z and no residual W to fund one.
A later COLLECT is a separate charged operation, absent from this table.

Coordinator becomes O0+d; Q0 and U0 stay unchanged. Thus D60 slack increases
by d. No preexisting operating budget, refundable deposit or another user's
balance funds the shortfall. Registered account count and user-pending slots
stay unchanged. System slots increase by one only if m>s; no slot is installed
in the dust branch. The one Withdrawal record closes and its open count drops
by one. No terminal record is invented in the bounded open set.

## Two invariant calculations

At prepare:

    R_actual + P = (R0-x-q-f)+x = R0-q-f
    D + N_book + W = 0+(R0-x-q-b-f)+(x+b) = R0-q-f

Across the atomic Failed batch:

    delta R_actual = y-d
    delta P = -x
    delta N_book = z = y+b-d
    delta W = -(x+b)
    delta D = 0

Hence each side changes by `y-d-x`. At the final boundary W=P=D=0
and R_actual=N_book. This remains true for z=0, d=m.
R_book changes by the same y-d as custody: the actual payout net is x-y;
q, f and the terminal d each have their separate settled debits. c must NOT
be subtracted again from y or from the available pot m: Native has already
removed it. Also do not charge b as an additional custody debit: it never left.

The no-event waiting row preserves both equations. A state that installs
incoming value but uses old W/P/N_book is not this atomic boundary and cannot
be substituted into the table. Other block events must contribute their own
paired deltas; this prediction does not assert invariants for partial batches.

For diagnostic reporting, use `min(b,c)` as the reserve portion allocated to
Native loss and `b-min(b,c)` as the nonnegative remainder before slot costs.
Never compute b-c unconditionally or store c>b as reserve consumption while
also asserting consumption+remainder=b. The terminal total returned z is
computed from actual assets y+b, not from a promise to return x.

## Limits and specification maintenance

This is algebraic prediction, not executed host evidence. It covers a matching
in-window Failed event and D65's direct receipt/dust disposition. It does not
predict no-bounce, late admission failure, full slots, bucket routing, repeated
returns or unrelated Native transaction charges. Any additional actual debit
must be identified and paired, not silently absorbed into y or q twice.
Neither reserve pricing margins nor a settlement window guarantee delivery or
a finite worst-case network delay. D68 changes their freezing conditions;
both configuration values still require freezing.

The specified file still contains the older absolute assertion at line 838,
"bounce 回来时补足金已锁定，不存在短缺状态", whereas lines 994-1003
and D68 explicitly reject it. This prediction follows the explicit D68
replacement; the residual sentence needs a specification edit by its owner.
The previous prediction's fully funded branch remains conditional, rather
than a claim that every return is fully funded.
