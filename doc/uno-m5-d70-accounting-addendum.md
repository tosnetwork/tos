# D70 symbolic accounting criteria

Specification: memo 16ab0954, SHA256
f900bb4b043c82e2e0925212371149ec2a10025c9309e922ce9edfa9143e2443.
This is an additive prospective criterion, not an edit to frozen predictions
and not a host execution result. No A execution outputs were used.

## Inputs and observation boundary

Let s be the authenticated slot fee, beta the settlement block's authenticated
base_compute, and u the system-issuance BILLING units, still subject to freezing.
Define g = checked(beta * u), h = checked(s + g). No numeric u is selected here;
the reported seven proof-work units do not supply u. These expressions are for
one actual receipt. Multiple receipts require individual charges and checked
aggregation; do not assume one operation always means one receipt.

Observe complete committed before/after custody, coordinator, bucket, R_book,
N_book, W and P, plus event-attributed fees_collected and actual installed
system receipts. Whole-block net income alone can hide an incorrect fee source.
The future execution paths are custody Failed, window-close Paid reserve return,
and type-2 sweep. None has been executed by this addendum. The old synthetic
`type_two_sweep` predicate in `workchain-m5-accounting-assertions.h` checks the
pre-D70 slot-only formula; it must not be used as D70 coverage without extension.

## Funded issuance branch

Assume all non-fee admission checks pass and the post-fee receipt is positive.
Let x be principal, q outgoing Native fee, b original reserve, f the separate
prepare operation fee, y actual timely bounce value, and R0 the initial common
R_actual/R_book/N_book value. These are the same isolated sequence assumptions
as the previous forecasts, with D=P=W initially zero.

Prepare is unchanged:

    R_actual = R_book = R0 - x - q - f
    N_book = R0 - x - q - b - f
    W = x + b; P = x; D = 0

Failed with m = checked(y + b) > h issues z = checked(m - h):

    R_actual = R_book = R0 - x - q - f + y - h
    N_book = (R0 - x - q - b - f) + z
    W = P = D = 0

Substituting z gives N_book = R_actual. Native loss c = x - y, when y <= x,
is already reflected in y and must not be deducted a second time. The total
return-cost expression is now checked(c + s + g). If c+s+g > b, z < x;
that is a normal shortfall, not an operating-budget receivable. The branch
requires m>h, not that reserve b cover all costs.

Paid reserve return with b > h issues z = checked(b - h):

    R_actual = R_book = N_book = R0 - x - q - f - h
    W = P = D = 0

Paid classification itself does not move principal again. Only issuing the
reserve return and paying its costs changes these balances. Both equations
R_actual=R_book and R_actual+P=D+N_book+W remain algebraically true for the
listed branches. Implementations must check each arithmetic operation and
must not underflow; algebraic cancellation is not a substitute for those checks.

For a funded type-2 sweep of gross y > h, require:

    t = checked(y - h)
    delta custody = delta R_book = delta N_book = t
    delta bucket holdings = -y
    delta refundable deposits = delta W = delta P = delta D = 0

The physical custody credit and book credit must both use t. Updating books
without moving t remains an independent failing case under D63.

## Routing question: unresolved, not silently decided

D70 (line 1428) says the sweep fee covers issuance compute. D63 (lines 956,
1421) still says the entire fee remains coordinator operating income. D32
(lines 640, 1390) routes compute to fees_collected. Thus substituting h for
s in the old sweep predicate would silently retain g at coordinator.

Conditional on applying D32 to this new compute component, the additional
criteria would be:

    delta event fees_collected = g
    sweep delta coordinator = -t - g = -y + s
    sweep delta protected holdings = -y
    sweep delta D60 slack = s

For the funded Paid/Failed issuance, the corresponding coordinator increment
would be s, not h, and event fees_collected would increase by g. These routing
rows await confirmation; they are not a chosen implementation. Do not route g
through custody merely to reuse a helper without an explicit accounting design.

## Insufficient total fee: unresolved branch

D65 (line 1423) specifies no receipt and all m to coordinator when m <= s.
D70 adds g but does not explicitly settle s < m <= s+g. Charging both fees in
that interval leaves no positive receipt. Merely using the old m>s test is
insufficient; partial principal compensation under D68 does not determine fee
priority or whether an unperformed issuance should incur its compute fee.

Required decision: no-issuance handling, actual charged components and their
routing for that interval (and corresponding sweep admission failure). Do not
invent min(h,m) and send it all to coordinator. The funded rows above do not
claim to cover this branch. It is not a reason to assert that reserves are
always sufficient.

## Reserved behavioral controls for host integration

1. On a funded actual issuance, omit g from the deducted amount while retaining
   the configured u and actual issuance. Fail at the decoded receipt amount and
   independently reconstructed R/N delta, not at unrelated admission checks.
2. On a funded actual sweep, move/book y-s instead of y-s-g. Fail the net-credit
   assertion. Independently omit the physical custody movement and require the
   physical-credit assertion to fail even if the proposed books match.
3. Once routing is confirmed, retain g at coordinator instead of the designated
   fee destination. Fail component routing even when total deductions match.
4. Restore each source mutation and require green. Disable the corresponding
   observation assertion in isolation and require the mutation driver itself
   to fail because its designated red disappears.

These are reserved tests, not registered or executed host controls. Their
observation slice and three execution paths are stated above. Old tests passing
cannot establish these new obligations. No production helper, frozen tariff,
A-owned file, or previous prediction was changed by this addendum.
