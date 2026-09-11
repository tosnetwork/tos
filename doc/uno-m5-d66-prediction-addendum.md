# D66 applicability of the frozen M5 prediction

Specification commit `55663567`, SHA256
`86832278bddf47a53a8886731ec71578d003d485be89233dc300a9b8046de875`.
The prior symbolic table is frozen in commit `48dca2c42` at
`doc/uno-m5-d64-symbolic-prediction.md`; it is not edited by this addendum.
No M5 live result has been received or used to construct either table.

D66 changes no predicted monetary delta. It identifies who enforces the
necessary bounds:

* The host checks `T = x + q + b` as u64 additions before scalar conversion.
  Overflow rejects before a statement or payout can be authorized.
* The unchanged proof enforces `T <= V_max` and `T + f <= a`. The necessary
  inequalities in the frozen table are **not additional host admission gates**.
* A wallet may precheck for diagnostics; that is not a consensus rule.

The prepare row remains:

```
delta R_actual = delta R_book = -(x + q + f)
delta N_book = -(x + q + b + f)
delta W = x + b
delta P = x
delta D = delta coordinator = delta refundable = delta bucket = 0
```

The confidential debit's sum with f is an arithmetic description, not a new
public balance precheck. f has no Withdrawal slot component under D65. q is
the distinct outgoing Native fee term in R_book, not part of F or W. b stays
in custody and is not added to D60's coordinator protected holdings.

For a Paid direct credit, let d=min(b,s): reserve and confidential rights both
end at `R0-x-q-f-d`, coordinator increases by d, W/P become zero. A positive
system receipt `b-s` is installed only if b>s; otherwise no receipt is made.
For a timely Failed direct credit, let actual Native loss c=x-y with c+s<=b:
reserve and rights end at `R0-q-f-c-s`, coordinator increases by s, W/P become
zero, and the system receipt is `y+b-s`. These remain alternative terminal
rows with available capacity, not an assertion about unspecified overflow
or out-of-allowance branches.

The settlement window and return allowance remain symbolic authenticated
inputs, not local defaults. Empirical envelopes are not network delay bounds.
