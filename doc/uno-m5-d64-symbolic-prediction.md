# D64/D65 symbolic prediction before M5 observations

Specification commit `8f02a558`, SHA256
`38e340e2afe6fa8e468125855fcd1261cd3bc0d0cd4ae69a716c9e8888a7e29d`.
This artifact is committed before any M5 live observations received by B.
No A M5 implementation, expected output, or live fixture was read. The table
uses explicit symbols; it does not derive inputs from subsequent results.

## Inputs and scope

One initially absent Withdrawal is tracked through prepare+payout, any number
of waiting blocks, and alternative terminal events. Independent late-return
and type-2 sweep deltas are provided for composition. Paid and timely Failed
are mutually exclusive, not two releases of the same record.

* x is principal, q is outgoing Native fee, b is the authenticated return
  allowance, and f is the protocol operation fee. All are independently
  validated. `T=x+q+b` is the checked public v; source debit is `T+f`.
* D65 sets the Withdrawal state-fee component S to zero. Thus f=C+tip;
  the computation tariff remains an explicit authenticated input, not an
  invented work-unit formula. q and b are not included in D32 F.
* s is the authenticated system-pending slot fee. No numeric default is used.
* Initially R_actual=R_book=N_book=R0 and W=P=D=0 for this isolated ledger.
  Source available is a0>=T+f; other users' rights are unchanged.
* O0 is coordinator Native balance, Q0 refundable deposits, U0 bucket holdings,
  with O0>=Q0+U0. These values are independent of custody's reserve b.
* L is the authenticated settlement window, left symbolic. Waiting rows apply
  only when no related event occurs. No finite network-delay bound is claimed.
* For timely Failed, y is the actual incoming bounce value and c=x-y is actual
  Native return loss, with 0<=c and c+s<=b for the covered fully funded case.
  The window's total cost charged against the allowance is c+s, not c alone.

All sums/subtractions in an implementation must be checked. Preparation also
requires T<=V_max and the source balance range. An x that individually fits
V_max can still fail these combined requirements.

## Main committed-state table

For Paid define `m=b`, `d=min(s,m)`, `z=m-d`. If m>s, d=s and a system receipt
z is installed. If m<=s, d=m goes to operating income and no receipt is made.
For the covered timely Failed case, gross return rights are `m=y+b`, fee s,
and system receipt `z=y+b-s = x+(b-c-s)`. Thus x is restored and only the
unused allowance after Native loss and slot fee is returned in addition.

| Boundary | R_actual | R_book | N_book | W | P | D |
| --- | --- | --- | --- | --- | --- | --- |
| Initial | R0 | R0 | R0 | 0 | 0 | 0 |
| Prepare + payout + D32 f | R0-x-q-f | R0-x-q-f | R0-x-q-b-f | x+b | x | 0 |
| Waiting, no related event | unchanged | unchanged | unchanged | unchanged | unchanged | 0 |
| Paid, including D65 disposition | R0-x-q-f-d | R0-x-q-f-d | R0-x-q-f-d | 0 | 0 | 0 |
| Alternatively timely Failed | R0-x-q-f+y-s | R0-x-q-f+y-s | R0-q-f-c-s | 0 | 0 | 0 |

At prepare, both sides of `R_actual+P = N_book+W` equal R0-q-f.
W excludes q and includes b. At either terminal row, R_actual=N_book and
W=P=0. b never left custody while locked; no new R sub-bucket is created.
R_book's explicit outgoing-fee subtraction is q, independently of f. At
release, the D65 fee/dust transfer also decreases R_book along with the actual
custody debit; it must not disappear from the cumulative event accounting.

| Boundary | Coordinator Native | Refundable | Bucket holdings | Source available | Newly installed system pending |
| --- | --- | --- | --- | --- | --- |
| Initial | O0 | Q0 | U0 | a0 | none |
| Prepare | O0 | Q0 | U0 | a0-x-q-b-f | none |
| Waiting | unchanged | unchanged | unchanged | unchanged | none |
| Paid | O0+d | Q0 | U0 | unchanged from prepare | z if b>s; otherwise none |
| Timely Failed | O0+s | Q0 | U0 | unchanged from prepare | y+b-s |

Source total rights after Paid are a0-x-q-f-d. After timely Failed they are
`a0-q-f-c-s`. Pending credit is not available credit: a later COLLECT must
be listed and charged separately. User-pending entries are unchanged in all
rows. System entries increase by one only when a receipt is installed.
Capacity reservations associated with W are not installed pending entries;
this table does not invent their future encoding. registered_accounts remains
unchanged throughout. Refundable deposits never fund these costs.

D60 slack O-Q-U is unchanged at prepare, increases by d at Paid, and by s at
Failed. The reserve allowance b is never added to Q or U.

## Additional event deltas

The following rows use their own authenticated before-state. They do not
release another Withdrawal or consume another allowance.

| Event | delta R_actual / R_book | delta N_book | delta W / P / D | delta coordinator | delta bucket | delta refundable |
| --- | --- | --- | --- | --- | --- | --- |
| Admitted late bounce of value y with slot fee s | y-s | y-s | 0 / 0 / 0 | s | 0 | 0 |
| Type-2 bucket sweep, gross y and fee s | y-s | y-s | 0 / 0 / 0 | -(y-s) | -y | 0 |

Both admitted rows install one system receipt y-s; their other admission
conditions must hold. The late bounce starts in custody and sends s out.
The type-2 sweep starts in coordinator and sends only y-s into custody;
s never visits custody. Sweep increases D60 slack by s. Assertions compare
complete batch boundaries, never new balances with old protected holdings.

## Scope limits and open inputs

The table covers the direct terminal-credit routes with an available system
slot, including Paid's specified dust branch. The timely Failed row explicitly
requires the allowance to cover Native loss plus the slot fee. It does not
invent a rule for exceeding that measured allowance, or assume the measured
value bounds all possible network conditions.

Unavailable system slots, invalid late-return admission, overflow buckets,
D62 return attempts/governance sweep and account closure require their actual
event inputs and authenticated identity mapping. No numeric full live sequence
or these branch-specific costs have been supplied. Do not claim the conditional
rows as predictions of unnamed events. D62's one-attempt predicate remains
assertion-only until an authenticated lineage adapter exists.

The older fee-table shorthand `f_send + max_bounce_cost` must not be read as
D64's f: D65 explicitly removes the Withdrawal slot charge, and b already
belongs in v/W. This artifact follows D64/D65 over that shorthand and leaves
the independent computation tariff as an input, never as a local default.

Independence is behavioral, not structural: A's existing files share the tree.
Future coordinator-relayed observations must be labeled as relayed, not as B's
measurements. Empirical allowance/window measurements gate activation; they
provide operating envelopes and alarms, not delivery or finite-delay guarantees.
