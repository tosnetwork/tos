# D78 symbolic prediction: no return prelock

Normative anchor: memo a131b9bb / SHA256 prefix 187dbc79290d6816, §11.2
state-transition table and D78. This is a new artifact, not a correction of the
historical D64/D68/D70/D71 predictions. No post-D78 host measurements were used
to derive it; pre-D78 reports and implementations are already known. Independence
is behavioral, not structural isolation. Later observations must identify whether
B read actual artifacts or received them through the coordinator. This document
is algebra, not host execution or a proof that its measurement instruments work.

## Symbols and input obligations

R means both independently observed R_actual and event-rebuilt R_book. N denotes
N_book, checked against independently decrypted rights when test keys permit.
P/W track the given outstanding principal; C is coordinator Native balance,
U protected unexpected-bucket holdings, J refundable registration deposits.
D=0 at committed batch boundaries is structural for these atomic operations,
not a separately measured persistent counter. Never substitute that inference
for an observation of R or N. Start with R0+P0=D0+N0+W0 and R_actual0=R_book0.

x is authorized principal; q is actual Native-priced outward forwarding fee;
f=S+C_fee+tip is the separately authenticated operation fee. Use checked T=x+q
and checked debit=T+f. f is not in T. For Withdrawal, billing units=SEND units=1;
S is explicit Withdrawal f_state, C_fee=base*1, tip=f-S-C_fee after checked
floor admission. No equation or range-object changes are predicted.

For a returned message y is its actual authenticated Native value. h=s+g,
g=checked(beta*u), s the system pending slot fee. beta,u are return-time explicit
configuration inputs, not inherited prepare defaults. Native loss x-y is already
missing from y and is not charged again. No b or max_bounce_cost exists.
The window and the three M5 wiring values (f_state, issuance billing units,
K_withdrawal) are not frozen by this document; no local values are supplied.

## Per-event prediction at atomic committed boundaries

All entries are deltas from that event's predecessor, not simultaneous alternative
branches. Let F_pool be the validator fee pool and n the shared issuance sequence.
J and registered_accounts remain unchanged in every listed event.

| Event | ΔR_actual = ΔR_book | ΔN | ΔP | ΔW | ΔC | ΔU | ΔF_pool | Pending / sequence |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| prepare | -(x+q+f) | -(x+q+f) | +x | +x | +S | 0 | C_fee+tip | no change / no change |
| Eligible phase0 or within-window bounce, y>h | y-h | y-h | -x | -x | +s | 0 | +g | one system receipt y-h / +1 |
| No-bounce deadline passes, no owner-triggered evaluation yet | 0 | 0 | 0 | 0 | 0 | 0 | 0 | no change / no change |
| Owner-triggered Paid close | 0 | 0 | -x | -x | 0 | 0 | 0 | no change / no change |
| Eligible late bounce, record already closed | y-h | y-h | 0 | 0 | +s | 0 | +g | one system receipt y-h / +1 |
| Eligible late bounce, expired record still open | y-h | y-h | -x | -x | +s | 0 | +g | one system receipt y-h / +1 |
| Nonissuance y<=h, retained in bucket, open matching obligation closed | 0 | 0 | -x | -x | +y | +y | 0 | no receipt / no advance |
| Same nonissuance after obligation closed | 0 | 0 | 0 | 0 | +y | +y | 0 | no receipt / no advance |

The bucket rows describe the value classified into the protected holding, not
spendable operator income. At the inlet custody transiently receives y, then the
same atomic batch transfers it to coordinator's bucket: net backing delta zero.
No attempted issuance means no issuance charge g; s is not earned without a
slot. Do not interpret this as a promise of zero unrelated Native execution
costs: any separately priced physical routing transaction must have its own
specified payer and measured fee, and must be reported separately rather than
silently debited from y or R. These rows exclude unrelated simultaneous events.
No-slot/closed-account refusal uses the same preservation rule; attribution and
overflow routing follow D29/D62 rather than invented identities.

At phase0 strong matching is direct; Q=0 is not passed into deadline arithmetic.
For phase1, arrival at Q+window is within-window; greater height is outside.
Closing the record lazily does not extend the height window. Per the authoritative
row6 an expired open record is closed while processing its late return; an
already closed record is not released again.

## Independent equalities and cumulative outcomes

Prepare changes each side of R+P=D+N+W by -(q+f). Eligible timely return changes
each by y-h-x. Paid changes each by -x. Eligible late return after closure changes
each by y-h. Bucket nonissuance changes each by -x if the obligation closes,
otherwise by zero. R_actual and R_book change together only if the physical and
ledger transitions in the table are both executed; their equality is not assumed
from the proposed effects.

For initial P0=W0=0 and one completed Withdrawal:

- Paid without bounce: R_final=R0-x-q-f, N_final=N0-x-q-f, P=W=0.
  User debit x+q+f; no refund or system receipt. C_final=C0+S, U_final=U0.
- Eligible bounce, timely or late after any required close:
  R_final=R0-x-q-f+y-h, N_final=N0-x-q-f+y-h, P=W=0.
  User's returned confidential claim is y-h, not x and not y plus a reserve.
  C_final=C0+S+s; U_final=U0; fee-pool increment C_fee+tip+g.
- Bucket disposition: R_final=R0-x-q-f, N_final=N0-x-q-f, P=W=0 after close;
  no new confidential claim. C_final=C0+S+y, U_final=U0+y.
  Attribution is a protected bucket entry, not free operating revenue.

D60 slack C-J-U increases by S at prepare, s at eligible return, zero at Paid
or pure bucket receipt. For independent successful type-II sweep of value z,
net custody/N increment z-s-g, coordinator delta -(z-s), bucket delta -z,
fee pool +g. Thus slack increases only s, not s+g. Batch-boundary snapshots only.

These equations do not establish the correctness of common-mode amounts.
Independently anchor serialized payment=x, Native fee=q, operation fee floor
and its S/C_fee/tip split, imported y, slot s, and computed/routed g. Perturb each
link separately and require its own oracle; disable that oracle with the mutation
retained and require the driver to fail. No b anchor or supplement exists to test.

## Applicability and inherited evidence

New interface evidence is c7a6f62e8: measured host context566, wrapper684,
crypto28/28, prover5/5 and codec11/11 with arithmetic/record controls. Those are
interface checks, not observations of this transition table. Earlier live greens
remain valid for their earlier code; the withdrawn atexit allegation does not
invalidate them. They cannot validate changed D78 fields by inheritance.
Unknown-origin, Native assumption, complete host contract and deployment approval
obligations remain separate. This prediction grants no guard retirement.
