# M5 accounting criteria before live execution

Specification: `TOS_UNO_PRIVACY_WORKCHAIN_V2.md`, SHA256
`dd979cd244831d3f0bd150a4ba83edc190954c2bf3bafc45f77ef63cb318c6a2`.
Source baseline: `e64a2d153`. No M5 live observations were consulted.
This document freezes the isolated D61/D63 expectations below. It is **not**
the complete per-block live prediction: the intended sequence and authenticated
inputs have been requested, and the two interpretation questions below remain
open. Do not fill missing inputs from observations after a run.

## Behavioral criteria

The test header `crypto/test/workchain-m5-accounting-assertions.h` accepts
observations, not production state. No new codec, authorization, proof relation,
or consensus error classification is introduced.

* D61: in the isolated forwarding stage, custody decreases by `x + q`, where
  `x` is principal and `q` is outgoing Native fee. Operating funds do not change.
  The return allowance `b` remains in custody, separately locked in W. Other
  independent events must be accounted for separately: net block balances alone
  could hide unauthorized spending behind simultaneous income.
* D63: for gross bucket value `y`, slot fee `s`, and `t = y - s`, require
  `custody += t`, `R_book += t`, `N_book += t`, coordinator balance `-= t`,
  bucket holdings `-= y`, refundable deposits unchanged, in one batch.
  The fee remains at coordinator and never enters custody.
* D62: over one entry's complete lineage, including its returned successor,
  at most one ordinary return message may be emitted. A returned entry must
  retain `return_failed`, and neither ordinary return nor Deposit admission
  may be retried after that flag is set. Governance sweep authorization is a
  separate responsibility and is not tested here.

The existing `account_workchain_payout` is executed as the D61 red sample:
custody 1000, operating 100, principal 700, outgoing fee 30, locally collected
fee 10 produce custody 300 and operating 70. The predicate rejects that result
specifically for operating funding. Synthetic compliant observations are
custody 270 and operating 100. This does not declare the production helper
D61-compliant; its current policy is deliberately exposed.

D62 and D63 use assertion-only synthetic states/traces. There is not yet an
authenticated M5 entry-lineage adapter or type-2 sweep implementation here.
Assigning the same test trace to an entry is not proof of authenticated
association across return messages. Future adapters must derive observations
from actual artifacts; caller-provided lineage IDs are insufficient.

## D60 interaction with D63

Let coordinator balance be C, refundable deposits Q, and bucket holdings U.
For an isolated type-2 sweep:

| Quantity | Before | After |
| --- | --- | --- |
| Coordinator Native balance | C | C - y + s |
| Refundable deposits | Q | Q |
| Bucket holdings | U | U - y |
| Custody / R_actual | R | R + y - s |
| R_book | B | B + y - s |
| N_book | N | N + y - s |
| W / P / D | W / P / D | unchanged |
| Operating remainder | C - Q - U | C - Q - U + s |

These expressions require sufficient bucket holdings and `0 <= s <= y`;
implementations must use checked arithmetic. Given D60 before the batch,
the final inequality remains true: its slack increases by s. The balance
debit and protected-holdings release are **not equal**; their difference is
the fee becoming operating income.

Example tested: C=200, Q=100, U=100, R=B=N=300, y=60, s=10.
Final C=150, Q=100, U=40, R=B=N=350 passes D60. Combining final C=150 with
old Q=100 and U=100 fails D60. This is a mixed snapshot, not a committed
batch. D60 specifies per-block validation (specification lines 216-219).
The current account settlement checks complete old and produced coordinator
snapshots (`workchain-account-settlement.h:374,397`). No existing D63
installation-order defect is claimed: that transition has not been implemented.

D61 prohibits paying outgoing fees from C's operating portion even if D60
still passes. Thus D60 is not an authorization test for the source of fees.

## Questions pending before the complete live prediction

1. Specification line 832 prices Withdrawal as `f_send + max_bounce_cost`;
   D25 includes slot fee in `f_send`. D61 line 1261 says withdrawals create
   no slot fee. Is the independent withdrawal operation fee's S component zero
   or the SEND slot fee? No interpretation has been selected here.
2. Lines 185 and 263 say the allowance stays in custody Native balance while
   also saying it is not counted in R_book / not chosen for R_actual. Line 195
   defines R_actual as custody Native balance. Does the wording mean that
   locking does not **increase** reserves (existing backing remains counted),
   rather than excluding that amount from reserves? No exclusion is assumed.
3. The planned live sequence, initial balances, principal amounts, outgoing
   fees, return allowances, and separate operation fees are still needed.
   Paid, timely return, late return and bucket sweep cases must be named before
   freezing a complete per-block table.

Independence is behavioral, not structural: A's existing files are in the same
tree. Reading was limited to the specified current payout red sample, D60's
existing checks, and specification; no M5 expected outputs were read. The
earlier M4 first prediction attempt lacked a committed artifact and was not
valid evidence. Future M5 observations, if relayed by the coordinator, must
be identified as relayed rather than directly observed by B.

Measured bounce-cost and settlement-window envelopes gate activation; they
do not establish a finite worst-case delay under arbitrary network conditions.

## Executed checks

```
cmake --build /home/tomi/uno-m3-refund-assert-build --target test-workchain-m5-accounting-assertions -j2
ctest --test-dir /home/tomi/uno-m3-refund-assert-build -R '^test-workchain-m5-accounting-assertions$' --output-on-failure
```

Build succeeded; default CTest target passed. Direct execution reported
`3 test(s) passed`. The initial new translation unit needed `block-parse.h`
before coordinator helpers to expose the existing TL-B namespace imports;
only the test header was adjusted, not production code or predicates.

Three isolated copies were separately compiled and linked against the same
libraries, each removing just one predicate branch. The original source and
build objects were not changed by these controls:

| Removed branch | Observed result |
| --- | --- |
| D61 operating-balance comparison | Exit 1: exact error-message assertion failed; the real helper output reached the custody-debit error instead |
| D63 physical custody credit comparison | Exit 1: expected error was absent |
| D62 repeated ordinary return comparison | Exit 1: expected error was absent |

These results establish that the intended assertion branches are exercised.
They do not establish M5 host compliance, complete lineage reconstruction,
governance sweep authorization, or a full regression result.

## Tracked successor (2026-09-11; does not rewrite frozen evidence)

The D62/D63 synthetic-only limitation is now a mandatory outstanding real-host
contract: [BUCKET-SWEEP](uno-m5-bucket-sweep-handoff.md). Its readiness runner exits
1 and names missing tests. Later D70/D71 fee splitting applies there; the original
pre-D70 arithmetic above remains historical, not the current sweep prescription.
