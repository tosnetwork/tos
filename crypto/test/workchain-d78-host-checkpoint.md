# D78 host checkpoint

Anchor: memo a131b9bb, specification SHA256 prefix 187dbc79290d6816.
This is a coordinated encoding/host checkpoint, not complete D78 or M5 acceptance.
B's c7a6f62e8 interface and 147f9b20b wallet fix are merged by ancestry.
No independent symbolic prediction was read or changed by A.

## Implemented boundary

- Withdrawal request/export v2, explicit abi_version=2, no v1 compatibility alias.
  Commitment T=x+q is checked; debit T+f is checked separately before verification.
  The eight equations and six ranges are B's unchanged SEND-shaped relation.
- Canonical host context remains 566 bytes. A named v2 domain constant supplies
  the tag size; wrapper is 30+64+3*8+566=684. Metering remains proof work, not
  Withdrawal's one billing unit. The old library-wide-looking ABI constant is
  not used for this family.
- Explicit account schema 4 migration and v2 bounded W record; W=P=x. The new
  test business layouts are 8 (prepare) and 9 (prepare+Failed), with no prelock.
  Retired M5 layouts 4..7 are rejected, not reinterpreted. M3/M4 layouts 1..3
  retain their encoding. No frozen price or capacity default was introduced.
- Positive eligible Failed issuance is checked y-slot-g. Released W and P are
  each x. The same actual inbox identity, Attempt association, sequence advance,
  fee destinations and atomic publication are retained.

Production-file changes in A's integration: workchain-proof-work.h (v2 typed
meter), workchain-proof-backend.cpp (v2 dispatch), workchain-failed-funded.h
(remove prelock arithmetic). No collator.cpp, validate-query.cpp, transaction.cpp
or D59 opening change. The legacy helper name does not select a funded/shortfall
policy: there is now only one positive issuance formula.

## Fresh execution, not inherited greens

The first rebuilt Native live target stopped at the still-old release wallet
example requesting return_reserve; /tmp/uno-d78-live.log. This is not a green.
B fixed the missed consumer in 147f9b20b; A rebuilt the actual release example
and Native target before the successful second run.

`uno-m3-live.py --m5-failed` exits 0, /tmp/uno-d78-live2.log:

- x=10000000, q=100, f=257; no b. Available 1000000000 -> 989999643,
  revision 1->2. Actual payout LT=16000002, value=x, flags=3.
- Prepare R_actual=R_book=N_hidden=989999643, P=W=10000000.
  Thus R+P=999999643=N+W, and R_actual=R_book independently.
- Real bounce y=9996070; receipt=6996062=y-3000000-8. Native loss 3930 is
  already absent from y and is not deducted a second time.
- Failed final R_actual=R_book=N_hidden=996995705, P=W=0:
  996995705+0=996995705+0. Sequence 1->2; receipt is the settlement origin.
- Actual payout hash F2305DADBA1726572F42806BEB43BC786BD58E784503158175D8ABEA7C092002;
  bounce D33FEF358E148B536E797DE273092A5C5701DCB41491D2C965F61F15A5A9C832.
- Prepare proof work 3620/3620; Failed 7/7. Equality alone is not evidence of
  numeric correctness: the wrapper is separately checked against B's versioned
  statement bytes. Actual normal unknown observations are 0; injected real
  Failed execution reports 1, LocalUnavailable, and zero publication.

Focused default CTest 4/4: proof-boundary-gates, proof-work,
withdrawal-statement-expiry, withdrawal-statement-effects
(/tmp/uno-d78-focused.log). The focused FailedFunded transition test passes 1/1
with receipt 56=70-2-12 and W release 100, not the old 156/200.
Full association remains red at its previously documented unrelated
CodecFailureCategoriesSurviveProtection write.is_error() assertion; not fixed
or presented as new D78 evidence.

After the same final host/wallet rebuild, fresh --m4 and ordinary M3 harnesses
each exit 0: /tmp/uno-d78-m4.log and /tmp/uno-d78-m3.log. M4 ends A=0,
B=1996999954; M3 ends A=987999514, B=0 with real Deposit and paired OFF runs.
These are newly executed regression sequences, not inherited pre-D78 greens.

## Red controls and retired evidence

Before changing its premise, the AST expiry guard failed on removal of
WithdrawalAmounts.return_reserve. Only that obsolete field expectation changed;
the call-target requirements and structural mutation controls are retained.
The ABI inventory separately reported the changed identities before registration.
Codec-test direct ABI uses and Rust cfg(test) system-origin calls were explicitly
registered, not excluded from scanning.

The new default metering test compares the actual versioned statement prefix
and size, not just arithmetic constants. An isolated shadow header changed
only the named tag back to v1. It still compiled, with the same 684 length, but
exited 1 at the prefix assertion (v2 != v1), /tmp/uno-d78-tag-red.log.
Original sources were not mutated; restored/default tests pass. The first
control driver hit a UTF-8 decoding error while collecting the abort backtrace;
rerunning the already-built mutant with raw log capture established the actual
designated assertion. That capture error is not counted as red evidence.

D78 retires the b +/-1 admission controls and shortfall-positive partial CTest
because their design was superseded, not because their old findings were wrong.
Historical evidence remains in 09a94d798, 82b53c675 and f12b8731b, and B's pinned
old replay/measurement sources are untouched. The Failed funding-edge trigger
is retained: banning all coordinator->custody capability would contradict D63.
No guard is retired by this checkpoint.

## Cross-boundary consistency: pre-change observed receipt as control

This retrospective comparison uses a control recorded before D78, not another
post-change formula check. It gives no additional formal contract credit.

Control: B's pre-D78 measurement committed in 92dd939c6, reviewing 82b53c675,
fixture /tmp/uno-m3-live-6igzl00b. Its
[normal.log](../../doc/measurements/uno-m5-shortfall-independent/normal.log)
reports `COMPONENTS ... installed_receipt=7996062`. The provenance matters:
[probe.cpp](../../doc/measurements/uno-m5-shortfall-independent/probe.cpp)
decodes accepted-state.boc, selects the actual owner's origin_pending.front(),
and prints that stored receipt.amount. The independently computed formula is
only compared to that value; it is not substituted for it. The nearby
PARAMETER_CONTROL variant=0 helper output is NOT the control used here.
The same probe reads y from failed-bounce.boc and s/base/units from zerostate,
and observes the actual custody transaction fee g=8.

At this follow-up, the retained accepted-state, bounce and zerostate file SHA256s
still match B's pre-change
[input-identities.json](../../doc/measurements/uno-m5-shortfall-independent/input-identities.json):
`1b598ccc…`, `39fc5473…`, `99fff079…`, respectively. The archived measurement
and fixture have not been regenerated using D78 code.

Comparison: A's post-D78 /tmp/uno-m3-live-wifgx0up, recorded in
/tmp/uno-d78-live2.log. assert_m5_failed reads receipt.amount from the accepted
owner root, checks its ciphertext by decryption, and separately checks the
configuration-derived fees against Native balances/transaction fees.

| Observed/input term | Pre-D78 control | Post-D78 observation |
|---|---:|---:|
| Actual bounce y | 9,996,070 | 9,996,070 |
| Slot fee s | 3,000,000 | 3,000,000 |
| Compute g (base 2, units 4) | 8 | 8 |
| Prelock b | 1,000,000 | absent |
| Installed receipt | 7,996,062 | 6,996,062 |

Observed difference: **7,996,062 - 6,996,062 = 1,000,000 = old b**.
Thus this matched-parameter observation supports exactly the expected removal
of the prelock contribution, using a historical measured control independent
of the new expression. These are not byte-identical fixtures (the state schema
and message identities changed), and one matched observation is not a proof
that arbitrary other inputs or compensating changes are impossible. It does
not close bucket disposition, Paid/late, or any formal contract slot.

## Explicit incompleteness

The y<=slot+g helper refusal is NOT bucket disposition. Closed/no-slot return
disposal, Paid lazy closure and late-return completion remain unimplemented;
there is no claim that refusal preserves bucket ownership or publishes value.
No phantom Paid refund path was added.

Fresh independent runners remain fail-closed: Failed 0/10 and prepare 0/9,
with all formal names missing (/tmp/uno-d78-failed-readiness.log and
/tmp/uno-d78-prepare-readiness.log). No D78 observed-marker was fabricated.
Full sequence successors and classification completion remain outstanding.
Zero unknowns covers only the executed observations, not all classifications.

The live driver did not capture an execution-time wallet binary digest/source
stamp. The release rebuild log and successful no-prelock CLI execution are
evidence, but not that stronger provenance pin. No retrospective hash is
presented as an execution-time capture.

Read-only Claude boundary review was requested for the changed host arithmetic,
versioning and provenance. At this evidence checkpoint its report is pending;
do not interpret the request itself as review approval.
