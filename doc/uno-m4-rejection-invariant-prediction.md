# M4 rejected Deposit: prediction before observation

This document is committed before receiving A's rejection-run observations.
B read only the specification and the coordinator's five-check instruction,
not A's rejection implementation or fixtures. Independence is behavioral, not
structural isolation. Later observations must be attributed to the coordinator
when relayed through it. The first, earlier fee-prediction attempt lacked a
committed artifact and was invalid; this prediction uses the corrected order.

Source: `/home/tomi/memo/TOS_UNO_PRIVACY_WORKCHAIN_V2.md`, current sections
3.1/3.2/3.3, 11.1, 11.3, D29/D30/D38/D52, plus the coordinator's explicit
exact-slot-fee, cross-origin duplicate-ID, and failed-sequence-install rules.
This is a prediction with explicit unresolved questions, not a run report.

## Scope and initial state

One ordinary, real Native Deposit arrives at coordinator, the destination
specified by section 11.1. It is not a payout bounce or late-return Deposit.
Compare committed states immediately before and after handling it, holding
unrelated transactions constant. Let initial values be Ra, Rb, N, D0, P0, W0;
registered count G; deposit sequence s; existing target user/system slot
counts u/t. Let I be actual imported Native value, not the claimed amount x.

A correct rejection is a valid protocol event, not an invalid block. A
candidate installing a forbidden credit is a different case. Local inability
to obtain state or resources must not select bounce versus bucket (11.3).

## Five admission failures

| Failed check | Expected committed principal values | Account and sequence result |
|---|---|---|
| Target absent or lifecycle disallows receipt | (Ra,Rb,N,D0,P0,W0) unchanged | G and s unchanged; absent target stays absent, existing record unchanged |
| x below V_min or above V_max | Same unchanged tuple | G,s,u,t unchanged; no ciphertext credit |
| No system slot, t=K_system_pending | Same unchanged tuple | t remains full; no eviction; u,G,s unchanged |
| Attached slot payment not exactly the authenticated fee, whether short or excess | Same unchanged tuple | No admitted receipt or successful-slot allocation; G,s,u,t unchanged |
| Derived ID already in either pending origin | Same unchanged tuple | Existing full receipt preserved, never overwritten; G,s,u,t unchanged |

For every row, available ciphertext, nonce, revision, key and all pre-existing
pending records remain unchanged by this rejected Deposit. The operation
does not register, close, or collect an account. There is no successful
Deposit effect, no D32 confidential fee deduction, and no installed increment
of deposit_sequence. Computing tentative s+1 is not installing it; failure
must leave the authenticated counter s. This applies the coordinator's D52
analogy to the Deposit counter, not an assumption that both counters coincide.

Derivation: 11.1 authorizes custody +x and creation of a system pending right
only when all admission checks pass, atomically. Rejection authorizes neither
side. R_book therefore gains no finalized Deposit, N_book gains no right, and
no committed D is created. Rejection creates no Withdrawal or payout and
therefore no P/W. In an M4 initial state D0=P0=W0=0 these stay zero structurally;
this is not a claim to read three persistent counters. Neither successful
bounce nor bucket attribution is a confidential pending receipt.

## Native return and fallback bucket

Section 11.3 selects the outcome deterministically from authenticated message,
configuration and block context: already-bounced messages are not bounced
again; bounce requires payable return fees and protocol reachability; otherwise
use the bucket. No delivery guarantee follows from creating an export.

For an isolated rejection with a successful return, bucket increment is zero.
The returned value is not assumed to equal x or I: section 3.3 assigns mistaken
message return fees to the message's attached value. Let E be exported value
and c_in the actual fees allocated to that incoming value; then I=E+c_in
when none of that value is retained. Native fees paid separately from operating
budget must be recorded separately, not counted twice or charged to backing.

For fallback, let y be actual value retained for the bucket after the applicable
Native charges. With no simultaneous sweep, net bucket balance grows by y;
no N_book, R, D, P or W increment accompanies it. The full Native equation
old+imported=new+exported+fees still applies, including any separately funded
operating expenditure. Do not substitute claimed x for y, assume full refund,
or discard a remainder because no return message can be made.

This ordinary rejected Deposit uses type 1 attribution: kind, original src
(workchain plus address), and value, with **no account_id**, even if its body
named a confidential target. Type 2 belongs to late payout returns and is not
this case. When the primary bucket is full, D29 requires src-keyed overflow;
when both bounded levels are full, it requires the unkeyed total and an event/
alarm for lost attribution. Thus preserving src is conditional on capacity,
not a universal claim across the explicitly authorized double-full fallback.
D30 stores net balances, not unbounded credited/swept totals in state.

A later type-1 sweep returns value to src, reducing bucket value with matching
Native export/fees; it does not issue confidential rights or change principal
books. Bucket attribution is a retained right to the specified mechanical
return policy. Consequently, 'no obligations' cannot honestly mean 'no state
or attribution remains': the explicit bucket exception creates such state.
The prediction is no Deposit/confidential/Withdrawal obligation, not absence
of all Native exports, bucket records, or fees.

## Custody versus coordinator

For the specified ordinary Deposit, Native ingress is to coordinator (11.1),
not custody. Only successful atomic admission transfers x into custody.
Therefore custody Native balance is unchanged on rejection, including fallback;
there is no required temporary custody credit. Native receipt by coordinator
is not R_actual. Transient transaction staging must not be reported as a
committed D or a finalized Deposit.

This does not settle a different experiment importing directly into custody.
D38 covers that destination too, whereas 3.2 defines R_actual as the entire
custody Native balance. If unreturned unexpected value remains physically
there, that definition and 'bucket does not enter backing' cannot both hold
without an explicit same-batch relocation or different balance definition.
The cited text does not specify that physical relocation. Do not silently
subtract a bucket from custody to make the assertion pass. This is an open
boundary question for the coordinator, outside the ordinary ingress prediction.

## Specification questions requiring a ruling

1. Section 3.2 line 216 unconditionally says bucket credit/sweep must not change
   R/D/N_book/W/P. Section 11.3's D29 conservation paragraph explicitly permits
   type-2 sweep admission with R+=y, R-=fee and N_book+=y-fee. These are different
   prescriptions for the same type-2 event. No interpretation is selected here;
   ordinary type-1 rejection predictions above do not need that decision.
2. The cited rules determine conservation and the return-fee source, but do not
   alone provide an exact numeric y or E: Native fee inputs, processing costs
   and their allocation must be supplied. In particular, no guessed retained
   slot-fee revenue or full-I bucket credit is predicted for failed admission.
3. Direct-to-custody unexpected retention needs the physical accounting boundary
   identified above before it can share the unchanged-custody assertion.

## Required observations and limits

For each isolated failure report the authenticated failed predicate, before/
after principal values and their derivation, complete account records or their
canonical comparison, both slot counts, G and s, and actual Native import,
return export or bucket delta, fees and their funding source. Report bucket
kind/src and absence of account_id, including overflow level when relevant.
Distinguish observed balances from structural zeros and derived equalities.

No exact Native fee, returned amount, bucket net amount without fee inputs,
recipient delivery, M5 behavior, or direct-to-custody physical routing is
predicted. No A result has been substituted into these expectations. The
unresolved specification questions are not silently filled by implementation.
