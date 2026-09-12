# D78 current acceptance handoff

Anchor: memo a131b9bb, specification SHA256 prefix 187dbc79290d6816.
This replaces prelock-specific requirements in the older contracts, not their
historical evidence. D78 changes the design. It does not imply that old controls
were wrong or that any current host obligation has passed. D79 and Appendix I
new evidence tasks are not implemented by this handoff.

## Retirements and retained boundaries

WITHDRAWAL-FAILED `topup`, `remainder`, `shortfall` are retired by D78, including
the old twelfth item. There is no reserve to supplement, refund or exhaust.
The mutation naming the obsolete shortfall-rejection message in the old
contract is retired with that branch; do not search for a renamed error string
and pretend it still represents a current control. The old parameter source
`doc/measurements/uno-m5-failed-independent/parameter.cpp` and its y+b-h expected
value remain pre-D78 evidence. A new y-h criterion appears below.

A negative control binds to the semantic property it breaks, never an error
string. Pin the baseline commit and exact mutation diff; establish that the
mutation applied and reached the intended assertion. Seeing any failure is not
sufficient. If an earlier stage must pass, separately prove that stage can fail.

Unchanged: D62 once-only bucket return, ownership/close prerequisite, D63
physical sweep and split fee destinations; D69 shared staged issuance counter,
checked advance, duplicate receipt rejection; D67 ID/LT uniqueness, enumerated
count and cap. Statement family remains ordinary SEND, no equation changes.
A red expiry guard is not retired until its replacement execution evidence is
installed. Retirement of reserve-specific controls grants no other retirement.

## Common execution and observation requirements

Start with a real authenticated post-D78 prepare predecessor and actual serialized
payout; import a real rich bounce through custody's independent inlet. Execute
the registered engine and validator reconstruction to atomic publication. Never
relax coordinator's bounced-message refusal. Observe committed account roots,
both pending dictionaries and counters, W/P and enumerated open records, Native
custody/coordinator balances and transactions, out_msgs and block fees_collected.
Use test-key decryption to check receipt amounts independently. Claimed effects
alone do not supply this observation cut.

Set x,q,f, slot fee s, base beta, issuance billing units u, capacities and window
through explicit authenticated test inputs. No default values or freezes are
introduced. Compute g=checked(beta*u), h=checked(s+g). x-y is already absent from
y; it must NOT be deducted a second time. No reserve exists.

Each negative must reach the named property assertion below after valid upstream
checks, emit evidence of that reached stage, then pass again after restoration.
Turning off its oracle while retaining the semantic mutation must make the
control driver fail. A matching return code alone is not proof of zero publication.

## WITHDRAWAL-FAILED: ten current mandatory names

Run `python3 crypto/test/workchain-withdrawal-failed-handoff.py --build BUILD`.
Names retain the prefix `test-workchain-withdrawal-failed-` and use these suffixes.
The new marker is `WITHDRAWAL-FAILED_D78_OBSERVED:<full-name>`; prelock markers
are deliberately insufficient. Missing, disabled, duplicated, skipped, failed or
unobserved tests remain fail-closed. Markers require independent source review.

| Suffix | Fixture and expected committed observation | Semantic mutation and designated failure |
|---|---|---|
| credit-y | Real bounce with y different from x and y>h. Observe imported gross y and custody/net confidential credit y-h from serialized Native inputs, not a proposed amount. | Substitute x for imported y: `CREDIT_ACTUAL_INBOUND` / `CREDIT_NET_Y_MINUS_H`, after actual inlet association, not decode failure. |
| release | Matched open W record. Event-local P and W each decrease exactly x; record disappears once; q never enters either amount. | Independently perturb P release, W release, or record principal: `RELEASE_P_X`, `RELEASE_W_X`, or authenticated-principal binding assertion. No reserve-based mutant. |
| identity | Successful real signing of the system receipt: Withdrawal settlement origin contains authenticated Attempt ID and consumes one shared staged deposit_sequence. Full pending dictionaries reject duplicates. | Suppress the committed sequence advance or bind wrong Attempt ID: `ISSUANCE_SEQUENCE` / `ISSUANCE_ATTEMPT` at publication/reconstruction. Keep actual issuance executed. |
| return-cost | Independently read s and beta,u from configuration, observe s to coordinator and g to block fees_collected; final receipt y-s-g. Native loss x-y is observed separately and never deducted again. | Omit s, omit g, route g to operator, or deduct x-y again: `RETURN_SERVICE_SPLIT` / `RETURN_NET_CREDIT`; vary beta/u and confirm g changes. No constant-g shortcut. |
| bucket-disposition | Real y<=h, including equality, plus no-slot and closed-account cases. No receipt or sequence increment; preserve authenticated fixed attribution in bucket, not operating income. Follow Native value out of custody into protected coordinator bucket. | Send y to free operating balance, issue a zero/underflow receipt, or drop attribution: `BUCKET_ATTRIBUTION_VALUE` / `NO_ISSUANCE`. Fail at post-publication semantic oracle, not an intentionally malformed inbox. |
| phase0 | Real phase0 predecessor, exact created_lt match; strong bounce settles directly regardless of zero queue_removed_height. | Feed zero to the height-window decision as though it were an observed removal: `PHASE0_MATCH_ACCEPTED` must fail on the otherwise valid run, not proof rejection. |
| conservation | Independently reconstruct each term at committed batch boundaries. Eligible return: R/N each +(y-h), P/W each -x. Bucket branch: no net backing/confidential credit; track protected bucket value separately. | Perturb one term at a time: its component oracle first, plus the two accounting identities. Never rely only on left==right to catch common errors. |
| vq-refusals | Use the old contract's pinned pre-change input/feature-OFF fixtures and independently compare the actual stable output bytes; retain its three original validator refusal sites. | Change a refusal outcome while holding input/mode fixed: `LEGACY_REFUSAL_BYTES`. String identity alone is not complete behavior evidence. |
| onoff | Same real custody bounce under OFF. Positively identify the original disabled-operation refusal; separately observe no execution, zero transactions and no candidate export. | Enable execution/publication under OFF: `OFF_REFUSAL` / `OFF_ZERO_PUBLICATION`. Do not infer these from an error code. |
| oracle-control | Retain a successfully executed credit/fee/sequence mutant while disabling only its paired oracle. | The driver must fail `ORACLE_CONTROL_NOT_DETECTED`. A child exiting zero must not turn an undetected mutation into a green contract. |

For no-slot/closed-account cases, never fabricate a usable account ID if the
body cannot supply it; existing D29/D62 attribution rules still govern. The
bucket contract independently covers sweep/return execution; this item covers
Failed-to-bucket handoff. These are different execution paths.

## WITHDRAWAL-PREPARE: same nine names, D78 markers

Run the existing prepare runner; marker is now
`WITHDRAWAL-PREPARE_D78_OBSERVED:<full-name>`. Prelock observations do not qualify.
The old contract's real host-input, kernel-capable-of-rejecting and atomic
publication requirements remain. Current semantic changes are:

| Suffix | Current fixture / observation / failure |
|---|---|
| debit | Proof binds checked T=x+q; total confidential debit checked T+f. x/q/f separately identifiable. Put f in T or omit q/f from debit: `COMMITTED_TOTAL` / `DEBIT_COMPONENTS` after successful relevant upstream verification. |
| overflow | Overflow x+q before scalar conversion must be rejected; debit addition likewise checked. Mutation wrapping either sum fails its arithmetic-stage oracle. T bound remains proof-owned; do not add a V_max constructor gate. |
| no-pending | Full authenticated user/system dictionaries and both counts unchanged by prepare; mutation installing a receipt fails `PREPARE_PENDING_CUT`. |
| record | Versioned per-account control record, independent count; ΔW=ΔP=x, q excluded. Old tags rejected. Mutate either amount or omit W while publishing payout: `PREPARE_RECORD_COMPONENTS`. |
| cap | Missing authenticated K_withdrawal or Withdrawal f_state => ConfigInvalid, no local defaults; owner-triggered due settlement before capacity check. Due no-bounce close costs no fee and installs no receipt under D78. |
| fee-admission | Required f and required-1 each have their own matching real proof, both pass real kernel; corrupted proof separately fails. Only the fee gate rejects the lower f at `FEE_ADMISSION`. |
| enqueue | Serialized value=x, actual fee=q, rich flags=3; actual created_lt recorded with same-batch enqueue. Mutate each independent link: `PAYOUT_PRINCIPAL`, `PAYOUT_FEE`, `PREPARE_ENQUEUE`. |
| onoff | Old OFF refusal positively observed, execution/publication independently absent. Unchanged scope, new interface fixture. |
| oracle-control | Disable only paired oracle with applied, reached mutant retained; driver must fail. Unchanged mechanism, new interface fixture. |

## Other existing tracked obligations under D78

The six sequence obligations remain, but successful Failed settlement (not Paid)
is the Withdrawal issuance fixture. Pure Paid consumes no deposit_sequence.
Three source kinds remain: Deposit, Withdrawal settlement, bucket sweep. D69
Deposit transcript bytes and all old SEND/COLLECT wallet vectors remain unchanged.

In the seven-item remaining-work mapping, `paid-lazy` now checks only P/W release
and record removal: R/N, Native balances, fee pool, pending/counters and sequence
all unchanged. Mutating any phantom refund, slot or fee fails `PAID_ZERO_PHYSICAL`.
`late-return` checks y-h issuance and distinguishes already closed records
(ΔP=ΔW=0) from expired-but-open records (both -x); no second release. Window is
height-derived, not record-presence-derived. These changes do not certify either
item. `activation-freeze` removes max_bounce_cost entirely; existing explicit
configuration/freeze obligations remain for the window and M5 wiring values.

Inherited live greens remain evidence about their original versions, not this
interface. No post-D78 Native execution or full contract completion is claimed
here. Historical y+b-h measurements and frozen predictions are preserved;
see the new D78 symbolic prediction for the changed design.
