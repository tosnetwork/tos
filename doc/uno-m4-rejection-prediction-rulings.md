# M4 rejection prediction: coordinator rulings

This addendum records the coordinator's rulings on the questions in the
prediction committed as `f1c7d39ad`. The original prediction is unchanged.
These are specification decisions, not rejection-run observations.

## Type-2 bucket sweep and section 3.2

Confirmed specification defect: section 3.2's blanket prohibition on bucket
credit/sweep changing R/D/N_book/W/P is too broad for D29's mechanical type-2
Deposit admission. The coordinator directs that section 3.2 be narrowed to
explicitly accommodate that paired transition; D29 is unchanged. Its mechanical
destination and explicit conservation pairing meet the purpose of the rule,
which is to prevent unpaired changes through the bucket.

This does not block M4: the coordinator reports type 2 structurally
unrepresentable in M4. The specification correction is a prerequisite for M5,
not a claim that the current text is already consistent or has been edited.

## Physical location of unexpected value

Confirmed specification defect: section 11.3 identifies the problem of a
stranger sending directly to custody, but does not define how bucket recording
removes that value from backing when R_actual is the entire custody Native
balance. Neither a subtraction of bucket holdings from R_actual nor a physical
transfer out of custody has been specified. Neither solution is selected here.

This is not merely a failed derivation: it was reported and the coordinator
explicitly ruled it an undefined specification boundary. It must be resolved
before implementing that direct-to-custody path.

The M4 rejection prediction remains applicable to ordinary section 11.1
Deposits addressed to coordinator. Rejected value never enters custody on that
path, so custody and R_actual do not increase. This conclusion must not be
generalized to all section 11.3 destinations.

## Return amount and retained bucket value

No specification defect was declared for the absence of a numeric return
amount. Bounce value and retained bucket net value require actual Native fee
inputs; neither may be assumed equal to claimed x or full imported value.
Insufficient value can prevent creation of a bounce altogether. The original
prediction's conservation equations and fee-input qualification remain in force.

## Prerequisites recorded by the coordinator

Before the relevant M5 paths are enabled:

1. Closure must account for the requirement that the account have no bucket
   attribution, extending the previously recorded closure expiry action.
2. Section 3.2 must explicitly accommodate D29's paired type-2 admission.
3. Physical handling of unexpected custody-held value must be defined before
   the direct-to-custody path is implemented.

This addendum does not implement those conditions, change an expiry guard,
or assert that M4 supplies their missing mechanisms.

## Specification maintenance finding

The coordinator identifies two instances in this round of the same pattern:
section 3.2's earlier absolute statements were not updated after later decisions
introduced paired changes, first D32 fees and then D29 type-2 admission.
The coordinator subsequently reports completing the section 3.2 cross-check,
finding four defects: the missing fee term, the statement that SEND/COLLECT
do not change N_book, the blanket bucket-sweep prohibition, and residual
Claim/ack/Deposit-refund text after deletion of the Claim mechanism. The
physical location of bucket value is separately an unanswered design question.
This completion is attributed to the coordinator; it is not a claim that B
performed that section's scan or that the specification has been corrected.

Behavioral independence and observation provenance remain as stated in the
prediction. No rejection result is inferred from these rulings.
