# M4 fee prediction comparison and COLLECT pricing text

## Evidence order and scope

The prediction was committed in `2d2829853`, in
`doc/uno-m4-fee-prediction.md`, before the coordinator requested the new
observation. This document is subsequent to that prediction. It records results
reported by the coordinator, not a separate execution by B.

Independence was behavioral, not structural: A's implementation files were
present in B's worktree. B did not read the fee calculation, validator
reconstruction, or A's expectations when deriving the prediction; code reading
was limited to authenticated input declarations and source comments. The first
attempt had no committed expectation artifact and does not qualify as the
predictive comparison. The committed new-input experiment was its replacement.

## Coordinator-reported comparison

Inputs: base=1000, slot_fee=250, send_tip=7, collect_tip=11, in nanotomi.

| Component | Committed SEND prediction | Reported SEND observation | Committed COLLECT prediction | Reported COLLECT observation |
|---|---:|---:|---:|---:|
| S | 250 | 250 | 0 | 0 |
| C | 1000 | 2288000 | 3000 | 2639000 |
| T | 7 | 7 | 11 | 11 |

The coordinator identified an implementation error: proof-work counts 2288
and 2639 were used as billing weights instead of SEND=1 and COLLECT=3. A
acknowledged that its tests used the same incorrect formula. No change to the
prediction or specification formula is needed to explain the discrepancy.
SEND's C was 2288 times the prediction; COLLECT's C was 2639/3, approximately
879.67 times the prediction. These ratios describe C, not the total fee F.

For scale only, at base=1000000 and slot_fee=3000000 with tip explicitly zero:

| Operation | Correct F (TOS) | F under the reported erroneous weights (TOS) |
|---|---:|---:|
| SEND | 0.004 | 2.291 |
| COLLECT | 0.003 | 2.639 |

This is arithmetic extrapolation, not another measured run. Both erroneous
values exceed V_min=1 TOS. The base_max bound is on the unit price, not a general
bound F <= V_min/2: the specification itself gives a three-unit COLLECT at
base_max as 1.5 V_min, before tip. That distinction remains true after fixing
the implementation's billing units.

The discrepancy was exposed by independent derivation, a committed prediction
before observation, and comparison. A's tests shared its mistaken formula;
B's prior kernel/codec tests did not implement this fee settlement. This is not
evidence that either test suite independently detected the pricing error.
No repaired implementation result or complete M4 regression is claimed here.

The specification was not ambiguous about these units. Line 765 explicitly
warns that D28 billing units are an accounting abstraction, not the D31
proof-work admission units, and that the two cannot substitute for each other
despite coming from the same authenticated configuration. That warning was
already present in the September 8 implementation-check corrections. The
implementation and its tests nevertheless shared the same contrary formula.
The written warning did not prevent this occurrence; the committed independent
prediction and subsequent comparison exposed it. Documentation states a
constraint, while mechanical checks and independent comparisons can detect
violations; neither is a proof that every future violation will be detected.

## What k means in the current specification

Source: `/home/tomi/memo/TOS_UNO_PRIVACY_WORKCHAIN_V2.md`, read without consulting
the fee computation or its tests.

- Sections 6.2 and 12, lines 413 and 747, retain the notation `f_collect(k)`.
- D28, line 767, explicitly assigns COLLECT three billing units for **any**
  k <= K_collect. This is the total for one COLLECT, not three units per item.
- Lines 771 and 815-816 give f = f_state + base_compute * units + tip, with
  COLLECT f_state=0 and units=3. Hence, for fixed base and tip, the current
  formula is f_collect(k)=3*base+tip throughout the valid k domain.
- No normative k-to-tip rule or other k-dependent fee component was found.
  A caller may choose a tip, but the protocol does not prescribe it from k.
  The explicit static tariff used for this prediction has one collect_tip.
- D18 at line 570 prices each newly created pending slot against the cleanup
  cost of forced k=1 collection, rather than amortizing that slot price over a
  full batch. This is not a definition of three billing units per receipt.
- D25 at line 751 motivates charging for COLLECT using measured cost. It does
  not require proportional pricing by elapsed time or by k. The recorded
  k=1/8 timings at line 570 are 11.8/37.9 ms; they are historical measurements,
  not new measurements made for this comparison.

Thus k affects the operation's statement, proof work, and admissible selection,
but has no varying coefficient in the current fee formula. The surviving
`f_collect(k)` notation should be clarified as constant in k for fixed base and
tip, or renamed by the specification owner. It does not justify implementing
3k, nor does cost variation alone contradict a deliberately flat billing
weight. The reference from D28 to D18 does not itself derive the numerical
weight three; D28 supplies that weight explicitly. No pricing rule or
specification text is changed by this document.
