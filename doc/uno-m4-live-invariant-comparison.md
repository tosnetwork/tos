# M4 live invariant prediction: reported comparison

The frozen prediction is `doc/uno-m4-live-invariant-prediction.md` at
`808b4f9d0`. This separate document records the coordinator's subsequent
observations relayed from A. It does not modify the prediction.

All supplied comparison rows agree with the prediction. B checked the
substituted arithmetic, but did not run or directly inspect the live sequence.
The coordinator reports nine successful blocks and nine successful OFF pairs.
Raw per-step state readings and a run commit were not supplied in this message;
this document is a comparison of the reported results, not a replacement for
A's execution evidence or an independent replay of it.

## Inputs and arithmetic

The coordinator identifies the tariff as base=2, slot_fee=3,000,000,
send_tip=5 and collect_tip=7, with two Deposits of 1,000,000,000 into A.
Thus X=2,000,000,000, q1=q2=q3=13 and h=3,000,007.
The collected-fee observations 7 and 13 agree with these inputs; those two
observations alone do not uniquely determine the tariff.

| Quantity | Substitution in the frozen formula | Result |
|---|---|---:|
| S total | slot_fee | 3,000,000 |
| C total | 10 * base | 20 |
| T total | send_tip + 3 * collect_tip | 26 |
| F total | S + C + T | 3,000,046 |
| D32 contribution to fees_collected | C + T | 46 |
| SEND amount v | X - q1 - q2 - h | 1,996,999,967 |
| Final confidential rights | X - F | 1,996,999,954 |

The SEND amount exceeds V_min=1,000,000,000. The predicted intermediate A
available amounts are 999,999,987 after COLLECT #1, 1,999,999,974 after
COLLECT #2, and zero after SEND. These intermediate numbers are substitutions,
not additional observations supplied by A.

## Reported comparison

| Frozen prediction | Report relayed by coordinator | Assessment |
|---|---|---|
| A available at closure = 0 | 0; A closed | Matches |
| B available = X - F | 1,996,999,954 | Matches |
| v = X - q1 - q2 - h | 1,996,999,967; SEND leaves A at zero | Matches |
| registered_accounts = G0 + 2 | 2; closing does not decrement it | Matches for fresh G0=0 |
| R_actual = R_book = N_book = R0 + X - F | All three 1,996,999,954 | Matches for R0=0 |
| Confidential rights equal N_book | Test-key-decrypted total also 1,996,999,954 | Matches |
| Final system/user slots empty for both accounts | 0/0 for each, read from actual final state | Matches |
| D = P = W = 0 at committed boundaries | Structural consequence of the atomic operation set; D zero per block | Structural agreement, not three measured counters |
| SEND collected fee = base + send_tip | 7 | Matches |
| Each COLLECT collected fee = 3 * base + collect_tip | 13 for each of three COLLECTs | Matches |

In particular, the reported backing and N_book terminal values include the
same F reduction. COLLECT is not treated as fee-free internal redistribution.
The coordinator also reports three controls becoming red and returning green
after restoration: unequal R values, nonzero D, and changing only the
confidential-side fee deduction. These are relayed test outcomes, not tests
executed by B. The structural-zero description of D/P/W must not be replaced
by a claim to have read three independent persistent counters.

Historical registration deposits and refunds remain outside the principal
equations, as explicitly required by the prediction. This batch does not
supply separate refund-message and historical-deposit observations; no new
independent refund validation is claimed here.

## Metering and context sizes

The reported producer/validator unit pairs agree for all nine blocks:

`433, 433, 7, 7, 2639, 2639, 2649, 2639, 441`.

These are proof-work units, not D28 billing units. The coordinator explains
the SEND difference from the old 2288 observation as the same profile-4
formula with different context input lengths:

- Old prototype: fixed operations 2222 + context 66 = 2288.
- This live input: fixed operations 2222 + context 427 = 2649.

The coordinator also reports a correction to its M3 acceptance record:
registration/closure use `encode_workchain_replay_context()` (426 bytes),
whereas SEND/COLLECT use `encode_workchain_transfer_context()` (427 bytes).
Its `git log -S` check found both encoders already present at M3 completion;
this was not an M4 split. The former claim that all four operations shared
one canonical encoder was incorrect. This provenance check is attributed to
the coordinator, not presented as newly performed by B.

## Scope and independence

The reported nine-block total fees_collected=51,895 and final coordinator
Native balance=11,008,999,900 lie outside the numerical prediction: they
require Native/system fee inputs beyond the D32 tariff. Neither number is
counted as a match or mismatch. In particular, 46 is the predicted D32
contribution, not a prediction of all block fees.

Four qualifications remain:

1. Independence was behavioral, not structural isolation. Implementation and
   prediction files were available across the worktrees; the parties declared
   that the prohibited material was not read before prediction/observation.
2. The first fee-comparison attempt had no committed prediction artifact and
   did not qualify. The later committed predictions were the corrective method.
3. Observations here passed through the coordinator; B did not directly
   observe the run.
4. P/W, and the stated committed-boundary treatment of D, are structural
   assertions, not independent persistent-counter measurements.

The earlier fee prediction exposed proof-work/billing-unit confusion
(SEND compute charge 2288 times correct, COLLECT 2639/3 times correct).
This live comparison instead agrees on every supplied prediction row.
Together they demonstrate the utility of committing an independently derived
expectation before observation; neither establishes correctness beyond the
tested sequence and reported evidence.
