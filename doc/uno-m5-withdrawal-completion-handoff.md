# WITHDRAWAL-COMPLETION: independent post-D78 controls

Source: memo a131b9bb, V2 specification SHA256
187dbc79290d6816162815fe323b8a126e33ab6828b6d92217e7a24dbbe401ee.
Derived from the normative section 11.2 table at lines 919–933 and section 11.3
at 1069–1088; NOT the superseded prose below the table or appendix H. This was
written without reading A's new completion implementation. A's messages about
its partial work are not execution evidence for these controls.

## The important correction: row 6 is not identifiable from P/W either

Table row 3 and row 6 BOTH have `(delta R, delta N, delta P, delta W)` =
`(y-h, y-h, -x, -x)`. Row 5 is `(y-h, y-h, 0, 0)`. Row 6 is nevertheless
required to execute the **out-of-window** path. Under D78, a row-3 misroute can
leave **every amount, both conservation equations, and record deletion unchanged**.
Therefore the row-6 oracle observes the actual dispatch/callee entry, separately
from the published arithmetic. The trace must be captured where execution enters
the late-return admission or within-window Failed path, not synthesized later
from height, copied from proposed effects, or labelled by the test's expected row.
If both paths currently share all code with no observable classification boundary,
that is an adapter gap: report NOT READY rather than claiming totals prove routing.

Closed-account returns are **row 9**, not row 8 in this version. The independent
cases below cover small value (7), full slot (8), and closed account (9).

## Common fixture and observation boundary

Use real Native payout/bounce envelopes, authenticated old account/control and
bucket roots, independently read configuration, and actual committed successor
roots/transactions. Establish phase 1 using D73: real prepare enqueued the message,
then authenticated higher-height queue absence established Q. Do not fabricate
phase 1, use Q=0, or infer prior enqueue from absence. Bounce height comes from
the actual import. No locally chosen production values for conditional freezes.

Measure each R_actual from custody Native balance, R_book from the independent
ledger, N_book from independently decrypted rights; enumerate P/W from their
corresponding actual messages/records. D=0 remains structural if no persisted
counter exists; do not call it a measured counter. Observe the complete account
control dictionary, user/system pending roots and enumerated counts, the shared
sequence, coordinator holdings/balance, Native transfers, actual fee destination,
and fixed bucket attribution. Snapshot all components at one committed batch.

`workchain_withdrawal_completion_oracle.py` provides a reusable Python/JSON
observer and `expect_red` driver. Its selftests supply **synthetic observations**
to test the observer. They do not discharge any real case below. A real adapter
must independently extract the observations above; a JSON file or marker alone
cannot establish provenance. `pending` in the JSON is a target/amount projection;
unchanged system/user roots additionally protect the complete no-entry cut.
The real adapter must validate enumerated counts against authenticated maps.

Run readiness with:

```
python3 crypto/test/workchain-withdrawal-completion-handoff.py --build BUILD
```

All eight exact CTest names must be uniquely registered, enabled, executed,
and emit `WITHDRAWAL-COMPLETION_D78_OBSERVED:<full-name>` only after positive,
semantic-mutant, oracle-disabled and restored runs. Missing or unobserved tests
exit 1 and are named. No registration exists for pretend successful host tests.
These carriers refine existing Paid/late/bucket obligations; they do not retire
or automatically increment either the prepare or Failed contract.

## Required real carriers (in priority order)

All names below start `test-workchain-withdrawal-completion-`.

| Suffix | Fixture and executed path | Observation and expected red |
|---|---|---|
| `row6` | Phase1 record still open; authenticated arrival at Q+window+1; y>h, live account with slot. Also use the same record at Q+window as a within-window positive control. | Expired case executes late-return admission, credit y-h, deletes this record, deltaP=deltaW=-x. **Mutation: force only the dispatch to row3**, preserving otherwise-valid inputs and arithmetic. Must fail `LATE_NOT_ROW3` on the actual branch trace; receipt/amount equality is deliberately insufficient. Exact-boundary positive must show the within-window path really can execute. No earlier association/proof/height-arithmetic error qualifies. |
| `row4` | Real phase1 expiry, no bounce, no intervening owner touch, then authorized new Withdrawal or close triggers lazy closure. Observe a prior untouched expired block too. | Before touch record remains; after touch selected old record actually disappears with one closure event, deltaP=deltaW=-x. Settlement contribution has zero R/N, zero value-moving messages, no receipt/sequence/issuance fee. Mutation suppresses closure → `RECORD_CLOSURE` or `ROW4_TRIGGERED`; injects a transfer (even offset by reverse transfer) → `ROW4_NO_VALUE_MOVEMENT`; adds debit/fee → named component delta. Check expiry precedes K_withdrawal cap: a full old set with this expired record admits an otherwise valid new Withdrawal. |
| `row5` | Row4 truly completed first, then a late authenticated self-describing bounce with y>h and slot. | Late admission credits y-h; P/W do not change again; no missing-open-record refusal. Route to row3 requiring an open record must fail this positive execution at the late-admission oracle, not be counted as a desired rejection. P is independently guarded: a payout-reference mutation reaches `DELTA_P`. W is carried upstream by `RECORD_CLOSURE`: an actual surviving-record principal decrement is rejected there; removing only that check on the same artifact reaches `DELTA_W`, retained as a cross-check. |
| `bucket-small` | Authenticated late return, open expired record; test y<h and y=h. Keep room in primary bucket and no return_failed flag. | Type2 bucket disposition committed; no system receipt/sequence/g. Record closes per row6, P/W decrease x. **Refusal without disposition** → `DISPOSITION_MUST_PUBLISH`; returning apparent success without installed bucket → `BUCKET_FIXED_ATTRIBUTION`. y=h+1 with slot provides positive issuance boundary. |
| `bucket-full` | Same late-open return with y>h but authenticated system map exactly full; bucket has room. | Existing pending roots/counts unchanged; installed type2 attribution and physical protected holdings, no issuance; closes old obligation as row6. Removing the bucket fallback while retaining helper error must fail the publication/disposition oracle. Also verify removing one pending item restores direct admission. |
| `bucket-closed` | Account genuinely closed before authenticated late return (row9), bucket has room; rich body still supplies target ID. | No account resurrection, no pending/sequence, no second P/W release; type2 bucket retains target ID. A clean helper refusal with no bucket commit is red, not a passing negative test. Open-account counterpart must be able to admit. |
| `sweep-atomic` | Eligible attributed type2 entry, actual authorized sweep, account open with slot and y>h. | All four D63 components below independently observed in **one batch**. Four mutants each omit one component, plus mixed-batch and retained-error/early-publication variants. Each must hit its named oracle; zero-return-code or aggregate equality alone is not enough. |
| `oracle-control` | Each preceding real semantic mutation retained while ONLY its paired observer is disabled, then restored. | Driver raises `ORACLE_MISSING:<assertion>` when expected red disappears; earlier errors raise `WRONG_FAILURE_LAYER`, not success. The observer-only default selftest is not this real-host CTest. If a premise says another gate passes, independently demonstrate that gate can also fail. |

The `sweep-atomic` fixture covers successful type2 credit, not a returned message
re-entering the bucket. D62 re-entry, retained `return_failed`, and subsequent
retry prevention remain owned by the existing BUCKET-SWEEP `return-once` and
`terminal` slots; successful removals alone do not discharge those slots.

Sweep authorization uses the execution-time entry set and has no automatic
expiry; the precise count/order, sequence-consumption and unbounded-wait scope
is stated in the existing [BUCKET-SWEEP contract](uno-m5-bucket-sweep-handoff.md#common-fixture-execution-and-observation-boundary).
The same requirements apply to this fixture; they are not yet execution evidence.

### Row4 measurement cut: do not charge its trigger to settlement

A new prepare itself spends x+q+f; closing may spend a fee from registration
refund. Neither becomes a row4 fee. Preserve the complete committed before/after
snapshots and an independently derived/observed contribution of that triggering
operation, with its own existing anchors. Subtract only that contribution when
passing the settlement observation to the oracle. Alternatively run a paired
otherwise-identical operation without the expired obligation and compare its
value effects. Do not normalize using the settlement's proposed effects: that
would subtract away precisely the bug under test. Preserve the trigger's new
record separately; the normalized record cut removes only the expired record.

A direct helper call with manually assigned phase1 is useful unit coverage but
cannot supply the above authentic queue/owner-trigger execution. No-action totals
are insufficient: the selected record and actual event must show closure occurred.
The row4 observer deliberately does not require y or any issuance-fee configuration:
there is no bounce and no issuance in this branch.

### Bucket disposition versus net value

The bucket remains physically at coordinator, not custody. The primary fixture
keeps room in both attribution levels; overflow loss of account_id is not an
excuse here. Decode exactly `(kind=2, src, account_id, tomis, return_failed=false)`
with no body or variable attribution payload. Verify a committed same-batch
physical move/holding increment, not a helper error or a proposed effects entry.
Retain account closed status and all pending roots/counts on the rejected admission.

The table has dashes for bucket monetary entries; **it does not supply a magic
zero Native routing fee**. The adapter must read authenticated incoming y and the
actual cost of the bucket move, derive the retained net with checked subtraction,
and compare that net with the actual bucket entry and physical holding. No local
default for that cost is permitted. Issuance did not happen, so g/slot issuance
income and sequence consumption must not appear. If the actual routing/cost
surface is unavailable, this remains NOT READY; do not fill the expected net
from the bucket record being tested. The oracle's `native_bucket_cost` is an
explicit observed input, not a new policy decision.

### D63: four requirements, separately named

For y in the bucket, s the slot fee, g=base*units, and t=y-s-g>0:

1. `D63_1_PHYSICAL_TRANSFER`: actual coordinator→custody transfer equals t;
   R_actual and R_book independently increase t.
2. `D63_2_HOLDINGS`: actual protected bucket holdings decrease y.
   This is carried upstream by D60's holdings/event pairing requirement, not
   independently reachable. Removing only that pairing check on the same
   mutation reaches `D63_2_HOLDINGS`; retain this assertion as a cross-check.
   D60 now carries both its own protected-holdings floor and this D63 component:
   narrowing, conditioning or relocating its pairing check can weaken D63_2
   without the ordinary downstream cross-check turning red to warn of that loss.
3. `D63_3_FEE_DESTINATIONS`: coordinator operating income s; actual block
   fees_collected contribution g. The coordinator balance decreases y-s;
   D60 slack increases s, **not s+g**. Verify destinations, not just deductions.
4. `D63_4_INSTALLED_CREDIT`: N_book/decrypted installed receipt increase t,
   exactly one successful sequence consumption and one system entry.

`D63_SAME_BATCH` requires all four observations from the same committed batch,
not four independently successful steps. All-or-nothing publication is carried
by section 9.3's overlay-and-commit architecture, not an assertion in this
contract: an error prevents candidate generation; changing actor scratch is not
publication. No premature-publication mutation has been established. The earlier
`D63_ABORT_ZERO_PUBLICATION` synthetic oracle selftest is not a real-host control.
No existing fail-closed artefact has been identified that covers arbitrary
engine writes outside the overlay, splitting publication from commit, or partial
external writes before returning an error. This is an acknowledged architecture
regression gap for appendix I.4, not a tested atomicity guarantee. The registered
Native payout-pair nonpublication test covers caller-owned Accounts/out_msgs only;
the I13e publication contract explicitly remains unwired. Neither closes this gap.
Not every omitted
component necessarily breaks every conservation equation; component assertions
are mandatory even when aggregate equalities happen to survive.

## Evidence status and remaining queue

Fresh evidence here: observer selftests and readiness-runner selftests; real-host
readiness is **0/8, fail-closed**. The row3-for-row6 substitution is observed red
in the independent **observer**, not claimed as an executed A host mutation.
The same precise mutation is required from the eventual adapter. No A completion
source or live output was used to set expected values. Historical predictions and
existing evidence remain untouched.

After this delivery, Native executable provenance binding and a current-schema
successor to the historical schema3 account-mutation driver remain distinct queued
work. Neither is closed by these controls or by the Rust wallet freshness pin.

### Subsequent execution: row4 closed, 2026-09-12

The initial 0/8 statement above describes delivery time. The frozen criteria are
unchanged. `test-workchain-withdrawal-completion-row4` now runs by default and
passed in 311.22 seconds: real Q=6, an untouched expired height, owner-triggered
closure, and an explicitly authenticated full cap of three. Isolated real-host
mutations reached `ROW4_TRIGGERED`, `ROW4_NO_VALUE_MOVEMENT`, and `DELTA_R_actual`;
disabling each paired oracle produced `ORACLE_MISSING`, and restoration passed.

Recorded candidates, predecessor states, configuration, block history, observed
JSON, selected actual callee logs and checksums are in
`measurements/uno-m5-withdrawal-completion/row4-real/`. `ctest.log` records the
default-suite result; `controls.log` independently rechecks the retained JSON.
This closes row4 only (1/8 here, 1/27 overall). Native executable provenance is
still a separate open limitation; these artifacts do not retroactively pin a
binary to its source. Other completion slots and the full readiness runner
remain fail-closed.

### Subsequent execution: bucket-small closed, 2026-09-12

The default bucket-small CTest passed in 638.76 seconds. Independently checked
observations give h=3,000,008: h-1 and h retain attributed bucket value, while
h+1 executes late issuance. Refusal and missing attribution hit their designated
oracles, both oracle-removal controls fail, and restoration passes. B also
reconstructed the equality-boundary observation from the accepted Native
artifacts and ran the frozen oracle again. Evidence is in
`measurements/uno-m5-withdrawal-completion/bucket-small-real/`.
This makes 2/8 here and 2/27 overall; other slots are not implied complete.

## Row6 closure: fresh default execution, 2026-09-12

Default CTest #19 passed in 213.23 seconds. Evidence is in
`measurements/uno-m5-withdrawal-completion/row6-real/`. The fresh pair used the
same Withdrawal identity, Q=6 and window=2: actual height 8 dispatched through
within-window-failed and actual height 9 through late-return-admission. These
are executed observations, not expected fork outcomes.

The isolated shadow changes only `late = arrival_height > deadline;` to
`late = false;` in `crypto/block/workchain-failed-funded.h`. Its accepted Native
candidate reaches `LATE_NOT_ROW3`; disabling the oracle while retaining that
observation reaches `ORACLE_MISSING:LATE_NOT_ROW3`. Restoring the production
header passes. Retained observations were independently rechecked after CTest.
The durable carrier is the default registered test; archived logs and JSON
identify this execution. Native artifact source provenance remains a separate
limitation; these selected artifacts are not a full standalone replay package.

Completion is now **3/8** (row4, bucket-small, row6). The coordinator corrected
the project inventory to 49 across seven runners (9/10/8/8/7/6/1); the other six
runners were not reaudited here and no closure is inferred for them. Earlier
27-slot totals describe only prepare, failed and completion, not the project.

## Row5 failure-layer investigation (not slot closure)

The owner's try-1/otherwise-2 ruling yields different answers for P and W.
`measurements/uno-m5-withdrawal-completion/row5-controls/` preserves actual
accepted observations, validation results and exact isolated header patches.
Replay uses the existing carrier's `shadow_binary` and `replay_paid` against
the late fixture after an independently observed Paid closure. No production
header or frozen oracle was edited.

* **P: try 1 succeeds.** In unmatched late admission, redirect one surviving
  record's payout LT to the returned original payout LT. The latter record is
  already closed. IDs/principals are unchanged; actual historical payment
  enumeration changes P by +9,999,863 and W by zero. The intact oracle rejects
  at `DELTA_P`, with `ORACLE_MISSING:DELTA_P` when disabled.
* **W: outcome 2 for the declared account's obligation set.** W is the sum of
  installed record principals, not a separately writable balance. Helper
  `released_p/released_w` metadata has no publication consumer. Decrement a
  surviving record's principal by one with checked subtraction in unmatched
  late admission: actual P stays unchanged, actual W decreases one, and
  `RECORD_CLOSURE` rejects the changed ID-to-principal map. This is specifically
  an obligation change caused by late admission, not a generic refusal. The
  same receipt and late dispatch remain intact. Removing ONLY that upstream
  oracle on the same accepted artifact reaches `DELTA_W`; with the intact
  oracle, DELTA_W remains a cross-check, not the primary carrier for this change.
* A second actual mutation deletes another live record: P/W each fall 137,
  the original closed ID remains absent, and `RECORD_CLOSURE` rejects the
  unrelated obligation release. Both record mutants also produce the paired
  `ORACLE_MISSING:RECORD_CLOSURE` red; restoring the header passes.

The mutated live driver exits after candidate publication on its own backing
assertion. The independent adapter requires validator acceptance and rebuilds
the candidate state; its named oracle red is therefore not an earlier Native
send/association rejection. Scope is this account's record projection and the
executed late-return path, not an exhaustive proof about all account updates.

Positive artifacts establish Paid block 8 (P/W -10,000,000) followed directly
by late block 9 (P/W zero), with identical Paid-after and late-before roots.
The old fixture's missing untouched alias was copied from its actual saved
before-state; fresh fixture generation now writes it itself. No state was
fabricated. Formal row5 registration/closure remains pending; completion stays
3/8. The original requested DELTA_W red is not relabelled as observed.

Row5 subsequently closed with default CTest #20: 246.49 seconds, including
fresh actual Paid/late root continuity, both semantic controls, oracle-disabled
controls, the W upstream-removal check, and restored execution. See row5-controls
`default-ctest.log` and `default-controls.log`; retained default-run observations
were independently checked again. Completion is **4/8** (row4, row5, row6,
bucket-small). No other runner or end-to-end authenticated queue-budget negative
is certified by this result.

Bucket-full closed with default CTest #21: 508.50 seconds. Full 4/4 slots
produce a type-2 attributed bucket entry; a real COLLECT removes exactly one
selected receipt (other encoded entries preserved), with authenticated updates
linked to the late predecessor; 3/4 then issues normally to 4/4. Refusal without
disposition reaches `DISPOSITION_MUST_PUBLISH`; omitted account attribution
reaches `BUCKET_FIXED_ATTRIBUTION`; each has an oracle-disabled red and restored
execution passes. Selected execution traces and independently rechecked actual
JSON are in `measurements/uno-m5-withdrawal-completion/bucket-full-real/`.
Completion is **5/8**; bucket-closed, sweep-atomic and oracle-control remain.
No other runner or end-to-end queue-budget claim is changed.

Excluded closure replay `/tmp/uno-closed-closure-after-engine.log` (fixture `uno-closed-closure-after-engine-Y70s2o`) was case **(b)**: the originating wallet pin passed (the replay retained that wallet observation), no `WALLET_FRESHNESS_MISMATCH` occurred, and exclusion was manual because a Native C++ header rollback overlapped compilation; the wallet pin does not bind the Native binary/dependency build.

Bucket-closed closed with default CTest #22: 406.95 seconds. The adapter
rebuilds the actual accepted close, checks active-to-closed with no pending/W,
links its successor to the late predecessor, and verifies the late publication
leaves the complete closed account root unchanged. Arrival installs type-2
fixed attribution; no immediate return-to-src is substituted. The active-account
/closed-Withdrawal counterpart still admits. Both named publication/attribution
mutants reach their intended oracles, oracle-disabled controls reject, restored
execution passes. Actual JSON was independently rechecked after CTest; selected
artifacts are in `measurements/uno-m5-withdrawal-completion/bucket-closed-real/`.
This phase-1 fixture does not establish generic closure liveness (including an
account with zero available balance and a still-phase-0 obligation). Nor does
it independently certify receipt of the Native registration refund.
Completion is **6/8**; sweep-atomic and oracle-control remain.
