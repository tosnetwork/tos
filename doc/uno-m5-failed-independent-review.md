# Independent funded Failed review: components and OFF artifacts

Reviewed A `2ebcd2cff9a6322b5b9ccba56c8dac8fbf700ab8`, parent
`09a94d798ea9b9b7c68f10a128c00de817d89141`. B source remains based on
`74279b51e`; no A/shared production files changed. The eleven-item prospective
WITHDRAWAL-FAILED contract is unchanged. This is a retrospective review after
seeing A's report, not a new pre-observation prediction.

## Results

| Item | Conclusion | Evidence strength |
|---|---|---|
| Native return cost 3930 | Correctly identified | B independently decoded actual bounce phase: 1309 collected + 2621 forwarded |
| Slot 3000000 | Authenticated test-profile slot fee | Config decoded independently, installed S component and Native coordinator delta agree |
| Compute 8 | Checked base 2 times billing units 4 | Config, source, actual transaction fee, helper parameter variations and isolated constant-g mutant |
| Gross custody recovery | Actual y=9996070, not x=10000000 | Actual message/transaction/account artifacts and direct source chain |
| Five stable OFF artifacts | Byte-identical | B compared bytes directly, not A's comparison script |
| Three old refusal sites | Bodies byte-identical; complete three-site behavior not established | Independent occurrence-aware source extraction plus one concrete OFF artifact pair |

No missing g was found. This does NOT establish the full Failed contract, all
classification paths or default production availability.

## Direct component provenance (locations in the pinned A commit)

`crypto/test/workchain-m3-node-engine.h:316-317` requires Failed, Deposit and tariff
profiles. Lines 359-362 pass the resolved `deposit.slot_fee`, `operation_tariff.base`
and `failed.issuance_billing_units` into the helper. These are from the authenticated
TEST configuration, not frozen production defaults. `workchain-m3-business-config.h`
encodes the explicit units at 124-125 and reads them at 181-184; the encoded input
has a value, not an omitted-field fallback to four. A zero/other future policy's
legality or the production business-config codec is outside this review.

`crypto/block/workchain-failed-funded.h:79-85` computes, with overflow checks:
loss=x-y; compute=base*units; fee=slot+compute; cost=loss+fee;
gross=y+b; issued=gross-fee. Cost must fit original reserve in this narrow funded
branch. Line 117 materializes separate S=slot, C=compute, T=0 components.
`workchain-operation-fees.h:74-77` preserves those fields;
`workchain-m3-node-engine.h:368-376` publishes the returned fees with the roots.

`workchain-native-allocation.h:63-75` sends S from custody to coordinator.
`transaction.cpp:4937-4948` subtracts C+T separately into Native transaction fees;
it does not retain C as coordinator revenue. This explains why a helper fee
field alone would be insufficient evidence: B also decoded the actual custody
transaction's `total_fees`, which equals 8, and coordinator's balance change,
which equals 3000000.

For y, `workchain-withdrawal-association.h:70-77` decodes original principal from
`original.value` but received amount separately from CURRENT `info.value`.
`workchain-failed-funded.h:71-85` uses received for y; it does not substitute x.
The physical credit is independently constructed: allocation overlay
`workchain-allocation-overlay.h:145-150` calls the custody import participant;
`transaction.cpp:4774-4782` delegates to entry construction, `:4879` stages credit,
and `stage_workchain_credit :4417-4461` validates the actual envelope's destination
and `info.value`, then checked-adds that value. No W principal enters that credit
function. Native fee subtraction happens separately afterward. The helper's
`recovered/released_p/released_w` numbers are not themselves Native balance edits.

## Independent decoding of A-produced accepted artifacts

B wrote a separate decoder (`observe.cpp`), not a call to A's live observer.
Input files were taken from `/tmp/uno-m3-live-8x3sz5uk`, copied with SHA256 hashes
into this report's evidence directory. The recipient candidate's decoded root
was checked against its archive ID. Its transaction input matches the actual
prepare payout; its output matches the exact `failed-bounce.boc` hash.
The decoded ordinary transaction bounce phase provides `msg_fees=1309` and
`fwd_fees=2621`. Only AFTER reading those fields does the probe compare their sum
3930 with x-y. Thus 3930 is not merely a name given to a subtraction.

Independent observations:

```
config: base=2, issuance_billing_units=4, slot_fee=3000000
old W: x=10000000, b=4000000
bounce actual value y=9996070
custody:    989999643 -> 996995705, delta=6996062
coordinator: 21003000250 -> 21006000250, delta=3000000
custody serialized transaction total_fees=8
installed aggregate system receipt=10996062
old W cardinality=1, final W cardinality=0
```

The probe asserts individual components: custody delta=y-(slot+g), coordinator
delta=slot, actual transaction fee=g, installed effects S/C independently, and
receipt=y+b-slot-g. It does not infer these from equal conservation sums.
It reads actual installed receipt amount and roots, but does not independently
re-decrypt N_hidden or revalidate the chain/Merkle transition in this review.
Artifact creation/acceptance remains A's execution; decoding/comparison is B's.

## Parameter dependence and meaningful red

Using the actual predecessor roots, actual accepted entry inbox, domain and
explicit policy above, B invoked the pinned helper with the real system-encryption
backend. Each case starts from the same predecessor independently; these are not
multiple concurrent issuances. Only the indicated resolved helper input changes:

| Change | g | slot | returned receipt |
|---|---:|---:|---:|
| original base=2, units=4 | 8 | 3000000 | 10996062 |
| base=3, units=4 | 12 | 3000000 | 10996058 |
| base=2, units=5 | 10 | 3000000 | 10996060 |
| slot increased by one | 8 | 3000001 | 10996061 |

In an isolated header copy only, replace
`__builtin_mul_overflow(policy.base_compute, policy.issuance_billing_units, &compute)`
with `(compute = 8, false)`. Original-case observations still pass; the base-change
case fails at `parameter.cpp:61`, the exact compute-fee assertion, exit 1.
Restore the original header: all four cases pass again. Receipt calculation,
Native artifact reading, decoder and expectations were not changed for the mutant.
This excludes a hardcoded eight in the helper. It is NOT an authenticated
configuration-change block or a complete modified host publication test; the
resolved policy perturbation is an explicit test input. No default CTest coverage
or eleven-item handoff completion is claimed by these standalone probes.

The probes were freshly compiled against B's compatible codec headers and the
pinned A helper, linking existing Native dependency libraries and the real Rust
system-encryption backend. They are not a full clean build. Initial missing
include/type dependencies and an incorrect augmented-account iteration in the
independent decoder were tool/instrument failures; selecting the recorded payout
recipient's dictionary entry corrected the latter. None is a product failure,
and no expected monetary value was edited to make the probe pass.

## OFF: independent byte comparison, with honest scope

B directly read the five BEFORE artifacts at the fixture root and AFTER artifacts
in `validator-off-after-evidence/`. Every length and byte matches:

| Artifact suffix | Bytes | Content |
|---|---:|---|
| calls | 19 | config=1, execute=0 |
| validation.delivery | 9 | recorded |
| validation.kind | 6 | error |
| validation.message | 89 | cannot execute configured workchain: multi-account admission and replay are not connected |
| validation.result | 15 | validate -7201 |

`off-comparison.json` records both paths, SHA256 and exact contents; raw copies
are retained. B did not rerun A's script or use its `cmp` result as evidence.
A's log/build attribution supplies which binary produced before versus after;
B did not independently rebuild/re-run the validator pair or certify its binary
provenance. Logs/timings/DB files are not included in the byte-equivalence claim.
These five files alone do not prove absence of every possible publication side
effect, nor that all three refusal paths executed.

B separately extracted each old refusal body from parent and target Git objects:
`validator_account_binding_custom` (78-79),
`validator_account_binding_ready` (85-86), and the account-binding visitor in
`check_transactions` (parent 6714-6715, target 6772-6773).
All THREE bodies, including permission checks and LocalUnavailable return with
`multi-account admission and replay are not connected`, are byte-identical.
The comparison retains position/identity and multiplicity, not a set of strings
that collapses three identical diagnostics to one. Details/source hashes are in
`refusal-source-comparison.json`.

The concrete OFF pair reaches the configuration/custom refusal. It does NOT
independently execute ready and transaction-visitor refusals. Therefore the
contract's full `vq-refusals` item remains unclosed despite this correct byte
comparison and unchanged bodies. Collator's fourth refusal was not independently
exercised here. No exhaustive behavioral equivalence is claimed.

## Remaining boundaries

Known incarnation classification/unknown-source-counter gaps remain outside this
narrow component review; they are not fixed or accepted. No sequence guard is
retired, and no missing contract test is relabeled green. Shortfall, late/Paid,
no-receipt threshold, all three separate OFF paths and the full authenticated
publication mutation/oracle-control matrix remain separate acceptance work.
