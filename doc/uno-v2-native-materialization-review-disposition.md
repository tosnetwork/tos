# Native closure and owned-inbox review disposition

This is an M1 component checkpoint, not M1 acceptance. The initial read-only
review is recorded in `~/memo/reviews/uno-v2-native-materialization-review.txt`.
It ran no builds or mutations. Follow-up controls are recorded with exact
substitutions, source hashes, commands and raw output in
`measurements/uno-v2-native-materialization-evidence.json`.

| Finding | Disposition | Evidence or remaining obligation |
|---|---|---|
| F1: limit outcome mapping | Fixed clarification | Exceeding an exact authenticated whole-candidate allowance rejects that candidate, never causes local abstention. Exhausting a temporary acquisition slice has no independent consensus verdict. No production mapping is installed here. |
| F2: zero limits | Disputed as a blanket requirement | These are raw acquisition allowances, not configuration validation. Empty input permits zero limits; a real empty cell needs zero bits. Both have positive tests. Production configuration validity and whole-input allocation remain separate obligations. |
| F3: pricing original roots | Fixed control; disputed predicted outcome | Switching pricing to the unavailable original roots aborts with `dereferencing null Ref<DataCell>`, not a silent one-bit undercount. The raw log preserves the actual diagnostic. Detachment remains useful independently of whether the legacy pricing walker is later hardened. |
| F4: effective level | Fixed | A real level-one pruned representation is returned with effective level zero. Removing the equality guard makes the identity test fail. |
| F5: virtualization and absent data | Fixed | Separate virtualized-view, loaded-virtualized-data and missing-data controls fail. Work counters distinguish early containment from a later error of the same class. |
| F6: private constructor | Fixed | Exact constructor inaccessibility is asserted; making it public fails compilation at that assertion. This is not counted as a runtime test. |
| F7: internal map consistency | Disputed as a live protocol guard | For immutable acyclic cell graphs, postorder completion and stable hashes imply every requested child exists and is complete. Defensive consistency returns remain local checks, not independently demonstrated peer-input rejection rules. |
| F8: exception sources | Fixed | The builder uses `finalize_novm`, not interpreter entry or `Ref::write`. The virtual loader is nevertheless inside the boundary. Eight concrete exception types are injected there, including `VmFatal`; removing each catch fails its test. These controls do not claim that every real builder call site throws. |
| F9: pruned representation budget | Fixed clarification | Counters cover encoded representation, not expanded proof or state cost. Separate semantic/state budgets remain required. |
| F10: peak memory | Fixed clarification | The map retains source and detached cells; duplicate-root work and output are O(roots), even with no additional cells/bits. Total auxiliary memory is O(cells + roots), not just the encoded payload size. No measured per-node overhead is claimed. |
| F11: source-aware virtualization classification | Deferred to production admission integration | Candidate-profile rejection and local Native acquisition have different provenance contracts. Do not infer a consensus verdict from the identical C++ predicate alone. Neither this raw materializer nor a local allowance is a replacement for authenticated, source-aware admission. |
| F12: runner gate | Fixed current documentation | The prior gate was in `workchain-account-settlement.h`, not the live single-account collator. This change replaces it with owned input and pre-engine role validation, while retaining the live integration gap explicitly. |

## Verification scope

Follow-up review: `~/memo/reviews/uno-v2-native-materialization-followup-review.txt`.
It inspected the 27 recorded controls without running them again, accepted the
F1/F2 clarification and corrected F3/F12. N1's count diagnostic is now separate
from invalid roles; this is diagnostic hygiene, not a new error class. N2 is
documented explicitly: the vector planner has no exception conversion, and a
Result signature does not promise no-throw execution under an active VM.
N4's direct algorithm/inbox includes are added. F7/F9/F10 are now also stated
at the materializer boundary. The final five-target regression, standalone
header command and source/binary identities are independently recorded in
`measurements/uno-v2-native-materialization-regression.json`; this supplies a
green runner against the post-mutation materializer, not a rerun of every old
mutation against that snapshot (N3).

Two follow-ups remain explicit. Before production wiring, local virtualized
acquisition must be distinguished from serialized, profile-forbidden special
candidate data; raw acquisition is not authority to change candidate validity.
Also, the fatal unavailable-cell pricing control does not prove every ordinary
Native caller is protected. Privacy-host pricing must consume detached closures;
hardening other Native paths is separate work, not an exception-catching claim.

The 22 closure controls comprise 21 rebuilt runtime failures and one intended
compile-time failure. The restored admission binary passes all nine tests.
The five runner controls cover the former rejection, pre-engine destination
validation, both inbound-bound forwarding paths, and committed inbox content.
Their recorded source snapshots precede the final closure exception-test
additions. These are manually run controls, not recurring mutation CI.

The runner fixture checks complete input hashes, exact import sums and credits,
real InMsg dictionary entries, payout/no-payout balances, ordering invariance,
and one engine call per execution. It does not authenticate a network queue,
establish complete aggregate admission, implement misdelivery record exceptions,
or prove live collator/validator symmetry. Registration, production version gates
and the remaining M1 integration are still open.
