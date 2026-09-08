# Private old-state replacement admission: review disposition

Scope: the uncommitted follow-up to `3966d2022`, not live multi-account
execution. The focused review is a working record in the memo repository,
`reviews/uno-v2-state-replacement-dependency-review-20260908.txt`.

| Finding | Disposition |
| --- | --- |
| F1: leaf-only, one-level, single-write fixture | Accepted. Retain the original leaf witness and add explicit 00/01/10/11 keys, a fork sibling, overlapping currency dictionaries with child references, and two sequential replacements. Removing deep-reference traversal fails on actual/charged counts 17/14. |
| F2(i): add a per-sibling limit | Disputed as a required mechanism. D31 authorizes aggregate old-state and per-account closure bounds, not per-subtree bounds. An augmentation summarizes multiple accounts; imposing one account's limit on that summary is not the approved account invariant. No local or configuration limit is invented here. |
| F2(ii): repeated traversal work | Accepted as a live-enablement blocker. The physical union is not a CPU-work counter. The current bound is at most declared writes times 256 path levels times admitted state cells, plus ordered-set operations. Numeric acceptance must include this work, or traversal must be improved with a separately justified closure-completion cache. A charged hash alone never certifies a completed closure. |
| F3: aggregate exhaustion should be authenticated-state corruption | Disputed. A candidate selects its read/write set. The same valid old state can fit individual batches but not their union. Exceeding the authenticated aggregate allowance is CandidateInvalid; malformed/unavailable authenticated data is local failure. An account exceeding its own persisted-account invariant is a different condition. Treating every aggregate overage as corruption would let over-budget declarations force abstention. Mandatory system progress and feasible configured allowances still require separate acceptance evidence. |
| F4: implicit Read mode | Fixed. Remove the default and name the mode at every caller. Restoring the default makes the compile-time expression assertion fail specifically on the newly callable three-argument overload. |
| F5: settlement lifetime outside the meter | Accepted as incomplete integration, not closed by this fixture. Carry admission through all later Native reads and independently verify the complete footprint before live enablement. Existing Native lookup, replacement and difference algorithms remain unchanged. |
| F6: trailing fork data | Fixed. Require Native-equivalent exhaustion of the fork extra slice. Before the fix, the independent Native decoder rejected the fixture but admission accepted it and the rejection assertion failed; after the fix it throws VmError before loading extra references. |
| F7: traversal order comment | Accepted clarification. Account closure uses lower-ref-first DFS; lookup walks top-down and admits each opposite sibling before the selected child. These are separate deterministic traversals. |
| F8: footprint changes profile interpretation | Record the development boundary. Profile 2 is not a deployed live execution contract here; the readiness gate remains closed. This fixes its incomplete implementation before calibration. A deployed semantic change would require the release/version discipline, not reuse of this development rationale. Singleton profile 1 is unchanged. |

The review's exception-boundary observation is conditional: the existing
singleton dispatch catch is not a new multi-account outer boundary. It does not
prove the private runner or a future live caller is protected. Authenticated
source typing and the full multi-account exception boundary remain required.

Manual mutation artifacts are one-shot evidence, not recurring mutation CI.
Ordinary test registration does not change that distinction. No M1 criterion
or complete D31 acceptance is closed by this disposition.
