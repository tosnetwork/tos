# Balance-kernel milestone review disposition

The milestone received a read-only Claude Code security review on 2026-09-07.
The verbatim record is `~/memo/reviews/uno-v2-kernel-implementation-review-20260907.txt`.
This document records changes and scope decisions, not an assertion that V2 is
production-ready. No host consensus judgement, custody or activation was changed.

| Finding | Disposition | Evidence or boundary |
|---|---|---|
| F1: identity COLLECT receipt handle | fixed | Each receipt handle is independently rejected before proof verification. The new test failed on the unchanged implementation at k=1, index=7. |
| F2: unfalsifiable nonidentity guards | fixed | Direct preparation tests exercise each public-key/new-handle/receipt-handle position; removing each of the three guard groups is a replayable mutation. |
| F3: missing policy/shape/alignment controls | fixed | Added invalid-policy, exact and over-limit context/proof, invalid relation/receipt shape and alignment witnesses. Shared policy validation now has the same priority in Rust and FFI. |
| F4: unmanifested build script | fixed | Validate the complete vendored file set, including root files, and reject symlinks. Git dependencies reject untracked files except Cargo's extraction marker. A disposable added build.rs must fail the gate. |
| F5: quadratic COLLECT cost | deferred, documented | ABI.md explicitly records dense matrix O(k squared) work/storage and per-call generator derivation. No internal K ceiling was authorized; production resource policy or a sparse implementation remains a separate decision. K=8 tests do not validate arbitrary K. |
| F6: SHA inequality posing as tamper control | fixed | Removed it. Mutate an actual disposable source file and invoke the real validator; disabling the set or hash comparison makes the tests fail. |
| F7: raw borrow lifetime | disputed as a defect | The private unsafe helper's lifetime is justified by the documented caller contract and its reviewed synchronous use, not by a type-level proof of arbitrary pointer validity. No pointer is retained. No stronger guarantee is claimed. |
| F8: mutation/differential runners outside CTest | deferred, explicit | Runners and C differential remain manual evidence. CTest enforces Rust/frozen vectors, vendor controls, header drift, source/graph gates and real FFI. A permanent full mutation job is a CI-policy decision, not silently claimed here. |
| F9: stale ignored V0 archive | informational | It is outside the active build target. Documentation distinguishes fresh archives from ignored historical artifacts; no unrelated local artifact was deleted. |
| F10: frozen mismatch diagnostic | fixed | Failures now report first differing byte offset and row as well as lengths. Existing transcript mutation exercises the failure path. |

One F3 detail was redundant rather than independently falsifiable:
`max_value != 0 && max_value <= max_balance` already implies
`max_balance != 0`. The duplicate zero-balance disjunct was removed and that
invariant is written next to the shared validation function. This does not
relax the accepted policy set.

The reviewer independently re-derived the eight SEND and 2k+5 COLLECT equations,
witness indexing, transcript event order and both independent range residuals.
Those findings support this implementation review, not unconditional knowledge
soundness, completeness of a production context codec or independent numeric
auditability of hidden balances.

See [the validation record](uno-v2-kernel-validation.md) for reproducible checks,
manual evidence, sanitizer limits and the incomplete indirect-call graph boundary.
