# Final second-seam classification evidence

This directory supersedes the test-source checkpoint in
`../uno-v2-second-seam-classification/`. Review followup removes the immutable
input postcondition (it was not a side-effect measurement) and verifies the
explicitly converted TVM selector by round-tripping the descriptor's key.
No production implementation changed during that followup.

Both controls are rerun against the final test bytes: wrong-mode changes the
batch classification to true; old-refusal puts back the prior LocalUnavailable
result. Each compiled successfully, exited 1 at its distinct assertion, was
restored byte-for-byte and explicitly rebuilt before the next mutation.
`restore-audit.py` reconstructs both mutant hashes from final source bytes,
checks recorded failure identities and restored positive output, and verifies
the final executable/test hashes. Four cases are positive classifications;
only the changed batch arm has new mutation evidence. The unchanged legacy
arms are not claimed to have new mutation controls.

Actual mutant executable: `build/test-workchain-collator-compute-mode`.
Every mutation/restoration explicitly builds that target with `-j32`.
Final rebuilding also explicitly names `test-tos-collator` (the other consumer
of the mutated header), `test-workchain-settlement-continuation`, and
`create-state`, besides `all-tests`. Counter CTest runs its lifecycle CMake
driver, its fixture CMake worker, then `crypto/create-state` and
`test-tos-collator`; all indirect executables are included in that list.
The collator executable was not rebuilt with either mutant.

The first-seam adapter/settlement controls are historical evidence for
unchanged code. Their positive tests, including real readiness, run again in
ordinary regression. Private I13 harnesses do not. No test here claims live
batch admission/replay: required-workchain refusal is still earlier than the
classifier and the final execution-path refusal remains closed. Literal
visitor refusals: collator 1, validator 3, plus registry 1.
