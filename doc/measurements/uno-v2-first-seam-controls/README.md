# First seam: settlement continuation controls

Scope: establish the first collator seam shape, not live admission/replay or
I13 acceptance. Twelve controls are recorded in the immediate subdirectories.
Run `python3 doc/measurements/uno-v2-first-seam-controls/restore-audit.py` from
the repository to reconstruct each mutant from final source bytes. It requires
one original occurrence, zero mutant occurrences, exact restored hashes, final
test-source identity, successful mutation compilation, the intended failure,
and successful explicit rebuilding and positive execution after restoration.
The script checks the exact control-name set, current restored binary hashes,
target-link lines in both compile logs, and all restored positive scenarios.
Historical mutant binary hashes are recorded and distinct; without retaining
those executable bytes this is not independent reconstruction of mutant binaries.
The delivery commit is the commit adding this README (`git log --diff-filter=A
--format=%H -- doc/measurements/uno-v2-first-seam-controls/README.md`); after
commit, the source blobs are independently checked against these same baselines.

| Control | Required observation |
| --- | --- |
| combined-entry | Actual registered engine body count 2; exactly-once assertion fails |
| settlement-observer | Empty admitted footprint is incorrectly accepted without observer |
| input-binding | Valid but different admitted input is incorrectly accepted without binding |
| usage-tracking-bypass | Settlement succeeds but actual settlement tracking reads are zero |
| usage-node-handoff | Returned node no longer belongs to the caller's tree |
| state-snapshot-handoff | Returned admission snapshot is missing |
| effects-budget | Authenticated effects cell limit is bypassed; invalid result accepted |
| output-budget | Authenticated output cell limit is bypassed; invalid result accepted |
| early-adapter-release | Real readiness loses the adapter before old-state unpacking |
| terminal-adapter-release | Real failed collation omits release before statistics delivery |
| binding-observation | Real disk observer corrupts the lifecycle field; checker rejects it |
| missing-state-classification | Missing local state admission is mislabeled CandidateInvalid |

Identity positive/negative checks run with every scenario: the token belongs
to its inspected adapter, a separately bound adapter yields the exact local
identity-guard result before entering the engine, and the original adapter
executes once. These are private fixtures, not a live admission token.
The tracking test starts a fresh tree after execution, observes settlement
reads, and compares its proof with the empty-tree proof, so prior engine loads
cannot supply its positive counter. This is not a new unmetered/metered live
proof equivalence claim.

Only the recorded target is compiled while each mutant is installed:
`test-workchain-settlement-continuation` for the private continuation controls,
or `test-tos-collator` for the three actor/disk controls. The exact executable
is explicitly rebuilt after every restoration;
the per-control commands and binary hashes are in record.json. No aggregate
target is used as a substitute. Final compilation additionally names
`test-workchain-block`, `test-tos-collator`, and `create-state`, alongside
`all-tests` and the continuation target. The counter CTest command is cmake,
which launches counter-fixture-lifecycle.cmake, then the worker script, then
`crypto/create-state` for Fift genesis and `test-tos-collator` for each node
invocation (including the probe self-test). Its system helpers are cmake,
base64 and filesystem operations; no further node executable is hidden behind
the CTest command. Private opt-in I13 drivers are not run in this regression.

`../uno-v2-first-seam-controls-checkpoint/` is superseded, not final evidence.
It includes an initial combined-entry restoration which changed indentation
and was caught by SHA256 comparison; exact source bytes were restored before
continuing. Its input negative used malformed framing and was subsequently
strengthened to valid framing with only the candidate changed. All eight
original controls here were rerun on the final strengthened test source;
four followup controls use that source or the unchanged readiness driver.
`checkpoint-eight-controls-audit.json` is the pre-review audit, not the final
twelve-control report. Early test
authoring compile errors and the original invalid fixture last-trans-LT are
not counted as guard evidence.
