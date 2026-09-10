# Prepared validator decisions: isolated calibration

Source commit: `9eff940be54517e3dd3c2e7d95c17b51f01c2c67`.
**Prepared, not connected.** No production visitor, registry gate or actor error
handling is changed. The tested implementation resides under
`crypto/test/prepared/` and is compiled/called only by an opt-in private target.
It is not a dormant production call site or a parallel collator implementation.

| Mutation | Only failing case | Numeric failure |
| --- | --- | --- |
| custom-answer | 0: resolved binding must not use legacy custom compute context | 1311 |
| custom-old-refusal | 0: resolved binding supplies an answer | 1310 |
| ready-old-refusal | 1: resolved binding supplies local readiness success | 1320 |
| custom-candidate-invalid | 2: missing local engine remains LocalUnavailable | 1331 |
| ready-candidate-invalid | 3: missing local engine remains LocalUnavailable | 1341 |

All five mutants compiled. Each ran all four cases: exactly its specified case
failed and the other three passed. Each mutation was restored byte-for-byte and
the actual executable target explicitly rebuilt before all four restored cases
ran successfully. The mutation/reapplication hashes were independently recomputed
from the committed blob and the archived replacements. Both the main-source
baseline and final restored-copy registered CTest passed (one actual test each,
no skip). Production refusal files remain byte-identical to `c55fa45e7` in both
source trees; their hashes are included.

The fixture parses the committed real genesis and uses the production scoped
resolver with a configuration-only registered account engine or an empty
registry. It does not pretend the fixture engine executes a batch. Failure
assertions distinguish local error codes from CandidateInvalid, but no real
ValidateQuery final-result classification or downstream reachability is claimed.
That gate evidence remains A-2. The prepared source has no candidate acquisition,
I13 verdict, synthetic transaction counter or synthetic export observer.

`report.json.gz` lists the explicit target/rebuild command and actual executable,
fixture hash, source commit/blob and both binary hashes. Full build/runtime
streams, including empty ones, are compressed losslessly. The standalone runner
is `crypto/test/workchain-validator-local-controls.py`. It requires a separate
checkout at the source commit and mutates only its prepared header. This run
reused the real-path disposable source/build directories from the merged-build
work, checked out at the pinned B commit and reconfigured for this opt-in target;
no source/build symlink was introduced. CMake caches retain build provenance.

`initial-compile-stop.gz` records the first development compile failure: the
old never-run draft passed argv directly where td::read_file requires explicit
CSlice conversion. This was corrected before the source commit and is not a
mutation or application-guard result. Neither this archive nor successful
private compilation moves D45's refusal point.

The A-2 handoff states partial coverage, names the exact earlier calibration
and confirms the successful-fixture raw-sidecar retention limitation. It is
included to prevent duplicated or inflated claims across the two work streams.
