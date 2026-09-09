# Shared activation consumer: final calibration

B source: `9f6e93a25b5e16c1b12ce6b9a695fb3ba54613ee`.
Shared helper: `c519361489d68708f7695f05fab8576397e78319`,
`crypto/test/workchain-activation-rejection.py`, loaded directly from the
integration worktree without copying it. The inventory binds the helper and its
real-input provenance to committed bytes. The default module path uses the same
helper after integration; this split-worktree run explicitly selects that file.

The helper owns both classification and four-row expectations. B invokes its
seven colocated checks, its unique-source check against B's production tree,
and `check_scoped_probe_output` on the freshly executed real resolver output.
No B classification table, wildcard, prefix stripping, or validator boundary is
introduced. Both known earlier failures must fail the consumer's activation
requirement; success and unknown-domain calibration belong to the shared helper.

The consumer-only mutation removes required shared-helper acceptance at guard
315. Python syntax compilation succeeds. The shared helper checks and context
unit vectors still pass; the consumer fails with typed ControlFailure identity
341 upon accepting the first earlier failure. Later consumer iterations are not
reached in that mutant and are not counted as passing. The context source is a
single exact committed-byte shadow; original/copy/mutant/restored/reapplication
hashes are recorded. Production and shared-helper files remain unchanged.

The separate renamed-context artifact records thirteen removals, each failing
only its designated schema vector, including the final typed local-error versus
candidate-reject distinction (316). Schema transaction/export fields are unit
inputs, NOT a simulated live candidate or evidence of actual zero effects.

CTest is genuinely registered by the opt-in module. An absent helper path and
physical removal of the probe binary each produce a failure element, no skip,
and nonzero CTest result. Restoring each dependency makes the same registered
test pass. These are dependency-propagation measurements, not production guard
or error-classification evidence. The missing binary is restored to its original
SHA256. All stdout/stderr files, including empty ones, are retained.

Final source guard passes. The rebuilt standard WorkchainBlock group executes
124 tests and passes. This does not claim the entire repository test suite or
live I13e acceptance. Deployment/activation/final commit gates and validator
sources are unchanged. Future live reverse controls must serialize the actual
final typed result and observe real transaction/export outcomes. Neither a log
line nor process exit code supplies that classification.
