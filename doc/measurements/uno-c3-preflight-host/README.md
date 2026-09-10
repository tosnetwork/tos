# C3 host contract and private controls

This is a **post-M1 host mechanism**, not C3 closure. The prerequisite
"an identified production preflight implementation exists" is currently
unsatisfied. No authentication adapter, admission-version authorization,
production inspector, block accumulator, or live call site is installed here.
The C2-facing interface reserves an explicit nonzero allowance before invoking
the inspector; collator and validator must implement their own accumulation
and derivation. Synthetic test limits do not supply authenticated configuration.

See [the contract and open integration obligations](../../../crypto/test/workchain-preflight-budget.md).
In particular, C2 alone leaves a preflight-sized hole. No-grace for preflight
depends on a budget known before inspection plus complete operation coverage;
the old `proof_work` declaration is checked after its callback and cannot meet
that condition. The closed gate is the reason the current incomplete state is
acceptable, not permission to move it.

## Evidence and exact scope

The base is `dd2327c90a6fd2c4d74f2579bd6afaadcbf246d7`. New code is bound by
archived full source files and SHA-256, **not claimed to exist in that base
commit**. Build source/dependency commands identify the measured header and
fixture. `report.json` records the final overlay hashes and native binary hash.
The isolated build is `/tmp/uno-c3-host-f2h9jo/build`; no shared Counter fixture
or previous build directory is used.

The private module registers `test-workchain-preflight-budget-gates` with a
Python driver, timeout and resource lock. It runs nine named native cases,
checks a pinned count against the native dispatch table, and requires every
completion marker. Normal registration of the six private I13 harnesses and
the default build behavior are unchanged. C3 has its own opt-in label.

The final matrix is 24 single-site source controls, all compiled successfully,
with exact failed-assertion checks. The controls include reservation amount and
ordering, operation precharge and arithmetic, sticky failure, primary reason
and exception payloads, empty selection, native/driver selection disagreement,
omitted completion, and a driver that must produce CTest **Failed**.
Every mutation is restored byte-for-byte, then the actual native executable
is explicitly rebuilt with `-j32`, checked against the baseline binary hash,
and all nine cases rerun. Neither `all-tests` nor rebuilding a Python/CTest
entry is used as a substitute for rebuilding the executable it actually runs.

Restoration audit reloads the archived original source, report and mutant bytes
from disk and independently reconstructs each edit. Separate damaged-original
and damaged-mutant evidence copies must fail that audit at their specific
checks; these are artifact-reader controls, not additional native cases.
Successful runs, expected failures, mutated files and restore logs are all
retained in `raw-controls.tar.gz`. The archive producer reads every member back
and verifies its hash before writing `report.json`.

Final readback verified **742 files**. Archive SHA-256:
`4d9c886b03c50a09d28a0ecb075793b28225765abedf48b3542c30680700bf64`.
The registered final JUnit result is one passed test, zero failed/skipped, whose
output contains all nine completed-case markers. All 24 source controls failed
at their prescribed assertions and restored the original source/binary hashes.

The initial pre-review eight-case run and initial 23-control batch remain in
the raw archive as historical checkpoints. They are not substituted for any
part of the final nine-case / 24-control batch.

## Review and residual boundaries

The host contract and tests received an initial read-only review and a focused
follow-up; [disposition](review-disposition.md) records the changes and the
declined override suggestion. No review transcript is stored in the repository.

The whole-repository removed-domain guard **does not pass** at this base.
The raw scan reports 103 findings in 13 existing files, including the root
build file and the embedded-tool/stdlib evidence directories. Every hit file
is compared byte-for-byte with the base commit in the archive audit. A second
scan with the new source files staged must have exactly the same output.
No exception, path rule or evidence content was changed to make it green.
This unit does not claim all-gates-green or silently classify these findings
as C3 test results.

All explicit native target builds use `-j32`. Fresh root configuration itself
also invoked the repository's existing OpenSSL setup, whose internal command
uses `make -j16`; that configuration output is retained, not described as an
all-`-j32` build. No root build-system changes were made for this private unit.

Full default builds, ordinary full regression, the private I13 harnesses and
production preflight were **not** run for this additive, opt-in unit. Both
production seam files must remain byte-identical to the base, with refusal
counts collator 1 / validator 3. No M1 acceptance or network reachability is
being extended by these private checks.
