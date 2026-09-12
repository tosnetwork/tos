# Unknown-origin execution tripwire

Specification: memo `802939ca`, SHA256 prefix `713fe38358cb2e87`.
Zero is necessary for the observed wiring run, never sufficient for complete
classification. The counter is a tripwire, not a certificate.

## Observation surface

The process-local, saturating atomic counter observes unclassified returned
Status codes at these account-execution boundaries:

- proof-preflight callback category normalization, before the old generic local
  return would erase the unknown code;
- D59-enabled collator account-batch result;
- validator account-replay final failure result.

Success and the already classified CandidateInvalid / LocalUnavailable /
AuthenticatedStateCorrupt codes retain their behavior. Other returned codes,
including legacy zero and neutral codec failures with no attached provenance,
emit `WORKCHAIN_UNKNOWN_ORIGIN`, increment the counter and abstain as -7201.
The diagnostic includes the static boundary name and original code/reason;
neither code wording nor exception class is used to infer candidate provenance.
The existing proof-preflight generic local return message is preserved.
Normalized local errors are not counted again at an enclosing boundary.

This does not detect errors swallowed before those boundaries, incorrect
already-known classifications, other execution profiles, or paths not executed.
Known local exceptions remain classified by their existing source scopes; the
counter does not certify that those scopes are all correct. It is diagnostic,
not authenticated state, a consensus limit, a fee, or an admission configuration.
It saturates rather than wrapping to zero, has no runtime reset, and does not
depend on whether a log consumer displays ERROR messages.

## Discriminating controls

`WorkchainProofContract.UnknownOriginTripwire` first ran with the local fallback
but no instrumentation. Three unclassified returns produced `0 != 3` at the
counter assertion (`/tmp/uno-unknown-red.log`), not a build/setup failure.
It also checks known codes with the same message remain unchanged, success
does not count, and passing a normalized error through another boundary does
not double-count.

The live control uses a test-only registered forwarding engine. It resolves
the same configuration and executes the real funded Failed transition, then
replaces its private result with legacy code zero before publication. The
driver requires -7201 at the unknown boundary, count=1, real proof work=7,
one engine call, zero Native transactions and no candidate export. OFF requires
its original refusal and count=0. The control is separate from the normal
accepted operation; its deliberate count=1 is NOT acceptance evidence.

Normal paired live operations require explicit counter sidecars containing
zero at process exit; a missing sidecar fails, it is not interpreted as zero.
This observes the collator/validator execution process, not public chain state.
The standalone archived-validator OFF probe is outside this new live sidecar
writer and must not be claimed as a counter observation.

## Measured checkpoint

Default CTest `test-workchain-proof-contracts` passes 1/1 (three contained
tests). Fresh full live `uno-m3-live.py --m5-failed` exits 0 in
`/tmp/uno-m3-live-v909pwpk` (`/tmp/uno-unknown-live.log`). The deliberately
unknown run logs boundary=collator-account-batch, code=0, the injected cause,
and count=1; the driver verifies work=7, -7201, zero transactions and no export.
Every ordinary OFF/ON run and the known-incarnation negative reports count=0.
The normal Failed publication still has R_actual=R_book=N_hidden=996995705,
receipt=10996062, sequence 1->2, P=W=0. The injected engine runs in a separate
process/DB and never contributes an accepted block to that sequence.

No direct injected-unknown validator replay was run in this checkpoint; the
validator call site is installed and the normal replay reports zero in the
shared collation/validation process. Do not describe this as symmetric unknown
fault-injection coverage.

Prepare guards passed 2/2 and the D59 permit inventory guard passed 1/1 without
changing their predicates. No full default-suite green is claimed.

## Boundary review disposition

Claude Code reviewed the consensus/error boundary read-only. Its proposed
blocker that `_Exit(disk_collator_tool_main(...))` necessarily suppresses the
sidecar is not applicable to the exercised path: collation failure calls
`std::exit(2)` inside `validator/manager-disk.cpp:274`, and completed acceptance
calls `std::exit(0)` at :400, before the outer `_Exit` can execute. Fresh actual
sidecars contain 1 for the injected error and 0 for normal execution. An early
return/abort without that exit callback still fails closed on missing evidence;
it is not counted as zero. No source change was made to accommodate that
incorrect call-flow inference.

The review correctly notes the old proof-preflight contract also maps known
`AuthenticatedStateCorrupt` (-7202) to its generic local status. This is NOT an
unknown returned code and is not counted here: contextual misuse of an already
known category is outside this counter's coverage, like other misclassifications.
The preflight hook observes the unclassified cases before normalization, not
every kind of category loss. The old contextual-category behavior is unchanged.
The review also identifies raw effects/declaration mismatch and parameter-codec
errors as real potential producers; their provenance still needs individual
adjudication/controls. The generic promise error retains the original cause only
in the ERROR log, not in the returned status message. These are explicit limits,
not a claim that the instrumentation completes their classification.

## Remaining obligations

The existing-account/schema classification surface found by the incarnation
review remains open. No Failed/prepare contract or sequence expiry guard is
retired by this instrumentation. The unrelated association codec exception
test remains untouched. No complete provenance census or M5 acceptance claim.

## Observation-channel follow-up (2026-09-12, before D78 migration)

Specification anchor: memo 368e663c, SHA256 prefix aa0b65776506eed3.
The reported universal `_Exit` blocker was withdrawn after checking the real
callee termination paths. Prior greens are not invalidated by that refuted
claim. Keep the working atexit registration: moving its save after the callee
would miss the actual std::exit paths.

The parent now distinguishes an unavailable sidecar explicitly with
UNKNOWN_ORIGIN_OBSERVATION_UNAVAILABLE and exit 2, rather than aborting through
move_as_ok. Missing evidence is never an observed zero. Reader controls exercise
missing, zero, one, and one-when-zero-is-required (the last reports
UNKNOWN_ORIGIN_OBSERVATION_MISMATCH). These controls exercise the reader only;
they are not evidence that a real child emitted a count.

The shortfall skip has been removed: injection follows successful real engine
execution and applies to this branch too. Fresh default CTest
test-workchain-withdrawal-failed-shortfall-positive-partial passes 1/1 (35.43s),
including unknown-enabled count=1, LocalUnavailable, and no publication, paired
with normal count=0. Log: /tmp/uno-counter-shortfall-pair.log; detailed output
was inspected in the build's Testing/Temporary/LastTest.log.

After rebuilding test-m3-live, three fresh serial harness invocations also
completed with exit 0: --m5-failed, --m4, and ordinary M3. Logs respectively:
/tmp/uno-counter-failed-pair.log, /tmp/uno-counter-m4.log,
/tmp/uno-counter-m3.log. Ordinary Failed includes the same real count=1 injection;
M4 ends A=0/B=1996999954, M3 A=987999514/B=0. These are observations of the
pre-D78 implementation, not evidence for the forthcoming changed statement.

Coverage remains the executed fixture/process paths, not runtime coverage of
all eleven disk-tool exits. No direct validator unknown injection, complete
classification proof, full contract completion, or guard retirement is claimed.
