# Isolated activation-pair infrastructure

This unit does not add a collator path and does not establish live I13e
acceptance. The shared activation classifier and its earlier-failure self-check
are owned by A. B defines no alternative diagnostic, source-origin check, or
classification fallback. The resolver calibration CTest imports that helper, runs its colocated self-check,
and invokes its production-origin check. It fails if the helper is missing; that
is not a skipped test. Until the shared source is merged into this worktree, an
explicit WORKCHAIN_ACTIVATION_HELPER path can reference the one committed helper
in the integration worktree. Evidence must pin that helper's separate source
commit and byte hash. No local copy or fallback is permitted.

`test-workchain-activation-control.cpp` constructs fresh Param 8, 12 and 84 cell
dictionaries inside each test case. There is no configuration path argument,
file-loading API, deployment path, shared mutable configuration source, or
production registry modification. Each case owns its registry. Cells are immutable.
The two configurations differ in the capability bit; descriptor, engine parameters
and ingress policy are otherwise identical. Their actual configuration root hashes
are output alongside raw status codes/messages. Registering or omitting the local
test engine does not change either configuration root.

This is a single-account resolver calibration, not a substitute for the future
multi-account engine/profile fixture. It executes the real
`resolve_scoped_workchain` boundary. Registered + enabled resolves successfully;
registered + disabled fails; unregistered cases fail earlier with two exact known diagnostic forms. Both
are classified False by the shared helper; other unknown forms remain exceptions. In particular the
production boundary itself generates -7201 for both the earlier failure and the
activation failure. No test-side conversion supplies that code. These real status
observations feed the shared helper's identity check. A disabled resolver
success exits immediately with 323 and requires coordinator reporting.

The resolver probe does not produce transactions or export candidates. It does
NOT invent zero counters to impersonate collator observations. Future live callers
must supply actual host transaction counts and candidate-export observations to
`workchain_activation_control.check_pair`, which imports A's shared classifier.
Source uniqueness and the shared classifier self-check must be run by that same
acceptance driver according to the shared helper API. Resolver calibration must not be used as a completed live acceptance result.

`check_pair_context` checks necessary, insufficient record constraints: a final typed local-error discriminator, non-success
and local failure code, zero transactions, no exports, same run/path/input/common
configuration, internal configuration provenance, opposite capability states,
distinct config roots, and a reached enabled frontier. Its synthetic unit vectors
are schema-validator tests only. A string field declaring internal provenance is
not proof of provenance; actual configuration constructors and the host adapter
must be reviewed and calibrated separately. Neither the schema checker nor a
configuration hash establishes whole-path equivalence on its own.

Every live caller must create a fresh exclusive run directory, construct both
configurations internally from the same immutable test recipe, run both sides,
and archive both observations together. No stale report or deployment path is an
acceptable input. Never classify an early unrelated -7201 as activation rejection.
Unexpected disabled-path success is a hard stop, not a fallback or a skip.

The optional CMake module registers the checker only on explicit inclusion. Its
static-library group is for the Linux private build's block/VM circular symbols;
no production build/link target is changed. Python, the probe binary and the shared
helper are required dependencies. Missing dependencies must fail.

The execution/recovery seam is specified separately in
`workchain-publication-execution-order.md`. Neither this unit nor that specification
opens the final commit gate, grants consensus finality, or permits sending.

Only the final typed host result may populate closed-control status fields. Never
parse logs or use a process return code to choose between candidate rejection and
local abstention. The resolver calibration emits fields from its actual returned
`td::Result`; it does not establish a validator terminal observation boundary.
A candidate-reject schema vector with otherwise unchanged diagnostics must fail
316. The live serializer still needs its own calibration when it exists.
