# Publication retry and actual engine execution: host wiring specification

This specifies the future shared host seam; it is not live integration evidence.
No collator/validator implementation, deployment configuration, activation gate,
or final commit gate is changed. The existing private publication mechanism does
not grant consensus finality or permission to send.

## Two concrete call sites

`WorkchainCandidatePublication::publish` in
`crypto/block/workchain-candidate-publication.cpp` first refuses unresolved
recovery, reads the persistent record for the supplied batch identity, and, if
present, returns through `read_and_release` without calling `Build`. Only an
observed absence plus a matching predecessor permits `auto built = build()`.
A read error is not absence. `recover` closes and reopens the real store; an
unresolved or unreadable result remains LocalUnavailable and prohibits execution.

The actual version-4 engine entry is
`engine.execute_metered_accounts(input, view, proofs)` in
`account_engine_detail::execute`, in `crypto/block/workchain-account-engine.h`.
The enclosing public host entry is the `execute_workchain_account_engine` overload
taking `AdmittedBatchInput`. It performs proof admission, account acquisition,
then the real engine invocation and its effect checks. The configured adapter
must forward the same verifier, not fall back to the unmetered entry.

The entire public host execution call belongs INSIDE the publication `Build`
callback, followed by settlement, private candidate construction, and serialization
of the real host-provided bundle. No engine call, speculative execution, eager
future, or precomputed effects may occur while preparing that callback. Capturing
immutable authenticated inputs and a reference to the configured engine is
permitted; capturing an already executed batch as a substitute is not.

The resulting order is:

1. Resolve recovery by closing/reopening and observing durable state.
2. Enter `publish` with the host-supplied stable batch identity, admitted-input
   identity, and expected predecessor. No new identity is generated on retry.
3. Existing matching committed record: read and release, without entering the
   engine. Unknown/read-failed state: stop without execution or release.
4. Confirm absent record and matching predecessor, then invoke `Build`.
5. Inside `Build`, invoke the real metered account engine, settle its effects,
   construct private candidate contents, and return the canonical bundle.
6. Perform the already specified write/decision/readback/release sequence.

This orders real execution behind the persistent decision. It does not promise
exactly one execution across an attempt conclusively recovered as NotCommitted:
such a retry may execute again. A committed or still-undetermined attempt must
not execute again. Restart replay in an independent validator remains a separate
block-execution scope under I13b; it is not a publication retry.

## Observations required when the live seam arrives

Place the independent execution-entry probe at the concrete test engine's
`execute_metered_accounts` body, before any work, not at `Build`, configuration,
proof-work inspection, serialization, or result comparison. Its fsynced test-only
trace must survive the crash and be reopened by the recovering process. Normal
commit, lost response, restart, and committed retry must retain the same entry
count. Unresolved recovery must leave it unchanged. A conclusively absent retry
has its separately specified additional execution. Test children must consume the
same trace identity; resetting the counter on restart is not evidence.

Calibrate that probe by a single temporary source change that really invokes the
engine again on the retry path while preserving the returned bundle; the execution
identity must fail while unchanged-content assertions remain satisfied. Do not
replace this with an extra counter increment or a second wrapper callback. The
existing private builder-entry trace proves only private builder scheduling and
must not be relabeled as real engine execution evidence.

I13a supplies the batch identity/count and separately verifies the count against
actual AccountBlocks. The publisher preserves those supplied values atomically;
it does not compute them. I13b's block-scope ledger remains a separate guard; it
must not mask the above execution-probe calibration by rejecting before the
instrumented concrete engine is entered. Distinguish such a rejection explicitly
rather than counting it as the execution counter's sensitivity.

## Remaining ownership and resource boundaries

A owns the shared live admission/execute/collator seam. B does not add a parallel
collator path. The live host still needs real providers for every bundle field
and must route actual same-block consumers through the isolated candidate view.
Blind replacement remains covered by dictionary delta checks, not read tracking.
Publication serialization/history costs still lack an authenticated D31 bound.
The final commit gate remains closed; this specification does not authorize moving
or opening it. Any incompatibility between that gate and the required call order
must be resolved before wiring rather than bypassed in a fixture.
