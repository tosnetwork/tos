# Shared measurement admission path

Source base: `tos@ac26402ec`. This unit changes only the test-only cost instrument.
The timed sample now calls the same `run` admission/backend dispatcher as the
semantic self-tests. An observation callback separates admission and backend
timing; accepted usage is published only after admission succeeds. Backend
status mismatch prevents publication of a sample.

The sample boundary is tested through its actual implementation with a counting,
non-dereferencing backend and an in-memory output stream. Valid metadata must
invoke two calls and produce a record. The positive control checks record
existence, not its fields or timing values. Invalid proof shape must return
failure, invoke zero calls and produce no record. The real timed wrapper supplies the
real ABI function; the self-test never supplies it.

The independent mutation bypassed admission only when the accepted-usage output
is requested (the sample path). All older semantic tests passed; the new sample
test then observed two calls on malformed input and exited 1. The mutated build
succeeded. Restored CTest passed. The exact patch, unit diff, build logs and test
logs are in `measurements/uno-d3-measure-gate-mutations.tar.gz`. This is manual
mutation evidence, not a recurring mutation facility.

Limits and call counts retain checked arithmetic. No production error class,
schema, host limit or exception boundary changes. The sample's status failure is
a failed measurement, not a consensus decision. Clock-floor calibration, strict
RSS failure handling and workload diversity remain separate work. The direct
shape-rejection timing loop still measures admission alone; this unit does not
claim to instrument it as a real proof-verification path. Previously published
timings remain observations of their original source, not this changed loop.

Read-only review found no blockers and confirmed the mutation targets only the
sample path. Followups remain: late-failure request injection, emitted field and
timing-order assertions, sample progress/failure diagnostics, limits derived from
request shape, and agreement with production shape rules. In particular, the
observation callback runs in the current code but its removal is not yet caught
by a timing assertion. These gaps do not constitute completed measurement
validation. Transcript: `~/memo/reviews/uno-d3-measurement-gate-review.txt`.
