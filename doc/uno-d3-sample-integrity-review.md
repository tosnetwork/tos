# Measurement sample integrity

Source base: `638a5590d`. Test-only instrumentation; no production admission,
wire, configuration, crypto primitive or new performance result.

The self-test now observes that a late-failure sample contains exactly one
modified request, that its expected backend status is enforced, and that an
unexpected backend failure stops subsequent calls and publishes no record.
Positive controls check emitted proof-call, Action and payload counts against
fixed expected values in addition to the independent backend call counter.

The timing boundary must lie between start and end before emission. Removing
the shared observation callback makes the positive sample fail instead of
publishing a negative duration. This is ordering validation, not clock-floor
calibration or an independent check of each serialized timing field.

Sample limits now derive from request Action count and proof length with checked
multiplication/addition. Two- and four-Action metadata cases demonstrate that
neither former fixed limit survives silently. Both shapes fit the backing arrays;
the stub ignores all buffers and never calls the real ABI. These
cases do not establish production shape-rule agreement or real four-Action
verification performance.

Seven independent mutations were built and failed the self-test: omit late
replacement, omit the timing callback, emit Action count as proof-call count,
ignore backend failure, restore fixed Action limit, restore fixed byte limit,
and treat the intentionally wrong request as expecting success. Each has an
explicit exit 1 and diagnostic. All mutations were restored and the registered
self-test passed in a filtered one-test CTest run, not a full-suite run.
Exact patches, source diff, build/red/restored logs are archived in
`measurements/uno-d3-sample-mutations.tar.gz`. This is historical manual mutation
evidence; the ordinary self-test, not mutation orchestration, is registered in CI.

Sample arithmetic/admission/backend/clock failures now emit diagnostics. Fixture
loading, standalone shape-timing failures, RSS acquisition and output-stream
failures still need separate work;
the change does not claim all measurement failure paths are instrumented. No
catch or consensus error classification changed. Real measurements must be rerun
against a committed instrument before deriving new performance conclusions.

Read-only review found no blockers. Expected-failure controls now announce their
intent, field mismatch diagnostics print the actual record, and the four-Action
case has full-sized backing storage (still no real proof or ABI execution).
The original seven mutations predate these review edits; the proof-count
mutation was repeated afterward, and final build/self-test logs and reviewed
diff are also archived. Serialized timing-field assertions and sample-limit
overflow wiring remain open. Transcript: `~/memo/reviews/uno-d3-sample-integrity-review.txt`.
