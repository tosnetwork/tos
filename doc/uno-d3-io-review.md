# Measurement RSS and output failures

Source base: `cc7e70b6b`. This unit is test-only; no production admission or
consensus error mapping changes.

RSS acquisition now returns failure on an unsuccessful query or nonpositive
Linux ru_maxrss, preserving the caller's output on failure. A proof sample with
unavailable RSS emits no record and fails. Output status is checked after flush,
so buffered failure is not silently reported as a successful sample. The
standalone shape timing loop also uses checked RSS and the output-flush helper,
and diagnoses an unexpected admission result.

Tests inject a failed RSS query with a plausible value, an invalid returned
value, and a successful known value; sentinel publication is checked. The actual
sample implementation is exercised with unavailable RSS, a prefailed output
stream, and a stream that accepts bytes but fails only on flush. These use a
counting stub, not the real proof ABI. The helper tests do not constitute an
end-to-end run of the separate shape timing loop or an actual filesystem outage.

Five independent guard-removal mutations built successfully and exited 1:
ignore query status, ignore RSS validity, ignore sample RSS failure, ignore
output status, omit flush. The restored registered self-test passed in a
filtered one-test CTest run. Patches, source diff, build/red/restored logs are
in `measurements/uno-d3-io-mutations.tar.gz`; these are manual historical
observations rather than an automated mutation gate.

Default non-throwing iostream error masks are used by these paths and tests.
No catch is added; a throwing stream or signal termination is not claimed to be
contained. Flush failure may leave partial bytes or preceding records behind:
a nonzero measurement-process result invalidates the run, not just its last
record. Flush is not fsync and does not prove durable storage. RSS remains a
process high-water mark, not per-phase memory. Counter arithmetic is checked;
this unit adds no amount arithmetic, clock calibration or performance results.

Read-only review found no blockers. Query-error, invalid-value and valid-value
controls now have separate diagnostics; unexpected shape timing reports its
actual status. The five mutations preceded these diagnostic refinements. The
query-error and invalid-value mutations were rerun afterward, with distinct
failure messages; final restored logs and a reviewed diff are archived alongside
the original diff. Direct shape-loop call-site mutation coverage remains open.
Transcript: `~/memo/reviews/uno-d3-io-review.txt`.
