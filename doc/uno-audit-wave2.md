# Audit wave 2 — implementation and evidence boundaries

This wave closes the selected independent guards, not activation or production
capacity. See `uno-wave2-build-gates.md`, `uno-wave2-protocol-guards.md`,
`uno-import-budget-cancellation.md`, `uno-ffi-concurrency-sanitizers.md`, and
`uno-inbound-time-boundary.md` for individual mutations and limitations.

The final Release build includes validator-engine. Eleven of twelve selected
CTest entries passed on the combined run. The existing download-state-budget
wall-time ratio assertion failed (4.12 versus 3.0); its functional assertions
had passed. An unchanged isolated rerun passed in 5.46 seconds. Both results
are retained in build/wave2-final-tests.log and wave2-budget-repeat.log; this
is not evidence that the timing assertion is stable. No threshold was changed.

New tests were made red by removing their respective guard, cancellation
propagation, output publication, or failure handling, then restored. Real Rust
FFI concurrency and instrumented sanitizer runs are distinct from the Python
harness tests and CTest registration checks. Neither registration nor a
same-process actor test establishes a real network synchronization gate.

The inbound timestamp guard remains: the authenticated normal queue path's
time ordering does not support the proposed ordinary clock-skew trigger.
Arbitrary test genesis and privileged queue injection remain unverified.

ConfigV2/input-limit tag derivation and policy identity binding remain design
artifacts in memo; this wave does not add ConfigV2 wire parsing or connect
preflight to consensus. Production partition and Reserve schemas are unchanged.
