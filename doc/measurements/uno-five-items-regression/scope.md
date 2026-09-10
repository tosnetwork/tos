# Regression reconciliation

The complete default build passed with -j32. The first ordinary run exercised
138 registered tests: 136 passed, two failed, zero skipped. The original console
log records both full failure diagnostics. The first JUnit's default passed
system-out excerpts were truncated by CTest; they are not published as evidence.
report.json contains its non-truncated per-test status/time metadata and original
file SHA-256. This is explicitly a derived status table, not the raw XML.

The first two-test follow-up passed but also used CTest's short passed-output
limit. The final two-test follow-up explicitly raises both limits to 10000000
bytes. Its complete JUnit, console log and full LastTest.log are archived; no
output-removal marker remains. TOL_STDLIB was set for this follow-up. The routing
fixture now changes shared-call arguments; no behavioral expectation was loosened.
create-state and test-tos-collator were explicitly rebuilt after the isolated
routing control. Public candidate/state BOCs and typed result sidecars are
archived for both restored routing configurations; databases are excluded.

Each former deferred test passed in the initial run, with the current test's
scope. Readiness certifies the expected fail-closed stop, not account execution
capability. Activation uses the D58 resolver predicate boundary. All 138 distinct
tests have passed across the recorded full run and corrected follow-up. This
must not be paraphrased as a single 138/138 green initial run. A future merge
must independently rerun and reconcile its own outcomes.

The extra removed-domain scan failed and is outside these CTest results. Its
allowlist was not changed; exact-path disposition remains a coordinator decision.
