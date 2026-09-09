# First-run failures: per-test comparison

Raw CTest statuses are distinct from whether the application ran. Diagnostics below locate failures; they are not used as typed CandidateReject/LocalUnavailable acceptance assertions.

| Test | First observation | Missing tool/environment explains it? | Second run | After retention migration |
| --- | --- | --- | --- | --- |
| test-counter-disk-integration | Bootstrap rejected: invalid instance installation / malformed engine configuration framing | No | Not run: fixture cap (CTest reports Failed) | Not rerun in the six-case admission check |
| test-counter-account-binding-readiness | Fixture retention/admission cap 16 reached before test body | No | Not run: fixture cap (CTest reports Failed) | Failed |
| test-counter-idle-replay | Bootstrap rejected: invalid instance installation / malformed engine configuration framing | No | Not run: fixture cap (CTest reports Failed) | Not rerun in the six-case admission check |
| test-counter-self-delivery | Bootstrap rejected: invalid instance installation / malformed engine configuration framing | No | Not run: fixture cap (CTest reports Failed) | Not rerun in the six-case admission check |
| test-counter-cross-delivery | Bootstrap rejected: invalid instance installation / malformed engine configuration framing | No | Not run: fixture cap (CTest reports Failed) | Not rerun in the six-case admission check |
| test-counter-native-sender | Bootstrap rejected: invalid instance installation / malformed engine configuration framing | No | Not run: fixture cap (CTest reports Failed) | Not rerun in the six-case admission check |
| test-counter-activation-missing_capability | Fixture retention/admission cap 16 reached before test body | No | Not run: fixture cap (CTest reports Failed) | Failed |
| test-counter-config-presence-missing_capability | Fixture retention/admission cap 16 reached before test body | No | Not run: fixture cap (CTest reports Failed) | Passed |
| test-counter-activation-old_version | Fixture retention/admission cap 16 reached before test body | No | Not run: fixture cap (CTest reports Failed) | Failed |
| test-counter-config-presence-old_version | Fixture retention/admission cap 16 reached before test body | No | Not run: fixture cap (CTest reports Failed) | Passed |
| test-counter-config-binding | Fixture retention/admission cap 16 reached before test body | No | Not run: fixture cap (CTest reports Failed) | Passed |
| test-counter-engine-config | Bootstrap rejected: invalid instance installation / malformed engine configuration framing | No | Not run: fixture cap (CTest reports Failed) | Not rerun in the six-case admission check |
| test-tol | Tol compiler exit 2: Failed to discover Tol stdlib; TOL_STDLIB requested explicitly | Yes | Passed | Not rerun in the six-case admission check |

The first run has six real bootstrap failures, six unexecuted application tests blocked by fixture admission, and one missing-environment failure. The second run does not explain or erase any of them. After moving retained directories, all six previously blocked tests executed: three passed; readiness failed with diagnostic 7406 and both activation tests failed during bootstrap with diagnostic 7409 (missing instance configuration). They did not establish the expected activation boundary.

All full logs, numeric line references, retained fixture inputs and observed collate sidecars are indexed in failure-comparison.json.
