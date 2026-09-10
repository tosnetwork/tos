# Ingress control evidence

The complete four-control run is uno-d58-controls-3, bound to b7947b836.
All modified production objects were compiled and linked successfully; all
replacement source copies were restored and reapplication hashes reconstructed.
Repository files were never changed by a mutation. Only the identified numeric
continuity assertion or activation-mode typed row differs. The shared consumer
is also executed for both activation modes; its wrong-mode run remains green.

Earlier attempts are retained. Run 1 completed two continuity controls then
stopped before the activation mutation because its source pattern occurred in
two different functions. The corrected pattern includes the exact activation
function signature, so the ingress loader is not mutated. Run 2 completed the
two continuity controls, then discovered that removing the minimum-version
check still returns an error from the later ingress lookup. Its expectation of
resolution success was wrong. Run 3 instead compares final typed rows and runs
the existing shared classifier, without introducing another classifier or
matching stderr diagnostics. The original activation test already requires the
specific activation identity; this is not a new acceptance assertion invented
to catch the mutant.

Build attempt 1 was stopped when it overlapped the oracle's final build.
Attempt 2 found missing/incorrect include ordering in the new test translation
unit; it is not behavior evidence. Attempt 3 compiled the corrected test.
The final mutation run explicitly rebuilds test-workchain-ingress-transition and
test-workchain-activation-control and runs the three CTest registrations.

These are private configuration-predicate tests. They do not establish a full
configuration-transition block's acceptance, live batch execution, or milestone
acceptance. Current merged outcomes must be remeasured, not inherited.
