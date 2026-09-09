# Manual private acceptance entry point

The workflow is dispatch-only and includes the construction module, which
includes the other two modules. No activation configuration or default build
is changed. Registration JSON must contain the exact three expected names,
commands bound to the repository's three Python drivers; the fresh JUnit report must contain exactly those three
successful, non-skipped executions. Both CTest's exit status and the report
are checked. Reports are retained even on failure.

`test-i13-results.py` runs three trivial CTest commands to obtain real JSON and
JUnit formats, then checks empty, missing, duplicate, skipped, failed and
not-run reports. These are **observer tests**, not I13 acceptance runs.
Removing the exact-count guard fails at `zero.json`; removing the execution
guard fails at `skipped.xml`; removing driver-path binding fails at
`wrong-driver.json` (a same-name test replaced by `cmake -E true`). Each mutation was applied separately, the Python
test executed, and the source restored byte-for-byte before the next control.
The restore audit contains exact replacements and hashes; `final.log` is the
final restored-source run. No undefined memory or failed compilation is used
as evidence.

At this change's base, the integration branch does not yet contain the reviewed
CTest mounting changes. Its manual workflow must therefore reject registration
until those changes are integrated. No hosted workflow or actual private
harness execution is claimed here. Ordinary full-regression results exclude
these opt-in harnesses; a separate manual result is required.

Review disposition: command presence alone was insufficient; it is replaced
by exact repository driver-path binding with a failing substitution control.
The label check was redundant with CTest's label selection and is removed.
The reviewed mounting commit `49adb250b` explicitly defines all three expected
test names and `workchain-i13-ctest/{construction,coverage,usage}/runs` paths;
their absence at the integration base does not establish a naming mismatch.
This dependency remains explicit until integration. Artifact absence remains
a loud failure, including when configuration failed; the original failing
step is retained, not replaced by an upload failure.

Build parallelism remains the owner's requested `-j32`; the private drivers
also currently use that bound. Hosted-runner resource adequacy is not measured
by this observer exercise. A hosted build failure must not be described as a
failed acceptance predicate or successful harness execution.
