# Closed-activation node-link connectivity smoke

Both actual node configurations built successfully with `-j32` from base
`c519361489d68708f7695f05fab8576397e78319` plus this unit's four-line
`validator/manager-disk.cpp` terminal-result observation change. The source hash
is in measurement.json; no other node source changed. Node version outputs
match. Binary and final observer hashes are in measurement.json.
Original build logs, cache snapshots, node versions, frozen test state and
final runtime observations are retained here. The ordinary 127-test regression
is recorded separately and excludes the private I13 harnesses. Its final JUnit
contains 127 cases, zero failures, zero errors and zero skips; the authoritative
summary agrees (100% passed, 0 failed out of 127).

OFF and ON caches differ only in `TOS_UNO_CRYPTO_NODE_LINK`. Actual observed
configuration is version 15, capabilities 494, with BlockTransition disabled;
the test genesis explicitly omits ConfigParam 84, so no ingress/profile is
installed. Production registry observations contain only TVM. The separately
identified explicit account-engine probe registers Basic:1129206833 in both
configurations; linking adds zero registrations. Both configurations' account collation paths
stop at missing registered block engine, identified by the terminal typed
Result's exact kind and message (not the generic code or a log line), before adapter/admission/replay,
with zero transactions and no candidate export. This is earlier than the
historical private-interface seam recorded at ffedd9d21. It is NOT proof of
activation-site rejection, full connectivity, or general zero allocation.

The bootstrap observes downstream validator-set and old-state sites, one
transaction and an actual nonempty candidate export. The same engine-counter
instrument has a separate nonzero execute-call calibration. The config-call,
adapter and ownership counters do not receive a nonzero calibration in this
closed-profile run; their recorded zeros alone are not reachability proof.
Missing trace/error fields fail rather than imply zero effects.
The complete effective OFF/ON traces are equal; comparison.json preserves them.
Wall-clock times under GDB are not performance samples.

Controls use one alternate observer script at a time, with a fresh pair of
isolated runs and the unchanged checker: a fabricated version increment fails
the exact configuration assertion; suppressing frontier events fails the exact
sequence assertion. These are observer controls, not production gate mutations.
The original observer remains byte-identical throughout; reverse application
and mutant hashes are recorded. A separate compiled one-line disk-manager
mutation changes only the recorded error message: the code stays -7201 and
transactions stay zero, but the exact message assertion fails. Restored source
and explicitly rebuilt test-tos-collator match their original hashes. The
all-tests target alone does not rebuild this disk tool; it was explicitly
rebuilt before regression. Final source rechecks the original paired
observations successfully. No activation or publication gate was changed.

Mutation target inventory: manager-disk.cpp belongs to static target
`validator-disk`; its only linked executable in repository CMake files is
`test-tos-collator` (root CMakeLists.txt). Both the mutation build and the restore
build explicitly used `cmake --build build --target test-tos-collator -j32`,
which rebuilt validator-disk and relinked that executable. The archived restore
log shows those steps. The intervening `all-tests validator-engine` build did
not mention either target; the executable still had the exact mutant hash
5462cdd0d25096bf092c7ef29b493f934fab9e937de2887d93656cd2160bf881.
After the explicit restore build its hash was again
cb08788abd4204e71661d134a224bdc6dd728fe30c0ac40a86d2fdfb74259b60,
identical to the original OFF snapshot. This is a measured target-coverage
gap, not an assumption that aggregate build targets rebuild every tool.

Regression maintenance caveat: the first complete ordinary regression reported
117 passed and 10 failed, not 127 passed. The ten failures hit the existing
16-directory fixture retention/admission cap before their fixtures ran. Fourteen
completed historical failure directories were moved, without deletion or cap
changes, to `build/retained-counter-fixtures-WqlrQX/` before the second run.
The pre-move check inspected test process names but omitted `/proc` cwd/fd
references. This is a maintenance-check gap, not evidence of pre-move idleness.
A subsequent check found all fourteen old paths absent and no references to
their old or retained paths among inspectable cwd/fd links; permission-denied
processes prevent a global no-reference claim. The second ctest was already
running during that check. Future maintenance must perform both checks from
`test/cleanup-counter-fixtures.py` before moving anything, with new test starts
held across the maintenance window. A post-move check cannot repair the missing
pre-move observation. Final regression counts must come from the completed
JUnit results and authoritative summary, never the completion ordinal.

The final checker imports the shared activation helper and checks the unique
production origin of both activation and missing-block-engine messages. Its
source-check followup has eight self-tests and eleven in-memory mutation
controls, archived separately from the prior helper commit's historical evidence.
All three smoke mutant observation sets and the baseline were rechecked using
the final checker: config, frontier and terminal-message assertions fail at
their distinct intended sites. This is a recheck of retained node observations,
not a claim that node execution was repeated after a Python-only change.
The terminal-message mutation measures the recorder, not a changed production
refusal site; the refusal site's uniqueness is checked independently in source.
Two nonblocking source-check limitations remain: the formatted missing-account-
engine message used by the shared helper's first calibration row is not pinned
to a unique producer; and the relative order of the block-engine lookup and
activation check is not asserted by the source checker. Fresh node runs observe
that order, but checker-only replay of retained observations does not establish
it for a changed production source. This bundle pins the measured node source
and does not claim either limitation closed.

Manual rerun: prepare a fresh directory containing `off/` and `on/` node and
test-tos-collator binaries, their CMakeCache.txt, `create-state`, and `types.o`.
Compile the diagnostic type source with the actual dispatch translation unit's
compile flags plus `-g -fstandalone-debug`; it supplies DWARF only and is never
linked into or executed by the node. This observer is explicitly limited to
x86-64 SysV and libstdc++ GDB printers. Run workchain-node-link-smoke.py with
`off DIR`, `on DIR`, then `check DIR`. Existing output directories fail closed.
The script generates test-only configuration, never deployment configuration.
