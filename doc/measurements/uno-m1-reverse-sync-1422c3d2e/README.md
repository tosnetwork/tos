# Reverse-merge regression record

Source commit: `1422c3d2e73ade6137742abddfed4ac1e09e90a6`.
Integrated commit: `6e089de558a587f674abf943e98a670c3cb25164`.

The existing WorkchainBlock binary was rebuilt with `-j32` using the recorded
Release configuration and this worktree as CMAKE_HOME_DIRECTORY. The original
build failed because the frozen-contract verification scripts default to a
nonexistent compiler path. The successful retry explicitly supplied this build's
FunC and Fift binaries through the scripts' existing environment parameters.
No source or verification step was bypassed.

The predecessor pair ran AggregateFeeSettlement then NativeDisposalEntry:
exactly two expected Running test entries, exit 0, and two passes. The standard
WorkchainBlock group ran all 124 source-enumerated cases in registration order,
exit 0, and 124 passes. Negative filters select the pair; positive filters are
conjunctive in this runner. Both complete stdout and stderr files are retained.
The initial result-parser mismatch is preserved separately and was followed by
a complete rerun, rather than retroactively treating a failed script as passing.

This is an existing-regression rerun, not a new guard-sensitivity measurement,
not the entire project test suite, and not live I13e acceptance. No test capability,
deployment configuration, activation gate, or final commit gate was changed.
