# C1 operation-reservation evidence

`restore-audit.json` is the index: sixteen distinct compiled runtime controls,
six final source-gate injections and two independent registration removals.
`final-checks.json` records the restored code/test sources, binaries, related
CTest results and three negative compiler probes with their positive control.
The compiler and CMake-registration controls are not counted as compiled
runtime mutations.

The runtime audit reconstructs every mutant from the final restored file.
A replacement may be a substring of the original expression: actual occurrence
counts are recorded, while exact whole-file hashes establish restoration. The
original and restored binaries also match. Logs are copied without whitespace
cleanup; trailing whitespace, terminal control bytes and native crash backtraces
are preserved. A whitespace warning in a raw log is not a source formatting
failure, and must not be fixed by editing the evidence.

Files named `final-scope-*` are the earlier scope checkpoint. The index refers
to `reviewed-scope-*` for the final gate, which also scans the node executable
directory. Earlier incomplete instrumentation, fixture errors and the aborted
inverse-string restoration are excluded from the successful-control count.
The low-formula record uses the final diagnostic driver; older versions of that
experiment do not add another control.

The source/mutation controls are manual evidence, not automatic CI mutation
runs. Ordinary tests, actual backend tracing and the source gate are registered
for repeat execution. The shared CI registration assertion requires both real
tests as well as the five pre-existing kernel gates. The subsequently approved
three exact-text build exceptions and the missing-linker-wrap runtime control
are recorded under `linkage/`. The two exact path-and-word exceptions were
approved and the scan passes with the raw artifacts staged. The additional
same-path negative control and ignore audit are recorded in
`../uno-v2-c1-linkage-final-controls.md` and `ignore-audit.json`.
This is not a claim that every CI workflow has run. No live
gate was moved or opened. Earlier source snapshots are historical checkpoints;
the commit binds the completed source set. Historical document hashes are not
claims about subsequent documentation-only disposition updates.
