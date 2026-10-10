# Positive controls for `scripts/static-analysis.py`

Each file here is analysed before every gate run, with the gate's own tools and
options, in a separate CodeChecker invocation. A line ending in
`// expect: <checker>` must produce exactly that report, and no other report may
appear. A control that loses its finding means the check no longer works, so the
gate refuses to report a clean result.

These files are deliberately defective. They are not built by CMake and are
never part of a gate comparison.
