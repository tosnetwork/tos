# Positive controls for `scripts/static-analysis.py`

Each file here is analysed before every gate run, with the gate's own tools and
options, in a separate CodeChecker invocation. A line ending in
`// expect: <checker>` must produce exactly that report, and no other report may
appear. A control that loses its finding means the check no longer works, so the
gate refuses to report a clean result.

These files are deliberately defective. They are not built by CMake and are
never part of a gate comparison.

`unused-status.cpp` covers dropped `td::Status` and `td::Result` values both
without a cast and with C-style or `static_cast<void>` discards. All must report.
The kept value and the exact, reasoned suppression must remain silent. This
makes the explicit-discard policy observable through the real analyzer, not
just through the Python rule table.
