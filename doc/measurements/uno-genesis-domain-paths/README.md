# Exact genesis-path permission calibration

Source: `5fcc4703ce2b5232a2be3671c29c9bdf27a12b04`.
Only `crypto/smartcont/uno-genesis-config.fif` and
`crypto/smartcont/uno-genesis-operators.fif` were added to `uno_paths`.
No wildcard, retired-symbol exemption or word-exception entry was added.

The full scan lost exactly ten diagnostics, all belonging to those two paths.
It still reports 73 other diagnostics: 21 lines present verbatim at
`a27ff2c77`, and 52 new or rewritten since that baseline. This is textual lineage,
not a claim that every new diagnostic was introduced by this two-line change.
Those remaining permissions are outside this decision; no global pass is claimed.

In an isolated worktree, one comment containing `halo2` was appended to the
committed genesis-config file. The input contains neither an Uno nor an EVM
identifier, so neither execution-domain rule can account for the new failure.
The scan added exactly one diagnostic at that line from the independent retired
rule; every pre-existing diagnostic remained identical. Restoration returned
both complete streams byte-for-byte to baseline. The global exit remained 1
throughout because unrelated path diagnostics remain; exit status alone is not
the evidence for this control.

`report.json.gz` contains the exact append offset, from/to bytes, committed
source reference and all four source hashes, plus every remaining diagnostic's
baseline classification. `reproduce.py.gz` and the full stdout/stderr archives
preserve the verbatim control material without adding a word exception for it.
The append was independently reapplied to the commit blob to reproduce the
mutant hash. Production sources were never mutated. The tested program is a
shell/Python text scanner; no native binary target is involved or claimed rebuilt.
