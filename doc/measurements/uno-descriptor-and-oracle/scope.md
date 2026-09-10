# Scope and incomplete attempts

Descriptor comparison and two controls bind production Fift bytes to commit
32545c25b (see each report). The oracle fixture and unchanged test translation
unit bind to a6eca776a; subsequent commits do not change those source bytes.
The registered command is captured in each oracle report. Final complete oracle
control is run 3: baseline green, valid changed output green without the oracle,
failed CTest with the oracle and a different WA SHA-256, byte-restored green,
explicit rebuild of test-smartcont and create-state successful.

Run 1 stopped at the measurement driver's incorrect cache-path lookup, after
CTest had failed. It is not a completed restore-audit control. Its mutant remains
only in the isolated archived fixture. Run 2 completed the behavioral sequence
and byte restoration but its native rebuild was stopped after CMake repeatedly
resolved relative dependencies against the physical /tmp build parent rather
than the worktree build symlink. It is not the completed rebuild evidence.
An overlapping second build was stopped; its diagnostics are retained separately.
Reconfiguring with the physical build directory fixed those dependency paths;
run 3 includes the required completed rebuild. No repository source was mutated.

The four individual answer generations are preserved separately. Only genesis
changed; the other three hashes match their existing answer rows. Two removed
rows have no surviving test registration. The old genesis answer's raw preimage
was unavailable; no complete old-BOC reconstruction is claimed.

Binary and object files are omitted; compilation/link commands, source commits,
input copies and binary hashes identify reconstruction. Large logs are losslessly
gzipped with their original byte counts and hashes in artifact-manifest.json.

The descriptor controls were subsequently rerun at 10b12dc6b as
uno-descriptor-controls-2. This is the final failure-identity calibration: it
reads numeric identity 1221 from report.json, not stderr text, and records the
actual create-state SHA-256. All other preceding byte comparisons remain
historical evidence. Both mutations and the five restored comparisons pass
this strengthened measurement, with unchanged production Fift source.
