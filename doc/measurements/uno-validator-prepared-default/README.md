# Default prepared-expiry registration

Source commit `7643c4887` closes the registration gap: the expiry check previously
existed in the repository but ran only through the opt-in private fixture.
That earlier evidence did not establish protection in ordinary default CTest.

`crypto/CMakeLists.txt` now unconditionally registers
`test-workchain-validator-prepared-expiry`, using the existing required Python3
interpreter. It invokes `crypto/test/workchain-validator-prepared-expiry.py`
with only `--repo`. No native probe, fixture or optional include is needed.
The optional private fixture continues to run the same guard before its probe.
The prepared header retains its explicit deletion/retargeting condition.

The main build passed after removing CMAKE_PROJECT_TOS_INCLUDE. Independently,
a new committed worktree was configured with exactly `cmake -S source -B build`,
without feature arguments or an optional project include. The actual generated
CTest registry contains the new default test and does not contain the optional
native visitor test. No hand-written CTest registration was substituted.

| Default CTest run | Result |
| --- | --- |
| Original committed source | Pass |
| Replace custom AccountBinding refusal with false | Failed, only 1350 |
| Restore custom source | Pass |
| Replace ready AccountBinding refusal with OK | Failed, only 1351 |
| Restore ready source | Pass |
| Physically remove validate-query.cpp | Failed, only 1352 |
| Restore missing source | Pass |

The 1352 check proves dependency failure propagation, not a production rejection
rule. All runs have exactly one JUnit execution and no skip. Successful and
failed stdout/stderr and JUnit are retained equally. The mutants live only in
the independent worktree, whose preimage equals the committed blob and the main
source. Original/mutant/restored/reapplied hashes were reconstructed. Main source
was never mutated.

The runtime chain is CTest -> Python -> source read. No native target includes
or compiles the mutated source in these controls; thus no native mutant artifact
requires a restore rebuild. Python reopens the restored bytes each time. This
is a source-lifecycle tripwire, not live gate reachability or consensus acceptance.
The native private mechanisms' distinct 1310/1320/1331/1341 controls remain in
their own earlier archive.

Registration source, scanner source, prepared header and interpreter hashes are
in report.json.gz. Full generated registry, cache, configure output, baseline,
mutant and restored runs are losslessly compressed. The source guard and its
default registration are committed code, not artifacts existing only in this
measurement directory.
