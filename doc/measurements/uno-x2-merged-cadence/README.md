# X-2: original cadence failures on the merged tree

Acceptance criteria were committed beforehand as memo `29484352`; their SHA256
is in the report and was checked against that committed file. This measures
criterion 5, not overall M1 acceptance or authority to create the integration
merge.

Parents A `33af64ee8775e89035c5c364615ff6e3ada853a8` and B
`203354611ba872d84687a1787bfdebf2cab5c730` produce tree
`63aacc17989a9ff1fad17c2bcb05e0d5d8c14eb8`, exactly the independently checked
eleven-test merged tree. A new detached worktree was merged without committing,
configured in a new real-path build directory and built with `-j32`. No A-2
source/build paths or ordinary source files were mutated. No integration merge
commit was created. A later integration result is not silently covered by these
pinned inputs.

| Control | Current mutation | Actual original failure |
| --- | --- | --- |
| omit-wire-field | Encode the current generated tag, instance_id and two refs, omitting only cadence32 | **402** at test-workchain-block.cpp:276: 288 bits instead of required 320, with two refs |
| discard-decoded-value | Decode current framing successfully, but replace the recorded cadence with zero | **405** at :280: decoded cadence differs from explicitly supplied acceptance cadence |

The current constructor is `uno_v2_engine_configuration_issued`, generated tag
`0x41868cd4`. Old 7008e8a40 controls predate mandatory instance_id and used a
64-bit expected layout. These adaptations preserve the original defects:
402 tests shell-shape completeness: in this mutation, omitting cadence32 makes
`cs.size() == 320 && cs.size_refs() == 2` fail. The assertion does not identify
which field is missing; omission of any 32-bit field would produce the same
width failure. It is not a field-specific cadence check.
405 tests cadence-value transmission: the decoded value must equal the explicitly
supplied acceptance cadence. It detects loss of that value after successful
framing checks, rather than malformed framing.

The two controls are not interchangeable. Together they cover complete shell
shape (with cadence omission manifesting as insufficient width) and transmission
of the cadence value. Neither result makes the other control redundant. The 405
mutation preserves the wire encoder and successful checks 401–404. The unchanged
input loop starts at zero and then one; the first nonzero recorded value exposes
substitution with zero. No current-cadence input or lookup was introduced.

Both mutants compiled and each executed exactly the intended test. The baseline
and both restored runs pass. All original/copy/mutant/restored/reapplied hashes
were reconstructed from the merged-tree blob. Restore commands explicitly build
`test-workchain-block`, `tos_block` and `smc-envelope`; the actual behavioral
executable is test-workchain-block, not a shell mock. The dependency chain through
CMake generators and embedded-contract func/fift invocations is also recorded.
This is a target/field-control build, not another default-all acceptance build.

Two initial stops are kept separately:

1. The first build hit the previously diagnosed source-relative FUNC_BIN default
   (source/build/crypto/func absent). Existing FUNC_BIN/FIFT_BIN outlets point at
   this build's real tools on the successful rerun. No masking symlink or source
   fix was introduced. TOL_STDLIB is explicitly supplied as in the earlier merge
   build. These are environment workarounds, not cadence-guard evidence.
2. The first native mutant run did reach 402, but the audit parser mistook copies
   of the same assertion in GDB's local-variable dump for additional events.
   The run was stopped, source restored and targets explicitly rebuilt. The
   corrected parser selects the original logger event and checks both its exact
   assertion expression and `(402 != 0)` / `(405 != 0)` identity. It does not accept
   arbitrary stderr matches or a nonzero exit alone. `corrected/` contains the
   completed calibration; the earlier run is not overwritten or credited.

Success and failure stdout/stderr are retained in full, including GDB diagnostics
and empty streams. Caches, generated header, source/blob hashes, commands and
binary hashes are archived. No historical K-record truthfulness, installation-time
comparison, exposure budget or open-gate claim follows from these two controls.
