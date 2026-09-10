# Prepared-code expiry calibration

Source: `a06a8bb5a` (full commit in report). Prepared file expiry comment and
registration landed in `d778308ea`. The private registered CTest now runs the
source guard before the compiled private decision fixture. The guard requires
each exact AccountBinding arm to remain a LocalUnavailable refusal. It does
not demand byte equality of the other two arms.

| Run | CTest exit | Only failure identity |
| --- | --- | --- |
| Production-source baseline | 0 | none |
| Isolated committed-source baseline | 0 | none |
| Replace custom refusal with false | 8 (Failed) | 1350 |
| Restore custom | 0 | none |
| Replace readiness refusal with OK | 8 (Failed) | 1351 |
| Restore readiness | 0 | none |

Both mutants leave the other refusal intact. A refusal elsewhere, or merely
mentioned in a comment, cannot satisfy the scoped full-body match. Unknown or
missing source shapes fail closed. The test does not skip missing dependencies.
When the gate opens, the prepared file must be deleted and its controls pointed
at production call sites. This instrument marks that required decision; it does
not establish live gate reachability or eliminate all interim copy drift.

The baseline uses the actual main CTest registration. Isolated controls clone
its command, replacing only repository source/fixture paths with a fresh committed
worktree. The probe binary stays the explicitly rebuilt, hashed private executable.
The generated isolated CTest file and both command arrays are archived, so this
relocation is inspectable. Mutated validate-query.cpp is read as source text only;
it is NOT compiled or linked into any executable in this control. Consequently
there is no native artifact holding mutant code to rebuild on restore. Python
reads the restored file afresh, and CTest plus the unchanged private executable
pass again. This is not a compiled candidate-acceptance mutation claim.

All original/mutant/restored/reapplied hashes agree with the committed preimage.
Success and failure stdout/stderr and JUnit are retained equally. Main source
is unchanged. The earlier baseline at d778308ea failed because the extraction
region omitted the final lambda brace; a06a8bb5a corrects that boundary. That
initial result is retained separately and is not credited as guard evidence.

The previous disposable source/build paths were requested concurrently by A.
No A-2 runtime had started; B disclosed that their source/cache had been reused.
These controls therefore use a new directory. A will use an immutable archived
merged-tree snapshot plus verified binary copies, not the current old-directory
source. No measurement is claimed against the mismatched source/cache.
