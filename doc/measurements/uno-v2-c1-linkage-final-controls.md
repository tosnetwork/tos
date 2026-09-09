# Final linkage-evidence exception control and ignore audit

The two exact path-and-word exceptions permit only the already archived
`MineUno` in the mutation declaration and its verbatim failure output. They do
not permit another retired identifier in those files. No directory or extension
rule was broadened. This Markdown audit report preserves the subsequent control
output verbatim below, under the existing documentation policy; it is not a new
scanner exception. The previously approved JSON and log remain unchanged.

## Same-path, different-word control

Append exactly `UnoToken\n` to
`doc/measurements/uno-v2-c1-operation-controls/linkage/uno-c1-approved-guard-final-red.log`,
run the repository guard (exit 1), then remove exactly that suffix and rerun
(exit 0). No source compilation is claimed for a textual scanner control.

Original/restored SHA256: `339ca827306beb7deb1cd7f5320c4a6062bb9a899d12f51c3d1aef7b9b1d98de`.

Observed mutant SHA256: `5c5cd6c35993e330cd72026839e8ecb60bc4f50efc07dc12202444123e4841ed`; independently reconstructed by appending the exact bytes above.

Red stdout/stderr payload (SHA256 `de50f20dccefd261b62f20a20ed5fdb127c7ce0dff86f5f44af61395919fe282`):

```text
doc/measurements/uno-v2-c1-operation-controls/linkage/uno-c1-approved-guard-final-red.log:3: retired implementation symbol: UnoToken: UnoToken
removed-execution-domain scan failed
```

Restored payload (SHA256 `3922e4c6b006268de627537c72edfd48c6f1b76130ecd3818ceb83d2a32d16b8`):

```text
removed-execution-domain scan passed: 5793 text files, 380 binary files and 0 directories skipped
```

## Ignore audit

`uno-v2-c1-operation-controls/ignore-audit.json` retains the enumerated paths,
literal references and both measured revisions; the adjacent script reproduces
the queries. `git check-ignore --no-index -v -z --stdin` includes tracked paths
in the check, rather than treating their normal ignored-status exit as proof.
A has 627 indexed evidence paths and 386 resolved literal reference candidates;
B has 731 and 222. Neither has ignored tracked evidence, ignored local files
under `doc/measurements`, or a referenced untracked artifact matching an ignore
rule. External scratch paths and dynamic templates are not claimed resolved.
No B file was edited. Its worktree may advance after the recorded snapshot.

An initial conservative inference manufactured a child CMakeLists.txt under a
directory named after an existing report. Reading the report showed that it
referred to the repository-root source file, not an archived artifact. The
resolver now recognizes that root source; this was not a missing evidence file.
The former ignored linkage directory was renamed, not force-added or unignored.
All 176 then-existing C1 artifact files were explicitly checked against
`git ls-files` after the rename, with no omitted subtree.
