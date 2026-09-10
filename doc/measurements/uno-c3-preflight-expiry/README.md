# Default C3 preflight expiry guard

This closes the registration gap, not C3. The host has a private budget
contract; no concrete production preflight implementation is available to
connect, and the execution gate stays closed.

The default `crypto/CMakeLists.txt` registers
`test-workchain-preflight-expiry`. Configuring again with
`-U CMAKE_PROJECT_TOS_INCLUDE` produced exactly that test for the preflight
name filter, without the opt-in native budget test. The registered default
test ran and passed; it was not an empty CTest selection.

A temporary third production source file defined `proof_work`. Its syntax
check succeeded. The registered guard then failed with identity
`preflight.production_expiry`, reporting that exact new path. CTest recorded
`status=fail` and a failure element. Removing the temporary source restored a
passing run. The temporary source is retained as `third-file.cpp` in the raw
archive, not in the production tree. This source-only control creates no
native executable containing the mutation.

The guard inventories all Git-visible first-party C/C++ source, not merely
the two known files. Five exact token identities are allowed in those files;
neither file is exempt as a whole. New occurrences or changes to recorded
tokens expire rather than being guessed safe. Preceding return types, class
names and call receivers are not fingerprinted. Test, documentation and vendored directories are outside
the production inventory. Generated/token-pasted identifiers are not covered
by this lexical check; it is not semantic analysis or proof of operation
coverage. On expiry the diagnostic requires connecting the budget contract,
deleting this guard and retargeting controls to production.

Read-only review independently tested additional implementations in both a
third file and an existing allowed file, duplicate occurrences, renaming and
whitespace reflow. Its documentation overclaim finding was accepted: token
identity is not whole-interface identity. Inventory read failures now emit a
distinct failure diagnostic rather than an unstructured traceback. The final
expiry round also covers escaped-newline identifiers and uppercase suffixes;
earlier rounds remain historical. Syntax checks in the final round explicitly
record their exit status, not merely an empty output log.
The final complete guard round is `stable2-*`: baseline, independent plain and
escaped-newline definitions (one occurrence each), and each restored pass.
`stable-*` stopped at an XML-reader assertion because joined XML whitespace
hid the JSON line from that reader. The source was restored in `finally`;
the corrected reader consumes `system-out` directly and the entire guard
round was restarted. That failed reader run is preserved, not counted passed.

The existing native driver currently enumerates **nine**, not eight, cases.
All 24 existing single-site mechanism controls were rerun against the header
with its final expiry banner. Every mutation failed at its intended assertion,
was restored byte-for-byte, and explicitly rebuilt
`test-workchain-preflight-budget` with `cmake --build ... --target
test-workchain-preflight-budget -j32`. Each rebuild was followed by the entire
nine-case driver. Two archived-evidence reader calibrations also failed at
their respective intended checks. The final registered private test passed.

These are scoped checks, not a full default build or full regression claim.
The repository removed-domain scan still reports its pre-existing 103
findings; its complete output is byte-identical to the preceding unit's
final scan. No exception or scanner rule was widened. This is not an
all-gates-green claim.
No Counter fixture was created, and no shared fixture cleanup was needed.
The prior unit's evidence remains historical and unmodified. The report binds
this run to its actual source overlay and records archive-member hashes.
