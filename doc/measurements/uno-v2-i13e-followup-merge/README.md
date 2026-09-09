# Private publication follow-up integration

Tested merge: `6e089de558a587f674abf943e98a670c3cb25164`.
Parents: `47f9967bcc3ea93aec9ae272a784e0f89fffdbb1` and
`2ee0365a4e408f3c3d033c78731906d13e17a11b`.

The fetched remote and local source branch agreed at the second parent.
The actual newly integrated range contains six commits: `78fab252a`,
`6c14be889`, `898b86953`, `dcc41be43`, `6ee1eb684`, `2ee0365a4`.
`ad4ff21eb` was already integrated in the preceding merge. This no-fast-forward
merge preserves the original source commits and authors; no rebase or squash
was used. The owner reviewed the source-branch implementation. This record is
the integration regression boundary, not another private publication acceptance.

The working tree had four unfinished smoke files, not a clean boundary. They
were explicitly saved before merging in stash
`e6b976d5db7bb4982b9b998e01c57da07e09838f`; they are not part of this merge
or its regression claims. Their pre-save hashes are retained in the working
record outside this source tree. No production judgement or activation change
was made to make the merge pass.

## Registration and regression scopes

The opt-in configuration uses only
`crypto/test/workchain-construction-isolation.cmake` as
`CMAKE_PROJECT_TOS_INCLUDE` (it includes the other two modules). Running
`ctest -L i13 --show-only=json-v1` still reports exactly three checks, and
`.github/scripts/check-i13-results.py registered` validates their exact names
and driver paths. This only lists them; **no private harness was run**.

The ordinary build explicitly sets `TOS_UNO_CRYPTO_NODE_LINK=OFF` and removes
`CMAKE_PROJECT_TOS_INCLUDE` from its cache. Other settings are retained.
`cmake --build build --target all-tests -j32` builds the ordinary targets;
`ctest --test-dir build --no-tests=error --output-on-failure --output-junit ...`
runs the ordinary regression. Its 127 registered checks have no name overlap
with the three private harnesses. The completed run exits 0: 127/127 passed,
944.37 seconds total. JUnit contains exactly the 127 registered names, each
with status `run` and no failure/error/skipped element. Raw JUnit/logs and
`final-checks.json` retain the result and per-artifact hashes.

**The 127 ordinary checks do not include private I13 harnesses.** Their
execution remains the owner-selected manual `workflow_dispatch` operation;
neither their execution nor hosted CI execution is claimed by this merge.
