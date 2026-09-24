# C06/P0-5: refuse local PQ session rotation before active group creation

Status: **RESOLVED for the temporary pre-group fail-closed safety cut**. Earlier
revisions said "OPEN" while fixed-head CI was pending. The real Manager/Bridge
zero/nonzero process test passed on immutable `029295c2a` (branch CI
`35991788936`) and the later integration tree `422847c8d` (branch CI
`35997167936`). This is not an implementation of recoverable PQ rotation.

## Defect and chosen boundary

The old `ValidatorManagerImpl::update_shards` derived the canonical PQ
`ValidatorSessionId` from chain state, then `--unsafe-catchain-rotate` replaced
it with `SHA256(id || native-endian rotation_tag)` for an active validator group.
The group handed that replacement to Bridge as `bus->session_id`; independent
proof checking still derives the canonical ID from chain state. This can put
locally generated finality into a different identity domain from the verifier.

Splitting consensus ID from local group/storage incarnation is the long-term
design, but the current lifecycle cannot safely assert that an old and new
signer actor never overlap. The same bus ID names the private overlay and the
existing Simplex vote DB; old signed-vote journals are verified with that bus
ID on restart. Future/observer group identity and cleanup must also agree with
the eventual storage incarnation. Reusing the canonical ID for both actors or
silently starting a fresh DB would trade this defect for double-signing or
discarded recovery state. The minimal patch therefore rejects a nonzero
effective rotation tag **before** active PQ group counting, ID derivation, or
group creation. Zero rotation retains the ordinary path. It deliberately does
not change `CheckProof` or trust a local CLI tag.

## Local process red/green

The test starts one real PQ validator and one DHT node for each of two short,
serial cases. It passes `--unsafe-catchain-rotate 0:0:0` and `0:0:1` through the
real validator-engine. The zero case requires a created group and a successful
masterchain `validatorStats.stats` event. The nonzero case requires a named
refusal and checks that the active group is not subsequently created. The two
independent network creations are controls, **not** a basis for comparing their
session IDs or zerostate hashes.

After review, the **strict same-harness pair** used the final test script
SHA-256 `55d77dc947e5e1d6f20b5a18840bee68c8df2f2d97923f8ff2c850647659ba42`
on both sides. The only tracked working-tree change in the old run was
`validator/manager.cpp` (the `git diff --binary` SHA-256 was
`2b5d4fec39c296124cb35f80f46a5f1b3c560f55b448f909f800afec0c5114c5`);
that file's SHA-256 exactly matched `git show 19f5b3406:validator/manager.cpp`,
`2c690f889a1b0da5c68d714fa02a1eb1f0d02d736dbf2886d60dac8274847b82`.
The fixed run restored `validator/manager.cpp` to the pre-final-comment
version of this patch, SHA-256
`386544250da34dfc1c42cdef112ea85ff16f2511ab67dc04b1406f0fe9568b5c`,
and `git diff --exit-code -- validator/manager.cpp` passed before rebuilding.
The final committed version changes only that explanatory comment to avoid
claiming a locally accepted serialized proof that was not retained; its source
SHA-256 is `930ee86caec19727e3860cdf96c5ad30eae990a7e12b1ae9ea495ffd5d8d93fe`.
The local process artifacts' `source_commit` alone names HEAD and therefore
does not describe the old working-tree override; these source hashes and patch
identity do.

| Final script and source | Binary SHA-256 | Outcome and preserved summary SHA-256 |
|---|---|---|
| Old Manager, final script, `test/integration/.pq-unsafe-rotation-same-harness-old-20260924T1003Z` | `0479d7a73f7b168199f2cf034edb9711ce286dc6f80a5dd75af49a1bf5ed1653` | Exit 1: zero `masterchain_stats_success`; nonzero `trusted_session_mismatch` (five log lines). Summary `321652b9faab0d2996ce777228b98f5e9b5021d157d093f484afba29caab6850`. |
| Fixed Manager, same final script, `test/integration/.pq-unsafe-rotation-same-harness-fixed-20260924T1004Z` | `a3a56d4a55428ae57d60c6ec1cff7de1d465f90636fe78adbd0f51a83b2a5980` | Exit 0: zero `masterchain_stats_success`; nonzero `rotation_refused`, no active group created. Summary `cb10fc12ab4678c592374b347922e880b523a2e9b69afa21e1a451b62a568e5b`. |

Both used `PYTHONPATH=test/tostester/src uv run python
test/integration/test_pq_unsafe_rotation_refusal.py --build-dir build
--artifact-dir <listed path> --base-port 28900 --timeout 45` after rebuilding
`validator-engine`; runs were serial, not overlapping. The older pair below
used a prior script that called the zero positive result
`masterchain_block_produced` rather than `masterchain_stats_success`. Its
underlying condition was the same structured masterchain stats event, but it
is **supporting evidence, not the strict same-harness comparison**.

| Source/binary | Command and outcome | Preserved summary SHA-256 |
|---|---|---|
| Old production `19f5b3406` manager source (`2c690f889a1b0da5c68d714fa02a1eb1f0d02d736dbf2886d60dac8274847b82`), binary `b94d47b30222bd472265bb98425857aebc28413b22e7d7a8c916f42a9e19ec96` | `PYTHONPATH=test/tostester/src uv run python test/integration/test_pq_unsafe_rotation_refusal.py --build-dir build --artifact-dir test/integration/.pq-unsafe-rotation-exact-old-20260924T0942Z --base-port 28900 --timeout 45` exited 1: zero made a block; nonzero produced nine `carried session_id does not match trusted expected session_id` log lines. | `ab25e3c087669e3a5f385b80f8d13542a917ec5326dae0e7e3a4cbfaeeb70ded` |
| Fail-closed working patch, binary `96cf5a4a8ccc2605ee0ecbd9d84bf534e5d7adf5b70b116c7a7fe05bb0c51cb4` | Same command with artifact `test/integration/.pq-unsafe-rotation-fixed-final-20260924T0954Z` exited 0: zero recorded successful masterchain stats; nonzero was refused before group creation. | `1e36607a320aa89a048b8599165ebcfbed2a3f08b4cbfbbb3d9a2ad527539a15` |
| Positive-control mutation `rotation_tag >= 0` (always refuse) | Same process test with artifact `test/integration/.pq-unsafe-rotation-always-refuse-control-20260924T0951Z` exited 1 on `PQ_ZERO_ROTATION_CONTROL_FAILURE: zero_rotation_refused`; source was restored and rebuilt afterward. | `84358f7f77f845862dc78c6eb122f545bd6ed175dc1d766fbc4b12ef4c64ac26` |

The old process observation is stronger than a source-only hypothesis: the
production validator logged the trusted-session mismatch. It does **not**
retain a serialized `BlockProof` accepted locally and rejected by independent
`CheckProof`, nor prove the old/new actor or DB lifecycle is safe for a dual-ID
repair. No September Merkle incident is attributed to this finding. Those
missing pieces gate any future **restoration** of rotation, not the temporary
refusal. The branch CI now runs the short process gate after its existing PQ
chain test, and the two fixed-tree runs above both passed; its
source guard also checks that the pre-group refusal and invocation remain.

`LogStreamer` now flushes each received chunk so a sparse refusal line is
visible while the process runs; without this, the earlier correct refusal was
buffered until teardown and the test falsely timed out. This changes test
observation only, not node logging or consensus behavior.
