# N04 BlockProof-before-marker write-after slice (N01 remains OPEN)

Committed fixture `d3d9d9892` with race-safe stop in `fbdea203d` adds
`test-n5-cut3-proof-recovery`. It uses the same verified FinalCert as the
joined Pool→StateResolver→BlockAccepter→Manager/RootDb path. The test-only
`N5AcceptFacade` waits for the real `run_accept_block_query` to finish, then
holds its response to BlockAccepter. Production StateResolver awaits that
`FinalizeBlock` response before writing `db_key_finalizedBlock`; the fixture
therefore stops after BlockProof/ApplyBlock but before the Simplex finalized
marker. Only the fixture response is held. On shutdown it returns a named
`cancelled` result so a failed ordering assertion does not leave live actors.
This controlled gate is not a claim about an arbitrary process crash.

The first cold child opens both DB roots in a new process. From the Simplex
journal it reads the exact saved FinalCert TL/hash and requires the finalized
marker to be absent. From RootDb it reads the target handle, data, state and
BlockProof, verifies the PQ proof envelope against the Config34 session and
compares every carried signature byte with the saved FinalCert. The proof
hash must match the writer's pre-marker read. A second new process restores
the genesis Manager context from RootDb and starts production Db→Pool
bootstrap without manually resending the certificate. A final cold child
requires the exact marker and the same proof/signature/state checks.

Post-commit `fbdea203d` [green raw log](../../test/integration/.n5-manager-db-fixture-20260924/fbdea203d-cut3-green.raw.log)
SHA-256 `27e3754ea7e7e6f3b7aba3bb9bc6fef23ad61e0ff1a43256387b7d6e4dd1e4b3`,
exit 0, shows `N5_CUT1_COLD_JOURNAL_NO_MARKER_OK`,
`N5_JOINED_COLD_PROOF_SIGNATURES_MATCH count=3`, then the same candidate's
`N5_JOINED_COLD_JOURNAL_MARKER_OK` and `N5_CUT3_RECOVERY_OK`. The
[four-test CTest log](../../test/integration/.n5-manager-db-fixture-20260924/fbdea203d-restored-ctest.log)
is `98b3839026dc6631f5d9ea07f8bf2e790d12fd3bcef2f4bc6b6d79a5fefbe52f`
(4/4 passed). Production `state-resolver.cpp` SHA-256 is
`2c07ccb84cebb322b39a8d67ebe3127b3a866a1b6aaac9adb120c2c530988095`;
committed fixture source SHA-256 is
`9caf49bc9cb0f2e2deb6fcdaa6d55f0a43be3e7de148cf6d9cd26f4757e4a50f`.
The retained [restored build](../../test/integration/.n5-manager-db-fixture-20260924/fbdea203d-restored-build.log)
is `c95fdabfcf67c1ab8f2ed4e3604c1a4a35747a8fc779d2ee815a264c9ed1cddc`
and [binary](../../test/integration/.n5-manager-db-fixture-20260924/fbdea203d-restored-binary)
is `5123d43c16f02a26d9a205b02b45bd37d2f75ca277271027156364b108e853b0`.

One unique [production mutation](n5-cut3-early-marker-mutant.patch), SHA-256
`df90a186e3de5a5a210b6be413b10d1e04ff1bb3bb6af895a207115e47bb0514`,
moves only the finalized-marker write before `FinalizeBlock`. It applies
cleanly to the restored file with `git apply --check --unidiff-zero`.
On the same committed test source, the
[red raw log](../../test/integration/.n5-manager-db-fixture-20260924/fbdea203d-early-marker-red.raw.log)
SHA-256 `6cb07a905bf63fe46befa492317e04b0dc0f40f2f3f2dc2339204a8f8502e903`
exits 1 on `N5 cut3 marker preceded the post-AcceptBlock proof gate`. This
is an ordering failure observed by the test, not an actor abort. Mutant
production source SHA-256 is
`6c696c94c13babe466eb4315eb0eb769b3caed1eb1b8965a29ac4510d178e935`;
[build log](../../test/integration/.n5-manager-db-fixture-20260924/fbdea203d-early-marker-build.log)
`1c08e955fd68581b5b3735f6fe9391897e3a580dc099c8e5c46e027323293c4c`;
[binary](../../test/integration/.n5-manager-db-fixture-20260924/fbdea203d-early-marker-mutant)
`2cea859e2856ec8e499b0fdd215508883f10b738ceeafe058f3ba7d1ed259b53`.

The CI source guard fails when either the cut3 CTest registration or its
workflow invocation is removed, naming the missing side, and passes when
restored. N04 remains OPEN until pushed exact-tree CI and independent review.
N01's complete reusable persistence chain and N05–N07 remain OPEN; none of
these controls proves arbitrary crash timing or release-scale durability.
