# N03 cold #13 write-after slice (N01 remains OPEN)

Committed test source `df3a6b037` adds `test-n5-cut2-signatures-recovery` to the
same actor/DB fixture as the joined FinalCert and N02 cut1 controls. One verified
FinalCert enters production Simplex Pool, StateResolver, BlockAccepter and
Manager. The test holds the `set_block_proof` promise **after** production
`RootDb::store_block_signatures` succeeds, but before the separate BlockProof
write. This is a controlled actor gate, not proof of an arbitrary crash timing.

A new process cold-opens the same DB roots. It checks the exact FinalCert TL
against the Simplex journal; seq1's handle is received and has the signatures
flag, while its proof is not initialized and the finalized marker is absent.
It calls production `Db::get_block_signatures`, compares every PQ signature
byte to the journal FinalCert, and requires `Db::get_block_proof` to return
`notready`. A subsequent new process restores the genesis Manager context and
starts production Db→Pool bootstrap without resending the certificate. A third
cold process checks the recovered proof, signatures, state and marker. The
gate therefore isolates a stored #13 signature file before BlockProof, while
the recovery still depends on the same saved certificate.

The post-commit clean `--n5-cut2` raw log is
[`df3a6b037-no-signature-file-restored-green.raw.log`](../../test/integration/.n5-manager-db-fixture-20260924/df3a6b037-no-signature-file-restored-green.raw.log),
SHA-256 `1f15dba99624725dde0e4178631457b921c06132074b8015e0a8c672fd29026b`,
exit 0. It prints `N5_CUT2_COLD_SIGNATURES_MATCH count=3 proof=notready` and
`N5_CUT2_RECOVERY_OK`. The exact test source SHA-256 is
`dda6173b6d3ba88ad0996082095293a102f75ff9d049beea329ed0a61c7d00e9`;
restored production `rootdb.cpp` is
`d05c73083b15ba922debe7e0158ec2e2a30c630a112f127761ffbe330ab909fd`.
The retained restored [build log](../../test/integration/.n5-manager-db-fixture-20260924/df3a6b037-no-signature-file-restored-build.log)
is `cbac59c5e7a7645d784bcdc60495329bd18000dcd4890934727615865bb0135a`;
its [binary](../../test/integration/.n5-manager-db-fixture-20260924/df3a6b037-no-signature-file-restored-binary)
is `985ff55883a1eb1ecda7d465f1db2ff302929fec766b3c8970207f0f4432920d`.

Two distinct one-change red controls were rebuilt from the committed test
source; their patches pass `git apply --check` on the restored production file:

| Control | Observed red boundary | Retained evidence (SHA-256) |
| --- | --- | --- |
| [Acknowledge without storing signatures](n5-cut2-no-signatures-mutant.patch), patch `ec6c4b09908deea06a7ac8977fdbb58cdfac2e74b078af79994ca0bbbe891bcf` | exit 1 with `signatures_flag=0`. This proves the handle flag is required; it **does not** independently prove cold #13 file reading. | Mutant source `6a178c787035cec43fede5329c160a9f5c61a5ea0510be3840f0e98bebd372bc`; [build](../../test/integration/.n5-manager-db-fixture-20260924/df3a6b037-no-signatures-build.log) `07c0d9ddc31e96e405c276e5afc8c7e83f0277aa53e56e296878b02e4e9a8bd3`; [binary](../../test/integration/.n5-manager-db-fixture-20260924/df3a6b037-no-signatures-mutant) `d75c6b8a45340b168d43f7b32fe6a9d3a184ffc726905de1bd60a771bd6a2a3e`; [raw](../../test/integration/.n5-manager-db-fixture-20260924/df3a6b037-no-signatures-red.raw.log) `1a20115ed5674d1bf98ed4756eddf66b46fa763ac3df0e4b343b50e56036b526`. |
| [Keep the flag/update callback, omit only the `Signatures` temp file](n5-cut2-no-signature-file-mutant.patch), patch `a2233702f3ebd1182f917bd29ee18a14f0e4cce0743dba155cfad9e98e550970` | exit 1 at `N5_CUT2_COLD_FAILED: #13 cold read`, with exact `file not in db: signatures_(...)`/`notready`; `N5_CUT2_BLOCKED_PROOF` records `signatures_flag=1`. This is the direct #13-file counterexample. | Mutant source `fa544f4381850f2f58107577520b08ea9b2f649b0c875c0be4a526da086aed0e`; [build](../../test/integration/.n5-manager-db-fixture-20260924/df3a6b037-no-signature-file-build.log) `07c0d9ddc31e96e405c276e5afc8c7e83f0277aa53e56e296878b02e4e9a8bd3`; [binary](../../test/integration/.n5-manager-db-fixture-20260924/df3a6b037-no-signature-file-mutant) `55f85451313be9820b74b3fa398fc320c2bf89f2e86446254a2679106bf28401`; [raw](../../test/integration/.n5-manager-db-fixture-20260924/df3a6b037-no-signature-file-red.raw.log) `b72da81e9f924cbaeb43bf67eef64d6caf54a869f9ddf3193764fda9f4497a7c`. |

The restored test group `test-n5-joined-finalcert`,
`test-n5-cut1-finalcert-recovery` and `test-n5-cut2-signatures-recovery` passes
3/3 ([raw CTest log](../../test/integration/.n5-manager-db-fixture-20260924/df3a6b037-cut2-clean-ctest.log),
SHA-256 `8488e975a9229b3bcba8d98ffc0296aa837dce4002248681c0cc1da3298c26e1`).
The CI source guard also fails in both directions: deleting the cut2 CTest
registration reports that the cut2 mode is absent; deleting the workflow run
reports that the #13 recovery behavior gate is absent. With both restored it
returns `BRANCH_CHAIN_PYTHON_CI_OK`. N03 is not signed off until the pushed exact-tree CI and independent
review. N01's full reusable five-cutpoint path, N04–N07, arbitrary crash
timing and release-scale durability remain OPEN.
