# N07: persisted PQ BlockProof through real CheckProof

Status: **local controlled actor/DB evidence; N07 and enclosing N01 OPEN** until the pushed exact-tree Branch PQ/Source guards CI and independent review. Source commits `dd30f98e0` and `c53885d5f`; the latter binds the proof byte-for-byte to the exact journaled FinalCert. No production consensus semantics were changed.

The writer drives the existing production Pool → StateResolver → BlockAccepter → Manager path for one PQ FinalCert, then exits. A new process reads the target BlockProof through `ValidatorManagerImpl::get_block_proof_from_db_short` from its retained RootDb and independently reads that FinalCert from the production Simplex journal. The test checks candidate ID, signer IDs, algorithms and all signature bytes against the proof. For each verdict it creates a separate genesis-only consumer RootDb, reads its governing genesis state through the DB API, and invokes the real `run_check_proof_query` actor. The fresh target handle lacks `inited_proof`: using the already accepted source handle would let `CheckProof::got_block_handle` return without re-verifying signatures.

The valid proof produces a target handle with `inited_proof`, and its bytes can then be read back through the consumer RootDb. The negative changes one byte of the first ML-DSA signature while retaining the exact candidate, set, session, slot and claimed weight; `CheckProof` returns `pq signatures: invalid signature`, and the consumer RootDb has no target proof. The test neither boots a full node nor asserts power-loss durability, transport authentication, or cross-node convergence. Consumer genesis is seeded and read back in one process, so this is a RootDb API check, not a separate cold-reopen claim for the consumer state.

On committed `c53885d5fe8efaf4d8e991978f7f708a5852ca15`, `test-n5-cut6-check-proof` passed 1/1 in 0.63 s, and the direct run exited 0. On documentation HEAD `9652f79b1`, the nine named N5 CTests passed 9/9 in 5.68 s (`9652-n5-suite.log`, SHA-256 `ca1126c762c822465d8a523e65ccb00b62b38b6783692067e2fb687e13bbb3d3`). Raw artifacts are retained under `test/integration/.n5-cut6-checkproof-20260924/`:

| Artifact | SHA-256 |
| --- | --- |
| committed test source | `052f0c1e1469c09f06b0e0486ee6c271919e2ea1fbfc35ef783792c2b85fc0dd` |
| clean production `check-proof.cpp` | `0e6a880458518fd512ab9800d85129298c307e167f8a592420bee74ba49549b6` |
| retained `c538-restored-test-c04-real-state-proof` binary | `b6a65a5b74069e3188a9dfd941f128ca5e141c3806ea980be101fb8391a63de3` |
| `c538-restored.raw.log` | `86254422cc84eaf1c08373c4677d023a1be1cb7c00c0e00fff1f0669d655b12b` |
| `c538-restored-ctest.log` | `b0e51ed8468d5fae54fa7b42527da05d8147136385b3d2bde8506cdef9a602f4` |

The one-line production mutation in `n5-cut6-bypass-pq-check-mutant.patch` replaces `verify_pq_proof_signatures` with the claimed weight. Applied to the same committed tree, it compiled and the test exited 1 because the altered signature was accepted. The mutation was then removed, production source restored, rebuilt, and the test passed. This is an actor-level reverse control for the cryptographic decision, not merely an assertion that the test parser dislikes malformed BOC.

| Mutant artifact | SHA-256 |
| --- | --- |
| mutant source | `cd1f6c2e0a6117a1330a7ae63a16c135377b5c2a6863a761f5c2bd2850457b57` |
| retained `c538-mutant-test-c04-real-state-proof` binary | `7bd14a31bc8317a33176037c7d77bcd6019a1f19b6ff9d8f47f8ce83fb82beb9` |
| `c538-mutant-build.log` | `72ba272629db9b9479699ad29c8ce32054fbba5beea7278715a1c168edb07b06` |
| `c538-mutant.raw.log` | `f6a4a5de4a988812b0bb92a198a27d284816546a528bcd7eca41f2b751910915` |
| mutation patch | `1aa1cd478a313c93572c65cca63631dc138debb4aa90bc587fd41e15a82d8be5` |

The CTest is registered in CMake and run by the every-push Branch PQ workflow. Its CI source guard pins both registrations. A fixed pushed SHA CI has not yet completed for this N07 addition. N03–N06 remain governed by their separate closure conditions; this result does not retroactively sign them off.

An independent review of `c0c5f2d47` found that the two binary hashes above originally pointed only to a moving build path. Both exact executables are now retained under the named artifact directory. Rebuilding the one-target mutant from the same unique patch reproduced `7bd14a31…`; restoring the production line rebuilt `b6a65a5b…`. The follow-up build logs are `c538-mutant-retain-build.log` (SHA-256 `f3771aa9d01008985fb20088fcdcc53c63327c196461fd1f4f6c03890ab6b433`) and `c538-clean-retain-build.log` (SHA-256 `72ba272629db9b9479699ad29c8ce32054fbba5beea7278715a1c168edb07b06`). This closes that provenance gap, not the pending fixed-head CI or broader N01 boundary.
