# N01: cold continuation to a second finalized PQ block

Status: local actor/DB evidence on committed source `e0923941d799cfdca47fac0a2de268eb9fddb46f`; **N01 remains OPEN** until the exact pushed-tree Branch PQ/Python and source-guard CI finish and the aggregate boundary is reviewed. N02–N07 retain their separately scoped sign-offs. This is an orderly, controlled process stop, not SIGKILL, power-loss atomicity, a live node network, or cross-node recovery.

`test-n5-cold-continuation` runs the production Simplex Pool → StateResolver → BlockAccepter → Manager/RootDb path for seq1, stops it, then starts a new process from the same Simplex RocksDB and RootDb/archive roots. The second process cold-reads seq1's exact FinalCert/marker/BlockProof/state, restores the Manager's genesis and seq1 tip context from RootDb, lets production Db→Pool bootstrap replay seq1 once, and requires zero seq1 `AcceptBlock` calls. It then submits a distinct seq2 candidate with `parent_id` naming seq1 and a new verified FinalCert through the same production actor path; exactly one new `AcceptBlock` call and the seq2 marker are required. The second process constructs/signs only the new seq2 candidate and certificates, not seq1.

A third process has no signing-key fixture. It cold-reads both exact FinalCert TL records and both finalized markers from the production Simplex journal, requires exactly one valid FinalCert for each CandidateId and no other FinalCert, then cold-reads both RootDb handles, BlockProof bytes, PQ session and per-signer signature bytes, block data, state roots, and predecessor links (seq0→seq1 and seq1→seq2). The seq1 proof hash is compared with the value recorded **before** the second process; its durable proof signature bytes must still match the original journaled FinalCert. A newly bootstrapped Pool reports seq2 as its latest finalized anchor. There is no separate persisted finalized-height API in this fixture: two exact markers plus that cold Pool anchor are the monotonic-progress observation, not a claim about every node's height.

Commands on the committed tree (all exit 0):

```text
ctest --test-dir build --output-on-failure -R '^test-n5-(accept-block|joined-finalcert|cut[1-6]-|cold-continuation|manager-db-fixture)'   # 10/10
build/test-c04-real-state-proof --n5-continue test/pq-native/data/c04-pq-genesis.boc
python3 scripts/check-branch-chain-python-ci.py .
```

The source guard was separately mutated in both directions. Removing the CMake registration exits 1, `N5 cold continuation CTest is absent or no longer invokes its seq2 mode`; removing only the workflow run exits 1, `N5 cold continuation through a second FinalCert behavior gate is absent`. The clean guard exits 0 and names the seq2 continuation. These checks pin registration, not the test's behavioral result.

The single behavioral reverse mutation is [n5-continuation-seq2-next-mutant.patch](n5-continuation-seq2-next-mutant.patch): `ValidatorManagerImpl::set_next_block` still writes seq0's next but omits the nonzero predecessor's next. The final test source is unchanged. The mutant builds, exits 1, and reaches the third cold process after both FinalCert journal/marker and proof-signature reads; it fails specifically with `N5 cold predecessor next differs`. Restoring production source yields 10/10 and the direct continuation exits 0. The patch is the only production change in that run; `manager.cpp` is restored in the committed tree. The clean and mutant build logs happen to have identical SHA-256 because Ninja printed the same three build-step lines, but the binaries and raw outputs differ and are retained separately.

Retained raw artifacts are under `test/integration/.n5-manager-db-fixture-20260924/` and are not Git-tracked:

| Artifact | SHA-256 |
| --- | --- |
| Committed test source | `65785bebe6b04f264e58aa17fc63f1fbc56cb31a6f9b4c4d5ce9954a4742a73b` |
| Clean `validator/manager.cpp` | `43ffd95fb6c6ab8d3a4fd5e36ffdf6b06ab91a0c32c4cdbcd526da08446ee79c` |
| Mutant `validator/manager.cpp` | `ef6c65dd8acd33aa0777f7832a5c22046470d06eb5614d77f11692b20269a514` |
| Committed unique mutation patch | `d63738e510cbecacd3896bd99515feff4b61abd609fd17152e807fafe965cd7a` |
| `n01-continuation-final-clean-build.log` | `d952d6684cc598fd152370d212eefe8a203a831ef03654024ead05e9b0bc7a4b` |
| `n01-continuation-final-clean.binary` | `90056f4f38e6986a8ca1ef9fe1095114aacc26d3fbdfb1ef005eeb7baaa0dfc1` |
| `n01-seq2-next-final-mutant-build.log` | `d952d6684cc598fd152370d212eefe8a203a831ef03654024ead05e9b0bc7a4b` |
| `n01-seq2-next-final-mutant.binary` | `a9a98066294d0fd12c7f03ee768035bd917ffe5bb7784fa3d748cdbc16f75ae2` |
| `n01-seq2-next-final-mutant.raw.log` | `ed8b25331ab74b65d6e66bd44550613a79ec1756028ec4d700e0893619d43e32` |
| `e0923941d-n5-suite.log` | `670daccea4f8dec68e7b623d096d5f18b2d934ae2dc64f94716e29858085ae54` |
| `e0923941d-continuation.raw.log` | `24288e491585ceea65b8c3cdab06f356133e7e85a2aee8b0f014804a8805b630` |
| `e0923941d-ci-guard.log` | `916e691eadd157c1cc71794c43154ffdd220631fb871403d635b6896b55bbbc5` |

The first local attempt built a seq2 header with the wrong predecessor seqno; the second omitted `last_masterchain_seqno_` from the test probe's cold Manager restoration and was rejected as “too new”. Both were fixture defects corrected before this evidence; their original logs remain in the artifact directory and are not production findings. A migration-induced CMake reconfigure rebuilt 913 targets before the mutant run, also recorded in its build log. No release-scale, forced-kill, ADNL ingress, or historical September incident attribution follows from this test.
