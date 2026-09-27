# N01 slice: production PQ AcceptBlock and cold RootDb

Status: **local write-after slice proven; N01 OPEN**. Fixed test source:
`edf3b3a14a700406f8a1e55636067c05d6693bcf`. This is not yet a
Pool-produced FinalCert, StateResolver `FinalizeBlock`, or production
finalized-marker sequence. It reuses C04's independently applicable PQ
seq0→seq1 block, Config34 set and locally signed/verified PQ finality signature
set as inputs to the real
`run_accept_block_query`, `ValidatorManagerImpl`, `RootDb`, and `ApplyBlock`.
No overlay or ADNL network is started.

`AcceptBlockQuery` writes block bytes, the PQ #13 signatures, state and
BlockProof, then applies the masterchain block. The test awaits its promise,
reads the proof hash through the writer's RootDb API, exits that Manager,
and starts a **new process** on the same DB root. The cold reader requires
the seq1 handle's received/signatures/proof/state/applied flags and expected
state root; it reads the exact written proof bytes by hash, parses its PQ
finality envelope, re-verifies the signature set against the trusted Config34
set and session, reads the state and block bytes, and checks the seq0 handle's
`next` points to seq1. A completed block may move the short-lived signature
file to archive; `RootDb::get_block_signatures` then returns `not in db` by
design. The durable BlockProof and handle flags, not that transient file,
form this cold-read contract.

The short mode is `test-n5-accept-block` (0.3 seconds); it is separate from
C04's ~61-second retention control. On the committed test source, the three
local CTests `test-c04-real-state-proof`, `test-n5-accept-block`, and
`test-n5-manager-db-fixture` passed 3/3. The post-commit N5-only rerun
passed 2/2. A follow-on workflow edit wires both short tests into Branch PQ
chain/Python CI and pins their build/run steps with the source guard; that
edit has no remote fixed-head result yet. Neither the existing `439efb4ee`
CI nor these local passes are fixed-head CI acceptance for N01.

Retained evidence:

| Item | SHA-256 |
| --- | --- |
| `test/integration/.n5-manager-db-fixture-20260924/edf3b3a14-accept-cold-green.log` | `f009f9be8904f8e5c9486f8620694263e5d985d65c70a4a0b4e2f850b682c651` |
| `test/integration/.n5-manager-db-fixture-20260924/edf3b3a14-n5-ctest.log` | `8eab1030955890a189b3c6b2ba702c61ea02bc038e90649617b9e6fd9748c285` |
| `test/integration/.n5-manager-db-fixture-20260924/edf3b3a14-c04-n5-ctest.log` | `59971eed2c3b842438cc6eab1a11a7aeeccd3c2fc779ab55604bfbdfa55d6048` |
| clean `build/test-c04-real-state-proof` | `96bfdecf3a595b4afb29ae5f7e4ecb6f2ace7fe108337685d91f7dec30718db8` |
| committed test source | `7f972636690133dab0cf02532e874ae716053f50390ac0f3bd39be3009507d46` |
| proof-hash-bypass mutant log | `5da756a918c9957b2d69f0b9d50d249d06ea87e727aa2329f37223d60526fa22` |
| proof-hash-bypass mutant source | `4e3788666100b294fcf9daff8ea957daaef1dba85f45cdc5bab21cd6ea6a3268` |
| proof-hash-bypass mutant binary | `7a27193aab1b52c0cf277c16fd48fec8ad7f163bf0c4ddc835278207aa1e0a51` |
| `n5-accept-proof-hash-bypass-mutant.patch` | `eb1a1cb95863c1965382579ac2314bc3501e792f43a795a8b7f213e63f43c90d` |
| `n5-accept-skip-signature-write-mutant.patch` | `5f7e305d944c8c8baf7327df0b2f2e508e6264ced4d3f472ce719c11ab9e8ccc` |
| signature-write-bypass mutant log | `7691aae1908b5205b5f9a095216e357ce03a47ec7a980637fac7a7994a096083` |
| signature-write-bypass mutant source | `7b7a804fba3ed0c3348e35e30e45695cbad7f5006b63aae8782b89d530b1de18` |
| signature-write-bypass mutant binary | `aa457d9d602969ab7f2ee884f61457450fbca880ed033703be51df5505eb6e75` |

The committed green wrote proof hash
`82328EE006CC0F83CF260BA1900BF12AF6FF6387613FA731E0A20268E784F754`
and the child accepted those exact bytes. The built-in reversed controls
require the same child's all-zero expected hash to fail specifically with
`N5 cold BlockProof bytes differ from writer` and a separate unwritten DB
root to fail specifically with `N5 cold handle: block handle not in db`.
The one-line proof-hash-bypass patch passes `git apply --check` on `edf3b3a14`;
with it, the all-zero-hash control turns red as `negative unexpectedly passed`
(exit 1). The production source was restored before the clean build.
The separate production-call bypass in `AcceptBlockQuery::written_block_data`
skipped only `set_block_signatures` while leaving its later callbacks in
place. The query itself returned success, but the writer-side RootDb read
refused with `N5 writer proof/signatures not initialized` (exit 1). The
unique patch applies to the clean tree; `validator/impl/accept-block.cpp`
was restored to SHA-256
`447169fb3300e0971c543024f94f436a0b5d0d83d37d70321cf69c4287b0f5ef`,
and the rebuilt clean test binary returned to the hash in the table. This
proves the `set_block_signatures` write is needed for this gate, but it still
does **not** directly cold-read a separate #13 record after archiving.
The CI source guard was also tested against removal of the N5 AcceptBlock
CTest, removal of the N5 FinalCert-journal CTest, and removal of its native
build target. Each separately returned exit 1 naming the missing gate; the
restored workflow/guard returned exit 0. Its success message names only
these two cold-read CTests, not the whole N01 persistence chain.
Changing the CMake `test-n5-accept-block` command away from `--n5-accept`
also returned exit 1, so a workflow step matching zero or the wrong CTest
cannot satisfy this guard.

Two development mutations are **not** counted as evidence: disabling C04's
different proof-hash check left this N5 mode green because it did not reach
that check; setting `run_accept_block_query(... apply=false)` also left it
green because the masterchain path still runs `ApplyBlock` later. The
surviving probes are recorded here so the test's claim is no broader than
the red control actually proved.

Next N01 work: join the production Pool `SaveCertificate`/StateResolver
`FinalizeBlock` and finalized marker to this RootDb write path, introduce
controlled crash/write-after cuts on both roots, then register the complete
fixture in branch CI on one immutable source SHA. N01 and N02–N07 stay OPEN.
