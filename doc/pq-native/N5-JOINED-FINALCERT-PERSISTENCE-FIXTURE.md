# N01 same-FinalCert actor/DB slice (still OPEN)

The `test-n5-joined-finalcert` CTest uses the valid PQ Config34 seq0→seq1
fixture from `c04-real-state-proof-test.cpp`. It builds one candidate and one
quorum-signed NotarCert and FinalCert for the same `CandidateId`. The candidate
is seeded through production `StoreCandidate`; the two certificates enter the
production Pool as serialized `IncomingProtocolMessage`s. The fixture waits for
the NotarCert to make that exact candidate resolvable before sending the
FinalCert. Pool verifies the certificate, awaits production `SaveCertificate`,
then emits `FinalizationObserved`; StateResolver awaits production
`FinalizeBlock`; BlockAccepter forwards the resulting PQ signature set to the
real Manager's `run_accept_block_query`, including RootDb/ApplyBlock. Only after
that return does StateResolver write the exact finalized marker.

A second process reads the same Simplex RocksDB root and RootDb root. It
requires the original serialized FinalCert under its production journal key,
verifies that cert again under the Config34 signers, and finds the exact
`CandidateId` finalized marker. From RootDb it requires the seq1 handle flags,
BlockProof bytes and PQ verification, applied state/root, block bytes and
seq0→seq1 `next`. It compares every PQ signature byte in the cold BlockProof
against that one recovered FinalCert, not merely two independently valid
signature sets. Its wrong-signature control alters one *expected* byte after
journal verification and requires the named proof-comparison refusal. A
comparison-bypass source mutation made the CTest fail on that control, but the
original red artifact was produced against a pre-commit source version. Mac's
independent review found that its recorded mutant source SHA-256 cannot be
reconstructed from fixed `974636495` plus the stated one-line change. It is
therefore **not** fixed-tree mutation evidence; the red result remains a
diagnostic observation pending a clean rerun from the committed source.

This is a local actor/DB boundary, not a real node network. Test-supplied
`StoreCandidate` and transport metadata do not prove candidate transport
authentication or ADNL. The FinalCert is made by the test signers and admitted
by production Pool, not assembled by Pool from live votes. The production
Bridge's anonymous `ManagerFacadeImpl` is replaced by a narrow test facade
that forwards `accept_block` to the same production `run_accept_block_query`;
it never substitutes a success result. The fixture does not separately cold
read the #13 signature file, which may be moved to archive after acceptance;
the persisted BlockProof is its observed PQ evidence. No write-after crash
boundary is claimed here.

Local pre-commit evidence (source tree based on `6d0d08d06`, with this unit's
tracked patch):

| Evidence | Result |
| --- | --- |
| `cmake --build build --target test-c04-real-state-proof -j4` | exit 0 |
| `ctest --test-dir build -V -R '^test-n5-joined-finalcert$'` | exit 0; [raw log](../../test/integration/.n5-manager-db-fixture-20260924/n5-joined-final-green.log), SHA-256 `1740c72ea6a205541a7cd884ccc4041eec276b0e8a44c4c7421903c1769965de` |
| Final test source / binary | SHA-256 `1ae99a9f07b9a1ff4eae225bf202db00facb847f142b4af95ba3f84729355b1e` / `75c28b84ca6212b39cbbec3506f130cecad44c8e495b31b45d911bf4b3db1b4b` |
| Pre-commit comparison bypass `if (false && !expected_cert_signatures.empty())` | CTest exit 8; named failure `wrong-signature control missed exact proof comparison`; [raw red log](../../test/integration/.n5-manager-db-fixture-20260924/n5-joined-compare-bypass-red.log), SHA-256 `07bd0d5437c55d6fdc21b308a34099968984202b569dc6de2516effc250ce61a`. The recorded mutant source / binary hashes `c491964f...` / `5a207b65...` identify that run but do not bind it to a unique mutation of fixed `974636495`. Do not use it for fixed-tree acceptance. |
| CI source guard: remove joined CTest run / change its CMake mode to `--n5-accept` | both exit 1 with their own named failure; restored guard exit 0 |

The `N5_JOINED_DB_ROOT` and retained `.finalcert.tl` paths in each raw log are
preserved for independent inspection. The individual roots are not added to
Git. The fixture was committed and pushed as `974636495`; its fixed-SHA
Branch PQ/Python, Source guards, and microbench jobs all succeeded. The
pre-commit comparison-bypass red artifact remains unqualified as a mutation
of that fixed SHA. A separate exact-source rerun below replaces it.

## Exact `974636495` comparison-bypass rerun

A detached, now-clean worktree at `974636495` supplied the test source. The
production source and shared test header used by this test have no tracked
changes between `974636495` and the later local `b1e6c2bb9`; its object was
compiled with `CCACHE_DISABLE=1` using the recorded Ninja compile command and
linked against those unchanged production libraries. This is an exact-source
test rebuild, not a claim that a separate full `974636495` build directory was
configured. The only source mutation is the retained
[one-line patch](n5-974-comparison-mutant.patch), SHA-256
`a8d0c65fb20eff8db41996a248bf7b97919aec8705cde1ca96efedae5377f709`;
`git apply --check --unidiff-zero` succeeds against the clean historical
worktree. The mutated source SHA-256 is
`f5f08bb9fe62a368b05e4029ba26f2d9fc57e44f598d8333cb43ad3ff729c89c`,
which independently confirms that the earlier recorded `c491964f…`
source hash was not this mutation.

| Exact-source control | Exit and SHA-256 |
| --- | --- |
| Clean source | `1ae99a9f07b9a1ff4eae225bf202db00facb847f142b4af95ba3f84729355b1e` |
| Clean build log / binary | [log](../../test/integration/.n5-manager-db-fixture-20260924/974-exact-baseline-build.log) `62b2be2b8928966ac5d6f64073fa876e60783bdca3a9d15aab41de83b6e14b94`; binary `af8e0f65ad0e94987b9a2f14cccd954e5123f8982ed57590afd7649459c6d8f8` |
| Clean restored run | exit 0; [raw log](../../test/integration/.n5-manager-db-fixture-20260924/974-exact-restored-final.raw.log) `cc34cb3843d44c56b99640caee727069bf5ac7a6da236857b8d7f7cd0774e0d3` |
| Mutant build log / binary | [log](../../test/integration/.n5-manager-db-fixture-20260924/974-exact-compare-mutant-build.log) `6a851fc3ecc372cf6818daf5fc46d2d5918bd9d456f9ed9d0bbba5db010caa7b`; binary `78d8e9be21640942f1b3a34a2e81868f8bb8e6418e4cdeced4b93835e2099f36` |
| Mutant run | exit 1 at `wrong-signature control missed exact proof comparison`; [raw log](../../test/integration/.n5-manager-db-fixture-20260924/974-exact-compare-mutant-final.raw.log) `7eb45c553b98334de5921453a0a725c6c9a13cefc208aa1a05b6390a5aa822c5` |

The detached historical worktree has no tracked diff after restoration. All
compiled binaries and raw logs remain outside Git in the N5 artifact directory.

N01 remains OPEN. The next cutpoint controls, in task order, are:

| Unit | Required crash/rebuild boundary |
| --- | --- |
| N02 | After real Pool FinalCert journal save, before #13 write: rebuild the same session, recover without losing or duplicating that certificate; reverse the save. |
| N03 | After #13 signature storage, before BlockProof storage: cold read the exact signature bytes and resume to proof; reverse the #13 write. |
| N04 | After BlockProof storage, before finalized marker: cold proof plus resumed marker, with a skipped-marker counterexample. |
| N05 | After marker and block acceptance: restart and show neither finality loss nor duplicate application. |
| N06 | Clear all actor memory, keep only DB/archive, and independently recover the same cert, proof, state and marker with wrong-root controls. |

The current joined test supplies a reusable baseline for those cuts; it does
not sign off N02–N06 or N07.
