# N02 FinalCert write-after recovery slice — scoped RESOLVED (N01 remains OPEN)

The controlled Cut 1 condition is satisfied on pushed `a4a4d472d`: Source
guards run `36046064427` succeeded, and Branch PQ/Python run `36046064592`
succeeded with `test-n5-cut1-finalcert-recovery` 1/1 passed on that exact SHA.
The independent review accepted the exact-source mutation provenance and
retained red/green build artifacts. This signs off only the deliberately
gated FinalCert-journal→cold Pool-bootstrap recovery cut, not an arbitrary
hard-crash window, the complete N01 fixture, or later cutpoints.

Committed test source `b1e6c2bb9` extends the local actor/DB fixture with a
controlled cut immediately after Pool's production `SaveCertificate`. The
writer registers Pool, CandidateResolver and Simplex Db, but deliberately
does **not** register StateResolver or BlockAccepter. It stores a signed
candidate and quorum NotarCert, sends one quorum FinalCert as a serialized
`IncomingProtocolMessage`, waits for the exact `db_key_vote`/`db_cert` write,
and stops the session. This actor-registration gate is not a claim about the
timing of an arbitrary real crash.

A first cold child opens the same Simplex RocksDB root and finds the exact
FinalCert TL/hash but no `db_key_finalizedBlock` marker. Through a fresh
Manager/RootDb actor it also requires the target seq1 handle to be absent for
the named `block handle not in db` reason. A second process restores only the
genesis Manager context from RootDb, opens that same Simplex session DB, and
starts production Db, Pool, CandidateResolver, StateResolver and BlockAccepter.
It sends no fresh FinalCert: Db loads `bus.bootstrap_certificates`, and Pool's
startup `handle_saved_certificate` replays the saved one. Its marker then
appears. A third cold process verifies the same FinalCert TL/hash, exact
marker, production BlockProof, applied state and proof signature bytes against
the recovered cert. The candidate carries a real leader signature so
CandidateResolver's cold deserializer can verify it; an earlier unsigned
probe failed at `Candidate broadcast signature is not valid` and is not green
recovery evidence.

The retained raw log is
[`b1e6c2bb9-cut1-final-green.raw.log`](../../test/integration/.n5-manager-db-fixture-20260924/b1e6c2bb9-cut1-final-green.raw.log),
SHA-256 `4a155708ad3753c0c5b6f9d9346a4764fa084353e9457ed4451d3daee7aede6c`,
exit 0. It names the retained DB root and original FinalCert TL file. The
committed test source SHA-256 is
`bfd993c07e8748e3c5d6ded385c4355918b5377db677ea4b209b26c45bf702d3`;
the restored binary SHA-256 is
`2558c9421296b4e60c4d887ede5dac559b554b17fdfec4ad21fac530afacca76`.
`test-n5-joined-finalcert` and `test-n5-cut1-finalcert-recovery` both pass
locally (2/2); the branch CI gate builds the common target and runs each
named CTest separately.

Two single-change production mutations were built and run from committed
`b1e6c2bb9`, then fully restored and the green binary rebuilt:

| Mutation | Result and retained identity |
| --- | --- |
| [Skip Pool bootstrap replay](n5-cut1-no-bootstrap-mutant.patch), patch SHA-256 `972be130c5ab3339166106fde3ab9ad47a5fb6ef51af534a5b5e6c13415be746` | exit 1. Initial cold checks still pass, then `N5 cut1 bootstrap FinalCert did not reach marker`. Mutant Pool source `95beec0728be1d918f33b3128d770b4f1d95a81acfe0b51d08595098d3830db1`; binary `fd6f3e8de24dfb94cae4f66217b2b0ae66ff83d350be368e26d129e184dc3da4`; [raw red](../../test/integration/.n5-manager-db-fixture-20260924/b1e6c2bb9-no-bootstrap-red.raw.log) `9a8522e20be8524fd804e8ade6e6c5f3719f981139a3fe58a57f02b806cf433b`. |
| [Skip production SaveCertificate](n5-cut1-no-save-mutant.patch), patch SHA-256 `cb4158f313b5712efba055e3d938252282efe5ad698af24726827db211e8d43f` | exit 1 at `Pool-to-finalized-marker` wait; no journal write can satisfy the cut. Mutant Pool source `3cbe26323ffa89262919fbe134e5947857d7f50d4a73ca65efed7d5f86156a25`; binary `1373caf0d77c4d0a4cd8379d6746f999053b8d26480c4be76fb0df4411bd140f`; [raw red](../../test/integration/.n5-manager-db-fixture-20260924/b1e6c2bb9-no-save-red.raw.log) `8a5519561e5c829e96f2ef4352f339e1937549623b1d4136782bb49e96141417`. |

Both zero-context patch files pass `git apply --check --unidiff-zero` on
the restored production source.

## Retained mutant rebuilds from pushed `a4a4d472d`

Mac's independent review of the earlier red cases reproduced the mutant
source hashes but noted that their compiled binaries and build logs had not
been retained. From pushed `a4a4d472d`, with only the corresponding one-line
Pool mutation applied each time, the build logs and executable binaries were
retained in the same artifact directory; the original Pool source was
restored and the clean binary rebuilt before the final run. These files are
not added to Git, but the exact paths and hashes are:

| Control | Build log SHA-256 | Retained binary SHA-256 | Raw run SHA-256 / exit |
| --- | --- | --- | --- |
| No bootstrap | [build](../../test/integration/.n5-manager-db-fixture-20260924/a4-no-bootstrap-build.log) `d2026dc80d6ffe1206fc984d9fef31856f09785899d1406b79e6ebaa92532e6e` | [binary](../../test/integration/.n5-manager-db-fixture-20260924/a4-no-bootstrap-mutant) `fd6f3e8de24dfb94cae4f66217b2b0ae66ff83d350be368e26d129e184dc3da4` | [red](../../test/integration/.n5-manager-db-fixture-20260924/a4-no-bootstrap-red.raw.log) `1f65b855be5700345d547f878a84ffd06cb74fb747136abe9de49f68f103950e`, exit 1 at bootstrap replay; first cold absence controls pass |
| No SaveCertificate | [build](../../test/integration/.n5-manager-db-fixture-20260924/a4-no-save-build.log) `425ff584905cc763346572d76dfb317403bdca11d1748650e33b19adce43db88` | [binary](../../test/integration/.n5-manager-db-fixture-20260924/a4-no-save-mutant) `1373caf0d77c4d0a4cd8379d6746f999053b8d26480c4be76fb0df4411bd140f` | [red](../../test/integration/.n5-manager-db-fixture-20260924/a4-no-save-red.raw.log) `9f5f6eed20fd19fcf6545126e545b1557f8fc54dc0bb319c4217f30d6d89d086`, exit 1 waiting for journal |
| Restored production source | [build](../../test/integration/.n5-manager-db-fixture-20260924/a4-clean-rebuild.log) `425ff584905cc763346572d76dfb317403bdca11d1748650e33b19adce43db88` | [binary](../../test/integration/.n5-manager-db-fixture-20260924/a4-clean-binary) `2558c9421296b4e60c4d887ede5dac559b554b17fdfec4ad21fac530afacca76` | [green](../../test/integration/.n5-manager-db-fixture-20260924/a4-cut1-restored-green.raw.log) `aaccda9e78c4e81a7f8f8f8369ee0880d7a52b20428a01e288316740fbae5409`, exit 0 with cold marker/proof/signature comparison |

The CI source guard was mutated in both directions: removing the CMake CTest
registration returned exit 1 with `N5 write-after recovery CTest is absent`,
and removing the workflow run returned exit 1 with `N5 FinalCert write-after
bootstrap recovery behavior gate is absent`. Restored guard exit 0.
This is a same-session write-after FinalCert recovery control, not evidence
for N03's #13-only cut, N04's proof-before-marker cut, N05's post-marker
idempotence, or N06's independent full-root rebuild. N01 and N03–N06 remain
OPEN pending their own cutpoint controls and fixed pushed-tree CI.
