# N01 slice: production Simplex FinalCert journal cold read

Status: **proved for `SaveCertificate` handler and journal key; N01 OPEN**.
The fixed production/test source is pushed `439efb4eea2260a254f7465369a29ea9265c4f93`.
This is not a Pool-produced FinalCert, StateResolver finalized marker, Manager
`AcceptBlock`, `#13`, BlockProof, or crash-at-write test. The fixture directly
publishes a verified FinalCert to the production Simplex DB actor to isolate
the first durable certificate record before joining the rest of the chain.

The writer child constructs four public-seed ML-DSA-44 keys and signs one
session-bound `FinalizeVote`. It uses production `Certificate<Vote>::from_tl`
to verify all four signatures and quorum before calling the Bus runtime's
`SaveCertificate` request. `simplex/db.cpp::process(SaveCertificate)` writes
`db_key_vote(SHA256(inner certificate TL)) → db_cert(inner certificate TL)`
through Bridge's unchanged RocksDB `DbImpl`; the request returns only after
the DB `set` completes, then the writer awaits `Db::close` and exits. The
writer saves its exact, randomized-signature inner TL as a separate comparison
artifact outside the DB. The reader is a new process at the same session
directory: it computes the production key from those retained bytes, reads
the production `db_cert`, compares the full inner TL and hash, and runs
`Certificate<Vote>::from_tl` again. A distinct unwritten root has the same
static genesis BOC but neither Manager handle nor certificate key; its forced
positive read requires exact missing-handle and missing-FinalCert-key errors.

At the committed source, the direct run exited 0 and CTest passed 1/1. Raw
artifacts are under `test/integration/.n5-manager-db-fixture-20260924/`:

| Artifact | SHA-256 |
| --- | --- |
| `439efb4ee-committed-green.log` | `4a9ecd202fe0d3cca7f5a38bae4aef2f1d2fd8e31c786e71de35dbae4550a37f` |
| `439efb4ee-committed-ctest.log` | `81a8ad185a7846ede40ef2cd494ea8b4273ce91f7142f640e769cdcb7c0d5082` |
| clean test binary | `3a1f09c7e9b41b45452388e809e6d4859fb9427932c8d803d119cd93229e204f` |
| test source | `438991ded6550344a40ed4b67fb22a5a00eab49534cbd9531374714c69cd63d4` |
| production `simplex/db.cpp` | `9828815f8239e010a0a8461f59b287e8ae33977e4ba3bbdab823caf8f138ff63` |
| production `simplex/certificate.cpp` | `1e1c6b55cbcab627616fc75f6dff2a836114dc153c3eee00cd10e84ef2cf03b8` |
| production `bridge.cpp` | `d9abf44a012811f9896c0d422d6fc7bedbebbeeb46d69deefe919c26623fb2ee` |

The committed green's 9,784-byte original TL is
`/tmp/n5-manager-persist-XpH12F.expected-finalcert.tl`, retained with the DB
root. The writer and cold reader both printed key hash
`249CCCF72AF965C217E7BEFF0D021511FB0F44B53D70C23D73D1D87F9710CEBD`.
An independent SHA-256 calculation using the crypto-hash backend over that
retained TL yielded the identical digest; its raw result is
`439efb4ee-committed-independent-sha256.txt` (SHA-256
`2f08e182c51e1fad051d614f4fc3e7aad87c3f9ed8d79dc36cecc939c1a917e5`).
The session-root journal and empty-root DB directories were retained; no
artifact was deleted.

Two single-change mutations on the **committed test source** make distinct
claims red, and were restored before rebuilding the identical clean binary:

| Mutation | Red result | Patch SHA-256 | Mutant binary SHA-256 |
| --- | --- | --- | --- |
| Skip the `SaveCertificate` publish but keep the writer's other steps | Cold reader: `FinalCert journal key absent` (exit 1); `439efb4ee-no-save-red.log` SHA-256 `6090df3afac207318ad35e2cce7e3c23d12e66c7e38648f6541ecaef0ca54ee3` | `5824f7f9848c64fbf26c342e6ea15fd0b988f101ea5856c6f7a54b5c9dd37c3b` | `4a10b3a72d4614993a7e6bc90a6063b6253d3c419ddde9a74dc9627ea3d69d4a` |
| Read the FinalCert from a different journal root while leaving Manager's root correct | Cold reader: `FinalCert journal key absent` (exit 1); `439efb4ee-wrong-journal-root-red.log` SHA-256 `d179374ca8f20df231342aa222093e8f692b054b0d380ab043562f3b72ee5dd3` | `0d92c59fc7db3176787fdaf9378dc336514ea912cea87b5a4cff4e5c677523b1` | `47d72c1bad037f9280c57dc1a4f5ee096d9a05ced2694c2b29735774f83dff3a` |

The first mutant test-source SHA-256 was
`4157102de677f94c9dd58f9fd08584b36a335bdc8b5628c9d334c07780dcfa71`;
the second was
`6574893afbe081a9ba39ce88151a8eba6abfb5945c5620b42265ec247e849244`.
Both unique patches pass `git apply --check` against `439efb4ee`. The older
`no-finalcert-save-red.log` from 17:38 used a prior output label and is only
development evidence; the `439efb4ee-no-save-red.log` from 17:43 is the
committed-source mutation. An earlier wrong-root bypass died at the Manager
empty-root control, not the certificate locator, and is not counted here.

Next N01 boundary: use the same true RootDb and journal roots while driving
Pool `SaveCertificate` → StateResolver `FinalizeBlock` → production Manager
`AcceptBlock`/`#13`/BlockProof and the finalized marker, with a named successful
write-after gate and cold reconstruction. A direct DB handler call alone does
not establish that chain, so N01 and N02–N07 remain OPEN.
