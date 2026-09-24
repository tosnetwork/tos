# N06 controlled Cut 5: rebuild finalized evidence from retained DB/archive

Status: local fixed-tree evidence. N06 and the encompassing N01 remain OPEN until an immutable-head Branch PQ CI run and independent review. This is process-separated actor/DB recovery after an orderly controlled stop; it does not claim a power-loss crash, peer convergence, or a full node startup.

At `089d06b9b2ad3437fda84f6f5eff04f955a4e1c8`, the existing production Pool→StateResolver→BlockAccepter→Manager path writes one signed FinalCert, finalized marker, accepted block and PQ BlockProof. The writer then stops its runtime and spawns a fresh `--n5-cut5-rebuild` process. That process gets a genesis BOC path **inside the retained root's static-file archive**, the DB root, and two expected hashes as comparison metadata. It receives no FinalCert TL file and does not construct the PQ signing-key fixture; `10ece72ab1ede5edba50889e30f474b8be1155ce` adds an explicit local refusal if key custody is constructed. The child scans the production Simplex `db_key_vote` journal, requires the exact FinalCert hash, verifies its candidate/vote ID and signatures, checks the finalized marker, then starts a fresh Manager/RootDb actor and cold-reads the accepted handle, proof bytes/signatures, state root, block data and predecessor next link. The BlockProof is compared byte-for-byte by hash and signature-by-signature with the journaled FinalCert. No re-signing is used for this cold reconstruction.

Two distinct negative roots run in fresh children. A wholly wrong root must not expose the certificate. A journal-only root containing a copy of the stopped writer's Simplex consensus directory, but no RootDb/archive, must find the certificate and then fail at the precise `block handle not in db` boundary. The latter prevents a journal-only recovery from being called full evidence recovery. These roots and the successful root are retained; the final raw run names `/tmp/n5-joined-finalcert-kdGqlk`, `/tmp/n5-cut5-wrong-root-PirRoO`, and `/tmp/n5-cut5-journal-only-p35fEE`.

Command: `ctest --test-dir build --output-on-failure -R '^test-n5-(accept-block|joined-finalcert|cut[1-5]-|manager-db-fixture)'`. Fixed `10ece72ab` source: 8/8 passed, exit 0. Direct `--n5-cut5` exited 0 with `N5_CUT5_DB_ARCHIVE_ONLY_OK`, `N5_CUT5_WRONG_ROOT_CERT_ABSENT_OK`, and `N5_CUT5_JOURNAL_ONLY_ROOTDB_ABSENT_OK`. CI registration is a separate named Branch PQ step, and the source guard pins both its workflow command and `--n5-cut5` CTest registration; each half was individually mutated to the preceding cut and the guard failed with the corresponding named error, then restored.

| Retained artifact under `test/integration/.n5-manager-db-fixture-20260924/` | SHA-256 |
| --- | --- |
| Clean test source | `5b1c59cce22ccfd44326acdcfae6484ffcbbe544e6183c101ca2f789bc0be168` |
| Clean `build/test-c04-real-state-proof` | `b72df4e958414cb85bcd58b8cf463e36999e0c122118568978274188a8f7c7cc` |
| `10ece72ab-cut5-final-clean-build.log` | `1c853c44c0a5f844717e21301db02c61169d36527f8c2883aeab6547b5cb550f` |
| `10ece72ab-cut5-final-clean-ctest.log` | `fc87d919369932b1c48f7fa45539761495c84504df95eb62a0a5b0abc55c47b8` |
| `10ece72ab-cut5-final-clean.raw.log` | `6277afa9130ab3a3fc56bc2744ff1de26cc9df60bcd66cac4a5db0c2c1d61be2` |

Two single-purpose red controls, both restored before the final green:

| Mutation from committed `10ece72ab` | Result | Patch / source / binary / build / raw SHA-256 |
| --- | --- | --- |
| Scan `db_key_finalizedBlock` instead of `db_key_vote` for the certificate | exit 1, `exact FinalCert absent from retained journal` | `n5-cut5-wrong-journal-prefix-mutant.patch` `719a4ea96a05e15a8e60d6f4eee07d23735b27cc4a03fa5a54afce2b898f543e` / `57269608631fc52b25818f763dae5aa593f6ce07e2b468efc5303a7418b0852a` / `a747af000a6402c34a8cfc9863c206937e9f383c7d59141b0de131fe23d9ffb5` / `40406b439f3cf3f4001bbd851c5d6b3b45c4f325ba5b05774b192f9ff5d634f3` / `bfbe4c57c15143968f323b6af1ba11ff23f09d642f68c59224ca338017dfab75` |
| Reconstruct private-key custody in the cold child | exit 1, `cold process unexpectedly constructed signing-key custody` | `n5-cut5-recreate-keys-mutant.patch` `ac19a02dbe97a62219838c58d1ca036164aced5c08bb513f696971af8a13d7d7` / `5d8c9e51b7b8f3de24e2258d909ca48e306c4ddbf18797e112c394b4826d1bb4` / `55067bf92c4fcd91b12781fabbd5807d497f6b79108c87ab44acd1c7f9c3ad3b` / `9108a458351fb7243714db8d6efef83ef4ddeb1623434231093aee03d7089363` / `b9314f76272df11dbae1633795390452cfc8f6ff4878db24554c211efd4924a9` |

Both mutation patches pass `git apply --check --unidiff-zero` on the fixed source and independently reconstruct their recorded mutant source hashes. A passing send or an empty journal would not satisfy this test. The direct post-AcceptBlock `#13` signature file may be moved into the archive by the production path; this Cut 5 compares the durable BlockProof signature bytes to the FinalCert, while N03 separately cold-reads `#13` at its earlier write boundary. The fixture does not independently replay another finalized block or demonstrate convergence to peers; those remain outside this cut.

Patch-header correction after `8de6706df`: the two initially committed zero-context replacement hunks carried line hints 1108 and 1281, which `git apply --verbose --check` accepted with offsets 1 and 5. The corrected hunks use the actual fixed-source lines 1109 and 1286 and apply with no offset. Only the patch headers and their recorded patch hashes changed; the mutant source, retained binaries, build logs, raw logs and test outcomes did not.
