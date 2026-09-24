# N01: dual-root Manager/consensus DB restart fixture

Status: `e03f8d971` established the N01 **foundation**, not the complete N01
write-after-cut fixture. N01 and N5 restart cuts N02–N07 remain OPEN. This is
one test executable using a writer child and separate reader children, not a
node-network, FinalCert-persistence, or crash-at-write result.

The test uses one real `ValidatorManagerImpl` actor and the production
`create_db_actor`/RootDb. Only network-heavy Manager startup is suppressed.
It writes a real PQ zerostate through `Db::store_zero_state_file`,
`Db::store_block_state` and `Db::store_block_handle`; the child reconstructs
the actor and RootDb at the **same** `db_root`, and requires the exact
zerostate handle state flag and state root. The writer child exits before any
reader starts, so all its actors and process-local caches are gone. This is
process separation, not a demonstration of orderly RootDb/Archive/CellDb
shutdown or a power-loss crash. A second, unwritten root carries the same
static genesis BOC but must have no handle. The wrong-root positive control
requires the exact `block handle not in db` error; an arbitrary nonzero exit
cannot satisfy it. This rules out a static-file or in-memory answer
masquerading as a persisted RootDb read.

The Simplex journal is a distinct RocksDB under the production
`consensus_db_root`/`consensus_db_dir_name(session_id)` path. Bridge and this
fixture now call the same `open_rocksdb_consensus_db` factory, which retains
Bridge's original `DbImpl` implementation and its awaited synchronous
`KeyValueAsync::set` boundary. The test writes only a fixture-specific string
marker, closes that journal writer, then reads it in a fresh process from the
same session directory; the unwritten root must be empty. This proves the
DB-root wiring, not that
`SaveCertificate` or the finalized marker was written. To complete N01, the
fixture must drive the production Pool `SaveCertificate` → StateResolver
`FinalizeBlock` → Manager `AcceptBlock`/`#13`/BlockProof → finalized-marker
chain, pause at a named successful production write callback, then reconstruct
the same DB root and session. N02–N06 must exercise the ordered cut points;
N07 must drive the real `CheckProof` actor.
`TestManagerFacade::accept_block` is not used: it validates signatures and
notifies the test consensus without production
AcceptBlock/RootDb persistence.

At exact committed source `e03f8d971`, the direct test exited 0 and the
registered CTest passed 1/1. Raw logs under
`test/integration/.n5-manager-db-fixture-20260924/` are
`e03f8d971-committed-green.log` (SHA-256
`02223eaea998fbd017ee88f03d66886de4144826b01e531769774a078b269f8a`)
and `e03f8d971-committed-ctest.log` (SHA-256
`79cb1bc06bc85eb1d800854d13a70e76903eedb61da3a5ce54de740b083a4d0e`).
The binary SHA-256 is
`fdfa2c9539cd187e80f480e84ebf9fc0b3b7a2eb57c009a08d3dcca52954ddbb`;
the test and reusable fixture source SHA-256 values are respectively
`8de7a70b9f4535f9926d3379aba22101f940ccd90d077ea2683971883b3e7fed`
and `4818c763bf842f03c388146651c24bd31389ad2c56d09dadcbc755511e0f8fba`.
The retained roots from that run are
`/tmp/n5-manager-persist-mRVcxD` (484 KiB) and
`/tmp/n5-manager-empty-j42aql` (320 KiB); neither was deleted.

Earlier development mutations and raw logs remain in the same artifact
directory, but they do not constitute the final child-writer controls below.
The reproducible root-state mutation patch is
`n5-rootdb-state-write-mutant.patch` (SHA-256
`426a9ded4c0cc3988e9e69baee476977fc3578eab21dd0517d29925be127f401`).
A third probe bypassed the explicit `Db::store_block_handle` and **survived**:
`store_block_state`
already leaves a readable handle in this fixture. Therefore N01 does not
claim that the extra handle write is individually load-bearing; the state
write is the measured boundary.

The final child-writer revision kept the production source and retained both
mutation controls. Its direct and CTest runs exited 0 (CTest 1/1). The clean
binary is SHA-256 `ebf4b2622ffa2da70d55fe798fec7f5675b94eae0709a77128ecf6654981b464`;
the test source is `4673396f19c0fb97a46b62b6eaaadac5b211018111be7aa85aa401e3a926cd5c`.
`child-writer-final-green.log` is `feec33193118b44e7ecc9adcd0da8c89d7ae59f30779296abe22a911cd585fe7`;
`child-writer-final-ctest.log` is `855a81acdeb58e179599c872bd7b0f674cfd3350c6630ce6edf3701220e7600e`.
On that exact test source, bypassing the journal write fails only at the named
journal read (`no-journal-child-writer-red.log`,
`50c1299a07eab211b5e722c6c7aff0f4c4bbdf4a28365f261627d7f20f2edbdd`);
the mutant binary SHA-256 is
`0c02080bcdc4c56ebeb50b9c3a0c48f0fe552de0c4fd50af5ca0362955dfadab`.
bypassing `store_block_state` fails only at the named RootDb state flag/root
(`no-root-state-child-writer-red.log`,
`9081ba6d23fa1986c97e5cee345648ad2887bf76e55bdc78cb6378cde77c6ca2`).
That mutant binary SHA-256 is
`0d2431f7965f59f9887d8a092072c26a7c4725bf74e374824a8e9ac3bf25fb01`.
The updated journal mutation patch is SHA-256
`b2b586e5d33f0af5f40031ce4a8df4e756cb977f45ea9ef39109e0b00414be52`;
both patches pass `git apply --check` on the clean fixture. The retained clean
roots are `/tmp/n5-manager-persist-89zaGd` and
`/tmp/n5-manager-empty-MM0AGH`; no root was deleted.

The first dual-root read crashed because the test opened `KeyValueAsync`
outside an actor scheduler. That was a fixture error, not a chain result;
its raw log and gdb backtrace are retained. The final child constructs the
journal within a scheduler, as Bridge does. No N5 closure claim follows from
this foundation. In particular, its mutation controls are about a seeded
zerostate and an arbitrary marker, not about a FinalCert journal or `#13`.
