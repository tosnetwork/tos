# C04/FN1: pending-finality proof failure provenance

The independent component audit at
`/home/tomi/memo/pq-native/N6-MAC-C04-FN1-RESULT-20260924.md` observed a
wrong-validator-set-hash PQ finality carrier accepted at broadcast ingress.
`BlockSignatureSet::serialize(vset)` then returned protocol violation 621.
Before this change, `ValidatorManagerImpl::try_process_pending_block_finality`
treated every proof-construction error except `notready`/`timeout` as bad
cached block bytes: it kept the offending evidence at the queue front and
erased the valid candidate. Four component-modelled block arrivals repeated
that decision; the good evidence behind the bad front was never reached.
The audit did not invoke the manager actor, so this is a component-level
mechanism, not an observed live-network halt.

Proof construction now reports which input failed. An invalid block root or
assembled block proof may retire block bytes. Once the computed trusted set
matches the block header's catchain sequence and validator-set hash, a
carrier declaring a different identity or failing serialization is finality
evidence failure: the bounded pending queue retires that entry and retains
the candidate for the next one. If the computed trusted set itself differs
from the block header, the local context can be stale. Both candidate and
evidence are retained for bounded `notready` retries; the existing 60-second
retention deadline still frees the evidence slot. This is not an unbounded
retry, and it does not claim that a stale state will necessarily arrive in
time. No validator or finality parameter was changed.

`test-pending-finality-cache` exercises production broadcast parsing,
signature-set serialization, queue order, and the production source/action
classifier with wrong-hash evidence ahead of valid evidence. It separately
pins header/trusted/evidence identity verdicts, including catchain sequence
and set hash, and the three source-specific actions. The source guard checks
the manager actually calls that classifier and the proof producer labels
evidence and trusted-context failures. A no-startup `ValidatorManagerImpl`
actor probe now exercises the manager's actual pending queue, block cache and
proof-failure handler in three directions: bad finality evidence retires only
the front certificate and leaves the next entry dequeuable; bad block bytes
retire only cached bytes; a stale trusted-context error retains both inputs
until bounded expiry removes the certificate. That first actor case supplies
errors at the handler boundary. A second no-startup fixture supplies a
syntactically valid masterchain block, wrong-set and correct PQ finality
evidence, and controlled masterchain state. It calls the production
`try_process_pending_block_finality` path: the wrong-set certificate fails
actual `WaitBlockData::generate_proof`, is removed while block bytes remain,
and the next certificate reaches proof construction and real PQ signature
verification. With stale trusted context, the same path retains both inputs,
retries after the context is replaced within the deadline, and completes.
A separate expired-context case shows the certificate is retired while block
bytes remain. Restoring the old proof-error behavior of deleting the cached
candidate makes the same manager test fail with
`PENDING_FINALITY_MANAGER_REAL_PROOF_FAILURE`.

The probe substitutes a successful `new_block_broadcast` callback; it does
**not** run downstream `AcceptBlock`, a database write, or a real network.
It therefore proves queue progression through proof and cryptographic
verification, not actual block acceptance. C04 remains OPEN pending that
downstream actor proof and fixed-commit CI. The historical network impact
is still not established from the component or actor fixtures alone.

The missing downstream proof is not a naming issue: production
`new_block_broadcast` creates `ValidateBroadcast`. That actor reads the
reference key-block or zero state and the target block handle, writes block
data, runs `CheckProof`, then may create `ApplyBlock`. `ApplyBlock` waits for
the actual shard state, persists parent links, and marks the handle applied.
The no-startup probe has none of those DB/state prerequisites. Pre-marking a
handle as received/proven/applied would bypass the operation C04 needs to
observe, so it is not an acceptable shortcut. A closing fixture must supply
a valid predecessor state and observable DB writes, or use a real manager
network, while retaining the bad-front/good, stale-context recovery, and
expiry controls. Until then, "broadcast callback succeeded" is the precise
boundary, not "block accepted."

An attempted independent `CheckProof` probe exposed a more specific fixture
precondition before any signature or DB decision. The synthetic manager test
passed its target-height (43) `PendingFinalityProbeState` as the proof's
starting masterchain state. Production `CheckProof::process_masterchain_state`
rejected it with `cannot check masterchain block proof ... starting from newer
masterchain state`: that routine requires a state strictly earlier than the
target block. Merely changing the synthetic state's ID to height 42 would not
make it a valid predecessor: its root is an empty test cell, whereas the
block's Merkle update expects a different old root, and
`MasterchainStateQ::get_validator_set(shard,time,catchain_seqno)` reads the
parsed state configuration, not the probe's `get_config_holder()` override.
This was a diagnostic fixture failure, not evidence that the valid finality
proof is rejected. The failing probe was removed; the existing test was rebuilt
and passed again.

The next executable fixture must start with a real predecessor state at N-1
whose root matches the block's Merkle update and whose ConfigParam 34 yields
the fixture's validator set. It must initialize a real block handle and DB,
deliver bad then good finality for that same block, and observe the good entry
through `ValidateBroadcast`, `CheckProof`, `ApplyBlock` and a persisted/applied
handle. Repeating with temporarily unavailable trusted context and then with
retention expiry gives the two remaining controls. The current synthetic
block/state pair is sufficient for `WaitBlockData::generate_proof` and the
manager queue, but is not a replacement for that predecessor-state fixture.

An offline component fixture now supplies that predecessor-state input without
claiming the downstream actor result. `test-c04-real-state-proof` reads the
frozen public PQ masterchain zerostate BOC (SHA-256
`4e833bf9650c48448969688b862abfd6ad31dd504aa9ab68757db683e47bb162`),
checks all four ConfigParam 34 signers, constructs a seqno-1 state with the
required zerostate entry in `OldMcBlocks`, and applies a real Merkle update.
It then signs with the shared test signer fixture, runs production proof
generation and parsing, and rejects a wrong old root, trusted session, or
declared validator-set hash. The imported fixture is the independently checked
candidate described in
`/home/tomi/memo/pq-native/N6-MAC-C04-REAL-FIXTURE-CANDIDATE-20260924.md`;
its patch SHA-256 is
`a04f9f8ec88ce89985a2f25c852417c6997cf8a1a028663547418304a0ea5224`.
On the working tree based on `19aba0749`, the new target built and its CTest passed
1/1; the test binary SHA-256 was
`52a1bcbaf602c766a1bcc0290f38e93f8a54cfffaaafd1751937192b7069e541`.
This is a component fixture and the Mac old/new result was a fixture repair,
not production C04 RED/GREEN. The Manager probe still substitutes the success
callback and has no DB-backed applied-block assertion. C04 remains OPEN.

The fixture also now parses its seqno-1 block with production `create_block`
and applies it to a freshly fetched seqno-0 `MasterchainStateQ` using the
production `apply_block`, requiring the exact generated seqno-1 state root.
The clean CTest passed; a one-field mutation that compared the applied result
to the old root failed with `C04_REAL_APPLY_FAILED` (exit 8 from CTest), then
the restored test passed. Raw logs are
`test/integration/.c04-real-state-proof-149b3d360/wrong-result-root-red.log`
(SHA-256 `9e0b54e23065ec45923b0a7e8861b94ffb94ffcc2002048a6a9bb0e3768af202`)
and `real-apply-final-green.log`
(SHA-256 `8ddafbeba3c885e0324d3d55271d2b7491dcf74e4343d5bdedbae00dab931811`).
The clean binary SHA-256 was
`e14e4a57de3ba07b060e39710d2191d1517465ab3fa8246e924e6269ef50896c`.
This rules out an inapplicable synthetic state transition as the next actor
fixture's first obstacle; it still does not exercise Manager/DB persistence.

The old-behavior mutation changed only the proof-error branch of
`try_process_pending_block_finality` back to candidate-byte erasure. The
`test-pending-finality-cache` CTest exited 8 and named
`PENDING_FINALITY_MANAGER_REAL_PROOF_FAILURE`; the restored tree passed.
The retained logs are
`test/integration/.c04-manager-proof-actor-20260924/old-behaviour-red.log`
(SHA-256 `8406f6e72baf85e84ac8bfdb10a17ac14ba15ee86d5fd9786bfada4ece87843c`)
and `current-green.log`
(SHA-256 `69c062d28c8e034c090663e7794880fbae5a0fe5e7f134c5fb2855c5422211c1`).

During actor-probe construction, three intentionally wrong manager mutations
were observed red with named assertions: forcing block-byte disposal for all
errors failed the bad-front evidence assertion; forcing all sources to
`FinalityEvidence` failed the bad-block-bytes assertion; and suppressing
trusted-context conversion to retryable `notready` failed the context
retention assertion. All mutations were restored before the clean build. The
all-`FinalityEvidence` mutation initially survived while the probe lacked a
bad-block-bytes case; that blind spot prompted the third direction. This is a
partial manager-integration gate, not C04 acceptance evidence.

Local pre-commit checks used `cmake --build build --parallel 4 --target
test-pending-finality-cache validator-engine test-pq-lite-forward-proof
test-download-next-blocks-validation`, followed by CTest names
`test-pending-finality-cache`, `pending-finality-retry-policy-source`,
`test-pq-lite-forward-proof`, and `test-download-next-blocks-validation`:
4/4 passed. The retained CTest log is
`test/integration/.c04-proof-source-precommit-20260924/ctest.log`, SHA-256
`9dafb2e35bf893dbc673f501523c4d41edf8e021c3c61b5779f3e9aa86340ead`.
This is a working-tree run, not fixed-commit acceptance. Five targeted
mutations were red: treating evidence error as bad block bytes; treating
trusted-context error as bad evidence; swapping either header-identity
verdict; and a manager bypass of the production classifier. The first four
were killed by the component test, the manager bypass by the source guard.

## DB-backed Manager actor gate (6171d053f)

The earlier statement above that the Manager probe ends at a supplied
successful broadcast callback describes `test-pending-finality-cache` and
was true when written. A separate fixture now takes the next boundary.
`test-c04-real-state-proof` starts a no-network `ValidatorManagerImpl` with
production `create_db_actor`/`RootDb`, a genuine seqno-0 PQ masterchain state
and a persisted genesis handle. Only production startup is suppressed; the
test provides the genesis static file, a no-op local Manager callback, and a
real `ExtMessagePool` actor. It does not replace pending-finality scheduling,
signature checking, `new_block_broadcast`, `ValidateBroadcast`, `CheckProof`,
`ApplyBlock`, or DB methods with success callbacks. It does not pre-mark any
seqno-1 target flags.

For one exact seqno-1 block, the actor admits wrong-set PQ finality first and
valid PQ finality second. The bad certificate fails proof construction with
621 and is removed as evidence; the same cached candidate then reaches the
good proof. After the queue drains, a fresh `RootDb::get_block_handle` fetch
from the archive checks `received`, `inited_proof`, `received_state`,
`is_applied`, `applied_stored` and the exact state root. Further DB calls read
the exact block data hash, byte-identical good proof, state root, and genesis
handle's next pointer to the target. The Manager's live handle separately
checks `processed`: that flag does not increment the handle version and is
not a persisted-handle contract. A successful broadcast Promise alone cannot
satisfy these assertions.

With the one-line old-behaviour mutation in
`c04-blockbytes-classification-mutant.patch` (SHA-256
`e5561627153f37a23af32a9df0ddea7797b9ea10c64a68492755b63b89544ec0`),
the same test source failed: `candidate_present=0 pending_entries=2
target_processed=0`, then the queue timed out. The patch applies cleanly to
the restored tree. The mutant `manager.cpp` SHA-256 was
`f2aefb3543fe071de7a5e4c059dd6e8b3788cc1519612608b5a27aed96db5c4b`
and binary SHA-256 was
`52227454cdda606e16b9950961e831db304026b150a31283574bf4af86217118`.
The restored production source SHA-256 is
`43ffd95fb6c6ab8d3a4fd5e36ffdf6b06ab91a0c32c4cdbcd526da08446ee79c`;
the test source is identical across red and green (SHA-256
`4fd8993878260990f29bb59c44bf0e7fb73181048bd4bef124a968ef6061a053`).
The clean binary SHA-256 is
`fcceb81977e681170125107356b28525be34361cb0afd575322c6711f0709f2f`.

Raw old-red and new-green logs, respectively, are
`test/integration/.c04-manager-actor-20260924/final-harness-old-red.log`
(SHA-256 `c70bc806beb6e425c50ecf879fc7202bb190ff18c0fa86131f659972fda61486`)
and `final-harness-new-green.log` (SHA-256
`35ff934a1937afcce3656b323ed920c667d201debd4bd5e3ef8522891b62d189`).
On committed `6171d053f`, the three targeted CTests passed; retained
`6171d053f-ctest.log` SHA-256 is
`9ec6c951542adc0c03fe69b1c0e2f3f9c108ab3af9c53cc8c8c31ead506d9bea`.
The DB roots printed in the raw logs remain in `/tmp` and were not removed.
The committed-tree green run's root is `/tmp/c04-manager-ccYOsW`: 39 files,
504 KiB allocated. SHA-256 of the sorted, relative-path `sha256sum` manifest
for those files is
`2f46747842fa03d6ee93c46ea4a6bba8e593a1b1198d6d2c35d59206b9149969`.
This is a local retained DB artifact, not a Git payload.

The DB-read handle has `processed() == false` even on the successful run;
`BlockHandleImpl::serialize()` and its deserialize constructor explicitly
mask `dbf_processed` (`validator/block-handle.cpp:34-50`). The successful
run's earlier diagnostic printed `received=1 proof=1 state=1 applied=1
applied_stored=1 processed=0` with the expected root. Therefore adding
`processed()` to the DB-read rejection condition would create a false
negative. The test asserts `processed()` on the live Manager handle and the
persisted effects on the separately fetched DB handle. This distinction was
raised in independent review of `6171d053f`; it is an intentional boundary,
not an omitted success condition.

This establishes downstream acceptance and persistence for the bad-front,
good-back case in the no-network Manager actor. It does **not** yet extend
the DB-backed path to transient trusted-context recovery or retention expiry;
those controls still use the earlier no-DB Manager probe. Fixed-head CI for
this added gate is also pending. C04 therefore remains OPEN, and no historical
network outage is attributed to this test.
