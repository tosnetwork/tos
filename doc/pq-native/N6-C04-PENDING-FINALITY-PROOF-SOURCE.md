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
