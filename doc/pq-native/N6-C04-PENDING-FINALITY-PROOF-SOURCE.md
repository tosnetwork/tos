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
evidence and trusted-context failures. The test remains component-level; an
actual `ValidatorManagerImpl` actor red/green, plus a stale-context positive
recovery path, is still required before this correctness question closes.

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
