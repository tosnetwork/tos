# I13 host mechanism inventory

Static inventory at the commit recorded in
`doc/measurements/uno-m1-i13-host-mechanism-inventory.json`. This is a deliverable
about missing mechanisms, not behavioral acceptance. D47 and D48 are the approved
requirements. No production code, activation gate or test checker is introduced.
The source inventory includes committed blob OIDs and content SHA256 values;
working bytes were checked against those blobs. The inspected host files also
match the recorded integration-branch revision. Later changes require rechecking.

| Invariant | Missing host mechanism | Required behavior | Existing reusable pieces |
|---|---|---|---|
| I13a: one logical batch per block | A block-wide AccountBlock identity enumerator/checker, and independent recomputation/comparison of committed batch count | D48: all wc=2 AccountBlocks reference one and the same batch identity; the set has exactly one identity. Derive the count from actual block contents and compare the submitted committed count, never use that count as the source of truth. | `UnoV2HostRecord` input/effects commitments; participant record construction; real storage/allocation/payout AccountBlocks; per-settlement replay and Native dictionary traversal |
| I13b: one execution per admitted input in a block execution scope | A host-owned scope ledger and a mandatory check at the stateful engine invocation boundary | D48: create at the start of processing a block candidate, destroy at its end; key by admitted input root hash; reject a second execution in that scope. Independent validator replay is a separate scope. | `ProofAdmittedBatchInput::root()`, retained admitted input and inspecting engine, stateful `execute_accounts` boundary and existing execute/replay callers |
| I13c: exact participants/write set and bound reads | Core private checks exist; enclosing live multi-account integration is still missing | Preserve equality in both directions and read hash/presence binding. Actual dictionary changes and physical participants must be independently reconstructed by the host. | `WorkchainAccountAccess::create/finish`, `expected_read/record_old_read/record_write`, `WorkchainAccountDictionary::verify_old_read/changed_accounts`, accepted private acceptance fixtures |
| I13d: exact change coverage and untouched accounts unchanged | Private observation/dictionary pieces exist; their complete lifetime and use through the enclosing live pipeline still need integration | Preserve actual delta coverage and unchanged untouched accounts. Unread-body observations alone do not imply unchanged dictionary entries; changes that replace an entry without loading its old body must remain covered. | `CellUsageTree::ScopedReadObserver`, `UsageCell`, pruned Merkle proofs, dictionary delta checks, full-byte and partial-state acceptance fixtures |
| I13e: one commit or zero commits | An atomic publication entry, real reader/recovery surfaces, release observer and store failure/recovery hooks | D47: commit the entire generation including message eligibility and batch count atomically; before-decision failure leaves no visible change or deferred orphan; after-decision interruption resolves the same commit, and retry neither re-executes nor republishes. | Private account settlement and outbound queue roots, import/export artifacts, replay comparison, approved test-only contract and pending assertions |

## I13a: existing bindings do not enforce block uniqueness

`crypto/block/block.tlb` defines `UnoV2HostRecord` with `input_hash`,
`effects_hash`, `account_id` and `effect_index`. Storage, settlement and entry
transaction descriptions reference that binding. The participant builder
`build_workchain_participant_records` supplies the same input/effects commitments
to one invocation's records. It validates the local key sequence and size; it
never scans a complete candidate block.

`Transaction::prepare_workchain_storage_participant` checks the binding's account
identity and restricted transaction context. This is not comparison with the
identities in all other AccountBlocks. `account_replay_detail::compare_rebuilt`
compares one settlement's reconstructed AccountBlocks root and other artifacts;
it has neither a submitted block-wide committed-count argument nor the D48
whole-block identity/count interface.

The live `ValidateQuery::check_transactions` multi-account alternative reports
that admission/replay are not connected. Its separate singleton alternative
requires exactly the executor AccountBlock. Applying that restriction to the
multi-account path would reject legitimate multiple participants; it cannot be
reused as the I13a uniqueness rule.

The implementation must connect a bounded scan of the actual candidate's entire
wc=2 AccountBlocks/transaction content to identity extraction, uniqueness and
count comparison. A producer's list of identities or a test-side list is not an
independent source. The existing input/effects pair provides commitment material;
this inventory does not invent a new identity encoding or claim that one already
has a block-wide validation API. Its exact mapping across entry and participant
records must be explicit in the host implementation.

Required future discrimination includes: multiple accounts sharing one identity
accept; no identity rejects; changed input commitment and changed effects
commitment are each examined; a second identity placed outside the first scanned
account must not be missed. Hold actual content fixed while varying the submitted
count to test count honesty. A candidate with two identities claiming count one
must reject, but that case alone cannot distinguish the uniqueness guard from
the count-comparison guard. Use single-identity content with a wrong count to
isolate the latter, and an honest recomputed count of two with two identities to
isolate the former, subject to the eventual entry's error identities/preconditions.
No such behavior has been measured here.

D47 atomicity binds count to content; it does not make the count truthful. D48
requires separate recomputation. The D47 assertions are still unwired: neither
atomic count/content behavior nor D48 count honesty is accepted by this inventory.

## I13b: an admission value is not an execution permit

`ProofAdmittedBatchInput` explicitly states that copying it is not a one-use
execution permit and leaves block uniqueness/the execution ledger to the host.
Its owned input and `root()` accessor supply the required hash source. No
block-execution scope ledger is supplied by this token. The separate "execution
ledger" comment in the access codec concerns canonical account-key declarations;
it does not create the D48 invocation ledger either.

The host must own the ledger across all stateful invocations while processing
one candidate. A fresh ledger per call is ineffective; a process-wide ledger
would reject legitimate repeated verification. Token copies must share the same
scope check, while a new validator replay scope must permit its own execution of
the same admitted root. The guard must prevent the second invocation, not merely
notice it after effects have been produced. Exact integration/lifecycle and
failure identities need the real host entry; no substitute ledger is implemented
inside the acceptance code.

## I13c and I13d: reusable measured private mechanisms

`WorkchainAccountAccess::finish` compares the actual changed accounts and physical
participants separately with the declared writes and verifies declared reads were
checked. The accepted private I13c/d evidence is at commits `1f5824ed4`,
`2f13d9a25`, `a724a99ba`, and `e542b08d5`. These establish the documented fixture
properties and guard controls, not full live-block integration.

The I13d fixtures include both complete serialization comparison and deliberately
pruned untouched bodies. The latter prove that the exercised private path can
complete without loading those bodies; the test also confirms loading them
raises the specific virtualization failure. They do not establish production
`VmVirtError` source classification. Direct dictionary replacement without loading
an old body is explicitly covered as a counterexample to an unconditional
"unread implies unchanged" claim. A complete host must retain tracking across
its entire relevant execution interval and preserve independent delta coverage.

## I13e: private root production is not atomic publication

The detailed [boundary inventory](workchain-i13e-boundary.md) and
[D47 contract](workchain-i13e-contract.md) remain the source inventory and approved
obligations. `WorkchainAccountSettlement` holds private account/AccountBlocks
roots, import information, exports and admission snapshots.
`WorkchainOutboundQueueRoots` supplies descriptors, outgoing and dispatch roots.
Private `tx.commit(account)` calls modify temporary Accounts, not the authoritative
publication generation. The singleton collator's local mutations do not establish
an atomic multi-account publisher or, by ordering alone, an external split-commit
bug. The state-download buffer's unrelated commit mechanism is not this entry.

D47 requires three actual observer surfaces: same-block authoritative consumers,
reopened real commit storage, and external logical release eligibility subject to
existing acceptance/finality rules. Private intermediates are excluded only when
no consensus-affecting consumer observes them, including observations later
rolled back. The test-only contract records those obligations; its undefined
adapter is not an implementation. D45's moved rejection boundary is the proposed
position 24 (`BeforeAtomicPublish`); position 25 (inside the store before its
decision), successful publication and post-decision recovery remain inaccessible
with the gate closed. This inventory does not move that gate.

## Handoff

I13a, I13b and I13e require real host mechanisms before behavioral acceptance can
be wired. I13c/d supply reusable private checks and measured fixtures, with live
integration still a separate obligation. Host changes remain under coordinator
ownership/scheduling. No implementation assignment, activation, resource-policy
relaxation or I13 acceptance follows from this inventory. No timing estimate is
made. Searches support source review within the recorded domains; missing keyword
matches alone are not treated as proof that a mechanism cannot exist elsewhere.
