# I13c / I13d live integration shape — approved private implementation scope

Source baseline: `5d8125ed5f636fc34064798caa7a58d6f5789f38`.
The coordinator approved the private implementation scope on 2026-09-09.
This shape document is not live implementation or acceptance evidence; private
implementation and its evidence are described in `crypto/test/workchain-coverage.md`.
I13c/I13d private components exist; live enforcement remains unconnected.
No activation, publication, or default-build gate changes are proposed here.
Legal authenticated identity installation and the remaining execution seam are
prerequisites for live controls, not reasons to replace their inputs with defaults.
The existing refusal text `multi-account admission and replay are not connected`
still occurs once in collator and three times in validator at this baseline.
The separate registry required-workchain refusal is also a seam; counting only
those four strings is not a connectivity proof.

## 1. Verified components and their actual boundaries

| Component | What exists | What it does not establish |
| --- | --- | --- |
| `WorkchainAccountAccess::create`, `expected_read`, `record_old_read`, `record_write`, `finish` in `crypto/block/workchain-account-access.h` | Bounded, ordered declarations; writes subset of reads; old hash/absence checks; read/write completion; separate exact comparisons of changed keys and physical participants against declared writes | It does not obtain either comparison vector independently. Most errors are message-only `td::Status`, not live provenance classifications. |
| `WorkchainAccountDictionary::verify_old_read` in `crypto/block/workchain-account-dictionary.h` | Declaration lookup before dictionary access, followed by actual old Account hash or authenticated absence | Missing content is not absence. This hash does not cover all ShardAccount metadata. |
| `WorkchainAccountDictionary::changed_accounts` in the same file | Native old/new ShardAccounts `scan_diff`, checking new changed-node augmentation and bounding collected keys before insertion | The key limit alone does not bound traversal work. Exceptions can originate on either side of the comparison. |
| Storage, allocation, and payout overlays | Build private Native accounts/transactions, compute a dictionary delta, call `finish` | Their participant vectors are populated by the construction loop. They are not a second decode of the final physical AccountBlocks artifact. |
| `account_engine_detail::execute` in `workchain-account-engine.h` | Acquires authenticated old accounts before engine execution, verifies declared hashes/absence, constructs an immutable `WorkchainAccountReadView`, retains state-admission evidence | The view is a fixed snapshot for that call, not evolving state across calls. Checking engine update keys does not independently rebuild physical participants. |
| `account_settlement_detail::settle_executed` in `workchain-account-settlement.h` | Settlement-only continuation with no engine argument; retains admission and checks settlement reads against admitted state footprint | Calling the combined execute-and-settle entry again would execute again. A successful private settlement is not a publication permit. |
| `CellUsageTree::ScopedReadObserver` and `UsageCell` | Stack-nested synchronous observation of attempted loads, including repeated/failed loads; existing proof tracking remains separate | A load trace does not enumerate all changed entries. A weak tree node does not own the tree. |
| `account_replay_detail::compare_rebuilt` in `workchain-account-replay.h` | Compares effects, accounts, AccountBlocks, InMsgDescr, end LT, and message presence/hash after independent rebuilding | It does not compare every final export/queue/publication component. Its mismatch Status is not itself a typed live verdict. |

The private coverage harness independently decodes physical participants in
`crypto/test/test-workchain-i13-acceptance.cpp::participants`, then compares them
with a separately obtained dictionary delta. Its blind replacement case changes
an entry whose old body has not been read; other cases cover metadata-only
changes, insertion, and deletion. The usage harness additionally executes from a
hash-bound Merkle proof with unused account bodies pruned. These are relevant
private evidence, not evidence that either live actor invokes the checks.

There is also an existing **generic live** dictionary-delta traversal:
`ValidateQuery::precheck_account_updates` and `precheck_one_account_update`
(`validator/impl/validate-query.cpp:3133–3219` at this baseline). It compares
`ps_.account_dict_` with `ns_.account_dict_`, requires AccountBlocks for changes,
and checks Account HASH_UPDATE values. It is not the missing I13c comparison
against admitted write declarations. Its broad VmError-to-rejection handling
must not be copied as the provenance boundary of the new mechanism. This proposal
does not change that existing path or claim its exception reachability is audited.

## 2. Lifetime: actor-owned context, phase-scoped observers

The answer is **not** “make every observer an actor member.” I13b remembers
execution for a whole candidate-processing lifetime. A read observer instead
enforces a particular phase's admitted footprint.

| Object | Create / retain | End of lifetime |
| --- | --- | --- |
| Authenticated binding, same configured adapter, old-state root and tree owner | Actor retains binding/adapter after resolution; old root/tree become available after state acquisition | After the last settlement, construction, proof, or failure-path consumer; all exits release ownership |
| Access/completion evidence for one batch attempt | After bounded declaration decoding, before its first old-account access | After final coverage checking or failure; never reused as another batch's evidence |
| Acquisition read observer | Immediately before the synchronous authenticated-state acquisition it guards | On leaving that synchronous scope, including exceptions |
| Settlement read observer | Immediately before settlement-only continuation, using that execution's state-admission evidence and original tree | After all settlement/output-admission reads in that scope; sticky failure checked before returning success |
| Delta and physical-record collectors | At final private-artifact validation, with authenticated bounds already available | After a complete typed result or failure; partial collections cannot authorize anything |

The collator already creates its proof usage tree and wraps the old root with
`UsageCell` (`collator.cpp:1190–1194`, `1237–1241`), and later supplies that tree
to MerkleUpdate generation (`:6132`). Reuse this tree. Do not replace its proof
callback, nest another tracking wrapper, or cache loaded cells to bypass loads.
The adapter's ownership already spans stages; proof generation can outlive the
adapter, so tree ownership must be determined by the last tree consumer too.

The validator does not currently have the analogous collator tree member. Its
future replay context needs an explicitly owned tree for acquired old-state
reads; do not claim that it already shares the collator arrangement. Proof-view
roots must retain their authenticated binding and acquisition provenance.

`ScopedReadObserver` requires LIFO destruction and uses callbacks tied to its
synchronous frame. Never keep one installed across an actor yield, queued Build
callback, or asynchronous continuation. The actor may retain immutable roots,
meters and bounded sticky outcome data across stages, **not** a stack observer.
Create a fresh scoped observer inside each later synchronous read phase using
the same surviving tree. An expired tree is a local lifetime-contract error;
silently replacing it would erase the original proof-tracking claim.

Current engine acquisition and overlay settlement use separate access objects.
Integration must explicitly preserve their evidence or independently repeat the
appropriate checks; it must not describe those objects as one existing ledger.
An independent validator replay has its own context and I13b execution scope.

## 3. Independent reconstruction and final validation point

Proposed order, preserving the publication Build boundary:

1. Resolve authenticated policy/identity and acquire authenticated old state;
   admit candidate input and declarations. Retain the same adapter throughout.
2. Inside the authorized execution attempt, acquire declared old accounts under
   the admitted state budget, verify hashes/absence, and execute the engine once.
   Where publication uses a Build callback, actual execution stays **inside**
   Build after its retry/predecessor checks, not in a captured precomputed result.
3. Pass the executed result to `settle_executed`, with no engine argument,
   retaining original admission, state meter and usage-tree context.
4. Complete the relevant private construction transformations. Independently
   derive dictionary changes and physical participants from the **final roots**.
5. Finish coverage checks and compare independently rebuilt artifacts with
   candidate claims in validator replay. Any subsequent root-changing stage
   invalidates this check and requires rechecking its affected artifacts.
6. Keep final publication/activation gates closed. Proof generation and final
   publication-bundle checks are separate obligations, not implied by coverage.

For the current exact-participant profile, define:

- `R`, `W`: bounded read/write declarations decoded from admitted input.
- `O`: authenticated old ShardAccounts root; never an engine-supplied old root.
- `N_rebuilt`: host-built private Native result, starting from `O` and using
  engine-produced effects as inputs to checked host construction, not accepting
  the engine's claimed dictionary as a reconstruction.
- `Delta_rebuilt`: changed keys from `O` versus `N_rebuilt`, comparing whole
  ShardAccount entries, including metadata, insertion and deletion.
- `P_rebuilt`: addresses independently decoded from final physical AccountBlocks,
  checking dictionary key/address and Native transaction/record bindings. Not
  the overlay construction-loop vector, declared writes, or engine update list.

Require both `Delta_rebuilt == W` and `P_rebuilt == W`, with their own checks;
one equality cannot stand in for the other. Old declared hashes/absence must
also have been verified, and required writes performed. A hash-verified declared
read is not a claim that the engine semantically consumed that account.

On validator replay, additionally obtain candidate-derived `N_claimed` from the
authenticated old root and candidate state update, and `P_claimed` from actual
candidate AccountBlocks. This is **not** independent rebuilding merely because
MerkleUpdate application happened in host code. Independently check its delta
and physical coverage, and compare candidate commitments/artifacts with the
separately rebuilt result. Claimed input/effects may be checked against admitted
commitments and the rebuild, but must not supply reconstruction truth. Claimed
caches, participant lists and committed counts are never independent oracles.

These sets concern the wc=2 account transition, not unrelated main-chain ledger
fields. Future profiles with different participant rules need explicit rules;
they cannot silently inherit exact-write-set semantics.

The present replay comparator's explicit field list remains useful, but the
final outbound queues/exports and whole publication generation must still be
checked at the I13e boundary. Do not label that larger comparison as already
implemented by `compare_rebuilt`.

All key-vector bounds come from authenticated policy, before allocation.
`changed_accounts(max_changes)` bounds output cardinality only. Traversed
dictionary cells/augmentation, repeated passes and temporary storage must also
be covered by admitted input/state/output budgets and aggregate work accounting.
No full-shard account-body materialization is proposed as a live shortcut.

## 4. Relationship to I13a: separate initial checks, explicit possible sharing

The current I13a scan returns identity/count/completion, not an independently
decoded participant vector. Its accepted count is not `P`, and its completion
does not certify account-state coverage.

For the initial shape, keep a separate bounded physical-participant extraction
pass over the same immutable AccountBlocks root. Reuse authenticated policy,
root binding, representation-source contract and Native decoding primitives;
do not reuse engine claims or reinterpret I13a's count as coverage. AccountBlock
and transaction validity checks remain necessary, including records in later
accounts. Account/effect indices are record bindings, not batch identities.

A later common decoded-record iterator could feed two independent accumulators
(I13a identity/count and I13c participants), exposing results only after the
whole traversal completes. That is a separate optimization with completeness
controls, not needed for this proposal. Avoid publishing a partially collected
participant set when the identity scanner terminates early.

The ShardAccounts old/new delta is a different traversal and cannot be replaced
by either AccountBlocks pass. Existing generic validator prechecks may eventually
provide reusable decoded facts, but only after preserving their limits, full
completion and provenance; their current bool/log result is not such an API.
Read observation is an execution-time mechanism, not either structural traversal.
Record the additional pass in auxiliary-work accounting instead of calling it free.

## 5. I13d: unread is not unchanged

Blind replacement can leave the old body unread while changing its dictionary
entry. Protection therefore comes from the independent whole-entry delta and
exact coverage against admitted writes and physical participants, plus binding
the candidate's final roots to independently rebuilt roots. It does not come
from a zero read counter.

Equal authenticated subtree commitments may preserve an untouched subtree
without loading its bodies. If a required differing path is unavailable, the
diff is incomplete: it cannot yield a successful coverage certificate. Metadata
changes must remain visible even if the Account body hash is unchanged.

The read observer separately prevents settlement from escaping the acquired
footprint. Declared read-only accounts in `R` but not `W` may legitimately be
read; “not written” must not be turned into a global zero-body-read rule.
Necessary dictionary spines and replacement augmentation are also distinct
from account bodies. Each phase must state its admitted footprint explicitly.

Private complete-state controls can compare untouched ShardAccount bytes after
the observation scope. Partial-proof controls instead show binding to the same
authenticated full-state root, correct rebuilt outputs, and unused bodies still
unloadable. They cannot claim to have serialized unavailable old bodies. The
test's oracle reads must not contaminate the measured execution scope.

For collator proof production, require same-input proof bytes with observation
enabled/disabled. The negative control must bypass an **actual tracked read**;
moving wrappers without losing tracking is not necessarily a failing mutation.

## 6. Proposed typed failure boundary

Classify by the source of the failed fact, not exception name, numeric nonzero,
or a log line. The following are proposed integration verdicts; they are not a
claim that every existing private helper already returns these types.

Implementation review clarification: representation acquisition and ownership of
the checked claim are two independent axes. An acquired candidate view whose
complete delta violates its declarations proves CandidateInvalid, not a local
failure. Missing/pruned acquired content instead remains LocalUnavailable.
Local reconstruction artifacts and authenticated old state are distinct from
candidate claims even when all three are represented by acquired cells.

| Failed fact / stage | Verdict | Required typed evidence |
| --- | --- | --- |
| Candidate declarations malformed, exceed authenticated bound, or disagree with successfully acquired old hash/absence | CandidateInvalid | Completed declaration/old-value comparison with a specific reason |
| Complete candidate dictionary delta differs from declared writes | CandidateInvalid | Complete delta result and changed-key mismatch reason |
| Complete candidate physical participant set differs from writes; malformed/badly bound received Native records | CandidateInvalid | Complete physical decode or explicit received-format failure, distinct from delta mismatch |
| Candidate claims differ from independently rebuilt artifacts, after required acquisition completed | CandidateInvalid | Typed artifact-comparison mismatch, identifying the component |
| Required locally acquired old/proof-view content unavailable, pruned or unloadable | LocalUnavailable | Acquisition failure carrying representation source and read stage; no “hash mismatch” fallback |
| Successfully acquired authenticated old state violates its own format/per-account invariant | Local failure family, preserving AuthenticatedStateCorrupt where established | Existing specific authenticated-state failure, not reclassified as a candidate error |
| Received candidate representation violates its admission rules, including prohibited pruning | CandidateInvalid | Explicit ReceivedCandidate provenance and format/level failure |
| Same shape occurs in an acquired/virtualized view | LocalUnavailable | Explicit AcquiredView provenance; cell level alone never selects the verdict |
| Aggregate candidate-driven traversal exceeds an authenticated budget | CandidateInvalid | Checked budget-exceeded result before additional allocation/work; not bad_alloc |
| Actual allocation/storage/backend unavailability | LocalUnavailable | Typed local failure; not used for a candidate budget violation |
| Host-built artifact violates its own construction contract; wrong adapter, missing meter, expired tree, or settlement escapes admitted footprint | LocalUnavailable | Local construction/lifetime/read-footprint reason, not a claim about candidate bytes |
| Engine reports a proof/semantic validation failure | Preserve the established typed source verdict | No inference from an untyped backend error or `effects.usage` |

Two adapters still need explicit design work before live use:

1. `WorkchainAccountAccess` and `changed_accounts` have message-only errors.
   `scan_diff` touches old and new sides and can throw generic VmError. Preserve
   side/acquisition provenance at the read boundary or pre-acquire bounded inputs
   with that provenance; return typed completion/mismatch/unavailable outcomes.
   Do not translate a blanket catch into candidate invalidity or local failure
   and call classification complete. An unclassified internal result is a
   boundary-contract failure, not evidence about the candidate.
2. A forbidden `WorkchainAccountReadView::read` currently leaves an untyped
   sticky error. A candidate-derived missing access declaration must be proven
   as such by semantic validation; an engine violating the supplied interface
   is a local contract failure. The same message cannot establish which occurred.
   The live adapter must retain that distinction rather than silently assigning
   every view error to either bucket. This is an explicit review point.

Keep mismatch reasons distinct so tests can isolate delta, participants,
old-value and read-footprint checks. A partial scan must carry no success
certificate usable by `finish` or count comparison. Helper callers check
`is_error()`/typed variants, never `code != 0`.

At the actor boundary, assertions consume the final typed result: collator
`Result<BlockCandidate>`, validator's rejection/local-failure outcome. Validator
logs can disagree with the terminal category and are not an oracle. Closed
configuration controls use the single shared activation helper; registration
failure is not activation rejection. They also require zero transactions and
no candidate export. No new capability authorization is implied.

## 7. Controls required after approval

Retain existing private controls as historical evidence; new integration claims
need controls on their final source and actual call path.

- Positive complete reconstruction: accepted result exposes independently
  decoded participants and actual delta equal to declared writes. A read-only
  declaration is also exercised without inventing a write requirement.
- Isolate delta mismatch and physical-participant mismatch: keep the other set
  correct, with distinguishable typed reasons. Include a later account so early
  traversal completion cannot pass.
- Blind write: old-body read count remains zero, but actual delta contains the
  replaced key and rejects undeclared change. Also exercise metadata-only
  change, insertion and deletion. Removing delta coverage must break its own
  assertion, not merely a later generic root comparison.
- Available old root with wrong declared commitment rejects; unavailable acquired
  root abstains. The same pruned representation under explicit received/acquired
  sources produces different prescribed outcomes, not a false hash mismatch.
- State budget and participant/key-vector bounds reject before extra work or
  allocation; missing content yields incomplete, not partial success.
- Observe real allowed reads positively and prohibited reads negatively; remove
  the observer and bypass an actual UsageCell read in separate controls. A caught
  observer exception must still leave a sticky failure checked before success.
- Preserve same-input block-state proof bytes with observation on/off; bypass
  one actual proof-tracked read to make that comparison fail. Oracle reads stay
  outside the measured scope.
- Tamper a final artifact after an earlier successful audit: final validation
  must catch it. Candidate tampering and local reconstruction-contract defects
  have separate typed-source expectations.
- Retain the real engine-method entry counter, same-adapter identity observation,
  and settlement-only no-engine shape. Independent validator replay is a new
  scope, not a second call in the collator's scope.
- Every enabled live fixture is paired with the closed configuration through the
  same real entrance and shared activation classifier, using final typed results.

Mutation evidence must identify which check failed, compile each behavioral
mutant, restore exact source bytes, and explicitly rebuild every executed target
including indirect tools. Private tests must be registered when opted in; their
manual workflow remains separate from ordinary regression. No test execution or
new acceptance claim is attached to this document-only proposal.

## 8. Review and implementation sequence

First review this lifetime/dataflow/classification shape, especially the two
untyped-boundary gaps above. Then implement bounded independent participant
extraction and typed coverage/acquisition adapters with private controls, without
changing the live files owned by the other workstream. Reuse existing algorithms
where their contracts suffice rather than building parallel overlay engines.

Live integration follows legal authenticated input availability and the execution
seam. It must retain the existing state-proof tracking and final closed gate,
audit all intervening early refusals, and establish real typed outcomes before
claiming I13c or I13d satisfied. Neither this document nor private reconstruction
alone changes their live acceptance status.
