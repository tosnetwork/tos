# Privacy workchain implementation progress

Branch: `feature/uno-privacy-workchain-v1`.

Design baseline: `memo@0c3fc8d0:TOS_UNO_PRIVACY_WORKCHAIN_V1.md`.
Base node revision: `5a6145cce`.

Artifact retention correction (2026-09-06): successful Counter fixture directories
are now removed automatically. Most legacy paths cited below were reclaimed after
archiving their top-level diagnostics; they are historical run identifiers, not
promises of retained databases. See [retention policy](counter-fixture-retention.md)
and the cleanup/revalidation entry at the end of this document.

## Implemented

Current sequencing (2026-09-06): further M3 expansion is paused for M1's
real-manager authenticated block/state acquisition, receiving-side batch replay,
and non-fake committee-consensus acceptance. A stable M3 state shape is not a
prerequisite for beginning these checks. Transport component results below do
not constitute this trust-path acceptance.

- Immutable block input/result interface and side-effect-free replay comparison.
- Engine-result commitments cover engine state, outbound messages, actions,
  receipts, events, data availability and resource accounting. The synthetic
  transaction and final shard wrapper are host outputs, not engine outputs.
- Counter fixture tests correct execution, input preservation, result field
  mutations, resource mutations, missing finality context and overflow.
- The Counter engine is shared in `crypto/test/workchain-counter-engine.h` by
  unit tests and the manual disk-backed collator tool. `test-tos-collator
  --counter-increment <uint64> -w 2 ...` explicitly registers it only in that test
  process and passes the candidate through the disk manager to real collation.
  `--counter-send-increment <uint64>` additionally supplies two native outgoing
  requests in the public candidate; the shared test engine returns these effects.
  The existing disk-manager flow then validates the candidate and writes it.
  Production startup does not include/register this fixture. The admission CTest
  checks wrong-shard rejection and full uint64 parsing followed by missing-config
  rejection. The separate disk integration test generates and exercises matching
  MC/shard states in a fresh database, as described below.
  Removing the tool's workchain guard changes the exact error and fails the
  admission CTest; the guard was restored.
- `test-counter-disk-integration` generates isolated test genesis states on
  global ID -23901, boots the disk manager, collates/validates/persists MC block 1
  to register workchain shards, then collates/validates/persists Counter block 1.
  The Counter executor has 1000 native operating atoms; other genesis accounts
  remain unfunded. This is not a private asset or Reserve allocation.
  Fresh processes reopen the same database for each subsequent candidate.
  Increment `UINT64_MAX - 41` is rejected, while `UINT64_MAX - 42` succeeds as
  Counter block 3 after a zero-increment message batch at block 2, proving the
  restored prior value is exactly 42. Increment 1 from block 3 then overflows.
  Rejected runs must not report a persisted block.
  The initial value is 40 and the first increment is 2. Test logs and databases
  remain under unique `build/counter-integration-*` directories for inspection.
- The disk tool can export a validated candidate and import it without collation,
  using the existing native `db_candidate` archive format (block ID, creator,
  complete block bytes and collated data). The integration test snapshots only
  the MC-bootstrap database into a peer directory before producing Counter block 1.
  The peer imports the exported candidate, checks the exact persisted block ID,
  then restarts for the 42/MAX boundary checks. Its CLI increment is deliberately
  zero: the imported transition must recover the actual candidate from block state.
  This tests independent database replay and persistence, not network transport.
  Wrong-shard and malformed archive imports are rejected before the valid import.
  Disabling import dispatch falls back to collation and fails the integration
  test's required import marker; the import branch was restored.
- The disk manager now uses the existing queue-proof importer in local-only
  mode instead of an unreachable neighbor-proof callback. MC bootstrap exercises
  this callback with genuine workchain zerostates, not fabricated empty proofs.
- This harness uses real Collator, ValidateQuery, AccountBlock/shard wrapping and
  database persistence, but fake block-signature acceptance. It is not a live
  committee, network synchronization, authenticated bridge or production audit.
- Live-path mutation checks disable batch creation in the collator and block
  replay selection in the validator. The integration test fails respectively on
  a missing executor AccountBlock and account-scope rejection of the batch.
  Both production paths were restored before the final passing run.
- Counter execution now reads a canonical `ShardStateUnsplit` and augmented
  `ShardAccounts` dictionary rather than treating a bare integer as a shard.
  `extract_workchain_engine_state` checks workchain/shard identity, absence of
  splitting, exactly the designated executor account, dictionary augmentation,
  account address/workchain consistency, and active non-rewritten state data.
  It reuses native `Account::unpack` on a local object without publishing state.
  Tests cover BoC restoration, wrong workchain/address, split flags/prefix,
  missing/extra executor accounts, inactive accounts and malformed roots.
- Removing the unsplit/workchain check accepts a wrong shard and fails the test.
  Removing the dictionary-key check accepts a leaf stored under a different key
  despite a matching embedded account address, and fails the test. Both guards
  were restored. The extractor assumes the caller authenticated the shard root;
  it does not establish finality or validate unrelated queue/value-flow state.
- Mutation check: temporarily removing cell hash comparison makes
  `RejectEveryResultMutation` fail at its rejection assertion. Comparison restored.
- Separate block-engine registration/configuration resolution in the host
  registry, with explicit scope lookup, duplicate-key rejection and null-config
  rejection. Account resolution rejects block engines before account policy use.
- Block engines must resolve an explicit executor address and nonzero wire-byte,
  verification-unit and written-cell limits from their validated configuration.
  `execute_resolved_workchain_block` checks input completeness, the configured
  singleton identity and all result resource counters. Its state-replay counterpart
  uses the same execution wrapper and derives identity from the resolved policy.
  Counter tests cover exact/under/over limits, absent limits, wrong executor
  identity and rejection of an otherwise valid persisted batch above its limit.
  Removing the resource check accepts an over-limit persisted batch and fails its
  rejection assertion; the check was restored. These are post-execution checks
  over deterministic engine metrics, not a substitute for cheap pre-verification
  admission limits or native storage limits. Live entry points are exercised by
  the disk fixture; production startup still registers no block engine.
- Registered Counter replay and scope/configuration tests pass; removing the
  account-scope guard causes the exact-error assertion to fail. Guard restored.
- `test-workchain-block` (twenty-two cases) and the full `validator-engine` target build
  pass with the existing Release/clang-21 build. CTest runs the new target.
- Canonical `WorkchainBlockResult` v2 and `WorkchainBlockOutputs` TL-B envelopes
  carry all six engine-effect references and three uint64 resource counters. The
  result root is exactly 224 bits/three references; its outputs child is exactly
  32 bits/four references. Both envelopes require ordinary cells and fixed version
  tags. Result v2 supersedes the unactivated development v1 envelope and rejects
  its tag. Payload interpretation remains the resolved engine's responsibility.
- Serialized-result replay decodes this envelope before independently executing
  and comparing every output. BoC round-trip, distinct field preservation,
  uint64 boundaries, generated TL-B validation, extra bits/missing references,
  wrong tags and special-cell rejection are covered by two additional tests.
- Mutation checks: relaxing the exact root bit count makes the rejection test
  fail; swapping receipt/event serialization makes round-trip replay fail.
  Both mutations were restored.
- Synthetic `trans_workchain_batch_v2$1001` description: two 256-bit
  input/effects commitments, three uint64 resource counters and a Maybe inbox,
  exactly 709 bits with zero or one reference. Both transaction parsers
  recognize it, including transaction-wrapper validation and storage-fee
  extraction (no native storage phase in this descriptor).
- Account transaction replay and the account emulator explicitly check execution
  scope. A syntactically valid batch transaction is rejected by the emulator
  before changing the account. A test invokes that real emulator entry point,
  checks the exact scope error and verifies unchanged account time.
- The native `Transaction` now has a staged block-batch type, reusing native
  account state-limit checks, storage statistics, serialization, commit and
  `AccountBlock` creation. Preparation checks the full prior account wrapper,
  previous transaction link and shard time, and derives the batch description
  from the supplied input/effects. Commit remains a separate step.
- `prepare_resolved_workchain_batch_transaction` executes under the resolved
  identity/resource policy, stages and serializes a native transaction without
  committing. Tests check independent replay, unchanged original account and
  transaction list, wrong executor, a requested LT below the prior account end,
  and resource-limit rejection. `Collator::create_workchain_batch_transaction`
  uses this helper, native size/storage estimates, account commit and LT/statistics
  updates. `Collator::do_collate_inner` now selects this path for block execution
  using `CollateParams::workchain_block_candidate`, bypasses account transaction
  scheduling, and then joins native AccountBlock/shard/block serialization.
  The supplied candidate is untrusted engine data, not configuration or finality.
  Account collation rejects unexpected candidates; block collation requires one.
  Removing candidate/scope matching accepts a missing block candidate and fails
  the rejection assertion; the check was restored.
  This branch still rejects split/merge; incoming messages to its configured
  executor are collected for the batch through native queue processing.
  Persisted outbound queues, dispatch queue advancement and native dequeue
  descriptors from the existing cleanup pass are supported. Non-bouncing Native
  delivery and processed-upto-driven cleanup now have disk integration evidence.
  The default registry still has no block engine; automatic candidate production
  remains pending. The disk fixture tests outbound native settlement end to end.
  Removing the exact staging-LT check silently advances an invalid requested LT
  and fails the rejection test; the check was restored.
- State-only batch round-trip tests execute 40 -> 42 from a native shard,
  serialize the synthetic transaction, independently replay its description,
  commit the account, validate the resulting `AccountBlock`, rebuild the shard
  account dictionary and restore its BoC to read 42. Native balance remains zero;
  transaction LT is 10 and the new account end LT is 11.
- Without explicit native message configuration the wrapper still rejects
  nonempty or malformed outbound-message maps. It rejects mixed account phases
  and externally altered Native value before preparation. Empty engine outbound
  messages use the one-bit empty HashmapE encoding. Size-limit failure does
  not authorize serialization; changing staged engine data also rejects it.
- Transaction-level outbound settlement now accepts ordered, contiguous
  `HashmapE 15 ^MessageRelaxed` internal requests when supplied native pricing and
  destination-workchain configuration. It calls the existing native send processor
  with fixed mode 1: exact attached value, fees paid separately, no failure skipping,
  balance draining or account deletion. It does not fabricate a compute phase.
  Requests are engine commitments; finalized messages, fees, balance and LT are
  host outputs. The account balance used here must be an independent operating
  budget, not Reserve backing. No Reserve or private-fee accounting is implemented
  by this helper.
- All outgoing messages are staged locally before accepting engine state. A later
  send failure, insufficient funds, bad ordering, message limits or LT overflow
  reject preparation without publishing earlier messages or changing the account.
  Serialization checks staged balance, fees, messages and end LT against tampering.
  Plain transaction/state replay accepts the same host-supplied pricing and
  reconstructs native settlement. Registry staging and replay now carry the same
  authenticated native action configuration through to this helper.
- The funded Counter unit fixture starts with 1000 operating atoms. Two messages
  each carry 100 and cost 100 forwarding atoms, leaving 600; 100 fee atoms are
  collected locally and 100 remain in the messages. Tests check source, amount,
  forwarding fee and LT, uncommitted account preservation, all-or-nothing failure,
  serialization tampering and independent replay. Changing replay prices fails the
  complete transaction hash comparison. This is not a bridge integration test.
- Mutation checks remove the operating-balance debit (test observes 1000 rather
  than 600) and remove the contiguous-index check (the rejection test accepts a
  map starting at index 1). Both mutations fail the funded settlement test and
  are restored before the passing verification run.
- Live batch collation registers normalized outputs with the native message
  scheduler, then processes them in enqueue-only mode. It supplies origin metadata
  using the executor address and batch LT. No output is re-executed as an ordinary
  account transaction in the batch block. Native queues, descriptors, block value
  flow and shard serialization remain the host's responsibility.
- Before creating a new batch the collator advances the existing native dispatch
  queue. Deferred outputs are processed in enqueue-only mode with their original
  payload, funding and origin metadata. The batch's requested LT is strictly after
  the executor's latest deferred emission LT, with an exhaustion check. Validator
  block replay admits only `msg_import_deferred_tr` host transit entries in InMsg;
  the normal validator verifies their removed DispatchQueue entry, matching
  envelopes, routing and paired OutMsg. No such entry credits the executor or
  substitutes for an authenticated engine system input.
- Validator batch replay recomputes messages and fees from authenticated pricing.
  Afterwards it shares the existing account outbound-message checks: every output
  must have a permitted OutMsg record with the right source transaction and origin
  metadata, and obey deferred-message ordering. The normal OutMsg/queue checks
  still verify the reverse transaction reference and queue state update. Native
  incoming queue consumption now builds the batch inbox; deferred host transit
  does not execute a recipient account in this block.
- The disk test now sends two messages carrying 100 atoms each to workchain 0.
  Fixture forwarding prices charge 100 per message: 33 collected locally and 67
  retained for forwarding. Block 1 asserts 1000 -> 600 balance, 334 exported, 66
  collected. The disk manager explicitly sets the test block collator's defer
  threshold to 1, so one output enters OutMsgQueue and one enters DispatchQueue.
  An independent database imports this block. After restart block 2 moves the old
  deferred message to OutMsgQueue and sends another pair (600 -> 200, OutMsgQueue
  1 -> 3, another output deferred). Its host transit imports 167 and exports 167;
  with new outputs, exported value is 501 and collected fees remain 66. A third
  pair fails for insufficient budget after local dispatch preparation. The next
  no-output batch still releases the same persisted deferred message (OutMsgQueue
  3 -> 4), imports/exports 167, and preserves executor balance 200. Tests assert
  both later batches have LT after deferred emission. This tests outgoing value flow,
  deferred progress without a second executor charge, and
  failure atomicity across restart. The delivery extension below exercises the
  receiving chain; bridge finality and private withdrawals remain unimplemented.
- Fake acceptance now has an explicit, default-off option to send the generated
  shard top description to the local manager callback. The disk manager enables
  it for shard blocks, allowing the existing `-s` export and `-M` import options
  to carry the native proof-link chain into a subsequent test MC block. Real
  acceptance/signature verification is unchanged. The fake signature semantics
  remain restricted to the existing test acceptance/description-validation paths.
- The test transfers are non-bouncing internal messages to the uninitialized
  Native address 0:...01. Counter block 3 exports its top description; test MC
  block 2 registers it. Native block 1 then executes the four ordinary receiving
  transactions: 668 atoms imported, 400 retained in accounts, 268 collected and
  no outgoing messages. Its top description is registered by MC block 3, which
  imports the 268 fees. Counter block 4 subsequently verifies neighbor queue
  proofs/processed-upto, removes all four delivered messages (queue 4 -> 0), and
  retains operating balance 200 with no new fees or value movement. This proves
  one-way native delivery and source queue cleanup, not UNO inbound execution,
  bouncing/refund handling, Reserve settlement or real committee finality.
- Delivery mutation checks disable the disk fake-accept description-send option
  (the required Counter top-description file is absent) and reinstate rejection
  of nonempty outgoing descriptors at batch admission (Counter block 4 cannot
  accept its native dequeue records). Both fail the integration test and are
  restored before final verification.
- Deferred-path mutation checks skip the batch dispatch pass (block 2 lacks the
  required 167-atom transit flow) and ignore the executor's emitted LT (batch LT
  collides with emitted LT 3000001). The integration assertions fail in both cases;
  both mutations are restored before verification.
- Live outbound mutation checks omit batch output registration (collation rejects
  unbalanced block value flow) and change validator-expected metadata depth from
  0 to 1 (shared outbound checking rejects mismatched metadata). Both fail the
  disk integration test at block 1 and are restored before final verification.
- Mutation checks: disabling batch serialization fails the commit/reload test;
  removing the unsettled-message rejection fails the exact rejection test.
  Both changes were restored.
- `replay_workchain_batch_transaction` independently reloads the prior account,
  re-executes the engine, reconstructs the complete native batch transaction and
  compares its hash, returning the reconstructed Account without committing.
  Host-supplied executor identity, LT, timestamp and serialization configuration
  are separate from the untrusted transaction. Tests mutate the prior transaction
  hash/LT, timestamp/LT, fees, original account status, account update hashes and
  executor address while preserving valid transaction syntax.
- Removing the complete-transaction hash comparison accepts a forged wrapper
  and fails the rejection assertion. The comparison was restored. This helper
  is not yet called by the live validator's block-execution path.
- Executor account data now uses `WorkchainExecutorState` (`57424531`): engine
  state plus an optional latest `WorkchainBatchWitness` (`57425731`) containing
  the candidate and canonical effects envelope. Initial state can omit the
  witness; every prepared batch writes one. The codec checks fixed cell shapes,
  complete candidate/effects pairs and equality of engine state with the effects.
- Native account serialization and storage limits now include the persisted
  candidate/effects. Tests restore the resulting shard BoC, recover the witness
  from the account and use its candidate to independently replay the original
  transaction, obtaining the same Account hash. Only the current witness is
  retained in current state; historical availability still requires block/state
  archive retention and live synchronization acceptance tests.
  Here witness means public verification data (candidate/proofs/ciphertexts),
  never wallet secrets or private proving inputs.
- Removing the persisted engine/effects equality check accepts an inconsistent
  witness and fails its rejection assertion. The check was restored.
- `replay_workchain_batch_state` recovers public candidate data from the claimed
  singleton executor state. Its context contains previous shard, configuration,
  finality and an optional authenticated inbound root supplied by the host. It checks the final transaction link,
  independently reconstructs the transaction and compares the complete Account,
  including the persisted effects, without publishing state. BoC recovery tests
  exercise this entry and reject altered transaction links, receipts and candidates.
  Removing the final Account comparison accepts altered stored receipts and makes
  the rejection assertion fail; the comparison was restored.
  This is an account/witness replay helper, not full shard validation: authenticated
  context, block headers, queues, value flow and live dispatch remain host duties.
- Mutation checks for the descriptor remove handwritten validation support,
  relax its exact bit length, and remove the real account-emulator scope call.
  Each produces the expected test failure; all three changes were restored.
- Batch inbound representation: `WorkchainBatchInbound` tag `57494e31`, nonzero uint15 count,
  `HashmapE 256 ^MsgEnvelope` keyed by original message hash. Decoding validates
  count, key/message identity, complete internal envelopes and produces deterministic
  (emitted LT, message hash) order, using created LT when emitted LT is absent.
  Different producer insertion orders produce the same dictionary; the same message
  cannot be included twice with different envelopes/emission times. UNO protocol
  source-locator ordering is an engine responsibility, not replaced by this host order.
- Inbound batches use descriptor tag `1001` with the original two commitments and
  counters plus a Maybe inbound-list reference. Unactivated tag `1000` has been
  removed; no-inbound batches also use `1001` with the absent-inbox bit. The old
  no-inbound input encoding remains unchanged. Both generated and handwritten TL-B
  parsing recognize the new tag; account-compute scope rejects it. Replay binds
  the inbound root in the authenticated input hash and separately compares the
  description's exposed list against the host list, preventing forged membership
  references from being paired with otherwise correct input/effect hashes.
- Native `is_transaction_in_msg` supports multi-message membership for descriptor
  `1001` through direct hash-dictionary lookup, without scanning the whole batch
  for each message. A v2 batch may not also claim an ordinary single input in r1.
  This lookup is not transaction validation, delivery authentication or acceptance;
  complete list validation and independent replay remain mandatory.
- Tests cover BoC round-trip, insertion-order invariance, emitted-LT ordering,
  equal-LT hash tie-breaking, duplicate original messages, count/key mismatches,
  malformed envelopes, input/list commitment substitution and positive/negative
  native membership. Native batch preparation now stages incoming value credit;
  collator queue consumption and self-queue inbound value-flow tests are integrated.
- Inbound mutation checks omit the exposed-list comparison during replay (a
  substituted membership list is accepted) and omit dictionary-key/message-hash
  checking (a falsely indexed envelope is accepted). Each fails its targeted
  assertion; both mutations are restored before final verification.

The engine result now contains `new_engine_state`, not a final shard state or
synthetic transaction. This removes the previous circular interface: a final
shard account dictionary contains the transaction hash, so it cannot be an
input to that same transaction's commitment.

`input_hash` is the Cell hash of `WorkchainBlockInput` v1 (tag `57424931`,
references in order: previous shard state, candidate, configuration, finality).
With inbound messages it uses v2 tag `57424932`, references previous shard,
candidate, context and inbound list. Context tag `57424332` binds configuration
and finality together, keeping the input within the four-reference Cell limit.
`effects_hash` is the Cell hash of `WorkchainBlockResult` v2 (tag `57425232`).
`make_workchain_batch_description` constructs both commitments; batch replay
checks the input commitment before executing, independently computes the effects
and checks their commitment plus explicit resource counters. Engine selection
and authentication of configuration/finality are still the host's responsibility.
These use the native Cell representation hash, not the user transaction-ID hash.
Native transaction/account wrapping, witness storage and transaction-level outbound
settlement are implemented. Live full-shard acceptance, outbound/deferred queue
persistence and outgoing block value flow are tested. Incoming account messages
remain unimplemented. Non-bouncing receiving-chain execution and delivered queue
cleanup have end-to-end disk evidence with fake consensus signatures.

Commitment tests cover serialized-description replay, all four input references,
all six engine-effect references, missing cells and all three resource counters.
Removing the effect-hash comparison makes the effect mutation test fail;
removing the pre-execution input-hash check changes the exact rejection and fails
the input test. Both guards were restored.

The result envelope is not a `TransactionDescr` constructor or a replacement
for native `Transaction` validation. The host inserts the synthetic batch transaction
into AccountBlock/block-extra and persists the result witness in executor data;
outgoing, deferred host and executor self-queue inbound LT/value-flow paths are
tested. Cross-workchain inbox delivery is also covered below; invalid-destination
recovery remains pending.
The effect envelope alone binds output data, while its batch description also
binds input context; neither authenticates the context by itself.

## Next host integration points

- Both `Collator::check_this_shard_mc_info` and
  `ValidateQuery::check_this_shard_mc_info` now use scope-preserving resolution.
  The registry returns an explicit account/block variant and validates descriptor
  identity against the configuration dictionary key. Tests cover both variants,
  masterchain/absent entries, unsplit configuration and mismatched identity.
  Removing the identity guard makes the mismatched-key rejection test fail;
  the guard was restored. Account-only resolution still rejects block engines.
- Both configuration paths now preserve execution scope. Required-workchain
  validation resolves block engines with their own configuration/resource policy;
  only account engines enter account-policy validation. Tests cover explicitly
  registered Counter acceptance, invalid split configuration, unregistered required
  engines, non-required remote engines and the default TVM account path. The default
  registry contains no block engine and advertised capabilities remain unchanged.
  Reinstating account-only rejection in required-workchain validation fails the
  registered Counter acceptance test; scoped validation was restored.
- `ValidateQuery::check_transactions` now has a separate block branch,
  requiring exactly the configured executor AccountBlock, rejecting native
  inbound message descriptors, and replaying from the previous shard,
  selected MC configuration root and MC state root. The helper validates the
  AccountBlock identity, augmented transaction dictionary, exactly one batch and
  matching AccountBlock/transaction state updates before persisted-state replay.
  Tests exercise the helper on a real serialized AccountBlock and reject changed
  identity, state updates and multiple transactions. Removing the AccountBlock
  state-update comparison accepts a forged wrapper and fails its rejection test;
  the comparison was restored. The disk integration test additionally exercises
  this branch with full Counter candidate blocks, not only the replay helper.
- The collator block path now bypasses per-account processing but still must supply
  canonical synthetic transactions to block-extra, account/state-update,
  message-queue and value-flow verification. Bypassing only scope checks is
  insufficient and would not constitute M1.
- `CheckAccountTxs::check_one_transaction` still reconstructs a per-account
  `Transaction` after its scope check. Block execution needs a separate host
  path; its account-scope rejection remains unchanged.

## Remaining requirements

This is partial M1, not an enabled privacy workchain. Counter collation, outgoing
native settlement, independent database replay and disk restart have end-to-end
test evidence. Both block branches still require an explicitly registered engine;
incoming account message settlement, return/bounce handling, distributed
consensus and complete node-to-node synchronization remain unverified. The TCP
snapshot fixture below now exercises remote state acquisition, but not either
of those end-to-end properties.
The disk harness cannot download and uses fake signature acceptance: it proves
restart and file-import replay, not network synchronization. Live synchronization
integration was not started by those tests; the routing work below is its first
network-layer change, not completed synchronization acceptance.
Context cells are not authentication proofs by themselves.

1. Authenticate block configuration/finality and resolve execution scope through
   the descriptor registry; integrate persisted witnesses with live block processing.
2. Integrate real collate/validate, message queues, value flow, resource limits,
   atomic publication, capability gating, restart and state synchronization.
3. Lock the payment proof dependency, circuit/VK, signature and encryption
   profiles; implement the complete FFI bundle verification and test vectors.
4. Implement note state, private transfers and local wallet proving/scanning.
5. Implement reserve-backed genesis, wide accounting, deposit claim/cancellation,
   withdrawal terminal payout, acknowledgement and reserved refund bundles.
6. Implement private fee collection/distribution, operating-budget isolation,
   authenticated checkpoints, upgrades and incident controls.
7. Run integration, mutation, model, recovery, multi-node and performance tests;
   meet the specification's activation and independent audit gates.

No production configuration activation or value-bearing genesis is enabled.

BlockTransition host activation now requires both ConfigParam 8 version >= 15
and the separate `capBlockTransition` bit (1024). Version 15 is the host's
existing supported baseline, not an assertion that older version-15 binaries
understand batches. The new bit is the opt-in boundary; activation still requires
a coordinated validator upgrade. Collator and validator advertise support for
this host capability, but the default engine registry remains TVM-only.
Only the Counter disk-test genesis enables the bit. This does not activate UNO.

The shared registry `resolve_block` gate precedes engine configuration and is
used by scoped resolution in collator configuration/construction and validator
configuration/transaction replay. Ordinary AccountCompute validation still
rejects batch descriptors by scope. Generated TL-B validation remains structural,
not permission to execute. Low-level codec/replay helpers are not standalone
consensus acceptance APIs. Broader import/proof/API call-site audit and independent
candidate-import negative activation tests remain outstanding.

Two real disk-node activation tests now generate isolated masterchain genesis
configurations: version 15 without the host capability, and version 14 with it.
Each bootstraps the masterchain successfully, registers the Counter engine, then
requires workchain-2 collation to fail with no batch staging or saved block.
The existing activated integration remains the positive control. Removing the
shared registry activation gate makes both negative tests incorrectly produce a
block (exit 0 instead of 2); restoring it makes both reject again. Generated
fixture variants verify their source marker before substitution so fixture drift
cannot silently leave activation enabled.

`RegistryRequiresConsensusActivation` uses real decoded ConfigParam 8 cells and
checks both sides of the version boundary, the capability on/off combinations,
and unavailable configuration. Omitting the registry gate makes resolution
incorrectly succeed and the test fail; the gate was restored. Network
`tosNode.capabilities.flags` is a different namespace and is not used as a
consensus activation signal; its engine-advertisement policy remains unfinished.

Execution-scope classification now switches on generated TransactionDescr
constructor enums through `check_tag`, without a second production wire-tag
boundary table. `get_tag` alone is insufficient: the generated selector can map
unassigned prefixes to a candidate constructor. The exhaustive four-bit-prefix
test checks every ordinary constructor, both tick/tock fourth-bit values, the
batch format, and rejection of unassigned prefixes in both scopes.
Replacing `check_tag` with `get_tag` makes the test fail because an unassigned
prefix is accepted as BlockTransition; the checked classifier was restored.

Review follow-up: `UnmatchedBatchInputDoesNotInvokeEngine` adds a successful
matching-input control and checks zero engine invocations for each mismatched
committed input field. Removing the pre-execution input-hash guard makes the
invocation assertion fail (1 instead of 0), independently of rejection wording.
The guard was restored. Earlier exact-message mutation checks demonstrate
diagnostic selection, not this execution-order property. Activation audit remains
required. Batch descriptors now use one format; retired tag 8 is rejected by the
generated parser, all handwritten parser paths, the codec and scope classifier.
Empty inboxes use Maybe=0; a present inbox must remain nonempty and canonical.
This intentionally invalidates development-only batch blocks from older builds.
Mutation verification: reintroducing tag-8 acceptance in handwritten `skip`
makes `RetiredBatchDescriptorRejected` fail at its skip-rejection assertion.
The mutation was removed. The same test checks the empty-inbox batch's native
message-membership behavior; existing tests cover nonempty inbox membership.

Native inbound preparation: the collator now uses a shared batch-start LT
selector that follows the host/deferred LT and every supplied inbox message's
created/emitted LT, while reserving one additional LT for transaction end.
It rejects host/message bounds >= UINT64_MAX-1 before transaction construction.
This does not authenticate delivery or enable native inbox credit. A test covers
host precedence, creation/emission precedence, malformed inboxes and exact
uint64 boundaries. Weakening the limit to reject only UINT64_MAX makes the
UINT64_MAX-1 rejection assertion fail; the correct limit was restored.
Native settlement still must credit only message value to the executor and
retain the native InMsg accounting of remaining forwarding fees, alongside
authenticated queue processing and exactly-once batch membership.

Validator replay now reconstructs its inbox from the native InMsgDescr records
instead of assuming it is absent or trusting the description's claimed list.
Final and deferred-final imports contribute their original envelopes; deferred
transit contributes none. Other import kinds and duplicate final messages reject.
This extraction is structural: the existing earlier `check_in_msg_descr` checks
queue proofs, dictionary keys, routing, fees and transaction backlinks. The
reconstructed canonical root is then passed through WorkchainBlockReplayContext
and compared with the batch input/description commitments. Inbox extraction alone
does not credit value; the transaction settlement layer performs that operation.
The import reconstruction test uses generated-TL-B-valid native records and
checks exact canonical inbox hash, transit-only/empty inputs, duplicates,
malformed inputs and a well-formed unsupported discard. Omitting deferred-final
envelopes makes its canonical-hash assertion fail; the inclusion was restored.

Native batch credit staging now checks version, exact standard destination with
no anycast, IHR-disabled/valid flags, creation/emission time, and native value
encoding. A checked addition builds a temporary balance from message principals
only; remaining forwarding fees stay in native InMsg accounting. Outbound mode-1
settlement spends from that temporary balance. No transaction balance, fee or
output is published until all messages and state limits succeed; the account is
not committed by preparation. This is native executor funding, not UNO reserve
allocation or private Note minting.

Tests cover two incoming 100-atom principals (balance 200, not 334), unchanged
account state, full native wrapper replay, rejection of late input times, a
successful incoming-funded outgoing message with independent replay, and an
insufficient second outgoing message leaving no partial credit/fee/output.
Omitting the credit update makes the balance-200 assertion fail; it was restored.
These are transaction-layer tests; the integration below extends them to native
queue consumption and incoming candidate replay, including cross-workchain funding.

Collator now collects executor-bound neighbor/own-queue deliveries after native
route/key/fee/processed-up-to checks. It commits their canonical inbox to the
batch, then publishes final InMsg records pointing to the serialized transaction.
Own-queue imports reuse native dequeue-immediate OutMsg and queue deletion.
Ordinary/deferred transit remains host-owned and contributes no engine input.
Collection respects native queue stop conditions and the 32767-envelope format
bound. Invalid executor destinations still reject; a live-chain recovery/bounce
policy is required so a protocol-valid wrong-address message cannot stall input
progress. This is an explicit remaining liveness issue, not activation-ready.
The implementation decision is recorded in `workchain-native-ingress-policy.md`:
destination admission must use shared consensus configuration, not the sender's
local engine registry, and activation must reconcile pending foreign queues.

The new self-delivery disk test sends two 100-atom messages, with one deferred,
then reopens nodes to receive them over two batches. Exact balances are
1000 -> 600 -> 700 -> 800; sender fees total 66 and import fees total 134.
The final empty batch preserves 800 with no duplicate input. An independent DB
snapshot imports the first receiving candidate through real ValidateQuery.
Omitting final InMsg publication makes the first receiving block fail native
value-flow conservation (in != out); publication was restored. Consensus
acceptance in this harness still uses the existing fake committee mechanism.

Cross-workchain disk coverage uses a second test-only Counter workchain (3),
with its own 1000-atom operating allocation. Workchain 2 sends two 100-atom
messages and flushes the deferred one; a masterchain checkpoint publishes its
outgoing queue. Workchain 3 imports both through neighbor queue proofs in one
batch: balance 1000 -> 1200, imported 334, collected forwarding fees 134.
An independent DB snapshot validates the exported receiving candidate. After
checkpointing the receiver, the sender removes both messages via native
processed-up-to proofs and preserves balance 600. Another receiving block must
preserve 1200 with no duplicate credit. This exercises different workchain IDs,
not just two processes replaying a self-queue. No production engine registration,
UNO reserve allocation or real committee signatures are introduced by the fixture.
Mutation verification: forcing a neighbor import to be marked as own-queue
delivery makes the cross-workchain receiver attempt an invalid local dequeue
and fail its queue-size invariant. The correct ownership flag was restored.

Shared ingress-policy foundation: the public entry codec uses tag 57495031,
481 bits and one opaque engine-configuration reference. It binds workchain,
engine format/selector/mode, descriptor version and executor address without
registering or executing the destination engine. The descriptor binding check
requires active unsplit execution and matching identity/version/mode. Tests
cover generated TL-B validation, BoC/canonical round trip, independent binding
failures, selector bounds, missing fields, trailing bits and uint64 mode values.
Removing the mode binding makes the mismatch assertion fail; it was restored.
The configuration table and sender filter are described below; activation and
migration gates remain required to address invalid-destination liveness fully.

The shared policy table codec now uses tag 57495431 and HashmapE 32 reference
entries. It preserves deterministic encoding independent of insertion order,
supports an explicit empty table and rejects duplicate IDs, malformed roots and
key/entry identity mismatches. The tests round-trip the table through BoC and
show that a wrong-key fixture passes structural TL-B validation but fails the
semantic decoder. Removing key/identity comparison makes that rejection fail;
the comparison was restored. This codec alone does not fix queue liveness.

Development ConfigParam 84 now carries the shared table. Native configuration
resolution binds its entries to ConfigParam 12 without loading a foreign engine;
the block receiver also checks that its engine's executor matches the public
entry. Global version 15 and capBlockTransition jointly enable lookup; absent
tables fail closed once enabled. Collation/emulation and independent validation
populate the same ActionPhaseConfig destination map. The shared native send and
bounce address path rejects anycast and non-executor destinations for listed
workchains, while unlisted workchains keep native behavior.

The public batch-settlement test sends real MessageRelaxed requests through
native action handling: correct destinations settle, wrong addresses and anycast
fail without publishing outputs or debiting the account, and clearing the policy
restores both legacy destinations. Separately disabling either destination-match
or anycast rejection makes the test fail because the forbidden send succeeds;
both guards were restored. Disk genesis generation includes ConfigParam 84 and
the cross-workchain fixture includes both executor entries.
Verification after restoration: create-state, test-workchain-block,
test-tos-collator and validator-engine build with -j48; all seven targeted CTest
cases pass three consecutive runs (21 executions).

Remaining ingress work includes authenticated wallet coverage and authenticated
activation/queue migration enforcement.
The referenced engine payload is not yet consumed as engine configuration.
This is not production activation and does not implement private notes or reserve
accounting.

Configuration-presence gate: `valid_config_data` now rejects parameter 84 unless
ConfigParam 8 declares version >= 15 and capBlockTransition. This is separate
from choosing whether an engine may execute: an empty table is still a parameter
whose presence requires activation. Predicate tests cover absent parameters,
both version/capability combinations, and missing/malformed version payloads.
Replacing the predicate with unconditional success makes the forbidden-presence
assertion fail; the predicate was restored. The inactive Counter fixtures omit
84 and continue testing engine activation independently.

This does not prove readiness of old validators or implement an authenticated
upgrade transition. The M0 all-validator upgrade ordering remains mandatory.
Full `valid_config_data` coverage now uses two isolated Counter configuration
rejection cases in the disk harness. They retain parameter 84 while respectively
lowering the version or clearing the capability. create-state must reach the
presence gate, fail, and publish no masterchain zerostate. Disabling the rejection
branch in `valid_config_data` (without changing the helper) makes both cases fail
because the complete configurations are accepted. The branch was restored.
The existing activated disk fixtures are the positive controls. These are
same-binary rejection fixtures, not deployment templates or upgrade procedures.
Further evidence must cover the real configuration-update path and mixed-version
binaries; these tests do not prove readiness or that every caller enforces it.

Ingress destination continuity is now checked in the shared configuration-transition
predicate used by collation and independent validation. Existing tables/entries
cannot disappear and an existing executor address cannot change without an
explicit migration rule (none is implemented). Unit tests check unchanged and
additive controls, deletion, and address replacement, including replacement mixed
with unrelated additions. Removing the continuity block makes deletion accepted;
removing only address comparison makes replacement accepted. Both tests fail for
the intended reason and both checks were restored. These are isolated transition
tests, not proof of full valid configurations or successful network upgrades.
New-entry activation, engine configuration transitions, validator readiness and
authenticated queue migration remain required; production activation is not enabled.

Receiver configuration agreement now has direct registry-resolution coverage:
matching policy succeeds; missing/empty/malformed tables, another workchain's
entry, descriptor-version mismatch and executor-address mismatch reject.
The test uses structurally encoded configuration cells and the real Counter
registration path. Removing the receiver's address comparison accepts the wrong
address; removing its descriptor-binding call accepts the wrong version. Each
mutation fails the corresponding status assertion, without matching error text;
both checks were restored. This covers receiver resolution, not sender lookup
without an engine, validator rollout readiness or engine-specific payload use.

Sender lookup now has separate coverage using decoded ConfigParam 12 and 84 cells.
The default registry has no Counter engine, yet the common resolver returns the
configured nonzero executor address. Missing descriptors, descriptor-version
mismatch and missing tables reject; explicit empty tables produce an empty map.
Removing the binding check in the sender resolver makes the version-mismatch
case succeed and its test fail; the check was restored. This proves lookup does
not require foreign-engine registration, not that a Native wallet's invalid send
is handled correctly end to end; that disk scenario remains outstanding.

The Native action/queue path now has an end-to-end disk fixture using an explicitly
unauthenticated test-only sender, not a production wallet. Its external call emits
two 100-atom requests: wrong executor address with send mode 3 (skip error), then
the correct executor with mode 1. Only one message enters the Native queue. An
independent DB validates the exported Native candidate; after a masterchain
checkpoint the Counter receiver imports 167 atoms of value/forwarding fees and
credits exactly 100 (balance 1000 -> 1100, fees 67). Native sending does not
register the Counter engine.

The fixture exposed a disk-tool startup race: external broadcasts were rejected
before the masterchain state was loaded and the tool produced an empty block.
The disk manager now buffers startup messages and parses them with the loaded
configuration's limits before collation; malformed queued input aborts the tool.
Production manager behavior is unchanged. The original empty-queue failure was
observed before the fix. Disabling destination admission subsequently produced
two queued messages instead of one and failed the fixture; admission was restored.
This does not test signing, wallet authorization, bounce/refund modes, or private
UNO issuance. The sender has no authentication and must never hold real funds.

The Native-sender fixture also checkpoints the receiving batch and reopens the
Native sender on its previous tip: the acknowledged outbound queue shrinks from
one entry to zero. A subsequent receiving batch remains at 1100 nanotomi with
no imports or additional credit. Bypassing Native queue cleanup leaves the queue
at one and fails the new cleanup assertion; cleanup was restored. This checks
processed-up-to queue recovery, not withdrawal payout acknowledgements.

Amount terminology follows Native: TOS is the display coin, Tomis the protocol
type, and nanotomi the base unit (1 TOS = 10^9 nanotomi). UNO uses the same base
unit. The design document now makes that scale explicit rather than presenting
10^18 as a parallel example. No wallet-layer legacy identifiers were renamed.

Executor monetary policy is explicit for this host version:
`kWorkchainExecutorIsSpecial=false` names the common extraction/replay choice,
and batch preparation rejects an account with a different special flag before
settlement. This preserves ordinary Native message charges against the operating
balance; it is not a ConfigParam 31 exemption. The batch path has no StoragePhase,
so neither storage-rent collection nor eventual rent freezing follows from that
flag. Persistent tree/nullifier resource funding remains an activation requirement.
The special-account negative test fails when the new guard is bypassed, because
batch preparation succeeds; the guard was restored. Existing fee/value-flow
tests continue to cover nonzero native message charges. This fixed version policy
is not a configurable fee waiver; changes require an explicit protocol revision.

Removed redundant callback key-length checks from inbox decoding, executor
extraction and batch AccountBlock validation. All three dictionaries are
constructed with 256-bit keys, and their traversal APIs pass get_key_bits(),
not a length supplied by a cell. Also removed the workchainInvalid equality
after the negative-workchain check: that sentinel is INT32_MIN. Unique executor,
dictionary-key/address binding, structural validation and full replay remain.
No security coverage is attributed to these unreachable branches and no new
negative test is claimed for their removal.

The queue interface now has a named read-only accessor,
`extract_workchain_native_queue_state(input)`, returning OutMsgQueueInfo directly
from the committed previous shard header. No independent queue field or new wire
format is introduced. It exposes outbound queue, processed-up-to and dispatch
state together; header extraction does not authenticate or traverse those queues.
Native queue proofs, routing, enqueue/dequeue and final queue/value-flow validation
remain host responsibilities. Engines emit outbound requests, never a replacement
native queue. Counter itself does not need to read the queue.

The accessor test compares the exact queue cell, changes only valid queue metadata
and observes a different input commitment, and rejects missing/malformed headers.
Returning the candidate instead of the queue makes the exact-cell assertion fail;
the accessor was restored. The full previous shard was already committed before
this change: this clarifies access and ownership, not a previously missing hash.

Alternate address encoding now has native settlement coverage: a 256-bit addr_var
for the executor is normalized to the exact same complete output message as its
addr_std form, while a wrong executor in addr_var is rejected. Disabling the
normalization makes the valid request fail the native final-message check and
the test's success assertion; normalization was restored. This covers workchain
2's standard-address range, not arbitrary extended workchain IDs or anycast.

Closed a policy/address-range mismatch: public ingress previously accepted any
nonnegative int32 workchain ID, while batch incoming credit requires addr_std's
int8 workchain field. Entry encoding/decoding now restricts this host policy to
0–127. Tests accept both endpoints and reject 128 and INT32_MAX, including raw
entries that pass generated TL-B structural validation. Removing the bound makes
the invalid-ID acceptance assertion fail; it was restored. Engine format remains
independent of workchain ID; this does not remove Extended engine selectors or
change UNO's workchain 2. Future wider addresses need a new policy version.

Complete configuration validation now also resolves the public ingress table
against ConfigParam 12 using the same engine-independent sender resolver. A
structurally valid but semantically mismatched policy can no longer be installed
and then fail only when a later block fetches its action configuration. The new
disk rejection case keeps version/capability enabled and changes only the policy's
descriptor version. create-state rejects it before publishing a zerostate.
Bypassing the added semantic-validation block lets that configuration succeed and
fails the test; the check was restored. This does not prove all-validator readiness
or authorize adding new policies to existing workchains with pending traffic.

Configuration transitions now reject adding a first ingress restriction to an
already listed workchain, whether the old table was absent or explicitly empty.
An old descriptor with admission currently closed does not establish that foreign
queues never held other destinations; the current transition API has no queue
reconciliation proof. No implicit migration override is allowed. Isolated tests
cover both rejection cases, unchanged policy and a newly introduced workchain
as controls. Bypassing this guard accepts the unsafe existing-workchain transition
and fails the assertion; the guard was restored. Fresh-workchain activation,
validator readiness and an authenticated migration protocol remain separate work.

Fresh ingress-policy installation now requires a new descriptor with native
admission closed (`accept_msgs=false`), rather than allowing installation and
opening in the same transition. Isolated transition tests reject an immediately
open descriptor, accept closed installation, and
accept a later opening with unchanged policy. Removing only the admission flag
check makes the immediately-open rejection assertion fail; it was restored.
This establishes ordering only: authenticated validator readiness, zero-state
acceptance and end-to-end configuration-update activation remain unfinished.

Native action settlement now has a closed-admission regression control with a
public executor policy installed: both canonical standard and variable addresses
are rejected while the destination descriptor has `accept_msgs=false`. The test
checks no output message, unchanged transaction principal and unchanged source
account; reopening admission accepts the same destination. Bypassing the native
destination admission check makes the closed case succeed and fails the status
assertion. The check was restored. This exercises the existing settlement gate,
not a new receiver-side ban on consuming messages already committed to queues.

Block-engine configuration resolution now receives the exact `engine_configuration`
Cell from the public ingress entry as an explicit argument. Host activation and
descriptor binding run before the engine callback; the engine must validate its
complete payload format. Counter defines an empty-cell configuration and rejects
payload bits or references. The tests preserve a descriptor-bound null-config
control and now expect invalid split descriptors to fail in the earlier host
binding check. Replacing the supplied payload with an empty cell makes the
nonempty-payload rejection test fail; the actual payload forwarding was restored.
This leaves engine-specific configuration parsing out of Native sender lookup.
It does not define the UNO configuration schema or authorize its future changes.

The disk harness now also installs a structurally valid public ingress entry
whose Counter payload contains an unsupported bit. Generic configuration
validation and a Native masterchain bootstrap succeed without interpreting the
foreign payload; Counter collation must then reject before batch staging and
without reporting a persisted block. Substituting an empty payload at the host
callback makes the same test produce and persist a workchain block (exit 0 rather
than the required exit 2), so the negative test fails for the intended reason.
The substitution was restored. This is same-binary mock-engine evidence, not a
deployment genesis or independent validation of an adversarial imported block.

Started the new UNO monetary core with `uno/core/amount.h`, a value type using
the candidate unsigned 128-bit accounting range in nanotomi. It reuses the
platform wide-integer implementation, provides checked addition/subtraction and
explicit Note u64 / symmetric bundle i64 narrowing. It does not restore the old
u64 aggregate counters or mining state. The four rejection guards were separately
bypassed: overflow, underflow, oversized Note value and oversized bundle magnitude
each made its own assertion fail; all guards were restored. Boundary controls
exercise carry/borrow across 64 bits and the 10^17 nanotomi allocation magnitude.
This is not an allocation authorization, proof implementation, state codec or
registered engine. Final amount width/codec still requires the Native monetary
authority decision; multiplication and the N/F/W transition layer remain work.

The first N/F/W accounting transitions now use those checked amounts: transfer
fee moves N to F; withdrawal preparation debits principal plus fee from N and
credits F/W separately; Paid Ack removes W without creating Notes; refund moves
only principal from W to N. Each function returns a new value and leaves input
untouched, including failures after an earlier calculation succeeded. Tests
check exact balances, principal-only refunds, wide-pool borrow and isolated
overflow/underflow at every arithmetic site. Skipping each transition result or
individual checked step makes the corresponding balance/rejection assertion
fail; swallowing the principal-plus-fee overflow was also detected. All temporary
mutations were restored. These are accounting calculations, not authorization:
receipt finality, permanent IDs/tombstones, proof verification, refund reservation
consumption and atomic state/queue commits remain required before engine use.
Shield claims, fee distribution and authenticated R/P/D reconciliation are not
implemented by this layer yet.

Accounting now also calculates ShieldClaim's N credit and the two fee-pool
distribution branches: private rewards move F to N, Native rewards move F to W
and require the later payout state machine. Exact-balance, zero and wide-borrow
controls cover these paths. Isolated tests reject N/W overflow and insufficient
F without changing the input. Replacing each of the three results with the old
state, and bypassing each of the five checked arithmetic sites, separately made
the matching assertion fail; all mutations were restored. ShieldClaim here is
not a runtime mint entry point: authenticated deposit consumption, the matching
D decrease at a reconciled cut, output bundle verification and permanent IDs
are still required outside these calculations. Fee distribution authorization,
unique distribution IDs and authenticated R/P/D reconciliation remain unfinished.

Wide amounts now include checked multiplication, with a pre-multiplication
maximum/divisor bound and explicit zero handling. Tests cover both zero operand
positions, the maximum times one, cross-word products, high-word operands and
overflow in both operand orders. Disabling the bound accepts an overflowing
product, replacing multiplication with the input loses the carry, and removing
zero handling reaches the underlying division-by-zero check; each mutation makes
the test fail and was restored. No supply scale, fee schedule or wire encoding
is inferred from this arithmetic operation.

Added aggregate refund leaf budgeting for the depth-32 tree. Valid counts obey
`next + reserved <= 2^32`; `2^32` represents exhaustion, never an insertion index.
Ordinary appends cannot consume reserved leaves. Preparation returns a new budget
only when both main outputs and refund reservation fit; refund consumes its
reservation while appending, and Paid releases capacity without appending.
Counts include dummy leaves, which must be supplied from verified bundle data.
Boundary tests fill all unreserved space and still append the reserved refund,
reject over-capacity/underflow inputs and preserve pre-state on failed prepare.
Bypassing capacity/admission/reservation rejection or skipping reservation,
release or refund append makes the corresponding test fail; mutations were
restored. This is aggregate arithmetic, not a tree implementation or proof of
reservation ownership. Per-withdrawal records, atomic N/F/W plus tree commit,
full refund data, and safe tree-capacity migration remain required.

`TransitionBudget` now calculates withdrawal preparation, Paid Ack and refund
over accounting and leaf capacity together, returning one result only after
both components succeed. Tests verify exact paired results and reject either
insufficient liabilities or insufficient leaf reservations without modifying
the input. Bypassing each of the six component calculations independently makes
the relevant rejection assertion fail; all mutations were restored. This does
not yet make a complete state transition atomic: real tree updates, individual
withdrawal identity/ownership, terminal records, verified proof data and native
outbound messages must join the same eventual host commitment.

Added explicit nanotomi-preserving conversion between UNO wide amounts and
Native Tomis integers. Native's existing VarUInteger 16 encoding permits at
most 120 unsigned bits; oversized, negative or absent values are rejected rather
than narrowed. This does not reduce the 128-bit aggregate counters or establish
a supply cap. Tests round-trip zero, 10^17, UINT64_MAX, 2^64 and the 120-bit maximum
through the real `t_Tomis` codec, with independent decimal controls. Removing
the outgoing bound, widening the incoming bound to 128 bits, or dropping high
bytes independently makes the relevant test fail; mutations were restored.
These conversion helpers are not yet wired into a Reserve contract or bridge.

Added logical bundle-context validation for Transfer, ShieldClaim, Unshield,
WithdrawalRefund, Genesis and private fee distribution. It checks the prescribed
public value balance and decoded spend/output permissions using checked wide
addition and symmetric i64 narrowing. Transfer accepts no separate principal;
output-only settlement accepts no separate fee in this API. Unknown contexts
fail closed. Tests cover all six contexts, wrong magnitudes/signs/permissions,
irrelevant public fields and range errors. Bypassing each rejection category,
dropping the output permission requirement or reversing the output-only sign
makes the matching assertion fail; changes were restored. This is not a wire-tag
assignment, canonical flags decoder, proof/signature verifier or authorization
for output-only issuance. Those must be connected at the real bundle boundary.

Started an isolated M2 Rust prototype under `uno/crypto`, pinned to the Orchard
0.15.5 release revision, an explicit feature set, Cargo.lock and Rust 1.97.1.
It compiles the actual circuit dependency and checks the allowed bundle/circuit
selector pair, rejecting historical and later profiles. The 12-combination
matrix fails when either selector comparison is removed; both were restored.
Locked offline tests and formatting checks pass. Source/API and initial advisory
review links are in its README. This is not a production dependency approval,
full security/license audit, VK identity manifest or proof verifier; no engine
registration, FFI or mainnet activation was added. Real proofs/signatures, pinned
VK reconstruction and complete TOS authorization/profile integration remain M2.

The Rust prototype now includes an allocation-free proof-shape precheck for
the pinned circuit: exact length, nonempty action set, explicit configured
action/byte limits, and checked length multiplication/addition. Its positive
sizes are compared against the actual pinned dependency. Removing each of four
rejection branches, or replacing either checked operation with wrapping math,
produces an erroneous Ok result and fails the targeted test. Overflow fixtures
supply the wrapped length deliberately, so a different error cannot conceal
the bypass. All mutations were restored and locked offline tests pass. Actual
proof verification and wiring this check before allocation remain unfinished.

The prototype now reconstructs the actual fixed-circuit verifying key internally
and reads its circuit version for bundle-profile checks. External callers cannot
inject a replacement key. Construction unwinds return an explicit error (this
does not recover process abort/OOM). The real-key test passes; changing only the
selected construction variant to the historical circuit makes the actual
key-version assertion fail. The fixed selector was restored. No canonical VK
fingerprint/reconstruction manifest, proof or signature verification, external
FFI or host registration is claimed by this step.

The Rust prototype now verifies typed authorized bundles with the internally
constructed fixed VK: profile and proof-shape checks precede proof verification,
all action spend signatures and the bundle-derived binding signature. Both
signature classes use the same supplied digest. A real generated output-only
proof/signature fixture passes; changed digest, damaged proof, zeroed spend
signatures and zeroed binding signature fail. Independently removing each of
the three cryptographic checks makes its isolated invalid fixture return Ok
and fail the test, rather than merely changing rejection wording. All three
mutations were restored. The fixture digest is not yet a TOS core digest and
the already allocated typed input is not a bounded wire ingress. This is not
output-only issuance authorization, stateful anchor/nullifier validation, a
canonical VK manifest, FFI or host integration; those remain required for M2
and the actual UNO engine.

Extended the real cryptographic fixture through a non-dummy spend: recover the
5000-nanotomi note, construct its depth-32 single-leaf witness, create a 4900
output with valueBalance 100, prove membership and sign with the actual spending
key. The resulting bundle passes the fixed verifier. Corrupting only the real
spend signature (leaving dummy signatures intact) fails; changing valueBalance
to 101 with unchanged proof and signatures fails binding verification. Removing
the respective signature check makes each isolated negative return Ok and fail
its assertion; both mutations were restored. The witness root is a fixture,
not an authenticated host anchor, and the recovery uses dependency encryption,
not the required hybrid profile. This extends M2 evidence without claiming
stateful admission, fee authorization or wallet integration.

Added a borrowed primitive-field bundle decoder to the Rust prototype. It checks
the fixed profile, resource/proof shape and reserved flags, excludes i64::MIN,
decodes anchor/cv_net/nf/rk/cmx with pinned APIs, and uses checked Action assembly
for nonidentity rk/epk. It copies ciphertext, signature and proof bytes unchanged;
successful construction is not proof/signature validity. Both real bundle
fixtures now pass through decoding before cryptographic verification. Twelve
independent mutations exercise profile, limits, flags, amount, primitive fields,
identity rejection and ciphertext preservation: invalid inputs become accepted,
or preserved bytes change, and the matching tests fail. All mutations were
restored. No outer Cell schema/profile-tag assignment, hybrid envelope, TOS
sighash, host-context authorization or production activation is implied.

Enforced the specification's canonical empty-tree anchor for disabled-spend
bundles at both primitive decoding and direct typed verification. A fresh real
output-only proof using field-zero anchor passes the underlying proof and all
signatures, demonstrating that cryptographic validity alone does not enforce
this UNO rule. The typed entry point rejects that otherwise-valid bundle; the
decoder tests both spend-flag settings with empty and nonempty anchors. Removing
either entry-point guard independently accepts the invalid case and fails its
test. Both guards were restored. This uses the public spend-enable flag, not
hidden real/dummy note classification, and does not replace transaction-kind
flags validation or authenticated host anchor membership.

Added context-bound Rust verification over the same bundle used for proof and
signature checks. Six logical variants implement the specified public nanotomi
equations and spend/output permissions, using checked u128 addition and i64
range conversion. Their typed fields exclude irrelevant principals/fees. Tests
cover all contexts and permission combinations, amount/sign mismatches, u128
overflow, symmetric i64 limits, real matching bundles, changed public amounts
and a corrupted proof through the combined API. Seven independent mutations
remove arithmetic, value, permission or composition checks; each returns Ok for
an invalid fixture and fails its assertion. All were restored. This parallels
the C++ context helper but does not claim cross-language conformance/FFI yet,
assign wire tags or authenticate settlement sources. Caller-supplied context
must ultimately be derived from authenticated host state and committed TOS core.

Recorded a frozen BLAKE2b-512 diagnostic snapshot of the actual constructed fixed
VK, including parameters and commitments exposed by its Debug representation.
The pinned public API has no internal VK serialization accessor; the similarly
named verifier-fingerprint feature captures a verifier execution, not a key.
The fixture README explicitly distinguishes this regression artifact from the
still-required canonical production key manifest and forbids automatic constant
regeneration. Rebuilding gives identical bytes. A historical VK with its selector
text relabelled as fixed still has a different digest. Replacing hashing with a
constant makes that test fail; selecting the historical constructor fails the
frozen digest assertion. Both mutations were restored. An independent skill
hash backend matched the Rust digest over the exported 907512-byte preimage.

Added one shared 26-case public-context corpus consumed by both the C++ host
helper tests and the Rust verifier-context tests. It covers six logical kinds,
zero/max values, sign and fee mismatches, spend/output permissions, high-word
amounts, u128 addition overflow and symmetric i64 bounds. Both readers require
all rows and compare to the same reviewed acceptance oracle. Removing each
implementation's balance comparison makes the wrong-fee case accepted; flipping
the first valid case's expected result fails both readers. All mutations were
restored. This provides agreement evidence for those inputs, not exhaustive
language equivalence, serialized wire conformance or an FFI boundary.

Added prototype C ABI v0 and a matching public header/static library around the
borrowed-field decoder and combined context/cryptographic verifier. The boundary
rejects unknown ABI/profile/context values and irrelevant monetary fields, checks
slice numeric bounds before construction, retains no caller pointers, shares an
immutable constructed key, and contains unwinding panics. Caller allocation
validity remains an explicit unsafe contract; OOM/abort are not recoverable.
Real positive and negative bundles exercise the exported function from Rust.
Thread-local test injection crosses the actual export; removing containment
aborts the test process. Removing ABI version/profile checks or the verification
call accepts invalid fixtures and fails tests. All mutations were restored.
A separately compiled C++ caller links the real static library and tests layout,
argument rejection and decoding rejection. C++ positive proof fixtures, platform
layout generation, sanitizers/fuzzing and node/engine linking remain unfinished;
the ABI does not assign transaction wire tags or authorize settlement sources.

Added actual C++ positive verification across the static-library ABI. The real
Rust fixture test optionally creates new public-only output/spend fixture files
in an explicit temporary directory; it refuses to overwrite files. A separately
compiled C++ reader constructs requests, accepts both valid bundles, rejects
independently changed digest/proof/each spend signature/binding signature and
resource/high-word amount errors, then accepts restored originals. Removing
each cryptographic check, rebuilding the Rust library and relinking C++ makes
its isolated invalid input succeed and the C++ test fail. All mutations were
restored. These temporary randomized records are not TOS wire, frozen production
vectors, secrets or authenticated settlement receipts. Node CMake registration,
platform ABI generation, sanitizer/fuzzing and engine integration remain open.

Added default-OFF `TOS_UNO_CRYPTO_PROTOTYPE_TESTS` CMake/CTest integration on native
Linux. Enabling it builds the locked/offline Rust static library in the CMake
build directory, links both C++ callers, and registers the Rust suite plus smoke
and real-fixture tests. Fresh fixture generation is checked for exit status and
actual files; C++ rejection is propagated. All three tests passed twice. A no-op
generator that returned success without files and a deliberately failing C++
caller both caused wrapper failure. Cargo tests share a resource lock. This adds
test targets only, not node linkage, workchain activation or config installation.

Added an owning C++ bundle adapter around the prototype ABI. It reuses existing
Amount/BundleContext checks, validates exact bounded proof shape before backend
invocation, maps contexts explicitly instead of enum casts, and preserves local
ABI/key/panic/unknown-status errors separately from invalid-bundle results.
Stub-only unit tests cover all six contexts and statuses; invalid public values
and lengths require zero backend calls even when the stub would also reject.
Removing either precheck fails specifically on an unexpected backend call. Three
other mutations detect enum-order drift, downgraded key failures and resource
length overflow. All were restored. The real CMake-linked fixture test also
exercises the adapter on valid proofs, corrupted proofs and changed digests.
This prepares a host call boundary but does not add a node/engine call site,
wire decoder, settlement authorization or state transition.

### Persistent used-nullifier primitive

Added `uno/core/used-nullifiers.h`, a 256-bit Cell dictionary used-set with
immutable staged batch insertion and no deletion API. Duplicate keys in the
batch or history reject without publishing a partially updated root. The set
does not special-case zero keys or dummy actions. Tests cover retained history,
late rejection, same-batch duplicates, empty batches and insertion-order root
equivalence. Changing dictionary insertion from Add to Set made the historical
duplicate rejection assertion fail; the mutation was restored.

This is a state building block, not full admission or StateV2 persistence:
untrusted root loading, owner-bound refund reservations (including cmx),
cryptographic admission, resource limits and atomic block integration remain
required. Only internally constructed roots can enter this class; dictionary
runtime exceptions are not converted into transaction rejection here.

### Owner-bound refund nullifier state

`NullifierState` composes the used set with two persistent Cell dictionaries:
nullifier-to-owner bindings and owner records containing a complete key-set
manifest. Ordinary insertion rejects reserved keys. Reservation rejects spent
keys, duplicate keys, other reservations, empty manifests and reused owner IDs.
Paid settlement releases the entire manifest; refund settlement moves the
entire manifest into the permanent used set. Neither path removes original
spend nullifiers. Both retain distinct terminal owner tombstones and reject
further transitions for that owner. Duplicate receipt handling must happen in
the authenticated bridge layer, not by running these transitions again.

Tests exercise multiple owners, zero keys, late conflicts, complete release
and consumption, terminal replay, original-state isolation and deterministic
roots across insertion orders. Three independent mutations fail on semantic
assertions: bypassing reserved-key admission accepts a conflicting spend;
skipping refund consumption leaves a nullifier unused; consuming on Paid
incorrectly spends a released key. All mutations were restored.

The record encoding is internal prototype state, not a frozen StateV2 schema.
External root decoding, resource limits, cmx reservation/history policy,
preverified refund-data binding, authenticated terminal receipts and joint
tree/accounting/block commit remain open. No engine call site is added here.

### Live synchronization: first routing blocker

Source tracing found that `FullNodeImpl::get_shard` explicitly rejected every
non-masterchain, non-basechain workchain. Thus earlier expectations that wc2
downloads could already use generic transport were incorrect. Overlay topology
also used the basechain monitoring depth for all workchains.

The production routing now tracks monitoring depth per workchain and resolves
known foreign overlays and their same-workchain ancestors. Unknown foreign
overlays do not fall back to masterchain; the existing basechain startup
fallback remains. Shared routing-policy tests cover wc2 selection, missing
overlays, independent depths, historical parent selection and topology reset.
Restoring the old foreign-workchain rejection makes wc2 selection fail;
restoring the shared basechain depth makes the independent-depth assertion
fail. Both mutations were restored. The production validator executable builds
with this policy, but the unit test does not instantiate live overlay actors.

This is not a live network test. Still required: independent real managers,
engine registration, actual peer transfer, normal signatures/acceptance and
receiver-side batch replay; separately, persistent-state acquisition/import,
resource measurements, catch-up and GC with the monolithic engine-state shape.
These are priority M1 prerequisites before freezing StateV2, not gates already
implemented by the disk harness.

### Snapshot shape: single executor account

Exposed the existing internal `split_shard_state` serializer function for a
direct regression test without changing its algorithm. A valid wc2 shard with
one executor account holds a Cell dictionary of 4096 deterministic synthetic
nullifiers. At snapshot split depths 1, 4 and 8, the real serializer produces
exactly one account-data part plus one header proof, not multiple pieces of
the account's data. The test independently BOC-round-trips both parts, verifies
the virtualized header root, reconstructs the shard from that header and the
account part, compares the complete state root, extracts the executor payload
and looks up every nullifier. Depth zero preserves the unsplit state.

Forcing the serializer to bypass splitting fails on the missing account/header
parts (one instead of two); the mutation was restored. This establishes the
account-prefix splitting limitation and a small in-memory serialization
round-trip, not scalable state synchronization. It does not exercise network
download, the production persistent-state importer, database reopening, peak
memory at large state sizes, catch-up, GC or note-tree retention. Increasing
account split depth cannot be assumed to reduce the single-account payload.

### Bounded on-disk parsing of the executor snapshot part

The account-data part now passes through an exclusive temporary file and the
downloader's full-options `parse_ondisk_state_streaming` entry point before
state reconstruction. The test supplies a 16 MiB resident budget and a counting
`CellDbStreamingSink`, verifies completion and all recovered nullifiers, and
explicitly checks that actual CellDb writes remain zero. A wrong expected root
is rejected after the complete cell count has been parsed; a one-cell budget
rejects before any cell reaches the sink. This distinguishes the two properties
from incidental rejection. Disabling the full-options root comparison makes
the wrong-root assertion fail; the mutation was restored.
Ignoring the supplied cell-count limit also makes the budget rejection
assertion fail; that mutation was restored as well.

The test uses the small 4096-key state, keeps the source fixture in memory, and
does not measure peak RSS. It exercises the bounded parser, not the actor-local
CellDb commit/rollback path, authenticated network checkpoint acquisition or a
cold node's end-to-end synchronization. Those remain required.

### Real CellDb actor import exposed a completion-loss bug

The UNO snapshot test now starts a real `CellDb` / `CellDbIn` on a two-worker
actor scheduler with an isolated RocksDB directory. The initial run timed out
after the import worker rejected its spool: a raw `td::thread` called
`send_closure` without a scheduler context, and `send_immediate` silently
discarded the completion message. This affected both success and failure
handoffs, not just this snapshot's contents.

Worker completion now publishes an atomic release flag; an actor-local 10 ms
timer checks it with acquire ordering and invokes the existing continuation.
The actor remains responsive and joins only after completion is published.
The pre-fix test timed out at 30 seconds; the fixed full test completes in
approximately 0.4 seconds on this host. This is regression evidence for actual
worker-to-actor completion, beyond the earlier parser-only tests.

A second concrete limitation remains: this 168133-byte snapshot exceeds the
default 300% spool reservation (504399 bytes) before finishing parse. The test
explicitly requires that budget rejection, then uses a test-only 2000% ratio
to exercise wrong-root rejection and successful retry on the same database.
Production defaults are unchanged; a suitable bounded reservation policy for
this state shape remains unresolved. The successful import recorded 8198
persisted cells in nine actor-side batches, returned a GC lease and allowed
all 4096 nullifiers to be lazily read from the resulting state. Database paths
are logged and retained for inspection.

This does not register the canonical block-state root, commit an authenticated
checkpoint, release the lease as a successful root-store operation, prove crash
recovery, or transport anything over the network. Those remain separate work.

### Encoding-aware import spool reservation

The default-ratio failure above is now addressed without raising the default
ratio or disk caps. BoC references are compact indices; CellDb records instead
contain each child's level mask, hashes and depths, plus a record header and
refcount. The rollback manifest can duplicate every new-cell record. A checked
conservative bound is therefore `2 * (file_bytes + 588 * cell_count)` for the
current Cell traits and non-BoC CellStorer encoding. The 588 is computed from
those traits in `streaming-import-budget.h`, not assumed from measured ratios.

The actor reads at most 256 header bytes, checks the header count against the
requested/default cell limit, and reserves the larger of the configured ratio
and this bound, capped by the existing per-import limit. If the conservative
bound exceeds that limit, the import may still proceed within the limit and
the existing per-record checks remain authoritative. Global reservation checks
are unchanged. This can reserve more disk capacity than actually needed; it is
not a claim about optimal concurrency or large-state performance.

The 4096-nullifier actor test now succeeds at the default 300% ratio, without
the prior 2000% override. It separately verifies an explicitly tiny per-import
cap rejects, restores the ordinary cap, rejects a wrong expected root and then
imports the same bytes successfully. Ignoring the encoding bound fails on that
valid import, not on an exact rejection string. The mutation was restored.
Arithmetic tests cover the 9977114-byte bound for the 168133-byte/8198-cell
fixture, zero inputs and multiplication/addition/doubling overflow boundaries.
Removing the rollback-copy factor fails the arithmetic test (688 instead of
1376 for its small fixture); that mutation was restored too.

### Root registration, lease release and database reopening

The actor fixture now follows successful import with the real `CellDb::store_cell`
root-registration path under a synthetic wc2 block ID. It holds the GC lease
until the store callback, releases it as committed, then requests a fresh inner
reader as a barrier and verifies the complete engine dictionary. A new read-only
`get_registered_state_root` actor query verifies the block-ID-to-root metadata,
not merely the existence of cells by hash.

The first scheduler and database actors are then destroyed. A new scheduler
opens the same RocksDB directory and loads the root without importing the
snapshot again. Both the registered metadata and every nullifier are checked.
Bypassing root registration while returning the already imported cell makes
the metadata query fail; the mutation was restored. This prevents raw cell
availability from masquerading as successful root registration.

The standalone fixture deliberately has no RootDb GC policy controller. CellDb
now retains state when that actor handle is absent instead of dereferencing an
empty handle upon lease release. Production nodes still consult their real
controller; no GC authorization is granted by this fallback.

This proves clean database reopening within one process, not process-crash
recovery, cold OS-cache performance, active GC, signed block acceptance,
authenticated checkpoint registration or network synchronization. The block ID
is synthetic and no full RootDb/validator manager is present in this fixture.

### Rust/C ABI header generation and drift rejection

Read the pre-deletion FFI build script/configuration and the vendored build
integration pin/refresh notes at `cd8e170a0^`. The prototype now follows the
generated-and-committed header pattern with cbindgen pinned to 0.29.0 as a
locked build dependency. Unlike the historical warning-only fallback, generation
errors and disagreement with the committed header stop the Cargo build.
Generation runs into OUT_DIR and never rewrites source during an ordinary build;
explicit regeneration is documented in `uno/crypto/ABI.md`.

Function signatures, request/Action fields, status discriminants and the actual
version/profile/context constants used in Rust now feed the same generated
header. The opt-in CMake Rust target already runs Cargo on each build, so its
real C++ callers cannot silently link a changed Rust surface against an old
header. Default-OFF stub-only builds still require no Rust toolchain and are not
cross-language consistency evidence.

Independent mutations of pointer constness, Action array length, status value,
context value and only the C header count type each failed specifically at the
header comparison. All were restored. C11 syntax checking and the linked C++
build passed. Generation does not prove length semantics, pointer validity or
ownership; runtime boundary guards and real-proof tests remain required.
All four `test-uno-crypto-*` CTest groups then passed twice, including the real
proof fixtures through the linked C++ adapter (49.52 seconds total).

The historical Corrosion v0.5.2 pin and whole-release refresh policy were read
and recorded as prior art in ABI.md. Native Linux-only direct Cargo integration,
per-build target directories, the default-OFF option, and production activation
scope are unchanged. No previously locked cryptographic dependency version was
changed to add the generator.

### First TCP snapshot acquisition evidence

`test/uno-snapshot-transport.cpp` now runs a real ADNL external TCP server and
client on localhost. Its remote fixture serves the prepare/size/slice queries;
the receiving actor inherits the production `fullnode::DownloadState` and uses
its real TL decoding, size reservation, slice assembly and completion path.
Only startup is overridden to skip manager-local lookup and node discovery.
No fake sender or direct response injection replaces the TCP transport.

The wc2 single-account snapshot (4096 synthetic nullifiers) now crosses that
connection before its received bytes are written to the import fixture's file
and passed to the actual CellDb worker, root registration and clean reopening
checks. The source bytes are held by the serving fixture, not loaded from the
receiving database. The test checks wc2 in slice requests, contiguous offsets,
query counts and byte-for-byte equality. Synthetic block and masterchain IDs
are not authenticated checkpoint evidence.

A separate 2 MiB + 137-byte transport payload requires two slices. Its matching
negative peer truncates the first response by one byte and would serve later
responses correctly if asked. The downloader must reject immediately with a
protocol violation after one slice. Disabling the production short-part guard
made the test fail with two queries instead of one; the guard was restored.
This checks actual acquisition order independently of rejection wording.

Scope: one process, real localhost TCP, synthetic serving callback, the external
client branch, and the small-state heap path. It does not test P2P RLDP/overlay
discovery, independent validator managers/processes, authenticated block/state
proofs, receiver-side batch replay, committee consensus, large-file download
mode or production download-to-import orchestration. The post-download tempfile
handoff is still test code. Large-state scaling, active GC and those full-node
paths remain M1 work, not accepted gates.

The fixture probes a random unused port before constructing the ordinary TCP
server; a close/rebind race fails within bounded actor timeouts. The existing
client may take its reconnect delay when the listener has not started yet.
Temporary test directories are retained under `/tmp/uno-snapshot-transport-*`
and `/tmp/uno-snapshot-celldb-*`; no production configuration is changed.
After restoring the mutation, the snapshot, workchain-routing and nullifier
CTest groups each passed three consecutive runs (42.07 seconds total).

### TCP file-mode acquisition and ownership

The TCP transport helper now returns the actual `DownloadedPersistentState`
instead of always copying it into an unbudgeted memory buffer. The compatibility
helper used by the small snapshot still explicitly requires the memory variant.
`TcpFileDownloadOwnership` supplies 64 MiB + 137 bytes, crossing the production
64 MiB heap threshold without changing it. The real downloader requests 33
slices, writes its tempfile, fsyncs/renames it and returns the file variant.
The fixture checks the entire file against the source in 1 MiB reads; it does
not map or allocate a full receiving-side verification buffer.

After the downloader and scheduler have stopped, the caller must still own an
existing finalized file and its full byte reservation. Moving the returned
object must preserve both; dropping the final owner must unlink the file and
restore the original budget counter. A matching truncated remote response must
leave neither reserved bytes nor any file in the dedicated download directory.

Two production mutations independently demonstrated these checks: bypassing
chunk writes failed the byte-comparison assertion, and bypassing abort cleanup
failed with one leftover file instead of zero. Both mutations were restored;
this change adds test coverage, not a production behavior change. Mutation-run
artifacts are retained under unique `/tmp/uno-snapshot-download-*` directories.
After restoration, snapshot, routing and nullifier CTest groups each passed
three consecutive runs (74.17 seconds total).

This closes the prior fixture's file-mode transport coverage gap, not the full
large-state synchronization requirement. The large payload is synthetic bytes,
not a large valid UNO state, and its sender is still a same-process fixture.
It supplies no RSS/performance bound, authenticated checkpoint, P2P overlay or
real-manager download/import evidence. The small valid UNO snapshot continues
to cover actual CellDb import/reopening separately.

### Slot-length measurement deliverable

The current 75-second slot is a candidate awaiting justification, not a fixed
performance target. M2 measurement output must include a conditional achievable
slot lower bound and a recommended value with margin, stating validator hardware,
network conditions, state size and block limits. Measure the complete critical
path and its tail behavior: MC time advancement, collation/verification, tree
and nullifier updates/persistence, propagation and agreement, including cold
state, maximum legal blocks and adversarial inputs. Component measurements alone
cannot freeze a slot without the real M1 network/consensus path.

Client proving is outside the submitted block's critical path, but its latency
matters for anchor availability and expiry. Freeze slot length together with
the candidate 100-height anchor window and 64-height expiry window; neither is
a fixed wall-clock duration under missed slots or stalled height. Preserve the
continuous scheduling-epoch requirement if slot duration changes. No measured
slot lower bound is available yet, and these transport tests do not supply one.

### Large single-account file acquisition through database reopening

The state-import fixture now accepts the downloader's `DownloadedPersistentState`
directly. For file-mode results it moves the exact `BudgetedStateFile`, retaining
its reservation through import and reopening; it does not recreate that file
from a copied memory buffer. Only the small memory-mode fixture uses a separate
temporary-file adapter.

An opt-in experiment builds one wc2 executor account containing the actual
permanent nullifier dictionary with 2,000,000 reproducible synthetic keys. Run:

```sh
cmake --build build --target test-uno-state-snapshot -j48
UNO_SNAPSHOT_LARGE_TEST=1 build/test-uno-state-snapshot --filter LargeSingleAccountDownloadAndImport
```

Without the environment variable this experiment explicitly logs that it was
not run; a default CTest pass is not large-state evidence. The large import
actor has a 1200-second test watchdog, not a consensus/slot deadline. Smaller
fixtures retain their 30-second watchdog.

The explicit run passed in 203.1 seconds on this host. Serialized size was
83,933,657 bytes, above the unchanged 64 MiB file threshold. The real TCP
downloader acquired the file, then the real CellDb worker committed 4,000,006
cells in 3907 actor batches. The expected root was
`20BBED0D6F111FC861106DC4AFB1712F61633C90699CA8D1552CF3BD14513FAF`.
The existing wrong-root rejection, all-key reads, root-registration metadata,
lease release and clean database reopening assertions all executed. The retained
database `/tmp/uno-snapshot-celldb-etPKG9` occupied approximately 410 MiB during
the run and 383 MiB on a later post-run check. The ordinary snapshot CTest also
passed (21.24 seconds).

This is a valid host shard/account representation with a nullifier dictionary,
not a frozen full UNO StateV2 including a note tree, bridge records and anchors.
It remains one process with a synthetic TCP serving callback and synthetic block
IDs, not real-manager orchestration or an authenticated checkpoint. Reopening
does not evict the OS page cache. The 203.1 seconds includes fixture construction,
negative import, multiple exhaustive dictionary scans and reopening; it is not
a download, per-block execution or slot-latency measurement. Source state and
the oracle keys remain in process memory, so process RSS is not receiver-only.

The worker reported a 175.6 ms slowest import slice during the successful
import, above its 5 ms scheduling target; the preceding rejection attempt also
reported a 279.6 ms slice. These are diagnostic observations requiring targeted
measurement, not an accepted scheduler bound. The result closes the split
between large file transport and large dictionary import evidence, but does not
close M1 network/consensus acceptance or M2 performance gates.

### Reconstructing the used-nullifier object after restart

Previously the primitive could only start from an empty set, while snapshot
tests inspected the persisted dictionary directly. `UsedNullifiers::from_root`
now validates and reconstructs the immutable object with an explicit maximum
entry count. Zero permits only the empty root. Validation reuses the native
dictionary label parser and strict fork checks, enforces empty leaf markers
(no bits or refs), and decreases the remaining key width at each fork. Recursion
is bounded by the 256-bit key width; the entry cap also bounds traversal of
shared subtrees as logical entries. This is a restore-time full scan, not a
per-transaction operation or a measured RSS/deadline bound.

Every dictionary node is loaded without implicit library resolution and special
cells are rejected. This matters even under an active VM context: the generic
dictionary reader can resolve library references. A test installs a working
library resolver, proves ordinary dictionary lookup invokes it, and requires
the persisted-state loader to reject both root and nested references without
calling it. Malformed cells, incomplete proofs and VM execution-budget exhaustion
return errors instead of producing an object.

Tests cover BoC round-trip, exact/insufficient entry limits, malformed forks,
nonempty bit/ref markers, pruned cells, duplicate rejection after restore and
deterministic immutable continuation. Independently removing the entry bound,
empty-marker check or non-resolving cell load made the corresponding tests fail;
all mutations were restored.

The database-reopening fixture now constructs this object from the reopened
account payload, rejects an existing nullifier and stages a new one while
preserving the original root. This stages a used-set update only; it does not
commit a new host block. Root authentication, complete StateV2 decoding and the
reservation/owner/amount/tree cross-field invariants remain separate requirements.
In particular, `NullifierState` still needs its own validated multi-root loader;
this API does not bypass refund reservations or authorize spending.

The final strict loader passed the explicit 2,000,000-key experiment in 207.0
seconds, including reopening, full validation, historical duplicate rejection and
staging a fresh key; its database is retained at
`/tmp/uno-snapshot-celldb-mYs19E`. The ordinary snapshot and nullifier CTest groups
also passed twice (72.81 seconds total). A load-counter test additionally proves
that a zero entry budget touches no cell and that an execution-budget exception
becomes an error, with a successful load of the same fixture as positive control.
These timings are test wall times, not isolated loader or slot measurements.

### Joint reservation-state restoration

`NullifierState::from_roots` now reconstructs used, reserved and owner state
together. Its explicit load limits cover used keys, reserved keys, owners and
the aggregate number of manifest entries across all owner records. Shared
manifest Cells are charged for every logical occurrence, not deduplicated into
an unbounded work allowance. The strict non-resolving dictionary walker is
shared with `UsedNullifiers`; marker, binding and owner record shapes remain
unchanged from the existing primitive encodings.

Before publishing an object, loading checks both directions of the pending
owner/manifest/reservation relation and requires used/reserved disjointness.
Every refunded manifest key must remain used. Paid owner manifests are retained
as tombstones, but their keys may subsequently be spent or reserved by another
owner; rejecting that legitimate reuse would make a valid persisted state
unloadable. Unknown statuses, extra binding data and malformed manifest markers
are rejected. No implicit library resolution is permitted in any component.

Round-trip tests restore mixed pending/paid/refunded histories and continue
refunds, compare resulting roots with uninterrupted execution, preserve the
original roots, and reject reuse of terminal owner IDs. Limit tests exercise
each independent cap, including the total across multiple manifests. Independent
mutations removing forward ownership matching, reverse manifest membership and
the refunded-used obligation each caused a different inconsistent fixture to
be accepted and its test to fail. All mutations were restored.
The nullifier and ordinary snapshot CTest groups each passed three consecutive
runs (84.74 seconds total). Default-constructed load limits are all zero;
nonempty restoration requires an explicit caller-supplied budget.

The outer StateV2 loader must authenticate these roots together as one committed
state and validate amounts, note tree, bridge records and receipt authority.
This API does not authenticate terminal events, define StateV2 serialization,
or enable an engine. The joint loader has unit/BoC round-trip evidence here;
the previously recorded large database experiment covered the used-set loader,
not a large mixed reservation history.

### Idle service policy measurement requirement

Freeze idle cadence together with slot length and anchor/expiry windows, not as
an omitted implementation default. The preferred unmeasured candidate is one
block-production attempt per eligible slot even without paying transactions;
this is an obligation under normal liveness assumptions, not a reason to reject
a legal successor after missed slots. Measure idle storage/bandwidth/CPU/I/O cost,
system-message service budgets and funding, expected maximum silence, and
checkpoint submission/retry delay before selecting and recording exact values.
If configurable, defaults, allowed ranges and activation/epoch boundaries must
be explicit. No idle-cadence value or ConfigV2 field is activated by this entry.

Checkpoint submission for an already locally finalized block must not wait for
a new user transaction or successor block. Ordinary 64-height transaction expiry
is not a refund timer and cannot substitute for authenticated terminal settlement.
An empty-block heartbeat exposes lack of progress, not proof against selective
censorship. No measured idle service policy has been accepted yet.

### Consecutive idle host batches and independent disk replay

The host already creates a batch after collecting imports even when that inbox
is empty. A missing candidate is deliberately invalid: an engine must supply an
explicit candidate encoding zero user actions. No candidate-presence guard was
relaxed and no production scheduling policy was changed.

`test-counter-idle-replay` starts two independent databases from the test genesis
and produces three consecutive zero-increment batches without incoming messages,
outgoing messages or native fees. Each candidate is exported and independently
validated/imported by a fresh peer process; full persisted block identifiers
must match. Fresh processes on both databases then reject an increment one above
the remaining counter range and accept the adjacent maximum, proving the restored
engine value remains exactly 40 and execution can resume after idle advancement.

A temporary mutation skipped batch construction when imports were empty. The
first idle block then failed validation with `missing block executor AccountBlock`,
and the positive test failed on the unsuccessful process exit, not a rejection
message assertion. The mutation was restored. This checks actual collate/validate
execution, not merely the presence of a staging log.

After restoration, the idle-replay, disk-integration, self-delivery and
cross-delivery CTest cases each passed three consecutive runs (12 executions,
14.57 seconds total with four parallel test jobs).

This remains a test-engine, file-transfer and disk-manager experiment with fake
signature acceptance. It does not exercise a live network, the normal committee,
UNO slot selection, timer-driven production, checkpoints, or system-message
funding. Its elapsed runtime is not a slot-length measurement. The next service
policy work must supply those missing scheduling/finality paths; an empty-action
host batch is only their execution prerequisite.

### Deterministic scheduling-epoch arithmetic prototype

`uno/core/slot-epoch.h` implements immutable, duration-parameterized scheduling
arithmetic without a wall clock or default duration. Genesis starts at slot zero;
times before the epoch and zero durations fail. Successor validation requires
exactly one height increment, a strictly greater slot, and equality with the slot
derived from the supplied authenticated time. Missed slots remain legal; claiming
an old slot at a later observation is not. Height exhaustion fails without wrapping.

The candidate epoch-change rule permits a later old-epoch slot boundary and
carries that boundary's slot number into the new epoch. Both shorter and longer
durations preserve continuity. This is an unactivated arithmetic proposal, not a
ConfigV2 wire definition or an accepted migration policy. The caller must select
the authoritative epoch for the observation, retain history for replay, authenticate
the configuration and predecessor, and enforce masterchain reference lag. An old
epoch object does not itself know that governance has replaced it.

Four unit cases cover boundary rounding, alternate durations, skipped slots,
duplicate/backfilled/future slots, height gaps, epoch continuity, and full-width
time. Private construction preserves `first_slot <= start_time` and duration at
least one, so computed slot cannot exceed the supplied time; no unreachable slot
overflow branch is installed. Three independent temporary mutations reset the
epoch slot offset, removed strict slot advancement, and removed the pre-epoch
time check. Each made its targeted test fail, and all were restored. An initial
dotted test filter selected zero cases and was discarded; the corrected filter
actually ran and failed the epoch-continuity case.
After restoration, the full `test-uno-amount` CTest group passed three consecutive
runs (0.03 seconds total).

This helper is not connected to a production engine or collator timer. It neither
authenticates a finality reference nor enforces the idle/checkpoint service policy,
and does not measure or freeze the slot duration. The full UNO execution and
configuration integration remains required.

### First repeatable full-ABI verification timing experiment

`uno/crypto/tests/abi-real.cpp` now accepts an optional sample count in
`[100,10000]`. The ordinary correctness invocation remains unchanged. Timing
mode reuses the real linked-library fixtures and all their positive/negative
controls, then measures valid verification and wrong-digest rejection separately.
Each timed call checks the returned status. Ten untimed warmups precede each
workload; nearest-rank p50/p95/p99/max use a monotonic clock. The first call of
each fixture is reported separately so initial key construction is not hidden
inside warm verification figures. See `uno/crypto/ABI.md` for reproduction.

Initial successful run on 2026-09-05, toserver, 192 logical CPUs (Intel Xeon
Platinum 8455C), native Linux Release, Rust 1.97.1 and unchanged Cargo.lock,
source base `68f3824ed` plus this timing change. Calls were serial from one
process, without CPU affinity or runtime thread-pool overrides. This was a
shared host, not a controlled dedicated benchmark; observed one-minute load
was 22.77 before and 73.50 during the experiment. Each workload had 1000 samples,
two Actions and a 7264-byte proof:

| Fixture / workload | p50 ms | p95 ms | p99 ms | max ms |
| --- | ---: | ---: | ---: | ---: |
| Output-only / valid | 10.2397 | 11.3085 | 12.0569 | 13.3555 |
| Output-only / wrong digest | 8.89983 | 9.66564 | 10.5273 | 12.1772 |
| Spend / valid | 10.2213 | 11.0541 | 12.2421 | 13.3017 |
| Spend / wrong digest | 8.85267 | 9.67726 | 10.5048 | 11.9872 |

The initial output-only ABI call took 2063.7 ms including key initialization;
the later spend first call took 9.0515 ms with the key already initialized.
Neither is an initialization percentile. Public fixtures were freshly generated
by the ordinary CTest (passed in 13.40 s) and retained under
`build/uno/crypto/fixtures/33aec81ebd2a7e1b7f8f/`.

To prove the measurement does not accept a removed verifier, a temporary mutation
replaced only the timed ABI call with a constant success status. The valid-only
timing then misleadingly approached zero, but the wrong-digest sample failed
(`got 0, expected 3`) and the process exited 2. The mutation was restored. A report
is usable only after the entire invocation succeeds, not from partial stdout.
An out-of-range sample count of 99 also rejected before attempting fixture I/O.

After restoration a second complete 4000-sample invocation passed on the same
fixtures. Valid output/spend p99 were 12.0744/11.9821 ms, maxima
14.5285/14.5029 ms; wrong-digest p99 were 10.2301/10.5877 ms. Initial key-inclusive
call was 1925.36 ms. This repeat is not a statistical confidence bound and does
not remove the shared-host or repeated-input limitations.

These are warm repeated-fixture ABI observations, including primitive decoding,
proof and signature verification, not the C++ owning adapter or host transition.
They exclude client proving, diverse/maximal bundles, worst-case malicious wire,
tree/nullifier updates, state serialization, storage tails, propagation and
committee agreement. They do not establish a block capacity, gas schedule, idle
cost or achievable slot lower bound. Those remain joint M1/M2 measurement outputs,
not a multiplication of this two-Action result by a proposed transaction count.

### Client proving measurement harness

The real Rust bundle test now has an opt-in `UNO_PROVING_SAMPLES=3..1000` mode.
It measures proving-key construction separately and repeatedly generates fresh
randomized proofs for both its output-only and genuine-spend fixtures. Each
sample times only `create_proof`, with the prepared witness clone outside the
interval; signing and complete verification run afterwards. The baseline proof
warms the prover, and the same key and witnesses are reused. This is deliberately
not end-to-end wallet construction or hybrid encryption measurement.

Every timed proof must verify and differ from its predecessor. A temporary
mutation returned the already verified baseline bundle and zero duration instead
of generating a proof. The second sample failed the cached-proof assertion and
the test exited 101. The mutation was restored. The assertion reports only its
reason, not both entire proof byte arrays. Small pilot runs report median/max;
tail percentiles are emitted only for at least 100 samples. Partial output from
a failed test is not usable measurement evidence.

The initial three-sample pilot passed both workloads and the existing real-bundle
negative controls in 18.24 seconds. Its medians were 1354.38628 ms (output-only)
and 1406.904055 ms (spend), with 3252.886042 ms proving-key construction. These
small pilot values are not tail estimates. Reproduction is in
`uno/crypto/README.md`; the default test does not repeat proving.

The subsequent 100-sample-per-workload run passed in 285.89 seconds on toserver
on 2026-09-05, source base `023384a76` plus this change, Rust 1.97.1 Release and
unchanged Cargo.lock. Both fixtures have two Actions and 7264-byte proofs.

| Proving workload | p50 ms | p95 ms | p99 ms | max ms |
| --- | ---: | ---: | ---: | ---: |
| Output-only | 1400.397126 | 1435.112684 | 1457.986233 | 1480.101301 |
| Genuine spend | 1353.742007 | 1408.072384 | 1423.208480 | 1423.802031 |

Proving-key construction was 2718.065829 ms in this run, a single observation,
not an initialization percentile. Calls were serial but the prover used its
default multicore runtime: process inspection observed 194 threads and 4837%
cumulative CPU utilization on this 192-logical-CPU machine. No affinity or runtime
thread override was applied. The shared host's one-minute load was 35.38 near
the start and 41.68 during spend sampling. These numbers must not be presented
as typical laptop/mobile performance, nor as independent-witness tail guarantees.

Client proving precedes submission. These measurements contribute to wallet and
anchor/expiry-window budgeting, but do not establish a consensus deadline or slot
lower bound. Memory, maximum-action counts, witness diversity and constrained
client hardware remain unmeasured; the full block state/transport path is still
needed for the slot and idle-cadence decision.
After the measurement run, the default full Rust library suite passed: 17 tests,
one intentionally ignored diagnostic export, 10.74 seconds, without the sample
environment variable.

### Nullifier transition cell-failure boundaries

The ordinary consumption path already rejects refund-reserved keys; no alternate
spending path was added. Inspection instead found that restore operations returned
VM failures as `Result` errors, while state updates could still throw past their
`Result` signatures. `UsedNullifiers::with_used` and the joint state's consumption,
reservation and settlement paths now convert `VmError`, `VmVirtError` and
`VmNoGas` into errors without publishing staged roots.

The new joint-state test first counts Cell reads on each successful consumption,
reservation, paid and refund fixture. It then injects each of those three exception
types separately at every observed read position, including late failures after
private staging has begun. Each attempt must return an error at the selected read,
leave all three source root hashes and key membership unchanged, and permit a
subsequent successful retry. A direct used-set test separately covers its own
budget-failure boundary, without relying on the joint state's outer handler.

Four independent temporary mutations rethrew the budget exception from used-set
update, joint consumption, reservation and settlement respectively. Each made
its targeted test fail through an escaping exception. All mutations were restored.
The fault injection covers Cell reads of these fixtures, not every allocation
or Cell creation failure, and is not a crash-recovery experiment.
After restoration the full nullifier and ordinary state-snapshot CTest groups
each passed three consecutive runs (85.29 seconds total). The opt-in large
snapshot experiment was not rerun for this error-boundary change.

These are still isolated state primitives. Boolean query methods retain their
VM exception contract; the outer engine must guard them and distinguish local
resource failure from invalid consensus input. No OOM recovery, production gas
schedule, complete StateV2 transaction or authenticated settlement is claimed.

### Actual note-tree frontier and complete-action spend witness

`uno/crypto/src/tree.rs` now supplies a depth-32 note-tree frontier using the
pinned Sinsemilla node hashing, canonical field encoding and empty roots. It
does not substitute a generic hash or revive the retired tree. The existing
incrementalmerkletree 0.8.2 dependency moved from dev to runtime without changing
Cargo.lock or any version. Ordered batch append stages a private frontier and
checks capacity after caller-supplied refund reservations. A malformed late leaf
does not publish preceding staged additions. Full capacity permits an empty
batch but never another leaf, and position never wraps.

The bounded Rust snapshot representation contains the next position, optional
last leaf and at most 32 prior subtree hashes. Restoration rejects inconsistent
empty/nonempty shapes, noncanonical nodes, wrong prior-subtree counts and excess
depth. This is not a frozen StateV2 wire/Cell codec or an authenticated history.
The outer state must authenticate the snapshot and reservation budget and retain
full output/ciphertext history; the frontier alone cannot serve wallet scanning
or historical witnesses. Duplicate-cmx policy remains an outer freeze item.

The existing real-spend crypto fixture now uses both output Actions, including
padding, to construct the tree. Its witness uses the actual randomized output
position and sibling; the witness anchor must equal both the frontier root and
its restored root. A genuine spend proof is then produced and fully verified
against this anchor, and both spend outputs append to the restored frontier
(position 2 to 4). This replaces the previous single-real-leaf test witness,
without claiming a production wallet or C++ tree adapter.

Unit tests compare incremental carry behavior with independent full-layer
reduction at every size from 1 to 65 and round-trip every frontier. Synthetic
near-capacity snapshots exercise the final leaf and reservation boundary without
claiming billions of historical outputs were generated. Independent mutations
skipped append, ignored reservations and reversed batch order; each failed a
different assertion (position, capacity rejection, or resulting root). All were
restored. Remaining work includes the tree ABI, canonical Cell storage, anchors,
authenticated combined state transition and actual append/serialization profiling.
After restoration, the full Rust and linked C++ real-ABI CTest cases each passed
twice (49.90 seconds total). The Rust suite contains 20 passing tests and one
intentionally ignored diagnostic export. Generated-header comparison stayed
unchanged; no new C ABI declaration or frozen verifying-key digest was introduced.

### Borrowed tree transition C ABI and real spend-anchor binding

`uno_crypto_tree_append_v0` now exposes the actual tree transition through the
generated header. Its fixed-size input frontier contains a position, last leaf,
prior-subtree count and 32 zero-padded node slots. Its caller-owned output contains
the successor frontier and root. This is ABI version 0/profile 1, not a canonical
Cell or StateV2 wire encoding. No pointers are retained or allocated buffers
returned. The existing proof-verification ABI is unchanged.

The boundary validates version/profile, count limit, numeric spans/alignment,
canonical unused slots and input/output non-overlap. Empty batches permit a null
commitment pointer. Parsing, staging and root hashing all finish before publishing
output; returned errors and caught panics leave caller output unchanged. The
caller must still guarantee valid allocations, exclusive output access and
authenticated state/limits/reservations. Aborts and OOM are not recovered.

A linked C++ test compares batch versus repeated append, restores with an empty
batch, rejects a malformed late leaf, checks unchanged sentinel output, reserved
capacity, count/profile bounds, padding, null spans, overlap and recovery. The
real C++ crypto fixture additionally computes the complete output Action tree via
this export and requires that root to equal its paired spend fixture's anchor.
Both fixtures are freshly generated; old single-leaf witness pairs are not reused.

Rust injects a panic immediately before publication and an overflowing span,
checking unchanged output and a subsequent successful call. Two independent
temporary mutations wrote output before validation or suppressed publication
entirely; the C++ test failed with exit 8 or 4 respectively. Both were restored.
The C header was regenerated explicitly, its ordinary build drift check passed,
and C11 syntax validation passed. The Rust tree implementation and VK fingerprint
were not changed. Host Cell persistence, combined state execution, anchors and
production activation remain required.

Final verification: Rust, C++ smoke and tree CTest groups each passed twice. The
real-ABI group's first pass succeeded, but its next fixture generation failed
with ENOSPC before C++ verification. A subsequent filesystem check showed 1.1 GiB
available without deleting artifacts; rerunning that group then passed twice
(23.86 seconds). The failed run is not counted as success. Disk headroom remains
low and needs attention before another large snapshot experiment.

### C++ frontier Cell persistence and continued execution

`uno/core/note-tree-state.h` now provides immutable tree state backed by the real
Rust ABI, with a strict, unactivated Cell prototype. A 358-bit header carries
tag `0x554e4630`, 64-bit next position, 256-bit last leaf and 6-bit prior-subtree
count. Exactly that many 256-bit ordinary node Cells follow in ABI order through
a single-reference list. The maximum is 32 node Cells plus the header. This does
not serialize native ABI structs or cache a trusted root; decoding reconstructs
the frontier and recomputes its root via the ABI. The tag/layout are not a frozen
StateV2 assignment or a deployment path.

Header/node bit counts and reference counts are exact. Oversized lists, trailing
data, special Cells, invalid empty states and inconsistent positions are rejected.
VM failures return errors; a library reference is never resolved implicitly.
Caller-supplied append limits and refund reservations still need authenticated
configuration/state. Failed append cannot modify the source object. The wrapper
preserves ABI status codes on errors, so the future engine must classify local
failures separately from invalid candidate state.

The new opt-in linked test walks 65 appends, serializing to BoC, restoring and
continuing after each append, with root and canonical Cell-hash equality. It also
checks empty restoration, late invalid leaves, limits/reservations, malformed
Cells, zero library resolver calls, read-budget failures and successful retries.
A synthetic full-capacity frontier loads in exactly 33 reads and cannot append;
an oversized count rejects after the header read only. This is not evidence of
billions of generated outputs or a database/cold-restart experiment.

Two independent mutations removed the exact header bit-length check or reversed
serialized node order. The tests respectively accepted forbidden trailing data
or observed a changed restored root and failed. Both mutations were restored.
Full StateV2 integration, history/DA storage, block-final anchors and host engine
registration remain open; a small frontier cannot replace the full output archive.
After restoration, the Cell, tree-ABI and real-ABI CTest groups each passed three
consecutive runs (35.20 seconds total). No large database experiment was required
or counted as evidence for this bounded codec.

### Disk exhaustion correction and clean-space revalidation (2026-09-06)

Counter disk integration left every completed fixture behind. Before maintenance,
the filesystem had only 1.9 GiB available and reported 100% usage. After checking
for live test processes and accessible fixture file descriptors/working directories,
explicit maintenance removed 900 exact Counter fixture directories and retained
the newest ten complete fixtures. Before deletion, 15,294 top-level diagnostic
files were archived in
`build/counter-fixture-diagnostics-1788652918935140968.tar.gz` (about 14 MiB).
Deleted database directories are not recoverable from that archive; they require
rerunning their fixtures. No unrelated Rust, integration or worktree artifacts
were cleaned. Available space rose to 176 GiB, then remained about 175 GiB after
revalidation (81% filesystem usage).

The parent-owned Counter lifecycle now removes a fixture only on successful
child completion, including early returns. Failures retain the complete fixture,
save child output in `lifecycle.log`, and report the path. The path is also printed
before execution for interrupted runs. Serialized admission permits at most 16
managed fixtures by default, counting active, failed and interrupted runs; reaching
the limit refuses new work rather than evicting potentially live diagnostics.
See [the retention policy](counter-fixture-retention.md) for explicit maintenance.

Three independent mutations proved the regression tests detect missing success
cleanup, deletion on failure, and bypassed admission limits. All were restored.
The final 13-test Counter group passed twice per test (3.12 seconds total), with
zero managed integration fixtures remaining and all ten legacy fixtures preserved.
The ordinary state-snapshot and real-crypto-ABI tests also each passed twice
(75.04 seconds total). The maintenance utility refused a dry run while CTest was
live, confirming its process guard.

With ample disk headroom, the opt-in `LargeSingleAccountDownloadAndImport` test
passed again in 184.1 seconds: 2,000,000 nullifiers, an 83,933,657-byte BoC,
4,000,006 imported Cells and 371,934,035 spool bytes. It exercised TCP download,
import, database reopening and continued state use. Its retained database is
`/tmp/uno-snapshot-celldb-cwvxb8`; the root is
`20BBED0D6F111FC861106DC4AFB1712F61633C90699CA8D1552CF3BD14513FAF`.
These are fresh functional results, not slot-performance measurements or full
validator-network acceptance. Earlier explicit ENOSPC failures are environmental
failures, not implementation-defect evidence; this does not claim to reproduce
every historical disk-adjacent failure.

### Height-indexed Anchor Window persistence

`uno/core/anchor-window.h` reuses the historical oldest-to-newest root-chain
storage idea, but not its mutable push API or permissive decoder. This is an
unactivated codec (`0x554e4130`), not a frozen StateV2 constructor. Capacity and
resource ceiling are explicit caller inputs: neither 100 blocks nor a wall-clock
duration is silently chosen. The prototype starts with the genesis root at height
zero and requires each subsequent height exactly once. Repeated roots occupy
separate entries so empty blocks still age old anchors. Immutable return values
let the engine retain its block pre-state window while constructing the next one.

A 128-bit header stores tag, height and count with exactly one reference. Each
following ordinary Cell contains exactly 256 root bits and only the required next
reference. Count must equal the lesser of capacity and the number of heights
since genesis, calculated without wrapping at maximum height. Oversized counts
reject before traversing the chain. Library Cells are not implicitly resolved;
VM read errors, incomplete proofs and execution-budget exhaustion return errors.
Configuration changes to capacity require a separate migration policy; decoding
with a different capacity is not such a policy.

Tests cover eviction, repeated idle roots, immutable pre-state, rejected repeated
or skipped heights, maximum height, BoC round trips and continued execution,
trailing bits/references, special Cells, and faults at every Cell read. A linked
tree test appends two distinct leaves and includes only the block-end root in
the successor window, then restores both tree and window and advances empty
blocks. The initial synthetic second leaf was the upstream empty-leaf encoding,
so it did not change the root; the corrected test explicitly asserts that the
intermediate and final roots differ before checking exclusion.

Independent mutations removed eviction and exact node bit-length validation.
The tests failed respectively on excess window size and acceptance of trailing
data. Both mutations were restored; `test-uno-used-nullifiers` and
`test-uno-tree-cell` then each passed three consecutive runs (1.88 seconds total).
This is component/composition evidence only:
production StateV2 authentication, transaction admission against the frozen
pre-state window, and the single end-of-block commit still require integration.

### Atomic note-state composition and cross-field restoration

`uno/core/note-state.h` combines the real tree frontier, full NullifierState
(used, reserved and owner dictionaries) and Anchor Window. Its prototype Cell
tag is `0x554e5330`, with three references and a strict three-bit optional-root
envelope for the dictionaries. This is a note-state component, not the complete
StateV2, transaction-admission interface or a production engine registration.

Block-end assembly/restoration requires tree root == latest anchor and used
nullifier count == next note position, counting every paired Action. Used-set
count is derived during dictionary validation and maintained only by successful
immutable insertion; it is not trusted as a serialized counter. Reserved leaf
count is derived from the authoritative reserved-nullifier dictionary, bounded by
remaining tree capacity, because every reserved paired Action needs one leaf.
Owner/manifest consistency remains validated by NullifierState. Reservation
counting scans pending keys; the cost must be measured and included in resource
policy, not advertised as constant-time restoration.

`apply_spend_effects` consumes effects from already verified spend bundles. It
checks explicit bundle/per-bundle/aggregate limits and successor height, freezes
the original Anchor Window, stages nullifier consumption in candidate order,
appends all outputs without consuming reserved capacity, and pushes one final
anchor. A duplicate in a later bundle or a late tree-ABI rejection discards all
staged changes. Empty blocks advance height/window without adding leaves. The
method deliberately does not claim to verify proofs/signatures, fees, expiry,
cmx reservation rules, system receipts or complete envelope authorization: the
future engine must verify those and atomically commit accounting, messages and
the output archive with this result. Mixed system/user execution remains open.

Tests cover late duplicates, malformed commitment rejection after dictionary
staging, successful retries, historical replay rejection after BoC restoration,
same-block intermediate-root rejection and next-block acceptance, cheap limits,
empty-block aging, reserved-key exclusion, terminal reservation release, and
cross-field/root-envelope corruption. Injecting each of the three VM read failure
classes at every read during restore and spend application leaves the source
Cell hash unchanged and allows a subsequent retry. Three independent mutations
removed pre-state anchor membership, tree/anchor equality and paired-count
equality. Each accepted a specifically forbidden input and failed its test;
all mutations were restored.

After rebuilding affected targets, the used-nullifier, tree/note-state and
ordinary snapshot groups each passed twice (65.14 seconds total). Additional
root-envelope negative tests were then rebuilt, and the used-nullifier and
tree/note-state groups each passed three further runs (4.09 seconds total).
No large snapshot performance result or complete UNO network acceptance is
claimed by these checks.

### Real bundle verification connected to atomic private fee application

`CryptoVerifiedTransfer` can be constructed only through the existing complete
bundle verifier in Transfer context. It owns the verified bundle bytes, fee and
digest; later mutation of the caller's input cannot change applied nullifiers,
outputs or retained authorization material. Invalid bundles return an absent
value, whereas local/ABI failures retain their Result error classification.
This type proves only crypto acceptance and the transfer public-value equation.
Its supplied digest still must come from the future canonical envelope layer;
it does not establish network/expiry/fee-policy admission on its own.

`PrivateTransferState` combines the note-state component with checked N/F/W
accounting. Its unactivated `0x55505430` Cell prototype has 416 bits and exactly
one note-state reference. The six 64-bit amount words preserve full unsigned
128-bit values. Assembly/restoration rejects aggregate overflow as well as
malformed headers. Block application checks aggregate resource limits, stages
each `N -> F` debit and the effects extracted from the same verified bundles,
then returns both together only if note-state application succeeds. Withdrawals
are unchanged; an empty block advances the window without charging a fee.

The real ABI fixture now uses its fully verified output-only bundle as an
explicit test bootstrap (5,000 nanotomi), then applies its real spend through
the verification token and state component. It observes N=4,900, F=100, W=0,
four total paired outputs/nullifiers and height one. It checks caller-input
mutation isolation, invalid digest/proof/fee, local verifier failure, duplicate
consumption, resource rejection, insufficient N, unchanged source state, BoC
restore/replay rejection and a subsequent idle block. No proof is mocked here,
but the funding bootstrap is not a runtime ShieldClaim or Reserve ceremony.

Additional codec tests cover high-bit and low-word round trips for all three
amounts, aggregate overflow, trailing bits/references, absent/special Cells and
idle preservation. One mutation allowed a failed spend verification to produce
a crypto-verified token: the real fixture reported acceptance of the wrong
digest. Another omitted the fee-accounting update: the fixture reported missing
expected fee/effect state. Both were restored before final verification.

Full canonical wire/sighash construction, expiry and fee policy, complete
actions/auth/data roots, system-message processing and production host
registration remain open. These component results are not M3 devnet acceptance.

After restoration and rebuilding both affected linked targets, the amount,
used-nullifier, tree/note-state and real-ABI CTest groups each passed twice
(26.93 seconds total). Real fixtures were freshly generated by the locked Rust
test for each real-ABI run.

### Derived private-transfer transcript and real signature binding

`uno/crypto/src/transfer_transcript.rs` adds a Rust-only, explicitly experimental
transcript candidate. Its [layout and dependency record](../uno/crypto/TRANSFER_TRANSCRIPT.md)
spell out integer widths, field order, length prefixes and distinct txid,
sighash and authorization domains. PrivateTransfer's absent external fields
and zero public in/out values are explicit; this is not a generic system-action
or mint encoder. Header identity, expiry/nonce/fee, all paired Action data and
per-Action KEM bytes enter txid. Proof and signatures enter only the separate
authorization digest. Input size limits are checked before streaming the fields.

`verify_transfer` derives the sighash from the same typed encoded object used
for primitive decoding and full context verification, rather than accepting a
sighash argument. Expected identity/limits still require authenticated policy;
canonical Cell decoding, expiry enforcement and fee-policy admission are not
implemented by this Rust entry point. The existing C++ ABI/digest-taking path
is unchanged and must be connected in a subsequent integration step.

The crypto-hash skill's advertised BLAKE3 backend was absent from its actual
script, so it was not used as a hash oracle. The implementation pins blake3
1.8.7 and its new transitive packages without bumping existing dependencies;
the dependency document records checksums, VCS identity, licenses and upstream
sources. Known-answer tests use upstream empty/three-byte vectors. Local
transcript snapshots are candidate-layout regression data, not an independent
production-wire specification or scheme freeze.

The real-proof fixture now signs the same proven spend against the derived
digest, verifies it, and rejects nonce/KEM modifications at spend-signature
validation. Four-byte KEM test placeholders prove only byte binding, not hybrid
encryption. Independent mutations omitted nonce or byte-string length prefixes:
the real signature test accepted a forbidden nonce change, or the field-boundary
test observed identical hashes for (ab,c) and (a,bc), respectively. Both mutations
were restored. All 23 enabled Rust tests then passed, including the fixed-VK
snapshot; the one ignored test remains an explicit diagnostic export.

After rebuilding the C++ linked targets, the Rust, real-ABI and tree/note-state
CTest groups each passed twice (45.80 seconds total). A final test-only change
made the fee mutation use checked arithmetic, then both transcript tests passed
again. The generated C header did not change.

## M1 real-manager network baseline (2026-09-06)

`scripts/m1-real-manager-sync.py` now runs four actual validator-engine processes,
one DHT process and a subsequently created cold observer, each with its own
database. It reuses the existing tostester network infrastructure, a private
test genesis (global ID -23902), and loopback peer addresses. It does not use
manager-disk or fake block acceptance. Only trusted genesis files are shared;
no warm database, archive or later block is copied to the observer.

This is **native/masterchain baseline evidence, not Counter or UNO acceptance**.
The script waits for a finalized masterchain target before creating the cold
node, waits for that node to catch up, compares the exact pre-existing block ID,
and requests its header again after stopping all four warm validators. That
last request proves local availability in the still-running cold node, not a
database-reopen or persistent-snapshot test. Warm logs contain real simplex
finalization with three-signature certificates; this is not yet evidence of
BlockTransition committee validation.

Reproduction requires Python 3.14 with tostester's bitarray, pynacl and
pycryptodome dependencies, and these freshly built targets:

```sh
cmake --build build --target validator-engine dht-server create-state generate-random-id toslibjson -- -j48
build/m1-real-network-env/bin/python scripts/m1-real-manager-sync.py
```

The local interpreter environment is not a checked-in dependency artifact.
The runner retains logs and report.json for success and failure, refuses fewer
than 20 GiB free, and admits at most three retained runs under its own prefix.
An operator must inspect those runs before making room for additional runs;
it never deletes another experiment or stops processes to acquire ports.

At base revision `2990c7699`, the initial run `m1-real-manager-run-e_wc69xk`
passed (target 17, cold height 47). The mutation stopped all warm validators
immediately before starting the cold node: `m1-real-manager-run-lv0hyfcw`
failed at the cold reach deadline with TimeoutError and passed=false, using
`--join-timeout 15`. Restoring the source passed again in
`m1-real-manager-run-duqmz1am` (target 18, cold height 48). This mutation tests
the harness's dependency on a live advancing network, **not** rejection of
forged proofs, altered state roots or invalid signatures.

The next concrete integration gap is candidate production: the real collator
requires a non-null candidate for BlockTransition, but the only current supplier
of `CollateParams::workchain_block_candidate` is manager-disk. Real node
startup also does not register Counter. A test-only real-node Counter setup and
candidate source are required before this harness can drive wc2 batch replay.
Authenticated invalid-proof/state tests, Counter committee consensus and cold
state acquisition, large valid state, reopening and resource bounds remain
open M1 gates. No UNO synchronization gate is accepted by this baseline.

### Counter real-network genesis prerequisite

The tostester configuration now has an opt-in `counter_workchain` fixture.
It requires global ID -23903, version 15 and unsplit shards before invoking
the genesis generator. It reuses the existing Counter account-state generator,
adds a v2 wc2 descriptor and capBlockTransition, and makes the extra trusted
zerostate available in each node's static directory. Initially no ingress
parameter was included; the real-node follow-up below adds the required test
ingress envelope. The default template rendering remains
unchanged; ordinary networks have no extra shard or host capability.

`test/tostester/test_counter_genesis.py`, run with the local Python environment,
passes two tests including real create-state generation with the option both
off and on. It independently parses generated configuration and checks wc2
presence, capability, descriptor engine ID, split depths, state hashes and the
extra state's global/workchain identity. Omitting descriptor injection makes
the enabled test fail because wc2 is absent. Removing profile admission makes
all four rejection cases fail at the explicit generator-invocation sentinel;
the restored checks reject before invoking the generator. Both mutations were
restored. These tests do not start nodes or establish batch replay. Candidate
production and test-only Counter registration remain the next integration work.

### First Counter committee and cold-join run

The explicit `test-counter-validator-engine` target now compiles test-only
Counter registration and a fixed increment-one candidate source. It is excluded
from default builds and installation. Production startup compiles neither. An
optional bounded, thread-safe in-process source in CollatorOptions can acquire
candidate data only after BlockTransition resolution, when no explicit candidate
exists; source errors and null results fail closed. Candidates still use the
normal commitments and independent validation. This is not a production UNO
mempool implementation or an engine execution bypass.

`scripts/m1-real-manager-sync.py --counter` selects the test binary and isolated
wc2 genesis. Real startup first exposed a missing `needCapabilities` flag in
MasterchainStateQ configuration extraction: the local execution gate saw zero
version/capabilities despite correctly encoded ConfigParam 8. The flag is now
requested. The next startup rejected the absent ingress table; the isolated
fixture now includes the same development ConfigParam 84 envelope as the disk
fixture. All participants use the new binary with version 15 and capability;
this is explicitly not an old-node compatibility or deployment/upgrade test.
The two failed startup runs were stopped after their validator processes had
exited. Their full directories were verified against
`build/m1-counter-startup-failures-20260906.tar.gz` before moving originals to
trash. No unrelated files or running nodes were targeted.

Run `m1-counter-network-run-bk5p2m96` then passed: four real validators produced
wc2 blocks, the cold observer acquired the exact pre-existing wc2 block 17,
and both that header and masterchain block 18's header remained available after
all validators stopped. Cold masterchain height was 48. Validator logs show
wc2 ValidateQuery execution and real three-signature simplex finalization.
The observer is not a committee member: its header acquisition is not evidence
that it independently executed the batch. Cold executor-state checks, forged
proof rejection, large authenticated snapshots and resource bounds remain open.
The runner keeps explicit unaccepted/untested fields in its report and caps
retained directories at three per native/Counter profile.

Mutation run `m1-counter-network-run-j96n30tn` compiled the test candidate source
to return null instead of increment one. Masterchain progress succeeded, but
the wc2 collator rejected the candidate/scope mismatch and the runner timed out
specifically in counter_tip (passed=false). Restoring and rebuilding the source
passed again in `m1-counter-network-run-sa3gs785`: Counter target 17, masterchain
target 18, cold masterchain 48. Production validator-engine also rebuilt, and
`test-workchain-block` plus `test-counter-disk-integration` passed (1.23 seconds).
The real-genesis tests passed with the required ingress table both present in
the enabled fixture and absent in the default fixture. Logs now write without
file buffering so early node failures are visible before harness shutdown.

### Cold Counter executor state and database reopening

The Counter runner now queries the executor account at the exact wc2 block ID
obtained before cold join. The Python client wraps raw.getAccountState in
withBlock; the existing C++ client validates the account proof against that
requested block. The runner checks response block identity, transaction identity,
wrapper/engine shape and value `40 + block.seqno` for the fixed increment-one
fixture. It then stops all warm validators, stops and starts the actual observer
on its existing database, creates a fresh client, and compares the same block's
executor data and transaction ID. No warm database is copied. The original cold
process log is saved separately before the restart would truncate it.

Initial run `m1-counter-network-run-8ascnmf1` passed for wc2 block 16 (value 56),
masterchain target 17 and cold height 48, including the offline-warm restart.
The harness had retained a closed client after stop; clearing that reference
enables the new connection. Removing the reset in the independent mutation run
`m1-counter-network-run-ogynv9_f` let initial synchronization/state checks pass
but failed specifically at the restarted-node reach deadline. The reset was
restored. The reports still do not claim malicious proof rejection, large-state
snapshot acquisition or full UNO synchronization acceptance.

Four small instrument tests in `test/tostester/test_counter_state_check.py`
cover the pinned/default request encoding and correct/genesis/off-by-one values.
They use synthetic responses, not cryptographic proofs. Removing the value
check makes both forbidden-value tests fail; removing withBlock makes the
request-encoding test fail. Both mutations were restored and all four passed.
The three previous header-run directories were compared against the complete
`build/m1-counter-header-runs-20260906.tar.gz` archive before moving them to
trash; the per-profile retention cap remains three directories.

The final restored run `m1-counter-network-run-wks1grij` also passed: wc2 block
17 (value 57), masterchain target 18 and cold height 48. The account data and
transaction identity remained identical after the observer process/database
reopened with all warm validators stopped.

### Real-manager proof root-binding probe

The independent Counter executable now launches a test-only actor after it
receives a non-genesis masterchain state. It obtains that real network-produced
block's stored proof through the real manager, submits the original proof for
successful revalidation, then flips one bit of the declared root hash while
retaining the genuine Merkle proof. It rebuilds a structurally valid BlockProof
envelope and submits it under the conflicting identity to validate_block_proof.
Success requires rejection at the incorrect-root-hash check, not a timeout or
BoC parsing error. The runner requires a passing probe from all four validators
and the cold observer; a failed or missing marker fails the run.

Run `m1-counter-network-run-9xsigcq3` passed this probe as well as Counter state
acquisition/reopening (wc2 target 17, masterchain target 18, cold height 47).
The original proof may hit an already-verified handle, so this is deliberately
**not** an uncached signature revalidation test. The conflicting declaration is
checked before that cache shortcut. There are two root-binding checks in the
parser path; this test claims rejection of conflicting roots, not that either
individual check is uniquely necessary.

The forged bytes enter through a local call to a real manager after proof
acquisition, not through a malicious peer's download response. Accordingly the
report adds manager_proof_root_binding_tested while leaving the broader
invalid_proof_rejection_tested and uno_sync_accepted false. Hostile remote proof
transport, new-block signature rejection and large authenticated snapshot
acquisition remain unaccepted. No production proof verification code is changed.
Previous state-run directories were verified against the complete
`build/m1-counter-state-runs-20260906.tar.gz` archive and moved to trash, retaining
recoverability without increasing the three-directory per-profile cap.

The negative-control build disabled the root flip, submitting an unchanged
valid proof in the negative step. Run `m1-counter-network-run-8q2bt_z3` failed
with the probe's acceptance assertion (`conflicting proof root was accepted`),
not a timeout or setup error. This proves the rejection test does not always
pass; it is not a mutation of either production root-check guard. Restoring the
flip and rebuilding passed in `m1-counter-network-run-c_tb1d1w` (Counter target
17, masterchain target 18, cold height 48), including executor-state reopening.
The ordinary validator-engine target rebuilt successfully with the test actor
excluded, and all four state/request instrument tests passed.

### Uncached Counter broadcast-signature probe

The test-only actor now also obtains a live wc2 TopBlockDescr from the real
manager's collator-facing interface, extracts its genuine committee signatures
and first proof-chain link, and reconstructs the equivalent BlockProof link.
It calls validate_block_broadcast_signatures with original signatures, then with
one bit changed in a 64-byte signature, then with the original signatures again.
All four validator processes must pass this probe; the cold non-committee
observer retains the proof/state probes without a signature-storage obligation.
The report distinguishes manager_broadcast_signature_rejection_tested from
remote transport rejection, which remains untested.

This signature-only ValidateBroadcast path does not take CheckProof's
already-verified-proof shortcut. The original block identity, session, slot,
candidate transcript, signer identifiers and signature length are retained.
Following the Ed25519 skill's encoding constraints, the test changes signature
content rather than malformed lengths or keys, and uses the actual consensus
verifier rather than a generic detached-signature replacement.

Two setup runs (`eeveyzps`, `e1pzpx0a`) demonstrated that the separate signature
DB record is unsuitable for this lookup: RootDb explicitly returns notready
once its block moves to archive. Bounded retry did not resolve it. Those runs
are in `build/m1-counter-signature-setup-failures-20260906.tar.gz` with full
directories verified before moving originals to trash. The live description
keeps the desired wc2 test scope without changing database retention.

Run `syj573ah` then caught a mutation-fixture bug: BufferSlice::clone shares
storage, so modifying the TL signature also corrupted the retained positive
control. Its third (original-signature) check correctly failed. The test now
deep-copies the selected signature bytes before flipping the bit. That failed
run is preserved in `build/m1-counter-signature-alias-failure-20260906.tar.gz`.
The earlier proof-only runs were likewise archived and verified in
`build/m1-counter-proof-runs-20260906.tar.gz`. These are test-fixture corrections,
not changes to production signature validation or archive policy.

Run `m1-counter-network-run-57xajl95` passed all four validators' signature
probes and the existing cold-state/reopening checks (Counter target 17,
masterchain target 18, cold height 48). The rejection reached the actual
signature verifier (`failed signature check: bad signature: Wrong signature`).
An independent mutation replaced ValidateBroadcast's final-signature check
with success in the isolated test binary. Run `m1-counter-network-run-qzl2k0yx`
then failed because the corrupted committee signature was accepted. The actual
verification call was restored; validator/validate-broadcast.cpp has no lasting
diff. This mutation tests loss of the verifier, not a changed error string.

The restored full run `m1-counter-network-run-slng2pmd` passed (Counter target
17, masterchain target 18, cold height 48), including the old proof-root and
database-reopening checks. Production and test node targets rebuilt; the probe
marker is present only in the test binary. The BlockTransition unit and disk
integration CTests passed (1.12 seconds), as did all four Python state/request
instrument tests. Remote malicious-download orchestration and large-state
synchronization remain outside this result; M1 is not marked complete.

### Cold Counter zerostate acquired from peers

The cold-join runner now withholds extra-workchain static state files from the
observer's first startup. FullNode.run exposes an opt-in `seed_extra_states`
argument (default true, affecting only initial static-file population); the
runner passes false and checks that only the masterchain/native static files
exist. No production node behavior or genesis definition changes.

Run `m1-counter-network-run-0yxo59ae` passed with the observer obtaining the
245-byte wc2 zerostate from a peer. Its log records DownloadState's peer
selection and completed download of `(2,8000000000000000,0)`. The runner now
requires both events, as well as the existing pinned executor-state and
database-reopening checks. The report exposes
`cold_counter_zerostate_peer_download_tested` separately from full UNO sync.
The ordinary zerostate downloader checks the received file hash and parsed
state root; this run exercises successful acquisition, not rejection of a
hostile peer's bytes. This is a small Counter genesis, not a large UNO snapshot
or the persistent-state streaming importer.

The negative control restored local extra-state seeding and adjusted the
static-file-count check to allow that deliberate setup. Run
`m1-counter-network-run-ukc2fqlp` then passed account acquisition but failed the
peer-download assertion. Thus the new evidence requirement detects the old
local-static shortcut independently of the setup count. Both temporary edits
were restored before the final run. The previous three completed signature
runs were archived and verified in
`build/m1-counter-signature-runs-20260906.tar.gz`; originals were moved to trash
without raising the three-run retention cap.

The restored run `m1-counter-network-run-u762rx3s` passed (Counter target 17,
masterchain target 18, cold height 48), including peer acquisition and database
reopening. The four state/request instrument tests and two genesis tests also
passed. M1 remains open for remote malicious-response rejection and large-state
synchronization; M3 expansion remains paused.

### Remote zerostate file-binding rejection and recovery

`--counter --counter-reencoded-state` enables one faulty wc2 zerostate response
per serving process. The test-only full-node library reserializes the genuine
state with BoC mode 0 after the server's archive integrity check, before the
normal overlay/RLDP response. The resulting 224-byte BoC is valid and has the
same Cell root as the genuine 245-byte file, but a different SHA-256 file hash.
Thus it reaches the receiver's file-binding check without relying on malformed
serialization or a changed state root. Subsequent responses are genuine so the
same run must reject, retry, synchronize, and reopen its own database.

The injector is compiled only into `full-node-counter-network`, an excluded
test library replacing `full-node` for `test-counter-validator-engine` alone.
The normal validator-engine links the normal library. Binary marker checks
find `COUNTER_ZERO_STATE_REENCODED` in the test binary and not the production
binary. No receiver validation policy is changed by this feature.

The first run (`ocej5x1i`) exposed an incorrect test expectation: this live
cold-join uses WaitBlockState::got_state_from_net, not
DownloadShardState::downloaded_zero_state. It rejected the bytes correctly but
the runner looked for the other actor's diagnostic. Correcting the expected
path passed in `zeoqah_z`. The runner also compares the observer's archived
wc2 zerostate bytes with the genuine source before checking the rejection log;
this is the independent persistence property, not an error-message assertion.

Mutation run `vx2numu5` removed WaitBlockState's in-memory zerostate file-hash
guard. The node still acquired the expected account state, but persisted the
224-byte representation, and the archive-byte assertion failed. Independent
parsing confirmed identical Cell roots for both files. The crypto-hash skill's
SHA-256 backend confirmed different file digests: genuine `b23a56f0...c4c265b4`,
persisted `7f57e012...ae489383`. Restoring the guard leaves no diff in
validator/downloaders/wait-block-state.cpp. This tests removal of the actual
binding check, not rejection-message wording.

The previous peer-acquisition runs were archived and verified in
`build/m1-counter-peer-state-runs-20260906.tar.gz`; the diagnostic-mismatch run
was archived and verified in `build/m1-counter-reencoded-setup-20260906.tar.gz`.
Original directories were moved to trash and remain recoverable, without
raising the retention cap. This result covers one remote zerostate corruption
class, not remote invalid block proofs/signatures, hostile checkpoint selection,
large-state import, or full UNO synchronization. M1 remains open.

The restored final run `m1-counter-network-run-x3cwezg7` passed the independent
archive-byte assertion, remote rejection/recovery, pinned account state and
database reopening (Counter target 17, masterchain target 18, cold height 48).
Both node targets and the Counter test executables rebuilt. BlockTransition
and disk integration CTests passed in 1.37 seconds; the four Python state/request
tests passed as well.

### Misbound wc2 proof received over the network

`--counter-misbound-proof` arms the isolated sender only after the initial four
validators have produced blocks. BlockFullSender changes one bit in the
proof_for file hash of its first wc2 response per process, preserving the
requested block ID, genuine block bytes and Merkle root. The response travels
through the ordinary full-block overlay/RLDP path. The test-only receiver
observer decodes the declared identity and records the real manager callback's
accept/reject result; it never substitutes its own verification result.

Run `gq5i1y4p` passed with all four servers injecting responses and the cold
node rejecting each. Rejection actually occurs during create_proof_link's
virtual-root construction, before CheckProof's further identity checks. This
is remote proof identity-binding coverage, not a signature-verifier test or a
claim that any one of the repeated identity guards is independently necessary.

Mutation run `5ttab80l` temporarily bypassed the manager's wc2 proof-link
validation entry point. The receiver observer recorded acceptance and the
concurrent Python watch failed immediately with `real receiver accepted a
misbound peer proof`. It did not depend on an error-message change or a later
state-sync timeout. The watch cancels and awaits the network exercise so its
owned processes are stopped on failure. The bypass was restored exactly;
validator/manager.cpp has no lasting diff. Production node marker searches
exclude all three test injection/observation markers, while the test binary
contains them.

Previous completed state-fault runs were archived and verified in
`build/m1-counter-reencoded-runs-20260906.tar.gz`, and original directories
moved to trash without increasing the retention cap. Remote invalid signature
and checkpoint cases and large-state synchronization remain open; the report
records this narrow result separately as `remote_misbound_proof_rejection_tested`.

The restored combined-fault run `3ewjis3v` passed both remote rejection modes,
correct state persistence, pinned account checks and database reopening
(Counter target 17, masterchain target 18, cold height 48). Both node targets
rebuilt, the two Counter CTests passed in 1.48 seconds, and all four Python
state/request tests passed. M1 is still not complete; M3 expansion remains
paused.
