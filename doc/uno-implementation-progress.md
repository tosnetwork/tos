# Privacy workchain implementation progress

Branch: `feature/uno-privacy-workchain-v1`.

Design baseline: `memo@0c3fc8d0:TOS_UNO_PRIVACY_WORKCHAIN_V1.md`.
Base node revision: `5a6145cce`.

## Implemented

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
consensus and network synchronization have not been accepted.
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

Remaining ingress work includes negative sender configuration lookup
coverage, a wrong-address Native wallet disk scenario, explicit alternate-address
encoding coverage, and authenticated activation/queue migration enforcement.
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
