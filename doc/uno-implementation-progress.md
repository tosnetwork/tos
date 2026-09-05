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
  admission limits or native storage limits. Live dispatch has not yet been
  activated for these entry points.
- Registered Counter replay and scope/configuration tests pass; removing the
  account-scope guard causes the exact-error assertion to fail. Guard restored.
- `test-workchain-block` (nineteen cases) and the full `validator-engine` target build
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
- Synthetic `trans_workchain_batch_v1$1000` description: two 256-bit
  input/effects commitments and three uint64 resource counters, exactly 708 bits
  with no references. Both generated and handwritten transaction parsers
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
  This branch still rejects split/merge, pending incoming messages and an existing
  dispatch queue. Persisted outbound queues are now supported. Native dequeue
  descriptors produced during cleanup still prevent this branch from proceeding;
  delivered-message cleanup and deferred-queue progress need further integration.
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
- Validator batch replay recomputes messages and fees from authenticated pricing.
  Afterwards it shares the existing account outbound-message checks: every output
  must have a permitted OutMsg record with the right source transaction and origin
  metadata, and obey deferred-message ordering. The normal OutMsg/queue checks
  still verify the reverse transaction reference and queue state update. Native
  incoming message settlement is still rejected.
- The disk test now sends two messages carrying 100 atoms each to workchain 0.
  Fixture forwarding prices charge 100 per message: 33 collected locally and 67
  retained for forwarding. Block 1 asserts 1000 -> 600 balance, 334 exported, 66
  collected and queue size 0 -> 2. An independent database imports this block.
  After restart it sends another pair (600 -> 200, queue 2 -> 4), rejects a third
  pair for insufficient budget, then creates a no-output block that preserves
  balance 200 and queue size 4. This tests complete outgoing block value flow and
  failure atomicity across restart, not receiving-chain execution or bridge finality.
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
  singleton executor state. Its context contains only previous shard, configuration
  and finality roots supplied by the host. It checks the final transaction link,
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

The engine result now contains `new_engine_state`, not a final shard state or
synthetic transaction. This removes the previous circular interface: a final
shard account dictionary contains the transaction hash, so it cannot be an
input to that same transaction's commitment.

`input_hash` is the Cell hash of `WorkchainBlockInput` v1 (tag `57424931`,
references in order: previous shard state, candidate, configuration, finality).
`effects_hash` is the Cell hash of `WorkchainBlockResult` v2 (tag `57425232`).
`make_workchain_batch_description` constructs both commitments; batch replay
checks the input commitment before executing, independently computes the effects
and checks their commitment plus explicit resource counters. Engine selection
and authentication of configuration/finality are still the host's responsibility.
These use the native Cell representation hash, not the user transaction-ID hash.
Native transaction/account wrapping, witness storage and transaction-level outbound
settlement are implemented. Live full-shard acceptance, outbound queue persistence
and outgoing block value flow are tested. Incoming/deferred messages and delivered
queue cleanup remain incomplete.

Commitment tests cover serialized-description replay, all four input references,
all six engine-effect references, missing cells and all three resource counters.
Removing the effect-hash comparison makes the effect mutation test fail;
removing the pre-execution input-hash check changes the exact rejection and fails
the input test. Both guards were restored.

The result envelope is not a `TransactionDescr` constructor or a replacement
for native `Transaction` validation. It is not yet inserted into block-extra;
synthetic transaction LT/value-flow semantics and host dispatch remain pending.
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
incoming/deferred message settlement, delivered queue cleanup, distributed
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

No production capability, network activation or value-bearing genesis is enabled.
