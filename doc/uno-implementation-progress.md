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
  switched to these entry points.
- Registered Counter replay and scope/configuration tests pass; removing the
  account-scope guard causes the exact-error assertion to fail. Guard restored.
- `test-workchain-block` (seventeen cases) and the full `validator-engine` target build
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
- State-only batch round-trip tests execute 40 -> 42 from a native shard,
  serialize the synthetic transaction, independently replay its description,
  commit the account, validate the resulting `AccountBlock`, rebuild the shard
  account dictionary and restore its BoC to read 42. Native balance remains zero;
  transaction LT is 10 and the new account end LT is 11.
- This initial wrapper rejects nonempty or malformed outbound-message maps,
  account execution phases and Native value changes. It cannot yet settle
  bridge messages, forwarding fees or operating budgets. Empty engine outbound
  messages now use the one-bit empty HashmapE encoding. Size-limit failure does
  not authorize serialization; changing staged engine data also rejects it.
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
Native state-only transaction/account wrapping and witness storage are implemented;
full shard wrapping, queue settlement and collator wiring remain pending.

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
- Both configuration paths call `validate_required_workchains`, which still
  requires account execution. Block engines therefore remain deliberately
  unavailable to the node until block dispatch is integrated.
- The block path must replace per-account transaction processing and supply
  canonical synthetic transactions to block-extra, account/state-update,
  message-queue and value-flow verification. Bypassing only scope checks is
  insufficient and would not constitute M1.
- `CheckAccountTxs::check_one_transaction` still reconstructs a per-account
  `Transaction` after its scope check. Block execution needs a separate host
  path, not removal of that rejection.

## Remaining requirements

This is the beginning of M1, not an enabled workchain. The interface is not yet
called by the collator or validator and its context cells are not authentication
proofs by themselves.

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
