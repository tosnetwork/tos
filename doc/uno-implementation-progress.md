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
- Registered Counter replay and scope/configuration tests pass; removing the
  account-scope guard causes the exact-error assertion to fail. Guard restored.
- `test-workchain-block` (twelve cases) and the full `validator-engine` target build
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
Witness placement and final transaction/account/shard wrapping remain pending.

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
  `ValidateQuery::check_this_shard_mc_info` currently call account resolution.
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
   the descriptor registry; implement witness placement and final transaction wrapping.
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
