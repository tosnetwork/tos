# Privacy workchain implementation progress

Branch: `feature/uno-privacy-workchain-v1`.

Design baseline: `memo@0c3fc8d0:TOS_UNO_PRIVACY_WORKCHAIN_V1.md`.
Base node revision: `5a6145cce`.

## Implemented

- Immutable block input/result interface and side-effect-free replay comparison.
- Result commitments cover state, synthetic transaction, outbound messages,
  actions, receipts, events, data availability and resource accounting.
- Counter fixture tests correct execution, input preservation, result field
  mutations, resource mutations, missing finality context and overflow.
- Mutation check: temporarily removing cell hash comparison makes
  `RejectEveryResultMutation` fail at its rejection assertion. Comparison restored.
- Separate block-engine registration/configuration resolution in the host
  registry, with explicit scope lookup, duplicate-key rejection and null-config
  rejection. Account resolution rejects block engines before account policy use.
- Registered Counter replay and scope/configuration tests pass; removing the
  account-scope guard causes the exact-error assertion to fail. Guard restored.
- `test-workchain-block` (four cases) and the full `validator-engine` target build
  pass with the existing Release/clang-21 build. CTest runs the new target.

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

## Remaining requirements

This is the beginning of M1, not an enabled workchain. The interface is not yet
called by the collator or validator and its context cells are not authentication
proofs by themselves.

1. Authenticate block configuration/finality and resolve execution scope through
   the descriptor registry; define the synthetic transaction encoding.
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
