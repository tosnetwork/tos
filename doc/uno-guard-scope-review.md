# UNO guard scope audit

Read against commit `6ea2fbf80`. This is a removal-candidate audit, not a claim that the narrowed guards or all their controls have passed. No production implementation changes are proposed here.

## Confirmed unrelated inventory entries

Each path below occurred in the previous closure identifier inventory. Group reasons identify the matched operation; location alone is not the reason for exclusion.

### Storage-provider contracts

`withdraw` submits or dispatches a storage-provider contract withdrawal; it does not describe a confidential account closure obligation.

- `storage/storage-daemon/StorageProvider.cpp`
- `storage/storage-daemon/StorageProvider.h`
- `storage/storage-daemon/storage-daemon-cli.cpp`
- `storage/storage-daemon/storage-daemon.cpp`
- `tosctl/src/tl/api/src/tos/dynamic.rs`
- `tosctl/src/tl/api/src/tos/rpc/storage/daemon.rs`

### Cell and message ownership extraction

`withdraw_single_root`, `SliceData::withdraw`, or `withdraw_header` takes an owned value out of a Rust container. These files can participate in cell processing, but the matched operation is ownership extraction, not a persisted settlement right.

- `tosctl/src/assembler/src/disasm/tests.rs`
- `tosctl/src/block/src/boc.rs`
- `tosctl/src/block/src/cell/slice.rs`
- `tosctl/src/block/src/messages.rs`

### VM value extraction

The matched `withdraw*` methods move a stack item, integer, tuple, continuation, command variables, or complete VM stack. They are VM memory/value operations, not confidential withdrawal or obligation records.

- `tosctl/src/sandbox/src/blockchain.rs`
- `tosctl/src/vm/src/executor/blockchain.rs`
- `tosctl/src/vm/src/executor/continuation.rs`
- `tosctl/src/vm/src/executor/engine/core.rs`
- `tosctl/src/vm/src/executor/engine/storage.rs`
- `tosctl/src/vm/src/executor/globals.rs`
- `tosctl/src/vm/src/executor/math.rs`
- `tosctl/src/vm/src/executor/stack.rs`
- `tosctl/src/vm/src/executor/tuple.rs`
- `tosctl/src/vm/src/executor/types.rs`
- `tosctl/src/vm/src/smart_contract_info.rs`
- `tosctl/src/vm/src/stack/continuation.rs`
- `tosctl/src/vm/src/stack/integer/mod.rs`
- `tosctl/src/vm/src/stack/mod.rs`

### Prediction-market collateral

`Deposit`/`Withdraw` and corresponding opcodes belong to prediction-market collateral. `key_epoch` belongs to OrderJson/PredictionOrderV1 or PmAccountV1 trading-key identity. The wrapper validates workchain -1/0, not the UNO account state.

- `tosctl/src/node-control/commands/src/commands/nodectl/prediction_cmd.rs`
- `tosctl/src/node-control/contracts/src/prediction_market.rs`
- `crypto/smartcont/prediction-market.tlb`

### AgentAccount Agreement authorization

`obligation_instance_id` and `obligation_id` identify Agreement-bound EconomicActionAuthorization/EconomicEffectAuthorization. These are the AgentAccount owner-authorized payment/effect requests, not a field in the confidential account or its closure state.

- `tosctl/src/node-control/commands/src/commands/nodectl/agent_cmd.rs`
- `tosctl/src/node-control/contracts/src/agent_account_custody.rs`

### CapabilityRegistry bonds

`WithdrawBond`/`withdraw_amount` and CAP_WITHDRAW_BOND_OPCODE refer to registry bond redemption, not UNO settlement obligations.

- `tosctl/src/node-control/commands/src/commands/nodectl/capability_registry_cmd.rs`
- `tosctl/src/node-control/contracts/src/capability_registry.rs`

### Nominator and staking positions

Deposit/withdraw identifiers encode staking and nominator requests or index their positions (`pending_deposit`, `withdraw_requested`, `deposited_total`). These contracts and query records are not the confidential account lifecycle.

- `tosctl/src/node-control/commands/src/commands/nodectl/pool_cmd.rs`
- `tosctl/src/node-control/contracts/src/liquid_controller/messages.rs`
- `tosctl/src/node-control/contracts/src/nominator/messages.rs`
- `tosctl/src/node-control/contracts/src/nominator_pool/messages.rs`
- `tosctl/src/node-control/contracts/src/nominator_pool/pool_impl.rs`
- `tosctl/src/node-control/contracts/src/nominator_pool/wrapper.rs`
- `tosctl/src/node-control/service/src/http/explorer_query_api.rs`
- `tosctl/src/node-control/service/src/indexer/indexer_task.rs`
- `tosctl/src/node-control/service/src/indexer/store.rs`
- `crypto/smartcont/liquid-staking/interaction.tlb`
- `crypto/smartcont/single-nominator-pool/single-nominator.tlb`
- `validator-engine/json-rpc-server-account-capability.cpp`

### ServiceActor revenue

`WithdrawRevenue`, SVC_WITHDRAW_REVENUE_OPCODE, and `withdrawable_revenue` describe ServiceActor earned revenue or its DTO. The indexer also indexes this revenue alongside staking positions.

- `tosctl/src/node-control/commands/src/commands/nodectl/service_actor_cmd.rs`
- `tosctl/src/node-control/contracts/src/service_actor.rs`
- `tosctl/src/node-control/service/src/http/agent_query_api.rs`

All 42 previous `tosctl/` and `storage/` entries are individually listed above. The three prediction-market epoch entries are also listed: the CLI, wrapper and TL-B contract schema. This does not claim these modules cannot use cells; their matched identifiers do not carry either guarded UNO property.

## Scope decision still pending

A fixed file list does not automatically detect an unconnected new source file. The existing new-file controls must not be retained only by injecting files which the real source reader cannot discover. A proposed alternative is explicit property entrypoints plus their referenced source closure, with new-file controls connected through that same path. That changes the boundary of the old unconnected-file controls and requires an explicit decision before claiming equivalent coverage.

## Validation already completed

- The real seven-step epoch behavior check passed on the merged source.
- In an isolated copy, replacing the persisted epoch/public-key comparison with `if (false)` made the real scenario exit 1 with `epoch behavior control did not identify a changed persisted epoch`. The repository scenario source was unchanged.
- `cargo test --locked --offline --lib -j2` in `uno/crypto`: 25 passed, 365.63 seconds.
- The same command in `uno/prover`: 8 passed, 689.75 seconds, including system COLLECT and both boundary configurations.
- `python3 uno/crypto/tests/kernel-gates.py -v`: 12 passed.
- Both unique `KernelGates.test_*` selectors referenced by `rng-acceptance.py` resolved and executed successfully. This is selector validation, not a rerun of the full RNG acceptance harness.
- The original closure inventory with all five existing controls passed, as did state-loader inventory and its controls. These are pre-narrowing results.
- `ctest --test-dir /home/tomi/uno-m3-refund-assert-build -R '^test-workchain-key-epoch-(inventory|behavior)$' --output-on-failure`: 2 passed. The inventory used the rejected directory-scope draft; only the unchanged seven-step behavior result is retained as evidence for the final scope work.
