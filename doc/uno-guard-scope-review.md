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

## Initial scope decision request (df8b10885)

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

## Adopted reachability boundary

The coordinator subsequently approved explicit entrypoints plus static references.
Both guards use `workchain_guard_reachability.py`; neither searches a directory
for matching identifiers. Their computed sets each contain 215 files on
`6ea2fbf80`. Both limits are 430 (twice that measured baseline). The limit is not
a snapshot to refresh automatically: exceeding it requests entrypoint review.
Each invocation emits the complete entrypoint/file list, count and external
include boundaries as JSON. Generated headers resolve to their committed inputs,
so building locally does not change this set.

Common roots and their roles:

- `crypto/block/workchain-account-settlement.h`: installs account effects and
  dispatches registration, rejection and closure Native settlement.
- `crypto/block/workchain-confidential-execution.h`: SEND/COLLECT state changes.
- `crypto/block/workchain-deposit-transition.h`: atomic Deposit state changes.
- `crypto/block/block.tlb`: input to the generated account/operation codec.

Epoch adds two roots: `crypto/block/workchain-registration-proof.cpp` is the
separately compiled host possession bridge; `uno/crypto/src/lib.rs` declares the
kernel modules that consume the epoch-bound requests. Closure instead adds
`crypto/block/transaction.cpp` for the Native refund/message materializer and
`crypto/test/workchain-m3-test-funding-operation.h` as the existing explicit test
operation exception. A header include does not imply its separately linked
implementation: that is why these source roots are named explicitly.

The closure token scan accepts C++/Rust/TL-B source suffixes. Native RPC `.tl`
inputs and generated platform `.in` templates appear in the dependency report,
but are not interpreted as confidential state declarations. Generated external
library code is not traversed. Rust module declarations follow local module
files; external dependency crates are not a second supply-chain scan.

LIMIT: this is lexical, static include/module reachability, not a call graph.
Runtime coupling, indirect references, macro-generated references and aliases
are not covered. New separately linked source units or schema generators need
explicit entrypoint review. Same-name identifiers outside this reachable set
are not covered. Existing inline test code within reached Rust source files is
still lexically inventoried; external test modules are not production roots.

## Additional removed closure entries

The previous audit enumerated the 42 `tosctl/`/`storage/` files and related native
contract schemas. These additional files account for the rest of the **55**
removed closure entries:

- `crypto/block/create-state.cpp`: Fift configuration-building words consume a
  `registration_deposit` amount and build the resource policy. They do not execute
  a confidential account transition or create its retained obligation view.
- `uno/archive/v1/core/accounting.h`: archived notes/withdrawals accounting and
  ShieldClaim operations, not the current account state.
- `uno/archive/v1/core/bundle-context.h`: archived ShieldClaim, Unshield and
  WithdrawalRefund bundle discriminators.
- `uno/archive/v1/core/crypto-verifier.h`: translates those archived bundle
  discriminators to the retired ABI.
- `uno/archive/v1/core/private-transfer-state.h`: archived note/fee/withdrawal
  state serialization.
- `uno/archive/v1/core/transition-budget.h`: archived `checked_prepare_withdrawal`
  arithmetic wrapper.
- `uno/crypto/include/uno_crypto_v0_retired.h`: version-0 ABI constants including
  UNO_WITHDRAWAL_REFUND. No current closure entrypoint includes it.
- `uno/crypto/src/ffi.rs`: the matched `deposit_id` is a borrowed D33 request field,
  not a persisted obligation representation. This file remains in the epoch
  guard through the explicit kernel root; it is not a closure source root.
- `uno/crypto/src/system_encryption.rs`: stateless D33 derivation/verification
  and its inline tests bind `deposit_id`, without retaining a lifecycle right.

Every retained closure hash is byte-for-byte unchanged from the prior snapshot;
only the 55 unreachable entries were removed. The epoch snapshot is re-expressed
using the extraction rule below; its matching file set drops exactly the three
prediction-market files identified above.

## Syntax units and controls

Epoch records a named epoch member declaration, an epoch-bearing expression, or
an epoch-bearing control header, qualified by its enclosing declaration scopes.
Calls and aggregate initializers remain balanced expressions: receivers and
argument/field positions affect what is written or bound. A neighboring field
or neighboring struct is not the same unit. Rust comma-delimited fields and
C++ semicolon-delimited fields are separated; TL-B records retain constructor
identity plus the named epoch member type. This is a lexical approximation,
not a full C++/Rust parser or proof of the absence of aliased writes.

Closure does not use C++/Rust semicolon fragments: it inventories selected
identifier tokens. Its three state representations and explicit test operation
retain whole-definition hashes intentionally, to detect new state that could
represent an obligation. TL-B semicolons terminate actual constructor records;
only UNO constructors enter the schema hash.

Controls retain the original properties and exercise the normal disk resolver:

- Epoch: a referenced new header writes epoch (unconditional and conditional);
  a retained member type and an existing assignment change; all are rejected.
- Epoch: unrelated adjacent C++ and Rust fields, an adjacent Rust struct and an
  unconnected same-name source do not change the inventory.
- Closure: new obligation field, referenced third-file obligation view, added
  operation constructor, changed explicit funding operation, and bucket
  `account_id` attribution all change the inventory. These are five controls,
  including the account-id control, not five plus a sixth existing control.
- The operation control extends the actual `block.tlb` generator input. TL-B
  has no include directive; a disconnected third schema is not falsely treated
  as part of the build. New-file discovery is exercised by the referenced view.
- Both resolvers reject an excessive include chain at the size-specific limit.
  Connected versus disconnected new-file controls use the same `Sources` reader;
  epoch also exercises a newly declared Rust module.

An isolated copy replacing the syntax-unit extractor with the old semicolon
split failed with `adjacent Rust field polluted an epoch declaration`.
An isolated copy removing literal-include traversal failed with
`literal new-file reference was not traversed`. Production sources were not
modified for either control. The first adjacent-struct fixture alone did not
expose the old splitter: intervening Rust array-type semicolons cut the old
fragment earlier. The adjacent-field fixture was added to exercise that actual
failure mechanism; the adjacent-struct check remains as well.

Validation mapping: Python reachability/extraction changes run in the existing
default closure/epoch inventory targets; the seven-step epoch behavior target
checks persisted transitions; the state-loader target checks that its independent
narrow inventory is unaffected. No production execution, ABI, schema, CMake or
Rust implementation is changed by this scope correction.

Final focused run: `ctest --test-dir /home/tomi/uno-m3-refund-assert-build
-R '^test-workchain-(m3-closure-expiry|state-loader-inventory|key-epoch-inventory|key-epoch-behavior)$'
--output-on-failure` passed **4/4**, 7.58 seconds. The epoch behavior target
executes the real seven-step sequence. This is not a claim of a full C++
regression run or of semantic completeness for either lexical guard.
