/*
    EVM Workchain — header-light bridge for the validator-manager seam.

    `validator/manager.cpp` walks every accepted EVM block's ext-msg
    descriptors and drives the deferred-apply queue defined in
    `evm/core/post-accept.h`. Including the full post-accept.h (and its
    transitive silkworm headers) inside validator/ would pull silkworm and
    evm-state into a TU that has no business depending on them; this thin
    shim exposes just the symbols the manager actually calls.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace td {
template <class T>
class Ref;
}  // namespace td

namespace vm {
class Cell;
}  // namespace vm

namespace evm_workchain {

/// Look up cached side effects for the accepted block's EVM messages, finalize
/// block-wide receipt/transaction roots, and publish them via
/// `apply_block_side_effects`. Messages must be passed in transaction order.
/// If an entry is missing, publish only the complete prefix so tx_index and
/// cumulativeGasUsed are never shifted onto later accepted transactions.
///
/// Audit #4 (2026-04-26): the lookup key binds tx_hash to seqno, timestamp,
/// rand seed, and parent hash so rejected candidates cannot collide with the
/// accepted one.
/// `chain_id` must come from the accepted workchain descriptor's vm_mode; it
/// is used only when deterministic replay is needed.
size_t apply_stashed_side_effects_for_messages(
    uint64_t accepted_block_seqno,
    uint64_t accepted_timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32],
    uint64_t chain_id,
    const std::vector<td::Ref<vm::Cell>>& msgs) noexcept;

/// Same as above, but with enough canonical context to deterministically
/// replay missing side effects. `initial_account_data` is the executor
/// account's cp.new_data from the previous canonical shard state; it may be
/// null when the executor account did not exist yet. `gas_limits` is indexed
/// like `msgs` and carries the accepted transaction's TOS compute gas_limit.
size_t apply_stashed_side_effects_for_messages(
    uint64_t accepted_block_seqno,
    uint64_t accepted_timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32],
    uint64_t chain_id,
    const std::vector<td::Ref<vm::Cell>>& msgs,
    const std::vector<uint64_t>& gas_limits,
    const td::Ref<vm::Cell>& initial_account_data) noexcept;

/// Extract the EVM executor account's StateInit.data (`cp.new_data`) from a
/// canonical ShardStateUnsplit root. Returns true when the shard state was
/// parsed; `account_data_out` is null if the executor account is absent.
bool extract_evm_executor_account_data_from_shard_state(
    td::Ref<vm::Cell> shard_state_root,
    const unsigned char executor_addr[32],
    td::Ref<vm::Cell>& account_data_out) noexcept;

}  // namespace evm_workchain
