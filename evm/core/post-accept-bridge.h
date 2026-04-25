/*
    EVM Workchain — header-light bridge for the validator-manager seam.

    `validator/manager.cpp` walks every accepted block's wc=1 ext-msg
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

/// True when `addr` (32-byte big-endian) matches the EVM executor account.
bool is_evm_executor_address(const unsigned char addr[32]) noexcept;

/// Look up cached side effects for the accepted block's EVM messages, finalize
/// block-wide receipt/transaction roots, and publish them via
/// `apply_block_side_effects`. Messages must be passed in transaction order.
///
/// Audit #4 (2026-04-26): the lookup key binds tx_hash to seqno, timestamp,
/// rand seed, and parent hash so rejected candidates cannot collide with the
/// accepted one.
size_t apply_stashed_side_effects_for_messages(
    uint64_t accepted_block_seqno,
    uint64_t accepted_timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32],
    const std::vector<td::Ref<vm::Cell>>& msgs) noexcept;

}  // namespace evm_workchain
