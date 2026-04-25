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

/// Look up the cached side effects for the EVM tx in `msg` at
/// `accepted_block_seqno`, then publish them via `apply_block_side_effects`.
/// No-op if the message is not an EVM transaction or the entry was never
/// stashed at that seqno (rejected candidate, eviction, restart-after-evict).
/// Returns true if an entry was found and applied.
///
/// Audit #4 (2026-04-26): the seqno is part of the stash key so that two
/// candidate blocks containing the same EVM tx (same tx_hash) at different
/// seqnos can each stash their own side-effects. With tx-hash-only keying
/// the second stash silently dropped its fx, and a candidate at seqno B
/// could be applied with the receipt/log/block records from seqno A.
bool apply_stashed_side_effects_for_message(uint64_t accepted_block_seqno,
                                            const td::Ref<vm::Cell>& msg) noexcept;

}  // namespace evm_workchain
