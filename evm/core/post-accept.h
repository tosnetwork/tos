/*
    EVM Workchain — post-accept side-effects application.

    The pure snapshot compute path (run_evm_compute_phase_snapshot) does NOT
    write into the global EvmState or the public side-channel RPC indexes;
    doing so during compute would re-introduce the consensus hazard the
    snapshot refactor exists to close (collator and validator may call
    compute many times against differently-mutated globals, producing
    divergent state roots). It may write a private pending recovery record
    keyed by candidate context.

    Instead, every per-tx RPC observability record (receipt, transaction,
    logs, block summary) is collected in an `EvmBlockSideEffects` instance
    that hangs off `block::ComputePhase::evm_side_effects`. A pending copy is
    also written to the RPC cache DB as a restart/eviction recovery record.
    After the block is accepted by the validator manager, the host invokes
    `apply_block_side_effects` exactly once per (block_id, tx_index) to
    publish those records into the in-memory state and the durable RPC indexes
    and to fire subscription notifications.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "evm/core/state.h"

#include <evmc/evmc.hpp>
#include <silkworm/core/types/log.hpp>

namespace vm {
class Cell;
}  // namespace vm

namespace td {
template <class T>
class Ref;
}  // namespace td

namespace evm_workchain {

/// One transaction's worth of post-accept records, captured during the
/// pure snapshot compute path. Layout intentionally mirrors what
/// `run_evm_compute_phase` (the legacy global path) used to write
/// directly into `g_evm_state` mid-execution.
struct EvmBlockSideEffects {
    /// Tx-level records.
    evmc::bytes32 tx_hash{};
    evmc::bytes32 rand_seed{};
    StoredReceipt receipt{};
    StoredTransaction transaction{};
    std::vector<silkworm::Log> logs{};

    /// Block-level summary. Populated for the block's first tx (the
    /// `!state.has_block` branch in the legacy code) — for subsequent
    /// txs in the same block `has_block` is false here, so apply skips
    /// the block insert.
    bool has_block{false};
    StoredBlock block{};
};

/// Publish one transaction's side effects: writes the receipt /
/// transaction / logs / block records into `g_evm_state` and the
/// durable side-channel RPC indexes (if open), then fires subscription
/// notifications. Called by the collator (post `create_block`) and the
/// validator manager (post `cleanup_applied_external_messages`) for every
/// wc=1 transaction in the accepted block.
///
/// Idempotent: a second call with the same `(block.number, tx_hash)`
/// short-circuits via the EvmState's already-present-check (the cache DB
/// just last-write-wins). Safe to call from multiple roles in the same
/// process (collator-then-validator), which is the operational reality on
/// a single-validator node.
void apply_block_side_effects(const EvmBlockSideEffects& fx);

// ---------------------------------------------------------------------------
// Deferred-apply queue: bridges pure compute -> post-BFT-accept apply.
// ---------------------------------------------------------------------------
//
// Compute fires for every candidate validation pass, including BFT-rejected
// ones. If `apply_block_side_effects` ran inline at compute time, every
// rejected candidate would still pollute the durable receipt / log / block
// RPC indexes and subscription notifications.
//
// Instead the dispatch lambda stashes the captured side effects under the
// accepted-block context and EVM tx_hash. A durable pending copy is keyed the
// same way, but it is not visible through the public RPC indexes. Only after
// the validator manager observes a canonical block
// (`cleanup_applied_external_messages`) does the host walk wc=1 transactions
// in BlockData, look up the cached effects, and apply.
//
// Cache cap: kMaxStashedSideEffects = 4096. On insert when full, the
// oldest-touched entry is evicted (linear scan; same pattern as
// WcExtMsgPerPeerLimiter::evict_oldest_locked in ext-message-pool.cpp).

/// Stash one transaction's side effects for later post-accept apply. Safe to
/// call from concurrent compute coroutines.
///
/// Audit #4 (2026-04-26): the key binds tx_hash to accepted-block context
/// (seqno, timestamp, rand seed, parent hash), so a BFT-rejected candidate
/// with the same EVM tx cannot publish stale receipt/log/block records.
void stash_side_effects(uint64_t block_seqno,
                        uint64_t timestamp,
                        const uint8_t rand_seed[32],
                        const uint8_t parent_block_hash[32],
                        const evmc::bytes32& tx_hash,
                        EvmBlockSideEffects fx);

/// Look up and remove the cached side effects for an accepted block context.
/// Returns std::nullopt if the entry was never stashed or was already taken
/// (or evicted). The caller is responsible for invoking
/// `apply_block_side_effects` on the returned value.
std::optional<EvmBlockSideEffects>
take_side_effects(uint64_t block_seqno,
                  uint64_t timestamp,
                  const uint8_t rand_seed[32],
                  const uint8_t parent_block_hash[32],
                  const evmc::bytes32& tx_hash);

/// Number of currently-stashed entries. Test/diagnostics only.
size_t stashed_side_effects_count() noexcept;

/// Clear only the in-memory deferred-apply queue. Test-only helper for
/// exercising restart/eviction recovery from the RPC cache DB.
void clear_stashed_side_effects_for_tests() noexcept;

struct EvmPostAcceptHealth {
    uint64_t missing_side_effects{0};
    uint64_t replayed_side_effects{0};
    uint64_t replay_failures{0};
    uint64_t malformed_messages{0};
    uint64_t malformed_special_cell_messages{0};
    uint64_t strict_root_failures{0};
    uint64_t incomplete_indexed_transactions{0};
    uint64_t incomplete_indexed_blocks{0};
};

EvmPostAcceptHealth evm_post_accept_health() noexcept;
void reset_evm_post_accept_health_for_tests() noexcept;
void hydrate_evm_rpc_incomplete_indexes_from_cache() noexcept;

/// True iff `tx_hash` belongs to an accepted EVM transaction whose public RPC
/// receipt/transaction/log indexes were intentionally withheld because the
/// post-accept side-effect stream had a gap. Unknown hashes must still return
/// the normal Ethereum JSON-RPC `null`, not a global indexing error.
bool is_evm_rpc_indexing_incomplete(const evmc::bytes32& tx_hash) noexcept;

/// True iff the accepted EVM block at `block_number` could not publish a
/// complete public RPC block/tx/receipt/log index. Number-keyed RPCs should
/// report indexing-incomplete instead of treating the accepted block as
/// unknown.
bool is_evm_rpc_block_indexing_incomplete(uint64_t block_number) noexcept;

struct RpcCacheRebuildStats {
    uint64_t from_block{0};
    uint64_t to_block{0};
    uint64_t blocks_seen{0};
    uint64_t blocks_written{0};
    uint64_t transactions_written{0};
    uint64_t receipts_written{0};
    uint64_t log_blocks_written{0};
    uint64_t errors{0};
    std::string last_error;
};

/// Rebuild the durable RPC side-channel cache from the canonical in-memory
/// block/tx/receipt/log indexes. This is an operator command for repairing
/// a corrupted or missing RocksDB cache; it never mutates consensus state.
RpcCacheRebuildStats rebuild_rpc_cache_from_global_state(
    uint64_t from_block,
    uint64_t to_block) noexcept;

// ---------------------------------------------------------------------------
// Helpers for the validator-manager seam.
// ---------------------------------------------------------------------------

/// True when `addr` (32-byte big-endian) matches the EVM executor account.
/// Provided here so `validator/manager.cpp` does not need to include
/// `evm/core/workchain.h` directly.
bool is_evm_executor_address(const unsigned char addr[32]) noexcept;

/// Decode an EVM external-message cell (`Message_Any` form built by
/// `build_evm_external_message`) and compute the keccak256(RLP) tx hash.
/// Returns std::nullopt for any parse failure — callers should treat that
/// as "not an EVM tx" and skip rather than fail loudly.
///
/// Cheaper than `decode_evm_transaction` because it skips ECDSA sender
/// recovery; only the RLP envelope is needed for the hash.
std::optional<evmc::bytes32>
try_derive_evm_tx_hash_from_message(const td::Ref<vm::Cell>& msg) noexcept;

/// Apply stashed side effects for an accepted block in transaction order.
/// This finalizes block-wide tx/receipt roots, cumulative gas, tx_index, and
/// logs bloom before publishing records to the RPC cache. If any accepted EVM
/// message is missing side effects or cannot be decoded, the whole block's
/// public EVM indexes are withheld instead of publishing a partial prefix with
/// misleading block/receipt semantics.
size_t apply_stashed_side_effects_for_messages(
    uint64_t accepted_block_seqno,
    uint64_t accepted_timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32],
    const std::vector<td::Ref<vm::Cell>>& msgs) noexcept;

/// Variant used by the validator manager when the previous canonical shard
/// state is available. If the memory stash and pending DB both miss, replay
/// the accepted EVM message from `initial_account_data` instead of dropping
/// the record.
size_t apply_stashed_side_effects_for_messages(
    uint64_t accepted_block_seqno,
    uint64_t accepted_timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32],
    const std::vector<td::Ref<vm::Cell>>& msgs,
    const std::vector<uint64_t>& gas_limits,
    const td::Ref<vm::Cell>& initial_account_data) noexcept;

bool extract_evm_executor_account_data_from_shard_state(
    td::Ref<vm::Cell> shard_state_root,
    td::Ref<vm::Cell>& account_data_out) noexcept;

}  // namespace evm_workchain
