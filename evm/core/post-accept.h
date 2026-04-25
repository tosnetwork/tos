/*
    EVM Workchain — post-accept side-effects application.

    The pure snapshot compute path (run_evm_compute_phase_snapshot) does NOT
    write into the global EvmState or the side-channel RPC cache DB; doing
    so during compute would re-introduce the consensus hazard the snapshot
    refactor exists to close (collator and validator may call compute many
    times against differently-mutated globals, producing divergent state
    roots).

    Instead, every per-tx RPC observability record (receipt, transaction,
    logs, block summary) is collected in an `EvmBlockSideEffects` instance
    that hangs off `block::ComputePhase::evm_side_effects`. After the block
    is accepted by the validator manager, the host invokes
    `apply_block_side_effects` exactly once per (block_id, tx_index) to
    publish those records into the in-memory state and the cache DB and to
    fire subscription notifications.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstdint>
#include <optional>
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
/// side-channel RPC cache DB (if open), then fires subscription
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
// rejected candidate would still pollute the RPC cache with receipts /
// logs / block records / subscription notifications.
//
// Instead the dispatch lambda stashes the captured side effects under
// the EVM tx_hash. Only after the validator manager observes a canonical
// block (`cleanup_applied_external_messages`) does the host walk wc=1
// transactions in BlockData, look up the cached effects, and apply.
//
// Cache cap: kMaxStashedSideEffects = 4096. On insert when full, the
// oldest-touched entry is evicted (linear scan; same pattern as
// WcExtMsgPerPeerLimiter::evict_oldest_locked in ext-message-pool.cpp).

/// Stash one transaction's side effects for later post-accept apply.
/// `tx_hash` MUST equal `fx.tx_hash`; `block_seqno` MUST equal
/// `fx.receipt.block_number`. Safe to call from concurrent compute
/// coroutines.
///
/// Audit #4 (2026-04-26): the key is (block_seqno, tx_hash). Two candidates
/// containing the same EVM tx at different seqnos each get their own slot.
/// On collision (same key), the entry is REPLACED — block-context-dependent
/// fields (block.number, receipt.block_number, etc.) can change between
/// re-runs of the same candidate seqno (e.g. timestamp drift), so the
/// freshest fx is the one most likely to match the eventually-accepted
/// candidate at apply time.
void stash_side_effects(uint64_t block_seqno,
                        const evmc::bytes32& tx_hash,
                        EvmBlockSideEffects fx);

/// Look up and remove the cached side effects for `(block_seqno, tx_hash)`.
/// Returns std::nullopt if the entry was never stashed or was already taken
/// (or evicted). The caller is responsible for invoking
/// `apply_block_side_effects` on the returned value.
std::optional<EvmBlockSideEffects>
take_side_effects(uint64_t block_seqno, const evmc::bytes32& tx_hash);

/// Number of currently-stashed entries. Test/diagnostics only.
size_t stashed_side_effects_count() noexcept;

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

}  // namespace evm_workchain
