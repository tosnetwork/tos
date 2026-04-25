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
#include <vector>

#include "evm/core/state.h"

#include <evmc/evmc.hpp>
#include <silkworm/core/types/log.hpp>

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

}  // namespace evm_workchain
