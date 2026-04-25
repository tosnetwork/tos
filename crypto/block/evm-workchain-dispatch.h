/*
    EVM Workchain dispatch — callback interface for the compute phase.

    This header lives in crypto/block/ (part of tos_crypto) so that
    transaction.cpp can call into the EVM workchain without creating a
    circular link dependency.  The evm_workchain module registers its
    implementation via set_evm_compute_handler() at startup.

    Source: TOS-specific integration point.
*/
#pragma once

#include <cstdint>
#include <functional>

#include "td/utils/Slice.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellSlice.h"

namespace block {
struct ComputePhase;
}

namespace evm_workchain_dispatch {

/// Signature of the EVM compute phase handler.
///
/// Parameters:
///   cp           — ComputePhase to populate with results
///   account_data — current executor StateInit.data cell (the cp.new_data
///                  v2 layout), or null on first activation. The handler
///                  decodes this into a per-call local CellEvmState so
///                  cp.new_data is a pure function of the inputs (no
///                  read/write of any process-global mutable state).
///   in_msg_body  — body cell slice containing the RLP payload
///   gas_limit    — max gas for this execution
///   block_seqno  — host-chain block sequence number (for block.number)
///   timestamp    — host-chain block Unix timestamp
///   rand_seed    — 256-bit block random seed
///   parent_block_hash — wc=1 parent block's root_hash (32 bytes), used
///                       for the EIP-2935 historical-block-hash ring
///                       buffer write so contracts get the real parent
///                       hash instead of zero. All-zero on block 0 and
///                       on non-EVM contexts.
///
/// Returns true if the phase completed (even on revert), false on infra error.
using EvmComputeHandler = std::function<bool(
    block::ComputePhase& cp,
    td::Ref<vm::Cell> account_data,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32])>;

/// Register the EVM compute phase handler.
/// Called once by the evm_workchain module during initialisation.
void set_evm_compute_handler(EvmComputeHandler handler);

/// Returns true if an EVM compute handler has been registered.
bool has_evm_compute_handler() noexcept;

/// Invoke the registered EVM compute handler.
/// Precondition: has_evm_compute_handler() == true.
bool invoke_evm_compute(
    block::ComputePhase& cp,
    td::Ref<vm::Cell> account_data,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32]);

/// Canonical "EVM activated account" code marker cell.
///
/// A single-byte cell containing 0x45 ('E'). Used as the StateInit.code cell
/// for every wc=1 ShardAccount in Phase A of the cell-native mirror — bytecode
/// itself lives in EvmAccountData.code_hash, so the outer code cell only needs
/// to satisfy the "account_active" requirement.
///
/// Returns the same Ref<vm::Cell> on every call (cached singleton). All
/// validators produce the same cell hash, which CellDb will deduplicate
/// across every EVM account.
td::Ref<vm::Cell> get_evm_code_marker_cell();

}  // namespace evm_workchain_dispatch
