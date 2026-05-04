/*
    Uno Workchain dispatch — callback interface for the compute phase.

    This header lives in crypto/block/ (part of tos_crypto) so that
    transaction.cpp can call into the Uno workchain without creating a
    circular link dependency.  The uno_workchain module registers its
    implementation via set_uno_compute_handler() at startup.

    Mirrors evm-workchain-dispatch.{h,cpp} exactly; see §8.1, §11.2 of
    doc/uno-workchain.md.

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
class WorkchainExecutionRegistry;
}

namespace uno_workchain_dispatch {

/// Signature of the Uno compute phase handler.
///
/// Parameters:
///   cp           — ComputePhase to populate with results
///   state_data   — current executor StateInit.data (UnoShardState root)
///   in_msg_body  — body cell slice containing the Transfer wire payload
///   gas_limit    — max gas (advisory; Uno has no VM, verify cost is
///                  bounded by tx structure — see §8.4)
///   block_seqno  — host-chain block sequence number
///   timestamp    — host-chain block Unix timestamp
///   rand_seed    — 256-bit block random seed
///
/// Returns true if the phase completed (even on reject), false on infra error.
using UnoComputeHandler = std::function<bool(
    block::ComputePhase& cp,
    td::Ref<vm::Cell> state_data,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32])>;

/// Register the Uno compute phase handler.
/// Called once by the uno_workchain module during initialisation.
void set_uno_compute_handler(UnoComputeHandler handler);

/// Returns true if a Uno compute handler has been registered.
bool has_uno_compute_handler() noexcept;

/// Invoke the registered Uno compute handler.
/// Precondition: has_uno_compute_handler() == true.
bool invoke_uno_compute(
    block::ComputePhase& cp,
    td::Ref<vm::Cell> state_data,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]);

/// Canonical "Uno activated account" code marker cell.
///
/// A single-byte cell containing 0x55 ('U'). Used as StateInit.code for the
/// wc=2 executor ShardAccount — analogous to EVM's 0x45 ('E') marker. The
/// UnoShardState itself lives in StateInit.data; the outer code cell only
/// needs to satisfy the "account_active" requirement.
///
/// Returns the same Ref<vm::Cell> on every call (cached singleton). All
/// validators produce the same cell hash, which CellDb will deduplicate.
td::Ref<vm::Cell> get_uno_code_marker_cell();

/// Register the Uno descriptor/policy engine with a WorkchainExecutionRegistry.
///
/// This is the Phase 1 compatibility registration: compute still flows through
/// the legacy UnoComputeHandler until transaction.cpp is moved to the generic
/// WorkchainEngine::run_compute path.
void register_uno_workchain_engine(block::WorkchainExecutionRegistry& registry);

}  // namespace uno_workchain_dispatch
