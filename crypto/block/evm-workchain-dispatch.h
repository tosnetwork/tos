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

#include "vm/cells/CellSlice.h"

namespace vm {
class Dictionary;
}

namespace block {
struct ComputePhase;
}

namespace evm_workchain_dispatch {

/// Signature of the EVM compute phase handler.
///
/// Parameters:
///   cp           — ComputePhase to populate with results
///   in_msg_body  — body cell slice containing the RLP payload
///   gas_limit    — max gas for this execution
///   block_seqno  — host-chain block sequence number
///   timestamp    — host-chain block Unix timestamp
///   rand_seed    — 256-bit block random seed
///   shard_accounts — (optional) collator's ShardAccounts dict for wc=2;
///                    when non-null, the EVM module syncs its state into this
///                    dict so the collator's MERKLE_UPDATE includes EVM state
///                    atomically with the rest of the shard. When null
///                    (testing/RPC paths), only the global EvmState is used.
///
/// Returns true if the phase completed (even on revert), false on infra error.
using EvmComputeHandler = std::function<bool(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32],
    vm::Dictionary* shard_accounts)>;

/// Register the EVM compute phase handler.
/// Called once by the evm_workchain module during initialisation.
void set_evm_compute_handler(EvmComputeHandler handler);

/// Returns true if an EVM compute handler has been registered.
bool has_evm_compute_handler() noexcept;

/// Invoke the registered EVM compute handler.
/// Precondition: has_evm_compute_handler() == true.
/// shard_accounts may be nullptr (testing); when supplied, the EVM module
/// will sync its state into this dict for atomic block commit.
bool invoke_evm_compute(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32],
    vm::Dictionary* shard_accounts = nullptr);

}  // namespace evm_workchain_dispatch
