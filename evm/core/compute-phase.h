/*
    EVM Workchain — compute phase adapter.

    Provides the bridge between the host-chain transaction lifecycle
    (Transaction::prepare_compute_phase) and the EVM execution engine.

    When the host chain identifies a transaction targeting the EVM workchain,
    it calls run_evm_compute_phase() instead of running TVM.  The function:
      1. Extracts the Ethereum transaction from the message body.
      2. Builds the EVM block context from host-chain block metadata.
      3. Executes the transaction via the EVM executor.
      4. Writes the result back into the host-chain ComputePhase structure.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstdint>
#include <memory>

#include "block/transaction.h"  // block::ComputePhase, block::ComputePhaseConfig
#include "evm/core/state.h"

namespace evm_workchain {

/// Run the EVM compute phase for a transaction targeting the EVM workchain.
///
/// Called from Transaction::prepare_compute_phase when the target account
/// belongs to wc=1 (which, under single-executor, is always the executor
/// account regardless of which EOA originated the signed Ethereum tx).
///
/// @param cp          The ComputePhase structure to populate with results.
/// @param in_msg_body The body cell slice of the inbound message (contains RLP).
/// @param gas_limit   Gas limit for this execution (from host-chain gas config).
/// @param state       Mutable EVM workchain state.
/// @param block_seqno Host-chain block sequence number.
/// @param timestamp   Host-chain block Unix timestamp.
/// @param rand_seed   Host-chain 256-bit block random seed.
/// @return            true if the compute phase completed (even on EVM revert);
///                    false only on infrastructure failure.
bool run_evm_compute_phase(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    EvmState& state,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]);

}  // namespace evm_workchain
