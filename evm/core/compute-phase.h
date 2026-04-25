/*
    EVM Workchain — compute phase adapter.

    Provides the bridge between the host-chain transaction lifecycle
    (Transaction::prepare_compute_phase) and the EVM execution engine.

    When the host chain identifies a transaction targeting the EVM workchain,
    it calls run_evm_compute_phase_snapshot() instead of running TVM.  The
    function:
      1. Extracts the Ethereum transaction from the message body.
      2. Decodes the supplied `account_data` cell (block-declared pre-state)
         into a fresh per-call CellEvmState — no shared mutable global is
         touched during execution.
      3. Builds the EVM block context from host-chain block metadata.
      4. Executes the transaction via the EVM executor against that local
         state.
      5. Writes the result back into the host-chain ComputePhase structure
         (`cp.new_data` is purely a function of the supplied `account_data`,
         the message body, and the block metadata).
      6. Stashes any RPC-observability side effects (receipt, transaction,
         logs, block) on `cp.evm_side_effects` for later application via
         `apply_block_side_effects` once the block is accepted.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstdint>
#include <memory>

#include "block/transaction.h"  // block::ComputePhase, block::ComputePhaseConfig
#include "evm/core/state.h"

namespace evm_workchain {

/// Pure-snapshot variant: runs the EVM compute phase against the supplied
/// `account_data` cell (the block-declared pre-state), with no read or
/// write to the process-global `g_evm_state`.
///
/// This is the consensus-safe entry point. Two calls with identical inputs
/// produce bitwise-identical `cp.new_data` cell hashes, so the collator and
/// every validator (including a freshly-restarted one) agree on state-root
/// derivation independently of in-process execution history.
///
/// @param cp           ComputePhase to populate with results.
/// @param account_data Cell that compute-phase produced for this account
///                     in the previous block (the cp.new_data v2 layout —
///                     magic + state_root ref + eth_state_root + rpc_cache).
///                     Pass null on first activation: the function builds a
///                     genesis-equivalent state with EIP-4788 / EIP-2935
///                     predeploys present so Cancun / Pectra system calls
///                     work from block 0.
/// @param in_msg_body  Body cell slice of the inbound message (RLP payload).
/// @param gas_limit    Gas limit (from host-chain gas config).
/// @param block_seqno  Host-chain block sequence number → block.number.
/// @param timestamp    Host-chain block Unix timestamp.
/// @param rand_seed    Host-chain 256-bit block random seed.
/// @return             true if the phase completed (even on EVM revert);
///                     false only on infrastructure failure.
bool run_evm_compute_phase_snapshot(
    block::ComputePhase& cp,
    td::Ref<vm::Cell> account_data,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]);

/// Legacy global-state variant. Retained for the test harness and any
/// historical call site that still hands an EvmState in directly. New
/// integrations MUST use `run_evm_compute_phase_snapshot` — this entry
/// point reads / mutates a shared mutable state and is therefore not
/// safe to use on the consensus path.
bool run_evm_compute_phase(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    EvmState& state,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]);

}  // namespace evm_workchain
