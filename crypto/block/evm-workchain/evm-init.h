/*
    EVM Workchain — module initialisation.

    Call init_evm_workchain() once at node startup to register the EVM
    compute phase handler with the host-chain transaction pipeline.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <string>

namespace evm_workchain {

class EvmState;

/// Register the EVM compute phase handler with the host chain.
///
/// @param db_root  Path to the node's database directory.  If non-empty,
///                 persistent RocksDB state is used at {db_root}/evm-state.
///                 If empty, in-memory state is used (volatile).
void init_evm_workchain(const std::string& db_root = "");

/// Access the global EVM workchain state singleton.
/// Available after init_evm_workchain() has been called.
EvmState& global_evm_state();

}  // namespace evm_workchain
