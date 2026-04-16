/*
    EVM Workchain — module initialisation.

    Call init_evm_workchain() once at node startup to register the EVM
    compute phase handler with the host-chain transaction pipeline.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

namespace evm_workchain {

class EvmState;

/// Register the EVM compute phase handler with the host chain.
/// Must be called once before any EVM workchain transactions are processed.
void init_evm_workchain();

/// Access the global EVM workchain state singleton.
/// Available after init_evm_workchain() has been called.
EvmState& global_evm_state();

}  // namespace evm_workchain
