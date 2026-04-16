/*
    EVM Workchain — module initialisation.

    Call init_evm_workchain() once at node startup to register the EVM
    compute phase handler with the host-chain transaction pipeline.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

namespace evm_workchain {

/// Register the EVM compute phase handler with the host chain.
/// Must be called once before any EVM workchain transactions are processed.
void init_evm_workchain();

}  // namespace evm_workchain
