/*
    EVM Workchain — native engine registration.

    Declares register_evm_workchain_engine(), which installs the
    EvmNativeEngine into a WorkchainExecutionRegistry.  The engine
    lives in evm/core/ so it can call run_evm_compute_phase_snapshot()
    directly without a function-pointer indirection.

    Source: TOS-specific integration point (Phase 4 refactor).
*/
#pragma once

#include <cstdint>

namespace block {
class WorkchainExecutionRegistry;
}  // namespace block

namespace evm_workchain {

/// Register the EVM native engine with the given registry.
/// Called once from init_evm_workchain() at node startup.
void register_evm_workchain_engine(block::WorkchainExecutionRegistry& registry);

}  // namespace evm_workchain
