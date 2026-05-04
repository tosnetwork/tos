/*
    Uno Workchain — native engine registration.

    Declares `register_uno_workchain_engine`, which wires the `UnoNativeEngine`
    (implemented in dispatch-engine.cpp) into a WorkchainExecutionRegistry.

    Phase 4 refactoring: the engine class now lives here in uno/core/ so it can
    call `uno_run_compute_phase()` directly without a function-pointer indirection
    through the old `uno_workchain_dispatch` callback bridge.

    Source: TOS-specific integration point.
*/
#pragma once

#include <cstdint>

namespace block {
class WorkchainExecutionRegistry;
}

namespace uno_workchain {

/// Register the Uno native engine with a WorkchainExecutionRegistry.
/// Called once at startup (from init_uno_workchain) on the global registry,
/// and from tests on local registries.
void register_uno_workchain_engine(block::WorkchainExecutionRegistry& registry);

}  // namespace uno_workchain
