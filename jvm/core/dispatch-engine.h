/*
    JVM Workchain — native engine registration.

    Declares register_jvm_workchain_engine(), which installs the
    JvmNativeEngine into a WorkchainExecutionRegistry.

    Engine key: {Basic, 0x4a564d31} ("JVM1").
    Activation code marker: 0x4a ('J').
    Singleton executor address: 0x0000...0001.
    ConfigParam 85: JVM v1 chain parameters.

    IMPORTANT: Do not add a hardcoded wc=3 branch in transaction.cpp.
    Registration happens through WorkchainExecutionRegistry::register_engine().

    Source: TOS-specific integration point.
*/
#pragma once

#include <cstdint>
#include <memory>

#include "jvm/core/avata-execution.h"

namespace block {
class WorkchainExecutionRegistry;
}  // namespace block

namespace jvm_workchain {

// Engine selector: "JVM1" big-endian, matches doc/jvm-roadmap.md.
// vm_version = 0x4a564d31 sign-extended to int32_t = 0x4a564d31 (positive).
constexpr std::int32_t kJvmVmVersion = 0x4a564d31;

// Activation code marker byte: 'J' = 0x4a.
constexpr std::uint8_t kJvmActivationCode = 0x4au;

// ConfigParam slot for JVM v1 chain parameters.
constexpr int kJvmConfigParam = 85;

class JvmComputeRuntime {
 public:
    virtual ~JvmComputeRuntime() = default;

    virtual td::Result<JvmAvataInvocationResult> run_contract(
        const block::WorkchainComputeInput& input,
        const block::WorkchainComputeContext& context,
        const JvmConfig& config,
        const JvmExecutorState& previous_state) const = 0;
};

/// Register the JVM native engine with a WorkchainExecutionRegistry.
/// Called once at startup (from init_jvm_workchain) before any wc=3
/// transactions are processed.
/// If runtime is null, run_compute fails closed until the Avata interpreter
/// runtime is linked and installed by init_jvm_workchain().
void register_jvm_workchain_engine(
    block::WorkchainExecutionRegistry& registry,
    std::shared_ptr<const JvmComputeRuntime> runtime = nullptr);

}  // namespace jvm_workchain
