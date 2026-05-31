/*
    JVM Workchain — native engine registration.

    Declares register_jvm_workchain_engine(), which installs the
    JvmNativeEngine into a WorkchainExecutionRegistry.

    Engine key: {Basic, 0x4a564d31} ("JVM1").
    Activation code marker: 0x4a ('J').
    Account policy: EngineDefined + admits_engine_create_account_actions.
    ConfigParam 85: JVM chain parameters (schema_version=2).
    Per-contract addresses are derived by `derive_jvm_contract_address`
    and materialized through the host `action_create_account` action.

    IMPORTANT: Do not add a hardcoded wc=3 branch in transaction.cpp.
    Registration happens through WorkchainExecutionRegistry::register_engine().

    Source: TOS-specific integration point.
*/
#pragma once

#include <cstdint>
#include <memory>

#include "jvm/core/avata-execution.h"  // transitively pulls cell-codec.h

namespace block {
class WorkchainExecutionRegistry;
}  // namespace block

namespace jvm_workchain {

// Engine selector: "JVM1" big-endian.
// vm_version = 0x4a564d31 sign-extended to int32_t = 0x4a564d31 (positive).
constexpr std::int32_t kJvmVmVersion = 0x4a564d31;

// Activation code marker byte: 'J' = 0x4a.
constexpr std::uint8_t kJvmActivationCode = 0x4au;

// ConfigParam slot for JVM v1 chain parameters.
constexpr int kJvmConfigParam = 85;

class JvmComputeRuntime {
 public:
    virtual ~JvmComputeRuntime() = default;

    // Per-account state with inline `class_bytes`, dedicated
    // `manifest_root`, and isolated `storage_root`.
    virtual td::Result<JvmAvataInvocationResult> run_contract(
        const block::WorkchainComputeInput& input,
        const block::WorkchainComputeContext& context,
        const JvmConfig& config,
        const JvmContractAccountState& previous_state) const = 0;

    // Hash of the loaded boot classpath / rt.jar bytes.  ConfigParam
    // 85's `stdlib_hash` is the consensus commitment to the runtime
    // profile every validator must execute against.  The engine
    // compares this getter's value to `cfg.stdlib_hash` on every
    // `run_compute` and fails closed on mismatch — without this,
    // two validators with the same on-chain ConfigParam 85 + state
    // could pass the existing `state.stdlib_hash == cfg.stdlib_hash`
    // gate but execute against different local jars (consensus
    // divergence).  Returns 32 zero bytes when no runtime is
    // installed; the engine's null-runtime check fails closed
    // before this getter is consulted in practice.
    virtual std::array<std::uint8_t, 32> rt_jar_hash() const = 0;
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
