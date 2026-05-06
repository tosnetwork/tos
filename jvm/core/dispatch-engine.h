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

    Source: TOS-specific integration point (Phase 2 scaffold).
*/
#pragma once

#include <cstdint>

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

/// Register the JVM native engine with a WorkchainExecutionRegistry.
/// Called once at startup (from init_jvm_workchain) before any wc=3
/// transactions are processed.
/// Phase 2 stub: run_compute returns NOT_READY until Phase 4 heap
/// serialization is implemented.
void register_jvm_workchain_engine(block::WorkchainExecutionRegistry& registry);

}  // namespace jvm_workchain
