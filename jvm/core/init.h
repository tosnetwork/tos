/*
    JVM workchain initialization.

    init_jvm_workchain() must be called once at node startup before any wc=3
    transactions are processed.  It initializes non-consensus Avata process
    resources and registers the JvmNativeEngine with the
    WorkchainExecutionRegistry.

    Source: TOS-specific integration point.
*/
#pragma once

namespace jvm_workchain {

/// Initialize non-consensus Avata process resources and register the JVM engine
/// with the default WorkchainExecutionRegistry.
/// db_root: validator database root path (reserved for future class-store access).
/// Returns true on success.
/// The linked runtime is initialized from TOS_JVM_AVATA_RT_JAR (or the CMake
/// Avata bridge default), TOS_JVM_AVATA_CONTRACT_CLASSPATH, and
/// TOS_JVM_AVATA_HEAP. If initialization fails, registration still succeeds
/// with a null runtime and wc=3 compute fails closed.
bool init_jvm_workchain(const char* db_root);

}  // namespace jvm_workchain
