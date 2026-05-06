/*
    JVM workchain initialization.

    init_jvm_workchain() must be called once at node startup before any wc=3
    transactions are processed.  It initializes non-consensus Avata process
    resources and registers the JvmNativeEngine with the
    WorkchainExecutionRegistry.

    Source: TOS-specific integration point (Phase 2 scaffold).
*/
#pragma once

namespace jvm_workchain {

/// Initialize non-consensus Avata process resources and register the JVM engine
/// with the default WorkchainExecutionRegistry.
/// db_root: validator database root path (used for class store access in future phases).
/// Returns true on success.
/// Phase 2 stub: creates no Avata resources; only registers the engine stub.
bool init_jvm_workchain(const char* db_root);

}  // namespace jvm_workchain
