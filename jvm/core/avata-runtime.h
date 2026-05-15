/*
    JVM Workchain — Avata-backed JvmComputeRuntime adapter.
*/
#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "jvm/core/dispatch-engine.h"

namespace jvm_workchain {

struct JvmLinkedAvataRuntimeOptions {
    // Required boot runtime jar. Normally provided by the CMake Avata bridge
    // default or TOS_JVM_AVATA_RT_JAR at validator startup.
    std::string boot_classpath;

    // Optional contract/application classpath. The v1 manifest resolver maps
    // (contract_id, method_id) to class/method names and resolves them here.
    std::string classpath;

    std::string max_heap{"128m"};
    std::vector<std::string> extra_options;
};

struct JvmAvataCallTarget {
    void* thread{nullptr};
    void* invocation_user{nullptr};
    std::shared_ptr<void> invocation_owner;
};

// Per-account resolver: looks up the call target through the
// `manifest_root` carried by `JvmContractAccountState`, and loads
// `class_bytes` from the same state.
using JvmAvataResolveCallTarget =
    td::Result<JvmAvataCallTarget> (*)(
        const block::WorkchainComputeInput& input,
        const block::WorkchainComputeContext& context,
        const JvmConfig& config,
        const JvmContractAccountState& previous_state,
        void* user);

class JvmAvataRuntime final : public JvmComputeRuntime {
 public:
    JvmAvataRuntime(JvmAvataExecutionApi api,
                    JvmAvataResolveCallTarget resolve_call_target,
                    void* resolve_user = nullptr,
                    std::shared_ptr<void> resolve_owner = nullptr,
                    std::array<std::uint8_t, 32> rt_jar_hash = {});

    td::Result<JvmAvataInvocationResult> run_contract(
        const block::WorkchainComputeInput& input,
        const block::WorkchainComputeContext& context,
        const JvmConfig& config,
        const JvmContractAccountState& previous_state) const override;

    std::array<std::uint8_t, 32> rt_jar_hash() const override {
        return rt_jar_hash_;
    }

 private:
    JvmAvataExecutionApi api_;
    JvmAvataResolveCallTarget resolve_call_target_{nullptr};
    void* resolve_user_{nullptr};
    std::shared_ptr<void> resolve_owner_;
    std::array<std::uint8_t, 32> rt_jar_hash_{};
    mutable std::mutex mutex_;
};

// Build a JvmAvataExecutionApi backed by the linked Avata interpreter C ABI.
// The call target resolver must resolve and pass an invocation object through
// JvmAvataCallTarget::invocation_user.  If that object owns decoded ABI
// argument storage, keep it alive through JvmAvataCallTarget::invocation_owner.
JvmAvataExecutionApi make_linked_jvm_avata_execution_api();

td::Result<std::shared_ptr<const JvmComputeRuntime>>
make_linked_jvm_avata_runtime(const JvmLinkedAvataRuntimeOptions& options);

// Hash the `:`-separated boot classpath, feeding each entry's file
// bytes (in listed order) through sha256 with a domain tag + length
// prefix + trailing entry-count anchor.  Used at runtime startup to
// produce `rt_jar_hash()` which the dispatch engine compares against
// ConfigParam 85's `stdlib_hash`.
//
// Exposed here (Phase EE) so the direct parity test against
// `compute_canonical_stdlib_hash` can call this function instead of
// going through the heavier `make_linked_jvm_avata_runtime` path.
// For a single-entry classpath, the output is IDENTICAL to
// `compute_canonical_stdlib_hash(file_bytes)` — that invariant is
// the consensus-correctness gate for every wc=3 deploy.
td::Result<std::array<std::uint8_t, 32>> hash_boot_classpath(
    const std::string& boot_classpath);

}  // namespace jvm_workchain
