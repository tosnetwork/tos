/*
    JVM Workchain — narrow Avata execution bridge helpers.

    These helpers keep consensus-side orchestration independent from the
    concrete Avata entry points. Production builds pass the linked Avata C ABI
    through make_linked_jvm_avata_execution_api(); tests can still inject fake
    function pointers to cover rollback and failure paths.
*/
#pragma once

#include <cstdint>
#include <vector>

#include "block/workchain-execution-dispatch.h"
#include "jvm/core/cell-codec.h"
#include "jvm/core/config-param.h"
#include "jvm/core/event-host.h"
#include "jvm/core/storage-cell-host.h"
#include "td/utils/Status.h"

struct AvataEventHost;
struct AvataStorageHost;

namespace jvm_workchain {

using JvmAvataSetOpcodeGasCosts =
    int (*)(void* thread, const std::uint64_t* gas_costs,
            std::uint32_t gas_cost_count);
using JvmAvataSetContractHelperGasCosts =
    int (*)(void* thread, const std::uint64_t* gas_costs,
            std::uint32_t gas_cost_count);

struct JvmAvataGasApi {
    int ok_status{0};
    JvmAvataSetOpcodeGasCosts set_opcode_gas_costs{nullptr};
    JvmAvataSetContractHelperGasCosts set_contract_helper_gas_costs{nullptr};
};

// Apply the resolved consensus gas schedule from ConfigParam 85 to an Avata
// thread before contract bytecode execution.  Standalone Avata defaults remain
// valid only for local tests that do not pass through the wc=3 compute adapter.
td::Status apply_jvm_gas_config_to_avata_thread(
    void* avata_thread,
    const JvmConfig& config,
    const JvmAvataGasApi& api);

using JvmAvataSetStorageHost =
    void (*)(const AvataStorageHost* host);
using JvmAvataClearStorageHost = void (*)();
using JvmAvataSetEventHost =
    void (*)(const AvataEventHost* host);
using JvmAvataClearEventHost = void (*)();
using JvmAvataBeginContractTransactionWithLimits =
    int (*)(void* thread, std::uint64_t gas_limit,
            std::uint64_t memory_limit);
using JvmAvataEndContractTransaction = int (*)(void* thread);
using JvmAvataContractRemainingGas =
    int (*)(void* thread, std::uint64_t* remaining_gas);
using JvmAvataContractMemoryUsed =
    int (*)(void* thread, std::uint64_t* used_bytes);
using JvmAvataInvokeContract =
    int (*)(void* thread, void* invocation_user);

struct JvmAvataExecutionApi {
    int ok_status{0};
    int out_of_gas_status{2};
    int out_of_memory_status{3};
    JvmAvataGasApi gas_api;
    JvmAvataSetStorageHost set_storage_host{nullptr};
    JvmAvataClearStorageHost clear_storage_host{nullptr};
    JvmAvataSetEventHost set_event_host{nullptr};
    JvmAvataClearEventHost clear_event_host{nullptr};
    JvmAvataBeginContractTransactionWithLimits
        begin_contract_transaction_with_limits{nullptr};
    JvmAvataEndContractTransaction end_contract_transaction{nullptr};
    JvmAvataContractRemainingGas contract_remaining_gas{nullptr};
    JvmAvataContractMemoryUsed contract_memory_used{nullptr};
    JvmAvataInvokeContract invoke_contract{nullptr};
};

struct JvmAvataInvocationResult {
    int invocation_status{0};
    bool success{false};
    bool out_of_gas{false};
    bool out_of_memory{false};
    std::uint64_t gas_used{0};
    std::uint64_t gas_remaining{0};
    std::uint64_t memory_used{0};
    td::Ref<vm::Cell> storage_root;
    td::Ref<vm::Cell> action_list;
    std::vector<JvmEvent> events;
};

// Execute one Avata contract transaction around an already-created Avata
// thread. This helper owns only consensus-side orchestration: storage host
// installation, storage snapshot commit/rollback, ConfigParam 85 gas table
// installation, and transaction resource accounting. The actual Java contract
// entrypoint is supplied by invoke_contract until the Avata interpreter target
// is linked into the workchain adapter.
td::Result<JvmAvataInvocationResult> execute_jvm_avata_transaction(
    void* avata_thread,
    const JvmConfig& config,
    std::uint64_t gas_limit,
    JvmStorageCellHost& storage,
    const JvmAvataExecutionApi& api,
    void* invocation_user,
    JvmEventHost* events = nullptr);

// Convert the already-executed Avata transaction result into the canonical
// custom-workchain compute output consumed by Transaction::prepare_compute_phase.
// This is intentionally separate from execute_jvm_avata_transaction() so tests
// can lock the consensus output shape before the real interpreter target is
// linked into JvmNativeEngine.
// Build the canonical compute output for a single per-contract wc=3 account
// by re-encoding the next `JvmContractAccountState` with the invocation's
// storage_root (class_hash, class_bytes, manifest_root are pinned at deploy
// time and not modified by run_compute).
td::Result<block::WorkchainComputeOutput> build_jvm_workchain_output(
    const JvmConfig& config,
    const JvmContractAccountState& previous_state,
    std::uint64_t gas_limit,
    const JvmAvataInvocationResult& invocation);

}  // namespace jvm_workchain
