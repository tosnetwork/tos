/*
    JVM Workchain — narrow Avata execution bridge helpers.
*/
#include "jvm/core/avata-execution.h"

#include "block/transaction.h"
#include "jvm/avata/include/avata/event.h"
#include "jvm/avata/include/avata/storage.h"

#include <utility>

namespace jvm_workchain {

namespace {

bool execution_api_complete(const JvmAvataExecutionApi& api) {
    return api.set_storage_host != nullptr &&
           api.clear_storage_host != nullptr &&
           api.begin_contract_transaction_with_limits != nullptr &&
           api.end_contract_transaction != nullptr &&
           api.contract_remaining_gas != nullptr &&
           api.contract_memory_used != nullptr &&
           api.invoke_contract != nullptr;
}

bool event_api_complete(const JvmAvataExecutionApi& api) {
    return api.set_event_host != nullptr &&
           api.clear_event_host != nullptr;
}

td::Status finish_storage_transaction(JvmStorageCellHost& storage,
                                      bool commit) {
    return commit ? storage.commit_transaction()
                  : storage.rollback_transaction();
}

td::RefInt256 jvm_gas_fees(const JvmConfig& config, std::uint64_t gas_used) {
    return td::make_refint(config.gas_price) * gas_used;
}

td::Ref<vm::Cell> empty_jvm_action_list() {
    return build_jvm_event_action_list(std::vector<JvmEvent>{});
}

}  // namespace

td::Status apply_jvm_gas_config_to_avata_thread(
    void* avata_thread,
    const JvmConfig& config,
    const JvmAvataGasApi& api) {
    if (avata_thread == nullptr) {
        return td::Status::Error("JVM Avata gas bridge received null thread");
    }
    if (api.set_opcode_gas_costs == nullptr ||
        api.set_contract_helper_gas_costs == nullptr) {
        return td::Status::Error("JVM Avata gas bridge is missing callbacks");
    }
    if (config.chain_id == 0 || config.gas_schedule_version == 0) {
        return td::Status::Error("JVM Avata gas bridge received unresolved config");
    }

    int status = api.set_opcode_gas_costs(
        avata_thread,
        config.opcode_gas_costs.data(),
        static_cast<std::uint32_t>(config.opcode_gas_costs.size()));
    if (status != api.ok_status) {
        return td::Status::Error("JVM Avata opcode gas table install failed");
    }

    status = api.set_contract_helper_gas_costs(
        avata_thread,
        config.helper_gas_costs.data(),
        static_cast<std::uint32_t>(config.helper_gas_costs.size()));
    if (status != api.ok_status) {
        return td::Status::Error("JVM Avata helper gas table install failed");
    }

    return td::Status::OK();
}

td::Result<JvmAvataInvocationResult> execute_jvm_avata_transaction(
    void* avata_thread,
    const JvmConfig& config,
    std::uint64_t gas_limit,
    JvmStorageCellHost& storage,
    const JvmAvataExecutionApi& api,
    void* invocation_user,
    JvmEventHost* events) {
    if (avata_thread == nullptr) {
        return td::Status::Error("JVM Avata execution received null thread");
    }
    if (!execution_api_complete(api)) {
        return td::Status::Error("JVM Avata execution API is incomplete");
    }
    if (events != nullptr && !event_api_complete(api)) {
        return td::Status::Error("JVM Avata event execution API is incomplete");
    }
    if (config.chain_id == 0 || config.max_heap_bytes == 0 ||
        config.max_gas_per_tx == 0) {
        return td::Status::Error("JVM Avata execution received unresolved config");
    }
    if (gas_limit == 0 || gas_limit > config.max_gas_per_tx) {
        return td::Status::Error("JVM Avata execution received invalid gas limit");
    }

    TRY_STATUS(apply_jvm_gas_config_to_avata_thread(
        avata_thread, config, api.gas_api));

    AvataStorageHost storage_host{};
    configure_avata_storage_host(storage, storage_host);
    api.set_storage_host(&storage_host);

    bool storage_transaction_open = false;
    bool event_transaction_open = false;
    bool contract_transaction_open = false;
    auto clear_host = [&]() {
        if (events != nullptr) {
            api.clear_event_host();
        }
        api.clear_storage_host();
    };

    auto fail = [&](td::Status status) -> td::Result<JvmAvataInvocationResult> {
        if (contract_transaction_open) {
            (void)api.end_contract_transaction(avata_thread);
            contract_transaction_open = false;
        }
        if (event_transaction_open) {
            (void)events->rollback_transaction();
            event_transaction_open = false;
        }
        if (storage_transaction_open) {
            (void)storage.rollback_transaction();
            storage_transaction_open = false;
        }
        clear_host();
        return status;
    };

    auto storage_status = storage.begin_transaction();
    if (storage_status.is_error()) {
        clear_host();
        return storage_status.move_as_error();
    }
    storage_transaction_open = true;

    AvataEventHost event_host{};
    if (events != nullptr) {
        configure_avata_event_host(*events, event_host);
        api.set_event_host(&event_host);
        auto event_status = events->begin_transaction();
        if (event_status.is_error()) {
            return fail(event_status.move_as_error());
        }
        event_transaction_open = true;
    }

    int status = api.begin_contract_transaction_with_limits(
        avata_thread, gas_limit, config.max_heap_bytes);
    if (status != api.ok_status) {
        return fail(td::Status::Error(
            "JVM Avata begin contract transaction failed"));
    }
    contract_transaction_open = true;

    const int invocation_status =
        api.invoke_contract(avata_thread, invocation_user);

    std::uint64_t remaining_gas = 0;
    status = api.contract_remaining_gas(avata_thread, &remaining_gas);
    if (status != api.ok_status) {
        return fail(td::Status::Error(
            "JVM Avata remaining gas query failed"));
    }
    if (remaining_gas > gas_limit) {
        return fail(td::Status::Error(
            "JVM Avata remaining gas exceeded gas limit"));
    }

    std::uint64_t memory_used = 0;
    status = api.contract_memory_used(avata_thread, &memory_used);
    if (status != api.ok_status) {
        return fail(td::Status::Error(
            "JVM Avata memory usage query failed"));
    }
    if (memory_used > config.max_heap_bytes) {
        return fail(td::Status::Error(
            "JVM Avata memory usage exceeded configured limit"));
    }

    status = api.end_contract_transaction(avata_thread);
    contract_transaction_open = false;
    if (status != api.ok_status) {
        return fail(td::Status::Error(
            "JVM Avata end contract transaction failed"));
    }

    JvmAvataInvocationResult result;
    result.invocation_status = invocation_status;
    result.success = invocation_status == api.ok_status;
    result.out_of_gas = invocation_status == api.out_of_gas_status;
    result.out_of_memory = invocation_status == api.out_of_memory_status;
    result.gas_remaining = remaining_gas;
    result.gas_used = gas_limit - remaining_gas;
    result.memory_used = memory_used;

    storage_status = finish_storage_transaction(storage, result.success);
    storage_transaction_open = false;
    if (storage_status.is_error()) {
        if (event_transaction_open) {
            (void)events->rollback_transaction();
            event_transaction_open = false;
        }
        clear_host();
        return storage_status.move_as_error();
    }

    if (events != nullptr) {
        auto event_status = result.success
            ? events->commit_transaction()
            : events->rollback_transaction();
        event_transaction_open = false;
        if (event_status.is_error()) {
            clear_host();
            return event_status.move_as_error();
        }
    }

    clear_host();
    if (result.success) {
        result.storage_root = storage.root_cell();
        if (events != nullptr) {
            result.events = events->events();
            result.action_list = build_jvm_event_action_list(result.events);
            if (result.action_list.is_null()) {
                return td::Status::Error("JVM Avata event action list encode failed");
            }
        }
    }
    return result;
}

td::Result<block::WorkchainComputeOutput> build_jvm_workchain_output(
    const JvmConfig& config,
    const JvmExecutorState& previous_state,
    std::uint64_t gas_limit,
    const JvmAvataInvocationResult& invocation) {
    if (config.chain_id == 0 || config.gas_price == 0 ||
        config.max_gas_per_tx == 0 || config.max_heap_bytes == 0) {
        return td::Status::Error(
            "JVM output builder received unresolved ConfigParam 85");
    }
    if (gas_limit == 0 || gas_limit > config.max_gas_per_tx ||
        invocation.gas_used > gas_limit) {
        return td::Status::Error(
            "JVM output builder received invalid gas accounting");
    }
    if (invocation.memory_used > config.max_heap_bytes) {
        return td::Status::Error(
            "JVM output builder received invalid memory accounting");
    }
    if (previous_state.schema_version != kJvmExecutorStateSchemaVersion ||
        previous_state.stdlib_hash != config.stdlib_hash) {
        return td::Status::Error(
            "JVM output builder received incompatible previous executor state");
    }
    if (invocation.success &&
        (invocation.out_of_gas || invocation.out_of_memory ||
         invocation.invocation_status != 0)) {
        return td::Status::Error(
            "JVM output builder received inconsistent success status");
    }

    block::WorkchainComputeOutput out;
    out.completed = true;
    out.accepted = true;
    out.skip_reason = block::ComputePhase::sk_none;
    out.out_of_gas = invocation.out_of_gas;
    out.exit_code = invocation.success ? 0 : invocation.invocation_status;
    out.gas_used = invocation.gas_used;
    out.gas_fees = jvm_gas_fees(config, invocation.gas_used);

    if (!invocation.success) {
        out.engine_success = false;
        out.committed = false;
        out.vm_log = invocation.out_of_gas
            ? "JVM execution exhausted gas"
            : (invocation.out_of_memory
                   ? "JVM execution exhausted memory"
                   : "JVM execution failed");
        return out;
    }

    if (invocation.storage_root.is_null() ||
        !validate_jvm_storage_root(invocation.storage_root)) {
        return td::Status::Error(
            "JVM output builder received invalid committed storage root");
    }

    auto action_list = invocation.action_list;
    if (action_list.is_null()) {
        action_list = empty_jvm_action_list();
    }
    if (action_list.is_null()) {
        return td::Status::Error(
            "JVM output builder failed to build empty action list");
    }

    JvmExecutorState next_state;
    next_state.schema_version = kJvmExecutorStateSchemaVersion;
    next_state.stdlib_hash = config.stdlib_hash;
    next_state.storage_root = invocation.storage_root;
    next_state.class_state_root = previous_state.class_state_root;
    auto new_data = encode_jvm_executor_state(next_state);
    if (new_data.is_null()) {
        return td::Status::Error(
            "JVM output builder failed to encode executor state");
    }

    out.engine_success = true;
    out.committed = true;
    out.new_data = std::move(new_data);
    out.action_list = std::move(action_list);
    out.vm_log = "JVM execution completed";
    return out;
}

td::Result<block::WorkchainComputeOutput> build_jvm_workchain_output_v2(
    const JvmConfig& config,
    const JvmContractAccountState& previous_state,
    std::uint64_t gas_limit,
    const JvmAvataInvocationResult& invocation) {
    if (config.chain_id == 0 || config.gas_price == 0 ||
        config.max_gas_per_tx == 0 || config.max_heap_bytes == 0) {
        return td::Status::Error(
            "JVM v2 output builder received unresolved ConfigParam 85");
    }
    if (gas_limit == 0 || gas_limit > config.max_gas_per_tx ||
        invocation.gas_used > gas_limit) {
        return td::Status::Error(
            "JVM v2 output builder received invalid gas accounting");
    }
    if (invocation.memory_used > config.max_heap_bytes) {
        return td::Status::Error(
            "JVM v2 output builder received invalid memory accounting");
    }
    if (previous_state.schema_version != kJvmContractAccountStateSchemaVersion ||
        previous_state.stdlib_hash != config.stdlib_hash ||
        previous_state.class_bytes.is_null()) {
        return td::Status::Error(
            "JVM v2 output builder received incompatible previous account state");
    }
    if (invocation.success &&
        (invocation.out_of_gas || invocation.out_of_memory ||
         invocation.invocation_status != 0)) {
        return td::Status::Error(
            "JVM v2 output builder received inconsistent success status");
    }

    block::WorkchainComputeOutput out;
    out.completed = true;
    out.accepted = true;
    out.skip_reason = block::ComputePhase::sk_none;
    out.out_of_gas = invocation.out_of_gas;
    out.exit_code = invocation.success ? 0 : invocation.invocation_status;
    out.gas_used = invocation.gas_used;
    out.gas_fees = jvm_gas_fees(config, invocation.gas_used);

    if (!invocation.success) {
        out.engine_success = false;
        out.committed = false;
        out.vm_log = invocation.out_of_gas
            ? "JVM execution exhausted gas"
            : (invocation.out_of_memory
                   ? "JVM execution exhausted memory"
                   : "JVM execution failed");
        return out;
    }

    if (invocation.storage_root.is_null() ||
        !validate_jvm_storage_root(invocation.storage_root)) {
        return td::Status::Error(
            "JVM v2 output builder received invalid committed storage root");
    }

    auto action_list = invocation.action_list;
    if (action_list.is_null()) {
        action_list = empty_jvm_action_list();
    }
    if (action_list.is_null()) {
        return td::Status::Error(
            "JVM v2 output builder failed to build empty action list");
    }

    JvmContractAccountState next_state;
    next_state.schema_version = kJvmContractAccountStateSchemaVersion;
    next_state.stdlib_hash = config.stdlib_hash;
    next_state.class_hash = previous_state.class_hash;
    next_state.class_bytes = previous_state.class_bytes;
    next_state.storage_root = invocation.storage_root;
    next_state.manifest_root = previous_state.manifest_root;
    auto new_data = encode_jvm_contract_account_state(next_state);
    if (new_data.is_null()) {
        return td::Status::Error(
            "JVM v2 output builder failed to encode contract account state");
    }

    out.engine_success = true;
    out.committed = true;
    out.new_data = std::move(new_data);
    out.action_list = std::move(action_list);
    out.vm_log = "JVM execution completed";
    return out;
}

}  // namespace jvm_workchain
