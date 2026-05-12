/*
    JVM Workchain — narrow Avata execution bridge helpers.
*/
#include "jvm/core/avata-execution.h"

#include "block/transaction.h"
#include "jvm/avata/include/avata/context.h"
#include "jvm/avata/include/avata/crypto.h"
#include "jvm/avata/include/avata/event.h"
#include "jvm/avata/include/avata/message.h"
#include "jvm/avata/include/avata/storage.h"
#include "vm/boc.h"

#include <algorithm>
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

bool context_api_complete(const JvmAvataExecutionApi& api) {
    return api.set_contract_context != nullptr &&
           api.clear_contract_context != nullptr;
}

bool crypto_api_complete(const JvmAvataExecutionApi& api) {
    return api.set_crypto_host != nullptr &&
           api.clear_crypto_host != nullptr;
}

bool message_api_complete(const JvmAvataExecutionApi& api) {
    return api.set_message_host != nullptr &&
           api.clear_message_host != nullptr;
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
    JvmEventHost* events,
    const AvataContractContext* context,
    const AvataCryptoHost* crypto,
    JvmMessageHost* messages) {
    if (avata_thread == nullptr) {
        return td::Status::Error("JVM Avata execution received null thread");
    }
    if (!execution_api_complete(api)) {
        return td::Status::Error("JVM Avata execution API is incomplete");
    }
    if (events != nullptr && !event_api_complete(api)) {
        return td::Status::Error("JVM Avata event execution API is incomplete");
    }
    if (context != nullptr && !context_api_complete(api)) {
        return td::Status::Error(
            "JVM Avata context execution API is incomplete");
    }
    if (crypto != nullptr && !crypto_api_complete(api)) {
        return td::Status::Error(
            "JVM Avata crypto execution API is incomplete");
    }
    if (messages != nullptr && !message_api_complete(api)) {
        return td::Status::Error(
            "JVM Avata message execution API is incomplete");
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
    bool message_transaction_open = false;
    bool contract_transaction_open = false;
    bool context_installed = false;
    bool crypto_installed = false;
    auto clear_host = [&]() {
        if (crypto_installed) {
            api.clear_crypto_host();
            crypto_installed = false;
        }
        if (context_installed) {
            api.clear_contract_context();
            context_installed = false;
        }
        if (messages != nullptr) {
            api.clear_message_host();
        }
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
        if (message_transaction_open) {
            (void)messages->rollback_transaction();
            message_transaction_open = false;
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

    AvataMessageHost message_host{};
    if (messages != nullptr) {
        configure_avata_message_host(*messages, message_host);
        api.set_message_host(&message_host);
        auto message_status = messages->begin_transaction();
        if (message_status.is_error()) {
            return fail(message_status.move_as_error());
        }
        message_transaction_open = true;
    }

    if (context != nullptr) {
        api.set_contract_context(context);
        context_installed = true;
    }

    if (crypto != nullptr) {
        api.set_crypto_host(crypto);
        crypto_installed = true;
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
            if (message_transaction_open) {
                (void)messages->rollback_transaction();
                message_transaction_open = false;
            }
            clear_host();
            return event_status.move_as_error();
        }
    }

    if (messages != nullptr) {
        auto message_status = result.success
            ? messages->commit_transaction()
            : messages->rollback_transaction();
        message_transaction_open = false;
        if (message_status.is_error()) {
            clear_host();
            return message_status.move_as_error();
        }
    }

    clear_host();
    if (result.success) {
        result.storage_root = storage.root_cell();
        if (events != nullptr) {
            result.events = events->events();
        }
        if (messages != nullptr) {
            result.outbound_messages = messages->messages();
        }
        // Build the unified action list.  Event-only and message-only
        // cases compose cleanly because both branches walk a possibly-
        // empty vector; result.action_list ends up null only if every
        // vector is empty, which encodes as the canonical empty cell.
        td::Ref<vm::Cell> event_actions =
            (events != nullptr)
                ? build_jvm_event_action_list(result.events)
                : td::Ref<vm::Cell>{};
        if (events != nullptr && event_actions.is_null()) {
            return td::Status::Error(
                "JVM Avata event action list encode failed");
        }
        if (messages != nullptr) {
            auto combined = build_jvm_combined_action_list(
                std::move(event_actions), result.outbound_messages);
            if (combined.is_null()) {
                return td::Status::Error(
                    "JVM Avata outbound action list encode failed");
            }
            result.action_list = std::move(combined);
        } else {
            result.action_list = std::move(event_actions);
        }
    }
    return result;
}

td::Result<block::WorkchainComputeOutput> build_jvm_workchain_output(
    const JvmConfig& config,
    const JvmContractAccountState& previous_state,
    std::uint64_t gas_limit,
    const JvmAvataInvocationResult& invocation,
    bool storage_walk_already_billed) {
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
    if (previous_state.schema_version != kJvmContractAccountStateSchemaVersion ||
        previous_state.stdlib_hash != config.stdlib_hash ||
        previous_state.class_bytes.is_null()) {
        return td::Status::Error(
            "JVM output builder received incompatible previous account state");
    }
    if (invocation.success &&
        (invocation.out_of_gas || invocation.out_of_memory ||
         invocation.invocation_status != 0)) {
        return td::Status::Error(
            "JVM output builder received inconsistent success status");
    }

    // Round-34/35: charge an admission gas floor on every accepted
    // compute, so the resolver work that runs BEFORE Avata gas
    // accounting (manifest parse, args decode, class load on cache
    // miss, method resolution) is paid for.  The floor is also
    // enforced as a pre-runtime affordability gate in
    // `JvmNativeEngine::run_compute` (round 35), so low-balance
    // accounts cannot trigger unbilled resolver work.
    //
    // Floor is small enough to not bother normal contracts (typical
    // calls use 10k+ gas anyway) but high enough to cover worst-case
    // 1024-entry manifest parsing.  Constant defined in
    // avata-execution.h so both sides see the same value.
    const std::uint64_t effective_gas_used =
        std::max<std::uint64_t>(invocation.gas_used,
                                 kJvmAdmissionGasFloor);

    block::WorkchainComputeOutput out;
    out.completed = true;
    out.accepted = true;
    out.skip_reason = block::ComputePhase::sk_none;
    out.out_of_gas = invocation.out_of_gas;
    out.exit_code = invocation.success ? 0 : invocation.invocation_status;
    out.gas_used = effective_gas_used;
    out.gas_fees = jvm_gas_fees(config, effective_gas_used);

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

    if (invocation.storage_root.is_null()) {
        return td::Status::Error(
            "JVM output builder received null committed storage root");
    }
    // Round 12: dropped the call to `validate_jvm_storage_root(...)` that
    // used to walk every dictionary entry and decode every storage value
    // here on the post-execution path.  That walk happened OUTSIDE Avata
    // gas / memory accounting on every successful call, so a contract
    // with large accumulated storage made even a no-op call expensive
    // for validators (CPU proportional to total storage, not requested
    // gas).  Storage values are produced by the engine itself via
    // `JvmStorageCellHost::store` → `encode_jvm_storage_value`, so they
    // are well-formed by construction at this point; the structural
    // shape of the dictionary is checked by `vm::Dictionary` lookups at
    // load time, also under the contract's gas budget.
    //
    // Round 12 also adds enforcement of ConfigParam 85's
    // `max_storage_cells` (parsed since the v2 schema but never
    // checked).  CellStorageStat with `limit_cells = config.max_storage_cells`
    // performs a unique-cell walk with early termination, so the worst-
    // case cost is bounded by the configured cap rather than by total
    // storage.  We only walk when `invocation.storage_root` differs from
    // `previous_state.storage_root` — calls that don't mutate storage
    // skip the walk entirely.
    if (config.max_storage_cells > 0 && !storage_walk_already_billed) {
        const bool storage_changed =
            previous_state.storage_root.is_null() ||
            invocation.storage_root->get_hash()
                != previous_state.storage_root->get_hash();
        if (storage_changed) {
            vm::CellStorageStat stat(
                static_cast<unsigned long long>(config.max_storage_cells));
            auto stat_result =
                stat.add_used_storage(invocation.storage_root, true);
            if (stat_result.is_error()) {
                return td::Status::Error(
                    "JVM committed storage_root exceeds ConfigParam 85 "
                    "max_storage_cells");
            }
        }
    }

    auto action_list = invocation.action_list;
    if (action_list.is_null()) {
        action_list = empty_jvm_action_list();
    }
    if (action_list.is_null()) {
        return td::Status::Error(
            "JVM output builder failed to build empty action list");
    }

    JvmContractAccountState next_state;
    next_state.schema_version = kJvmContractAccountStateSchemaVersion;
    next_state.stdlib_hash = config.stdlib_hash;
    next_state.class_hash = previous_state.class_hash;
    // Forward `deployer` and `address_commit` so the engine's
    // address-binding gate keeps accepting subsequent calls on the same
    // account.  Only `storage_root` is allowed to change between calls;
    // `class_hash`, `class_bytes`, `manifest_root`, `stdlib_hash`,
    // `deployer`, and `address_commit` are pinned at deploy time.
    next_state.deployer = previous_state.deployer;
    next_state.address_commit = previous_state.address_commit;
    next_state.class_bytes = previous_state.class_bytes;
    next_state.storage_root = invocation.storage_root;
    next_state.manifest_root = previous_state.manifest_root;
    auto new_data = encode_jvm_contract_account_state(next_state);
    if (new_data.is_null()) {
        return td::Status::Error(
            "JVM output builder failed to encode contract account state");
    }

    out.engine_success = true;
    out.committed = true;
    out.new_data = std::move(new_data);
    out.action_list = std::move(action_list);
    out.vm_log = "JVM execution completed";
    return out;
}

}  // namespace jvm_workchain
