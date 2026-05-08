/*
    JVM Workchain — Avata-backed JvmComputeRuntime adapter implementation.
*/
#include "jvm/core/avata-runtime.h"

#include "jvm/avata/include/avata/contract.h"
#include "jvm/avata/include/avata/event.h"
#include "jvm/avata/include/avata/storage.h"
#include "jvm/core/class-manifest.h"
#include "jvm/core/message-abi.h"
#include "td/utils/logging.h"

#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace vm {
class Machine;
class Thread;
}  // namespace vm

namespace {

#if defined(_WIN32) || defined(__CYGWIN__)
#define TOS_AVATA_JNICALL __stdcall
#else
#define TOS_AVATA_JNICALL
#endif

using AvataJint = std::int32_t;
using AvataJBoolean = std::uint8_t;

constexpr AvataJint kAvataJniOk = 0;
constexpr AvataJint kAvataJniVersion16 = 0x00010006;
constexpr AvataJBoolean kAvataJniTrue = 1;

struct AvataJavaVMOption {
    char* optionString;
    void* extraInfo;
};

struct AvataJavaVMInitArgs {
    AvataJint version;
    AvataJint nOptions;
    AvataJavaVMOption* options;
    AvataJBoolean ignoreUnrecognized;
};

struct AvataJavaVMVTable {
    void* reserved0;
    void* reserved1;
    void* reserved2;
    AvataJint(TOS_AVATA_JNICALL* DestroyJavaVM)(vm::Machine*);
    void* AttachCurrentThread;
    void* DetachCurrentThread;
    void* GetEnv;
    void* AttachCurrentThreadAsDaemon;
};

struct AvataMachinePrefix {
    AvataJavaVMVTable* vtable;
};

}  // namespace

extern "C" AvataJint TOS_AVATA_JNICALL JNI_CreateJavaVM(
    vm::Machine** machine,
    vm::Thread** thread,
    void* args);

namespace jvm_workchain {

namespace {

struct LinkedAvataVmState {
    ~LinkedAvataVmState() {
        auto* machine_prefix =
            reinterpret_cast<AvataMachinePrefix*>(machine);
        if (machine_prefix != nullptr && machine_prefix->vtable != nullptr &&
            machine_prefix->vtable->DestroyJavaVM != nullptr) {
            (void)machine_prefix->vtable->DestroyJavaVM(machine);
        }
        machine = nullptr;
        thread = nullptr;
    }

    vm::Machine* machine{nullptr};
    vm::Thread* thread{nullptr};
    std::vector<std::string> option_storage;
};

struct LinkedAvataRuntimeState {
    JvmLinkedAvataRuntimeOptions options;
    std::map<std::string, std::shared_ptr<LinkedAvataVmState>> vm_cache;
};

struct LinkedAvataInvocation {
    AvataContractMethod method{0};
    JvmArgs args;
};

int invoke_linked_static_void_contract(void* thread, void* invocation_user) {
    auto* invocation = static_cast<LinkedAvataInvocation*>(invocation_user);
    if (invocation == nullptr || invocation->method == 0) {
        return AVATA_CONTRACT_BAD_ARGUMENT;
    }

    std::vector<AvataContractArg> args;
    args.reserve(invocation->args.values.size());
    for (const auto& value : invocation->args.values) {
        if (value.bytes.size() >
            std::numeric_limits<std::uint32_t>::max()) {
            return AVATA_CONTRACT_BAD_ARGUMENT;
        }
        AvataContractArg arg;
        arg.type = static_cast<std::uint8_t>(value.type);
        arg.bytes = value.bytes.empty() ? nullptr : value.bytes.data();
        arg.bytes_length = static_cast<std::uint32_t>(value.bytes.size());
        args.push_back(arg);
    }

    return avata_invoke_contract_static_void_args(
        reinterpret_cast<AvataThread*>(thread),
        invocation->method,
        args.empty() ? nullptr : args.data(),
        static_cast<std::uint32_t>(args.size()));
}

td::Result<std::shared_ptr<LinkedAvataVmState>> create_linked_avata_vm(
    const JvmLinkedAvataRuntimeOptions& options) {
    auto state = std::make_shared<LinkedAvataVmState>();
    state->option_storage.reserve(2 + options.extra_options.size() +
                                  (options.classpath.empty() ? 0 : 1));
    state->option_storage.push_back("-Xbootclasspath:" + options.boot_classpath);
    if (!options.classpath.empty()) {
        state->option_storage.push_back("-Djava.class.path=" +
                                        options.classpath);
    }
    state->option_storage.push_back("-Xmx" + options.max_heap);
    for (const auto& option : options.extra_options) {
        if (!option.empty()) {
            state->option_storage.push_back(option);
        }
    }

    std::vector<AvataJavaVMOption> vm_options;
    vm_options.reserve(state->option_storage.size());
    for (auto& option : state->option_storage) {
        AvataJavaVMOption vm_option;
        vm_option.optionString = const_cast<char*>(option.c_str());
        vm_option.extraInfo = nullptr;
        vm_options.push_back(vm_option);
    }

    AvataJavaVMInitArgs args;
    args.version = kAvataJniVersion16;
    args.nOptions = static_cast<AvataJint>(vm_options.size());
    args.options = vm_options.data();
    args.ignoreUnrecognized = kAvataJniTrue;

    const int status =
        JNI_CreateJavaVM(&state->machine, &state->thread, &args);
    if (status != kAvataJniOk || state->machine == nullptr ||
        state->thread == nullptr) {
        return td::Status::Error(
            PSTRING() << "JVM linked Avata runtime VM creation failed with status "
                      << status);
    }
    return state;
}

td::Result<JvmArgs> decode_linked_invocation_args(
    const std::string& method_spec,
    td::Ref<vm::Cell> args) {
    if (method_spec == kJvmStaticVoidMethodSpec &&
        validate_jvm_static_void_call_args(method_spec, args).is_ok()) {
        return JvmArgs{};
    }

    TRY_STATUS(validate_jvm_typed_call_args(method_spec, args));
    return parse_jvm_args(std::move(args));
}

td::Status install_account_class_into_vm(
    LinkedAvataVmState& vm_state,
    const std::string& class_name,
    const JvmStorageValue& class_bytes) {
    if (class_bytes.size() > std::numeric_limits<std::uint32_t>::max()) {
        return td::Status::Error(
            "JVM class bytes exceed Avata ABI length");
    }
    const int status = avata_define_contract_class(
        reinterpret_cast<AvataThread*>(vm_state.thread),
        class_name.c_str(),
        class_bytes.data(),
        static_cast<std::uint32_t>(class_bytes.size()));
    if (status != AVATA_CONTRACT_OK) {
        return td::Status::Error(
            PSTRING() << "JVM linked Avata class install failed with status "
                      << status);
    }
    return td::Status::OK();
}

std::string class_hash_cache_key(const JvmClassHash& class_hash) {
    return std::string(reinterpret_cast<const char*>(class_hash.data()),
                       class_hash.size());
}

td::Result<std::shared_ptr<LinkedAvataVmState>> get_vm_for_account(
    LinkedAvataRuntimeState& state,
    const JvmContractAccountState& previous_state,
    const std::string& class_name) {
    // Cache key is `class_hash` (sha256 of class bytes).  Two contract
    // accounts that deploy the same class share one cached VM, mirroring the
    // Cell DB physical dedup of `class_bytes` itself.
    const auto key = class_hash_cache_key(previous_state.class_hash);
    auto it = state.vm_cache.find(key);
    if (it != state.vm_cache.end()) {
        return it->second;
    }
    TRY_RESULT(vm_state, create_linked_avata_vm(state.options));
    TRY_RESULT(class_bytes,
               decode_jvm_storage_value(previous_state.class_bytes));
    TRY_STATUS(
        install_account_class_into_vm(*vm_state, class_name, class_bytes));
    state.vm_cache.emplace(key, vm_state);
    return vm_state;
}

td::Result<JvmAvataCallTarget> linked_avata_resolve_call_target(
    const block::WorkchainComputeInput& input,
    const block::WorkchainComputeContext& context,
    const JvmConfig& config,
    const JvmContractAccountState& previous_state,
    void* user) {
    (void)context;
    (void)config;

    auto* state = static_cast<LinkedAvataRuntimeState*>(user);
    if (state == nullptr) {
        return td::Status::Error(
            "JVM linked Avata resolver is missing runtime state");
    }
    if (previous_state.manifest_root.is_null()) {
        return td::Status::Error(
            "JVM linked Avata resolver is missing per-account manifest");
    }
    if (previous_state.class_bytes.is_null()) {
        return td::Status::Error(
            "JVM linked Avata resolver is missing class_bytes");
    }

    TRY_RESULT(call, parse_jvm_call_descriptor(input.inbound_body));
    TRY_RESULT(entry,
               find_jvm_method_manifest_entry(previous_state.manifest_root,
                                              call.method_id));
    TRY_RESULT(decoded_args,
               decode_linked_invocation_args(entry.method_spec, call.args));
    TRY_RESULT(vm_state,
               get_vm_for_account(*state, previous_state, entry.class_name));
    if (vm_state->thread == nullptr) {
        return td::Status::Error(
            "JVM linked Avata resolver is missing VM thread");
    }

    AvataContractMethod method = 0;
    const int status = avata_resolve_contract_static_void(
        reinterpret_cast<AvataThread*>(vm_state->thread),
        entry.class_name.c_str(),
        entry.method_name.c_str(),
        entry.method_spec.c_str(),
        &method);
    if (status != AVATA_CONTRACT_OK || method == 0) {
        return td::Status::Error(
            PSTRING() << "JVM v2 linked Avata resolver failed with status "
                      << status);
    }

    auto invocation = std::make_shared<LinkedAvataInvocation>();
    invocation->method = method;
    invocation->args = std::move(decoded_args);

    JvmAvataCallTarget target;
    target.thread = vm_state->thread;
    target.invocation_user = invocation.get();
    target.invocation_owner = std::move(invocation);
    return target;
}

}  // namespace

JvmAvataRuntime::JvmAvataRuntime(
    JvmAvataExecutionApi api,
    JvmAvataResolveCallTarget resolve_call_target,
    void* resolve_user,
    std::shared_ptr<void> resolve_owner)
    : api_(api)
    , resolve_call_target_(resolve_call_target)
    , resolve_user_(resolve_user)
    , resolve_owner_(std::move(resolve_owner)) {
}

td::Result<JvmAvataInvocationResult> JvmAvataRuntime::run_contract(
    const block::WorkchainComputeInput& input,
    const block::WorkchainComputeContext& context,
    const JvmConfig& config,
    const JvmContractAccountState& previous_state) const {
    if (resolve_call_target_ == nullptr) {
        return td::Status::Error(
            "JVM Avata runtime is missing call target resolver");
    }
    if (!validate_jvm_storage_root(previous_state.storage_root)) {
        return td::Status::Error(
            "JVM Avata runtime received invalid storage root");
    }

    std::lock_guard<std::mutex> guard(mutex_);
    TRY_RESULT(target,
               resolve_call_target_(input,
                                    context,
                                    config,
                                    previous_state,
                                    resolve_user_));
    if (target.thread == nullptr) {
        return td::Status::Error(
            "JVM Avata runtime resolver returned null thread");
    }

    JvmStorageCellHost storage(previous_state.storage_root);
    JvmEventHost events;
    return execute_jvm_avata_transaction(target.thread,
                                         config,
                                         input.gas_limit,
                                         storage,
                                         api_,
                                         target.invocation_user,
                                         &events);
}

JvmAvataExecutionApi make_linked_jvm_avata_execution_api() {
    JvmAvataExecutionApi api;
    api.ok_status = AVATA_CONTRACT_OK;
    api.out_of_gas_status = AVATA_CONTRACT_OUT_OF_GAS;
    api.out_of_memory_status = AVATA_CONTRACT_OUT_OF_MEMORY;
    api.gas_api.ok_status = AVATA_CONTRACT_OK;
    api.gas_api.set_opcode_gas_costs = reinterpret_cast<JvmAvataSetOpcodeGasCosts>(
        avata_set_opcode_gas_costs);
    api.gas_api.set_contract_helper_gas_costs =
        reinterpret_cast<JvmAvataSetContractHelperGasCosts>(
            avata_set_contract_helper_gas_costs);
    api.set_storage_host = avata_set_storage_host;
    api.clear_storage_host = avata_clear_storage_host;
    api.set_event_host = avata_set_event_host;
    api.clear_event_host = avata_clear_event_host;
    api.begin_contract_transaction_with_limits =
        reinterpret_cast<JvmAvataBeginContractTransactionWithLimits>(
            avata_begin_contract_transaction_with_limits);
    api.end_contract_transaction =
        reinterpret_cast<JvmAvataEndContractTransaction>(
            avata_end_contract_transaction);
    api.contract_remaining_gas =
        reinterpret_cast<JvmAvataContractRemainingGas>(
            avata_contract_remaining_gas);
    api.contract_memory_used =
        reinterpret_cast<JvmAvataContractMemoryUsed>(
            avata_contract_memory_used);
    api.invoke_contract = invoke_linked_static_void_contract;
    return api;
}

td::Result<std::shared_ptr<const JvmComputeRuntime>>
make_linked_jvm_avata_runtime(const JvmLinkedAvataRuntimeOptions& options) {
    if (options.boot_classpath.empty()) {
        return td::Status::Error(
            "JVM linked Avata runtime requires a boot classpath");
    }
    if (options.max_heap.empty()) {
        return td::Status::Error(
            "JVM linked Avata runtime requires a max heap option");
    }

    auto state = std::make_shared<LinkedAvataRuntimeState>();
    state->options = options;

    // Validate the boot runtime eagerly so init_jvm_workchain() still fails
    // closed on an unusable rt.jar.  Execution VMs are cached per class_hash
    // so contracts sharing identical bytecode share one cached VM.
    TRY_RESULT(probe_vm, create_linked_avata_vm(state->options));
    (void)probe_vm;

    std::shared_ptr<const JvmComputeRuntime> runtime =
        std::make_shared<JvmAvataRuntime>(
            make_linked_jvm_avata_execution_api(),
            linked_avata_resolve_call_target,
            state.get(),
            state);
    return runtime;
}

}  // namespace jvm_workchain
