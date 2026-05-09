/*
    JVM Workchain — Avata-backed JvmComputeRuntime adapter implementation.
*/
#include "jvm/core/avata-runtime.h"

#include "jvm/avata/include/avata/contract.h"
#include "jvm/avata/include/avata/event.h"
#include "jvm/avata/include/avata/storage.h"
#include "jvm/core/class-manifest.h"
#include "jvm/core/message-abi.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "td/utils/SharedSlice.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

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

// Round-33 fix: bound the per-class Avata VM cache.  Pre-fix the
// `class_hash` -> VM map was unbounded; a sender able to cause many
// distinct deploys / calls (each one with a fresh class_hash) could
// force unbounded persistent VM growth and repeat the unmetered
// class-load work on every miss.  When the cache is full we evict
// an arbitrary existing entry rather than reject — JVMs share the
// same rt.jar so eviction is safe; the only cost is re-loading
// `class_bytes` if the same class_hash recurs.  Setting this to
// 256 keeps memory bounded (few hundred MiB at the worst case)
// while still amortizing class-load across calls for the typical
// few-active-contracts workload.
constexpr std::size_t kJvmAvataVmCacheMaxEntries = 256;

struct LinkedAvataRuntimeState {
    JvmLinkedAvataRuntimeOptions options;
    std::map<std::string, std::shared_ptr<LinkedAvataVmState>> vm_cache;
    // Hash of the boot classpath bytes captured at runtime startup
    // (round-17).  Round-18 also uses this to defend against rt.jar
    // changing on disk between startup and lazy VM creation: every
    // cache-miss VM creation re-hashes the boot classpath and rejects
    // if it disagrees with this captured value.
    std::array<std::uint8_t, 32> rt_jar_hash{};
    // Round-19/20/21: a process-private chmod-0700 directory we
    // mkdtemp at startup, plus the chmod-0600 file paths for every
    // boot classpath entry inside it.  `options.boot_classpath` is
    // rewritten to point at these copies, so the JVM's
    // `JNI_CreateJavaVM`/`Finder` mapping cannot pull bytes that
    // disagree with `rt_jar_hash`.  Round-21 dropped the previous
    // reliance on `/tmp` being root-owned + sticky: even a non-root
    // owner of the parent dir can unlink children under sticky-only
    // permissions, but mkdtemp inside `/tmp` produces a directory
    // we own with 0700, where only our UID has any access at all.
    std::string private_classpath_dir;
    std::vector<std::string> private_classpath_files;
    ~LinkedAvataRuntimeState() {
        for (const auto& path : private_classpath_files) {
            (void)::unlink(path.c_str());
        }
        if (!private_classpath_dir.empty()) {
            (void)::rmdir(private_classpath_dir.c_str());
        }
    }
};

// Hash the `:`-separated boot classpath, feeding each entry's file
// bytes (in listed order) through sha256.  Empty entries are skipped
// to mirror Avata's own tokenizer behavior.  Used both at runtime
// startup and on every lazy VM creation to ensure the bytes that
// `JNI_CreateJavaVM` will read still match ConfigParam 85's
// `stdlib_hash` commitment.
//
// Round-19: length-prefix each entry so the hash is a canonical
// commitment to (entry_count, entry_lengths, entry_bytes) rather
// than the raw concatenation of bytes.  Without prefixes,
// `[a, bc]` and `[ab, c]` would hash to the same value, which is
// a domain-separation bug for multi-entry classpaths (the current
// production config uses a single rt.jar so the same hash is
// produced either way, but a future multi-entry config would
// silently collide).  We also feed a fixed domain tag so the same
// helper output cannot be confused with a sha256 over arbitrary
// concatenated data.
td::Result<std::array<std::uint8_t, 32>> hash_boot_classpath(
    const std::string& boot_classpath) {
    std::array<std::uint8_t, 32> out{};
    td::Sha256State sha;
    sha.init();
    static constexpr td::Slice kDomain{
        "TOS-JVM-AVATA-BOOTCLASSPATH-v1"};
    sha.feed(kDomain);
    std::string remaining = boot_classpath;
    std::uint64_t entry_count = 0;
    while (!remaining.empty()) {
        auto colon = remaining.find(':');
        std::string entry = (colon == std::string::npos)
                                ? remaining
                                : remaining.substr(0, colon);
        remaining = (colon == std::string::npos)
                        ? std::string{}
                        : remaining.substr(colon + 1);
        if (entry.empty()) {
            continue;
        }
        auto data = td::read_file(entry);
        if (data.is_error()) {
            return td::Status::Error(
                PSLICE() << "JVM Avata runtime cannot hash boot classpath "
                            "entry "
                         << entry << ": " << data.error().message());
        }
        const auto bytes = data.move_as_ok();
        // Length prefix (8-byte big-endian) before the entry bytes
        // ensures unique encoding regardless of split between
        // entries.
        const std::uint64_t len = bytes.size();
        std::uint8_t len_be[8];
        for (int i = 0; i < 8; ++i) {
            len_be[i] = static_cast<std::uint8_t>(len >> (56 - i * 8));
        }
        sha.feed(td::Slice(reinterpret_cast<const char*>(len_be), 8));
        sha.feed(td::Slice(bytes.data(), bytes.size()));
        ++entry_count;
    }
    // Trailing entry-count provides a second domain anchor against any
    // attempt to swap entries while preserving total bytes.
    std::uint8_t count_be[8];
    for (int i = 0; i < 8; ++i) {
        count_be[i] =
            static_cast<std::uint8_t>(entry_count >> (56 - i * 8));
    }
    sha.feed(td::Slice(reinterpret_cast<const char*>(count_be), 8));
    sha.extract(td::MutableSlice(reinterpret_cast<char*>(out.data()),
                                  out.size()));
    return out;
}

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
    state->option_storage.reserve(3 + options.extra_options.size());
    state->option_storage.push_back("-Xbootclasspath:" + options.boot_classpath);
    // Round-18 fix: ALWAYS emit `-Djava.class.path=...` so Avata cannot
    // fall back to its default of "." (the current working directory),
    // which would let local jars/directories influence FindClass
    // results.  Contract bytecode only reaches the VM via JVAC
    // `class_bytes` + `avata_load_class_bytes`; the application
    // classpath should not contribute.  When `options.classpath` is
    // empty we still emit the option with no value so the override
    // takes effect.
    state->option_storage.push_back("-Djava.class.path=" + options.classpath);
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
    // Round 63 MEDIUM fix: for a static-void spec, propagate the
    // validation result directly instead of falling through to the
    // typed-args decode.  Pre-fix the fall-through path called
    // `parse_jvm_args` (full byte memcpy of every typed value)
    // before catching the count mismatch in
    // `validate_jvm_typed_args_against_spec`, leaking unbilled
    // resolver work for an attacker who attached a large `Bytes`
    // payload to a `()V` call.
    if (method_spec == kJvmStaticVoidMethodSpec) {
        TRY_STATUS(validate_jvm_static_void_call_args(method_spec, args));
        return JvmArgs{};
    }

    // Round 61 MEDIUM fix: parse the typed args ONCE.  Pre-fix
    // `validate_jvm_typed_call_args` itself called `parse_jvm_args`
    // and we then called it again here, doubling the byte-decode
    // work (memcpy of every typed `Bytes` argument's payload chain)
    // before any Avata gas was charged.  Now parse once and reuse
    // the parsed result for type validation.
    TRY_RESULT(decoded_args, parse_jvm_args(std::move(args)));
    TRY_STATUS(validate_jvm_typed_args_against_spec(method_spec, decoded_args));
    return decoded_args;
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
    // Round-18 fix: re-hash the boot classpath on every cache-miss
    // VM creation and verify it still matches the startup hash.
    // Without this, an attacker (or an operator's misconfigured CD
    // pipeline) could swap rt.jar on disk between
    // `make_linked_jvm_avata_runtime` and the first lazy VM creation,
    // and the new VM would load different bytes silently while
    // `runtime->rt_jar_hash()` still reports the stale startup hash.
    TRY_RESULT(current_jar_hash,
               hash_boot_classpath(state.options.boot_classpath));
    if (current_jar_hash != state.rt_jar_hash) {
        return td::Status::Error(
            "JVM Avata runtime: boot classpath bytes on disk no longer "
            "match the startup hash; refusing to instantiate a VM that "
            "would diverge from ConfigParam 85 stdlib_hash");
    }
    TRY_RESULT(vm_state, create_linked_avata_vm(state.options));
    TRY_RESULT(class_bytes,
               decode_jvm_storage_value(previous_state.class_bytes));
    TRY_STATUS(
        install_account_class_into_vm(*vm_state, class_name, class_bytes));
    // Round-33 fix: bound the cache to prevent unbounded growth from
    // distinct class_hashes.  Evict an arbitrary existing entry
    // (begin() in std::map is the smallest-keyed entry; we don't
    // need LRU semantics — eviction just amortizes class-load cost
    // across callers, and any evicted contract that recurs simply
    // re-installs at next-call cost).
    if (state.vm_cache.size() >= kJvmAvataVmCacheMaxEntries) {
        state.vm_cache.erase(state.vm_cache.begin());
    }
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
    std::shared_ptr<void> resolve_owner,
    std::array<std::uint8_t, 32> rt_jar_hash)
    : api_(api)
    , resolve_call_target_(resolve_call_target)
    , resolve_user_(resolve_user)
    , resolve_owner_(std::move(resolve_owner))
    , rt_jar_hash_(rt_jar_hash) {
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
    // NOTE: deliberately NOT walking the full storage tree here for the
    // same reason `decode_jvm_contract_account_state` no longer does:
    // post-round-9, the per-call O(N) walk over total storage size was a
    // DoS vector — every minimal-gas call paid validator CPU proportional
    // to the contract's accumulated storage before any gas was metered.
    // Storage values decode lazily in `JvmStorageCellHost::load` under
    // the contract's gas budget.  The first-activation invariant
    // (`storage_root.is_null()` when `msg_state_used == true`) keeps an
    // attacker from injecting a malformed storage tree at deploy time.

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
    // Round 61 MEDIUM fix: bill the contract for the per-byte
    // validator-CPU work spent decoding + materializing typed
    // `Bytes` arguments BEFORE Avata gas accounting started.  The
    // resolver above ran `decode_linked_invocation_args` (which
    // memcpys each typed value's payload chain) and, at runtime
    // entry, the Avata `make_byte_backed_value` path further
    // allocates and copies a Java `byte[]` per argument — work
    // proportional to the args' total byte count for which Avata's
    // metered execution does NOT charge.  Sum the decoded arg
    // payload bytes and add them to the result's gas_used after
    // execute_jvm_avata_transaction returns.  Same pattern as the
    // round-39 storage walk billing: dispatch-engine.cpp's round-40
    // affordable-gas cap catches the overflow and rejects with
    // `sk_no_gas` if the total exceeds what the account can pay.
    std::uint64_t arg_bytes_charge = 0;
    if (target.invocation_owner != nullptr) {
        auto* inv =
            static_cast<LinkedAvataInvocation*>(target.invocation_user);
        if (inv != nullptr) {
            for (const auto& v : inv->args.values) {
                if (arg_bytes_charge >
                    std::numeric_limits<std::uint64_t>::max() - v.bytes.size()) {
                    arg_bytes_charge =
                        std::numeric_limits<std::uint64_t>::max();
                    break;
                }
                arg_bytes_charge += v.bytes.size();
            }
        }
    }
    auto exec_res = execute_jvm_avata_transaction(target.thread,
                                                  config,
                                                  input.gas_limit,
                                                  storage,
                                                  api_,
                                                  target.invocation_user,
                                                  &events);
    if (exec_res.is_error()) {
        return exec_res.move_as_error();
    }
    auto result = exec_res.move_as_ok();
    if (result.gas_used >
        std::numeric_limits<std::uint64_t>::max() - arg_bytes_charge) {
        result.gas_used = std::numeric_limits<std::uint64_t>::max();
    } else {
        result.gas_used += arg_bytes_charge;
    }
    return result;
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

// Create a process-private chmod-0700 directory under /tmp via
// mkdtemp.  Round-21 made the directory itself 0700, but the
// PARENT (`/tmp`) must also be trusted: the parent's owner can
// always rename or rmdir its children regardless of those
// children's modes (sticky bit only blocks NON-owner unlinks),
// and could then substitute an attacker-controlled directory or
// symlink in our private path before we open files inside it.
// Round-22 therefore validates /tmp itself: it must be a
// directory, sticky (S_ISVTX), and owned by either uid 0 or our
// own euid.  An operator who needs JVM v2 on a host where /tmp is
// owned by some other uid (e.g., a container that maps /tmp to a
// non-root user that isn't the validator's euid) must remount it
// or run the validator under that uid.
td::Result<std::string> create_private_classpath_dir() {
    static constexpr const char* kTmpDir = "/tmp";
    {
        struct stat st{};
        if (::stat(kTmpDir, &st) != 0) {
            return td::Status::Error(
                PSLICE() << "JVM Avata runtime cannot stat " << kTmpDir
                         << ": " << std::strerror(errno));
        }
        if (!S_ISDIR(st.st_mode)) {
            return td::Status::Error(
                PSLICE() << "JVM Avata runtime: " << kTmpDir
                         << " is not a directory");
        }
        if ((st.st_mode & S_ISVTX) == 0) {
            return td::Status::Error(
                PSLICE() << "JVM Avata runtime requires " << kTmpDir
                         << " to have the sticky bit set; otherwise non-"
                            "owner UIDs could unlink children");
        }
        const uid_t euid = ::geteuid();
        if (st.st_uid != 0 && st.st_uid != euid) {
            return td::Status::Error(
                PSLICE() << "JVM Avata runtime requires " << kTmpDir
                         << " to be owned by uid 0 or our euid (" << euid
                         << "); a third-party owner could rename or rmdir "
                            "our private directory");
        }
    }

    std::string tmpl = std::string(kTmpDir) + "/tos-jvm-rtjar-XXXXXX";
    if (::mkdtemp(&tmpl[0]) == nullptr) {
        return td::Status::Error(
            PSLICE() << "JVM Avata runtime mkdtemp failed for "
                     << tmpl << ": " << std::strerror(errno));
    }
    // mkdtemp guarantees 0700 on Linux, but be explicit so other
    // platforms cannot widen the mode through umask.
    if (::chmod(tmpl.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) != 0) {
        ::rmdir(tmpl.c_str());
        return td::Status::Error(
            PSLICE() << "JVM Avata runtime chmod 0700 failed for "
                     << tmpl << ": " << std::strerror(errno));
    }
    return tmpl;
}

// Round-23/24: defend against `META-INF/MANIFEST.MF Class-Path:`
// entries that would let the JAR loader pull in jars outside the
// consensus-committed boot classpath.  Round 23 used a raw byte
// scan, but that misses compressed (deflated) manifest entries
// where the literal `Class-Path:` is hidden inside the compressed
// stream.  Round 24 strengthens the check by:
//   1. Parsing the ZIP central directory.
//   2. Requiring every entry to use compression method 0 (STORED)
//      so the raw byte scan works reliably.  Our canonical
//      `jar c0f` build already produces stored-only archives.
//   3. Then running the raw byte scan for the literal in any
//      common case spelling.
//
// `validate_jar_no_compression_or_class_path` returns false if
// either the central directory cannot be parsed, an entry uses a
// non-stored compression method, or any byte run matches the
// `Class-Path:` literal.  Conservative on all three axes.
bool jar_bytes_contain_class_path_header(td::Slice bytes) {
    static constexpr td::Slice kNeedle{"Class-Path:"};
    static constexpr td::Slice kNeedleLower{"class-path:"};
    static constexpr td::Slice kNeedleUpper{"CLASS-PATH:"};
    if (bytes.size() < kNeedle.size()) {
        return false;
    }
    auto contains = [&](td::Slice needle) {
        for (std::size_t i = 0; i + needle.size() <= bytes.size(); ++i) {
            if (std::memcmp(bytes.data() + i, needle.data(),
                            needle.size()) == 0) {
                return true;
            }
        }
        return false;
    };
    return contains(kNeedle) || contains(kNeedleLower) ||
           contains(kNeedleUpper);
}

// Read a 16-bit / 32-bit little-endian integer from `data`.  ZIP
// is canonically little-endian.
inline std::uint16_t le16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(
        static_cast<std::uint32_t>(p[0]) |
        (static_cast<std::uint32_t>(p[1]) << 8));
}
inline std::uint32_t le32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

// Walk the ZIP central directory and return false if any entry uses
// a compression method other than 0 (stored).  Used so the raw byte
// scan for `Class-Path:` is reliable — a compressed manifest entry
// would hide the literal inside a deflated stream and bypass the
// scan.  Round-24 confirmed this gap with `jar cfm` (default
// deflate).
//
// Round-25: parser-disagreement defense.  Avata's loader does NOT
// trust EOCD `cd_total_entries`; it walks consecutive central-
// directory headers until a non-entry signature
// (jvm/avata/src/finder.cpp).  An attacker can therefore set
// `cd_total_entries=1` with a benign STORED first entry and a
// deflated duplicate `META-INF/MANIFEST.MF` immediately after; if
// our walker stops at the EOCD count, it misses the second entry.
// We mirror Avata: walk by signature, verify every entry is STORED,
// and additionally cross-check that the EOCD count and size match
// the actual walked entries (so no parser disagreement is allowed).
bool jar_all_entries_stored(td::Slice bytes) {
    // End-of-central-directory (EOCD) signature 0x06054b50.  Search
    // the last 65557 bytes (max EOCD size including comment).
    if (bytes.size() < 22) return false;
    const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(bytes.data());
    const std::size_t n = bytes.size();
    const std::size_t scan_from =
        (n > 65557) ? (n - 65557) : 0;
    std::size_t eocd_off = std::string::npos;
    for (std::size_t i = (n >= 22 ? n - 22 : 0); i + 4 <= n && i >= scan_from;
         --i) {
        if (le32(p + i) == 0x06054b50u) {
            eocd_off = i;
            break;
        }
        if (i == 0) break;
    }
    if (eocd_off == std::string::npos) {
        return false;
    }
    // EOCD layout (22 bytes minimum):
    //   sig(4) disk(2) cd_disk(2) cd_entries_disk(2)
    //   cd_total_entries(2) cd_size(4) cd_offset(4) comment_len(2)
    if (eocd_off + 22 > n) return false;
    const std::uint16_t cd_entries_claimed = le16(p + eocd_off + 10);
    const std::uint32_t cd_size_claimed = le32(p + eocd_off + 12);
    const std::uint32_t cd_offset = le32(p + eocd_off + 16);
    const std::uint16_t comment_len = le16(p + eocd_off + 20);
    // Round-26 fix: anchor `cd_offset` to the EOCD position.  Without
    // this, an attacker can point `cd_offset` at bytes inside a
    // STORED entry's body that LOOK like central-directory headers
    // (and even satisfy the round-25 walk + count/size cross-check)
    // while the real central directory lives elsewhere.  Avata's
    // loader follows whatever `cd_offset` says, so the guard's view
    // and the loader's view diverge whenever `cd_offset` does not
    // point at the actual CD.  The canonical layout has the CD
    // immediately followed by EOCD; require that exactly.
    if (static_cast<std::uint64_t>(cd_offset)
            + static_cast<std::uint64_t>(cd_size_claimed) != eocd_off) {
        return false;
    }
    // Also pin the EOCD's own length: header (22) + comment must
    // exactly equal the trailing bytes.  Otherwise garbage past the
    // EOCD comment could later be parsed as a separate trailer or
    // mask alternative metadata.
    if (eocd_off + 22u + comment_len != n) {
        return false;
    }

    // Walk every central-directory header from `cd_offset` until we
    // see a non-entry signature, mirroring Avata's loader.  Reject
    // if any entry is non-STORED (method != 0), if any header is
    // truncated, or if the actual entry count / total size disagrees
    // with the EOCD-claimed values (parser disagreement is the
    // round-25 attack).
    std::size_t off = cd_offset;
    std::uint32_t walked = 0;
    while (off + 4 <= n) {
        const std::uint32_t sig = le32(p + off);
        if (sig != 0x02014b50u) {
            // First non-entry signature ends the central directory.
            break;
        }
        if (off + 46 > n) return false;
        const std::uint16_t method = le16(p + off + 10);
        if (method != 0) {
            return false;
        }
        const std::uint16_t name_len = le16(p + off + 28);
        const std::uint16_t extra_len = le16(p + off + 30);
        const std::uint16_t comment_len = le16(p + off + 32);
        // Round-27 fix: validate the central entry's local-header
        // offset and data range.  Avata's loader uses
        // `localHeaderOffset` and the central `compressed_size` to
        // map entry data; a crafted archive can pass the EOCD/CD
        // anchor checks but point a central entry's local-header
        // offset near/beyond EOF, causing an out-of-bounds read or
        // crash on probe/load.  Validate each central entry's local
        // header structurally before handing the file to Avata.
        const std::uint32_t comp_size_central = le32(p + off + 20);
        const std::uint32_t local_off = le32(p + off + 42);
        // Round-28 fix: 32-bit additions of `local_off + 30u` can
        // wrap when `local_off` is near UINT32_MAX, then the
        // subsequent `p + local_off` dereferences out of bounds.
        // Use subtraction-form bounds checks (no addition) before
        // any pointer formation.
        if (local_off > n || n - local_off < 30u) {
            return false;
        }
        if (le32(p + local_off) != 0x04034b50u) {
            return false;
        }
        const std::uint16_t local_method = le16(p + local_off + 8);
        if (local_method != 0) {
            return false;
        }
        const std::uint16_t local_name_len = le16(p + local_off + 26);
        const std::uint16_t local_extra_len = le16(p + local_off + 28);
        // 64-bit arithmetic for the cumulative local header span.
        const std::uint64_t local_header_total =
            static_cast<std::uint64_t>(local_off) + 30u +
            local_name_len + local_extra_len;
        if (local_header_total > n) {
            return false;
        }
        // Round-28 fix: require local entry data to end before the
        // CENTRAL DIRECTORY, not merely before the end of the
        // archive.  Otherwise a malformed JAR can place compressed
        // entry bytes that overlap the central-directory or EOCD
        // span, producing a ZIP polyglot whose Avata-loaded data
        // intersects metadata regions.  The canonical layout has
        // locals strictly before the CD, the CD before EOCD.
        if (local_header_total
                + static_cast<std::uint64_t>(comp_size_central)
            > cd_offset) {
            return false;
        }
        // Central directory must place its local header before the
        // central directory itself (canonical layout).
        if (local_off >= cd_offset) {
            return false;
        }
        const std::size_t entry_size =
            46u + name_len + extra_len + comment_len;
        if (off + entry_size > n) return false;
        off += entry_size;
        ++walked;
        if (walked == 0xFFFFu) {
            // EOCD's 16-bit count cannot represent more than 65535
            // entries (Zip64 would be needed); reject to avoid
            // ambiguity.
            return false;
        }
    }
    // Must end exactly at the EOCD position (which the round-26
    // anchor check above proved equals `cd_offset + cd_size_claimed`),
    // AND the actual walked count must match the claimed count.
    // Either disagreement is the round-25 / round-26 attack vector.
    if (walked != cd_entries_claimed) {
        return false;
    }
    if (off != eocd_off) {
        return false;
    }
    return true;
}

// Copy a single boot classpath entry into the process-private
// 0700 directory, returning the new path.  The original entry is
// read once into memory; the caller deletes the returned path when
// the runtime state is torn down.  Used by
// `make_linked_jvm_avata_runtime` to remove the round-19 TOCTOU
// window between our hash and the JVM's `JNI_CreateJavaVM` mapping.
td::Result<std::string> materialize_private_classpath_entry(
    const std::string& private_dir,
    std::size_t index,
    const std::string& src_path) {
    auto data = td::read_file(src_path);
    if (data.is_error()) {
        return td::Status::Error(
            PSLICE() << "JVM Avata runtime cannot read boot classpath "
                        "entry "
                     << src_path << " for private copy: "
                     << data.error().message());
    }
    const auto bytes = data.move_as_ok();
    // Round-24: require the JAR's central directory to use only the
    // STORED (uncompressed) method.  A deflated manifest would hide
    // the `Class-Path:` literal inside the compressed stream and
    // bypass the byte scan below.  Our canonical `jar c0f` build
    // already produces stored-only archives.
    if (!jar_all_entries_stored(td::Slice(bytes.data(), bytes.size()))) {
        return td::Status::Error(
            PSLICE() << "JVM Avata runtime: boot classpath entry "
                     << src_path
                     << " uses a compressed JAR entry; the consensus-bound "
                        "rt.jar must be built with stored-only entries "
                        "(`jar c0f`) so the manifest Class-Path scan can "
                        "see literal headers");
    }
    // Reject any boot classpath entry whose bytes contain a manifest
    // `Class-Path:` header.  Reliable now that all entries are
    // STORED — see `jar_bytes_contain_class_path_header` for the
    // rationale.
    if (jar_bytes_contain_class_path_header(
            td::Slice(bytes.data(), bytes.size()))) {
        return td::Status::Error(
            PSLICE() << "JVM Avata runtime: boot classpath entry "
                     << src_path
                     << " contains a 'Class-Path:' manifest header; that "
                        "would let it pull external jars not committed "
                        "by ConfigParam 85 stdlib_hash");
    }

    char idx_buf[32];
    std::snprintf(idx_buf, sizeof(idx_buf), "%04zu.bin", index);
    std::string out_path = private_dir + "/" + idx_buf;
    int fd = ::open(out_path.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                    S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return td::Status::Error(
            PSLICE() << "JVM Avata runtime open failed for "
                     << out_path << ": " << std::strerror(errno));
    }
    if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        ::close(fd);
        ::unlink(out_path.c_str());
        return td::Status::Error(
            PSLICE() << "JVM Avata runtime fchmod 0600 failed for "
                     << out_path << ": " << std::strerror(errno));
    }
    std::size_t written = 0;
    while (written < bytes.size()) {
        ssize_t n = ::write(fd, bytes.data() + written,
                            bytes.size() - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            ::unlink(out_path.c_str());
            return td::Status::Error(
                PSLICE() << "JVM Avata runtime write failed for "
                         << out_path << ": " << std::strerror(errno));
        }
        written += static_cast<std::size_t>(n);
    }
    if (::close(fd) != 0) {
        ::unlink(out_path.c_str());
        return td::Status::Error(
            PSLICE() << "JVM Avata runtime close failed for "
                     << out_path << ": " << std::strerror(errno));
    }
    return out_path;
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

    // Round-20: reject security-sensitive caller-supplied options at
    // the runtime boundary so a future internal caller cannot
    // accidentally override the private-copy boot classpath or
    // re-enable the application classpath that round-18 closed.
    // The current production caller (`init_jvm_workchain`) leaves
    // both empty so this is not reachable today, but defending the
    // invariant in code is cheap.
    if (!options.classpath.empty()) {
        return td::Status::Error(
            "JVM linked Avata runtime: caller-supplied classpath is not "
            "allowed (would re-enable application classpath that round-18 "
            "explicitly closes); contracts must reach the VM only via JVAC "
            "class_bytes");
    }
    // Round-21: reject ALL caller-supplied `extra_options`.  Round-20
    // narrowly rejected `-Xbootclasspath` and `-Djava.class.path`, but
    // arbitrary `-D` properties still enter Avata's VM property table
    // and Avata-specific keys (e.g. `-Davata.bootstrap`) affect
    // bootstrap / native library loading.  A future internal caller
    // could pass any such property after the runtime's protected
    // options and silently change the VM's class-loading or native
    // surface while `runtime->rt_jar_hash()` still reports the
    // private-copy hash.  Production `init_jvm_workchain` leaves
    // extra_options empty, so this is a hard close on a latent
    // boundary — callers that genuinely need to extend the VM
    // command line must add an allowlisted helper rather than the
    // freeform list.
    if (!options.extra_options.empty()) {
        return td::Status::Error(
            "JVM linked Avata runtime: caller-supplied extra_options are "
            "not allowed; the consensus-bound rt.jar is the only sanctioned "
            "VM input and arbitrary -D / -X options can affect class "
            "loading or native surface in ways not committed by ConfigParam "
            "85 stdlib_hash");
    }

    auto state = std::make_shared<LinkedAvataRuntimeState>();
    state->options = options;

    // Round-19/21: copy each boot classpath entry into a chmod-0600
    // file inside a process-private chmod-0700 directory we mkdtemp
    // at startup.  This closes the residual TOCTOU window round-18
    // left between the per-VM-creation re-hash and the JVM's
    // `JNI_CreateJavaVM` mapping, and round-21 strengthens the
    // surrounding-directory guarantees from "/tmp sticky" to "owned
    // and accessible only by us".  The directory and copies are
    // unlinked on `LinkedAvataRuntimeState` destruction.
    TRY_RESULT(private_dir, create_private_classpath_dir());
    state->private_classpath_dir = private_dir;
    {
        std::string remaining = options.boot_classpath;
        std::string rewritten;
        std::size_t index = 0;
        while (!remaining.empty()) {
            auto colon = remaining.find(':');
            std::string entry = (colon == std::string::npos)
                                    ? remaining
                                    : remaining.substr(0, colon);
            remaining = (colon == std::string::npos)
                            ? std::string{}
                            : remaining.substr(colon + 1);
            if (entry.empty()) {
                continue;
            }
            TRY_RESULT(private_path,
                       materialize_private_classpath_entry(
                           private_dir, index++, entry));
            state->private_classpath_files.push_back(private_path);
            if (!rewritten.empty()) rewritten += ':';
            rewritten += private_path;
        }
        if (rewritten.empty()) {
            return td::Status::Error(
                "JVM linked Avata runtime: boot classpath had no "
                "non-empty entries");
        }
        state->options.boot_classpath = rewritten;
    }

    // Validate the boot runtime eagerly so init_jvm_workchain() still fails
    // closed on an unusable rt.jar.  Execution VMs are cached per class_hash
    // so contracts sharing identical bytecode share one cached VM.
    TRY_RESULT(probe_vm, create_linked_avata_vm(state->options));
    (void)probe_vm;

    // Hash the rt.jar so the engine can verify it matches ConfigParam
    // 85's `stdlib_hash` on every run_compute.  Round-18: the same
    // helper runs on every lazy VM creation in `get_vm_for_account`,
    // so a rt.jar swap between startup and first contract call is
    // also caught.  Round-19: we now hash the private copies (which
    // we control) rather than the original `options.boot_classpath`,
    // so an attacker who modifies the original after startup cannot
    // affect what the JVM loads.
    TRY_RESULT(rt_jar_hash,
               hash_boot_classpath(state->options.boot_classpath));
    state->rt_jar_hash = rt_jar_hash;

    std::shared_ptr<const JvmComputeRuntime> runtime =
        std::make_shared<JvmAvataRuntime>(
            make_linked_jvm_avata_execution_api(),
            linked_avata_resolve_call_target,
            state.get(),
            state,
            rt_jar_hash);
    return runtime;
}

}  // namespace jvm_workchain
