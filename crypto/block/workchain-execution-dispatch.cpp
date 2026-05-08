/*
    Workchain execution registry and descriptor normalization.
*/
#include "block/workchain-execution-dispatch.h"

#include <sstream>

#include "td/utils/logging.h"

namespace block {

namespace {

constexpr std::int32_t kTvmVmVersion = -1;
constexpr std::int32_t kEvmVmVersion = 0x45564D;    // "EVM"
constexpr std::int32_t kUnoVmVersion = 0x554E4F31;  // "UNO1"
constexpr std::int32_t kJvmVmVersion = 0x4a564d31;  // "JVM1"

struct TvmEngineConfig final : public WorkchainEngineConfig {
};

class TvmDescriptorEngine final : public WorkchainEngine {
 public:
  WorkchainEngineKey engine_key() const override {
    return tvm_workchain_engine_key();
  }

  td::Result<std::shared_ptr<const WorkchainEngineConfig>> validate_and_resolve_config(
      const WorkchainExecutionDescriptor& descriptor,
      const block::Config& /*block_transition_config*/) const override {
    if (!workchain_engine_key_is_tvm(workchain_engine_key_from_descriptor(descriptor))) {
      return td::Status::Error("TVM engine received non-TVM descriptor");
    }
    if (descriptor.vm_mode != 0) {
      return td::Status::Error("TVM descriptor requires vm_mode=0");
    }
    std::shared_ptr<const WorkchainEngineConfig> result = std::make_shared<TvmEngineConfig>();
    return result;
  }

  AccountExecutionPolicy account_policy(const WorkchainExecutionDescriptor& /*descriptor*/,
                                        const WorkchainEngineConfig& /*engine_config*/) const override {
    return AccountExecutionPolicy{};
  }

  td::Result<WorkchainComputeOutput> run_compute(const WorkchainComputeInput& /*input*/,
                                                 const WorkchainComputeContext& /*context*/) const override {
    return td::Status::Error("TVM uses the native transaction.cpp compute path");
  }
};

}  // namespace

std::string workchain_engine_key_to_string(const WorkchainEngineKey& key) {
  std::ostringstream os;
  os << (key.format == WorkchainFormat::Basic ? "Basic" : "Extended") << ":" << key.selector;
  return os.str();
}

bool workchain_engine_key_is_tvm(const WorkchainEngineKey& key) {
  return key == tvm_workchain_engine_key();
}

bool workchain_engine_key_is_evm(const WorkchainEngineKey& key) {
  return key == evm_workchain_engine_key();
}

bool workchain_engine_key_is_uno(const WorkchainEngineKey& key) {
  return key == uno_workchain_engine_key();
}

bool workchain_engine_key_is_jvm(const WorkchainEngineKey& key) {
  return key == jvm_workchain_engine_key();
}

WorkchainEngineKey tvm_workchain_engine_key() {
  return {WorkchainFormat::Basic, kTvmVmVersion};
}

WorkchainEngineKey evm_workchain_engine_key() {
  return {WorkchainFormat::Basic, kEvmVmVersion};
}

WorkchainEngineKey uno_workchain_engine_key() {
  return {WorkchainFormat::Basic, kUnoVmVersion};
}

WorkchainEngineKey jvm_workchain_engine_key() {
  return {WorkchainFormat::Basic, kJvmVmVersion};
}

td::Result<WorkchainExecutionDescriptor> normalize_workchain_descriptor(const WorkchainInfo& info) {
  if (!info.is_valid()) {
    return td::Status::Error("cannot normalize invalid WorkchainInfo");
  }

  WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = info.workchain;
  descriptor.enabled_since = info.enabled_since;
  descriptor.active = info.active;
  descriptor.accept_msgs = info.accept_msgs;
  descriptor.format = info.basic ? WorkchainFormat::Basic : WorkchainFormat::Extended;
  descriptor.version = info.version;
  descriptor.vm_version = info.vm_version;
  descriptor.vm_mode = info.vm_mode;
  descriptor.workchain_type_id = info.basic ? 0 : info.workchain_type_id;
  descriptor.min_split = static_cast<std::uint8_t>(info.min_split);
  descriptor.max_split = static_cast<std::uint8_t>(info.max_split);
  descriptor.min_addr_len = static_cast<std::uint16_t>(info.min_addr_len);
  descriptor.max_addr_len = static_cast<std::uint16_t>(info.max_addr_len);
  descriptor.addr_len_step = static_cast<std::uint16_t>(info.addr_len_step);
  descriptor.zerostate_root_hash = info.zerostate_root_hash;
  descriptor.zerostate_file_hash = info.zerostate_file_hash;
  return descriptor;
}

WorkchainEngineKey workchain_engine_key_from_descriptor(const WorkchainExecutionDescriptor& descriptor) {
  if (descriptor.format == WorkchainFormat::Basic) {
    return WorkchainEngineKey{descriptor.format, static_cast<std::int64_t>(descriptor.vm_version)};
  }
  return WorkchainEngineKey{descriptor.format, static_cast<std::int64_t>(descriptor.workchain_type_id)};
}

td::Status validate_workchain_execution_descriptor_transitions(
    const WorkchainSet& old_workchains, const WorkchainSet& new_workchains) {
  for (const auto& [workchain_id, old_info] : old_workchains) {
    if (old_info.is_null()) {
      continue;
    }
    auto new_it = new_workchains.find(workchain_id);
    if (new_it == new_workchains.end() || new_it->second.is_null()) {
      return td::Status::Error(PSTRING() << "workchain " << workchain_id
                                         << " removes its execution descriptor"
                                         << " without an explicit migration rule");
    }
    const auto& new_info = new_it->second;
    TRY_RESULT(old_descriptor, normalize_workchain_descriptor(*old_info));
    TRY_RESULT(new_descriptor, normalize_workchain_descriptor(*new_info));
    auto old_key = workchain_engine_key_from_descriptor(old_descriptor);
    auto new_key = workchain_engine_key_from_descriptor(new_descriptor);
    if (!(old_key == new_key)) {
      return td::Status::Error(PSTRING() << "active workchain " << workchain_id
                                         << " changes execution key from "
                                         << workchain_engine_key_to_string(old_key)
                                         << " to "
                                         << workchain_engine_key_to_string(new_key)
                                         << " without an explicit migration rule");
    }
    if (old_descriptor.version != new_descriptor.version) {
      return td::Status::Error(PSTRING() << "active workchain " << workchain_id
                                         << " changes WorkchainDescr version from "
                                         << old_descriptor.version << " to "
                                         << new_descriptor.version
                                         << " without an explicit migration rule");
    }
    if (old_descriptor.format == WorkchainFormat::Basic &&
        old_descriptor.vm_mode != new_descriptor.vm_mode) {
      return td::Status::Error(PSTRING() << "active workchain " << workchain_id
                                         << " changes vm_mode from "
                                         << old_descriptor.vm_mode << " to "
                                         << new_descriptor.vm_mode
                                         << " without an explicit migration rule");
    }
    if (old_descriptor.min_addr_len != new_descriptor.min_addr_len ||
        old_descriptor.max_addr_len != new_descriptor.max_addr_len ||
        old_descriptor.addr_len_step != new_descriptor.addr_len_step) {
      return td::Status::Error(PSTRING() << "active workchain " << workchain_id
                                         << " changes address-length shape"
                                         << " without an explicit migration rule");
    }
    // Zerostate hash changes for active workchains are state forks unless a
    // future migration rule explicitly defines otherwise.
    if (old_descriptor.zerostate_root_hash != new_descriptor.zerostate_root_hash) {
      return td::Status::Error(PSTRING() << "active workchain " << workchain_id
                                         << " changes zerostate_root_hash"
                                         << " without an explicit migration rule");
    }
    if (old_descriptor.zerostate_file_hash != new_descriptor.zerostate_file_hash) {
      return td::Status::Error(PSTRING() << "active workchain " << workchain_id
                                         << " changes zerostate_file_hash"
                                         << " without an explicit migration rule");
    }
  }
  return td::Status::OK();
}

void WorkchainExecutionRegistry::register_engine(std::unique_ptr<WorkchainEngine> engine) {
  CHECK(engine != nullptr);
  auto key = engine->engine_key();
  auto inserted = engines_.emplace(key, std::move(engine));
  LOG_CHECK(inserted.second) << "duplicate workchain engine registration for "
                             << workchain_engine_key_to_string(key);
}

bool WorkchainExecutionRegistry::register_engine_if_absent(std::unique_ptr<WorkchainEngine> engine) {
  CHECK(engine != nullptr);
  auto key = engine->engine_key();
  if (has_engine(key)) {
    return false;
  }
  auto inserted = engines_.emplace(key, std::move(engine));
  LOG_CHECK(inserted.second) << "duplicate workchain engine registration for "
                             << workchain_engine_key_to_string(key);
  return true;
}

bool WorkchainExecutionRegistry::has_engine(const WorkchainEngineKey& key) const {
  return engines_.count(key) != 0;
}

td::Result<ResolvedWorkchainExecution> WorkchainExecutionRegistry::resolve(
    const WorkchainExecutionDescriptor& descriptor, const block::Config& block_transition_config) const {
  if (!descriptor.active) {
    return td::Status::Error(PSTRING() << "workchain " << descriptor.workchain_id << " is inactive");
  }
  auto key = workchain_engine_key_from_descriptor(descriptor);
  auto it = engines_.find(key);
  if (it == engines_.end()) {
    return td::Status::Error(PSTRING() << "missing workchain engine " << workchain_engine_key_to_string(key)
                                       << " for workchain " << descriptor.workchain_id);
  }
  TRY_RESULT(engine_config, it->second->validate_and_resolve_config(descriptor, block_transition_config));
  ResolvedWorkchainExecution resolved;
  resolved.executor = it->second.get();
  resolved.descriptor = descriptor;
  resolved.engine_config = std::move(engine_config);
  return resolved;
}

td::Result<std::optional<ResolvedWorkchainExecution>> WorkchainExecutionRegistry::resolve_workchain(
    const block::WorkchainSet& workchains, tos::WorkchainId workchain_id,
    const block::Config& block_transition_config) const {
  if (workchain_id == tos::masterchainId) {
    return std::optional<ResolvedWorkchainExecution>{};
  }
  auto it = workchains.find(workchain_id);
  if (it == workchains.end() || it->second.is_null() || !it->second->active) {
    return std::optional<ResolvedWorkchainExecution>{};
  }
  TRY_RESULT(descriptor, normalize_workchain_descriptor(*it->second));
  TRY_RESULT(resolved, resolve(descriptor, block_transition_config));
  return std::optional<ResolvedWorkchainExecution>{std::move(resolved)};
}

td::Result<std::optional<AccountExecutionPolicy>> WorkchainExecutionRegistry::resolve_account_policy(
    const block::WorkchainSet& workchains, tos::WorkchainId workchain_id,
    const block::Config& block_transition_config) const {
  TRY_RESULT(resolved, resolve_workchain(workchains, workchain_id, block_transition_config));
  if (!resolved.has_value()) {
    return std::optional<AccountExecutionPolicy>{};
  }
  auto policy = resolved->executor->account_policy(resolved->descriptor, *resolved->engine_config);
  TRY_STATUS(validate_account_execution_policy_supported(policy));
  return std::optional<AccountExecutionPolicy>{std::move(policy)};
}

td::Status WorkchainExecutionRegistry::validate_required_workchains(
    const block::WorkchainSet& workchains, const block::Config& block_transition_config,
    const LocalWorkchainRoleSet& local_roles) const {
  for (const auto& [workchain_id, info] : workchains) {
    if (info.is_null() || !info->active || !local_roles.requires_local_execution(workchain_id)) {
      continue;
    }
    TRY_RESULT(descriptor, normalize_workchain_descriptor(*info));
    TRY_RESULT(resolved, resolve(descriptor, block_transition_config));
    auto policy = resolved.executor->account_policy(resolved.descriptor, *resolved.engine_config);
    TRY_STATUS(validate_account_execution_policy_supported(policy));
  }
  return td::Status::OK();
}

td::Status validate_account_execution_policy_supported(const AccountExecutionPolicy& policy) {
  switch (policy.kind) {
    case AccountExecutionPolicyKind::AnyAccount:
      return td::Status::OK();
    case AccountExecutionPolicyKind::SingletonExecutor:
      if (!policy.singleton_address.has_value()) {
        return td::Status::Error("singleton executor policy is missing singleton_address");
      }
      return td::Status::OK();
    case AccountExecutionPolicyKind::ShardLocalExecutor:
      return td::Status::Error("shard-local executor policy is not implemented by the host");
    case AccountExecutionPolicyKind::EngineDefined:
      // Engine-defined policy: the engine owns address-space routing within
      // its workchain. The host accepts any account in the workchain and
      // optionally lets the engine emit `action_create_account` to
      // materialize new accounts at deterministic addresses.
      return td::Status::OK();
  }
  return td::Status::Error("unknown account execution policy kind");
}

bool resolved_workchain_execution_is_custom(const ResolvedWorkchainExecution& execution) {
  return !workchain_engine_key_is_tvm(workchain_engine_key_from_descriptor(execution.descriptor));
}

bool resolved_workchain_execution_is_evm(const ResolvedWorkchainExecution& execution) {
  return workchain_engine_key_is_evm(workchain_engine_key_from_descriptor(execution.descriptor));
}

td::uint32 workchain_execution_capability_flags(const WorkchainExecutionRegistry& registry) {
  td::uint32 flags = 0;
  if (registry.has_engine(evm_workchain_engine_key())) {
    flags |= kTosNodeCapabilityWorkchainEvm;
  }
  if (registry.has_engine(uno_workchain_engine_key())) {
    flags |= kTosNodeCapabilityWorkchainUno;
  }
  if (registry.has_engine(jvm_workchain_engine_key())) {
    flags |= kTosNodeCapabilityWorkchainJvm;
  }
  return flags;
}

WorkchainExecutionRegistry& default_workchain_execution_registry() {
  static WorkchainExecutionRegistry registry;
  static bool tvm_registered = [] {
    registry.register_engine_if_absent(std::make_unique<TvmDescriptorEngine>());
    return true;
  }();
  (void)tvm_registered;
  return registry;
}

}  // namespace block
