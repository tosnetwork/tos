/*
    Workchain execution registry and descriptor normalization.
*/
#include "block/workchain-execution-dispatch.h"

#include <sstream>

#include "td/utils/logging.h"

namespace block {

std::string workchain_engine_key_to_string(const WorkchainEngineKey& key) {
  std::ostringstream os;
  os << (key.format == WorkchainFormat::Basic ? "Basic" : "Extended") << ":" << key.selector;
  return os.str();
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

td::Status WorkchainExecutionRegistry::validate_required_workchains(
    const block::WorkchainSet& workchains, const block::Config& block_transition_config,
    const LocalWorkchainRoleSet& local_roles) const {
  for (const auto& [workchain_id, info] : workchains) {
    if (info.is_null() || !info->active || !local_roles.requires_local_execution(workchain_id)) {
      continue;
    }
    TRY_RESULT(descriptor, normalize_workchain_descriptor(*info));
    TRY_RESULT(resolved, resolve(descriptor, block_transition_config));
    (void)resolved;
  }
  return td::Status::OK();
}

WorkchainExecutionRegistry& default_workchain_execution_registry() {
  static WorkchainExecutionRegistry registry;
  return registry;
}

}  // namespace block
