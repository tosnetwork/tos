/*
    Workchain execution registry and descriptor normalization.

    This is the host-chain side of config-driven workchain dispatch.  It is
    intentionally small: ConfigParam 12 remains the consensus source of truth;
    this registry only answers whether the local binary can execute the
    declared workchain format.
*/
#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include "block/block.h"
#include "block/mc-config.h"
#include "td/utils/Status.h"
#include "tos/tos-shard.h"
#include "tos/tos-types.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellSlice.h"

namespace block {

enum class WorkchainFormat {
  Basic,
  Extended
};

struct WorkchainEngineKey {
  WorkchainFormat format{WorkchainFormat::Basic};
  // Basic: vm_version:int32 sign-extended to int64_t.
  // Extended: workchain_type_id:uint32.
  std::int64_t selector{0};

  bool operator<(const WorkchainEngineKey& other) const {
    if (format != other.format) {
      return static_cast<int>(format) < static_cast<int>(other.format);
    }
    return selector < other.selector;
  }
  bool operator==(const WorkchainEngineKey& other) const {
    return format == other.format && selector == other.selector;
  }
};

std::string workchain_engine_key_to_string(const WorkchainEngineKey& key);
bool workchain_engine_key_is_tvm(const WorkchainEngineKey& key);

struct WorkchainExecutionDescriptor {
  tos::WorkchainId workchain_id{tos::workchainInvalid};
  std::uint32_t enabled_since{0};
  bool active{false};
  bool accept_msgs{false};

  WorkchainFormat format{WorkchainFormat::Basic};
  std::uint32_t version{0};
  std::int32_t vm_version{0};
  std::uint64_t vm_mode{0};
  std::uint32_t workchain_type_id{0};

  std::uint8_t min_split{0};
  std::uint8_t max_split{0};
  std::uint16_t min_addr_len{0};
  std::uint16_t max_addr_len{0};
  std::uint16_t addr_len_step{0};
  td::Bits256 zerostate_root_hash;
  td::Bits256 zerostate_file_hash;

  td::Ref<vm::Cell> raw_descriptor_cell;
};

td::Result<WorkchainExecutionDescriptor> normalize_workchain_descriptor(const WorkchainInfo& info);
WorkchainEngineKey workchain_engine_key_from_descriptor(const WorkchainExecutionDescriptor& descriptor);

struct WorkchainEngineConfig {
  virtual ~WorkchainEngineConfig() = default;
};

struct WorkchainSideEffects {
  virtual ~WorkchainSideEffects() = default;
};

enum class AccountExecutionPolicyKind {
  AnyAccount,
  SingletonExecutor,
  ShardLocalExecutor,
  EngineDefined
};

struct AccountExecutionPolicy {
  AccountExecutionPolicyKind kind{AccountExecutionPolicyKind::AnyAccount};
  std::optional<tos::StdSmcAddress> singleton_address;

  bool accepts_external_inbound{true};
  bool accepts_internal_inbound{true};
  bool may_activate_uninitialized_account{true};

  td::Ref<vm::Cell> activation_code;
};

struct WorkchainComputeContext {
  tos::WorkchainId workchain_id{tos::workchainInvalid};
  tos::ShardIdFull shard;
  std::uint64_t block_seqno{0};
  tos::LogicalTime block_lt{0};
  std::uint64_t now{0};

  std::uint32_t global_version{0};
  std::array<std::uint8_t, 32> rand_seed{};
  std::array<std::uint8_t, 32> parent_block_hash{};

  WorkchainExecutionDescriptor descriptor;
  std::shared_ptr<const WorkchainEngineConfig> engine_config;
  std::shared_ptr<const block::Config> block_transition_config;
};

struct WorkchainComputeInput {
  tos::StdSmcAddress account_addr;
  td::Ref<vm::Cell> current_code;
  td::Ref<vm::Cell> current_data;
  block::CurrencyCollection account_balance;
  td::Ref<vm::Cell> inbound_message;
  td::Ref<vm::CellSlice> inbound_body;
  tos::LogicalTime msg_lt{0};
  std::uint64_t gas_limit{0};
};

struct WorkchainComputeOutput {
  int skip_reason{0};
  bool completed{false};
  bool accepted{false};
  bool committed{false};
  bool engine_success{false};
  bool msg_state_used{false};
  bool account_activated{false};
  bool out_of_gas{false};
  int mode{0};
  std::int32_t exit_code{0};
  std::int32_t exit_arg{0};
  int vm_steps{0};
  tos::Bits256 vm_init_state_hash;
  tos::Bits256 vm_final_state_hash;

  std::uint64_t gas_used{0};
  td::RefInt256 gas_fees;

  td::Ref<vm::Cell> new_data;
  td::Ref<vm::Cell> new_code;
  td::Ref<vm::Cell> action_list;

  std::string vm_log;
  std::unique_ptr<WorkchainSideEffects> side_effects;
};

class WorkchainEngine {
 public:
  virtual ~WorkchainEngine() = default;

  virtual WorkchainEngineKey engine_key() const = 0;

  virtual td::Result<std::shared_ptr<const WorkchainEngineConfig>> validate_and_resolve_config(
      const WorkchainExecutionDescriptor& descriptor, const block::Config& block_transition_config) const = 0;

  virtual AccountExecutionPolicy account_policy(const WorkchainExecutionDescriptor& descriptor,
                                                const WorkchainEngineConfig& engine_config) const = 0;

  virtual td::Result<WorkchainComputeOutput> run_compute(const WorkchainComputeInput& input,
                                                         const WorkchainComputeContext& context) const = 0;
};

struct ResolvedWorkchainExecution {
  const WorkchainEngine* executor{nullptr};
  WorkchainExecutionDescriptor descriptor;
  std::shared_ptr<const WorkchainEngineConfig> engine_config;
};

struct LocalWorkchainRoleSet {
  bool require_all_active{false};
  std::set<tos::WorkchainId> required_workchains;

  bool requires_local_execution(tos::WorkchainId workchain_id) const {
    return require_all_active || required_workchains.count(workchain_id) != 0;
  }
};

class WorkchainExecutionRegistry {
 public:
  void register_engine(std::unique_ptr<WorkchainEngine> engine);
  bool register_engine_if_absent(std::unique_ptr<WorkchainEngine> engine);
  bool has_engine(const WorkchainEngineKey& key) const;

  td::Result<ResolvedWorkchainExecution> resolve(const WorkchainExecutionDescriptor& descriptor,
                                                 const block::Config& block_transition_config) const;

  td::Result<std::optional<ResolvedWorkchainExecution>> resolve_workchain(
      const block::WorkchainSet& workchains, tos::WorkchainId workchain_id,
      const block::Config& block_transition_config) const;

  td::Result<std::optional<AccountExecutionPolicy>> resolve_account_policy(
      const block::WorkchainSet& workchains, tos::WorkchainId workchain_id,
      const block::Config& block_transition_config) const;

  td::Status validate_required_workchains(const block::WorkchainSet& workchains,
                                          const block::Config& block_transition_config,
                                          const LocalWorkchainRoleSet& local_roles) const;

 private:
  std::map<WorkchainEngineKey, std::unique_ptr<WorkchainEngine>> engines_;
};

// Transitional Phase 1 owner used by startup registration and legacy
// transaction dispatch. Long-term block execution should inject a registry
// through the block-transition context rather than depending on this process
// singleton.
WorkchainExecutionRegistry& default_workchain_execution_registry();

}  // namespace block
