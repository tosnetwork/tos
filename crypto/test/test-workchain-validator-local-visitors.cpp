#include "prepared/workchain-validator-local-decisions.h"
#include <iostream>
#include "block/mc-config.h"
#include "block/workchain-execution-dispatch.h"
#include "block/workchain-resource-policy.h"
#include "td/utils/filesystem.h"
#include "td/utils/overloaded.h"
#include "vm/boc.h"
#include "validator/impl/workchain-account-decisions.h"

namespace {
void require(bool value, int identity) {
  if (!value) { std::cerr << "{\"failure_identity\":" << identity << "}\n"; std::exit(1); }
}
struct FixtureConfig final : block::WorkchainEngineConfig {};
// Configuration-only fixture engine. Execution is deliberately unavailable;
// successful resolution must not be confused with replay capability.
class FixtureEngine final : public block::RegisteredWorkchainAccountEngine {
 public:
  block::WorkchainEngineKey engine_key() const override { return block::uno_v2_workchain_engine_key(); }
  td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
      const block::WorkchainExecutionDescriptor&, const block::Config&,
      const td::Ref<vm::Cell>& root) const override {
    TRY_RESULT(parameters, block::decode_workchain_engine_parameters(root));
    if (parameters.parameters.is_null()) return td::Status::Error("missing fixture business configuration");
    return std::shared_ptr<const block::WorkchainEngineConfig>(std::make_shared<FixtureConfig>());
  }
  td::Result<std::uint64_t> proof_work(const td::Ref<vm::Cell>&, const block::InputPolicyIdentity&,
                                      const block::WorkchainEngineConfig&) const override {
    return td::Status::Error("fixture does not execute proof work");
  }
  td::Result<block::WorkchainAccountEffects> execute_accounts(
      const td::Ref<vm::Cell>&, block::WorkchainAccountReadView&,
      const block::WorkchainEngineConfig&) const override {
    return td::Status::Error("fixture does not execute account batches");
  }
};
}

int main(int argc, char** argv) {
  require(argc == 2 || argc == 3, 1300);
  const int selected = argc == 3 ? std::atoi(argv[2]) : -1;
  require(selected >= -1 && selected <= 3, 1307);
  auto bytes = td::read_file(td::CSlice(argv[1])); require(bytes.is_ok(), 1301);
  auto root = vm::std_boc_deserialize(bytes.ok().as_slice()); require(root.is_ok(), 1302);
  tos::BlockIdExt zero{tos::BlockId{tos::masterchainId, tos::shardIdAll, 0},
                        root.ok()->get_hash().bits(), td::Bits256::zero()};
  auto config = block::ConfigInfo::extract_config(root.ok(), zero,
      block::Config::needWorkchainInfo | block::Config::needCapabilities);
  require(config.is_ok(), 1303);
  block::WorkchainExecutionRegistry registry;
  require(registry.register_account_engine(std::make_unique<FixtureEngine>()).is_ok(), 1304);
  auto resolved_execution = registry.resolve_scoped_workchain(2, *config.ok());
  require(resolved_execution.is_ok() && resolved_execution.ok().has_value(), 1305);
  require(std::holds_alternative<block::ResolvedWorkchainAccountBinding>(*resolved_execution.ok()), 1306);
  // These are the actual production visitor decisions, not prepared copies.
  // The earlier registry gate makes both unreachable in a closed full actor;
  // invoking the decisions directly tests OFF behavior, not live reachability.
  // Conditional D59 refusals invalidated the old unconditional-text criterion:
  // default behavior, rather than spelling, is the property being preserved.
  // LIMIT: this does not establish correctness of test-enabled execution.
  const auto& binding = std::get<block::ResolvedWorkchainAccountBinding>(*resolved_execution.ok());
  auto& production_registry = block::default_workchain_execution_registry();
  require(!production_registry.test_only_account_instance_execution_enabled(binding), 1353);
  auto actual_custom = tos::validator::validator_account_binding_custom(binding);
  require(actual_custom.is_error(), 1350);
  require(actual_custom.error().code() == static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable), 1354);
  auto actual_ready = tos::validator::validator_account_binding_ready(binding);
  require(actual_ready.is_error(), 1351);
  require(actual_ready.code() == static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable), 1355);
  std::cout << "default OFF: actual validator custom and ready both LocalUnavailable\n";
  // Real authenticated-config resolution feeds prepared local decisions only.
  // No ValidateQuery actor or production gate is invoked or modified here.
  if (selected == -1 || selected == 0) {
  auto custom = prepared_validator::custom(std::move(resolved_execution));
  require(custom.is_ok(), 1310);
  require(!custom.ok(), 1311);
  }
  if (selected == -1 || selected == 1) {
  auto ready = prepared_validator::ready(registry.resolve_scoped_workchain(2, *config.ok()));
  require(ready.is_ok(), 1320);
  }
  block::WorkchainExecutionRegistry missing_registry;
  if (selected == -1 || selected == 2) {
  auto missing_custom = prepared_validator::custom(missing_registry.resolve_scoped_workchain(2, *config.ok()));
  require(missing_custom.is_error(), 1330);
  require(missing_custom.error().code() == static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable), 1331);
  }
  if (selected == -1 || selected == 3) {
  auto missing_ready = prepared_validator::ready(missing_registry.resolve_scoped_workchain(2, *config.ok()));
  require(missing_ready.is_error(), 1340);
  require(missing_ready.code() == static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable), 1341);
  }
  std::cout << "prepared, not connected: custom=false; ready=OK; missing engine=LocalUnavailable\n";
}
