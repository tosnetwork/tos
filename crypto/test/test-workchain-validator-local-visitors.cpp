#include <iomanip>
#include <iostream>
#include "block/mc-config.h"
#include "block/workchain-execution-dispatch.h"
#include "block/workchain-resource-policy.h"
#include "td/utils/filesystem.h"
#include "td/utils/overloaded.h"
#include "vm/boc.h"

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
  require(argc == 2, 1300);
  auto bytes = td::read_file(argv[1]); require(bytes.is_ok(), 1301);
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
  // The complete visitor statements are extracted verbatim from the production
  // validator. This is a local-expression test, not a ValidateQuery call-site test.
#include "validator-custom-visitor.inc"
  require(custom.is_ok(), 1310);
  require(!custom.ok(), 1311);
  auto execution_res = registry.resolve_scoped_workchain(2, *config.ok());
  require(execution_res.is_ok() && execution_res.ok().has_value(), 1312);
#include "validator-ready-visitor.inc"
  require(ready.is_ok(), 1320);
  std::cout << "{\"scope\":\"local-visitor-only\",\"custom_result\":false,\"ready_result\":true}\n";
}
