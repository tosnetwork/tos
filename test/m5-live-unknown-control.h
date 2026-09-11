#pragma once
#include "crypto/test/workchain-m3-node-engine.h"
#include "block/workchain-unknown-origin.h"

namespace m3_live {
inline std::string unknown_observation_path;
inline void save_unknown_observation() {
  td::write_file(unknown_observation_path,
      std::to_string(block::workchain_unknown_origin_count()) + "\n").ensure();
}

// TEST ONLY: preserve the actual registered configuration and engine execution,
// then substitute an unclassified lower-layer failure before effects escape.
class UnknownAfterExecution final : public block::RegisteredWorkchainAccountEngine {
  block::m3_test::M3NodeEngine engine_;
 public:
  UnknownAfterExecution(block::WorkchainEngineKey key, std::string path) : engine_(key,std::move(path)) {}
  block::WorkchainEngineKey engine_key() const override { return engine_.engine_key(); }
  td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
      const block::WorkchainExecutionDescriptor& descriptor, const block::Config& config,
      const td::Ref<vm::Cell>& payload) const override {
    return engine_.validate_and_resolve_config(descriptor,config,payload);
  }
  td::Result<std::uint64_t> proof_work(const td::Ref<vm::Cell>& candidate,
      const block::InputPolicyIdentity& identity, const block::WorkchainEngineConfig& config) const override {
    return engine_.proof_work(candidate,identity,config);
  }
  td::Result<block::WorkchainAccountEffects> execute_accounts(const td::Ref<vm::Cell>& input,
      block::WorkchainAccountReadView& accounts, const block::WorkchainEngineConfig& config) const override {
    return engine_.execute_accounts(input,accounts,config);
  }
  td::Result<block::WorkchainAccountEffects> execute_metered_accounts(const td::Ref<vm::Cell>& input,
      block::WorkchainAccountReadView& accounts, const block::WorkchainEngineConfig& config,
      block::WorkchainProofVerifier& proofs) const override {
    TRY_RESULT(effects,engine_.execute_metered_accounts(input,accounts,config,proofs));
    return td::Status::Error("injected unclassified failure after real Failed execution");
  }
};
} // namespace m3_live
