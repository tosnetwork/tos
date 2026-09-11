#pragma once
#include "crypto/test/workchain-m3-node-engine.h"

namespace m3_live {
// Isolated TEST producer mutation: run the real engine, preserve the receipt
// and total custody debit, but misdirect compute income to the coordinator.
// Both real collation and validator replay use this deliberately faulty engine.
class ComputeToOperator final : public block::RegisteredWorkchainAccountEngine {
  block::m3_test::M3NodeEngine engine_;
 public:
  ComputeToOperator(block::WorkchainEngineKey key, std::string path) : engine_(key,std::move(path)) {}
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
    CHECK(effects.fees && effects.fees->compute_fee->sgn() > 0);
    auto& fees = *effects.fees;
    block::CurrencyCollection combined;
    CHECK(block::CurrencyCollection::add(block::CurrencyCollection(fees.state_fee),
        block::CurrencyCollection(fees.compute_fee),combined));
    fees.state_fee = combined.tomis;
    fees.compute_fee = td::make_refint(0);
    return effects;
  }
};
} // namespace m3_live
