#include <limits>

#include "block/mc-config.h"

#include "native-config-transaction.h"
#include "native-registry.h"
namespace tos::auth {

NativeConfigTransaction::NativeConfigTransaction(NativeCommittee committee, NativeEvidence evidence,
                                                 std::shared_ptr<const FinalizedAnchorSource> history,
                                                 NativeRegistryBlock accepted, ChainContext chain,
                                                 std::uint32_t inclusion)
    : committee_(std::move(committee))
    , evidence_(std::move(evidence))
    , history_(std::move(history))
    , context_{std::move(chain), committee_.snapshot(), *history_}
    , reader_(evidence_.reader())
    , host_(std::move(accepted), context_, reader_, inclusion, evidence_.root(), evidence_.authorizations()) {
}

Result<std::unique_ptr<NativeConfigTransaction>> NativeConfigTransaction::open(
    const NativeConfigTransactionInputs& inputs, td::Ref<vm::Cell> transaction_evidence,
    std::shared_ptr<const FinalizedAnchorSource> history, const EvidenceCharge& charge, StateReadBudget budget) {
  if (inputs.masterchain_state.is_null() || transaction_evidence.is_null() || !history)
    return Error{"native-config-transaction-input"};
  if (inputs.chain.genesis_root == Hash{} || inputs.chain.genesis_file == Hash{} ||
      inputs.chain.chain_domain == Hash{} || inputs.chain.network == 0)
    return Error{"native-config-transaction-chain"};
  // A masterchain successor has exactly one coordinate. Requiring only
  // inclusion > parent would allow a gathered +2/+N coordinate to select due
  // transitions and freshness rules for a block that is not being built.
  if (inputs.parent.seqno_ == std::numeric_limits<std::uint32_t>::max() ||
      inputs.inclusion != inputs.parent.seqno_ + 1)
    return Error{"native-config-transaction-coordinate"};

  auto committee = NativeCommittee::derive(inputs.masterchain_state, inputs.parent, inputs.chain, inputs.shard,
                                           inputs.catchain, budget);
  if (!committee.ok())
    return committee.error();

  auto config = block::Config::extract_from_state(inputs.masterchain_state, 0);
  if (config.is_error())
    return Error{"native-config-transaction-config"};
  auto registry = NativeRegistry::bootstrap(config.ok()->get_config_param(46), inputs.parent.seqno_, budget);
  if (!registry.ok())
    return registry.error();
  auto accepted = NativeRegistryBlock::begin(registry.value(), inputs.inclusion, budget);
  if (!accepted.ok())
    return accepted.error();

  auto evidence = NativeEvidence::open(std::move(transaction_evidence), charge);
  if (!evidence.ok())
    return evidence.error();

  return std::unique_ptr<NativeConfigTransaction>(new NativeConfigTransaction(
      std::move(committee.value()), std::move(evidence.value()), std::move(history), std::move(accepted.value()),
      inputs.chain, inputs.inclusion));
}
}  // namespace tos::auth
