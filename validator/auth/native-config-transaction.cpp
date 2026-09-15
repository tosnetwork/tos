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
    , host_(std::move(accepted), context_, reader_, inclusion) {
}

Result<std::unique_ptr<NativeConfigTransaction>> NativeConfigTransaction::open(
    const NativeConfigTransactionInputs& inputs, td::Ref<vm::Cell> transaction_evidence,
    std::shared_ptr<const FinalizedAnchorSource> history, const EvidenceCharge& charge, StateReadBudget budget) {
  if (inputs.masterchain_state.is_null() || transaction_evidence.is_null() || !history)
    return Error{"native-config-transaction-input"};
  if (inputs.chain.genesis_root == Hash{} || inputs.chain.genesis_file == Hash{} ||
      inputs.chain.chain_domain == Hash{} || inputs.chain.network == 0)
    return Error{"native-config-transaction-chain"};
  // The registry may only be advanced past the state it is being read from.
  if (inputs.inclusion <= inputs.parent.seqno_)
    return Error{"native-config-transaction-coordinate"};

  // The committee that governs this update is derived from the parent state at
  // the parent's own anchor, not from the block being built: a block cannot be
  // governed by a committee it is itself introducing.
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

  // Evidence is whatever the transaction carried, validated before use and
  // never fetched from anywhere else.
  auto evidence = NativeEvidence::open(std::move(transaction_evidence), charge);
  if (!evidence.ok())
    return evidence.error();

  return std::unique_ptr<NativeConfigTransaction>(new NativeConfigTransaction(
      std::move(committee.value()), std::move(evidence.value()), std::move(history), std::move(accepted.value()),
      inputs.chain, inputs.inclusion));
}
}  // namespace tos::auth
