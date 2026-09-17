#include <limits>

#include "block/mc-config.h"

#include "native-config-transaction.h"
#include "native-registry.h"
namespace tos::auth {

NativeConfigTransaction::NativeConfigTransaction(NativeCommittee committee, NativeEvidence evidence,
                                                 std::shared_ptr<const FinalizedAnchorSource> history,
                                                 NativeRegistryBlock accepted, ChainContext chain,
                                                 std::uint32_t inclusion, td::Ref<vm::Cell> proposal)
    : committee_(std::move(committee))
    , evidence_(std::move(evidence))
    , history_(std::move(history))
    , context_{std::move(chain), committee_.snapshot(), *history_}
    , reader_(evidence_.reader())
    , host_(std::move(accepted), context_, reader_, inclusion, evidence_.root(), evidence_.authorizations(),
              std::move(proposal)) {
}

namespace {
Result<NativeCommittee> transaction_committee(const NativeConfigTransactionInputs& inputs,
                                              const NativeConfigSequence& sequence, StateReadBudget budget) {
  if (inputs.masterchain_state.is_null())
    return Error{"native-config-transaction-input"};
  if (inputs.chain.genesis_root == Hash{} || inputs.chain.genesis_file == Hash{} ||
      inputs.chain.chain_domain == Hash{} || inputs.chain.network == 0)
    return Error{"native-config-transaction-chain"};
  if (inputs.parent.seqno_ == std::numeric_limits<std::uint32_t>::max() ||
      inputs.inclusion != inputs.parent.seqno_ + 1)
    return Error{"native-config-transaction-coordinate"};

  auto committee = NativeCommittee::derive(inputs.masterchain_state, inputs.parent, inputs.chain, inputs.shard,
                                           inputs.catchain, budget);
  if (!committee.ok())
    return committee.error();

  if (sequence.inclusion() != inputs.inclusion || sequence.parent().seqno_ != inputs.parent.seqno_ ||
      sequence.chain().chain_domain != inputs.chain.chain_domain)
    return Error{"native-config-transaction-sequence"};
  return committee;
}
}  // namespace

Result<std::unique_ptr<NativeConfigTransaction>> NativeConfigTransaction::open(
    const NativeConfigTransactionInputs& inputs, const NativeConfigSequence& sequence,
    td::Ref<vm::Cell> transaction_evidence, td::Ref<vm::Cell> admitted_proposal,
    std::shared_ptr<const FinalizedAnchorSource> history, const EvidenceCharge& charge, StateReadBudget budget) {
  if (transaction_evidence.is_null() || !history)
    return Error{"native-config-transaction-input"};

  auto evidence = NativeEvidence::open(std::move(transaction_evidence), charge);
  if (!evidence.ok())
    return evidence.error();
  return open_admitted(inputs, sequence, std::move(evidence.value()), std::move(admitted_proposal),
                       std::move(history), budget);
}

Result<std::unique_ptr<NativeConfigTransaction>> NativeConfigTransaction::open_admitted(
    const NativeConfigTransactionInputs& inputs, const NativeConfigSequence& sequence, NativeEvidence evidence,
    td::Ref<vm::Cell> admitted_proposal, std::shared_ptr<const FinalizedAnchorSource> history, StateReadBudget budget) {
  if (!history || evidence.root().is_null())
    return Error{"native-config-transaction-input"};

  auto committee = transaction_committee(inputs, sequence, budget);
  if (!committee.ok())
    return committee.error();
  auto accepted = sequence.accepted();

  return std::unique_ptr<NativeConfigTransaction>(new NativeConfigTransaction(
      std::move(committee.value()), std::move(evidence), std::move(history), std::move(accepted), inputs.chain,
      inputs.inclusion, std::move(admitted_proposal)));
}
}  // namespace tos::auth
