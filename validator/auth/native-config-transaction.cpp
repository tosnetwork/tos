#include <limits>

#include "block/mc-config.h"

#include "native-config-transaction.h"
#include "native-registry.h"
namespace tos::auth {

// What admission established before any execution attempt. It is immutable and
// may therefore back more than one fresh host without re-opening the evidence
// container. The mutable pieces -- reader state, registry work allowance and
// staged host state -- live in NativeConfigTransaction itself, not here.
struct NativeConfigTransaction::Material {
  NativeCommittee committee;
  NativeEvidence evidence;
  std::shared_ptr<const FinalizedAnchorSource> history;
  NativeRegistryBlock accepted;
  ChainContext chain;
  std::uint32_t inclusion;
  td::Ref<vm::Cell> proposal;

  Material(NativeCommittee committee, NativeEvidence evidence, std::shared_ptr<const FinalizedAnchorSource> history,
           NativeRegistryBlock accepted, ChainContext chain, std::uint32_t inclusion, td::Ref<vm::Cell> proposal)
      : committee(std::move(committee))
      , evidence(std::move(evidence))
      , history(std::move(history))
      , accepted(std::move(accepted))
      , chain(std::move(chain))
      , inclusion(inclusion)
      , proposal(std::move(proposal)) {
  }
};

NativeConfigTransaction::NativeConfigTransaction(std::shared_ptr<const Material> material)
    : material_(std::move(material))
    , context_{material_->chain, material_->committee.snapshot(), *material_->history}
    , reader_(material_->evidence.reader())
    , host_(material_->accepted, context_, reader_, material_->inclusion, material_->evidence.root(),
            material_->evidence.authorizations(), material_->proposal) {
}

namespace {
Result<NativeCommittee> transaction_committee(const NativeConfigTransactionInputs& inputs,
                                              const NativeConfigSequence& sequence, StateReadBudget budget) {
  if (inputs.masterchain_state.is_null())
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

  // The sequence must be the one for this block. A sequence opened against
  // another parent or another coordinate holds a prefix that was never on the
  // path this transaction extends, and taking it would be the same mistake as
  // deriving one from the parent -- only harder to see.
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

  // Preserve the original order for callers that have not admitted evidence:
  // state/sequence checks precede parsing the transaction container.
  auto committee = transaction_committee(inputs, sequence, budget);
  if (!committee.ok())
    return committee.error();
  auto accepted = sequence.accepted();

  auto evidence = NativeEvidence::open(std::move(transaction_evidence), charge);
  if (!evidence.ok())
    return evidence.error();

  auto material = std::make_shared<Material>(std::move(committee.value()), std::move(evidence.value()),
                                             std::move(history), std::move(accepted), inputs.chain,
                                             inputs.inclusion, std::move(admitted_proposal));
  return std::unique_ptr<NativeConfigTransaction>(new NativeConfigTransaction(std::move(material)));
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

  auto material = std::make_shared<Material>(std::move(committee.value()), std::move(evidence), std::move(history),
                                             std::move(accepted), inputs.chain, inputs.inclusion,
                                             std::move(admitted_proposal));
  return std::unique_ptr<NativeConfigTransaction>(new NativeConfigTransaction(std::move(material)));
}

std::unique_ptr<NativeConfigTransaction> NativeConfigTransaction::clone_for_execution() const {
  return std::unique_ptr<NativeConfigTransaction>(new NativeConfigTransaction(material_));
}

const FinalizedAnchorSource& NativeConfigTransaction::history() const {
  return *material_->history;
}

const Authorizations& NativeConfigTransaction::authorizations() const {
  return material_->evidence.authorizations();
}
}  // namespace tos::auth
