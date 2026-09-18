#include "manager-finalized-head.h"

namespace tos::auth {
namespace {
bool same_verification(const NativeFinalityVerification& left,
                       const NativeFinalityVerification& right) {
  return left.block == right.block && left.kind == right.kind &&
         left.catchain == right.catchain &&
         left.validator_set_hash == right.validator_set_hash &&
         left.signed_weight == right.signed_weight &&
         left.total_weight == right.total_weight;
}
}  // namespace

Result<std::unique_ptr<ManagerFinalizedHeadSource>>
ManagerFinalizedHeadSource::create(ChainContext chain,
                                   tos::BlockIdExt zero_block,
                                   td::Ref<vm::Cell> zero_state) {
  if (chain.network == 0 || chain.genesis_root == Hash{} ||
      chain.genesis_file == Hash{} || chain.chain_domain == Hash{})
    return Error{"manager-finality-chain"};
  if (zero_state.is_null())
    return Error{"manager-finality-genesis-state"};
  return std::unique_ptr<ManagerFinalizedHeadSource>(
      new ManagerFinalizedHeadSource(std::move(chain), std::move(zero_block),
                                     std::move(zero_state)));
}

Result<bool> ManagerFinalizedHeadSource::note_verified(
    NativeFinalityVerification value) {
  if (!value.block.is_masterchain_ext() || value.block.seqno() == 0)
    return Error{"manager-finality-verification-block"};

  auto [it, inserted] = verified_.emplace(value.block, value);
  if (!inserted && !same_verification(it->second, value))
    return Error{"manager-finality-verification-conflict"};
  return promote(value.block);
}

Result<bool> ManagerFinalizedHeadSource::note_applied(
    tos::BlockIdExt id, Bytes original_block,
    td::Ref<vm::Cell> resulting_state) {
  if (!id.is_masterchain_ext() || id.seqno() == 0)
    return Error{"manager-finality-applied-block"};
  if (resulting_state.is_null())
    return Error{"manager-finality-applied-state"};

  auto parsed = native_masterchain_block_anchor(original_block, chain_.network);
  if (!parsed.ok())
    return parsed.error();
  const auto expected = anchor_of(id, resulting_state);
  if (parsed.value() != expected)
    return Error{"manager-finality-applied-binding"};

  auto found = applied_.find(id);
  if (found != applied_.end()) {
    if (found->second.block != original_block ||
        found->second.state->get_hash() != resulting_state->get_hash())
      return Error{"manager-finality-applied-conflict"};
  } else {
    applied_.emplace(
        id, Applied{std::move(original_block), std::move(resulting_state)});
  }
  return promote(id);
}

Result<bool> ManagerFinalizedHeadSource::promote(const tos::BlockIdExt& id) {
  if (!verified_.contains(id) || !applied_.contains(id))
    return false;

  if (latest_complete_) {
    if (id.seqno() < latest_complete_->seqno())
      return false;
    if (id.seqno() == latest_complete_->seqno() &&
        id != *latest_complete_)
      return Error{"manager-finality-complete-conflict"};
  }

  const bool advanced =
      !latest_complete_ || id.seqno() > latest_complete_->seqno();
  latest_complete_ = id;
  prune();
  return advanced;
}

void ManagerFinalizedHeadSource::prune() {
  if (!latest_complete_)
    return;
  const auto keep_from = latest_complete_->seqno();
  for (auto it = verified_.begin(); it != verified_.end();) {
    if (it->first.seqno() < keep_from)
      it = verified_.erase(it);
    else
      ++it;
  }
  for (auto it = applied_.begin(); it != applied_.end();) {
    if (it->first.seqno() < keep_from)
      it = applied_.erase(it);
    else
      ++it;
  }
}

Result<NativeHeadObservation> ManagerFinalizedHeadSource::observe() const {
  NativeHeadObservation result;
  if (!latest_complete_) {
    result.configured_genesis = genesis_;
    return result;
  }
  auto it = applied_.find(*latest_complete_);
  if (it == applied_.end())
    return Error{"manager-finality-incomplete"};
  result.finality_candidate =
      NativeHeadCandidate{it->second.block, it->second.state};
  return result;
}

Result<NativeFinalityVerification>
ManagerFinalizedHeadSource::verify_signatures(
    const tos::BlockIdExt& block) const {
  auto it = verified_.find(block);
  if (it == verified_.end())
    return Error{"manager-finality-verification-missing"};
  return it->second;
}
}  // namespace tos::auth
