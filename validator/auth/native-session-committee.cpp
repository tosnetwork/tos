#include "native-session-committee.h"

namespace tos::auth {
namespace {
constexpr const char* need_block = "session-handoff-block-needed";
constexpr const char* need_state = "session-handoff-state-needed";
constexpr const char* need_identity = "session-handoff-identity-needed";

Anchor anchor_from_session_block(const SessionBirthBlock& block) {
  return {block.seqno, block.root, block.file, block.state};
}

bool same_target(tos::ShardIdFull left, tos::ShardIdFull right) {
  return left.workchain == right.workchain && left.shard == right.shard;
}
}  // namespace

Result<std::shared_ptr<const NativeSessionCommitteeContext>>
admit_native_session_committee(
    const std::shared_ptr<const NativeSessionCommitteeContext>& existing,
    const NativeSessionBirth& birth, const ChainContext& chain,
    StateReadBudget committee_budget) {
  const auto& selected = birth.birth().selected();
  const auto& epoch = selected.epoch;
  const auto anchor = anchor_from_session_block(selected.block);
  const tos::ShardIdFull target{epoch.workchain, epoch.shard};
  auto state = birth.state();

  return admit_session_committee<NativeCommittee>(
      existing, birth.birth(),
      [state = std::move(state), anchor, chain, target, epoch,
       committee_budget](const SessionBirthBlock& requested_birth)
          -> Result<NativeCommittee> {
        if (requested_birth !=
            SessionBirthBlock{anchor.seqno_, anchor.root_, anchor.file_,
                              anchor.state_})
          return Error{"session-committee-birth"};
        return NativeCommittee::derive(state, anchor, chain, target,
                                       epoch.catchain, committee_budget);
      });
}

NativeSessionCommitteeAdmission::NativeSessionCommitteeAdmission(
    td::Ref<vm::Cell> finalized_head_state,
    Anchor independently_finalized_head, ChainContext chain,
    NativeSessionIdInput identity,
    std::shared_ptr<const NativeSessionCommitteeContext> existing,
    NativeSessionHistoryBudget history_budget,
    StateReadBudget committee_budget)
    : head_state_(std::move(finalized_head_state)),
      head_(std::move(independently_finalized_head)),
      chain_(std::move(chain)),
      identity_(std::move(identity)),
      history_budget_(history_budget),
      committee_budget_(committee_budget),
      existing_(std::move(existing)) {
}

Result<std::optional<NativeSessionCommitteeRequest>>
NativeSessionCommitteeAdmission::advance() {
  if (result_)
    return std::optional<NativeSessionCommitteeRequest>{};
  if (pending_)
    return pending_;

  std::optional<NativeSessionCommitteeRequest> requested;

  NativeBlockReader block_reader =
      [this, &requested](const tos::BlockIdExt& id,
                         std::size_t maximum) -> Result<Bytes> {
    for (const auto& input : blocks_) {
      if (input.id == id) {
        if (input.bytes.empty() || input.bytes.size() > maximum)
          return Error{"history-block-bound"};
        return input.bytes;
      }
    }
    if (requested)
      return Error{"session-handoff-request-order"};
    requested = NativeSessionBlockRequest{id, maximum};
    return Error{need_block};
  };

  NativeSessionStateReader state_reader =
      [this, &requested](const Anchor& anchor)
          -> Result<td::Ref<vm::Cell>> {
    for (const auto& input : states_)
      if (input.anchor == anchor)
        return input.state;
    if (requested)
      return Error{"session-handoff-request-order"};
    requested = NativeSessionStateRequest{anchor};
    return Error{need_state};
  };

  NativeSessionIdentityInputReader identity_reader =
      [this, &requested](const Anchor& anchor, td::Ref<vm::Cell> state,
                         tos::ShardIdFull target)
          -> Result<NativeSessionIdInput> {
    for (const auto& input : identities_)
      if (input.anchor == anchor && same_target(input.target, target))
        return input.input;
    if (requested)
      return Error{"session-handoff-request-order"};
    requested =
        NativeSessionIdentityRequest{anchor, std::move(state), target};
    return Error{need_identity};
  };

  auto birth = NativeSessionBirth::resolve(
      head_state_, head_, chain_, identity_, std::move(block_reader),
      std::move(state_reader), std::move(identity_reader), history_budget_);
  if (!birth.ok()) {
    const auto& code = birth.error().code;
    if (code == need_block || code == need_state || code == need_identity) {
      if (!requested)
        return Error{"session-handoff-request-missing"};
      pending_ = std::move(requested);
      return pending_;
    }
    return birth.error();
  }

  auto admitted = admit_native_session_committee(
      existing_, birth.value(), chain_, committee_budget_);
  if (!admitted.ok())
    return admitted.error();
  result_ = admitted.value();
  return std::optional<NativeSessionCommitteeRequest>{};
}

Result<bool> NativeSessionCommitteeAdmission::provide_block(
    const tos::BlockIdExt& id, Bytes bytes) {
  if (result_)
    return Error{"session-handoff-complete"};
  if (!pending_ ||
      !std::holds_alternative<NativeSessionBlockRequest>(*pending_))
    return Error{"session-handoff-response-mismatch"};
  const auto request = std::get<NativeSessionBlockRequest>(*pending_);
  if (!(request.id == id))
    return Error{"session-handoff-response-mismatch"};
  if (bytes.empty() || bytes.size() > request.maximum_bytes)
    return Error{"session-handoff-block-bound"};
  blocks_.push_back(BlockInput{id, std::move(bytes)});
  pending_.reset();
  return true;
}

Result<bool> NativeSessionCommitteeAdmission::provide_state(
    const Anchor& anchor, td::Ref<vm::Cell> state) {
  if (result_)
    return Error{"session-handoff-complete"};
  if (!pending_ ||
      !std::holds_alternative<NativeSessionStateRequest>(*pending_))
    return Error{"session-handoff-response-mismatch"};
  const auto request = std::get<NativeSessionStateRequest>(*pending_);
  if (request.anchor != anchor)
    return Error{"session-handoff-response-mismatch"};
  states_.push_back(StateInput{anchor, std::move(state)});
  pending_.reset();
  return true;
}

Result<bool> NativeSessionCommitteeAdmission::provide_identity(
    const Anchor& anchor, tos::ShardIdFull target,
    NativeSessionIdInput input) {
  if (result_)
    return Error{"session-handoff-complete"};
  if (!pending_ ||
      !std::holds_alternative<NativeSessionIdentityRequest>(*pending_))
    return Error{"session-handoff-response-mismatch"};
  const auto request = std::get<NativeSessionIdentityRequest>(*pending_);
  if (request.anchor != anchor || !same_target(request.target, target))
    return Error{"session-handoff-response-mismatch"};
  identities_.push_back(IdentityInput{anchor, target, std::move(input)});
  pending_.reset();
  return true;
}

Result<std::shared_ptr<const NativeSessionCommitteeContext>>
NativeSessionCommitteeAdmission::context() const {
  if (!result_)
    return Error{"session-handoff-not-ready"};
  return result_;
}

}  // namespace tos::auth
