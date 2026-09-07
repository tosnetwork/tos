#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>
#include <vector>

#include "td/utils/Status.h"
#include "common/bitstring.h"

namespace block {

namespace participant_lt_detail {
inline td::Result<std::uint64_t> checked_add(std::uint64_t a, std::uint64_t b) {
  // a is a uint64 value, so max - a cannot underflow.
  if (b > std::numeric_limits<std::uint64_t>::max() - a) {
    return td::Status::Error("participant logical time overflow");
  }
  return a + b;
}
}  // namespace participant_lt_detail

// Inputs must come from authenticated old accounts and the admitted message
// schedule. This utility neither authenticates them nor commits account state.
struct WorkchainParticipantTiming {
  td::Bits256 account;
  std::uint64_t previous_end_lt;
  std::uint64_t outbound_count;
};

struct WorkchainParticipantLt {
  td::Bits256 account;
  std::uint64_t start_lt;
  std::uint64_t end_lt;
  std::uint64_t outbound_count;

  td::Result<std::uint64_t> message_lt(std::uint64_t index) const;
};

struct WorkchainParticipantLtPlan {
  std::uint64_t start_lt;
  std::uint64_t end_lt;
  std::vector<WorkchainParticipantLt> participants;
};

// The host/inbox lower bound includes created and emitted message LTs. Account
// keys must be strictly increasing; one transaction is allocated per account.
// Limits are resolved protocol values, not local execution preferences.
inline td::Result<WorkchainParticipantLtPlan> plan_workchain_participant_lts(
    std::uint64_t authenticated_after_lt, const std::vector<WorkchainParticipantTiming>& inputs,
    std::uint64_t max_participants, std::uint64_t max_outbound_messages) {
  if (inputs.empty() || inputs.size() > max_participants) {
    return td::Status::Error("participant count outside admitted bounds");
  }
  auto after = authenticated_after_lt;
  std::uint64_t total_messages = 0;
  const WorkchainParticipantTiming* previous = nullptr;
  for (const auto& input : inputs) {
    if (previous && !(previous->account < input.account)) {
      return td::Status::Error("participant accounts are not strictly ordered");
    }
    previous = &input;
    after = std::max(after, input.previous_end_lt);
    TRY_RESULT(total, participant_lt_detail::checked_add(total_messages, input.outbound_count));
    if (total > max_outbound_messages) {
      return td::Status::Error("outbound count exceeds admitted bound");
    }
    total_messages = total;
  }
  TRY_RESULT(start, participant_lt_detail::checked_add(after, 1));
  TRY_RESULT(first_message, participant_lt_detail::checked_add(start, 1));
  WorkchainParticipantLtPlan plan{start, first_message, {}};
  plan.participants.reserve(inputs.size());
  for (const auto& input : inputs) {
    TRY_RESULT(end, participant_lt_detail::checked_add(first_message, input.outbound_count));
    plan.participants.push_back({input.account, start, end, input.outbound_count});
    plan.end_lt = std::max(plan.end_lt, end);
  }
  return plan;
}

inline td::Result<std::uint64_t> WorkchainParticipantLt::message_lt(std::uint64_t index) const {
  if (index >= outbound_count) {
    return td::Status::Error("participant message index outside schedule");
  }
  TRY_RESULT(first, participant_lt_detail::checked_add(start_lt, 1));
  TRY_RESULT(value, participant_lt_detail::checked_add(first, index));
  if (value >= end_lt) {
    return td::Status::Error("participant message outside transaction LT interval");
  }
  return value;
}

}  // namespace block
