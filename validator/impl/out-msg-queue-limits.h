#pragma once
#include <limits>
#include <optional>

#include "td/utils/common.h"

namespace tos::validator {
// The outbound message queue of a shard is bounded by the hard and soft limits of
// ConfigParam 43. These rules are shared by the collator, which keeps the queue under
// the hard limit by deferring, and the validator, which checks the result.

// True when the queue, together with `pending` messages that will certainly be added to
// it, has reached the hard limit, so a further message must go to the dispatch queue.
inline bool out_msg_queue_reached_hard_limit(td::uint64 queue_size, td::uint64 pending, td::uint64 hard_limit) {
  if (pending > std::numeric_limits<td::uint64>::max() - queue_size) {
    return true;
  }
  return queue_size + pending >= hard_limit;
}

// True when a new queue size breaks the hard limit. A queue that already exceeded the
// limit in the previous state (it can after a merge) may not grow beyond that size.
inline bool out_msg_queue_exceeds_hard_limit(td::uint64 new_size, td::uint64 hard_limit,
                                             std::optional<td::uint64> old_size_in_state) {
  td::uint64 limit = hard_limit;
  if (old_size_in_state && *old_size_in_state > limit) {
    limit = *old_size_in_state;
  }
  return new_size > limit;
}

// True when the previous queue is so long that any outbound message may be deferred,
// including the first message of a transaction and messages of special accounts.
inline bool out_msg_queue_soft_limit_exceeded(std::optional<td::uint64> old_size_in_state, td::uint64 soft_limit) {
  return old_size_in_state && *old_size_in_state > soft_limit;
}

// True when the queue is too long for the shard to want a merge.
inline bool out_msg_queue_blocks_merge(td::uint64 queue_size, td::uint64 hard_limit) {
  return queue_size > hard_limit / 2;
}

enum class DeferralRefusal { None, FirstMessage, SpecialAccount };

// Why a validator refuses a deferred outbound message, if it does. Deferring is
// unrestricted once an earlier message of the account was deferred, when the account
// had a non-empty dispatch queue, or when the previous queue exceeded the soft limit.
inline DeferralRefusal deferral_refusal(bool first_message, bool masterchain_special_account, bool defer_all_messages,
                                        bool always_allow_defer) {
  if (defer_all_messages || always_allow_defer) {
    return DeferralRefusal::None;
  }
  if (first_message) {
    return DeferralRefusal::FirstMessage;
  }
  if (masterchain_special_account) {
    return DeferralRefusal::SpecialAccount;
  }
  return DeferralRefusal::None;
}
}  // namespace tos::validator
