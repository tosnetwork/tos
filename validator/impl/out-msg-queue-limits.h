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

// Conservative retry admission: a foreign transit needs a new outbound entry.
// Stop when all slots are occupied or reserved for dispatched messages.
// Already processed messages, final deliveries and requeues of our own messages
// do not grow the queue and must remain available even when the queue is full.
inline bool out_msg_queue_postpone_transit(bool already_processed, bool from_our_queue, bool to_us,
                                           td::uint64 queue_size, td::uint64 pending, td::uint64 hard_limit) {
  return !already_processed && !from_our_queue && !to_us &&
         out_msg_queue_reached_hard_limit(queue_size, pending, hard_limit);
}

// A queue already above the configured limit (for example after a merge) may
// retain its recorded size. Both admission on retry and final validation use it.
inline td::uint64 out_msg_queue_effective_hard_limit(td::uint64 hard_limit,
                                                     std::optional<td::uint64> old_size_in_state) {
  return old_size_in_state && *old_size_in_state > hard_limit ? *old_size_in_state : hard_limit;
}

// The limit applies to the final state, not intermediate changes within a block.
inline bool out_msg_queue_exceeds_hard_limit(td::uint64 new_size, td::uint64 hard_limit,
                                             std::optional<td::uint64> old_size_in_state) {
  return new_size > out_msg_queue_effective_hard_limit(hard_limit, old_size_in_state);
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
