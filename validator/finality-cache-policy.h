/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <map>
#include <utility>

#include "common/errorcode.h"
#include "crypto/block/pq-signature-limits.h"
#include "crypto/pq/pq-consensus.h"

namespace tos::validator {

enum class PendingFinalityAdmission { Keep, Append, Replace };
enum class PendingFinalityRejection {
  None,
  Policy,
  SenderAlreadyPending,
  SenderBudget,
  SharedBudget,
  ValidatorReservedBudget
};

constexpr const char *pending_finality_rejection_name(PendingFinalityRejection rejection) {
  switch (rejection) {
    case PendingFinalityRejection::None:
      return "none";
    case PendingFinalityRejection::Policy:
      return "policy";
    case PendingFinalityRejection::SenderAlreadyPending:
      return "sender_already_pending";
    case PendingFinalityRejection::SenderBudget:
      return "sender_budget";
    case PendingFinalityRejection::SharedBudget:
      return "shared_budget";
    case PendingFinalityRejection::ValidatorReservedBudget:
      return "validator_reserved_budget";
  }
  return "unknown";
}
enum class PendingFinalityCapacity { Shared, ValidatorReserved };
enum class PendingFinalityFailureAction { Retry, DiscardPermanent, DiscardExpired };
struct PendingFinalityAttemptToken {
  std::uint64_t queue_generation{0};
  std::uint64_t attempt_generation{0};

  explicit operator bool() const {
    return queue_generation != 0 && attempt_generation != 0;
  }
  friend bool operator==(PendingFinalityAttemptToken lhs, PendingFinalityAttemptToken rhs) {
    return lhs.queue_generation == rhs.queue_generation && lhs.attempt_generation == rhs.attempt_generation;
  }
  friend bool operator!=(PendingFinalityAttemptToken lhs, PendingFinalityAttemptToken rhs) {
    return !(lhs == rhs);
  }
};

struct PendingFinalityFailureResult {
  PendingFinalityFailureAction action{PendingFinalityFailureAction::DiscardPermanent};
  double retry_at{0};
};

// The retention bound is wall-clock time because notready waits on network,
// database and chain-progress events rather than on a bounded computation. It
// starts at admission, not at each attempt: this deadline protects retained
// memory, and restarting it could let repeated attempts extend an attacker's
// occupancy indefinitely. It matches the manager's existing 60-second
// block-data wait on this path. An
// exponential retry delay avoids a tight actor loop while still probing state
// changes throughout that window. The expiry timer independently frees the
// sender slot even if no triggering event ever arrives.
inline constexpr double pending_finality_retention_seconds = 60.0;
inline constexpr double pending_finality_initial_retry_seconds = 0.5;
inline constexpr double pending_finality_max_retry_seconds = 8.0;
inline constexpr double pending_finality_no_expiry = std::numeric_limits<double>::max();

constexpr PendingFinalityFailureAction pending_finality_failure_action(int error_code, double now, double expires_at) {
  if (error_code != ErrorCode::notready && error_code != ErrorCode::timeout) {
    return PendingFinalityFailureAction::DiscardPermanent;
  }
  if (now >= expires_at) {
    return PendingFinalityFailureAction::DiscardExpired;
  }
  return PendingFinalityFailureAction::Retry;
}

constexpr bool pending_finality_exceeds_budget(std::size_t current, std::size_t removed, std::size_t added,
                                               std::size_t budget) {
  // `removed` is structurally the sum of entries selected from `current`: both
  // values are computed from the same store immediately before this call, and
  // no mutation occurs between them. Keep the check explicit nonetheless;
  // accounting corruption must reject rather than rely on unsigned wraparound.
  if (removed > current) {
    return true;
  }
  current -= removed;
  return current > budget || added > budget - current;
}

struct PendingFinalityAdmissionResult {
  PendingFinalityAdmission action{PendingFinalityAdmission::Keep};
  PendingFinalityRejection rejection{PendingFinalityRejection::None};

  bool admitted() const {
    return rejection == PendingFinalityRejection::None && action != PendingFinalityAdmission::Keep;
  }
};

// Remote entries are charged by their received boxed-TL payload bytes; local
// entries use their measured intrinsic signature bytes. Each sender may retain
// one unverified candidate per block, and that block-local candidate may occupy
// exactly the measured maximum 400-signer carrier. Across blocks, one sender
// may retain four such carriers: the three-consecutive-block recovery window
// exercised by the accepted-chain gate plus one in-flight successor. This is
// enough for normal pipelining while one public peer can occupy at most 1/4 of
// the shared pool and one committee authority at most 1/100 of its reserved
// pool. Four hundred committee shares are four times the aggregate reserved
// pool, so the pool remains the aggregate constraint without allowing one
// sender to monopolise it. A minimum charge for either source bounds both
// memory and object count. Block IDs are not range-gated here: masterchain and
// shardchain seqnos are not comparable, and valid finality can precede local
// block data, so no cheap generic trusted window exists at this boundary.
inline constexpr std::size_t pending_finality_sender_per_block_budget_bytes =
    block::pq::pq_block_finality_broadcast_max_bytes;
inline constexpr std::size_t pending_finality_sender_global_carrier_shares = 4;
static_assert(pending_finality_sender_global_carrier_shares <=
              std::numeric_limits<std::size_t>::max() / pending_finality_sender_per_block_budget_bytes);
inline constexpr std::size_t pending_finality_sender_global_budget_bytes =
    pending_finality_sender_global_carrier_shares * pending_finality_sender_per_block_budget_bytes;
inline constexpr std::size_t pending_finality_minimum_charge_bytes = 4096;
inline constexpr std::size_t pending_finality_public_candidate_slots = 16;
inline constexpr std::size_t pending_finality_max_validator_senders =
    tos::pq::PQConsensusLimits{}.max_certificate_signers;
static_assert(pending_finality_max_validator_senders <=
              std::numeric_limits<std::size_t>::max() / pending_finality_sender_per_block_budget_bytes);
// Public shard overlays admit non-validator peers, so peer cardinality cannot
// justify a committee-sized global budget. Non-validator senders share a fixed
// 16-candidate pool. A disjoint pool reserves one measured maximum-size carrier
// for each transport authority in the largest admitted validator set, ensuring
// public peers cannot crowd valid committee evidence out and preventing rounded
// MiB shares from admitting more than 400 committee senders. The reserved pool
// holds one complete maximum-size committee; it does not promise independent
// reservations across a validator-set rotation. These are hard upper bounds
// rather than preallocations; together they cap retained unverified evidence at
// 409452160 bytes (about 390.48 MiB).
inline constexpr std::size_t pending_finality_public_budget_bytes =
    pending_finality_public_candidate_slots * pending_finality_sender_per_block_budget_bytes;
inline constexpr std::size_t pending_finality_validator_reserved_budget_bytes =
    pending_finality_max_validator_senders * pending_finality_sender_per_block_budget_bytes;
static_assert(pending_finality_sender_global_budget_bytes < pending_finality_public_budget_bytes);
static_assert(pending_finality_max_validator_senders <=
              std::numeric_limits<std::size_t>::max() / pending_finality_sender_global_budget_bytes);
static_assert(pending_finality_max_validator_senders * pending_finality_sender_global_budget_bytes >
              pending_finality_validator_reserved_budget_bytes);
static_assert(pending_finality_public_budget_bytes <=
              std::numeric_limits<std::size_t>::max() - pending_finality_validator_reserved_budget_bytes);
inline constexpr std::size_t pending_finality_total_budget_bytes =
    pending_finality_public_budget_bytes + pending_finality_validator_reserved_budget_bytes;

// A verified cached value keeps the old strength policy: final replaces
// approve, while equal strength and downgrades keep the verified value.
// Unverified evidence has no block-level ownership: distinct authenticated
// senders append candidates which are verified in arrival order once the block
// supplies the trusted context.
constexpr PendingFinalityAdmission pending_finality_admission(bool has_cached, bool cached_is_verified,
                                                              bool cached_is_final, bool incoming_is_verified,
                                                              bool incoming_is_final) {
  if (!has_cached) {
    return PendingFinalityAdmission::Replace;
  }
  if (incoming_is_verified) {
    if (!cached_is_verified || (!cached_is_final && incoming_is_final)) {
      return PendingFinalityAdmission::Replace;
    }
    return PendingFinalityAdmission::Keep;
  }
  if (cached_is_verified) {
    return !cached_is_final && incoming_is_final ? PendingFinalityAdmission::Append : PendingFinalityAdmission::Keep;
  }
  return PendingFinalityAdmission::Append;
}

template <class Evidence, class Sender>
class PendingFinalityCandidates {
 public:
  explicit PendingFinalityCandidates(std::uint64_t queue_generation) : queue_generation_(queue_generation) {
  }

  struct Entry {
    Evidence evidence;
    Sender sender;
    std::size_t accounted_bytes;
    PendingFinalityCapacity capacity;
    bool verified;
    bool is_final;
    double expires_at{pending_finality_no_expiry};
    double retry_not_before{0};
    double retry_delay{pending_finality_initial_retry_seconds};
  };

  struct ProcessingAttempt {
    const Entry *entry{nullptr};
    PendingFinalityAttemptToken token{0};

    explicit operator bool() const {
      return entry != nullptr;
    }
    const Entry *operator->() const {
      return entry;
    }
    friend bool operator==(ProcessingAttempt attempt, std::nullptr_t) {
      return !attempt;
    }
    friend bool operator!=(ProcessingAttempt attempt, std::nullptr_t) {
      return static_cast<bool>(attempt);
    }
  };

  PendingFinalityAdmission admission(bool verified, bool is_final) const {
    bool cached_is_verified = false;
    bool cached_is_final = false;
    for (const auto &entry : entries_) {
      if (entry.verified) {
        cached_is_verified = true;
        cached_is_final = cached_is_final || entry.is_final;
      }
    }
    auto action =
        pending_finality_admission(!entries_.empty(), cached_is_verified, cached_is_final, verified, is_final);
    if (processing_ && action == PendingFinalityAdmission::Replace) {
      action = PendingFinalityAdmission::Append;
    }
    return action;
  }

  PendingFinalityAdmission admit(Evidence evidence, Sender sender, std::size_t accounted_bytes,
                                 PendingFinalityCapacity capacity, bool verified, bool is_final, double expires_at) {
    auto action = admission(verified, is_final);
    if (action == PendingFinalityAdmission::Keep) {
      return action;
    }
    if (action == PendingFinalityAdmission::Replace) {
      entries_.clear();
    }
    entries_.push_back(Entry{std::move(evidence), std::move(sender), accounted_bytes, capacity, verified, is_final,
                             expires_at, 0, pending_finality_initial_retry_seconds});
    return action;
  }

  bool has_unverified_from(const Sender &sender) const {
    for (const auto &entry : entries_) {
      if (!entry.verified && entry.sender == sender) {
        return true;
      }
    }
    return false;
  }

  std::size_t accounted_bytes() const {
    std::size_t result = 0;
    for (const auto &entry : entries_) {
      result += entry.accounted_bytes;
    }
    return result;
  }

  std::size_t accounted_bytes(const Sender &sender) const {
    std::size_t result = 0;
    for (const auto &entry : entries_) {
      if (entry.sender == sender) {
        result += entry.accounted_bytes;
      }
    }
    return result;
  }

  std::size_t accounted_bytes(PendingFinalityCapacity capacity) const {
    std::size_t result = 0;
    for (const auto &entry : entries_) {
      if (entry.capacity == capacity) {
        result += entry.accounted_bytes;
      }
    }
    return result;
  }

  ProcessingAttempt begin_processing(double now) {
    erase_expired(now);
    if (processing_ || entries_.empty()) {
      return {};
    }
    if (entries_.front().retry_not_before > now) {
      return {};
    }
    if (next_attempt_generation_ == std::numeric_limits<std::uint64_t>::max()) {
      return {};
    }
    processing_ = true;
    processing_token_ = {queue_generation_, next_attempt_generation_++};
    return {&entries_.front(), processing_token_};
  }

  PendingFinalityFailureResult resolve_front_failure(PendingFinalityAttemptToken token, int error_code, double now) {
    if (!is_processing(token)) {
      return {};
    }
    auto &entry = entries_.front();
    auto action = pending_finality_failure_action(error_code, now, entry.expires_at);
    if (action == PendingFinalityFailureAction::Retry) {
      entry.retry_not_before = std::min(now + entry.retry_delay, entry.expires_at);
      entry.retry_delay = std::min(entry.retry_delay * 2, pending_finality_max_retry_seconds);
      processing_ = false;
      processing_token_ = {};
      return {action, entry.retry_not_before};
    } else {
      entries_.pop_front();
      processing_ = false;
      processing_token_ = {};
      return {action, 0};
    }
  }

  std::size_t erase_expired(double now) {
    auto old_size = entries_.size();
    bool processing_front_expired = processing_ && !entries_.empty() && entries_.front().expires_at <= now;
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(), [now](const Entry &entry) { return entry.expires_at <= now; }),
        entries_.end());
    if (processing_front_expired) {
      processing_ = false;
      processing_token_ = {};
    }
    return old_size - entries_.size();
  }

  bool complete_front(PendingFinalityAttemptToken token, bool accepted) {
    if (!is_processing(token)) {
      return false;
    }
    bool accepted_final = accepted && entries_.front().is_final;
    entries_.pop_front();
    if (accepted_final) {
      entries_.clear();
    }
    processing_ = false;
    processing_token_ = {};
    return true;
  }

  bool mark_front_verified(PendingFinalityAttemptToken token) {
    if (!is_processing(token)) {
      return false;
    }
    entries_.front().verified = true;
    return true;
  }

  bool cancel_processing(PendingFinalityAttemptToken token) {
    if (!is_processing(token)) {
      return false;
    }
    processing_ = false;
    processing_token_ = {};
    return true;
  }

  bool empty() const {
    return entries_.empty();
  }

  std::size_t size() const {
    return entries_.size();
  }

  bool processing() const {
    return processing_;
  }

  bool is_processing(PendingFinalityAttemptToken token) const {
    return processing_ && !entries_.empty() && static_cast<bool>(token) && processing_token_ == token;
  }

 private:
  std::deque<Entry> entries_;
  bool processing_ = false;
  const std::uint64_t queue_generation_;
  PendingFinalityAttemptToken processing_token_{};
  std::uint64_t next_attempt_generation_{1};
};

template <class BlockKey, class Sender, class Evidence>
class PendingFinalityStore {
 public:
  using Candidates = PendingFinalityCandidates<Evidence, Sender>;

  PendingFinalityAdmissionResult admit(const BlockKey &block, Sender sender, Evidence evidence,
                                       std::size_t serialized_bytes, PendingFinalityCapacity capacity, bool verified,
                                       bool is_final, double expires_at) {
    auto it = entries_.find(block);
    auto action = it == entries_.end() ? PendingFinalityAdmission::Replace : it->second.admission(verified, is_final);
    if (action == PendingFinalityAdmission::Keep) {
      return {action, PendingFinalityRejection::Policy};
    }
    if (!verified && it != entries_.end() && it->second.has_unverified_from(sender)) {
      return {PendingFinalityAdmission::Keep, PendingFinalityRejection::SenderAlreadyPending};
    }

    const auto charge = std::max(serialized_bytes, pending_finality_minimum_charge_bytes);
    const auto removed_sender =
        action == PendingFinalityAdmission::Replace && it != entries_.end() ? it->second.accounted_bytes(sender) : 0;
    const auto removed_capacity =
        action == PendingFinalityAdmission::Replace && it != entries_.end() ? it->second.accounted_bytes(capacity) : 0;
    const auto block_sender_bytes = it == entries_.end() ? 0 : it->second.accounted_bytes(sender);
    if (pending_finality_exceeds_budget(block_sender_bytes, removed_sender, charge,
                                        pending_finality_sender_per_block_budget_bytes)) {
      return {PendingFinalityAdmission::Keep, PendingFinalityRejection::SenderBudget};
    }
    if (pending_finality_exceeds_budget(sender_bytes(sender), removed_sender, charge,
                                        pending_finality_sender_global_budget_bytes)) {
      return {PendingFinalityAdmission::Keep, PendingFinalityRejection::SenderBudget};
    }
    const auto capacity_budget = capacity == PendingFinalityCapacity::ValidatorReserved
                                     ? pending_finality_validator_reserved_budget_bytes
                                     : pending_finality_public_budget_bytes;
    if (pending_finality_exceeds_budget(capacity_bytes(capacity), removed_capacity, charge, capacity_budget)) {
      return {PendingFinalityAdmission::Keep, capacity == PendingFinalityCapacity::ValidatorReserved
                                                  ? PendingFinalityRejection::ValidatorReservedBudget
                                                  : PendingFinalityRejection::SharedBudget};
    }
    if (it == entries_.end()) {
      if (next_queue_generation_ == std::numeric_limits<std::uint64_t>::max()) {
        return {PendingFinalityAdmission::Keep, PendingFinalityRejection::Policy};
      }
      it = entries_.emplace(block, Candidates{next_queue_generation_++}).first;
    }
    return {it->second.admit(std::move(evidence), std::move(sender), charge, capacity, verified, is_final, expires_at),
            PendingFinalityRejection::None};
  }

  std::size_t erase_expired(double now) {
    std::size_t erased = 0;
    for (auto it = entries_.begin(); it != entries_.end();) {
      erased += it->second.erase_expired(now);
      if (it->second.empty()) {
        it = entries_.erase(it);
      } else {
        ++it;
      }
    }
    return erased;
  }

  Candidates *get_if_exists(const BlockKey &block) {
    auto it = entries_.find(block);
    return it == entries_.end() ? nullptr : &it->second;
  }

  const Candidates *get_if_exists(const BlockKey &block) const {
    auto it = entries_.find(block);
    return it == entries_.end() ? nullptr : &it->second;
  }

  void erase(const BlockKey &block) {
    entries_.erase(block);
  }

  std::size_t total_bytes() const {
    std::size_t result = 0;
    for (const auto &[unused, candidates] : entries_) {
      (void)unused;
      result += candidates.accounted_bytes();
    }
    return result;
  }

  std::size_t capacity_bytes(PendingFinalityCapacity capacity) const {
    std::size_t result = 0;
    for (const auto &[unused, candidates] : entries_) {
      (void)unused;
      result += candidates.accounted_bytes(capacity);
    }
    return result;
  }

  std::size_t sender_bytes(const Sender &sender) const {
    std::size_t result = 0;
    for (const auto &[unused, candidates] : entries_) {
      (void)unused;
      const auto block_bytes = candidates.accounted_bytes(sender);
      if (block_bytes > std::numeric_limits<std::size_t>::max() - result) {
        return std::numeric_limits<std::size_t>::max();
      }
      result += block_bytes;
    }
    return result;
  }

 private:
  std::map<BlockKey, Candidates> entries_;
  std::uint64_t next_queue_generation_{1};
};

}  // namespace tos::validator
