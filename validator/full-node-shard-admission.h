/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <algorithm>
#include <atomic>
#include <iterator>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include "adnl/adnl-node-id.hpp"
#include "adnl/adnl-query-answer.h"
#include "auto/tl/tos_api.h"
#include "auto/tl/tos_api.hpp"
#include "common/errorcode.h"
#include "metrics/node-state-snapshot.h"
#include "td/utils/Status.h"
#include "td/utils/Time.h"
#include "td/utils/overloaded.h"
#include "tl-utils/common-utils.hpp"
#include "tos/tos-types.h"

#include "rate-limiter.h"

namespace tos::validator::fullnode {

using FullNodeRateLimiter = SourceAwareRateLimiter<td::int32, ShardIdFull, adnl::AdnlNodeIdShort>;

// Heavy requests are priced in units of 2 MiB of requested data.
constexpr td::uint64 k_heavy_request_cost_unit = td::uint64{1} << 21;
// Largest zero state a node serves; the full node uses the same bound.
constexpr td::uint64 k_max_zerostate_bytes = td::uint64{16} << 20;
// Small requests are cheap fixed-size lookups that still read the database,
// so they get their own generous bound instead of being free.
constexpr size_t k_small_request_limit = 200;

constexpr size_t heavy_request_cost(td::uint64 requested_max_size) {
  size_t cost = static_cast<size_t>((requested_max_size / k_heavy_request_cost_unit) +
                                    (requested_max_size % k_heavy_request_cost_unit != 0 ? 1 : 0));
  return cost == 0 ? 1 : cost;
}

// The most expensive request an honest node must be able to send: a whole
// zero state. Archive and persistent-state slices are requested in 2 MiB
// parts and cost one unit.
constexpr size_t k_max_mandatory_request_cost = heavy_request_cost(k_max_zerostate_bytes);

// Cost of a parsed request, from the size it claims before anything is looked
// up, so a probe for a missing resource pays what it asked for.
inline size_t full_node_request_cost(tos_api::Function &function) {
  size_t cost = 1;
  tos_api::downcast_call(
      function,
      td::overloaded(
          [&](const tos_api::tosNode_getArchiveSlice &query) {
            cost = heavy_request_cost(query.max_size_ > 0 ? static_cast<td::uint64>(query.max_size_) : 0);
          },
          [&](const tos_api::tosNode_downloadPersistentStateSliceV2 &query) {
            cost = heavy_request_cost(query.max_size_ > 0 ? static_cast<td::uint64>(query.max_size_) : 0);
          },
          [&](const tos_api::tosNode_downloadZeroState &) { cost = heavy_request_cost(k_max_zerostate_bytes); },
          [&](const auto &) {}));
  return cost;
}

// Default admission limits of the full node: the window and the global,
// heavy and medium allowances per window.
constexpr double k_default_ratelimit_window_size = 1.0;
constexpr size_t k_default_ratelimit_global = 96;
constexpr size_t k_default_ratelimit_heavy = 64;
constexpr size_t k_default_ratelimit_medium = 72;

struct FullNodeRateLimits {
  RateLimit global;
  RateLimit heavy;
  RateLimit medium;
  RateLimit small;
};

inline FullNodeRateLimits full_node_rate_limits(double window_size, size_t global, size_t heavy, size_t medium) {
  return FullNodeRateLimits{RateLimit{window_size, global}, RateLimit{window_size, heavy},
                            RateLimit{window_size, medium}, RateLimit{window_size, k_small_request_limit}};
}

// Refuse limits under which an enabled window could never admit one
// mandatory request from a source: the global and heavy windows must fit a
// zero-state download, the others a single unit.
inline td::Status check_full_node_rate_limits(const FullNodeRateLimits &limits) {
  TRY_STATUS(FullNodeRateLimiter::check_window_admits("global", limits.global, k_max_mandatory_request_cost));
  TRY_STATUS(FullNodeRateLimiter::check_window_admits("heavy", limits.heavy, k_max_mandatory_request_cost));
  TRY_STATUS(FullNodeRateLimiter::check_window_admits("medium", limits.medium, 1));
  TRY_STATUS(FullNodeRateLimiter::check_window_admits("small", limits.small, 1));
  return td::Status::OK();
}

inline std::shared_ptr<FullNodeRateLimiter> make_full_node_rate_limiter(const FullNodeRateLimits &limits) {
  return std::make_shared<FullNodeRateLimiter>(
      limits.global, limits.heavy,
      std::set{tos_api::tosNode_getArchiveSlice::ID, tos_api::tosNode_downloadPersistentStateSliceV2::ID,
               tos_api::tosNode_downloadZeroState::ID},
      limits.medium,
      std::set{tos_api::tosNode_downloadBlock::ID, tos_api::tosNode_downloadBlockFull::ID,
               tos_api::tosNode_downloadNextBlockFull::ID, tos_api::tosNode_downloadNextBlocksFull::ID,
               tos_api::tosNode_downloadBlockProof::ID, tos_api::tosNode_downloadBlockProofLink::ID,
               tos_api::tosNode_downloadKeyBlockProof::ID, tos_api::tosNode_downloadKeyBlockProofLink::ID,
               tos_api::tosNode_getOutMsgQueueProof::ID, tos_api::tosNode_prepareKeyBlockProof::ID},
      limits.small,
      std::set{tos_api::tosNode_getNextBlockDescription::ID, tos_api::tosNode_getNextBlocksDescription::ID,
               tos_api::tosNode_prepareBlockProof::ID, tos_api::tosNode_prepareBlock::ID,
               tos_api::tosNode_prepareZeroState::ID, tos_api::tosNode_getNextKeyBlockIds::ID,
               tos_api::tosNode_getArchiveInfo::ID, tos_api::tosNode_getShardArchiveInfo::ID,
               tos_api::tosNode_preparePersistentState::ID, tos_api::tosNode_getPersistentStateSizeV2::ID});
}

// The reply a query refused for capacity may carry: for each query type
// listed here, the reply its own handler gives when it has nothing to offer,
// which every requester of that type takes as "not ready, ask again". Only
// types with a served handler and such an empty reply are listed. Raw block
// and proof downloads have no empty reply and prepareBlocks has no handler,
// so they and every other type keep the silent refusal. The reply is fixed
// and built here without any lookup.
inline std::optional<td::BufferSlice> capacity_refusal_answer(td::int32 function_id) {
  switch (function_id) {
    case tos_api::tosNode_downloadBlockFull::ID:
    case tos_api::tosNode_downloadNextBlockFull::ID:
      return create_serialize_tl_object<tos_api::tosNode_dataFullEmpty>();
    case tos_api::tosNode_downloadNextBlocksFull::ID:
      return create_serialize_tl_object<tos_api::tosNode_nextBlocksFull>(
          std::vector<tos_api::object_ptr<tos_api::tosNode_DataFull>>{});
    case tos_api::tosNode_prepareBlock::ID:
      return create_serialize_tl_object<tos_api::tosNode_notFound>();
    case tos_api::tosNode_prepareBlockProof::ID:
    case tos_api::tosNode_prepareKeyBlockProof::ID:
      return create_serialize_tl_object<tos_api::tosNode_preparedProofEmpty>();
    case tos_api::tosNode_preparePersistentState::ID:
    case tos_api::tosNode_prepareZeroState::ID:
      return create_serialize_tl_object<tos_api::tosNode_notFoundState>();
    default:
      return std::nullopt;
  }
}

// `rate` tokens a second, held up to `burst`; it starts full. Time that runs
// backwards adds nothing.
class TokenBucket {
 public:
  TokenBucket(double rate, double burst, td::Timestamp now) : rate_(rate), burst_(burst), tokens_(burst), at_(now) {
  }

  void refill(td::Timestamp now) {
    double elapsed = now.at() - at_.at();
    if (elapsed > 0.0) {
      tokens_ = std::min(burst_, tokens_ + elapsed * rate_);
      at_ = now;
    }
  }
  bool has_token() const {
    return tokens_ >= 1.0;
  }
  void take() {
    tokens_ -= 1.0;
  }
  bool full() const {
    return tokens_ >= burst_;
  }

 private:
  double rate_;
  double burst_;
  double tokens_;
  td::Timestamp at_;
};

struct RefusalAnswerLimits {
  double global_rate;
  double global_burst;
  double source_rate;
  double source_burst;
  size_t max_sources;
};

// How long an answer to a capacity refusal may stay in the transport that
// sends it. Over RLDP that bounds the live refusal-answer transfers to the
// budget's burst plus this many seconds of its rate: 96 + 192 * 3 = 672 in
// all and 24 + 48 * 3 = 168 per source, before expiry slack. Plain ADNL
// answers sit in their own bounded, non-retransmitted queue (10 s TTL), and
// QUIC answers stay under QUIC's stream budgets and its absolute inbound
// stream lifetime (120 s by default), not under this bound; those figures
// are for RLDP only.
constexpr double k_refusal_answer_lifetime = 3.0;

// Sources tracked by the refusal-answer budget at most. The global budget
// already keeps the live entries near its burst plus one refill time of its
// rate, so this cap only matters if that reasoning breaks.
constexpr size_t k_refusal_answer_max_sources = 1024;

// An answer costs the node a transfer, more than the admission check that
// refused the query, so answers get their own budget: twice the default
// admission rate, globally and for each source's share of it, with one
// window's allowance as the burst. The budget does not follow the configured
// limits, so a node that loosens or disables admission still bounds it.
inline RefusalAnswerLimits default_refusal_answer_limits() {
  constexpr double window = k_default_ratelimit_window_size;
  const double global = static_cast<double>(k_default_ratelimit_global);
  const double share = static_cast<double>(FullNodeRateLimiter::per_source_limit(k_default_ratelimit_global));
  return RefusalAnswerLimits{2.0 * global / window, global, 2.0 * share / window, share, k_refusal_answer_max_sources};
}

// The budget for answering capacity refusals, shared by every shard actor
// that shares the node's limiter. Each answer is charged once to the global
// bucket and once to its source's; past either, the refusal stays silent.
// Sources are kept in order of their latest charge and dropped once their
// bucket is full again, when they are indistinguishable from a new source.
// Only aggregate counts are kept; with a sink, they are also added to it,
// which is how the node's budget reaches the metrics exporter.
class RefusalAnswerBudget {
 public:
  using Counters = health::NodeStateGauges::RefusalAnswers;

  explicit RefusalAnswerBudget(RefusalAnswerLimits limits = default_refusal_answer_limits(),
                               td::Timestamp now = td::Timestamp::now(), Counters *sink = nullptr)
      : limits_(limits), global_(limits.global_rate, limits.global_burst, now), sink_(sink) {
  }
  RefusalAnswerBudget(const RefusalAnswerBudget &) = delete;
  RefusalAnswerBudget &operator=(const RefusalAnswerBudget &) = delete;

  // Takes one answer from both budgets, or nothing when either is spent.
  bool try_take(const adnl::AdnlNodeIdShort &source, td::Timestamp now) {
    std::unique_lock lock(mutex_);
    expire_sources(now);
    global_.refill(now);
    auto it = sources_.find(source);
    std::optional<TokenBucket> fresh;
    TokenBucket *bucket = nullptr;
    if (it != sources_.end()) {
      bucket = &it->second.bucket;
      bucket->refill(now);
    } else if (sources_.size() < limits_.max_sources) {
      fresh.emplace(limits_.source_rate, limits_.source_burst, now);
      bucket = &*fresh;
    }
    if (bucket == nullptr || !bucket->has_token() || !global_.has_token()) {
      suppressed_.fetch_add(1, std::memory_order_relaxed);
      if (sink_ != nullptr) {
        sink_->suppressed.fetch_add(1, std::memory_order_relaxed);
      }
      return false;
    }
    global_.take();
    bucket->take();
    if (it == sources_.end()) {
      order_.push_back(source);
      sources_.emplace(source, SourceState{*fresh, std::prev(order_.end())});
    } else {
      order_.splice(order_.end(), order_, it->second.order);
    }
    answered_.fetch_add(1, std::memory_order_relaxed);
    if (sink_ != nullptr) {
      sink_->answered.fetch_add(1, std::memory_order_relaxed);
    }
    return true;
  }

  td::uint64 answered() const {
    return answered_.load(std::memory_order_relaxed);
  }
  td::uint64 suppressed() const {
    return suppressed_.load(std::memory_order_relaxed);
  }
  size_t tracked_sources(td::Timestamp now) {
    std::unique_lock lock(mutex_);
    expire_sources(now);
    return sources_.size();
  }

 private:
  struct SourceState {
    TokenBucket bucket;
    std::list<adnl::AdnlNodeIdShort>::iterator order;
  };

  // The front entry is the least recently charged; an entry charged more
  // often behind it is dropped at most one refill time later.
  void expire_sources(td::Timestamp now) {
    while (!order_.empty()) {
      auto it = sources_.find(order_.front());
      if (it == sources_.end()) {
        order_.pop_front();
        continue;
      }
      it->second.bucket.refill(now);
      if (!it->second.bucket.full()) {
        return;
      }
      order_.pop_front();
      sources_.erase(it);
    }
  }

  RefusalAnswerLimits limits_;
  std::mutex mutex_;
  TokenBucket global_;
  std::map<adnl::AdnlNodeIdShort, SourceState> sources_;
  std::list<adnl::AdnlNodeIdShort> order_;
  std::atomic<td::uint64> answered_{0};
  std::atomic<td::uint64> suppressed_{0};
  Counters *sink_ = nullptr;
};

// What admission decided about one query: admitted for dispatch, refused for
// capacity after parsing (the parsed query is kept, so the refusal can be
// answered without parsing or charging it again), or failed with the error
// to answer with (a malformed query, or no limiter).
class QueryAdmission {
 public:
  enum class Outcome { admitted, refused_for_capacity, failed };

  static QueryAdmission admitted(tos_api::object_ptr<tos_api::Function> function) {
    return QueryAdmission{Outcome::admitted, std::move(function), td::Status::OK()};
  }
  static QueryAdmission refused_for_capacity(tos_api::object_ptr<tos_api::Function> function) {
    return QueryAdmission{Outcome::refused_for_capacity, std::move(function), td::Status::OK()};
  }
  static QueryAdmission failed(td::Status error) {
    return QueryAdmission{Outcome::failed, nullptr, std::move(error)};
  }

  Outcome outcome() const {
    return outcome_;
  }
  bool is_admitted() const {
    return outcome_ == Outcome::admitted;
  }
  // The parsed query; null when admission failed.
  const tos_api::Function *function() const {
    return function_.get();
  }
  tos_api::object_ptr<tos_api::Function> move_function() {
    return std::move(function_);
  }
  // The error of a failed admission.
  const td::Status &error() const {
    return error_;
  }
  td::Status move_error() {
    return std::move(error_);
  }

 private:
  QueryAdmission(Outcome outcome, tos_api::object_ptr<tos_api::Function> function, td::Status error)
      : outcome_(outcome), function_(std::move(function)), error_(std::move(error)) {
  }

  Outcome outcome_;
  tos_api::object_ptr<tos_api::Function> function_;
  td::Status error_;
};

// Admission of overlay queries for one shard of the full node: it holds the
// shard's registration in the shared limiter, parses each query, charges it
// to the sending source and to this shard, and refuses it before anything is
// dispatched. A query that cannot be parsed is still charged to its source.
class ShardQueryAdmission {
 public:
  ShardQueryAdmission(std::shared_ptr<FullNodeRateLimiter> limiter, ShardIdFull shard,
                      std::shared_ptr<RefusalAnswerBudget> refusal_answers = nullptr)
      : limiter_(std::move(limiter)), refusal_answers_(std::move(refusal_answers)), shard_(shard) {
  }
  ShardQueryAdmission(const ShardQueryAdmission &) = delete;
  ShardQueryAdmission &operator=(const ShardQueryAdmission &) = delete;
  ~ShardQueryAdmission() {
    stop();
  }

  void start() {
    if (limiter_ && !registered_) {
      limiter_->register_shard(shard_);
      registered_ = true;
    }
  }

  void stop() {
    if (limiter_ && registered_) {
      limiter_->unregister_shard(shard_);
      registered_ = false;
    }
  }

  // Parses the query and charges it once. Without a limiter every query
  // fails, as it does when it cannot be parsed.
  QueryAdmission admit(adnl::AdnlNodeIdShort src, td::BufferSlice query, td::Timestamp now = td::Timestamp::now()) {
    if (!limiter_) {
      return QueryAdmission::failed(td::Status::Error(ErrorCode::failure, "too many requests"));
    }
    auto parsed = fetch_tl_object<tos_api::Function>(std::move(query), true);
    if (parsed.is_error()) {
      if (!limiter_->check_in_unparseable(shard_, src, now)) {
        return QueryAdmission::failed(td::Status::Error(ErrorCode::failure, "too many requests"));
      }
      return QueryAdmission::failed(td::Status::Error(ErrorCode::protoviolation, "cannot parse tosnode query"));
    }
    auto function = parsed.move_as_ok();
    if (!limiter_->check_in(function->get_id(), full_node_request_cost(*function), shard_, src, now)) {
      return QueryAdmission::refused_for_capacity(std::move(function));
    }
    return QueryAdmission::admitted(std::move(function));
  }

  // The reply to a query refused for capacity: its type's empty answer while
  // the refusal-answer budget lasts, otherwise the refusal error, which leaves
  // the requester to its own timeout as before. An answer may stay in the
  // transport for k_refusal_answer_lifetime from `now`, an absolute deadline
  // set here once and never restarted on the way to the transport.
  td::Result<adnl::AdnlQueryAnswer> answer_capacity_refusal(adnl::AdnlNodeIdShort src,
                                                            const tos_api::Function &function,
                                                            td::Timestamp now = td::Timestamp::now()) {
    auto answer = capacity_refusal_answer(function.get_id());
    if (!answer || !refusal_answers_ || !refusal_answers_->try_take(src, now)) {
      return td::Status::Error(ErrorCode::failure, "too many requests");
    }
    return adnl::AdnlQueryAnswer{std::move(*answer), td::Timestamp::in(k_refusal_answer_lifetime, now)};
  }

  // Admits one query and settles on `promise` what admission alone decides:
  // a failure with its error, a capacity refusal with its answer or error.
  // Returns the query when it is admitted, with `promise` left for dispatch.
  tos_api::object_ptr<tos_api::Function> admit_or_answer(adnl::AdnlNodeIdShort src, td::BufferSlice query,
                                                         td::Promise<adnl::AdnlQueryAnswer> &promise,
                                                         td::Timestamp now = td::Timestamp::now()) {
    auto admission = admit(src, std::move(query), now);
    switch (admission.outcome()) {
      case QueryAdmission::Outcome::failed:
        promise.set_error(admission.move_error());
        return nullptr;
      case QueryAdmission::Outcome::refused_for_capacity:
        promise.set_result(answer_capacity_refusal(src, *admission.function(), now));
        return nullptr;
      case QueryAdmission::Outcome::admitted:
        break;
    }
    return admission.move_function();
  }

 private:
  std::shared_ptr<FullNodeRateLimiter> limiter_;
  std::shared_ptr<RefusalAnswerBudget> refusal_answers_;
  ShardIdFull shard_;
  bool registered_ = false;
};

}  // namespace tos::validator::fullnode
