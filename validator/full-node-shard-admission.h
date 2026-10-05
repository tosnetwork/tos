/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <memory>
#include <set>
#include <utility>

#include "adnl/adnl-node-id.hpp"
#include "auto/tl/tos_api.h"
#include "auto/tl/tos_api.hpp"
#include "common/errorcode.h"
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

// Admission of overlay queries for one shard of the full node: it holds the
// shard's registration in the shared limiter, parses each query, charges it
// to the sending source and to this shard, and refuses it before anything is
// dispatched. A query that cannot be parsed is still charged to its source.
class ShardQueryAdmission {
 public:
  ShardQueryAdmission(std::shared_ptr<FullNodeRateLimiter> limiter, ShardIdFull shard)
      : limiter_(std::move(limiter)), shard_(shard) {
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

  // Returns the parsed query when it is admitted, or the error to answer with.
  // Without a limiter every query is refused.
  td::Result<tos_api::object_ptr<tos_api::Function>> admit(adnl::AdnlNodeIdShort src, td::BufferSlice query,
                                                           td::Timestamp now = td::Timestamp::now()) {
    if (!limiter_) {
      return td::Status::Error(ErrorCode::failure, "too many requests");
    }
    auto parsed = fetch_tl_object<tos_api::Function>(std::move(query), true);
    if (parsed.is_error()) {
      if (!limiter_->check_in_unparseable(shard_, src, now)) {
        return td::Status::Error(ErrorCode::failure, "too many requests");
      }
      return td::Status::Error(ErrorCode::protoviolation, "cannot parse tosnode query");
    }
    auto function = parsed.move_as_ok();
    if (!limiter_->check_in(function->get_id(), full_node_request_cost(*function), shard_, src, now)) {
      return td::Status::Error(ErrorCode::failure, "too many requests");
    }
    return std::move(function);
  }

 private:
  std::shared_ptr<FullNodeRateLimiter> limiter_;
  ShardIdFull shard_;
  bool registered_ = false;
};

}  // namespace tos::validator::fullnode
