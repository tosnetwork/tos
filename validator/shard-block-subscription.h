/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <cstddef>
#include <map>
#include <set>
#include <utility>
#include <vector>

#include "auto/tl/tos_api.h"
#include "tl-utils/tl-utils.hpp"
#include "tos/tos-tl.hpp"
#include "validator/validator.h"

namespace tos::validator {

// Subscriptions between a shard block verifier and the trusted retainers that
// confirm shard blocks to it.
//
// A retainer sends each confirmation once, when it confirms the block, and
// sends every confirmation it still holds for a shard when it receives a new
// subscription, or a subscription carrying kShardBlockVerifierResendFlag. A
// verifier that lost a confirmation (dropped it when its retry queues were
// full, or never received the message) recovers it only through such a
// replay. Recovery therefore needs retainers that understand the resend flag:
// a retainer that predates it keeps answering renewals without replaying, and
// it may keep an expired subscription until it next confirms a block, so even
// letting the subscription lapse is no guaranteed way to get a replay from it.
// Such retainers must be upgraded; a verifier reports a subscription whose
// retainer never acknowledges a replay as unsupported.

// Subscription flag asking a retainer to send every confirmation it still
// holds for the shard again, as it does for a new subscription.
inline constexpr td::uint32 kShardBlockVerifierResendFlag = 1;
// Reply flag by which a retainer says it queued every confirmation it holds
// for the shard in answer to this subscription. It does not say they arrived.
inline constexpr td::uint32 kShardBlockRetainerReplayedFlag = 1;
// The least interval between two replays a retainer makes to one subscriber
// on request; a new subscription is always answered.
inline constexpr double kShardBlockRetainerMinResendInterval = 5.0;
// How long a retainer keeps a subscription that is not renewed.
inline constexpr double kShardBlockRetainerSubscriptionTtl = 60.0;
// How often a verifier renews its subscriptions.
inline constexpr double kShardBlockVerifierSubscribePeriod = 10.0;

// --- Wire adapter: what the verifier sends and how it reads the answer ---

inline td::BufferSlice make_shard_block_subscribe_request(const ShardIdFull &shard, td::uint32 flags) {
  return create_serialize_tl_object<tos_api::shardBlockVerifier_subscribe>(create_tl_shard_id(shard),
                                                                           static_cast<td::int32>(flags));
}

// The flags of a retainer's answer, or the error that stands in for an answer.
inline td::Result<td::uint32> parse_shard_block_subscribe_reply(td::Result<td::BufferSlice> reply) {
  TRY_RESULT(data, std::move(reply));
  TRY_RESULT(obj, fetch_tl_object<tos_api::shardBlockVerifier_subscribed>(data, true));
  return static_cast<td::uint32>(obj->flags_);
}

// --- Retainer side ---

// A retainer's subscribers and when each may be answered with a replay. Owned
// by one actor; not thread-safe.
class ShardBlockRetainerSubscriptions {
 public:
  using Peer = adnl::AdnlNodeIdShort;
  using Key = std::pair<Peer, ShardIdFull>;

  struct Request {
    ShardIdFull shard;
    td::uint32 flags;
  };
  struct Answer {
    bool send_retained = false;  // send every held confirmation for the shard now
    td::BufferSlice reply;       // the serialized shardBlockVerifier.subscribed
  };

  static td::Result<Request> parse_request(td::Slice data) {
    TRY_RESULT(query, fetch_tl_object<tos_api::shardBlockVerifier_subscribe>(data, true));
    return Request{create_shard_id(query->shard_), static_cast<td::uint32>(query->flags_)};
  }

  // Records a subscription at `now` and decides whether to replay. A
  // subscription it has none of, or whose time to live passed, is new.
  Answer subscribe(const Peer &src, const ShardIdFull &shard, td::uint32 flags, double now) {
    State &state = subscribers_[{src, shard}];
    const bool new_subscription = !state.ttl_set || state.ttl <= now;
    const bool resend_requested = (flags & kShardBlockVerifierResendFlag) != 0;
    const bool resend_allowed = now >= state.resend_allowed_at;
    Answer answer;
    td::uint32 reply_flags = 0;
    if (new_subscription || (resend_requested && resend_allowed)) {
      answer.send_retained = true;
      state.resend_allowed_at = now + kShardBlockRetainerMinResendInterval;
      reply_flags |= kShardBlockRetainerReplayedFlag;
    }
    state.ttl_set = true;
    state.ttl = now + kShardBlockRetainerSubscriptionTtl;
    answer.reply =
        create_serialize_tl_object<tos_api::shardBlockVerifier_subscribed>(static_cast<td::int32>(reply_flags));
    return answer;
  }

  // Subscribers of shards intersecting `shard` that have not expired.
  std::vector<Peer> active_for(const ShardIdFull &shard, double now) const {
    std::vector<Peer> result;
    for (const auto &[key, state] : subscribers_) {
      if (state.ttl > now && shard_intersects(key.second, shard)) {
        result.push_back(key.first);
      }
    }
    return result;
  }

  // Drops expired subscriptions and those `drop` selects.
  template <class Predicate>
  void remove_if(double now, Predicate drop) {
    for (auto it = subscribers_.begin(); it != subscribers_.end();) {
      if (it->second.ttl <= now || drop(it->first)) {
        it = subscribers_.erase(it);
      } else {
        ++it;
      }
    }
  }

  std::size_t size() const {
    return subscribers_.size();
  }

 private:
  struct State {
    bool ttl_set = false;
    double ttl = 0;
    double resend_allowed_at = 0;
  };
  std::map<Key, State> subscribers_;
};

// --- Verifier side ---

// Recovery of confirmations a verifier lost, per (trusted node, shard)
// subscription. Owned by one actor; not thread-safe.
//
// Two things start recovery: a confirmation dropped for full retry queues
// (request), and a local wait still unresolved (refresh with the
// subscriptions it needs). While a subscription is recovering, each regular
// subscription asks for a replay. An acknowledged replay ends recovery, but
// the acknowledgement only says the replay was queued: if a wait it should
// have resolved is still unresolved at the next refresh, recovery starts again.
// So a wait keeps asking, once per subscription period, until it is resolved,
// its block is registered, or the configuration stops requiring it.
//
// Recovery a dropped confirmation started, with no wait depending on it, is
// given up after kMaxAttempts failed or unacknowledged attempts; a later wait
// for that block starts it again. A subscription whose retainer answers
// kMaxUnacknowledged times without acknowledging is reported as unsupported:
// that retainer predates the resend flag and must be upgraded.
template <class Key>
class ShardBlockSubscriptionRecovery {
 public:
  static constexpr unsigned kMaxAttempts = 6;
  static constexpr unsigned kMaxUnacknowledged = 3;

  // Starts recovery for a subscription unless it is already recovering.
  void request(const Key &key) {
    states_.try_emplace(key);
  }

  // Marks exactly the subscriptions in `required` as needed by unresolved
  // waits, starting recovery for any that are not recovering, and gives up
  // recovery no wait needs once its attempts are spent.
  void refresh(const std::set<Key> &required) {
    for (const auto &key : required) {
      states_.try_emplace(key);
    }
    for (auto it = states_.begin(); it != states_.end();) {
      it->second.required = required.contains(it->first);
      if (!it->second.required && it->second.attempts >= kMaxAttempts) {
        it = states_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // The flags for the regular subscription `key`.
  td::uint32 subscription_flags(const Key &key) const {
    return states_.contains(key) ? kShardBlockVerifierResendFlag : 0;
  }

  void on_reply(const Key &key, td::uint32 reply_flags) {
    auto it = states_.find(key);
    if (it == states_.end()) {
      return;
    }
    if ((reply_flags & kShardBlockRetainerReplayedFlag) != 0) {
      unsupported_.erase(key);
      states_.erase(it);
      return;
    }
    ++it->second.attempts;
    if (++it->second.unacknowledged >= kMaxUnacknowledged && unsupported_.insert(key).second) {
      newly_unsupported_.insert(key);
    }
  }

  void on_failure(const Key &key) {
    auto it = states_.find(key);
    if (it != states_.end()) {
      ++it->second.attempts;
    }
  }

  // Forgets subscriptions `keep` rejects (no longer configured).
  template <class Predicate>
  void retain_if(Predicate keep) {
    for (auto it = states_.begin(); it != states_.end();) {
      it = keep(it->first) ? std::next(it) : states_.erase(it);
    }
    for (auto it = unsupported_.begin(); it != unsupported_.end();) {
      it = keep(*it) ? std::next(it) : unsupported_.erase(it);
    }
  }

  // Subscriptions found unsupported since the last call, to report once.
  std::set<Key> take_newly_unsupported() {
    return std::exchange(newly_unsupported_, {});
  }

  bool outstanding(const Key &key) const {
    return states_.contains(key);
  }
  bool unsupported(const Key &key) const {
    return unsupported_.contains(key);
  }

 private:
  struct State {
    unsigned attempts = 0;
    unsigned unacknowledged = 0;
    bool required = false;
  };
  std::map<Key, State> states_;
  std::set<Key> unsupported_;
  std::set<Key> newly_unsupported_;
};

// A verifier's subscriptions to its trusted retainers: which requests each
// regular round sends, and what an answer means for recovery. The actor only
// moves the requests and answers between this and the network.
class ShardBlockVerifierSubscriptions {
 public:
  using Peer = adnl::AdnlNodeIdShort;
  using Key = std::pair<Peer, ShardIdFull>;
  using Recovery = ShardBlockSubscriptionRecovery<Key>;

  struct Outgoing {
    Key key;
    td::BufferSlice request;
  };

  // Confirmations from these peers were dropped: recover them on every
  // subscription the peer serves.
  void dropped(const std::set<Peer> &peers, const ShardBlockVerifierConfig &config) {
    for (const auto &shard_config : config.shards) {
      for (const auto &node_id : shard_config.trusted_nodes) {
        if (peers.contains(node_id)) {
          recovery_.request({node_id, shard_config.shard_id});
        }
      }
    }
  }

  // One regular round: `unresolved` are the subscriptions local waits still
  // need (ShardBlockConfirmations::unresolved_wait_sources). Returns a
  // request for every configured subscription, asking for a replay where
  // recovery is outstanding.
  std::vector<Outgoing> round(const ShardBlockVerifierConfig &config, const std::set<Key> &unresolved) {
    recovery_.refresh(unresolved);
    std::vector<Outgoing> out;
    for (const auto &shard_config : config.shards) {
      for (const auto &node_id : shard_config.trusted_nodes) {
        Key key{node_id, shard_config.shard_id};
        out.push_back(Outgoing{
            key, make_shard_block_subscribe_request(shard_config.shard_id, recovery_.subscription_flags(key))});
      }
    }
    return out;
  }

  // The answer to a request from round(), or the error that replaced it.
  // Returns the parse result so the caller can log a failure.
  td::Status answered(const Key &key, td::Result<td::BufferSlice> reply) {
    auto flags = parse_shard_block_subscribe_reply(std::move(reply));
    if (flags.is_error()) {
      recovery_.on_failure(key);
      return flags.move_as_error();
    }
    recovery_.on_reply(key, flags.ok());
    return td::Status::OK();
  }

  // Forgets recovery for subscriptions the configuration no longer has.
  void configured(const ShardBlockVerifierConfig &config) {
    std::set<Key> keys;
    for (const auto &shard_config : config.shards) {
      for (const auto &node_id : shard_config.trusted_nodes) {
        keys.insert({node_id, shard_config.shard_id});
      }
    }
    recovery_.retain_if([&](const Key &key) { return keys.contains(key); });
  }

  Recovery &recovery() {
    return recovery_;
  }

 private:
  Recovery recovery_;
};

}  // namespace tos::validator
