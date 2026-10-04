/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "td/actor/MultiPromise.h"

#include "shard-block-verifier.hpp"

namespace tos::validator {

void ShardBlockVerifier::start_up() {
  update_config(opts_->get_shard_block_verifier_config());
  update_masterchain_state(last_masterchain_state_);

  class Callback : public adnl::Adnl::Callback {
   public:
    explicit Callback(td::actor::ActorId<ShardBlockVerifier> id) : id_(std::move(id)) {
    }
    void receive_message(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data) override {
      td::actor::send_closure(id_, &ShardBlockVerifier::process_message, src, std::move(data));
    }
    void receive_query(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data,
                       td::Promise<td::BufferSlice> promise) override {
      // The ShardBlockVerifier ADNL
      // subscription only accepts asynchronous `confirmBlocks` MESSAGES;
      // queries are not part of the protocol. Empty body would drop the
      // promise and hang the caller — return an explicit error instead.
      promise.set_error(td::Status::Error("shard block verifier does not support queries"));
    }

   private:
    td::actor::ActorId<ShardBlockVerifier> id_;
  };
  td::actor::send_closure(adnl_, &adnl::Adnl::subscribe, local_id_,
                          adnl::Adnl::int_to_bytestring(tos_api::shardBlockVerifier_confirmBlocks::ID),
                          std::make_unique<Callback>(actor_id(this)));
  td::actor::send_closure(rldp_, &rldp2::Rldp::add_id, local_id_);
}

void ShardBlockVerifier::tear_down() {
  td::actor::send_closure(adnl_, &adnl::Adnl::unsubscribe, local_id_,
                          adnl::Adnl::int_to_bytestring(tos_api::shardBlockVerifier_confirmBlocks::ID));
}

void ShardBlockVerifier::update_masterchain_state(td::Ref<MasterchainState> state) {
  last_masterchain_state_ = std::move(state);
  confirmations_.prune_registered();
  collect_resend_requests();
}

void ShardBlockVerifier::wait_shard_blocks(std::vector<BlockIdExt> blocks, td::Promise<td::Unit> promise) {
  confirmations_.wait(blocks, std::move(promise));
  collect_resend_requests();
}

void ShardBlockVerifier::update_config(td::Ref<ShardBlockVerifierConfig> new_config) {
  config_ = new_config;
  confirmations_.set_config(std::move(new_config));
  all_trusted_nodes_.clear();
  std::set<SubscriptionKey> configured;
  for (auto& shard : config_->shards) {
    all_trusted_nodes_.insert(shard.trusted_nodes.begin(), shard.trusted_nodes.end());
    for (auto& node_id : shard.trusted_nodes) {
      configured.insert({node_id, shard.shard_id});
    }
  }
  recovery_.retain_if([&](const SubscriptionKey& key) { return configured.contains(key); });
  collect_resend_requests();

  alarm_timestamp().relax(send_subscribe_at_ = td::Timestamp::now());
}

void ShardBlockVerifier::collect_resend_requests() {
  auto requests = confirmations_.take_resend_requests();
  if (requests.empty() || config_.is_null()) {
    return;
  }
  for (const auto& node_id : requests) {
    LOG(WARNING) << "Dropped confirmations from " << node_id << ": recovering them through its subscriptions";
    for (auto& shard_config : config_->shards) {
      for (auto& trusted : shard_config.trusted_nodes) {
        if (trusted == node_id) {
          recovery_.request({node_id, shard_config.shard_id});
        }
      }
    }
  }
}

void ShardBlockVerifier::alarm() {
  if (send_subscribe_at_ && send_subscribe_at_.is_in_past()) {
    const double now = td::Time::now();
    for (auto& shard_config : config_->shards) {
      for (auto& node_id : shard_config.trusted_nodes) {
        SubscriptionKey key{node_id, shard_config.shard_id};
        // A subscription recovering dropped confirmations asks for a resend,
        // or is let lapse so that the next one is new to the retainer.
        auto flags = recovery_.subscription(key, now);
        if (!flags) {
          continue;
        }
        td::Promise<td::BufferSlice> P = [SelfId = actor_id(this), key](td::Result<td::BufferSlice> R) {
          td::actor::send_closure(SelfId, &ShardBlockVerifier::subscription_answered, key, std::move(R));
        };
        td::actor::send_closure(rldp_, &rldp2::Rldp::send_query, local_id_, node_id, "subscribe", std::move(P),
                                td::Timestamp::in(3.0),
                                create_serialize_tl_object<tos_api::shardBlockVerifier_subscribe>(
                                    create_tl_shard_id(shard_config.shard_id), *flags));
      }
    }
    send_subscribe_at_ = td::Timestamp::in(kShardBlockVerifierSubscribePeriod);
  }
  alarm_timestamp().relax(send_subscribe_at_);
}

void ShardBlockVerifier::subscription_answered(SubscriptionKey key, td::Result<td::BufferSlice> R) {
  const double now = td::Time::now();
  if (R.is_error()) {
    LOG(WARNING) << "Subscribe to " << key.first << " for " << key.second.to_str() << " : " << R.move_as_error();
    recovery_.on_failure(key, now);
    return;
  }
  auto r_reply = fetch_tl_object<tos_api::shardBlockVerifier_subscribed>(R.move_as_ok(), true);
  if (r_reply.is_error()) {
    LOG(WARNING) << "Subscribe to " << key.first << " for " << key.second.to_str() << " : " << r_reply.move_as_error();
    recovery_.on_failure(key, now);
    return;
  }
  recovery_.on_reply(key, static_cast<td::uint32>(r_reply.ok()->flags_), now);
}

void ShardBlockVerifier::process_message(adnl::AdnlNodeIdShort src, td::BufferSlice data) {
  if (!all_trusted_nodes_.contains(src)) {
    LOG(INFO) << "Message from " << src << " : unknown src";
    return;
  }
  auto r_obj = fetch_tl_object<tos_api::shardBlockVerifier_confirmBlocks>(data, true);
  if (r_obj.is_error()) {
    LOG(INFO) << "Message from " << src << " : " << r_obj.move_as_error();
    return;
  }
  using ConfirmResult = ShardBlockConfirmations::ConfirmResult;
  for (const auto& b : r_obj.ok()->blocks_) {
    BlockIdExt block_id = create_block_id(b);
    switch (confirmations_.confirm(src, block_id)) {
      case ConfirmResult::Accepted:
        VLOG(VALIDATOR_DEBUG) << "Confirm for " << block_id.to_str() << " from " << src << " : accepted";
        break;
      case ConfirmResult::Confirmed:
        LOG(INFO) << "Confirm for " << block_id.to_str() << " from " << src << " : accepted, CONFIRMED";
        break;
      case ConfirmResult::Duplicate:
        VLOG(VALIDATOR_DEBUG) << "Confirm for " << block_id.to_str() << " from " << src << " : duplicate";
        break;
      case ConfirmResult::UnknownSource:
        LOG(INFO) << "Confirm for " << block_id.to_str() << " from " << src << " : unknown src";
        break;
      case ConfirmResult::NotTracked:
        VLOG(VALIDATOR_DEBUG) << "Confirm for " << block_id.to_str() << " from " << src << " : ignored";
        break;
      case ConfirmResult::Deferred:
        VLOG(VALIDATOR_DEBUG) << "Confirm for " << block_id.to_str() << " from " << src
                              << " : held, beyond the registered shard top lookahead";
        break;
      case ConfirmResult::PeerBudget:
        LOG(INFO) << "Confirm for " << block_id.to_str() << " from " << src << " : held, peer budget exhausted ("
                  << confirmations_.peer_entries(src) << " entries, " << confirmations_.peer_bytes(src) << " bytes)";
        break;
      case ConfirmResult::GlobalBudget:
        LOG(INFO) << "Confirm for " << block_id.to_str() << " from " << src << " : held, global budget exhausted ("
                  << confirmations_.peer_entries() << " entries, " << confirmations_.peer_bytes() << " bytes)";
        break;
      case ConfirmResult::Dropped:
        LOG(WARNING) << "Confirm for " << block_id.to_str() << " from " << src << " : dropped, retry queues full ("
                     << confirmations_.deferred(src) << " held for this peer, " << confirmations_.deferred()
                     << " in total)";
        break;
    }
  }
  collect_resend_requests();
}

std::optional<BlockSeqno> ShardBlockVerifier::registered_seqno(const BlockIdExt& block_id) const {
  if (last_masterchain_state_.is_null()) {
    return std::nullopt;
  }
  ShardIdFull shard = block_id.shard_full();
  shard.shard |= 1;
  auto shard_desc = last_masterchain_state_->get_shard_from_config(shard, false);
  if (shard_desc.is_null()) {
    return std::nullopt;
  }
  return shard_desc->top_block_id().seqno();
}

}  // namespace tos::validator
