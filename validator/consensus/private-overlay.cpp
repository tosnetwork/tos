/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include <algorithm>
#include <limits>
#include <map>
#include <random>
#include <set>
#include <vector>

#include "adnl/adnl-node-id.hpp"
#include "auto/tl/tos_api.h"
#include "overlay/overlays.h"
#include "td/utils/Random.h"
#include "td/utils/Status.h"
#include "td/utils/logging.h"

#include "bus.h"
#include "stats.h"
#include "validator/consensus/simplex/misbehavior.h"

namespace tos::validator::consensus {

namespace tl {

using requestError = tos_api::consensus_requestError;
using RequestErrorRef = tl_object_ptr<requestError>;

}  // namespace tl

namespace {

class PrivateOverlayImpl : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  static bool should_be_spawned(const Bus& bus) {
    return bus.is_validator() || bus.config.observers_in_private_overlay();
  }

  void start_up() override {
    auto& bus = *owning_bus();
    overlays_ = bus.overlays;
    local_adnl_id_ = bus.local_adnl_id;
    adnl_sender_ = bus.adnl_sender;
    params_ = bus.config.noncritical_params;
    slots_per_leader_window_ = bus.config.slots_per_leader_window;

    std::vector<adnl::AdnlNodeIdShort> validator_nodes;
    std::vector<td::Bits256> overlay_nodes_tl;
    std::map<PublicKeyHash, td::uint32> authorized_keys;

    const td::uint64 max_broadcast_size_wide = static_cast<td::uint64>(bus.config.max_block_size) +
                                               bus.config.max_collated_data_size + (1U << 20);
    LOG_CHECK(max_broadcast_size_wide <= std::numeric_limits<td::uint32>::max())
        << "Configured consensus broadcast limit overflows uint32";
    const td::uint32 max_broadcast_size = static_cast<td::uint32>(max_broadcast_size_wide);
    for (const auto& peer : bus.validator_set) {
      adnl_id_to_peer_[peer.adnl_id] = peer;
      short_id_to_peer_[peer.short_id] = peer;
      validator_nodes.push_back(peer.adnl_id);
      overlay_nodes_tl.push_back(peer.short_id.bits256_value());
      authorized_keys.emplace(peer.short_id, max_broadcast_size);
    }

    auto overlay_nodes = bus.config.observers_in_private_overlay() ? bus.all_validators : validator_nodes;
    if (std::find(overlay_nodes.begin(), overlay_nodes.end(), local_adnl_id_) == overlay_nodes.end()) {
      overlay_nodes.push_back(local_adnl_id_);
    }
    std::sort(overlay_nodes.begin(), overlay_nodes.end());
    overlay_nodes.erase(std::unique(overlay_nodes.begin(), overlay_nodes.end()), overlay_nodes.end());
    for (const auto& node : overlay_nodes) {
      overlay_nodes_.insert(node);
      if (node != local_adnl_id_) {
        other_overlay_nodes_.push_back(node);
      }
    }

    td::actor::send_closure(adnl_sender_, &adnl::AdnlSenderEx::add_id, local_adnl_id_);

    auto overlay_seed = create_tl_object<tl::overlayId>(bus.session_id, std::move(overlay_nodes_tl));
    auto overlay_full_id = overlay::OverlayIdFull{serialize_tl_object(overlay_seed, true)};
    overlay_id_ = overlay_full_id.compute_short_id();

    overlay::OverlayOptions options;
    options.name_ = PSTRING() << "valgroup" << bus.shard.to_str() << "." << bus.cc_seqno;
    options.broadcast_speed_multiplier_ = bus.validator_opts->get_catchain_broadcast_speed_multiplier();
    options.private_ping_peers_ = true;
    options.twostep_broadcast_sender_ = adnl_sender_;
    options.send_twostep_broadcast_ = true;
    options.allow_old_broadcasts_ = false;

    td::actor::send_closure(overlays_, &overlay::Overlays::create_private_overlay_ex, local_adnl_id_,
                            std::move(overlay_full_id), std::move(overlay_nodes), make_callback(),
                            overlay::OverlayPrivacyRules{0, 0, std::move(authorized_keys)},
                            PSTRING() << R"({ "type": "consensus", "shard": ")" << bus.shard.to_str()
                                      << R"(", "cc_seqno": )" << bus.cc_seqno << R"( })",
                            std::move(options));
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const StopRequested>) {
    td::actor::send_closure(overlays_, &overlay::Overlays::delete_overlay, local_adnl_id_, overlay_id_);
    stop();
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const OutgoingProtocolMessage> message) {
    auto send_to_peer = [&](const adnl::AdnlNodeIdShort& adnl_id) {
      if (adnl_id == local_adnl_id_) {
        return;
      }
      td::actor::send_closure(overlays_, &overlay::Overlays::send_message_via, adnl_id, local_adnl_id_, overlay_id_,
                              message->message.data.clone(), adnl_sender_);
    };

    auto broadcast_fn = [&](const OutgoingProtocolMessage::BroadcastToAll&) {
      for (const auto& adnl_id : other_overlay_nodes_) {
        send_to_peer(adnl_id);
      }
    };

    auto broadcast_validators_fn = [&](const OutgoingProtocolMessage::BroadcastToValidators&) {
      for (const auto& [adnl_id, _] : adnl_id_to_peer_) {
        send_to_peer(adnl_id);
      }
    };

    auto gossip_fn = [&](const OutgoingProtocolMessage::BroadcastToRandom& r) {
      std::vector<adnl::AdnlNodeIdShort> selected_peers;
      std::sample(other_overlay_nodes_.begin(), other_overlay_nodes_.end(), std::back_inserter(selected_peers),
                  std::min(r.count, other_overlay_nodes_.size()), gossip_rng_);

      for (auto peer : selected_peers) {
        send_to_peer(peer);
      }
    };

    std::visit(td::overloaded(broadcast_fn, broadcast_validators_fn, gossip_fn), message->recipient);
  }

  template <>
  td::actor::Task<ProtocolMessage> process(BusHandle, std::shared_ptr<OutgoingOverlayRequest> message) {
    adnl::AdnlNodeIdShort dst;
    if (message->destination) {
      dst = *message->destination;
    } else {
      if (other_overlay_nodes_.empty()) {
        co_return td::Status::Error("No private-overlay peer is available");
      }
      dst = other_overlay_nodes_[td::Random::fast(0, static_cast<int>(other_overlay_nodes_.size()) - 1)];
    }
    auto [awaiter, promise] = td::actor::StartedTask<td::BufferSlice>::make_bridge();
    const td::uint64 max_response_size_wide = static_cast<td::uint64>(owning_bus()->config.max_block_size) +
                                              owning_bus()->config.max_collated_data_size + (1U << 20);
    if (max_response_size_wide > std::numeric_limits<td::uint32>::max()) {
      co_return td::Status::Error("Configured consensus response limit overflows uint32");
    }
    td::actor::send_closure(
        overlays_, &overlay::Overlays::send_query_via, dst, local_adnl_id_, overlay_id_, "", std::move(promise),
        message->timeout, std::move(message->request.data), static_cast<td::uint32>(max_response_size_wide),
        adnl_sender_);
    auto response = co_await std::move(awaiter);
    if (fetch_tl_object<tl::requestError>(response, true).is_ok()) {
      co_return td::Status::Error("Peer returned an error");
    }
    co_return ProtocolMessage{std::move(response)};
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const CandidateGenerated> event) {
    if (owning_bus()->config.enable_block_sync()) {
      return;
    }
    if (!owning_bus()->is_validator()) {
      LOG(ERROR) << "private-overlay: observer attempted to broadcast a generated candidate";
      return;
    }
    td::BufferSlice extra = create_serialize_tl_object<tos_api::consensus_broadcastExtra>(event->candidate->id.slot);
    td::actor::send_closure(overlays_, &overlay::Overlays::send_broadcast_fec_with_extra, local_adnl_id_, overlay_id_,
                            owning_bus()->local_id->short_id, 0, event->candidate->serialize(), std::move(extra));
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const NoncriticalParamsUpdated> event) {
    params_ = event->params;
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const FinalizeBlock> event) {
    td::uint32 slot = event->candidate->id.slot;
    first_nonfinalized_slot_ = slot + 1;
    // Purge dedup entries for slots that are now finalized and
    // cannot appear again in any future broadcast precheck.
    seen_broadcasts_.erase(seen_broadcasts_.begin(), seen_broadcasts_.lower_bound(first_nonfinalized_slot_));
  }

  // V-021: PrecheckCandidateBroadcast handler relocated from
  // simplex::PoolImpl to this actor, which owns broadcast-deduplication
  // state and is the natural home for broadcast-level validity checks.
  template <>
  td::actor::Task<> process(BusHandle, std::shared_ptr<PrecheckCandidateBroadcast> query) {
    if (query->slot < first_nonfinalized_slot_) {
      co_return td::Status::Error("Slot is already finalized");
    }
    // Use first_nonfinalized_slot_ as a conservative lower bound for
    // the current slot: now_ >= first_nonfinalized_slot_ always holds,
    // so this check only admits slightly more broadcasts than the pool
    // would — never fewer.
    if (query->slot > first_nonfinalized_slot_ + params_.max_leader_window_desync * slots_per_leader_window_) {
      co_return td::Status::Error("Slot is too far in the future");
    }
    if (query->signature_checked) {
      auto [it, inserted] = seen_broadcasts_.emplace(query->slot, query->broadcast_id);
      if (!inserted && it->second != query->broadcast_id) {
        co_return td::Status::Error("Duplicate broadcast");
      }
    } else {
      auto it = seen_broadcasts_.find(query->slot);
      if (it != seen_broadcasts_.end() && it->second != query->broadcast_id) {
        co_return td::Status::Error("Duplicate broadcast");
      }
    }
    co_return td::Unit{};
  }

 private:
  std::unique_ptr<overlay::Overlays::Callback> make_callback() {
    class Callback final : public overlay::Overlays::Callback {
     public:
      explicit Callback(td::actor::ActorId<PrivateOverlayImpl> owner) : owner_(owner) {
      }

      void receive_message(adnl::AdnlNodeIdShort src, overlay::OverlayIdShort, td::BufferSlice data) override {
        td::actor::send_closure(owner_, &PrivateOverlayImpl::on_overlay_message, src, std::move(data));
      }

      void receive_query(adnl::AdnlNodeIdShort src, overlay::OverlayIdShort, td::BufferSlice data,
                         td::Promise<td::BufferSlice> promise) override {
        td::actor::send_closure(owner_, &PrivateOverlayImpl::on_query, src, std::move(data), std::move(promise));
      }

      void receive_broadcast_with_extra(PublicKeyHash src, overlay::OverlayIdShort, td::BufferSlice data,
                                        td::BufferSlice extra) override {
        td::actor::send_closure(owner_, &PrivateOverlayImpl::on_overlay_broadcast, src, std::move(data),
                                std::move(extra));
      }

      void precheck_broadcast(PublicKeyHash src, overlay::OverlayIdShort overlay_id, td::Bits256 broadcast_id,
                              td::BufferSlice extra, bool signature_checked, td::Promise<> promise) override {
        td::actor::send_closure(owner_, &PrivateOverlayImpl::precheck_broadcast, src, broadcast_id, std::move(extra),
                                signature_checked, std::move(promise));
      }

      void check_broadcast(PublicKeyHash, overlay::OverlayIdShort, td::BufferSlice,
                           td::Promise<td::Unit> promise) override {
        promise.set_value(td::Unit());
      }

     private:
      td::actor::ActorId<PrivateOverlayImpl> owner_;
    };

    return std::make_unique<Callback>(actor_id(this));
  }

  void on_overlay_message(adnl::AdnlNodeIdShort src_adnl_id, td::BufferSlice data) {
    if (!overlay_nodes_.contains(src_adnl_id)) {
      LOG(WARNING) << "private-overlay: dropping message from non-member adnl src " << src_adnl_id;
      return;
    }
    auto it = adnl_id_to_peer_.find(src_adnl_id);
    auto source_validator =
        it == adnl_id_to_peer_.end() ? std::optional<PeerValidatorId>{} : std::optional{it->second.idx};
    owning_bus().publish<IncomingProtocolMessage>(source_validator, src_adnl_id, std::move(data));
  }

  void on_overlay_broadcast(PublicKeyHash src, td::BufferSlice data, td::BufferSlice extra) {
    if (owning_bus()->config.enable_block_sync()) {
      LOG(WARNING) << "Dropping candidate broadcast in the consensus overlay while block sync is enabled";
      return;
    }
    if (owning_bus()->is_validator() && src == owning_bus()->local_id->short_id) {
      return;
    }

    // The previous code called `.move_as_ok()` on the parse Result without
    // checking, so a malformed
    // `consensus_broadcastExtra` from any authorized validator crashed the
    // daemon. Mirror precheck_broadcast's parse-error handling.
    auto parsed_extra_r = fetch_tl_object<tos_api::consensus_broadcastExtra>(extra, true);
    if (parsed_extra_r.is_error()) {
      LOG(WARNING) << "private-overlay: dropping broadcast with malformed extra from " << src
                   << ": " << parsed_extra_r.move_as_error();
      return;
    }
    auto parsed_extra = parsed_extra_r.move_as_ok();

    // Same `.at(src)` throw vector as on_overlay_message. The precheck
    // already rejects unknown src, but defense-in-depth here is cheap.
    auto peer_it = short_id_to_peer_.find(src);
    if (peer_it == short_id_to_peer_.end()) {
      LOG(WARNING) << "private-overlay: dropping broadcast from unknown short_id src " << src;
      return;
    }

    auto& bus = *owning_bus();
    auto peer = peer_it->second;
    // Clone raw bytes before the deserialize call so they remain available
    // for the MisbehaviorReport if parsing fails (V-025).
    auto raw_bytes = data.clone();
    auto maybe_candidate = Candidate::deserialize(std::move(data), bus, peer.idx, parsed_extra->slot_);

    if (maybe_candidate.is_error()) {
      auto error_str = maybe_candidate.move_as_error().to_string();
      LOG(WARNING) << "MISBEHAVIOR: Failed to deserialize block candidate broadcast from "
                   << src << ": " << error_str;
      auto proof = simplex::MalformedBroadcast::create(std::move(raw_bytes), peer.idx, std::move(error_str));
      owning_bus().publish<MisbehaviorReport>(peer.idx, proof);
      return;
    }
    auto candidate = maybe_candidate.move_as_ok();
    if (!candidate->is_empty()) {
      const auto& block = std::get<BlockCandidate>(candidate->block);
      td::actor::send_closure(bus.manager, &ManagerFacade::cache_block_candidate, block.clone());
    }
    owning_bus().publish<CandidateReceived>(std::move(candidate));
  }

  td::actor::Task<> precheck_broadcast(PublicKeyHash src, td::Bits256 broadcast_id, td::BufferSlice extra,
                                       bool signature_checked) {
    if (owning_bus()->config.enable_block_sync()) {
      co_return td::Status::Error("Precheck failed: candidate broadcasts use the block-sync overlay");
    }
    auto parsed_extra = fetch_tl_object<tos_api::consensus_broadcastExtra>(extra, true);
    if (parsed_extra.is_error()) {
      co_return parsed_extra.move_as_error_prefix("Precheck failed: Failed to parse broadcast extra: ");
    }

    auto& bus = *owning_bus();
    // Bare `.at(src)` throws if the src is not in the overlay membership map.
    // Return a structured error.
    auto peer_it = short_id_to_peer_.find(src);
    if (peer_it == short_id_to_peer_.end()) {
      co_return td::Status::Error("Precheck failed: src is not in private overlay membership");
    }
    auto peer = peer_it->second.idx;
    td::uint32 slot = parsed_extra.move_as_ok()->slot_;
    if (peer != bus.collator_schedule->expected_collator_for(slot)) {
      co_return td::Status::Error("Precheck failed: Broadcast is not from the expected collator");
    }

    co_return co_await owning_bus()
        .publish<PrecheckCandidateBroadcast>(slot, broadcast_id, signature_checked)
        .trace("Precheck failed");
  }

  void on_query(adnl::AdnlNodeIdShort src, td::BufferSlice data, td::Promise<td::BufferSlice> promise) {
    if (!overlay_nodes_.contains(src)) {
      LOG(WARNING) << "private-overlay: dropping query from non-member adnl src " << src;
      promise.set_value(create_serialize_tl_object<tl::requestError>());
      return;
    }
    auto it = adnl_id_to_peer_.find(src);
    auto source_validator =
        it == adnl_id_to_peer_.end() ? std::optional<PeerValidatorId>{} : std::optional{it->second.idx};
    auto request = std::make_shared<IncomingOverlayRequest>(source_validator, src, std::move(data));

    auto task = [](BusHandle bus, auto message, auto promise) -> td::actor::Task<> {
      auto response = co_await bus.publish(message).wrap();
      if (response.is_ok()) {
        promise.set_value(response.move_as_ok().data);
      } else {
        LOG(WARNING) << "Failed to process overlay request from " << message->source << ": "
                     << response.move_as_error();
        promise.set_value(create_serialize_tl_object<tl::requestError>());
      }
      co_return td::Unit{};
    };
    task(owning_bus(), request, std::move(promise)).start().detach();
  }

  td::actor::ActorId<overlay::Overlays> overlays_;
  td::actor::ActorId<adnl::AdnlSenderEx> adnl_sender_;
  overlay::OverlayIdShort overlay_id_;
  adnl::AdnlNodeIdShort local_adnl_id_;
  std::set<adnl::AdnlNodeIdShort> overlay_nodes_;
  std::vector<adnl::AdnlNodeIdShort> other_overlay_nodes_;
  std::map<adnl::AdnlNodeIdShort, PeerValidator> adnl_id_to_peer_;
  std::map<PublicKeyHash, PeerValidator> short_id_to_peer_;

  std::mt19937 gossip_rng_{td::Random::fast_uint32()};

  // Broadcast deduplication state (V-021).
  NewConsensusConfig::NoncriticalParams params_;
  td::uint32 slots_per_leader_window_ = 1;
  td::uint32 first_nonfinalized_slot_ = 0;
  std::map<td::uint32, td::Bits256> seen_broadcasts_;
};

}  // namespace

void PrivateOverlay::register_in(td::actor::Runtime& runtime) {
  runtime.register_actor<PrivateOverlayImpl>("PrivateOverlay");
}

}  // namespace tos::validator::consensus
