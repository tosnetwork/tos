/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include <map>
#include <limits>
#include <vector>

#include "adnl/adnl-node-id.hpp"
#include "auto/tl/tos_api.h"
#include "overlay/overlays.h"
#include "td/utils/Status.h"
#include "td/utils/logging.h"

#include "bus.h"
#include "simplex/misbehavior.h"

namespace tos::validator::consensus {

namespace tl {

using blockSyncOverlayId = tos_api::consensus_blockSyncOverlayId;
using broadcastExtra = tos_api::consensus_broadcastExtra;

}  // namespace tl

namespace {

class BlockSyncOverlayImpl : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  static bool should_be_spawned(const Bus& bus) {
    return bus.config.enable_block_sync();
  }

  void start_up() override {
    auto& bus = *owning_bus();
    overlays_ = bus.overlays;
    local_adnl_id_ = bus.local_id.adnl_id;
    adnl_sender_ = bus.adnl_sender;

    std::vector<adnl::AdnlNodeIdShort> overlay_nodes;
    std::map<PublicKeyHash, td::uint32> authorized_keys;
    const td::uint64 max_broadcast_size_wide = static_cast<td::uint64>(bus.config.max_block_size) +
                                               bus.config.max_collated_data_size + (1U << 20);
    LOG_CHECK(max_broadcast_size_wide <= std::numeric_limits<td::uint32>::max())
        << "Configured block-sync broadcast limit overflows uint32";
    const td::uint32 max_broadcast_size = static_cast<td::uint32>(max_broadcast_size_wide);
    for (const auto& peer : bus.validator_set) {
      overlay_nodes.push_back(peer.adnl_id);
      adnl_pubkey_to_peer_.emplace(peer.adnl_id.pubkey_hash(), peer);
      authorized_keys.emplace(peer.adnl_id.pubkey_hash(), max_broadcast_size);
    }

    td::actor::send_closure(adnl_sender_, &adnl::AdnlSenderEx::add_id, local_adnl_id_);

    auto overlay_seed = create_tl_object<tl::blockSyncOverlayId>(bus.session_id);
    auto overlay_full_id = overlay::OverlayIdFull{serialize_tl_object(overlay_seed, true)};
    overlay_id_ = overlay_full_id.compute_short_id();

    overlay::OverlayOptions options;
    options.name_ = PSTRING() << "blocksync" << bus.shard.to_str() << "." << bus.cc_seqno;
    options.private_ping_peers_ = true;
    options.twostep_broadcast_sender_ = adnl_sender_;
    options.send_twostep_broadcast_ = true;
    options.allow_old_broadcasts_ = false;

    td::actor::send_closure(overlays_, &overlay::Overlays::create_private_overlay_ex, local_adnl_id_,
                            std::move(overlay_full_id), std::move(overlay_nodes), make_callback(),
                            overlay::OverlayPrivacyRules{0, 0, std::move(authorized_keys)},
                            PSTRING() << R"({ "type": "blocksync", "shard": ")" << bus.shard.to_str()
                                      << R"(", "cc_seqno": )" << bus.cc_seqno << R"( })",
                            std::move(options));
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const StopRequested>) {
    td::actor::send_closure(overlays_, &overlay::Overlays::delete_overlay, local_adnl_id_, overlay_id_);
    stop();
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const CandidateGenerated> event) {
    td::BufferSlice extra = create_serialize_tl_object<tl::broadcastExtra>(event->candidate->id.slot);
    td::actor::send_closure(overlays_, &overlay::Overlays::send_broadcast_fec_with_extra, local_adnl_id_, overlay_id_,
                            local_adnl_id_.pubkey_hash(), 0, event->candidate->serialize(), std::move(extra));
  }

 private:
  std::unique_ptr<overlay::Overlays::Callback> make_callback() {
    class Callback final : public overlay::Overlays::Callback {
     public:
      explicit Callback(td::actor::ActorId<BlockSyncOverlayImpl> owner) : owner_(owner) {
      }

      void receive_broadcast_with_extra(PublicKeyHash src, overlay::OverlayIdShort, td::BufferSlice data,
                                        td::BufferSlice extra) override {
        td::actor::send_closure(owner_, &BlockSyncOverlayImpl::on_overlay_broadcast, src, std::move(data),
                                std::move(extra));
      }

      void precheck_broadcast(PublicKeyHash src, overlay::OverlayIdShort, td::Bits256 broadcast_id,
                              td::BufferSlice extra, bool signature_checked, td::Promise<> promise) override {
        td::actor::send_closure(owner_, &BlockSyncOverlayImpl::precheck_broadcast, src, broadcast_id, std::move(extra),
                                signature_checked, std::move(promise));
      }

      void check_broadcast(PublicKeyHash, overlay::OverlayIdShort, td::BufferSlice,
                           td::Promise<td::Unit> promise) override {
        promise.set_value(td::Unit());
      }

     private:
      td::actor::ActorId<BlockSyncOverlayImpl> owner_;
    };

    return std::make_unique<Callback>(actor_id(this));
  }

  void on_overlay_broadcast(PublicKeyHash src, td::BufferSlice data, td::BufferSlice extra) {
    if (src == local_adnl_id_.pubkey_hash()) {
      return;
    }

    auto parsed_extra = fetch_tl_object<tl::broadcastExtra>(extra, true);
    if (parsed_extra.is_error()) {
      LOG(WARNING) << "block-sync overlay: malformed broadcast metadata from " << src << ": "
                   << parsed_extra.move_as_error();
      return;
    }

    auto& bus = *owning_bus();
    auto peer_it = adnl_pubkey_to_peer_.find(src);
    if (peer_it == adnl_pubkey_to_peer_.end()) {
      LOG(WARNING) << "block-sync overlay: broadcast from a non-validator " << src;
      return;
    }

    auto raw_bytes = data.clone();
    auto maybe_candidate =
        Candidate::deserialize(std::move(data), bus, peer_it->second.idx, parsed_extra.move_as_ok()->slot_);
    if (maybe_candidate.is_error()) {
      auto error = maybe_candidate.move_as_error().to_string();
      LOG(WARNING) << "MISBEHAVIOR: block-sync candidate from " << src << " is invalid: " << error;
      auto proof = simplex::MalformedBroadcast::create(std::move(raw_bytes), peer_it->second.idx, std::move(error));
      owning_bus().publish<MisbehaviorReport>(peer_it->second.idx, proof);
      return;
    }
    owning_bus().publish<CandidateReceived>(maybe_candidate.move_as_ok());
  }

  td::actor::Task<> precheck_broadcast(PublicKeyHash src, td::Bits256 broadcast_id, td::BufferSlice extra,
                                       bool signature_checked) {
    auto parsed_extra = fetch_tl_object<tl::broadcastExtra>(extra, true);
    if (parsed_extra.is_error()) {
      co_return parsed_extra.move_as_error_prefix("Precheck failed: failed to parse block-sync metadata: ");
    }

    auto& bus = *owning_bus();
    auto peer_it = adnl_pubkey_to_peer_.find(src);
    if (peer_it == adnl_pubkey_to_peer_.end()) {
      co_return td::Status::Error("Precheck failed: block-sync source is not a validator");
    }
    const td::uint32 slot = parsed_extra.move_as_ok()->slot_;
    if (peer_it->second.idx != bus.collator_schedule->expected_collator_for(slot)) {
      co_return td::Status::Error("Precheck failed: block-sync source is not the expected collator");
    }

    co_return co_await owning_bus()
        .publish<PrecheckCandidateBroadcast>(slot, broadcast_id, signature_checked)
        .trace("Block-sync precheck failed");
  }

  td::actor::ActorId<overlay::Overlays> overlays_;
  td::actor::ActorId<adnl::AdnlSenderEx> adnl_sender_;
  overlay::OverlayIdShort overlay_id_;
  adnl::AdnlNodeIdShort local_adnl_id_;
  std::map<PublicKeyHash, PeerValidator> adnl_pubkey_to_peer_;
};

}  // namespace

void BlockSyncOverlay::register_in(td::actor::Runtime& runtime) {
  runtime.register_actor<BlockSyncOverlayImpl>("BlockSyncOverlay");
}

}  // namespace tos::validator::consensus
