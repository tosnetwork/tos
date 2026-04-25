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
#pragma once

#include "overlay/overlay.h"
#include "rldp2/rldp.h"
#include "td/actor/actor.h"

#include "NodeActor.h"

namespace tos_rldp = tos::rldp2;

class PeerManager : public td::actor::Actor {
 public:
  PeerManager(tos::adnl::AdnlNodeIdShort adnl_id, tos::overlay::OverlayIdFull overlay_id, bool client_mode,
              td::actor::ActorId<tos::overlay::Overlays> overlays, td::actor::ActorId<tos::adnl::Adnl> adnl,
              td::actor::ActorId<tos_rldp::Rldp> rldp)
      : overlay_id_(std::move(overlay_id))
      , client_mode_(client_mode)
      , overlays_(std::move(overlays))
      , adnl_(std::move(adnl))
      , rldp_(std::move(rldp)) {
    CHECK(register_adnl_id(adnl_id) == 1);
  }
  void start_up() override {
  }
  void tear_down() override {
    for (const auto& p : subscribed_peers_) {
      if (p.second > 0) {
        auto adnl_id = peer_to_andl(p.first);
        if (adnl_id.is_ok()) {
          send_closure(overlays_, &tos::overlay::Overlays::delete_overlay, adnl_id.move_as_ok(),
                       overlay_id_.compute_short_id());
        }
      }
    }
  }
  void send_query(tos::PeerId src, tos::PeerId dst, td::BufferSlice query, td::Promise<td::BufferSlice> promise) {
    TRY_RESULT_PROMISE(promise, src_id, peer_to_andl(src));
    TRY_RESULT_PROMISE(promise, dst_id, peer_to_andl(dst));
    send_closure(overlays_, &tos::overlay::Overlays::send_query_via, dst_id, src_id, overlay_id_.compute_short_id(), "",
                 std::move(promise), td::Timestamp::in(10), std::move(query), 1 << 25, rldp_);
  }

  void execute_query(tos::adnl::AdnlNodeIdShort src, tos::adnl::AdnlNodeIdShort dst, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) {
    auto src_id = register_adnl_id(src);
    auto dst_id = register_adnl_id(dst);
    auto it = peers_.find(std::make_pair(dst_id, src_id));
    if (it == peers_.end()) {
      auto node_it = nodes_.find(dst_id);
      if (node_it == nodes_.end()) {
        LOG(ERROR) << "Unknown query destination";
        promise.set_error(td::Status::Error("Unknown query destination"));
        return;
      }
      if (!node_it->second.is_alive()) {
        LOG(ERROR) << "Expired query destination";
        promise.set_error(td::Status::Error("Unknown query destination"));
        return;
      }
      send_closure(node_it->second, &tos::NodeActor::start_peer, src_id,
                   [promise = std::move(promise),
                    data = std::move(data)](td::Result<td::actor::ActorId<tos::PeerActor>> r_peer) mutable {
                     TRY_RESULT_PROMISE(promise, peer, std::move(r_peer));
                     send_closure(peer, &tos::PeerActor::execute_query, std::move(data), std::move(promise));
                   });
      return;
    }
    send_closure(it->second, &tos::PeerActor::execute_query, std::move(data), std::move(promise));
  }

  void register_peer(tos::PeerId src, tos::PeerId dst, td::actor::ActorId<tos::PeerActor> peer) {
    peers_[std::make_pair(src, dst)] = std::move(peer);
    register_src(src, [](td::Result<td::Unit> res) { res.ensure(); });
  }

  void register_node(tos::PeerId src, td::actor::ActorId<tos::NodeActor> node) {
    nodes_[src] = std::move(node);
    register_src(src, [](td::Result<td::Unit> res) { res.ensure(); });
  }

  void unregister_node(tos::PeerId src, td::actor::ActorId<tos::NodeActor> node) {
    auto it = nodes_.find(src);
    CHECK(it != nodes_.end());
    if (it->second == node) {
      nodes_.erase(it);
    }
    unregister_src(src, [](td::Result<td::Unit> res) { res.ensure(); });
  }

  void unregister_peer(tos::PeerId src, tos::PeerId dst, td::actor::ActorId<tos::PeerActor> peer) {
    auto it = peers_.find(std::make_pair(src, dst));
    CHECK(it != peers_.end());
    if (it->second == peer) {
      peers_.erase(it);
    }
    unregister_src(src, [](td::Result<td::Unit> res) { res.ensure(); });
  }

  void unregister_src(tos::PeerId src, td::Promise<td::Unit> promise) {
    TRY_RESULT_PROMISE(promise, src_id, peer_to_andl(src));
    if (--subscribed_peers_[src] == 0) {
      subscribed_peers_.erase(src);
      send_closure(overlays_, &tos::overlay::Overlays::delete_overlay, src_id, overlay_id_.compute_short_id());
    }
    promise.set_value({});
  }
  void register_src(tos::PeerId src, td::Promise<td::Unit> promise) {
    TRY_RESULT_PROMISE(promise, src_id, peer_to_andl(src));
    if (subscribed_peers_[src]++ == 0) {
      auto rules = tos::overlay::OverlayPrivacyRules{};
      class Callback : public tos::overlay::Overlays::Callback {
       public:
        explicit Callback(td::actor::ActorId<PeerManager> peer_manager, tos::adnl::AdnlNodeIdShort dst)
            : peer_manager_(std::move(peer_manager)), dst_(dst) {
        }
        void receive_message(tos::adnl::AdnlNodeIdShort src, tos::overlay::OverlayIdShort overlay_id,
                             td::BufferSlice data) override {
        }
        void receive_query(tos::adnl::AdnlNodeIdShort src, tos::overlay::OverlayIdShort overlay_id,
                           td::BufferSlice data, td::Promise<td::BufferSlice> promise) override {
          td::actor::send_closure(peer_manager_, &PeerManager::execute_query, src, dst_, std::move(data),
                                  std::move(promise));
        }
        void receive_broadcast(tos::PublicKeyHash src, tos::overlay::OverlayIdShort overlay_id,
                               td::BufferSlice data) override {
        }

       private:
        td::actor::ActorId<PeerManager> peer_manager_;
        tos::adnl::AdnlNodeIdShort dst_;
      };
      tos::overlay::OverlayOptions opts;
      opts.announce_self_ = !client_mode_;
      opts.frequent_dht_lookup_ = true;
      send_closure(overlays_, &tos::overlay::Overlays::create_public_overlay_ex, src_id, overlay_id_.clone(),
                   std::make_unique<Callback>(actor_id(this), src_id), rules, R"({ "type": "storage" })", opts);
    }
    promise.set_value({});
  }

  td::Result<tos::adnl::AdnlNodeIdShort> peer_to_andl(tos::PeerId id) {
    if (id <= 0 || id > adnl_ids_.size()) {
      return td::Status::Error(PSLICE() << "Invalid peer id " << id);
    }
    return adnl_ids_[id - 1];
  }

  tos::PeerId register_adnl_id(tos::adnl::AdnlNodeIdShort id) {
    auto it = adnl_to_peer_id_.emplace(id, next_peer_id_);
    if (it.second) {
      adnl_ids_.push_back(id);
      next_peer_id_++;
    }
    return it.first->second;
  }

  void get_peers(tos::PeerId src, td::Promise<std::vector<tos::PeerId>> promise) {
    TRY_RESULT_PROMISE(promise, src_id, peer_to_andl(src));
    send_closure(overlays_, &tos::overlay::Overlays::get_overlay_random_peers, src_id, overlay_id_.compute_short_id(),
                 30, promise.send_closure(actor_id(this), &PeerManager::got_overlay_random_peers));
  }

  void get_peer_info(tos::PeerId src, tos::PeerId peer, td::Promise<std::pair<td::Bits256, std::string>> promise) {
    TRY_RESULT_PROMISE(promise, src_id, peer_to_andl(src));
    TRY_RESULT_PROMISE(promise, peer_id, peer_to_andl(peer));
    td::actor::send_closure(
        adnl_, &tos::adnl::Adnl::get_conn_ip_str, src_id, peer_id,
        promise.wrap([peer_id](std::string s) { return std::make_pair(peer_id.bits256_value(), std::move(s)); }));
  }

  static td::unique_ptr<tos::NodeActor::NodeCallback> create_callback(td::actor::ActorId<PeerManager> peer_manager) {
    class Context : public tos::NodeActor::NodeCallback {
     public:
      Context(td::actor::ActorId<PeerManager> peer_manager) : peer_manager_(peer_manager) {
      }
      void get_peers(tos::PeerId src, td::Promise<std::vector<tos::PeerId>> promise) override {
        send_closure(peer_manager_, &PeerManager::get_peers, src, std::move(promise));
      }
      void register_self(td::actor::ActorId<tos::NodeActor> self) override {
        CHECK(self_.empty());
        self_ = self;
        send_closure(peer_manager_, &PeerManager::register_node, 1, self_);
      }
      ~Context() override {
        if (!self_.empty()) {
          send_closure(peer_manager_, &PeerManager::unregister_node, 1, self_);
        }
      }
      td::actor::ActorOwn<tos::PeerActor> create_peer(tos::PeerId self_id, tos::PeerId peer_id,
                                                      std::shared_ptr<tos::PeerState> state) override {
        CHECK(self_id == 1);
        class PeerCallback : public tos::PeerActor::Callback {
         public:
          PeerCallback(tos::PeerId self_id, tos::PeerId peer_id, td::actor::ActorId<PeerManager> peer_manager)
              : self_id_(self_id), peer_id_(peer_id), peer_manager_(std::move(peer_manager)) {
          }
          void register_self(td::actor::ActorId<tos::PeerActor> self) override {
            CHECK(self_.empty());
            self_ = std::move(self);
            send_closure(peer_manager_, &PeerManager::register_peer, self_id_, peer_id_, self_);
          }
          void send_query(td::uint64 query_id, td::BufferSlice query) override {
            send_closure(peer_manager_, &PeerManager::send_query, self_id_, peer_id_, std::move(query),
                         promise_send_closure(self_, &tos::PeerActor::on_query_result, query_id));
          }

          ~PeerCallback() {
            if (!self_.empty()) {
              send_closure(peer_manager_, &PeerManager::unregister_peer, self_id_, peer_id_, self_);
            }
          }

         private:
          td::actor::ActorId<tos::PeerActor> self_;
          tos::PeerId self_id_;
          tos::PeerId peer_id_;
          td::actor::ActorId<PeerManager> peer_manager_;
        };
        return td::actor::create_actor<tos::PeerActor>(PSLICE() << "PeerActor " << peer_id,
                                                       td::make_unique<PeerCallback>(self_id, peer_id, peer_manager_),
                                                       std::move(state));
      }

      void get_peer_info(tos::PeerId src, tos::PeerId peer,
                         td::Promise<std::pair<td::Bits256, std::string>> promise) override {
        td::actor::send_closure(peer_manager_, &PeerManager::get_peer_info, src, peer, std::move(promise));
      }

     private:
      td::actor::ActorId<PeerManager> peer_manager_;
      std::vector<tos::PeerId> peers_;
      td::actor::ActorId<tos::NodeActor> self_;
    };
    return td::make_unique<Context>(std::move(peer_manager));
  }

 private:
  tos::overlay::OverlayIdFull overlay_id_;
  bool client_mode_ = false;
  td::actor::ActorId<tos::overlay::Overlays> overlays_;
  td::actor::ActorId<tos::adnl::Adnl> adnl_;
  td::actor::ActorId<tos_rldp::Rldp> rldp_;

  std::map<std::pair<tos::PeerId, tos::PeerId>, td::actor::ActorId<tos::PeerActor>> peers_;
  std::map<tos::PeerId, td::actor::ActorId<tos::NodeActor>> nodes_;
  tos::PeerId next_peer_id_{1};
  std::map<tos::adnl::AdnlNodeIdShort, tos::PeerId> adnl_to_peer_id_;
  std::vector<tos::adnl::AdnlNodeIdShort> adnl_ids_;

  std::map<tos::PeerId, td::uint32> subscribed_peers_;

  void got_overlay_random_peers(td::Result<std::vector<tos::adnl::AdnlNodeIdShort>> r_peers,
                                td::Promise<std::vector<tos::PeerId>> promise) {
    TRY_RESULT_PROMISE(promise, peers, std::move(r_peers));

    std::vector<tos::PeerId> res;
    for (auto peer : peers) {
      res.push_back(register_adnl_id(peer));
    }

    promise.set_value(std::move(res));
  }
};
