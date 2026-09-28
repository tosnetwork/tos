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

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#include <cstdio>

#include "adnl/adnl-test-loopback-implementation.h"
#include "adnl/adnl.h"
#include "common/errorlog.h"
#include "keyring/keyring.h"
#include "overlay/overlay-manager.h"
#include "overlay/overlay.hpp"
#include "td/db/RocksDb.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "test/plumtree/scheduler.h"
#include "test/plumtree/transport.h"

namespace tos::overlay {
class OverlayImplPlumtreePolicyTest {
 public:
  static void admit(OverlayImpl &overlay, OverlayNode node) {
    overlay.add_peer(std::move(node), true);
  }
  static PlumtreeRepairDiagnostics diagnostics(OverlayImpl &overlay) {
    return overlay.broadcasts_plumtree_.repair_diagnostics_for_test();
  }
  static td::uint32 flags(OverlayImpl &overlay) {
    // Discovery is covered by DHT tests; this test supplies verified peers directly.
    overlay.next_dht_query_ = td::Timestamp::never();
    return overlay.peer_list_.local_member_flags_;
  }
};
class PolicyOverlay : public OverlayImpl {
 public:
  using OverlayImpl::OverlayImpl;
  void admit(OverlayNode node) {
    OverlayImplPlumtreePolicyTest::admit(*this, std::move(node));
  }
  void diagnostics(td::Promise<PlumtreeRepairDiagnostics> promise) {
    promise.set_value(OverlayImplPlumtreePolicyTest::diagnostics(*this));
  }
  void check_flags(td::uint32 expected) {
    CHECK(OverlayImplPlumtreePolicyTest::flags(*this) == expected);
  }
};
}  // namespace tos::overlay

class PolicySender : public tos::overlay::plumtree_sim::SimulatedSender {
 public:
  using SimulatedSender::SimulatedSender;
  void check_receive_budget(tos::adnl::AdnlNodeIdShort local, tos::adnl::AdnlNodeIdShort peer, bool large) {
    CHECK(large ? get_peer_mtu(local, peer) > 1024 : get_peer_mtu(local, peer) == 1024);
  }
  void check_shared_budget(tos::adnl::AdnlNodeIdShort local, tos::adnl::AdnlNodeIdShort peer) {
    add_peer_mtu(local, peer, 8192);
    add_peer_mtu(local, peer, 8192);
    remove_peer_mtu(local, peer, 8192);
    CHECK(get_peer_mtu(local, peer) == 8192);
    remove_peer_mtu(local, peer, 8192);
    CHECK(get_peer_mtu(local, peer) == 1024);
  }
};

// Three real overlay actors and real signing/forwarding/repair paths. The
// transport is deterministic and records every attempted wire delivery.
TEST(Overlay, PublicPlumtreeSourcesAndObserver) {
  using namespace tos;
  using namespace tos::overlay;
  using namespace tos::overlay::plumtree_sim;
  auto db = td::mkdtemp("/tmp", "overlay-policy").move_as_ok();
  auto network = std::make_shared<SimNetwork>();
  network->base_time = td::Time::now();
  network->geo_alpha_ms = 1;
  network->geo_beta_ms_per_km = 0;
  network->jitter = 0;
  network->geo_by_node.resize(3);
  network->sent_bytes_by_node.resize(3);
  network->received_bytes_by_node.resize(3);
  network->tx_free_at_by_node.resize(3);
  network->rx_free_at_by_node.resize(3);
  auto delivery = std::make_shared<DeliveryState>(3);
  td::actor::ActorOwn<keyring::Keyring> keyring;
  td::actor::ActorOwn<adnl::TestLoopbackNetworkManager> net;
  td::actor::ActorOwn<adnl::Adnl> adnl;
  td::actor::ActorOwn<PolicySender> sender;
  td::actor::ActorOwn<OverlayManager> manager;
  td::actor::Scheduler scheduler({0}, true);
  std::vector<PrivateKey> keys;
  std::vector<adnl::AdnlNodeIdShort> ids;
  std::vector<td::actor::ActorId<PolicyOverlay>> actors;
  auto full = create_serialize_tl_object<tos_api::pub_overlay>(td::BufferSlice("public-plumtree-policy"));
  auto overlay_id = OverlayIdFull{full.clone()}.compute_short_id();
  scheduler.run_in_context([&] {
    errorlog::ErrorLog::create(db);
    keyring = keyring::Keyring::create(db);
    net = td::actor::create_actor<adnl::TestLoopbackNetworkManager>("policy net");
    adnl = adnl::Adnl::create(db, keyring.get());
    sender = td::actor::create_actor<PolicySender>("policy sender", network);
    td::actor::send_closure(sender, &adnl::AdnlSenderEx::set_default_mtu, 1024);
    td::actor::send_closure(adnl, &adnl::Adnl::register_network_manager, net.get());
    auto address = adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();
    for (size_t i = 0; i < 3; ++i) {
      keys.emplace_back(privkeys::Ed25519::random());
      ids.emplace_back(keys.back().compute_public_key().compute_short_id());
      network->node_by_adnl[ids.back()] = i;
      td::actor::send_closure(keyring, &keyring::Keyring::add_key, keys.back(), true, [](td::Result<>) {});
      td::actor::send_closure(adnl, &adnl::Adnl::add_id, adnl::AdnlNodeIdFull{keys.back().compute_public_key()},
                              address, static_cast<td::uint8>(0));
      td::actor::send_closure(net, &adnl::TestLoopbackNetworkManager::add_node_id, ids.back(), true, true);
    }
    {
      auto cache = td::RocksDb::open(db + "/overlays").move_as_ok();
      auto cache_key =
          create_hash_tl_object<tos_api::overlay_db_key_nodes>(ids[0].bits256_value(), overlay_id.bits256_value());
      cache.set(cache_key.as_slice(), "obsolete overlay discovery cache").ensure();
    }
    manager = td::actor::create_actor<OverlayManager>("policy overlays", db, keyring.get(), adnl.get(),
                                                      td::actor::ActorId<dht::Dht>{});
    network->overlay_manager = manager.get();
    std::map<PublicKeyHash, td::uint32> authorized;
    for (auto &key : keys)
      authorized[key.compute_short_id()] = Overlays::max_fec_broadcast_size();
    OverlayPrivacyRules rules{Overlays::max_fec_broadcast_size(), CertificateFlags::AllowFec, authorized};
    for (size_t i = 0; i < 3; ++i) {
      OverlayOptions opts;
      opts.enable_plumtree_broadcast_ = true;
      opts.plumtree_broadcast_sender_ = sender.get();
      opts.is_original_sender_ = i < 2;
      opts.max_neighbours_ = 2;
      auto own = td::actor::create_actor<PolicyOverlay>(
          "policy overlay", keyring.get(), adnl.get(), manager.get(), td::actor::ActorId<dht::Dht>{}, ids[i],
          OverlayIdFull{full.clone()}, OverlayType::Public, std::vector<adnl::AdnlNodeIdShort>{},
          std::vector<PublicKeyHash>{}, OverlayMemberCertificate{}, std::make_unique<DeliveryCallback>(delivery, i),
          rules, "policy-test", opts);
      actors.push_back(own.get());
      td::actor::send_closure(manager, &OverlayManager::register_overlay, ids[i], overlay_id,
                              OverlayMemberCertificate{}, std::move(own));
    }
    for (size_t i = 0; i < 3; ++i) {
      td::actor::send_closure(actors[i], &PolicyOverlay::check_flags, i < 2 ? 2u : 0u);
      for (size_t j = 0; j < 3; ++j)
        if (i != j) {
          td::actor::send_closure(adnl, &adnl::Adnl::add_peer, ids[i],
                                  adnl::AdnlNodeIdFull{keys[j].compute_public_key()}, address);
          OverlayNode node{adnl::AdnlNodeIdFull{keys[j].compute_public_key()}, overlay_id, j < 2 ? 2u : 0u,
                           static_cast<td::int32>(td::Clocks::system()), td::Slice{}};
          node.update_signature(
              keys[j].create_decryptor().move_as_ok()->sign(node.to_sign().as_slice()).move_as_ok().as_slice());
          td::actor::send_closure(actors[i], &PolicyOverlay::admit, std::move(node));
        }
    }
  });
  pump_scheduler(scheduler, 64);
  size_t payloads_to_sources = 0, payloads_to_observer = 0, repairs = 0;
  auto pump = [&](double seconds) {
    auto end = td::Time::now() + seconds;
    for (size_t n = 0; n < 2000 && td::Time::now() < end; ++n) {
      pump_scheduler(scheduler);
      auto next = network->next_event_time();
      double target = next ? network->base_time + next.value() : td::Time::now() + 0.05;
      td::Time::jump_in_future(std::min(end, std::max(td::Time::now(), target)));
      auto events = network->pop_due_events(network->now_s());
      scheduler.run_in_context([&] {
        for (auto &event : events) {
          if (event.kind == SimEventKind::Message) {
            td::Slice data = event.data.as_slice();
            fetch_tl_prefix<tos_api::overlay_message>(data, true).ensure();
            auto bytes = data.ubegin();
            auto type = static_cast<td::int32>(
                static_cast<td::uint32>(bytes[0]) | (static_cast<td::uint32>(bytes[1]) << 8) |
                (static_cast<td::uint32>(bytes[2]) << 16) | (static_cast<td::uint32>(bytes[3]) << 24));
            if (type == tos_api::overlay_broadcastPlumtreeSimple::ID ||
                type == tos_api::overlay_broadcastPlumtreeFec::ID ||
                type == tos_api::overlay_broadcastPlumtreeIHave::ID) {
              if (event.dst == ids[2])
                ++payloads_to_observer;
              else
                ++payloads_to_sources;
            }
            td::actor::send_closure(manager, &OverlayManager::receive_message, event.src, event.dst,
                                    std::move(event.data));
          } else if (event.kind == SimEventKind::Query) {
            ++repairs;
            td::actor::send_closure(manager, &OverlayManager::receive_query, event.src, event.dst,
                                    std::move(event.data), std::move(event.promise));
          } else {
            event.promise.set_value(std::move(event.data));
          }
        }
      });
    }
    pump_scheduler(scheduler, 64);
  };
  // A seeds the observer's eager upstream; B then exercises forwarding toward A.
  for (int mode = 0; mode < 2; ++mode) {
    for (size_t origin : {0u, 1u}) {
      td::BufferSlice payload(8000);
      payload.as_slice().fill(static_cast<char>('a' + mode * 2 + origin));
      auto hash = td::sha256_bits256(payload.as_slice());
      delivery->start_broadcast(hash, {false, false, true}, td::Time::now());
      scheduler.run_in_context([&] {
        if (mode == 0) {
          td::actor::send_closure(manager, &Overlays::send_broadcast_plumtree, ids[origin], overlay_id,
                                  keys[origin].compute_short_id(), 0, hash, std::move(payload));
        } else {
          td::actor::send_closure(manager, &Overlays::send_broadcast_plumtree_fec, ids[origin], overlay_id,
                                  keys[origin].compute_short_id(), 0, std::move(payload));
        }
      });
      pump(3);
      ASSERT_EQ(delivery->expected_remaining_count(), 0u);
      ASSERT_EQ(payloads_to_sources, 0u);
      scheduler.run_in_context([&] {
        // A source-only peer is still our upstream; its inbound grant must remain.
        td::actor::send_closure(sender, &PolicySender::check_receive_budget, ids[2], ids[origin], true);
        td::actor::send_closure(sender, &PolicySender::check_receive_budget, ids[origin], ids[2], false);
      });
      pump_scheduler(scheduler);
    }
  }
  PlumtreeRepairDiagnostics observer_diagnostics;
  bool got_diagnostics = false;
  scheduler.run_in_context([&] {
    td::actor::send_closure(actors[2], &PolicyOverlay::diagnostics,
                            td::PromiseCreator::lambda([&](td::Result<PlumtreeRepairDiagnostics> result) {
                              observer_diagnostics = result.move_as_ok();
                              got_diagnostics = true;
                            }));
  });
  pump_scheduler(scheduler, 64);
  ASSERT_TRUE(got_diagnostics);
  std::printf(
      "Three-actor delivery workload: observer_deliveries=4 ihave_immediate_checks=%llu ihave_repair_checks=%llu\n",
      static_cast<unsigned long long>(observer_diagnostics.immediate_checks),
      static_cast<unsigned long long>(observer_diagnostics.deferred_checks));
  ASSERT_TRUE(payloads_to_observer > 0);
  ASSERT_TRUE(repairs > 0);
  scheduler.run_in_context(
      [&] { td::actor::send_closure(sender, &PolicySender::check_shared_budget, ids[0], ids[1]); });
  pump_scheduler(scheduler);
  // Ordinary transaction-style broadcasts still reach both publishing nodes.
  for (bool fec : {false, true}) {
    td::BufferSlice ordinary(fec ? 8000 : 700);
    ordinary.as_slice().fill(fec ? 'f' : 't');
    delivery->start_broadcast(td::sha256_bits256(ordinary.as_slice()), {true, true, true}, td::Time::now());
    scheduler.run_in_context([&] {
      if (fec) {
        td::actor::send_closure(manager, &Overlays::send_broadcast_fec_ex, ids[2], overlay_id,
                                keys[2].compute_short_id(), 0, std::move(ordinary));
      } else {
        td::actor::send_closure(manager, &Overlays::send_broadcast_ex, ids[2], overlay_id, keys[2].compute_short_id(),
                                0, std::move(ordinary));
      }
    });
    pump(3);
    ASSERT_EQ(delivery->expected_remaining_count(), 0u);
  }
  auto scrape = [&] {
    std::optional<metrics::MetricSet> set;
    scheduler.run_in_context([&] {
      td::actor::send_closure(
          manager, &Overlays::collect,
          td::PromiseCreator::lambda([&](td::Result<metrics::MetricSet> result) { set = result.move_as_ok(); }));
    });
    pump_scheduler(scheduler, 64);
    CHECK(set.has_value());
    return std::move(*set);
  };
  auto value = [](const metrics::MetricSet &set, const std::string &name, const std::string &direction) {
    double total = 0;
    for (const auto &family : set.families)
      if (family.name == name) {
        for (const auto &metric : family.metrics) {
          bool matches = false;
          for (const auto &label : metric.label_set.labels)
            matches |= label.key == "direction" && label.val == direction;
          if (matches)
            for (const auto &sample : metric.samples)
              total += sample.value;
        }
      }
    return total;
  };
  auto first_scrape = scrape();
  // Four Plumtree broadcasts deliver both to their local origin and the observer;
  // each ordinary broadcast delivers to all three actors (8*8000 + 3*(700+8000)).
  CHECK(value(first_scrape, "overlay_broadcast_bytes_total", "in") == 90100);
  CHECK(value(first_scrape, "overlay_broadcast_bytes_total", "out") == 40700);
  CHECK(value(first_scrape, "overlay_broadcast_messages_total", "in") == 14);
  auto repeat_scrape = scrape();
  CHECK(value(repeat_scrape, "overlay_broadcast_bytes_total", "in") == 90100);
  // An overlay removed before its next scrape must flush its remaining delta once.
  auto last_payload = create_serialize_tl_object<tos_api::dht_ping>(42);
  auto last_size = static_cast<double>(last_payload.size());
  scheduler.run_in_context([&] {
    td::actor::send_closure(actors[2], &OverlayImpl::deliver_broadcast, keys[0].compute_short_id(),
                            std::move(last_payload), td::BufferSlice{});
  });
  pump_scheduler(scheduler, 64);
  scheduler.run_in_context([&] { td::actor::send_closure(manager, &Overlays::delete_overlay, ids[2], overlay_id); });
  pump_scheduler(scheduler, 64);
  auto after_removal = scrape();
  CHECK(value(after_removal, "overlay_broadcast_bytes_total", "in") == 90100 + last_size);
  CHECK(value(after_removal, "overlay_broadcast_messages_total", "in") == 15);
  // Outgoing counters describe attempts, even if the addressed overlay no longer exists.
  scheduler.run_in_context([&] {
    auto payload = create_serialize_tl_object<tos_api::dht_ping>(42);
    td::actor::send_closure(manager, &Overlays::send_broadcast_ex, ids[2], overlay_id, keys[2].compute_short_id(), 0,
                            payload.clone());
    td::actor::send_closure(manager, &Overlays::send_broadcast_fec_ex, ids[2], overlay_id, keys[2].compute_short_id(),
                            0, payload.clone());
    td::actor::send_closure(manager, &Overlays::send_broadcast_plumtree_fec, ids[2], overlay_id,
                            keys[2].compute_short_id(), 0, payload.clone());
    td::actor::send_closure(manager, &Overlays::send_broadcast_plumtree, ids[2], overlay_id, keys[2].compute_short_id(),
                            0, td::Bits256::zero(), payload.clone());
  });
  pump_scheduler(scheduler, 64);
  auto after_attempts = scrape();
  CHECK(value(after_attempts, "overlay_broadcast_bytes_total", "out") == 40700 + 4 * last_size);
  CHECK(value(after_attempts, "overlay_broadcast_bytes_total", "in") == 90100 + last_size);
  scheduler.run_in_context([&] {
    manager.reset();
    sender.reset();
    adnl.reset();
    net.reset();
    keyring.reset();
  });
  pump_scheduler(scheduler, 64);
  network->overlay_manager = {};
  actors.clear();
  td::rmrf(db).ensure();
}
