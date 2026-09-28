/* Copyright (c) 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <set>

#include "adnl/adnl-test-loopback-implementation.h"
#include "common/errorlog.h"
#include "keyring/keyring.h"
#include "overlay/overlay-manager.h"
#include "overlay/overlay.hpp"
#include "plumtree/scheduler.h"
#include "plumtree/transport.h"
#include "plumtree/util.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "tl-utils/tl-utils.hpp"

namespace tos::overlay {
class OverlayImplTwostepTest {
 public:
  static void add_non_permanent(OverlayImpl& overlay, OverlayNode node) {
    auto id = node.adnl_id_short();
    overlay.peer_list_.peers_.insert(id, OverlayPeer(std::move(node)));
    CHECK(overlay.peer_list_.peers_.get(id));
    CHECK(!overlay.is_persistent_node(id));
  }
  static BroadcastsTwostep& broadcasts(OverlayImpl& overlay) {
    return overlay.broadcasts_twostep_;
  }
};
class RelayOverlay : public OverlayImpl {
 public:
  using OverlayImpl::OverlayImpl;
  void check_predicate(OverlayNode non_permanent, adnl::AdnlNodeIdShort permanent, adnl::AdnlNodeIdShort absent,
                       bool permanent_selected) {
    OverlayImplTwostepTest::add_non_permanent(*this, std::move(non_permanent));
    CHECK(!is_twostep_intermediate_node(non_permanent_id_));
    CHECK(is_twostep_intermediate_node(permanent) == permanent_selected);
    CHECK(!is_twostep_intermediate_node(absent));
  }
  void set_non_permanent_id(adnl::AdnlNodeIdShort id) {
    non_permanent_id_ = id;
  }
  void check_frame(adnl::AdnlNodeIdShort source, td::BufferSlice frame, td::Promise<> promise) {
    check_frame_inner(source, std::move(frame), std::move(promise)).start().detach();
  }

 private:
  td::actor::Task<> check_frame_inner(adnl::AdnlNodeIdShort source, td::BufferSlice frame, td::Promise<> promise) {
    td::Slice data = frame.as_slice();
    fetch_tl_prefix<tos_api::overlay_message>(data, true).ensure();
    auto& broadcasts = OverlayImplTwostepTest::broadcasts(*this);
    td::Result<> result;
    if (auto simple = fetch_tl_object<tos_api::overlay_broadcastTwostepSimple>(data, true); simple.is_ok()) {
      result = co_await broadcasts.process_broadcast(this, source, simple.move_as_ok()).wrap();
    } else {
      result = co_await broadcasts
                   .process_broadcast(this, source,
                                      fetch_tl_object<tos_api::overlay_broadcastTwostepFec>(data, true).move_as_ok())
                   .wrap();
    }
    promise.set_result(std::move(result));
    co_return td::Unit{};
  }
  adnl::AdnlNodeIdShort non_permanent_id_;
};
}  // namespace tos::overlay

namespace {
using namespace tos;
using namespace tos::overlay;
using namespace tos::overlay::plumtree_sim;

struct Received {
  size_t count = 0;
  PublicKeyHash source;
  std::string payload;
  std::string extra;
};

class Callback final : public Overlays::Callback {
 public:
  Callback(std::vector<Received>& received, size_t index) : received_(received), index_(index) {
  }
  void receive_broadcast_with_extra(PublicKeyHash src, OverlayIdShort, td::BufferSlice data,
                                    td::BufferSlice extra) override {
    auto& row = received_[index_];
    ++row.count;
    row.source = src;
    row.payload = data.as_slice().str();
    row.extra = extra.as_slice().str();
  }
  void precheck_broadcast(PublicKeyHash, OverlayIdShort, td::Bits256, td::BufferSlice, bool,
                          td::Promise<> promise) override {
    promise.set_value(td::Unit());
  }
  void check_broadcast(PublicKeyHash, OverlayIdShort, td::BufferSlice, td::Promise<> promise) override {
    promise.set_value(td::Unit());
  }

 private:
  std::vector<Received>& received_;
  size_t index_;
};

struct FirstHop {
  adnl::AdnlNodeIdShort destination;
  int constructor;
  int seqno;
};

class Fixture {
 public:
  Fixture(size_t members, size_t online, std::vector<size_t> selection, bool receiver_default = false,
          bool sender_default = false, bool authorize = true)
      : directory_(td::mkdtemp("/tmp", "twostep-relays").move_as_ok())
      , network_(std::make_shared<SimNetwork>())
      , received_(online)
      , scheduler_({0}, true)
      , online_(online) {
    network_->base_time = td::Time::now();
    network_->geo_alpha_ms = 1;
    network_->geo_beta_ms_per_km = 0;
    network_->jitter = 0;
    network_->geo_by_node.resize(members);
    network_->sent_bytes_by_node.resize(members);
    network_->received_bytes_by_node.resize(members);
    network_->tx_free_at_by_node.resize(members);
    network_->rx_free_at_by_node.resize(members);
    for (size_t i = 0; i <= members; ++i) {
      keys_.push_back(make_key(PSTRING() << "twostep-test-" << i));
      ids_.emplace_back(keys_.back().compute_public_key().compute_short_id());
      if (i < members)
        network_->node_by_adnl[ids_.back()] = i;
    }
    std::vector<adnl::AdnlNodeIdShort> peers(ids_.begin(), ids_.begin() + members);
    std::set<adnl::AdnlNodeIdShort> selected;
    for (auto i : selection)
      selected.insert(ids_.at(i));
    full_ = create_serialize_tl_object<tos_api::pub_overlay>(td::BufferSlice("twostep-relay-test"));
    overlay_id_ = OverlayIdFull{full_.clone()}.compute_short_id();
    scheduler_.run_in_context([&] {
      errorlog::ErrorLog::create(directory_);
      keyring_ = keyring::Keyring::create(directory_);
      net_ = td::actor::create_actor<adnl::TestLoopbackNetworkManager>("relay net");
      adnl_ = adnl::Adnl::create(directory_, keyring_.get());
      sender_ = td::actor::create_actor<SimulatedSender>("relay sender", network_);
      td::actor::send_closure(adnl_, &adnl::Adnl::register_network_manager, net_.get());
      auto address = adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();
      for (size_t i = 0; i < online_; ++i) {
        td::actor::send_closure(keyring_, &keyring::Keyring::add_key, keys_[i], true, [](td::Result<>) {});
        td::actor::send_closure(adnl_, &adnl::Adnl::add_id, adnl::AdnlNodeIdFull{keys_[i].compute_public_key()},
                                address, 0);
      }
      manager_ = td::actor::create_actor<OverlayManager>("relay overlays", directory_, keyring_.get(), adnl_.get(),
                                                         td::actor::ActorId<dht::Dht>{});
      for (size_t i = 0; i < online_; ++i) {
        OverlayOptions options;
        options.twostep_broadcast_sender_ = sender_.get();
        options.send_twostep_broadcast_ = true;
        options.allow_old_broadcasts_ = false;
        if (!(i == 0 ? sender_default : receiver_default))
          options.twostep_intermediate_nodes_ = selected;
        auto actor = td::actor::create_actor<RelayOverlay>(
            "relay overlay", keyring_.get(), adnl_.get(), manager_.get(), td::actor::ActorId<dht::Dht>{}, ids_[i],
            OverlayIdFull{full_.clone()}, OverlayType::FixedMemberList, peers, std::vector<PublicKeyHash>{},
            OverlayMemberCertificate{}, std::make_unique<Callback>(received_, i),
            OverlayPrivacyRules{0, 0,
                                authorize ? std::map<PublicKeyHash, td::uint32>{{ids_[0].pubkey_hash(), 1 << 20}}
                                          : std::map<PublicKeyHash, td::uint32>{}},
            "relay-test", options);
        actors_.push_back(actor.get());
        td::actor::send_closure(manager_, &OverlayManager::register_overlay, ids_[i], overlay_id_,
                                OverlayMemberCertificate{}, std::move(actor));
      }
    });
    pump_scheduler(scheduler_, 128);
  }
  ~Fixture() {
    scheduler_.run_in_context([&] {
      manager_.reset();
      sender_.reset();
      adnl_.reset();
      net_.reset();
      keyring_.reset();
    });
    pump_scheduler(scheduler_, 128);
    scheduler_.stop();
    td::rmrf(directory_).ensure();
  }
  void send(size_t bytes = 8000) {
    payload_.assign(bytes, 'r');
    scheduler_.run_in_context([&] {
      td::actor::send_closure(manager_, &OverlayManager::send_broadcast_fec_with_extra, ids_[0], overlay_id_,
                              ids_[0].pubkey_hash(), 0, td::BufferSlice(payload_), td::BufferSlice("signed-extra"));
    });
    pump();
  }
  void pump() {
    // Fixed scheduler/time budget also completes pending asynchronous signing. Empty
    // transport queues alone are not treated as completion.
    for (size_t step = 0; step < 256; ++step) {
      pump_scheduler(scheduler_, 8);
      td::Time::jump_in_future(td::Time::now() + 0.005);
      auto events = network_->pop_due_events(network_->now_s());
      scheduler_.run_in_context([&] {
        for (auto& event : events) {
          CHECK(event.kind == SimEventKind::Message);  // private ping is disabled
          td::Slice data = event.data.as_slice();
          fetch_tl_prefix<tos_api::overlay_message>(data, true).ensure();
          auto message = fetch_tl_object<tos_api::overlay_Broadcast>(data, true);
          if (message.is_ok() && event.src == ids_[0]) {
            auto& object = message.ok();
            if (object->get_id() == tos_api::overlay_broadcastTwostepFec::ID) {
              auto& fec = static_cast<tos_api::overlay_broadcastTwostepFec&>(*object);
              first_.push_back({event.dst, object->get_id(), fec.seqno_});
              captures_.push_back(event.data.clone());
            } else if (object->get_id() == tos_api::overlay_broadcastTwostepSimple::ID) {
              first_.push_back({event.dst, object->get_id(), -1});
              captures_.push_back(event.data.clone());
            }
          }
          auto it = std::find(ids_.begin(), ids_.begin() + online_, event.dst);
          if (it == ids_.begin() + online_)
            continue;
          td::actor::send_closure(manager_, &OverlayManager::receive_message, event.src, event.dst,
                                  std::move(event.data));
        }
      });
    }
    pump_scheduler(scheduler_, 128);
  }
  void expect_hops(std::vector<size_t> destinations, bool fec) const {
    ASSERT_EQ(first_.size(), destinations.size());
    std::set<adnl::AdnlNodeIdShort> expected, actual;
    std::set<int> seqnos;
    for (auto i : destinations)
      expected.insert(ids_.at(i));
    for (const auto& row : first_) {
      ASSERT_EQ(row.constructor,
                fec ? tos_api::overlay_broadcastTwostepFec::ID : tos_api::overlay_broadcastTwostepSimple::ID);
      actual.insert(row.destination);
      if (fec)
        seqnos.insert(row.seqno);
    }
    ASSERT_TRUE(actual == expected);
    if (fec)
      for (size_t i = 0; i < destinations.size(); ++i)
        ASSERT_TRUE(seqnos.contains(static_cast<int>(i)));
  }
  void expect_fec_symbols(size_t k) const {
    CHECK(!captures_.empty());
    for (const auto& frame : captures_) {
      td::Slice bytes = frame.as_slice();
      fetch_tl_prefix<tos_api::overlay_message>(bytes, true).ensure();
      auto fec = fetch_tl_object<tos_api::overlay_broadcastTwostepFec>(bytes, true).move_as_ok();
      ASSERT_EQ(fec->part_.size(), (payload_.size() + k - 1) / k);
      ASSERT_EQ((payload_.size() + fec->part_.size() - 1) / fec->part_.size(), k);
    }
    LOG(INFO) << "first hops=" << first_.size() << " K=" << k << " online=" << online_;
  }
  void expect_delivery(bool remote) const {
    for (size_t i = 0; i < online_; ++i) {
      const auto& row = received_[i];
      ASSERT_EQ(row.count, i == 0 || remote ? 1u : 0u);
      if (row.count) {
        ASSERT_TRUE(row.source == ids_[0].pubkey_hash());
        ASSERT_EQ(row.payload, payload_);
        ASSERT_EQ(row.extra, "signed-extra");
      }
    }
  }
  void check_non_permanent(bool selected) {
    OverlayNode node{adnl::AdnlNodeIdFull{keys_.back().compute_public_key()}, overlay_id_, 0,
                     static_cast<td::int32>(td::Clocks::system()), td::Slice{}};
    node.update_signature(
        keys_.back().create_decryptor().move_as_ok()->sign(node.to_sign().as_slice()).move_as_ok().as_slice());
    scheduler_.run_in_context([&] {
      td::actor::send_closure(actors_[0], &RelayOverlay::set_non_permanent_id, ids_.back());
      td::actor::send_closure(actors_[0], &RelayOverlay::check_predicate, std::move(node), ids_[1],
                              adnl::AdnlNodeIdShort{td::Bits256::zero()}, selected);
    });
    pump_scheduler(scheduler_, 128);
  }
  td::BufferSlice captured() const {
    CHECK(!captures_.empty());
    return captures_[0].clone();
  }
  td::Status replay(td::BufferSlice frame) {
    std::optional<td::Result<>> result;
    scheduler_.run_in_context([&] {
      td::actor::send_closure(actors_[1], &RelayOverlay::check_frame, ids_[0], std::move(frame),
                              td::PromiseCreator::lambda([&](td::Result<> value) { result = std::move(value); }));
    });
    pump();
    CHECK(result);
    return result->is_error() ? result->move_as_error() : td::Status::OK();
  }

 private:
  std::string directory_;
  std::shared_ptr<SimNetwork> network_;
  std::vector<Received> received_;
  td::actor::Scheduler scheduler_;
  size_t online_;
  std::vector<PrivateKey> keys_;
  std::vector<adnl::AdnlNodeIdShort> ids_;
  td::BufferSlice full_;
  OverlayIdShort overlay_id_;
  std::string payload_;
  std::vector<FirstHop> first_;
  std::vector<td::BufferSlice> captures_;
  std::vector<td::actor::ActorId<RelayOverlay>> actors_;
  td::actor::ActorOwn<keyring::Keyring> keyring_;
  td::actor::ActorOwn<adnl::TestLoopbackNetworkManager> net_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<SimulatedSender> sender_;
  td::actor::ActorOwn<OverlayManager> manager_;
};
}  // namespace

TEST(Twostep, CurrentRelaysAndObserverDelivery) {
  Fixture f(9, 9, {0, 1, 2, 3, 4, 5, 6, 9});
  f.send();
  f.expect_hops({1, 2, 3, 4, 5, 6}, true);
  f.expect_delivery(true);
}
TEST(Twostep, SimpleRelayCountFallback) {
  Fixture f(7, 7, {0, 1, 2, 3});
  f.send();
  f.expect_hops({1, 2, 3}, false);
  f.expect_delivery(true);
}
TEST(Twostep, OfflineNonCurrentRelays) {
  {
    Fixture f(21, 7, {});
    f.send();
    std::vector<size_t> ids;
    for (size_t i = 1; i < 21; ++i)
      ids.push_back(i);
    f.expect_hops(ids, true);
    f.expect_fec_symbols(9);
    f.expect_delivery(false);
  }
  {
    Fixture f(21, 7, {0, 1, 2, 3, 4, 5, 6});
    f.send();
    f.expect_hops({1, 2, 3, 4, 5, 6}, true);
    f.expect_fec_symbols(2);
    f.expect_delivery(true);
  }
}
TEST(Twostep, EmptyDefault) {
  Fixture f(7, 7, {});
  f.send();
  f.expect_hops({1, 2, 3, 4, 5, 6}, true);
  f.expect_delivery(true);
}
TEST(Twostep, BoundariesAndDegenerateOptions) {
  for (size_t remotes : {0u, 1u, 2u, 4u, 5u})
    for (size_t bytes : {512u, 513u}) {
      std::vector<size_t> selected{0}, remote;
      for (size_t i = 1; i <= remotes; ++i) {
        selected.push_back(i);
        remote.push_back(i);
      }
      Fixture f(7, 7, selected);
      f.send(bytes);
      f.expect_hops(remote, remotes >= 5 && bytes >= 513);
      f.expect_delivery(remotes > 0);
    }
  Fixture f(7, 7, {7});
  f.send();
  f.expect_hops({}, false);
  f.expect_delivery(false);
}
TEST(Twostep, MixedPolicies) {
  {
    Fixture f(9, 9, {0, 1, 2, 3, 4, 5, 6}, true);
    f.send();
    f.expect_hops({1, 2, 3, 4, 5, 6}, true);
    f.expect_delivery(true);
  }
  {
    Fixture f(9, 9, {0, 1, 2, 3, 4, 5, 6}, false, true);
    f.send();
    f.expect_hops({1, 2, 3, 4, 5, 6, 7, 8}, true);
    f.expect_delivery(true);
  }
}
TEST(Twostep, KnownNonPermanentPeer) {
  {
    Fixture f(7, 7, {0, 1, 7});
    f.check_non_permanent(true);
  }
  {
    Fixture f(7, 7, {});
    f.check_non_permanent(true);
  }
}
TEST(Twostep, AuthenticationExtraAndReceiveBound) {
  td::BufferSlice simple, fec;
  {
    Fixture source(7, 7, {0, 1, 2, 3});
    source.send();
    simple = source.captured();
  }
  {
    Fixture source(7, 7, {});
    source.send();
    fec = source.captured();
  }
  {
    Fixture target(7, 7, {});
    ASSERT_TRUE(target.replay(simple.clone()).is_ok());
  }
  {
    Fixture target(7, 7, {}, false, false, false);
    ASSERT_TRUE(target.replay(simple.clone()).is_error());
  }
  for (bool alter_extra : {false, true}) {
    td::Slice bytes = simple.as_slice();
    auto prefix = fetch_tl_prefix<tos_api::overlay_message>(bytes, true).move_as_ok();
    auto object = fetch_tl_object<tos_api::overlay_broadcastTwostepSimple>(bytes, true).move_as_ok();
    if (alter_extra)
      object->extra_ = td::BufferSlice("tampered-extra");
    else
      object->signature_.as_slice()[0] ^= 1;
    Fixture target(7, 7, {});
    auto result = target.replay(serialize_tl_object(prefix, true, serialize_tl_object(object, true)));
    ASSERT_TRUE(result.is_error());
  }
  td::Slice bytes = fec.as_slice();
  auto prefix = fetch_tl_prefix<tos_api::overlay_message>(bytes, true).move_as_ok();
  auto object = fetch_tl_object<tos_api::overlay_broadcastTwostepFec>(bytes, true).move_as_ok();
  object->seqno_ = 7;
  Fixture target(7, 7, {});
  auto result = target.replay(serialize_tl_object(prefix, true, serialize_tl_object(object, true)));
  ASSERT_TRUE(result.is_error());
  ASSERT_TRUE(result.message().str().find("too big seqno") != std::string::npos);
}
