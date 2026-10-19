#include <cstdio>
#include <ctime>

#include "overlay/overlay-manager.h"
#include "overlay/overlay.hpp"
#include "td/utils/crypto.h"
#include "td/utils/tests.h"
#include "test/plumtree/scheduler.h"
#include "test/plumtree/transport.h"

namespace tos::overlay {
struct RepairTestState {
  std::vector<std::pair<adnl::AdnlNodeIdShort, td::uint64>> requests;
  bool checked = false;
  std::size_t deliveries = 0;
};
class RepairDeliveryCallback : public Overlays::Callback {
 public:
  explicit RepairDeliveryCallback(std::shared_ptr<RepairTestState> state) : state_(std::move(state)) {
  }
  void receive_broadcast(PublicKeyHash, OverlayIdShort, td::BufferSlice) override {
    ++state_->deliveries;
  }

 private:
  std::shared_ptr<RepairTestState> state_;
};
class RepairManager : public OverlayManager {
 public:
  explicit RepairManager(std::shared_ptr<RepairTestState> state) : OverlayManager("", {}, {}, {}), state_(state) {
  }
  void start_up() override {
  }
  void send_query_via(adnl::AdnlNodeIdShort dst, adnl::AdnlNodeIdShort, OverlayIdShort, std::string,
                      td::Promise<td::BufferSlice> promise, td::Timestamp, td::BufferSlice, td::uint64 max_answer_size,
                      td::actor::ActorId<adnl::AdnlSenderInterface>) override {
    state_->requests.emplace_back(dst, max_answer_size);
    promise.set_error(td::Status::Error("test transport has no part"));
  }

 private:
  std::shared_ptr<RepairTestState> state_;
};
class OverlayImplPlumtreeRepairTest {
 public:
  static BroadcastsPlumtree &broadcasts(OverlayImpl &overlay) {
    return overlay.broadcasts_plumtree_;
  }
};
class RepairOverlay : public OverlayImpl {
 public:
  using OverlayImpl::OverlayImpl;
  void start_up() override {
  }
  void alarm() override {
  }
  void run_checks(PrivateKey key, std::shared_ptr<RepairTestState> state, bool benchmark) {
    auto &b = OverlayImplPlumtreeRepairTest::broadcasts(*this);
    std::vector<adnl::AdnlNodeIdShort> peers;
    for (int i = 0; i < 24; ++i)
      peers.emplace_back(PrivateKey{privkeys::Ed25519::random()}.compute_public_key().compute_short_id());
    b.add_peer_state_for_test(peers.back());  // Keep real IHAVEs pending until repair time.
    auto submit = [&](int id, int peer, int size, bool valid, int signature_size = 64) {
      auto broadcast_id = td::sha256_bits256(td::Slice(std::to_string(id)));
      auto hash = td::sha256_bits256("part");
      auto timestamp = td::Clocks::system();
      auto to_sign = create_serialize_tl_object<tos_api::overlay_broadcastPlumtreeSimple_toSign>(
          broadcast_id, timestamp, 0, size, hash);
      auto signature = key.create_decryptor().move_as_ok()->sign(to_sign.as_slice()).move_as_ok();
      if (!valid)
        signature.as_slice().fill('x');
      if (signature_size != 64)
        signature = td::BufferSlice(signature_size);
      auto message = create_tl_object<tos_api::overlay_broadcastPlumtreeIHave>(
          broadcast_id, timestamp, 0, 0, key.compute_public_key().tl(), Certificate::empty_tl(), timestamp, size, hash,
          std::move(signature));
      auto task = b.process_ihave(this, peers[peer], std::move(message)).start_immediate();
      CHECK(task.await_ready());
      return task.await_resume().is_ok();
    };
    auto submit_fec = [&](int id, int peer, int part_index, bool valid) {
      auto broadcast_id = td::sha256_bits256(td::Slice(std::to_string(id)));
      auto part_label = std::string("fec-part-") + std::to_string(part_index);
      auto hash = td::sha256_bits256(td::Slice(part_label));
      auto timestamp = td::Clocks::system();
      auto tree_index = part_index + 1;
      auto to_sign = create_serialize_tl_object<tos_api::overlay_broadcastPlumtreeFec_toSign>(
          broadcast_id, timestamp, part_index, tree_index, 1000, hash);
      auto signature = key.create_decryptor().move_as_ok()->sign(to_sign.as_slice()).move_as_ok();
      if (!valid)
        signature.as_slice().fill('x');
      auto message = create_tl_object<tos_api::overlay_broadcastPlumtreeIHave>(
          broadcast_id, timestamp, part_index, tree_index, key.compute_public_key().tl(), Certificate::empty_tl(),
          timestamp, 1000, hash, std::move(signature));
      auto task = b.process_ihave(this, peers[peer], std::move(message)).start_immediate();
      CHECK(task.await_ready());
      return task.await_resume().is_ok();
    };
    if (benchmark) {
      std::vector<tl_object_ptr<tos_api::overlay_broadcastPlumtreeSimple>> payloads;
      double cpu_ms = 0;
      for (int id = 0; id < 500; ++id) {
        auto broadcast_id = td::sha256_bits256(td::Slice(std::to_string(id)));
        td::BufferSlice data(1000);
        data.as_slice().fill('a');
        auto hash = td::sha256_bits256(data.as_slice());
        auto timestamp = td::Clocks::system();
        auto to_sign = create_serialize_tl_object<tos_api::overlay_broadcastPlumtreeSimple_toSign>(
            broadcast_id, timestamp, 0, 1000, hash);
        auto signature = key.create_decryptor().move_as_ok()->sign(to_sign.as_slice()).move_as_ok();
        payloads.push_back(create_tl_object<tos_api::overlay_broadcastPlumtreeSimple>(
            0, timestamp, key.compute_public_key().tl(), Certificate::empty_tl(), broadcast_id, 0, std::move(data),
            signature.clone()));
        for (int peer = 1; peer <= 5; ++peer) {
          auto message = create_tl_object<tos_api::overlay_broadcastPlumtreeIHave>(
              broadcast_id, timestamp, 0, 0, key.compute_public_key().tl(), Certificate::empty_tl(), timestamp, 1000,
              hash, signature.clone());
          auto start = std::clock();
          auto task = b.process_ihave(this, peers[peer], std::move(message)).start_immediate();
          CHECK(task.await_ready());
          CHECK(task.await_resume().is_ok());
          cpu_ms += 1000.0 * static_cast<double>(std::clock() - start) / static_cast<double>(CLOCKS_PER_SEC);
        }
      }
      auto diag = b.repair_diagnostics_for_test();
      auto retained_before_delivery = diag.retained_auth_bytes;
      // Actual signed eager payloads arrive before the repair timer. Redundant
      // candidates are erased by the production delivery path, not by a test reset.
      for (auto &payload : payloads) {
        auto task = b.process_simple_payload(this, peers.back(), std::move(payload)).start_immediate();
        CHECK(task.await_ready());
        CHECK(task.await_resume().is_ok());
      }
      auto after_delivery = b.repair_diagnostics_for_test();
      CHECK(state->deliveries == 500);
      CHECK(after_delivery.pending_parts == 0 && after_delivery.retained_auth_bytes == 0);
      std::printf(
          "IHAVE workload: messages=2500 deliveries=%zu immediate_checks=%llu deferred_checks=%llu cpu_ms=%.3f "
          "retained_before_delivery=%zu retained_after_delivery=%zu\n",
          state->deliveries, static_cast<unsigned long long>(diag.immediate_checks),
          static_cast<unsigned long long>(diag.deferred_checks), cpu_ms, retained_before_delivery,
          after_delivery.retained_auth_bytes);
      std::fflush(stdout);
      CHECK(diag.immediate_checks == 500 && diag.deferred_checks == 0);
      CHECK(retained_before_delivery == 500 * 4 * (36 + 84 + 64));
      state->checked = true;
      return;
    }
    CHECK(!submit(0, 0, 1000, false));
    CHECK(b.repair_diagnostics_for_test().pending_parts == 0);  // Invalid first announcement cannot seed trust.

    CHECK(submit(1, 1, 1000, true));
    CHECK(submit(1, 2, 2000, false));  // Canonical forged signature is deferred, never used for a query.
    CHECK(submit(1, 3, 3000, true));
    auto diag = b.repair_diagnostics_for_test();
    CHECK(diag.immediate_checks == 2 && diag.deferred_checks == 0 && diag.targets == 3);
    CHECK(diag.retained_auth_bytes == 2 * (36 + 84 + 64));
    CHECK(!submit(1, 4, 3000, true, 65));  // Noncanonical signatures cannot bypass eager validation.
    b.flush_repairs_for_test(this);
    diag = b.repair_diagnostics_for_test();
    CHECK(diag.deferred_checks == 2 && diag.retained_auth_bytes == 0 && diag.pending_parts == 0);
    // Source authorization revoked between acceptance and repair: not a valid repair destination.
    CHECK(submit(2, 5, 1000, true));
    CHECK(submit(2, 6, 1000, true));
    set_privacy_rules(OverlayPrivacyRules{});
    b.flush_repairs_for_test(this);
    set_privacy_rules(OverlayPrivacyRules{Overlays::max_fec_broadcast_size(),
                                          CertificateFlags::AllowFec,
                                          {{key.compute_short_id(), Overlays::max_fec_broadcast_size()}}});

    // Authentication is per missing FEC part, not merely per broadcast. A
    // valid IHAVE for part 0 must not let a forged first IHAVE for part 1 seed
    // repair state without a source-signature check.
    // Earlier malformed-signature cases ban peers 0, 2 and 4. Use independent
    // peers so this regression measures part authentication, not the ban list.
    CHECK(submit_fec(100, 20, 0, true));
    auto cross_part_diag = b.repair_diagnostics_for_test();
    auto checks_after_part0 = cross_part_diag.immediate_checks;
    CHECK(!submit_fec(100, 21, 1, false));
    cross_part_diag = b.repair_diagnostics_for_test();
    CHECK(cross_part_diag.immediate_checks == checks_after_part0 + 1);
    CHECK(submit_fec(100, 22, 1, true));
    cross_part_diag = b.repair_diagnostics_for_test();
    CHECK(cross_part_diag.immediate_checks == checks_after_part0 + 2);
    b.flush_repairs_for_test(this);
    CHECK(b.repair_diagnostics_for_test().pending_parts == 0);

    // Configurable target count is clamped even when the caller requests an enormous cap.
    for (int i = 7; i < 20; ++i)
      CHECK(submit(3, i, 1000, true));
    for (int i = 1; i < 7; ++i)
      CHECK(submit(3, i, 1000, true));
    diag = b.repair_diagnostics_for_test();
    CHECK(diag.targets == PLUMTREE_MAX_REPAIR_TARGETS);
    CHECK(diag.retained_auth_bytes <= diag.targets * PLUMTREE_MAX_REPAIR_AUTH_BYTES);
    // Bounded broadcast backlog, each first signature is still verified.
    for (int i = 4; i < 1040; ++i)
      CHECK(submit(i, 1, 1000, true));
    diag = b.repair_diagnostics_for_test();
    CHECK(diag.pending_parts == 1024 && diag.targets == 1024);
    CHECK(diag.retained_auth_bytes == 0);
    state->checked = true;
  }
};
}  // namespace tos::overlay

static void run_repair_fixture(bool benchmark) {
  using namespace tos;
  using namespace tos::overlay;
  auto state = std::make_shared<RepairTestState>();
  auto network = std::make_shared<plumtree_sim::SimNetwork>();
  td::actor::Scheduler scheduler({0}, true);
  td::actor::ActorOwn<RepairManager> manager;
  td::actor::ActorOwn<plumtree_sim::SimulatedSender> sender;
  td::actor::ActorOwn<RepairOverlay> overlay;
  scheduler.run_in_context([&] {
    manager = td::actor::create_actor<RepairManager>("repair recorder", state);
    sender = td::actor::create_actor<plumtree_sim::SimulatedSender>("unused repair transport", network);
    OverlayOptions opts;
    opts.enable_plumtree_broadcast_ = true;
    opts.plumtree_broadcast_sender_ = sender.get();
    opts.plumtree_fec_options_.max_repair_targets_ = 1000000;
    auto key = PrivateKey{privkeys::Ed25519::random()};
    auto local = adnl::AdnlNodeIdShort{PrivateKey{privkeys::Ed25519::random()}.compute_public_key().compute_short_id()};
    auto full = create_serialize_tl_object<tos_api::pub_overlay>(td::BufferSlice("repair-auth-test"));
    OverlayPrivacyRules rules{Overlays::max_fec_broadcast_size(),
                              CertificateFlags::AllowFec,
                              {{key.compute_short_id(), Overlays::max_fec_broadcast_size()}}};
    overlay = td::actor::create_actor<RepairOverlay>(
        "repair overlay", td::actor::ActorId<keyring::Keyring>{}, td::actor::ActorId<adnl::Adnl>{}, manager.get(),
        td::actor::ActorId<dht::Dht>{}, local, OverlayIdFull{std::move(full)}, OverlayType::Public,
        std::vector<adnl::AdnlNodeIdShort>{}, std::vector<PublicKeyHash>{}, OverlayMemberCertificate{},
        std::make_unique<RepairDeliveryCallback>(state), rules, "repair-test", opts);
    td::actor::send_closure(overlay, &RepairOverlay::run_checks, std::move(key), state, benchmark);
  });
  plumtree_sim::pump_scheduler(scheduler, 64);
  ASSERT_TRUE(state->checked);
  ASSERT_EQ(state->requests.size(), benchmark ? 0u : 4u);
  if (!benchmark) {
    ASSERT_EQ(state->requests[0].second, 1000u + 4096u);
    ASSERT_EQ(state->requests[1].second, 3000u + 4096u);
    ASSERT_TRUE(state->requests[0].first != state->requests[1].first);
    ASSERT_EQ(state->requests[2].second, 1000u + 4096u);
    ASSERT_EQ(state->requests[3].second, 1000u + 4096u);
    ASSERT_TRUE(state->requests[2].first != state->requests[3].first);
  }
  scheduler.run_in_context([&] {
    overlay.reset();
    sender.reset();
    manager.reset();
  });
  plumtree_sim::pump_scheduler(scheduler, 64);
}

TEST(Overlay, PlumtreeLazyRepairAuthentication) {
  run_repair_fixture(false);
}
TEST(Overlay, PlumtreeIHaveCpuWorkload) {
  run_repair_fixture(true);
}
