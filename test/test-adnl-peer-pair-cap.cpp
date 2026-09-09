/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Verifies the per-local-id peer-pair ceiling in AdnlPeerTableImpl: once a local
// id holds max_peer_pairs pairs, a packet from a brand-new unprotected peer is
// dropped instead of creating another peer-pair actor without bound.
//
// Falsifiability: with the ceiling in place the third distinct sender's message
// is never delivered (its pair is refused); remove the check in
// receive_decrypted_packet and the third message is delivered, failing the
// assertion below.

#include <array>
#include <atomic>
#include <cstdlib>

#include "adnl/adnl-network-manager.h"
#include "adnl/adnl-test-loopback-implementation.h"
#include "adnl/adnl.h"
#include "td/utils/port/path.h"
#include "td/utils/port/signals.h"

namespace {

constexpr size_t kMaxPeerPairs = 2;
constexpr int kSenders = 3;

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(verbosity_INFO);
  td::set_default_failure_signal_handler().ensure();

  std::string db_root = "tmp-dir-test-adnl-peer-pair-cap";
  td::rmrf(db_root).ignore();
  td::mkdir(db_root).ensure();

  td::actor::ActorOwn<tos::keyring::Keyring> keyring;
  td::actor::ActorOwn<tos::adnl::TestLoopbackNetworkManager> network_manager;
  td::actor::ActorOwn<tos::adnl::Adnl> adnl;

  tos::adnl::AdnlNodeIdShort dst;
  std::array<tos::adnl::AdnlNodeIdShort, kSenders> senders;

  // One atomic flag per sender, set when dst delivers that sender's message.
  std::array<std::atomic<bool>, kSenders> delivered;
  for (auto& d : delivered) {
    d.store(false);
  }

  std::atomic<bool> network_manager_ready{false};
  std::atomic<bool> adnl_subscription_ready{false};

  td::actor::Scheduler scheduler({2});

  scheduler.run_in_context([&] {
    keyring = tos::keyring::Keyring::create(db_root);
    network_manager = td::actor::create_actor<tos::adnl::TestLoopbackNetworkManager>("test network manager");
    adnl = tos::adnl::Adnl::create(db_root, keyring.get());
    td::actor::send_closure(adnl, &tos::adnl::Adnl::register_network_manager, network_manager.get());
    td::actor::send_closure(adnl, &tos::adnl::Adnl::set_max_peer_pairs, kMaxPeerPairs);

    auto addr = tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();

    // Receiver.
    auto dst_pk = tos::PrivateKey{tos::privkeys::Ed25519::random()};
    auto dst_pub = dst_pk.compute_public_key();
    dst = tos::adnl::AdnlNodeIdShort{dst_pub.compute_short_id()};
    td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, std::move(dst_pk), true, [](td::Result<>) {});
    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id, tos::adnl::AdnlNodeIdFull{dst_pub}, addr,
                            static_cast<td::uint8>(0));
    td::actor::send_closure(network_manager, &tos::adnl::TestLoopbackNetworkManager::add_node_id, dst, false, true);

    // Senders. Each is a distinct local id that only sends.
    for (int i = 0; i < kSenders; i++) {
      auto pk = tos::PrivateKey{tos::privkeys::Ed25519::random()};
      auto pub = pk.compute_public_key();
      senders[i] = tos::adnl::AdnlNodeIdShort{pub.compute_short_id()};
      td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, std::move(pk), true, [](td::Result<>) {});
      td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id, tos::adnl::AdnlNodeIdFull{pub}, addr,
                              static_cast<td::uint8>(0));
      // The sender needs dst's address to reach it.
      td::actor::send_closure(adnl, &tos::adnl::Adnl::add_peer, senders[i], tos::adnl::AdnlNodeIdFull{dst_pub}, addr);
      td::actor::send_closure(network_manager, &tos::adnl::TestLoopbackNetworkManager::add_node_id, senders[i], true,
                              false);
    }

    td::actor::send_lambda(network_manager, [&] { network_manager_ready.store(true, std::memory_order_release); });
  });

  scheduler.run_in_context([&] {
    class Callback : public tos::adnl::Adnl::Callback {
     public:
      Callback(std::array<tos::adnl::AdnlNodeIdShort, kSenders>& senders,
               std::array<std::atomic<bool>, kSenders>& delivered)
          : senders_(senders), delivered_(delivered) {
      }
      void receive_message(tos::adnl::AdnlNodeIdShort src, tos::adnl::AdnlNodeIdShort dst,
                           td::BufferSlice data) override {
        for (int i = 0; i < kSenders; i++) {
          if (senders_[i] == src) {
            delivered_[i].store(true, std::memory_order_release);
          }
        }
      }
      void receive_query(tos::adnl::AdnlNodeIdShort src, tos::adnl::AdnlNodeIdShort dst, td::BufferSlice data,
                         td::Promise<td::BufferSlice> promise) override {
        UNREACHABLE();
      }

     private:
      std::array<tos::adnl::AdnlNodeIdShort, kSenders>& senders_;
      std::array<std::atomic<bool>, kSenders>& delivered_;
    };
    td::actor::send_closure(adnl, &tos::adnl::Adnl::subscribe, dst, "T",
                            std::make_unique<Callback>(senders, delivered));
    td::actor::send_lambda(adnl, [&] { adnl_subscription_ready.store(true, std::memory_order_release); });
  });

  auto setup_timeout = td::Timestamp::in(10.0);
  while (!network_manager_ready.load(std::memory_order_acquire) ||
         !adnl_subscription_ready.load(std::memory_order_acquire)) {
    if (!scheduler.run(0.1)) {
      LOG(FATAL) << "scheduler stopped before setup completed";
    }
    if (setup_timeout.is_in_past()) {
      LOG(FATAL) << "timed out waiting for test setup";
    }
  }

  auto send_from = [&](int i) {
    scheduler.run_in_context([&] {
      td::BufferSlice msg(2);
      msg.as_slice()[0] = 'T';
      msg.as_slice()[1] = static_cast<char>('0' + i);
      td::actor::send_closure(adnl, &tos::adnl::Adnl::send_message, senders[i], dst, std::move(msg));
    });
  };

  auto wait_for = [&](auto predicate, double timeout, const char* what) {
    auto deadline = td::Timestamp::in(timeout);
    while (!predicate()) {
      if (!scheduler.run(0.05)) {
        LOG(FATAL) << "scheduler stopped while waiting for " << what;
      }
      if (deadline.is_in_past()) {
        LOG(FATAL) << "timed out waiting for " << what;
      }
    }
  };

  // Fill the ceiling: the first two senders each create a pair on dst and are
  // delivered.
  send_from(0);
  send_from(1);
  wait_for([&] { return delivered[0].load() && delivered[1].load(); }, 20.0, "first two deliveries");

  // The third sender would create a third pair for dst, which is at its limit
  // of two. Its packet must be dropped, so its message is never delivered.
  send_from(2);

  // Give the third message ample scheduler time to (not) arrive.
  auto quiet = td::Timestamp::in(3.0);
  while (!quiet.is_in_past()) {
    if (!scheduler.run(0.05)) {
      break;
    }
  }

  CHECK(delivered[0].load());
  CHECK(delivered[1].load());
  CHECK(!delivered[2].load());  // refused by the peer-pair ceiling

  LOG(ERROR) << "peer-pair ceiling held: 2 of 3 distinct senders admitted, third refused";

  // Actors keep long-lived idle alarms scheduled, so draining the scheduler to
  // quiescence would hang; force-exit like the other ADNL loopback tests.
  td::rmrf(db_root).ignore();
  std::_Exit(0);
  return 0;
}
