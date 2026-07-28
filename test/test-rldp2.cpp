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

    In addition, as a special exception, the copyright holders give permission
    to link the code of portions of this program with the OpenSSL library.
    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the file(s),
    but you are not obligated to do so. If you do not wish to do so, delete this
    exception statement from your version. If you delete this exception statement
    from all source files in the program, then also delete it here.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#include <memory>
#include <set>

#include "adnl/adnl-network-manager.h"
#include "adnl/adnl-test-loopback-implementation.h"
#include "adnl/adnl.h"
#include "rldp2/rldp.h"
#include "td/utils/Random.h"
#include "td/utils/port/path.h"
#include "td/utils/port/signals.h"

int main() {
  SET_VERBOSITY_LEVEL(verbosity_INFO);

  {
    // Direct unit test of tos::rldp2::detail::complete_out_query's boundary
    // behavior (rldp2/rldp.h), which enforces OutQuery::max_answer_size
    // against a received rldp_answer. This check is provably unreachable via
    // any RLDP2-wire-protocol-compliant sender -- see the comment on
    // complete_out_query for why -- so it can't be exercised end-to-end by
    // a malicious raw-wire peer (confirmed experimentally: a peer that tries
    // to answer bigger than the query's declared max_answer_size gets its
    // own reply dropped by RldpConnection's total_size accounting before it
    // is ever reassembled). This unit-tests the logic directly instead.
    LOG(ERROR) << "testing OutQuery answer-size boundary directly";

    auto run = [](td::uint64 max_answer_size, size_t data_size) -> td::Result<td::BufferSlice> {
      td::Result<td::BufferSlice> result;
      auto P = td::PromiseCreator::lambda([&](td::Result<td::BufferSlice> R) { result = std::move(R); });
      tos::rldp2::detail::complete_out_query(std::move(P), max_answer_size, td::BufferSlice(data_size));
      return result;
    };

    {
      auto r = run(10, 10);
      CHECK(r.is_ok());
      CHECK(r.ok_ref().size() == 10);
    }
    {
      auto r = run(10, 11);
      CHECK(r.is_error());
    }
    {
      auto r = run(0, 0);
      CHECK(r.is_ok());
    }
    {
      auto r = run(0, 1);
      CHECK(r.is_error());
    }
    {
      auto r = run(1'000'000, 200'000);
      CHECK(r.is_ok());
      CHECK(r.ok_ref().size() == 200'000);
    }

    LOG(ERROR) << "success";
  }

  std::string db_root_ = "tmp-dir-test-rldp2";
  td::rmrf(db_root_).ignore();
  td::mkdir(db_root_).ensure();

  td::set_default_failure_signal_handler().ensure();

  td::actor::ActorOwn<tos::keyring::Keyring> keyring;
  td::actor::ActorOwn<tos::adnl::TestLoopbackNetworkManager> network_manager;
  td::actor::ActorOwn<tos::adnl::Adnl> adnl;
  td::actor::ActorOwn<tos::rldp2::Rldp> rldp;

  tos::adnl::AdnlNodeIdShort src;
  tos::adnl::AdnlNodeIdShort dst;

  td::actor::Scheduler scheduler({0});

  scheduler.run_in_context([&] {
    keyring = tos::keyring::Keyring::create(db_root_);
    network_manager = td::actor::create_actor<tos::adnl::TestLoopbackNetworkManager>("test net");
    adnl = tos::adnl::Adnl::create(db_root_, keyring.get());
    rldp = tos::rldp2::Rldp::create(adnl.get());
    td::actor::send_closure(adnl, &tos::adnl::Adnl::register_network_manager, network_manager.get());

    auto pk1 = tos::PrivateKey{tos::privkeys::Ed25519::random()};
    auto pub1 = pk1.compute_public_key();
    src = tos::adnl::AdnlNodeIdShort{pub1.compute_short_id()};
    td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, std::move(pk1), true, [](td::Result<>) {});

    auto pk2 = tos::PrivateKey{tos::privkeys::Ed25519::random()};
    auto pub2 = pk2.compute_public_key();
    dst = tos::adnl::AdnlNodeIdShort{pub2.compute_short_id()};
    td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, std::move(pk2), true, [](td::Result<>) {});

    auto addr = tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();

    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id, tos::adnl::AdnlNodeIdFull{pub1}, addr, td::uint8(0));
    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id, tos::adnl::AdnlNodeIdFull{pub2}, addr, td::uint8(0));
    td::actor::send_closure(rldp, &tos::rldp2::Rldp::add_id, src);
    td::actor::send_closure(rldp, &tos::rldp2::Rldp::add_id, dst);

    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_peer, src, tos::adnl::AdnlNodeIdFull{pub2}, addr);

    td::actor::send_closure(network_manager, &tos::adnl::TestLoopbackNetworkManager::add_node_id, src, true, true);
    td::actor::send_closure(network_manager, &tos::adnl::TestLoopbackNetworkManager::add_node_id, dst, true, true);
  });

  auto send_packet = [&](td::uint32 i) {
    td::BufferSlice d{5};
    d.as_slice()[0] = '1';
    d.as_slice().remove_prefix(1).copy_from(td::Slice{reinterpret_cast<td::uint8 *>(&i), 4});

    return d;
  };

  std::atomic<td::uint32> remaining{0};
  scheduler.run_in_context([&] {
    class Callback : public tos::adnl::Adnl::Callback {
     public:
      void receive_message(tos::adnl::AdnlNodeIdShort src, tos::adnl::AdnlNodeIdShort dst,
                           td::BufferSlice data) override {
        CHECK(src == src);
        CHECK(dst == dst);
        if (data.size() >= 5) {
          CHECK(td::crc32c(data.as_slice().truncate(data.size() - 4)) ==
                *reinterpret_cast<const td::uint32 *>(data.as_slice().remove_prefix(data.size() - 4).begin()));
        }
        CHECK(remaining_ > 0);
        remaining_--;
      }
      void receive_query(tos::adnl::AdnlNodeIdShort src, tos::adnl::AdnlNodeIdShort dst, td::BufferSlice data,
                         td::Promise<td::BufferSlice> promise) override {
        CHECK(data.size() == 5);

        td::uint32 s = *reinterpret_cast<const td::uint32 *>(data.as_slice().remove_prefix(1).begin());

        td::BufferSlice d{s};
        if (s >= 4) {
          td::Random::secure_bytes(d.as_slice().truncate(s - 4));
          auto x = td::crc32c(d.as_slice().truncate(d.size() - 4));

          d.as_slice().remove_prefix(d.size() - 4).copy_from(td::Slice{reinterpret_cast<td::uint8 *>(&x), 4});
        } else {
          td::Random::secure_bytes(d.as_slice());
        }

        promise.set_value(std::move(d));
      }
      Callback(std::atomic<td::uint32> &remaining) : remaining_(remaining) {
      }

     private:
      std::atomic<td::uint32> &remaining_;
    };
    td::actor::send_closure(adnl, &tos::adnl::Adnl::subscribe, dst, "1", std::make_unique<Callback>(remaining));
  });

  std::vector<td::uint32> sizes{1, 1024, 1 << 20, 2 << 20, 3 << 20, 10 << 20, 16 << 20};

  for (auto &size : sizes) {
    LOG(ERROR) << "testing delivering of packet of size " << size;

    auto f = td::Clocks::system();
    scheduler.run_in_context([&] {
      remaining++;
      td::actor::send_closure(rldp, &tos::rldp2::Rldp::send_query_ex, src, dst, std::string("t"),
                              td::PromiseCreator::lambda([&](td::Result<td::BufferSlice> R) {
                                R.ensure();
                                remaining--;
                              }),
                              td::Timestamp::in(1024.0), send_packet(size), size + 1024);
    });

    auto t = td::Timestamp::in(1024.0);
    while (scheduler.run(16)) {
      if (!remaining) {
        break;
      }
      if (t.is_in_past()) {
        LOG(FATAL) << "failed to receive packets: remaining=" << remaining;
      }
    }

    LOG(ERROR) << "success. Time=" << (td::Clocks::system() - f);
  }

  scheduler.run_in_context([&] {
    td::actor::send_closure(network_manager, &tos::adnl::TestLoopbackNetworkManager::set_loss_probability, 0.1);
  });
  LOG(ERROR) << "set loss to 10%";

  for (auto &size : sizes) {
    LOG(ERROR) << "testing delivering of packet of size " << size;

    auto f = td::Clocks::system();
    scheduler.run_in_context([&] {
      remaining++;
      td::actor::send_closure(rldp, &tos::rldp2::Rldp::send_query_ex, src, dst, std::string("t"),
                              td::PromiseCreator::lambda([&](td::Result<td::BufferSlice> R) {
                                R.ensure();
                                remaining--;
                              }),
                              td::Timestamp::in(1024.0), send_packet(size), size + 1024);
    });

    auto t = td::Timestamp::in(1024.0);
    while (scheduler.run(16)) {
      if (!remaining) {
        break;
      }
      if (t.is_in_past()) {
        LOG(FATAL) << "failed to receive packets: remaining=" << remaining;
      }
    }

    LOG(ERROR) << "success. Time=" << (td::Clocks::system() - f);
  }

  scheduler.run_in_context([&] {
    td::actor::send_closure(network_manager, &tos::adnl::TestLoopbackNetworkManager::set_loss_probability, 0.0);
  });

  {
    // End-to-end regression test: if a peer's answer would be bigger than the
    // max_answer_size the caller declared to send_query_ex, the query promise
    // must resolve with an error rather than silently handing back
    // oversized/truncated data. In this loopback setup the responder's own
    // pre-existing self-check (in process_message(rldp_query&)) refuses to
    // send back an oversized reply at all, so this exercises that guard plus
    // the query-timeout error path end-to-end; it cannot in isolation force
    // an oversized rldp_answer past a well-behaved responder to reach the
    // requester-side OutQuery::max_answer_size double-check added in
    // rldp2/rldp.cpp's process_message(rldp_answer&) specifically -- that
    // second check only matters against a peer that ignores its own
    // self-check, which the test harness here (using the same honest RldpIn
    // on both ends) cannot manufacture without injecting raw/malformed wire
    // traffic. See PR description for why this is an accepted test gap.
    LOG(ERROR) << "testing oversized answer is rejected, not silently accepted";
    const td::uint32 requested_reply_size = 200000;
    const td::uint64 declared_max_answer_size = 1024;
    const double query_timeout = 3.0;

    auto f = td::Clocks::system();
    bool got_error = false;
    scheduler.run_in_context([&] {
      remaining++;
      td::actor::send_closure(rldp, &tos::rldp2::Rldp::send_query_ex, src, dst, std::string("t"),
                              td::PromiseCreator::lambda([&](td::Result<td::BufferSlice> R) {
                                got_error = R.is_error();
                                remaining--;
                              }),
                              td::Timestamp::in(query_timeout), send_packet(requested_reply_size),
                              declared_max_answer_size);
    });

    auto t = td::Timestamp::in(query_timeout + 10.0);
    while (scheduler.run(16)) {
      if (!remaining) {
        break;
      }
      if (t.is_in_past()) {
        LOG(FATAL) << "oversized-answer query neither completed nor errored: remaining=" << remaining;
      }
    }
    CHECK(got_error);

    LOG(ERROR) << "success (rejected as expected). Time=" << (td::Clocks::system() - f);
  }

  td::rmrf(db_root_).ensure();
  std::_Exit(0);
  return 0;
}
