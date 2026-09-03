/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// The connection cap at its real entry point.
//
// A unit test of the admission helper proves the rule; it does not prove the
// node uses it. This drives a real Rldp actor -- built on a real ADNL over the
// loopback network manager -- past MAX_CONNECTIONS with distinct peers, and
// asks the node itself how many connections it is holding. Nothing here
// reaches into the implementation: peers arrive through the public send path
// and the count comes back through the public stats query.
//
// Peer ids are fabricated rather than key-backed on purpose. ADNL authenticates
// a peer id, so a real attacker cannot forge one -- but generating keys is
// free, so it presents unlimited legitimate identities, and what reaches this
// table is the same either way: a stream of ids it has never seen.

#include "adnl/adnl-test-loopback-implementation.h"
#include "adnl/adnl.h"
#include "keyring/keyring.h"
#include "rldp2/rldp.h"
#include "td/utils/port/path.h"
#include "td/utils/port/signals.h"

#include <cstdlib>

namespace {

// Comfortably past the 4096 cap, so the table is driven well beyond it rather
// than just up to it.
constexpr td::uint32 kPeersToPresent = 5000;

// Peers the second local id holds before the flood starts. Well under its
// share of the cap, so the fairness rule must keep every one of them.
constexpr td::uint32 kQuietPeers = 32;

tos::adnl::AdnlNodeIdShort fabricated_peer(td::uint32 n) {
  td::Bits256 bits;
  bits.set_zero();
  bits.as_slice().copy_from(td::Slice{reinterpret_cast<const td::uint8 *>(&n), sizeof(n)});
  return tos::adnl::AdnlNodeIdShort{bits};
}

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::set_default_failure_signal_handler().ensure();

  std::string db_root = "tmp-dir-test-rldp2-connection-cap";
  td::rmrf(db_root).ignore();
  td::mkdir(db_root).ensure();

  td::actor::ActorOwn<tos::keyring::Keyring> keyring;
  td::actor::ActorOwn<tos::adnl::TestLoopbackNetworkManager> network_manager;
  td::actor::ActorOwn<tos::adnl::Adnl> adnl;
  td::actor::ActorOwn<tos::rldp2::Rldp> rldp;
  // Two local ids, as a real node has: one public entry point that takes the
  // flood, and one whose peers must survive it.
  tos::adnl::AdnlNodeIdShort flooded_id;
  tos::adnl::AdnlNodeIdShort quiet_id;

  td::actor::Scheduler scheduler({0});

  scheduler.run_in_context([&] {
    keyring = tos::keyring::Keyring::create(db_root);
    network_manager = td::actor::create_actor<tos::adnl::TestLoopbackNetworkManager>("test net");
    adnl = tos::adnl::Adnl::create(db_root, keyring.get());
    rldp = tos::rldp2::Rldp::create(adnl.get());
    td::actor::send_closure(adnl, &tos::adnl::Adnl::register_network_manager, network_manager.get());

    auto addr = tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();
    auto add_local_id = [&](tos::adnl::AdnlNodeIdShort &out) {
      auto pk = tos::PrivateKey{tos::privkeys::Ed25519::random()};
      auto pub = pk.compute_public_key();
      out = tos::adnl::AdnlNodeIdShort{pub.compute_short_id()};
      td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, std::move(pk), true, [](td::Result<>) {});
      td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id, tos::adnl::AdnlNodeIdFull{pub}, addr, td::uint8(0));
      td::actor::send_closure(rldp, &tos::rldp2::Rldp::add_id, out);
      td::actor::send_closure(network_manager, &tos::adnl::TestLoopbackNetworkManager::add_node_id, out, true, true);
    };
    add_local_id(flooded_id);
    add_local_id(quiet_id);
  });

  // The quiet id establishes its peers first, while the table is empty. These
  // are what a purely global cap would evict: they go quiet and stay quiet
  // while the flood keeps refreshing its own.
  scheduler.run_in_context([&] {
    for (td::uint32 i = 1; i <= kQuietPeers; i++) {
      td::actor::send_closure(rldp, &tos::rldp2::Rldp::send_message, quiet_id, fabricated_peer(i),
                              td::BufferSlice("x"));
    }
  });

  // Then present a stream of peers the node has never seen, all to the other
  // local id. Each one reaches get_or_create_connection, which is the path the
  // cap has to hold.
  scheduler.run_in_context([&] {
    for (td::uint32 i = 1; i <= kPeersToPresent; i++) {
      td::actor::send_closure(rldp, &tos::rldp2::Rldp::send_message, flooded_id, fabricated_peer(kQuietPeers + i),
                              td::BufferSlice("x"));
    }
  });

  bool answered = false;
  tos::rldp2::Rldp::ConnectionStats stats;
  scheduler.run_in_context([&] {
    td::actor::send_closure(rldp, &tos::rldp2::Rldp::get_connection_stats,
                            td::PromiseCreator::lambda([&](td::Result<tos::rldp2::Rldp::ConnectionStats> R) {
                              R.ensure();
                              stats = R.move_as_ok();
                              answered = true;
                            }));
  });

  auto deadline = td::Timestamp::in(120.0);
  while (scheduler.run(1)) {
    if (answered) {
      break;
    }
    if (deadline.is_in_past()) {
      break;
    }
  }

  auto fail = [&](td::Slice what) {
    LOG(ERROR) << "FAILED: " << what;
    td::rmrf(db_root).ignore();
    std::exit(1);
  };

  // A stats query that never came back would make every assertion below vacuous.
  if (!answered) {
    fail("the node never answered the connection stats query");
  }
  size_t quiet_held = 0;
  size_t flooded_held = 0;
  for (auto &[id, held] : stats.per_local_id) {
    if (id == quiet_id) {
      quiet_held = held;
    } else if (id == flooded_id) {
      flooded_held = held;
    }
  }
  LOG(ERROR) << "presented " << kPeersToPresent << " distinct peers to one local id: " << stats.live
             << " connections live (" << flooded_held << " flooded, " << quiet_held << " quiet), " << stats.evicted
             << " evicted";

  if (stats.live > 4096) {
    fail(PSLICE() << "connection table grew past its cap: " << stats.live);
  }
  // Exactly at the cap, not merely under it: anything less would mean the
  // peers never reached the table and the test proves nothing.
  if (stats.live != 4096) {
    fail(PSLICE() << "expected the table to sit at its cap, found " << stats.live);
  }
  // Every peer past the cap displaced exactly one existing connection.
  // The flood is confined to its own share of the table, and every connection
  // the other local id established before it survives.
  if (quiet_held != kQuietPeers) {
    fail(PSLICE() << "the flood cost the other local id connections: " << quiet_held << " of " << kQuietPeers
                  << " left");
  }
  // The flood did reach the cap and kept going -- without evictions the run
  // proves nothing about what happens at the boundary.
  if (stats.evicted == 0) {
    fail("no evictions: the flood never reached the cap, so nothing here was tested");
  }

  // Shut the actors down inside the scheduler rather than leaving them alive
  // and calling _Exit. The scheduler drains on destruction and its object pool
  // then checks that everything it handed out came back, so a clean teardown
  // is evidence that the evicted connections were really destroyed and not
  // just dropped from the table.
  scheduler.run_in_context([&] {
    rldp.reset();
    adnl.reset();
    network_manager.reset();
    keyring.reset();
  });
  td::rmrf(db_root).ignore();
  LOG(ERROR) << "success";
  return 0;
}
