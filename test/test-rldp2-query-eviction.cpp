/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// What happens to a query in flight when the connection carrying it goes away.
//
// A connection's expiry is the later of its current one and the deadline of
// the work handed to it, so a connection carrying a query outlives the query
// by a full connection timeout. That is what keeps a remote flood from taking
// it: an inbound message part creates a connection expiring one timeout from
// now, always sooner than one holding a query, so the flood evicts its own
// entries before it ever reaches the query's connection. This test checks that
// property holds -- it is the reason the hang below is not remotely
// reachable.
//
// The connection can still be removed by other means (its own expiry, or a
// local caller that hands the table work with a longer deadline), and the
// query's completion lives in the connection's actor. If that actor is
// destroyed without anything telling the query, the caller waits forever and
// the query's record is never reclaimed. So removal must answer the query
// rather than drop it, whatever caused the removal. The test forces the
// eviction that a remote peer cannot, and checks the query is answered.
//
// Packet delivery is suppressed throughout so the query cannot complete on
// its own and every answer observed comes from the removal path.

#include "adnl/adnl-test-loopback-implementation.h"
#include "adnl/adnl.h"
#include "keyring/keyring.h"
#include "rldp2/rldp.h"
#include "td/utils/port/path.h"
#include "td/utils/port/signals.h"

#include <cstdlib>

namespace {

constexpr td::uint32 kPeersToPresent = 6000;

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

  std::string db_root = "tmp-dir-test-rldp2-query-eviction";
  td::rmrf(db_root).ignore();
  td::mkdir(db_root).ensure();

  td::actor::ActorOwn<tos::keyring::Keyring> keyring;
  td::actor::ActorOwn<tos::adnl::TestLoopbackNetworkManager> network_manager;
  td::actor::ActorOwn<tos::adnl::Adnl> adnl;
  td::actor::ActorOwn<tos::rldp2::Rldp> rldp;
  tos::adnl::AdnlNodeIdShort src;
  tos::adnl::AdnlNodeIdShort dst;

  td::actor::Scheduler scheduler({0});

  scheduler.run_in_context([&] {
    keyring = tos::keyring::Keyring::create(db_root);
    network_manager = td::actor::create_actor<tos::adnl::TestLoopbackNetworkManager>("test net");
    adnl = tos::adnl::Adnl::create(db_root, keyring.get());
    rldp = tos::rldp2::Rldp::create(adnl.get());
    td::actor::send_closure(adnl, &tos::adnl::Adnl::register_network_manager, network_manager.get());

    auto addr = tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();
    auto pk1 = tos::PrivateKey{tos::privkeys::Ed25519::random()};
    auto pub1 = pk1.compute_public_key();
    src = tos::adnl::AdnlNodeIdShort{pub1.compute_short_id()};
    td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, std::move(pk1), true, [](td::Result<>) {});

    auto pk2 = tos::PrivateKey{tos::privkeys::Ed25519::random()};
    auto pub2 = pk2.compute_public_key();
    dst = tos::adnl::AdnlNodeIdShort{pub2.compute_short_id()};
    td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, std::move(pk2), true, [](td::Result<>) {});

    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id, tos::adnl::AdnlNodeIdFull{pub1}, addr, td::uint8(0));
    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id, tos::adnl::AdnlNodeIdFull{pub2}, addr, td::uint8(0));
    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_peer, src, tos::adnl::AdnlNodeIdFull{pub2}, addr);
    td::actor::send_closure(rldp, &tos::rldp2::Rldp::add_id, src);
    td::actor::send_closure(rldp, &tos::rldp2::Rldp::add_id, dst);
    td::actor::send_closure(network_manager, &tos::adnl::TestLoopbackNetworkManager::add_node_id, src, true, true);
    td::actor::send_closure(network_manager, &tos::adnl::TestLoopbackNetworkManager::add_node_id, dst, true, true);
    // Nothing is delivered, so the query below can never complete by itself.
    td::actor::send_closure(network_manager, &tos::adnl::TestLoopbackNetworkManager::set_loss_probability, 1.0);
  });

  bool answered = false;
  bool answered_with_error = false;
  scheduler.run_in_context([&] {
    td::actor::send_closure(rldp, &tos::rldp2::Rldp::send_query_ex, src, dst, std::string("q"),
                            td::PromiseCreator::lambda([&](td::Result<td::BufferSlice> R) {
                              answered = true;
                              answered_with_error = R.is_error();
                            }),
                            // Far beyond the run, so any answer comes from the
                            // eviction and not from the query's own timeout.
                            td::Timestamp::in(100000.0), td::BufferSlice("hello"), 1 << 20);
  });
  scheduler.run(0.05);

  // A flood of the shape a remote peer can produce: connections whose expiry
  // is one connection timeout from now, the same as an inbound message part
  // creates.
  scheduler.run_in_context([&] {
    for (td::uint32 i = 1; i <= kPeersToPresent; i++) {
      td::actor::send_closure(rldp, &tos::rldp2::Rldp::send_message, src, fabricated_peer(i), td::BufferSlice("x"));
    }
  });
  scheduler.run(0.5);

  auto fail = [&](td::Slice what) {
    LOG(ERROR) << "FAILED: " << what;
    td::rmrf(db_root).ignore();
    std::exit(1);
  };

  bool connection_gone = false;
  bool stats_answered = false;
  scheduler.run_in_context([&] {
    td::actor::send_closure(rldp, &tos::rldp2::Rldp::get_connection_stats,
                            td::PromiseCreator::lambda([&](td::Result<tos::rldp2::Rldp::ConnectionStats> R) {
                              R.ensure();
                              auto stats = R.move_as_ok();
                              stats_answered = true;
                              connection_gone = stats.evicted > 0;
                              LOG(ERROR) << "after the flood: " << stats.live << " live, " << stats.evicted
                                         << " evicted, " << stats.pending_queries << " queries still pending";
                            }));
  });
  scheduler.run(0.05);

  if (!stats_answered) {
    fail("the node never answered the connection stats query");
  }
  // Without evictions the flood never reached the cap and the run proves
  // nothing at all.
  if (!connection_gone) {
    fail("no connection was evicted, so nothing here was tested");
  }

  // First property: a flood of remotely-reachable shape cannot displace the
  // connection carrying a query, because that connection expires later than
  // anything the flood creates. If this ever stops holding, the hang below
  // becomes remotely reachable.
  if (answered) {
    fail("a flood displaced the connection carrying a query: the hang is remotely reachable");
  }

  // Now force the removal a remote peer cannot: work handed to the table with
  // a deadline beyond the query's, which pushes the query's connection to the
  // front of the expiry order.
  scheduler.run_in_context([&] {
    for (td::uint32 i = 1; i <= kPeersToPresent; i++) {
      td::actor::send_closure(rldp, &tos::rldp2::Rldp::send_message_ex, src, fabricated_peer(kPeersToPresent + i),
                              td::Timestamp::in(1000000.0), td::BufferSlice("x"));
    }
  });
  scheduler.run(0.5);

  size_t pending_after = 0;
  bool second_stats = false;
  scheduler.run_in_context([&] {
    td::actor::send_closure(rldp, &tos::rldp2::Rldp::get_connection_stats,
                            td::PromiseCreator::lambda([&](td::Result<tos::rldp2::Rldp::ConnectionStats> R) {
                              R.ensure();
                              pending_after = R.ok().pending_queries;
                              second_stats = true;
                            }));
  });
  scheduler.run(0.05);
  if (!second_stats) {
    fail("the node never answered the second connection stats query");
  }
  LOG(ERROR) << "after forcing the eviction: query answered=" << answered << " with_error=" << answered_with_error
             << ", " << pending_after << " queries still pending";

  if (!answered) {
    fail("the query whose connection was removed was never answered: the caller hangs and its record leaks");
  }
  if (!answered_with_error) {
    fail("the removed query reported success");
  }
  // The record has to go with it, or the table grows by one per removal.
  if (pending_after != 0) {
    fail(PSLICE() << "the removed query's record was left behind: " << pending_after << " still pending");
  }

  auto pending_now = [&](td::Slice what) {
    size_t pending = 0;
    bool answered_stats = false;
    scheduler.run_in_context([&] {
      td::actor::send_closure(rldp, &tos::rldp2::Rldp::get_connection_stats,
                              td::PromiseCreator::lambda([&](td::Result<tos::rldp2::Rldp::ConnectionStats> R) {
                                R.ensure();
                                pending = R.ok().pending_queries;
                                answered_stats = true;
                              }));
    });
    scheduler.run(0.05);
    if (!answered_stats) {
      fail(PSLICE() << "the node never answered the connection stats query " << what);
    }
    return pending;
  };

  // Every query entitles its peer to an answer that may use the part of the
  // inbound budget reserved for answers, so one peer may not hold more than
  // its bound of them. Nothing here is ever answered, so every admitted query
  // stays outstanding. The deadline is later than anything above, so no
  // connection carrying these is evicted while they are counted.
  const size_t per_connection = tos::rldp2::Rldp::MAX_PENDING_QUERIES_PER_CONNECTION;
  size_t refused_by_peer_bound = 0;
  size_t refused_otherwise = 0;
  scheduler.run_in_context([&] {
    for (size_t i = 0; i < per_connection + 16; i++) {
      td::actor::send_closure(rldp, &tos::rldp2::Rldp::send_query_ex, src, dst, std::string("q"),
                              td::PromiseCreator::lambda([&](td::Result<td::BufferSlice> R) {
                                if (R.is_ok()) {
                                  return;
                                }
                                if (R.error().message().str().find("from this peer") != std::string::npos) {
                                  ++refused_by_peer_bound;
                                } else {
                                  ++refused_otherwise;
                                }
                              }),
                              td::Timestamp::in(10000000.0), td::BufferSlice("x"), 1 << 20);
    }
  });
  scheduler.run(1.0);
  auto pending_on_one_peer = pending_now("after flooding one peer");
  LOG(ERROR) << "after flooding one peer: " << pending_on_one_peer << " pending, " << refused_by_peer_bound
             << " refused by the per-peer bound, " << refused_otherwise << " refused otherwise";
  if (pending_on_one_peer != per_connection) {
    fail(PSLICE() << "one peer holds " << pending_on_one_peer << " queries, not its bound of " << per_connection);
  }
  // Refused before sending, by the bound itself, not left to fail later.
  if (refused_by_peer_bound != 16 || refused_otherwise != 0) {
    fail("queries past the per-peer bound were not refused by it");
  }

  // A peer that accepts requests and never answers them decides how many
  // queries the node is holding, unless the total is capped. Spread over
  // enough peers that the per-peer bound does not stop them first.
  size_t refused = 0;
  const td::uint32 peers = static_cast<td::uint32>(tos::rldp2::Rldp::MAX_PENDING_QUERIES / per_connection + 8);
  scheduler.run_in_context([&] {
    for (td::uint32 peer = 1; peer <= peers; peer++) {
      for (size_t i = 0; i < per_connection; i++) {
        td::actor::send_closure(rldp, &tos::rldp2::Rldp::send_query_ex, src,
                                fabricated_peer(3 * kPeersToPresent + peer), std::string("q"),
                                td::PromiseCreator::lambda([&refused](td::Result<td::BufferSlice> R) {
                                  if (R.is_error()) {
                                    ++refused;
                                  }
                                }),
                                td::Timestamp::in(10000000.0), td::BufferSlice("x"), 1 << 20);
      }
    }
  });
  scheduler.run(1.0);

  auto pending_at_cap = pending_now("after flooding many peers");
  LOG(ERROR) << "after flooding queries: " << pending_at_cap << " pending, " << refused << " refused";

  if (pending_at_cap > tos::rldp2::Rldp::MAX_PENDING_QUERIES) {
    fail(PSLICE() << "outstanding queries grew past their cap: " << pending_at_cap);
  }
  // Refused, not silently dropped: a caller that gets no answer at all is the
  // hang this whole file is about.
  if (refused == 0) {
    fail("queries past the cap were neither admitted nor refused");
  }

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
