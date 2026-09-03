/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// An inbound RLDP message part creates a connection for whatever source id it
// claims, and ADNL source ids cost nothing to mint, so the connection table is
// attacker-driven. It is bounded by evicting the entry closest to expiring
// whenever the cap is reached. Because the expiry of a connection is refreshed
// on every packet it carries, the entry chosen is always the most idle one --
// a peer in the middle of a transfer is never the victim. These tests pin that
// rule and, just as importantly, that the table and the expiry order are
// always mutated together: if they drifted apart the table would leak entries
// that nothing could ever evict.

#include "rldp2/rldp-connection-limits.h"

#include "td/utils/tests.h"

#include <map>

namespace tos {
namespace {

using Key = std::pair<adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort>;

adnl::AdnlNodeIdShort peer(td::uint8 n) {
  td::Bits256 bits;
  bits.set_zero();
  bits.as_slice()[0] = n;
  return adnl::AdnlNodeIdShort{bits};
}

TEST(Rldp2ConnectionLimits, EvictsTheEntryClosestToExpiring) {
  std::map<Key, int> connections;
  rldp2::RldpTimeoutSet timeouts;

  auto local = peer(0);
  // Three peers, refreshed at different times: peer(3) is the most idle.
  for (auto [n, at] : {std::pair<td::uint8, double>{1, 300.0}, {2, 200.0}, {3, 100.0}}) {
    connections[{local, peer(n)}] = n;
    timeouts.emplace(td::Timestamp::at(at), local, peer(n));
  }

  EXPECT(rldp2::evict_most_idle_connection(connections, timeouts));
  EXPECT(connections.size() == 2);
  EXPECT(timeouts.size() == 2);
  // The most idle peer is gone; the two that were used more recently remain.
  EXPECT(!connections.contains({local, peer(3)}));
  EXPECT(connections.contains({local, peer(1)}));
  EXPECT(connections.contains({local, peer(2)}));
}

TEST(Rldp2ConnectionLimits, EvictionKeepsTableAndExpiryOrderInStep) {
  std::map<Key, int> connections;
  rldp2::RldpTimeoutSet timeouts;
  auto local = peer(0);
  for (td::uint8 n = 1; n <= 8; ++n) {
    connections[{local, peer(n)}] = n;
    timeouts.emplace(td::Timestamp::at(100.0 + n), local, peer(n));
  }

  // Draining must remove from both containers in lockstep and stop cleanly.
  while (rldp2::evict_most_idle_connection(connections, timeouts)) {
    EXPECT(connections.size() == timeouts.size());
  }
  EXPECT(connections.empty());
  EXPECT(timeouts.empty());
  // Evicting an empty table reports that there was nothing to drop.
  EXPECT(!rldp2::evict_most_idle_connection(connections, timeouts));
}

}  // namespace
}  // namespace tos
