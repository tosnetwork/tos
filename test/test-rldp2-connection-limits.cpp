/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// An inbound RLDP message part creates a connection for its source id. ADNL
// authenticates that id, so the sender really holds the key -- but keys cost
// nothing to generate, so an attacker supplies as many legitimate identities
// as it likes and the connection table is still attacker-driven. It is bounded
// by evicting the entry closest to expiring whenever the cap is reached. A
// connection's expiry is refreshed on every packet it carries, so the entry
// chosen is the one quiet longest: the best available proxy for "least likely
// to be in use", not a guarantee -- a transfer stalled on a retransmit is
// quiet too. Losing it costs a re-create on the peer's next packet.
//
// These tests pin the admission rule (the table never exceeds the cap, however
// long the flood runs) and that the table and the expiry order are always
// mutated together: if they drifted apart the table would leak entries that
// nothing could ever evict.

#include "rldp2/rldp-connection-limits.h"

#include "td/utils/tests.h"

#include <map>

namespace tos {
namespace {

using Key = std::pair<adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort>;

adnl::AdnlNodeIdShort peer(td::uint8 n, td::uint8 high = 0) {
  td::Bits256 bits;
  bits.set_zero();
  bits.as_slice()[0] = static_cast<char>(n);
  bits.as_slice()[1] = static_cast<char>(high);
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

// The property that matters at the call site: no matter how many distinct
// peers arrive, the table never grows past the cap.
TEST(Rldp2ConnectionLimits, AdmissionHoldsTheTableAtTheCap) {
  constexpr size_t kCap = 8;
  std::map<Key, int> connections;
  rldp2::RldpTimeoutSet timeouts;
  auto local = peer(0);

  // Every peer is distinct and every one is admitted -- this is the flood the
  // cap exists for. Peers arrive in order, so each new one is more recently
  // active than everything already in the table.
  size_t evicted_total = 0;
  for (td::uint16 n = 1; n <= 300; ++n) {
    auto admission = rldp2::admit_connection(connections, timeouts, kCap);
    EXPECT(admission.admitted);
    evicted_total += admission.evicted;
    Key key{local, peer(static_cast<td::uint8>(n & 0xff), static_cast<td::uint8>(n >> 8))};
    connections[key] = n;
    timeouts.emplace(td::Timestamp::at(100.0 + n), key.first, key.second);
    EXPECT(connections.size() <= kCap);
    EXPECT(connections.size() == timeouts.size());
  }
  EXPECT(connections.size() == kCap);
  // Every peer past the first kCap displaced exactly one, and the count is
  // reported: an operator can tell a cap being exercised from one that is not.
  EXPECT(evicted_total == 300 - kCap);

  // What survives is the most recent window, not an arbitrary subset.
  for (td::uint16 n = 300 - kCap + 1; n <= 300; ++n) {
    EXPECT(connections.contains({local, peer(static_cast<td::uint8>(n & 0xff), static_cast<td::uint8>(n >> 8))}));
  }
}

TEST(Rldp2ConnectionLimits, AdmissionIsANoOpBelowTheCap) {
  std::map<Key, int> connections;
  rldp2::RldpTimeoutSet timeouts;
  auto local = peer(0);
  for (td::uint8 n = 1; n <= 3; ++n) {
    connections[{local, peer(n)}] = n;
    timeouts.emplace(td::Timestamp::at(100.0 + n), local, peer(n));
  }

  // Room to spare: admitting must not evict anyone.
  auto admission = rldp2::admit_connection(connections, timeouts, 8);
  EXPECT(admission.admitted);
  EXPECT(admission.evicted == 0);
  EXPECT(connections.size() == 3);
  EXPECT(timeouts.size() == 3);
}

TEST(Rldp2ConnectionLimits, AdmissionRefusesRatherThanGrowWhenTheOrderIsLost) {
  std::map<Key, int> connections;
  rldp2::RldpTimeoutSet timeouts;
  auto local = peer(0);
  // A table at the cap with no expiry order: nothing can be chosen for
  // eviction. Refusing the connection keeps the bound; admitting anyway would
  // let the table grow without limit for the rest of the process's life.
  for (td::uint8 n = 1; n <= 4; ++n) {
    connections[{local, peer(n)}] = n;
  }
  EXPECT(!rldp2::admit_connection(connections, timeouts, 4).admitted);
  EXPECT(connections.size() == 4);
}

}  // namespace
}  // namespace tos
