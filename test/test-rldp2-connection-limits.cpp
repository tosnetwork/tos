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
// by evicting whenever the cap is reached.
//
// Two rules decide the victim, and these tests pin both. The table never
// exceeds the cap, however long the flood runs. And a local id holding no more
// than its share of the cap never loses a connection to another id's traffic:
// a node's public entry point cannot cost it the consensus peers of a
// different id. The connection chosen is the one quiet longest, which is the
// best available proxy for "least likely to be in use", not a guarantee -- a
// transfer stalled on a retransmit is quiet too.
//
// The tests also pin that the two views of the table -- the connections and
// the expiry order they are evicted through -- are always mutated together. If
// they drifted apart the table would leak entries nothing could ever evict.

#include "rldp2/rldp-connection-limits.h"

#include "td/utils/tests.h"

#include <map>

namespace tos {
namespace {

using Key = std::pair<adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort>;
using Table = std::map<Key, int>;

adnl::AdnlNodeIdShort peer(td::uint8 n, td::uint8 high = 0) {
  td::Bits256 bits;
  bits.set_zero();
  bits.as_slice()[0] = static_cast<char>(n);
  bits.as_slice()[1] = static_cast<char>(high);
  return adnl::AdnlNodeIdShort{bits};
}

// Seed one connection into both views, the way the actor does.
void add(Table &connections, rldp2::RldpTimeoutSet &timeouts, adnl::AdnlNodeIdShort local_id,
         adnl::AdnlNodeIdShort peer_id, double expiry) {
  connections[{local_id, peer_id}] = 1;
  rldp2::record_connection(timeouts, local_id, peer_id, td::Timestamp::at(expiry));
}

size_t total_ordered(const rldp2::RldpTimeoutSet &timeouts) {
  size_t total = 0;
  for (auto &[local_id, order] : timeouts) {
    total += order.size();
  }
  return total;
}

// Evict once, whoever the rule picks. Returns false when there was nothing to
// evict.
bool evict_once(Table &connections, rldp2::RldpTimeoutSet &timeouts, adnl::AdnlNodeIdShort local_id, size_t share) {
  auto victim = rldp2::choose_eviction_victim(timeouts, local_id, share);
  if (!victim) {
    return false;
  }
  auto &chosen = victim.value();
  rldp2::erase_connection(connections, timeouts, chosen.local_id, chosen.peer_id, chosen.expiry);
  return true;
}

TEST(Rldp2ConnectionLimits, EvictsTheEntryClosestToExpiring) {
  Table connections;
  rldp2::RldpTimeoutSet timeouts;
  auto local = peer(0);

  // Three peers, refreshed at different times: peer(3) is the most idle.
  add(connections, timeouts, local, peer(1), 300.0);
  add(connections, timeouts, local, peer(2), 200.0);
  add(connections, timeouts, local, peer(3), 100.0);

  EXPECT(evict_once(connections, timeouts, local, 8));
  EXPECT(connections.size() == 2);
  EXPECT(total_ordered(timeouts) == 2);
  // The most idle peer is gone; the two used more recently remain.
  EXPECT(!connections.contains({local, peer(3)}));
  EXPECT(connections.contains({local, peer(1)}));
  EXPECT(connections.contains({local, peer(2)}));
}

TEST(Rldp2ConnectionLimits, EvictionKeepsBothViewsInStep) {
  Table connections;
  rldp2::RldpTimeoutSet timeouts;
  auto local = peer(0);
  for (td::uint8 n = 1; n <= 8; ++n) {
    add(connections, timeouts, local, peer(n), 100.0 + n);
  }

  while (evict_once(connections, timeouts, local, 8)) {
    EXPECT(connections.size() == total_ordered(timeouts));
  }
  EXPECT(connections.empty());
  EXPECT(timeouts.empty());
  // An emptied local id leaves no phantom partition behind.
  EXPECT(rldp2::connections_held_by(timeouts, local) == 0);
}

TEST(Rldp2ConnectionLimits, RefreshingMovesAConnectionWithoutChangingTheCount) {
  Table connections;
  rldp2::RldpTimeoutSet timeouts;
  auto local = peer(0);
  add(connections, timeouts, local, peer(1), 100.0);
  add(connections, timeouts, local, peer(2), 200.0);

  // peer(1) carries a packet and is no longer the most idle.
  rldp2::refresh_connection(timeouts, local, peer(1), td::Timestamp::at(100.0), td::Timestamp::at(300.0));
  EXPECT(rldp2::connections_held_by(timeouts, local) == 2);

  EXPECT(evict_once(connections, timeouts, local, 8));
  EXPECT(!connections.contains({local, peer(2)}));
  EXPECT(connections.contains({local, peer(1)}));
}

// The property that matters at the call site: no matter how many distinct
// peers arrive, the table never grows past the cap.
TEST(Rldp2ConnectionLimits, AdmissionHoldsTheTableAtTheCap) {
  constexpr size_t kCap = 8;
  Table connections;
  rldp2::RldpTimeoutSet timeouts;
  auto local = peer(0);

  // Every peer is distinct and every one is admitted -- this is the flood the
  // cap exists for. Peers arrive in order, so each new one is more recently
  // active than everything already in the table.
  size_t evicted_total = 0;
  for (td::uint16 n = 1; n <= 300; ++n) {
    auto admission = rldp2::admit_connection(connections, timeouts, kCap, local, kCap);
    EXPECT(admission.admitted);
    evicted_total += admission.evicted;
    auto peer_id = peer(static_cast<td::uint8>(n & 0xff), static_cast<td::uint8>(n >> 8));
    add(connections, timeouts, local, peer_id, 100.0 + n);
    EXPECT(connections.size() <= kCap);
    EXPECT(connections.size() == total_ordered(timeouts));
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
  Table connections;
  rldp2::RldpTimeoutSet timeouts;
  auto local = peer(0);
  for (td::uint8 n = 1; n <= 3; ++n) {
    add(connections, timeouts, local, peer(n), 100.0 + n);
  }

  // Room to spare: admitting must not evict anyone.
  auto admission = rldp2::admit_connection(connections, timeouts, 8, local, 8);
  EXPECT(admission.admitted);
  EXPECT(admission.evicted == 0);
  EXPECT(connections.size() == 3);
}

TEST(Rldp2ConnectionLimits, AdmissionRefusesRatherThanGrowWhenTheOrderIsLost) {
  Table connections;
  rldp2::RldpTimeoutSet timeouts;
  auto local = peer(0);
  // A table at the cap with no expiry order: nothing can be chosen for
  // eviction. Refusing the connection keeps the bound; admitting anyway would
  // let the table grow without limit for the rest of the process's life.
  for (td::uint8 n = 1; n <= 4; ++n) {
    connections[{local, peer(n)}] = n;
  }
  EXPECT(!rldp2::admit_connection(connections, timeouts, 4, local, 4).admitted);
  EXPECT(connections.size() == 4);
}

// ─── the fairness rule ────────────────────────────────────────────────

TEST(Rldp2ConnectionLimits, AFloodedLocalIdRecyclesItsOwnInsteadOfTakingFromAnother) {
  constexpr size_t kCap = 8;
  constexpr size_t kShare = 4;
  Table connections;
  rldp2::RldpTimeoutSet timeouts;
  auto flooded = peer(0);
  auto other = peer(200);

  // The other id's connections are the quietest in the whole table -- exactly
  // what a purely global rule would pick off first.
  for (td::uint8 n = 1; n <= 4; ++n) {
    add(connections, timeouts, other, peer(n), 100.0 + n);
  }
  for (td::uint8 n = 5; n <= 8; ++n) {
    add(connections, timeouts, flooded, peer(n), 200.0 + n);
  }

  auto admission = rldp2::admit_connection(connections, timeouts, kCap, flooded, kShare);
  EXPECT(admission.admitted);
  EXPECT(admission.evicted == 1);
  // It took the slot from itself, and the other id is untouched.
  EXPECT(rldp2::connections_held_by(timeouts, other) == 4);
  EXPECT(rldp2::connections_held_by(timeouts, flooded) == 3);
  EXPECT(!connections.contains({flooded, peer(5)}));
}

TEST(Rldp2ConnectionLimits, AFloodCannotStarveAnotherLocalIdHoweverLongItRuns) {
  constexpr size_t kCap = 8;
  constexpr size_t kShare = 4;
  Table connections;
  rldp2::RldpTimeoutSet timeouts;
  auto flooded = peer(0);
  auto quiet = peer(200);

  // Two connections belonging to a second local id, established first and then
  // never used again, so they stay at the head of the expiry order forever.
  add(connections, timeouts, quiet, peer(1), 1.0);
  add(connections, timeouts, quiet, peer(2), 2.0);

  for (td::uint16 n = 1; n <= 500; ++n) {
    auto admission = rldp2::admit_connection(connections, timeouts, kCap, flooded, kShare);
    EXPECT(admission.admitted);
    add(connections, timeouts, flooded, peer(static_cast<td::uint8>(n & 0xff), static_cast<td::uint8>(n >> 8)),
        100.0 + n);
    EXPECT(connections.size() <= kCap);
  }

  // Both of the quiet id's connections are still there after five hundred
  // admissions that each had a quieter victim available.
  EXPECT(rldp2::connections_held_by(timeouts, quiet) == 2);
  EXPECT(connections.contains({quiet, peer(1)}));
  EXPECT(connections.contains({quiet, peer(2)}));
}

TEST(Rldp2ConnectionLimits, ALocalIdBelowItsShareTakesFromAnOverServedOne) {
  constexpr size_t kCap = 8;
  constexpr size_t kShare = 4;
  Table connections;
  rldp2::RldpTimeoutSet timeouts;
  auto hog = peer(0);
  auto starved = peer(200);

  // One id holds the whole table; a second has nothing and asks for a slot.
  for (td::uint8 n = 1; n <= 8; ++n) {
    add(connections, timeouts, hog, peer(n), 100.0 + n);
  }

  auto admission = rldp2::admit_connection(connections, timeouts, kCap, starved, kShare);
  EXPECT(admission.admitted);
  EXPECT(admission.evicted == 1);
  EXPECT(rldp2::connections_held_by(timeouts, hog) == 7);
}

TEST(Rldp2ConnectionLimits, ASingleLocalIdBehavesAsPlainMostIdleEviction) {
  constexpr size_t kCap = 4;
  Table connections;
  rldp2::RldpTimeoutSet timeouts;
  auto only = peer(0);
  // With one local id the share is the whole cap, so the fairness rule must
  // not change anything: the most idle connection is still the victim.
  for (td::uint8 n = 1; n <= 4; ++n) {
    add(connections, timeouts, only, peer(n), 100.0 + n);
  }

  auto admission = rldp2::admit_connection(connections, timeouts, kCap, only, kCap);
  EXPECT(admission.admitted);
  EXPECT(!connections.contains({only, peer(1)}));
  EXPECT(connections.size() == 3);
}

TEST(Rldp2ConnectionLimits, TheAlarmSeesTheEarliestExpiryAcrossEveryLocalId) {
  rldp2::RldpTimeoutSet timeouts;
  EXPECT(!rldp2::earliest_expiry(timeouts));

  rldp2::record_connection(timeouts, peer(0), peer(1), td::Timestamp::at(500.0));
  rldp2::record_connection(timeouts, peer(200), peer(2), td::Timestamp::at(100.0));
  rldp2::record_connection(timeouts, peer(201), peer(3), td::Timestamp::at(300.0));

  // Partitioning the order by local id must not hide the globally earliest
  // expiry, or connections would outlive their timeout.
  auto next = rldp2::earliest_expiry(timeouts);
  EXPECT(next);
  EXPECT(next.at() == td::Timestamp::at(100.0).at());
}

// Understating the share inverts the rule: every id reads as at or above it,
// so nobody may take a slot from anybody. An id holding a single connection
// can then only recycle that one, however idle the rest of the table is.
TEST(Rldp2ConnectionLimits, AnUnderstatedShareWedgesAnIdOnTheConnectionsItHas) {
  constexpr size_t kCap = 8;
  auto small = peer(0);
  auto hog = peer(200);
  auto seed = [&](Table &connections, rldp2::RldpTimeoutSet &timeouts) {
    add(connections, timeouts, small, peer(1), 1.0);
    for (td::uint8 n = 2; n <= 8; ++n) {
      add(connections, timeouts, hog, peer(n), 100.0 + n);
    }
  };

  // A share of one: the id holding a single connection is already "at its
  // share", so it evicts that connection to make room and gains nothing.
  Table understated;
  rldp2::RldpTimeoutSet understated_timeouts;
  seed(understated, understated_timeouts);
  auto wedged = rldp2::admit_connection(understated, understated_timeouts, kCap, small, 1);
  EXPECT(wedged.admitted);
  EXPECT(!understated.contains({small, peer(1)}));
  EXPECT(rldp2::connections_held_by(understated_timeouts, hog) == 7);

  // The share the rule actually computes for two holders of an eight slot
  // table. Now the small id is well below it and takes a slot from the id
  // that is over its own.
  Table correct;
  rldp2::RldpTimeoutSet correct_timeouts;
  seed(correct, correct_timeouts);
  auto share = rldp2::per_local_id_share(kCap, correct_timeouts.size());
  EXPECT(share == 4);
  auto ok = rldp2::admit_connection(correct, correct_timeouts, kCap, small, share);
  EXPECT(ok.admitted);
  EXPECT(correct.contains({small, peer(1)}));
  EXPECT(rldp2::connections_held_by(correct_timeouts, hog) == 6);
}

// The share must follow the ids that actually hold connections. Registered
// but idle ids would shrink it forever, since nothing ever unregisters one.
TEST(Rldp2ConnectionLimits, TheShareFollowsLiveHoldersAndNeverReachesZero) {
  // One busy local id gets the whole cap; competition tightens it.
  EXPECT(rldp2::per_local_id_share(4096, 0) == 4096);
  EXPECT(rldp2::per_local_id_share(4096, 1) == 4096);
  EXPECT(rldp2::per_local_id_share(4096, 2) == 2048);
  EXPECT(rldp2::per_local_id_share(4096, 4) == 1024);
  // A holder count cannot exceed the cap, but the floor holds if one ever did.
  EXPECT(rldp2::per_local_id_share(4096, 4096) == 1);
  EXPECT(rldp2::per_local_id_share(4096, 100000) == 1);
}

}  // namespace
}  // namespace tos
