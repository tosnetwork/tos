/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <map>
#include <set>
#include <utility>

#include "adnl/adnl-node-id.hpp"
#include "td/utils/Time.h"
#include "td/utils/optional.h"

namespace tos::rldp2 {

// Connection bookkeeping is two views of one table that must stay in step: the
// connections themselves, and the expiry order eviction picks a victim from.
// Every removal goes through erase_connection below for exactly that reason --
// a view that drifts out of step leaks entries nothing can ever evict.
//
// The expiry order is partitioned by local id rather than global, because the
// eviction rule has to answer two questions cheaply: which connection of a
// given local id is the most idle, and which local ids are holding more than
// their share. A node has a handful of local ids, so a per-id order answers
// both by looking at the front of each partition, and the size of a partition
// is the id's connection count -- no separate counter to drift.
//
// Evicting picks the entry closest to expiring. A connection's expiry is
// refreshed on every packet it carries, so that entry is the one that has been
// quiet longest -- the best available proxy for "least likely to be in use",
// not a proof of it: a transfer stalled waiting on a retransmit is quiet too,
// and can be chosen. Losing it costs a re-create on the peer's next packet,
// which RLDP recovers from, so the trade-off is deliberate.
//
// Kept here, apart from the actor, so the rules can be exercised directly with
// the real key and timestamp types.
using PeerExpiryOrder = std::set<std::pair<td::Timestamp, adnl::AdnlNodeIdShort>>;
using RldpTimeoutSet = std::map<adnl::AdnlNodeIdShort, PeerExpiryOrder>;

// How many connections a local id currently holds.
inline size_t connections_held_by(const RldpTimeoutSet &timeout_set, adnl::AdnlNodeIdShort local_id) {
  auto it = timeout_set.find(local_id);
  return it == timeout_set.end() ? 0 : it->second.size();
}

// The earliest expiry across every local id, for the actor's alarm. Empty when
// there are no connections at all.
inline td::Timestamp earliest_expiry(const RldpTimeoutSet &timeout_set) {
  td::Timestamp earliest;
  for (auto &[local_id, order] : timeout_set) {
    if (!order.empty() && (!earliest || order.begin()->first.at() < earliest.at())) {
      earliest = order.begin()->first;
    }
  }
  return earliest;
}

// The single place a connection is added to the bookkeeping.
inline void record_connection(RldpTimeoutSet &timeout_set, adnl::AdnlNodeIdShort local_id,
                              adnl::AdnlNodeIdShort peer_id, td::Timestamp timeout) {
  timeout_set[local_id].emplace(timeout, peer_id);
}

// The single place a connection is removed.
template <typename ConnectionMap>
void erase_connection(ConnectionMap &connections, RldpTimeoutSet &timeout_set, adnl::AdnlNodeIdShort local_id,
                      adnl::AdnlNodeIdShort peer_id, td::Timestamp timeout) {
  connections.erase({local_id, peer_id});
  auto order = timeout_set.find(local_id);
  if (order == timeout_set.end()) {
    return;
  }
  order->second.erase({timeout, peer_id});
  if (order->second.empty()) {
    timeout_set.erase(order);
  }
}

// Refreshing an existing connection moves its place in the expiry order. It is
// neither added nor removed, so the local id's count must not change with it.
inline void refresh_connection(RldpTimeoutSet &timeout_set, adnl::AdnlNodeIdShort local_id,
                               adnl::AdnlNodeIdShort peer_id, td::Timestamp from, td::Timestamp to) {
  auto order = timeout_set.find(local_id);
  if (order == timeout_set.end()) {
    return;
  }
  order->second.erase({from, peer_id});
  order->second.emplace(to, peer_id);
}

// Who loses a connection when the table is full.
//
// The cap is global, so without this rule a flood arriving at one local id
// would spend the whole table and take another id's connections with it -- a
// node's public entry point could cost it the consensus peers of a different
// id. `per_local_id_share` is the number of connections a local id may hold
// before it must recycle its own instead of taking from anyone else:
//
//   - An id at or above its share evicts its own most idle connection. It is
//     never blocked from accepting new peers, and it never displaces another
//     id.
//   - An id below its share evicts the most idle connection belonging to some
//     id that is at or above its share. Because the table is full and the
//     shares divide the cap, such an id always exists.
//
// So a local id holding no more than its share can never lose a connection to
// another id's traffic. With a single local id the share is the whole cap and
// the rule reduces to plain most-idle eviction.
struct EvictionVictim {
  adnl::AdnlNodeIdShort local_id;
  adnl::AdnlNodeIdShort peer_id;
  td::Timestamp expiry;
};

inline td::optional<EvictionVictim> choose_eviction_victim(const RldpTimeoutSet &timeout_set,
                                                           adnl::AdnlNodeIdShort local_id,
                                                           size_t per_local_id_share) {
  auto front_of = [](const RldpTimeoutSet::const_iterator &it) {
    return EvictionVictim{it->first, it->second.begin()->second, it->second.begin()->first};
  };

  auto mine = timeout_set.find(local_id);
  if (mine != timeout_set.end() && !mine->second.empty() && mine->second.size() >= per_local_id_share) {
    return front_of(mine);
  }

  td::optional<EvictionVictim> best;
  auto consider = [&](const RldpTimeoutSet::const_iterator &it) {
    auto candidate = front_of(it);
    if (!best || candidate.expiry.at() < best.value().expiry.at()) {
      best = candidate;
    }
  };
  for (auto it = timeout_set.begin(); it != timeout_set.end(); ++it) {
    if (!it->second.empty() && it->second.size() >= per_local_id_share) {
      consider(it);
    }
  }
  if (best) {
    return best;
  }
  // No id is at or above its share, which a full table divided into equal
  // shares cannot produce. Fall back to the most idle connection anywhere
  // rather than let the table grow.
  for (auto it = timeout_set.begin(); it != timeout_set.end(); ++it) {
    if (!it->second.empty()) {
      consider(it);
    }
  }
  return best;
}

struct AdmissionResult {
  // Whether the caller may insert the new connection.
  bool admitted{false};
  // How many existing connections had to be dropped to make room. Non-zero
  // means the table is at its cap, which is worth surfacing: under normal
  // operation it never is.
  size_t evicted{0};
};

// Admission for a new connection: evict until there is room, then report
// whether the caller may insert. Returning the decision rather than doing the
// insert keeps the rules testable on their own.
template <typename ConnectionMap>
AdmissionResult admit_connection(ConnectionMap &connections, RldpTimeoutSet &timeout_set, size_t max_connections,
                                 adnl::AdnlNodeIdShort local_id, size_t per_local_id_share) {
  AdmissionResult result;
  while (connections.size() >= max_connections) {
    auto victim = choose_eviction_victim(timeout_set, local_id, per_local_id_share);
    if (!victim) {
      // The order is empty while the table is not, which means the two views
      // have drifted apart. Refuse rather than grow.
      return result;
    }
    auto &chosen = victim.value();
    erase_connection(connections, timeout_set, chosen.local_id, chosen.peer_id, chosen.expiry);
    ++result.evicted;
  }
  result.admitted = true;
  return result;
}

}  // namespace tos::rldp2
