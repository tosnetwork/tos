/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <set>
#include <tuple>

#include "adnl/adnl-node-id.hpp"
#include "td/utils/Time.h"

namespace tos::rldp2 {

// Connection bookkeeping is two containers that must stay in step: the table
// itself and the expiry order. Evicting picks the entry closest to expiring.
// A connection's expiry is refreshed on every packet it carries, so that entry
// is the one that has been quiet longest -- which is the best available proxy
// for "least likely to be in use", not a proof of it: a transfer stalled
// waiting on a retransmit is quiet too, and can be chosen. Losing it costs a
// re-create on the peer's next packet, which RLDP recovers from, so the
// trade-off is deliberate. Kept here, apart from the actor, so the rule can be
// exercised directly with the real key and timestamp types.
using RldpTimeoutSet = std::set<std::tuple<td::Timestamp, adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort>>;

template <typename ConnectionMap>
bool evict_most_idle_connection(ConnectionMap &connections, RldpTimeoutSet &timeout_set) {
  if (timeout_set.empty()) {
    return false;
  }
  auto it = timeout_set.begin();
  auto [timeout, local_id, peer_id] = *it;
  connections.erase({local_id, peer_id});
  timeout_set.erase(it);
  return true;
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
// insert keeps the size rule testable on its own.
template <typename ConnectionMap>
AdmissionResult admit_connection(ConnectionMap &connections, RldpTimeoutSet &timeout_set, size_t max_connections) {
  AdmissionResult result;
  while (connections.size() >= max_connections) {
    if (!evict_most_idle_connection(connections, timeout_set)) {
      // Nothing left to evict: the order is empty while the table is not,
      // which means the two have drifted apart. Refuse rather than grow.
      return result;
    }
    ++result.evicted;
  }
  result.admitted = true;
  return result;
}

}  // namespace tos::rldp2
