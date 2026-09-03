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
// itself and the expiry order. Evicting picks the entry closest to expiring --
// a connection's expiry is refreshed on every packet it carries, so that entry
// is the most idle peer and never one in the middle of a transfer -- and drops
// it from both. Kept here, apart from the actor, so the rule can be exercised
// directly with the real key and timestamp types.
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

}  // namespace tos::rldp2
