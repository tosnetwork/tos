/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <map>
#include <set>

#include "adnl/adnl-node-id.hpp"
#include "auto/tl/tos_api.h"
#include "fec/fec.h"
#include "keys/keys.hpp"
#include "overlay/overlay.h"

namespace tos {

namespace overlay {

class OverlayImpl;
class BroadcastFec;
class BroadcastFecPart;

class BroadcastsFec {
 public:
  BroadcastsFec();
  ~BroadcastsFec();
  void send(OverlayImpl *overlay, PublicKeyHash send_as, td::BufferSlice data, td::uint32 flags,
            double speed_multiplier);
  void send_part(OverlayImpl *overlay, PublicKeyHash send_as, Overlay::BroadcastDataHash data_hash, td::uint32 size,
                 td::uint32 flags, td::BufferSlice part, td::uint32 seqno, fec::FecType fec_type, td::uint32 date);
  void signed_(OverlayImpl *overlay, std::unique_ptr<BroadcastFecPart> &&part,
               td::Result<std::pair<td::BufferSlice, PublicKey>> &&R);
  td::Status process_broadcast(OverlayImpl *overlay, adnl::AdnlNodeIdShort src_peer_id,
                               tl_object_ptr<tos_api::overlay_broadcastFec> broadcast);
  td::Status process_broadcast(OverlayImpl *overlay, adnl::AdnlNodeIdShort src_peer_id,
                               tl_object_ptr<tos_api::overlay_broadcastFecShort> broadcast);
  void checked(OverlayImpl *overlay, Overlay::BroadcastHash &&hash, td::Result<td::Unit> &&R);
  void gc(OverlayImpl *overlay);

 private:
  td::Status process(OverlayImpl *overlay, BroadcastFecPart &part, bool is_ours);

  // In-flight admission ceiling, checked in process() before a new broadcast is
  // created. When the table is full it first reclaims entries past the assembly
  // window (a gc pass) and only then, if still full, refuses the newcomer --
  // rather than evicting one already being assembled. Reclaiming first matters
  // on fixed-member overlays, whose periodic gc can be tens of seconds apart
  // while the assembly window is much shorter, so the table can be full of
  // already-expired entries. Our own (is_ours) broadcasts are locally paced and
  // exempt, so this bounds the inbound/remote table, not locally originated
  // broadcasts.
  td::Status ensure_in_flight_capacity(OverlayImpl *overlay, bool is_ours);

  std::map<Overlay::BroadcastHash, std::unique_ptr<BroadcastFec>> broadcasts_;
  // Index of in-flight broadcasts ordered by their (sender-supplied) date, which
  // is what gc expires on. Insertion order is not date order -- the accepted
  // date may lead or lag arrival -- so an insertion-ordered list cannot let gc
  // stop at the first fresh entry. Ordering by date lets gc evict every expired
  // entry and stop as soon as the earliest remaining date is fresh, and lets the
  // admission path tell in O(1) whether anything can be reclaimed.
  std::multimap<td::uint32, Overlay::BroadcastHash> by_date_;

  // Test support: inject a decoder-less in-flight entry with a chosen date and
  // read the table size, so gc() and the admission ceiling can be exercised
  // without standing up real FEC state and crypto. try_process_fresh_for_test
  // drives the real process() with a minimal part carrying a fresh hash, so the
  // production admission wiring (not just the predicate) is covered. Defined
  // where BroadcastFec is a complete type.
  void inject_in_flight_for_test(Overlay::BroadcastHash hash, td::uint32 date);
  size_t in_flight_count_for_test() const;
  size_t capacity_for_test() const;
  td::Status try_process_fresh_for_test(OverlayImpl *overlay, Overlay::BroadcastHash hash, bool is_ours);
  friend class BroadcastsFecTestAccess;
};

}  // namespace overlay

}  // namespace tos
