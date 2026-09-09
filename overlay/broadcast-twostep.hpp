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
#include <memory>
#include <utility>

#include "adnl/adnl-node-id.hpp"
#include "auto/tl/tos_api.h"
#include "keys/keys.hpp"
#include "td/utils/Status.h"
#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/int_types.h"

#include "overlay.h"

namespace tos {

namespace overlay {

class OverlayImpl;
struct BroadcastTwostep;
struct BroadcastTwostepDataSimple;
struct BroadcastTwostepDataFec;

class BroadcastsTwostep {
 public:
  BroadcastsTwostep();
  ~BroadcastsTwostep();
  void send(OverlayImpl *overlay, PublicKeyHash send_as, td::BufferSlice data, td::BufferSlice extra, td::uint32 flags);
  void signed_simple(OverlayImpl *overlay, BroadcastTwostepDataSimple &&data,
                     td::Result<std::pair<td::BufferSlice, PublicKey>> &&R);
  void signed_fec(OverlayImpl *overlay, BroadcastTwostepDataFec &&data,
                  td::Result<std::pair<td::BufferSlice, PublicKey>> &&R);
  td::actor::Task<> process_broadcast(OverlayImpl *overlay, adnl::AdnlNodeIdShort src_peer_id,
                                      tl_object_ptr<tos_api::overlay_broadcastTwostepSimple> broadcast);
  td::actor::Task<> process_broadcast(OverlayImpl *overlay, adnl::AdnlNodeIdShort src_peer_id,
                                      tl_object_ptr<tos_api::overlay_broadcastTwostepFec> broadcast);
  void gc(OverlayImpl *overlay);

  void init_sender(td::actor::ActorId<adnl::AdnlSenderInterface> sender) {
    sender_ = std::move(sender);
  }

 private:
  td::actor::ActorId<adnl::AdnlSenderInterface> sender_;
  std::map<Overlay::BroadcastHash, std::unique_ptr<BroadcastTwostep>> broadcasts_;
  // Index of in-flight broadcasts ordered by their (sender-supplied) date, which
  // is what gc expires on. Insertion order is not date order -- the accepted
  // date may lead or lag arrival -- so an insertion-ordered list cannot let gc
  // stop at the first fresh entry. Ordering by date lets gc evict every expired
  // entry and stop as soon as the earliest remaining date is fresh, and lets the
  // admission path tell in O(1) whether anything can be reclaimed.
  std::multimap<td::uint32, Overlay::BroadcastHash> by_date_;

  td::uint64 rebroadcast(OverlayImpl *overlay, const adnl::AdnlNodeIdShort &bcast_src_adnl_id,
                         const td::BufferSlice &data);

  // In-flight admission ceiling, checked in process_broadcast at the commit
  // point before a new broadcast is created. When the table is full it first
  // reclaims entries past the assembly window (a gc pass) and only then, if
  // still full, refuses the newcomer rather than evicting one being assembled.
  // Reclaiming first matters on fixed-member overlays, whose periodic gc can be
  // tens of seconds apart while the 25 s assembly window is shorter, so the
  // table can be full of already-expired entries. This is a receiver-side path,
  // so there is no is_ours exemption.
  td::Status ensure_in_flight_capacity(OverlayImpl *overlay);

  // The single insertion primitive for a new in-flight broadcast: it applies the
  // capacity gate and, only if admitted, tracks the broadcast in both indexes.
  // process_broadcast inserts only through here, so the gate and the insert are
  // inseparable -- a test that drives this at capacity fails if the gate is
  // removed, and an insertion that bypassed it would not assemble the broadcast
  // at all (caught by the end-to-end receive path).
  td::Status admit_and_track(OverlayImpl *overlay, td::uint32 date, Overlay::BroadcastHash broadcast_id,
                             std::unique_ptr<BroadcastTwostep> bcast);

  // Test support: inject a decoder-less in-flight entry with a chosen date and
  // read the table size, so gc() and the admission ceiling can be exercised
  // without standing up real FEC state and crypto. try_admit_fresh_for_test
  // drives the real admit_and_track primitive with a synthetic entry, covering
  // the production insertion gate. Defined where BroadcastTwostep is a complete
  // type.
  void inject_in_flight_for_test(Overlay::BroadcastHash broadcast_id, td::uint32 date);
  size_t in_flight_count_for_test() const;
  size_t capacity_for_test() const;
  td::Status try_admit_fresh_for_test(OverlayImpl *overlay, Overlay::BroadcastHash broadcast_id);
  friend class BroadcastsTwostepTestAccess;
};
}  // namespace overlay

}  // namespace tos
