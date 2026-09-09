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
#include "td/utils/List.h"
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
  td::ListNode lru_;

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

  // Test support: inject a decoder-less in-flight entry with a chosen date and
  // read the table size, so gc() and the admission ceiling can be exercised
  // without standing up real FEC state and crypto. Defined where
  // BroadcastTwostep is a complete type.
  void inject_in_flight_for_test(Overlay::BroadcastHash broadcast_id, td::uint32 date);
  size_t in_flight_count_for_test() const;
  size_t capacity_for_test() const;
  friend class BroadcastsTwostepTestAccess;
};
}  // namespace overlay

}  // namespace tos
