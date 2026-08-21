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

#include <bitset>

#include "td/actor/PromiseFuture.h"
#include "td/actor/actor.h"
#include "td/utils/port/IPAddress.h"

#include "adnl-node-id.hpp"
#include "adnl-proxy-types.h"

namespace td {
class UdpServer;
}

namespace tos {

namespace adnl {

class AdnlPeerTable;

using AdnlCategoryMask = std::bitset<256>;

class AdnlNetworkConnection : public td::actor::Actor {
 public:
  class Callback {
   public:
    virtual void on_change_state(bool ready) = 0;
    virtual ~Callback() = default;
  };
  virtual void send(AdnlNodeIdShort src, AdnlNodeIdShort dst, td::uint32 priority, td::BufferSlice message) = 0;
  virtual bool is_alive() const = 0;
  virtual bool is_active() const = 0;

  virtual void get_ip_str(td::Promise<td::string> promise) = 0;
  virtual ~AdnlNetworkConnection() = default;
};

class AdnlNetworkManager : public td::actor::Actor {
 public:
  struct PacketSuppressionStats {
    td::uint64 inbound{0};
    td::uint64 outbound{0};

    td::uint64 total() const {
      return inbound + outbound;
    }
  };

  //using ConnHandle = td::uint64;
  class Callback {
   public:
    virtual ~Callback() = default;
    //virtual void receive_packet(td::IPAddress addr, ConnHandle conn_handle, td::BufferSlice data) = 0;
    virtual void receive_packet(td::IPAddress addr, AdnlCategoryMask cat_mask, td::BufferSlice data) = 0;
  };
  static td::actor::ActorOwn<AdnlNetworkManager> create(td::uint16 out_port);

  virtual ~AdnlNetworkManager() = default;

  virtual void install_callback(std::unique_ptr<Callback> callback) = 0;

  virtual void add_self_addr(td::IPAddress addr, AdnlCategoryMask cat_mask, td::uint32 priority) = 0;
  virtual void add_proxy_addr(td::IPAddress addr, td::uint16 local_port, std::shared_ptr<AdnlProxy> proxy,
                              AdnlCategoryMask cat_mask, td::uint32 priority) = 0;
  virtual void send_udp_packet(AdnlNodeIdShort src_id, AdnlNodeIdShort dst_id, td::IPAddress dst_addr,
                               td::uint32 priority, td::BufferSlice data) = 0;
  //virtual void send_tcp_packet(AdnlNodeIdShort src_id, AdnlNodeIdShort dst_id, td::IPAddress dst_addr,
  //                             td::uint32 priority, td::BufferSlice data) = 0;
  //virtual void send_answer_packet(AdnlNodeIdShort src_id, AdnlNodeIdShort dst_id, td::IPAddress dst_addr,
  //                             ConnHandle conn_handle, td::uint32 priority, td::BufferSlice data) = 0;
  virtual void set_local_id_category(AdnlNodeIdShort id, td::uint8 cat) = 0;

  // Measurement tools can request one bounded whole-socket loss window. The
  // production manager implements it below the encrypted ADNL packet layer so
  // both directions are observably suppressed. Ordinary nodes never call this
  // method; implementations that cannot support it fail explicitly.
  virtual void suppress_packets_until(td::Timestamp until, td::Promise<PacketSuppressionStats> promise) {
    promise.set_error(td::Status::Error("packet suppression is unsupported by this network manager"));
  }

  static constexpr td::uint32 get_mtu() {
    return 1440;
  }

  struct PrintId {};
  PrintId print_id() const {
    return PrintId{};
  }
};

}  // namespace adnl

}  // namespace tos

namespace td {

inline td::StringBuilder &operator<<(td::StringBuilder &sb, const tos::adnl::AdnlNetworkManager::PrintId &id) {
  sb << "[networkmanager]";
  return sb;
}

inline td::StringBuilder &operator<<(td::StringBuilder &sb, const tos::adnl::AdnlNetworkManager &manager) {
  sb << manager.print_id();
  return sb;
}

inline td::StringBuilder &operator<<(td::StringBuilder &sb, const tos::adnl::AdnlNetworkManager *manager) {
  sb << manager->print_id();
  return sb;
}

}  // namespace td
