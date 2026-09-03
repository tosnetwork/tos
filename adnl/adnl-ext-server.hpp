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

#include "td/net/TcpListener.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/crypto.h"

#include "adnl-ext-connection.hpp"
#include "adnl-ext-server-limits.h"
#include "adnl-ext-server.h"
#include "adnl-peer-table.h"

namespace tos {

namespace adnl {

class AdnlExtServerImpl;

class AdnlInboundConnection : public AdnlExtConnection {
 public:
  AdnlInboundConnection(td::SocketFd fd, td::actor::ActorId<AdnlPeerTable> peer_table,
                        td::actor::ActorId<AdnlExtServerImpl> ext_server, std::unique_ptr<Callback> callback)
      : AdnlExtConnection(std::move(fd), std::move(callback), false), peer_table_(peer_table), ext_server_(ext_server) {
  }

  td::Status process_packet(td::BufferSlice data) override;
  td::Status process_init_packet(td::BufferSlice data) override;
  td::Status process_custom_packet(td::BufferSlice &data, bool &processed) override;
  void inited_crypto(td::Result<td::BufferSlice> R);
  void query_finished(td::Bits256 query_id, td::Result<td::BufferSlice> result);

 private:
  td::actor::ActorId<AdnlPeerTable> peer_table_;
  td::actor::ActorId<AdnlExtServerImpl> ext_server_;
  AdnlNodeIdShort local_id_;

  td::SecureString nonce_;
  AdnlNodeIdShort remote_id_ = AdnlNodeIdShort::zero();
  ExtConnectionQueryLimits query_limits_{1.0, 64, 32};
};

class AdnlExtServerImpl : public AdnlExtServer {
 public:
  void add_tcp_port(td::uint16 port) override;
  void add_local_id(AdnlNodeIdShort id) override;
  void accepted(td::SocketFd fd);
  void connection_closed(std::string peer_ip);
  void decrypt_init_packet(AdnlNodeIdShort dst, td::BufferSlice data, td::Promise<td::BufferSlice> promise);

  void start_up() override {
    for (auto &port : ports_) {
      add_tcp_port(port);
    }
    ports_.clear();
  }

  void reopen_port() {
  }

  AdnlExtServerImpl(td::actor::ActorId<AdnlPeerTable> adnl, std::vector<AdnlNodeIdShort> ids,
                    std::vector<td::uint16> ports)
      : peer_table_(adnl) {
    for (auto &id : ids) {
      add_local_id(id);
    }
    for (auto &port : ports) {
      ports_.insert(port);
    }
  }

 private:
  td::actor::ActorId<AdnlPeerTable> peer_table_;
  std::set<AdnlNodeIdShort> local_ids_;
  std::set<td::uint16> ports_;
  std::map<td::uint16, td::actor::ActorOwn<td::TcpInfiniteListener>> listeners_;
  ExtServerConnectionLimits connection_limits_{1024, 64};
};

}  // namespace adnl

}  // namespace tos
