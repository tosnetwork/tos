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
#include <set>
#include <string>

#include "td/net/TcpListener.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/crypto.h"

#include "adnl-ext-connection.hpp"
#include "adnl-ext-query-failure.h"
#include "adnl-ext-server-limits.h"
#include "adnl-ext-server.h"
#include "adnl-peer-table.h"

namespace tos {

namespace adnl {

class AdnlExtServerImpl;

class AdnlInboundConnection : public AdnlExtConnection {
 public:
  AdnlInboundConnection(td::SocketFd fd, td::actor::ActorId<AdnlPeerTable> peer_table,
                        td::actor::ActorId<AdnlExtServerImpl> ext_server, AdnlNodeIdShort anonymous_remote_id,
                        std::string peer_ip, std::shared_ptr<ExtServerQueryLimits> server_query_limits,
                        std::shared_ptr<ExtQueryFailurePolicy> failure_policy, std::unique_ptr<Callback> callback)
      : AdnlExtConnection(std::move(fd), std::move(callback), false)
      , peer_table_(peer_table)
      , ext_server_(ext_server)
      , anonymous_remote_id_(anonymous_remote_id)
      , peer_ip_(std::move(peer_ip))
      , server_query_limits_(std::move(server_query_limits))
      , failure_policy_(std::move(failure_policy)) {
  }

  td::Status process_packet(td::BufferSlice data) override;
  td::Status process_init_packet(td::BufferSlice data) override;
  td::Status process_custom_packet(td::BufferSlice &data, bool &processed) override;
  void inited_crypto(td::Result<td::BufferSlice> R);
  void query_finished(td::Bits256 query_id, td::Result<td::BufferSlice> result);

  // Terminal counts for this connection, per failure kind, reported when it closes.
  struct QueryOutcomes {
    static constexpr size_t kKinds = 6;
    td::uint64 accepted{0};
    td::uint64 replied[kKinds]{};
    td::uint64 closed[kKinds]{};
  };

 protected:
  void tear_down() override;

 private:
  // Every query whose ID was parsed ends in an answer or a closed connection.
  // Answers the original ID with the service's bounded failure payload when an
  // encoder is installed and the failure-reply budget allows; otherwise returns an
  // error so the caller closes the connection. Never leaves the ID unanswered.
  td::Status reject_or_close(td::Bits256 query_id, ExtQueryFailure failure);
  bool send_failure_answer(td::Bits256 query_id, const ExtQueryFailure &failure);
  void note_failure(td::Bits256 query_id, ExtQueryFailureKind kind, bool replied);

  td::actor::ActorId<AdnlPeerTable> peer_table_;
  td::actor::ActorId<AdnlExtServerImpl> ext_server_;
  AdnlNodeIdShort local_id_;

  td::SecureString nonce_;
  AdnlNodeIdShort remote_id_ = AdnlNodeIdShort::zero();
  AdnlNodeIdShort anonymous_remote_id_;
  std::string peer_ip_;
  std::shared_ptr<ExtServerQueryLimits> server_query_limits_;
  std::shared_ptr<ExtQueryFailurePolicy> failure_policy_;
  ExtConnectionQueryLimits query_limits_{1.0, 64, 32};
  td::RateLimiterWindow failure_replies_{ExtQueryFailurePolicy::kReplyWindowSeconds,
                                         ExtQueryFailurePolicy::kMaxRepliesPerConnection};
  QueryOutcomes outcomes_;
  td::uint64 failures_logged_{0};
};

class AdnlExtServerImpl : public AdnlExtServer {
 public:
  void add_tcp_port(td::uint16 port) override;
  void add_local_id(AdnlNodeIdShort id) override;
  void wait_listening(td::Promise<td::Unit> promise) override;
  void set_query_failure_encoder(std::shared_ptr<const ExtQueryFailureEncoder> encoder) override;
  void accepted(td::SocketFd fd);
  void tcp_port_listening(td::uint16 port, td::Status status);
  void connection_closed(std::string peer_ip);
  void decrypt_init_packet(AdnlNodeIdShort dst, td::BufferSlice data, td::Promise<td::BufferSlice> promise);

  void start_up() override {
    initial_ports_pending_ = ports_;
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
  std::set<td::uint16> initial_ports_pending_;
  std::map<td::uint16, td::actor::ActorOwn<td::TcpInfiniteListener>> listeners_;
  std::vector<td::Promise<td::Unit>> listening_waiters_;
  td::Status listening_status_;
  ExtServerConnectionLimits connection_limits_{1024, 64};
  // Bound parked and executing requests across connections. The per-IP limit
  // stays below the validator execution budget so one address cannot monopolize it.
  std::shared_ptr<ExtServerQueryLimits> query_limits_ = std::make_shared<ExtServerQueryLimits>(4096, 256);
  // Shared with every connection so an encoder installed later reaches existing ones.
  std::shared_ptr<ExtQueryFailurePolicy> failure_policy_ = std::make_shared<ExtQueryFailurePolicy>();

  // A refused connection is the flood this limiter exists to absorb, so a
  // line per refusal is a line per packet the sender chose to send, into
  // log files that have no size bound of their own. Report the running
  // total once per interval instead: it says the same thing and cannot be
  // driven faster than the clock.
  void note_refused_connection(td::Slice reason);

  static constexpr double REFUSAL_LOG_INTERVAL = 60.0;
  td::uint64 connections_refused_{0};
  td::Timestamp next_refusal_log_;
};

}  // namespace adnl

}  // namespace tos
