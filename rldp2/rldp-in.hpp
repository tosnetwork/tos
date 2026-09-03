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

#include "adnl/adnl-peer-table.h"
#include "adnl/adnl-query.h"
#include "td/utils/List.h"
#include "tl-utils/tl-utils.hpp"

#include "rldp.hpp"
#include "rldp-connection-limits.h"

namespace tos {

namespace rldp2 {

class RldpLru : public td::ListNode {
 public:
  TransferId transfer_id() {
    return transfer_id_;
  }

  RldpLru(TransferId transfer_id) : transfer_id_(transfer_id) {
  }
  RldpLru() {
  }

  static RldpLru *from_list_node(td::ListNode *node) {
    return static_cast<RldpLru *>(node);
  }

 private:
  TransferId transfer_id_;
};

class RldpConnectionActor;
class RldpIn : public RldpImpl {
 public:
  static constexpr td::uint64 mtu() {
    return (1ull << 37);
  }
  static constexpr td::uint32 lru_size() {
    return 128;
  }
  void on_sent(TransferId transfer_id, td::Result<td::Unit> state);
  void on_part_completed(adnl::AdnlNodeIdShort local_id, adnl::AdnlNodeIdShort peer_id, TransferId transfer_id,
                         td::uint32 part, td::uint64 decoded_bytes);

  void set_part_completed_callback(PartCompletedCallback callback) override {
    part_completed_callback_ = std::move(callback);
  }

  void send_message(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data) override;
  void send_message_ex(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::Timestamp timeout,
                       td::BufferSlice data) override;

  void send_query(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, std::string name,
                  td::Promise<td::BufferSlice> promise, td::Timestamp timeout, td::BufferSlice data) override {
    send_query_ex(src, dst, name, std::move(promise), timeout, std::move(data), default_mtu());
  }
  void send_query_ex(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, std::string name,
                     td::Promise<td::BufferSlice> promise, td::Timestamp timeout, td::BufferSlice data,
                     td::uint64 max_answer_size) override;
  void send_query_ex_with_transfer_id(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, std::string name,
                                      td::Promise<td::BufferSlice> promise, td::Timestamp timeout, td::BufferSlice data,
                                      td::uint64 max_answer_size, td::Bits256 request_transfer_id) override;
  void answer_query(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::Timestamp timeout,
                    adnl::AdnlQueryId query_id, TransferId transfer_id, td::BufferSlice data);

  void receive_message_part(adnl::AdnlNodeIdShort source, adnl::AdnlNodeIdShort local_id, td::BufferSlice data);

  void process_message(adnl::AdnlNodeIdShort source, adnl::AdnlNodeIdShort local_id, TransferId transfer_id,
                       tos_api::rldp_message &message);
  void process_message(adnl::AdnlNodeIdShort source, adnl::AdnlNodeIdShort local_id, TransferId transfer_id,
                       tos_api::rldp_query &message);
  void process_message(adnl::AdnlNodeIdShort source, adnl::AdnlNodeIdShort local_id, TransferId transfer_id,
                       tos_api::rldp_answer &message);
  void receive_message(adnl::AdnlNodeIdShort source, adnl::AdnlNodeIdShort local_id, TransferId transfer_id,
                       td::Result<td::BufferSlice> data);

  void add_id(adnl::AdnlNodeIdShort local_id) override;

  void get_conn_ip_str(adnl::AdnlNodeIdShort l_id, adnl::AdnlNodeIdShort p_id,
                       td::Promise<td::string> promise) override;

  explicit RldpIn(td::actor::ActorId<adnl::AdnlPeerTable> adnl) : adnl_(adnl) {
  }

 protected:
  void on_mtu_updated(td::optional<adnl::AdnlNodeIdShort> local_id,
                      td::optional<adnl::AdnlNodeIdShort> peer_id) override;

  void alarm() override;

 private:
  std::unique_ptr<adnl::Adnl::Callback> make_adnl_callback();

  td::actor::ActorId<adnl::AdnlPeerTable> adnl_;

  struct Connection;
  std::map<std::pair<adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort>, Connection> connections_;
  RldpTimeoutSet timeout_set_;

  struct OutQuery {
    td::Promise<td::BufferSlice> promise;
    td::uint64 max_answer_size;
  };
  std::map<TransferId, OutQuery> queries_;

  std::set<adnl::AdnlNodeIdShort> local_ids_;
  PartCompletedCallback part_completed_callback_;

  td::actor::ActorId<RldpConnectionActor> get_or_create_connection(adnl::AdnlNodeIdShort local_id,
                                                                   adnl::AdnlNodeIdShort peer_id, bool incoming,
                                                                   td::Timestamp timeout = {});

  static constexpr double CONNECTION_TIMEOUT = 120.0;

  // Upper bound on live peer connections. An inbound message part creates a
  // connection for its source id. ADNL authenticates that id, so it is not
  // spoofable -- but generating fresh keys is free, so an attacker presents as
  // many identities as it likes and without a cap the table grows with the
  // rate of fresh identities for a whole CONNECTION_TIMEOUT window. The cap is
  // global across local ids: a flood on one entry point can evict connections
  // belonging to another, which is a deliberate trade (a hard global memory
  // bound over per-id fairness) and the reason it sits far above any
  // legitimate peer count. Every comparable table in the node is bounded (DHT
  // values and reverse connections, overlay peers, ADNL idle peer pairs, the
  // external server's connections and queries); this one was the exception.
  static constexpr size_t MAX_CONNECTIONS = 4096;

  // How often to report continuing eviction after the first one.
  static constexpr td::uint64 EVICTION_LOG_INTERVAL = 1024;

  // Total connections dropped to stay within the cap. It is the signal that
  // the bound is being exercised at all; without it the cap is silent and
  // there is nothing to calibrate it against.
  td::uint64 connections_evicted_{0};
};

}  // namespace rldp2

}  // namespace tos
