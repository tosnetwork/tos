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
#include "auto/tl/tos_api.h"
#include "auto/tl/tos_api.hpp"
#include "fec/fec.h"
#include "td/utils/Random.h"

#include "RldpConnection.h"
#include "rldp-in.hpp"

namespace tos {

namespace rldp2 {

namespace detail {

void complete_out_query(td::Promise<td::BufferSlice> promise, td::uint64 max_answer_size, td::BufferSlice data) {
  if (data.size() <= max_answer_size) {
    promise.set_value(std::move(data));
  } else {
    promise.set_error(td::Status::Error("received too big answer"));
  }
}

}  // namespace detail

struct RldpIn::Connection {
  td::actor::ActorOwn<RldpConnectionActor> actor;
  td::Timestamp remove_at;
};

class RldpConnectionActor : public td::actor::Actor, private ConnectionCallback {
 public:
  RldpConnectionActor(td::actor::ActorId<RldpIn> rldp, adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst,
                      td::actor::ActorId<adnl::Adnl> adnl)
      : rldp_(std::move(rldp)), src_(src), dst_(dst), adnl_(std::move(adnl)) {};

  void send(TransferId transfer_id, td::BufferSlice query, td::Timestamp timeout = td::Timestamp::never()) {
    connection_.send(transfer_id, std::move(query), timeout);
    yield();
  }
  void set_receive_limits(TransferId transfer_id, td::Timestamp timeout, td::uint64 max_size) {
    connection_.set_receive_limits(transfer_id, timeout, max_size);
  }
  void receive_raw(td::BufferSlice data) {
    connection_.receive_raw(std::move(data));
    yield();
  }
  void set_default_mtu(td::uint64 mtu) {
    connection_.set_default_mtu(mtu);
  }

 private:
  td::actor::ActorId<RldpIn> rldp_;
  adnl::AdnlNodeIdShort src_;
  adnl::AdnlNodeIdShort dst_;
  td::actor::ActorId<adnl::Adnl> adnl_;
  RldpConnection connection_;

  void loop() override {
    alarm_timestamp() = connection_.run(*this);
  }

  void send_raw(td::BufferSlice data) override {
    send_closure(adnl_, &adnl::Adnl::send_message, src_, dst_, std::move(data));
  }
  void receive(TransferId transfer_id, td::Result<td::BufferSlice> data) override {
    send_closure(rldp_, &RldpIn::receive_message, dst_, src_, transfer_id, std::move(data));
  }
  void on_sent(TransferId transfer_id, td::Result<td::Unit> state) override {
    send_closure(rldp_, &RldpIn::on_sent, transfer_id, std::move(state));
  }
  void on_part_completed(TransferId transfer_id, td::uint32 part, td::uint64 decoded_bytes) override {
    send_closure(rldp_, &RldpIn::on_part_completed, src_, dst_, transfer_id, part, decoded_bytes);
  }
};

namespace {
TransferId get_random_transfer_id() {
  TransferId transfer_id;
  td::Random::secure_bytes(transfer_id.as_slice());
  return transfer_id;
}
TransferId get_responce_transfer_id(TransferId transfer_id) {
  return transfer_id ^ TransferId::ones();
}
}  // namespace

size_t RldpIn::per_local_id_share() const {
  // The expiry order is partitioned by local id, so its size is the number of
  // local ids currently holding connections.
  return tos::rldp2::per_local_id_share(MAX_CONNECTIONS, timeout_set_.size());
}

void RldpIn::get_connection_stats(td::Promise<ConnectionStats> promise) {
  ConnectionStats stats;
  stats.live = connections_.size();
  stats.evicted = connections_evicted_;
  stats.per_local_id.reserve(timeout_set_.size());
  for (auto &[id, order] : timeout_set_) {
    stats.per_local_id.emplace_back(id, order.size());
  }
  promise.set_value(std::move(stats));
}

void RldpIn::send_message(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data) {
  return send_message_ex(src, dst, td::Timestamp::in(10.0), std::move(data));
}

void RldpIn::send_message_ex(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::Timestamp timeout,
                             td::BufferSlice data) {
  td::Bits256 id;
  td::Random::secure_bytes(id.as_slice());

  auto B = serialize_tl_object(create_tl_object<tos_api::rldp_message>(id, std::move(data)), true);

  auto transfer_id = get_random_transfer_id();
  auto connection = get_or_create_connection(src, dst, false, timeout);
  if (connection.empty()) {
    // The connection table would not admit this peer. Dropping the message is
    // the only option left, and it must be an explicit one: sending to an
    // empty actor id terminates the process.
    VLOG(RLDP_INFO) << "dropping outbound message " << src << " -> " << dst << " : no connection available";
    return;
  }
  send_closure(connection, &RldpConnectionActor::send, transfer_id, std::move(B), timeout);
}

void RldpIn::send_query_ex(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, std::string name,
                           td::Promise<td::BufferSlice> promise, td::Timestamp timeout, td::BufferSlice data,
                           td::uint64 max_answer_size) {
  send_query_ex_with_transfer_id(src, dst, std::move(name), std::move(promise), timeout, std::move(data),
                                 max_answer_size, get_random_transfer_id());
}

void RldpIn::send_query_ex_with_transfer_id(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, std::string name,
                                            td::Promise<td::BufferSlice> promise, td::Timestamp timeout,
                                            td::BufferSlice data, td::uint64 max_answer_size,
                                            td::Bits256 request_transfer_id) {
  if (request_transfer_id.is_zero()) {
    promise.set_error(td::Status::Error("explicit RLDP request transfer id must be nonzero"));
    return;
  }
  auto query_id = adnl::AdnlQuery::random_query_id();

  auto date = static_cast<td::uint32>(timeout.at_unix()) + 1;
  auto B = serialize_tl_object(create_tl_object<tos_api::rldp_query>(query_id, max_answer_size, date, std::move(data)),
                               true);

  auto response_transfer_id = get_responce_transfer_id(request_transfer_id);
  if (queries_.count(response_transfer_id) != 0) {
    promise.set_error(td::Status::Error("explicit RLDP response transfer id is already active"));
    return;
  }
  auto connection = get_or_create_connection(src, dst, false, timeout);
  if (connection.empty()) {
    promise.set_error(td::Status::Error("no RLDP connection available for this peer"));
    return;
  }
  queries_.emplace(response_transfer_id, OutQuery{.promise = std::move(promise), .max_answer_size = max_answer_size});
  send_closure(connection, &RldpConnectionActor::set_receive_limits, response_transfer_id, timeout, max_answer_size);
  send_closure(connection, &RldpConnectionActor::send, request_transfer_id, std::move(B), timeout);
}

void RldpIn::answer_query(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::Timestamp timeout,
                          adnl::AdnlQueryId query_id, TransferId transfer_id, td::BufferSlice data) {
  auto B = serialize_tl_object(create_tl_object<tos_api::rldp_answer>(query_id, std::move(data)), true);

  auto connection = get_or_create_connection(src, dst, false, timeout);
  if (connection.empty()) {
    VLOG(RLDP_INFO) << "dropping answer " << src << " -> " << dst << " : no connection available";
    return;
  }
  send_closure(connection, &RldpConnectionActor::send, transfer_id, std::move(B), timeout);
}

void RldpIn::receive_message_part(adnl::AdnlNodeIdShort source, adnl::AdnlNodeIdShort local_id, td::BufferSlice data) {
  auto connection = get_or_create_connection(local_id, source, true);
  if (connection.empty()) {
    return;
  }
  send_closure(connection, &RldpConnectionActor::receive_raw, std::move(data));
}

td::actor::ActorId<RldpConnectionActor> RldpIn::get_or_create_connection(adnl::AdnlNodeIdShort local_id,
                                                                         adnl::AdnlNodeIdShort peer_id, bool incoming,
                                                                         td::Timestamp timeout) {
  if (!timeout) {
    timeout = td::Timestamp::now();
  }
  timeout += CONNECTION_TIMEOUT;
  auto it = connections_.find(std::make_pair(local_id, peer_id));
  if (it != connections_.end()) {
    auto previous = it->second.remove_at;
    it->second.remove_at = std::max(it->second.remove_at, timeout);
    refresh_connection(timeout_set_, local_id, peer_id, previous, it->second.remove_at);
    alarm_timestamp().relax(timeout);
    return it->second.actor.get();
  }
  td::uint64 mtu = get_peer_mtu(local_id, peer_id);
  if (mtu == 0 && incoming) {
    VLOG(RLDP_INFO) << "dropping incoming packet " << local_id << " <- " << peer_id << " : peer not allowed";
    return {};
  }
  auto admission = admit_connection(connections_, timeout_set_, MAX_CONNECTIONS, local_id, per_local_id_share());
  if (!admission.admitted) {
    VLOG(RLDP_INFO) << "refusing connection " << local_id << " , " << peer_id << " : connection table is full";
    return {};
  }
  if (admission.evicted > 0) {
    // The table only reaches its cap under a flood of fresh peer identities or
    // a badly undersized bound. Either way an operator needs to see it, but a
    // line per evicted connection would itself be a flood, so report the first
    // one and then one per EVICTION_LOG_INTERVAL evictions.
    connections_evicted_ += admission.evicted;
    if (connections_evicted_ == admission.evicted || connections_evicted_ % EVICTION_LOG_INTERVAL == 0) {
      LOG(WARNING) << "rldp2 connection table is at its " << MAX_CONNECTIONS
                   << " connection cap: evicted " << connections_evicted_
                   << " idle connections so far to admit new peers";
    }
  }
  auto connection =
      td::actor::create_actor<RldpConnectionActor>("RldpConnection", actor_id(this), local_id, peer_id, adnl_);
  td::actor::send_closure(connection, &RldpConnectionActor::set_default_mtu, mtu);
  auto res = connection.get();
  connections_[std::make_pair(local_id, peer_id)] = {std::move(connection), timeout};
  record_connection(timeout_set_, local_id, peer_id, timeout);
  alarm_timestamp().relax(timeout);
  VLOG(RLDP_INFO) << "creating connection " << local_id << " , " << peer_id << " ("
                  << (incoming ? "inbound" : "outbound") << ")";
  return res;
}

void RldpIn::receive_message(adnl::AdnlNodeIdShort source, adnl::AdnlNodeIdShort local_id, TransferId transfer_id,
                             td::Result<td::BufferSlice> r_data) {
  if (r_data.is_error()) {
    auto it = queries_.find(transfer_id);
    if (it != queries_.end()) {
      it->second.promise.set_error(r_data.move_as_error());
      queries_.erase(it);
    } else {
      VLOG(RLDP_INFO) << "received error to unknown transfer_id " << transfer_id << " " << r_data.error();
    }
    return;
  }

  auto data = r_data.move_as_ok();
  //LOG(ERROR) << "RECEIVE MESSAGE " << data.size();
  auto F = fetch_tl_object<tos_api::rldp_Message>(std::move(data), true);
  if (F.is_error()) {
    VLOG(RLDP_INFO) << "failed to parse rldp packet [" << source << "->" << local_id << "]: " << F.error();
    if (auto it = queries_.find(transfer_id); it != queries_.end()) {
      it->second.promise.set_error(F.move_as_error_prefix("received invalid rldp query answer: "));
      queries_.erase(it);
    }
    return;
  }

  tos_api::downcast_call(*F.move_as_ok().get(),
                         [&](auto &obj) { this->process_message(source, local_id, transfer_id, obj); });

  if (auto it = queries_.find(transfer_id); it != queries_.end()) {
    it->second.promise.set_error(td::Status::Error("received invalid rldp query answer"));
    queries_.erase(it);
  }
}

void RldpIn::process_message(adnl::AdnlNodeIdShort source, adnl::AdnlNodeIdShort local_id, TransferId transfer_id,
                             tos_api::rldp_message &message) {
  td::actor::send_closure(adnl_, &adnl::AdnlPeerTable::deliver, source, local_id, std::move(message.data_));
}

void RldpIn::process_message(adnl::AdnlNodeIdShort source, adnl::AdnlNodeIdShort local_id, TransferId transfer_id,
                             tos_api::rldp_query &message) {
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), source, local_id,
                                       timeout = td::Timestamp::at_unix(message.timeout_), query_id = message.query_id_,
                                       max_answer_size = static_cast<td::uint64>(message.max_answer_size_),
                                       transfer_id](td::Result<td::BufferSlice> R) mutable {
    if (R.is_ok()) {
      auto data = R.move_as_ok();
      if (data.size() > max_answer_size) {
        VLOG(RLDP_NOTICE) << "rldp query failed: answer too big";
      } else {
        if (!timeout || td::Timestamp::in(60.0) < timeout) {
          timeout = td::Timestamp::in(60.0);
        }
        td::actor::send_closure(SelfId, &RldpIn::answer_query, local_id, source, timeout, query_id,
                                transfer_id ^ TransferId::ones(), std::move(data));
      }
    } else {
      VLOG(RLDP_NOTICE) << "rldp query failed: " << R.move_as_error();
    }
  });
  VLOG(RLDP_DEBUG) << "delivering rldp query";
  td::actor::send_closure(adnl_, &adnl::AdnlPeerTable::deliver_query, source, local_id, std::move(message.data_),
                          std::move(P));
}

void RldpIn::process_message(adnl::AdnlNodeIdShort source, adnl::AdnlNodeIdShort local_id, TransferId transfer_id,
                             tos_api::rldp_answer &message) {
  auto it = queries_.find(transfer_id);
  if (it != queries_.end()) {
    detail::complete_out_query(std::move(it->second.promise), it->second.max_answer_size, std::move(message.data_));
    queries_.erase(it);
  } else {
    VLOG(RLDP_INFO) << "received answer to unknown query " << message.query_id_;
  }
}

void RldpIn::on_sent(TransferId transfer_id, td::Result<td::Unit> state) {
  //TODO: completed transfer
}

void RldpIn::on_part_completed(adnl::AdnlNodeIdShort local_id, adnl::AdnlNodeIdShort peer_id, TransferId transfer_id,
                               td::uint32 part, td::uint64 decoded_bytes) {
  if (part_completed_callback_) {
    part_completed_callback_(local_id, peer_id, transfer_id, part, decoded_bytes);
  }
}

void RldpIn::add_id(adnl::AdnlNodeIdShort local_id) {
  if (local_ids_.count(local_id) == 1) {
    return;
  }

  std::vector<std::string> X{adnl::Adnl::int_to_bytestring(tos_api::rldp2_messagePart::ID),
                             adnl::Adnl::int_to_bytestring(tos_api::rldp2_confirm::ID),
                             adnl::Adnl::int_to_bytestring(tos_api::rldp2_complete::ID)};
  for (auto &x : X) {
    td::actor::send_closure(adnl_, &adnl::Adnl::subscribe, local_id, x, make_adnl_callback());
  }

  local_ids_.insert(local_id);
}

void RldpIn::get_conn_ip_str(adnl::AdnlNodeIdShort l_id, adnl::AdnlNodeIdShort p_id, td::Promise<td::string> promise) {
  td::actor::send_closure(adnl_, &adnl::AdnlPeerTable::get_conn_ip_str, l_id, p_id, std::move(promise));
}

void RldpIn::on_mtu_updated(td::optional<adnl::AdnlNodeIdShort> local_id, td::optional<adnl::AdnlNodeIdShort> peer_id) {
  auto update_mtu = [&](const auto &it) {
    auto &[p, connection] = *it;
    td::actor::send_closure(connection.actor, &RldpConnectionActor::set_default_mtu, get_peer_mtu(p.first, p.second));
  };
  if (local_id && peer_id) {
    auto it = connections_.find({local_id.value(), peer_id.value()});
    if (it != connections_.end()) {
      update_mtu(it);
    }
    return;
  }
  auto it =
      local_id ? connections_.lower_bound({local_id.value(), adnl::AdnlNodeIdShort::zero()}) : connections_.begin();
  while (it != connections_.end()) {
    if (local_id && it->first.second != local_id.value()) {
      break;
    }
    update_mtu(it);
    ++it;
  }
}


void RldpIn::alarm() {
  // The expiry order is partitioned by local id, so expired connections are
  // collected from the front of each partition before anything is erased --
  // erasing while iterating would invalidate the partition being walked.
  std::vector<std::tuple<adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::Timestamp>> expired;
  for (auto &[local_id, order] : timeout_set_) {
    for (auto it = order.begin(); it != order.end() && it->first.is_in_past(); ++it) {
      expired.emplace_back(local_id, it->second, it->first);
    }
  }
  for (auto &[local_id, peer_id, timeout] : expired) {
    VLOG(RLDP_INFO) << "removing old connection " << local_id << " , " << peer_id;
    erase_connection(connections_, timeout_set_, local_id, peer_id, timeout);
  }
  auto next = earliest_expiry(timeout_set_);
  if (next) {
    alarm_timestamp() = next;
  }
}

std::unique_ptr<adnl::Adnl::Callback> RldpIn::make_adnl_callback() {
  class Callback : public adnl::Adnl::Callback {
   private:
    td::actor::ActorId<RldpIn> id_;

   public:
    Callback(td::actor::ActorId<RldpIn> id) : id_(id) {
    }
    void receive_message(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data) override {
      td::actor::send_closure(id_, &RldpIn::receive_message_part, src, dst, std::move(data));
    }
    void receive_query(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data,
                       td::Promise<td::BufferSlice> promise) override {
      promise.set_error(td::Status::Error(ErrorCode::notready, "rldp does not support queries"));
    }
  };

  return std::make_unique<Callback>(actor_id(this));
}

td::actor::ActorOwn<Rldp> Rldp::create(td::actor::ActorId<adnl::Adnl> adnl) {
  return td::actor::create_actor<RldpIn>("rldp", td::actor::actor_dynamic_cast<adnl::AdnlPeerTable>(adnl));
}

}  // namespace rldp2

}  // namespace tos
