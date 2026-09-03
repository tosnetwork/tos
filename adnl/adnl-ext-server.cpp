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
#include "keys/encryptor.h"

#include "adnl-ext-server.hpp"
#include "utils.hpp"

namespace tos {

namespace adnl {

td::Status AdnlInboundConnection::process_packet(td::BufferSlice data) {
  TRY_RESULT(f, fetch_tl_object<tos_api::adnl_message_query>(std::move(data), true));
  if (!query_limits_.try_acquire()) {
    // Reject only this query. Returning an error from process_packet stops the
    // whole multiplexed TCP connection and discards unrelated in-flight work.
    log_dropped_query("per-connection admission limit exceeded");
    return td::Status::OK();
  }
  if (!server_query_limits_->try_acquire(peer_ip_)) {
    query_limits_.release();
    log_dropped_query("server or per-IP in-flight limit exceeded");
    return td::Status::OK();
  }
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), query_id = f->query_id_, peer_ip = peer_ip_,
       server_query_limits = server_query_limits_](td::Result<td::BufferSlice> R) mutable {
        server_query_limits->release(peer_ip);
        td::actor::send_closure(SelfId, &AdnlInboundConnection::query_finished, query_id, std::move(R));
      });
  auto source_id = remote_id_.is_zero() ? anonymous_remote_id_ : remote_id_;
  td::actor::send_closure(peer_table_, &AdnlPeerTable::deliver_query, source_id, local_id_, std::move(f->query_),
                          std::move(P));
  return td::Status::OK();
}

void AdnlInboundConnection::log_dropped_query(td::Slice reason) {
  // A client that keeps sending past its budget would otherwise turn every
  // rejected query into a log line, so only the first drop per connection is
  // surfaced at warning level; the running total is reported when it closes.
  if (dropped_queries_++ == 0) {
    LOG(WARNING) << "Dropping external query from " << peer_ip_ << ": " << reason;
  } else {
    LOG(DEBUG) << "Dropping external query from " << peer_ip_ << ": " << reason;
  }
}

void AdnlInboundConnection::tear_down() {
  if (dropped_queries_ > 0) {
    LOG(INFO) << "External connection from " << peer_ip_ << " closed after " << dropped_queries_
              << " dropped queries";
  }
  AdnlExtConnection::tear_down();
}

void AdnlInboundConnection::query_finished(td::Bits256 query_id, td::Result<td::BufferSlice> result) {
  query_limits_.release();
  if (result.is_error()) {
    LOG(INFO) << "failed ext query: " << result.error();
    return;
  }
  auto answer = create_tl_object<tos_api::adnl_message_answer>(query_id, result.move_as_ok());
  send(serialize_tl_object(answer, true));
}

td::Status AdnlInboundConnection::process_init_packet(td::BufferSlice data) {
  if (data.size() < 32) {
    return td::Status::Error(ErrorCode::protoviolation, "too small init packet");
  }
  local_id_ = AdnlNodeIdShort{data.as_slice().truncate(32)};
  data.confirm_read(32);

  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::BufferSlice> R) {
    td::actor::send_closure(SelfId, &AdnlInboundConnection::inited_crypto, std::move(R));
  });

  td::actor::send_closure(ext_server_, &AdnlExtServerImpl::decrypt_init_packet, local_id_, std::move(data),
                          std::move(P));
  stop_read();
  return td::Status::OK();
}

void AdnlInboundConnection::inited_crypto(td::Result<td::BufferSlice> R) {
  if (R.is_error()) {
    LOG(ERROR) << "failed to init crypto: " << R.move_as_error();
    stop();
    return;
  }
  auto init_data = R.move_as_ok();
  auto S = init_crypto(init_data.as_slice());
  if (S.is_error()) {
    LOG(ERROR) << "failed to init crypto (2): " << S;
    stop();
    return;
  }
  send(td::BufferSlice());
  resume_read();
  notify();
}

td::Status AdnlInboundConnection::process_custom_packet(td::BufferSlice &data, bool &processed) {
  if (data.size() == 12) {
    auto F = fetch_tl_object<tos_api::tcp_ping>(data.clone(), true);
    if (F.is_ok()) {
      auto f = F.move_as_ok();
      auto obj = create_tl_object<tos_api::tcp_pong>(f->random_id_);
      send(serialize_tl_object(obj, true));
      processed = true;
      return td::Status::OK();
    }
  }
  if (1) {
    auto F = fetch_tl_object<tos_api::tcp_authentificate>(data.clone(), true);
    if (F.is_ok()) {
      if (nonce_.size() > 0 || !remote_id_.is_zero()) {
        return td::Status::Error(ErrorCode::protoviolation, "duplicate authenticate");
      }
      auto f = F.move_as_ok();
      if (f->nonce_.size() == 0 || f->nonce_.size() > 512) {
        return td::Status::Error(ErrorCode::protoviolation, "bad nonce size");
      }
      nonce_ = td::SecureString{f->nonce_.size() + 256};
      nonce_.as_mutable_slice().truncate(f->nonce_.size()).copy_from(f->nonce_.as_slice());
      td::Random::secure_bytes(nonce_.as_mutable_slice().remove_prefix(f->nonce_.size()));

      auto obj = create_tl_object<tos_api::tcp_authentificationNonce>(
          td::BufferSlice{nonce_.as_slice().remove_prefix(f->nonce_.size())});
      send(serialize_tl_object(obj, true));
      processed = true;
      return td::Status::OK();
    }
  }

  if (nonce_.size() != 0) {
    auto F = fetch_tl_object<tos_api::tcp_authentificationComplete>(data.clone(), true);
    if (F.is_ok()) {
      auto f = F.move_as_ok();
      if (nonce_.size() == 0 || !remote_id_.is_zero()) {
        return td::Status::Error(ErrorCode::protoviolation, "duplicate authentificate");
      }

      auto pub_key = PublicKey{f->key_};
      // ADNL node identities are Ed25519 keys.  PublicKey also supports
      // symmetric/overlay key types, but accepting those here would widen the
      // TCP authentication protocol beyond the identity scheme used by TON
      // and allow a non-node key to become a remote ADNL identity.
      if (!pub_key.is_ed25519()) {
        return td::Status::Error("expected ed25519 key");
      }
      TRY_RESULT(enc, pub_key.create_encryptor());
      TRY_STATUS(enc->check_signature(nonce_.as_slice(), f->signature_.as_slice()));

      remote_id_ = AdnlNodeIdShort{pub_key.compute_short_id()};
      nonce_.clear();
      processed = true;
      return td::Status::OK();
    }
  }

  return td::Status::OK();
}

void AdnlExtServerImpl::add_tcp_port(td::uint16 port) {
  auto it = listeners_.find(port);
  if (it != listeners_.end()) {
    return;
  }

  class Callback : public td::TcpListener::Callback {
   private:
    td::actor::ActorId<AdnlExtServerImpl> id_;

   public:
    Callback(td::actor::ActorId<AdnlExtServerImpl> id) : id_(id) {
    }
    void accept(td::SocketFd fd) override {
      td::actor::send_closure(id_, &AdnlExtServerImpl::accepted, std::move(fd));
    }
  };

  auto act = td::actor::create_actor<td::TcpInfiniteListener>(
      td::actor::ActorOptions().with_name("listener").with_poll(), port, std::make_unique<Callback>(actor_id(this)));
  listeners_.emplace(port, std::move(act));
}

void AdnlExtServerImpl::add_local_id(AdnlNodeIdShort id) {
  local_ids_.insert(id);
}

void AdnlExtServerImpl::accepted(td::SocketFd fd) {
  td::IPAddress peer_address;
  auto status = peer_address.init_peer_address(fd);
  if (status.is_error()) {
    LOG(WARNING) << "Rejecting external connection with unknown peer address: " << status;
    return;
  }
  auto peer_ip = peer_address.get_ip_host();
  if (!connection_limits_.try_acquire(peer_ip)) {
    LOG(WARNING) << "Rejecting external connection from " << peer_ip << ": connection limit exceeded";
    return;
  }

  class Callback final : public AdnlExtConnection::Callback {
   public:
    Callback(td::actor::ActorId<AdnlExtServerImpl> server, std::string peer_ip)
        : server_(server), peer_ip_(std::move(peer_ip)) {
    }
    void on_close(td::actor::ActorId<AdnlExtConnection>) override {
      td::actor::send_closure(server_, &AdnlExtServerImpl::connection_closed, std::move(peer_ip_));
    }
    void on_ready(td::actor::ActorId<AdnlExtConnection>) override {
    }

   private:
    td::actor::ActorId<AdnlExtServerImpl> server_;
    std::string peer_ip_;
  };

  // Derive the anonymous identity and the rate-limiting key together, before
  // the call, so neither depends on the order the arguments below happen to be
  // evaluated in.
  auto identity = make_ext_connection_identity(std::move(peer_ip));
  td::actor::create_actor<AdnlInboundConnection>(td::actor::ActorOptions().with_name("inconn").with_poll(),
                                                 std::move(fd), peer_table_, actor_id(this),
                                                 AdnlNodeIdShort{identity.anonymous_id},
                                                 identity.peer_ip, query_limits_,
                                                 std::make_unique<Callback>(actor_id(this), identity.peer_ip))
      .release();
}

void AdnlExtServerImpl::connection_closed(std::string peer_ip) {
  connection_limits_.release(peer_ip);
}

void AdnlExtServerImpl::decrypt_init_packet(AdnlNodeIdShort dst, td::BufferSlice data,
                                            td::Promise<td::BufferSlice> promise) {
  auto it = local_ids_.find(dst);
  if (it != local_ids_.end()) {
    td::actor::send_closure(peer_table_, &AdnlPeerTable::decrypt_message, dst, std::move(data), std::move(promise));
  } else {
    promise.set_error(td::Status::Error());
  }
}

td::actor::ActorOwn<AdnlExtServer> AdnlExtServerCreator::create(td::actor::ActorId<AdnlPeerTable> adnl,
                                                                std::vector<AdnlNodeIdShort> ids,
                                                                std::vector<td::uint16> ports) {
  return td::actor::create_actor<AdnlExtServerImpl>("extserver", adnl, std::move(ids), std::move(ports));
}

}  // namespace adnl

}  // namespace tos
