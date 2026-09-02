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

    Copyright 2019-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "http-inbound-connection.h"
#include "http-server.h"

namespace tos {

namespace http {

HttpServer::HttpServer(td::IPAddress address, std::shared_ptr<Callback> callback, Limits limits)
    : address_(address), callback_(std::move(callback)), limits_(limits) {
  add_collector(collector_.get());
}

void HttpServer::start_up() {
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_sync_collector, metrics_.connections);
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_sync_collector, metrics_.connections_total);
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_sync_collector, metrics_.requests_total);
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_sync_collector, metrics_.responses_total);

  class Callback : public td::TcpListener::Callback {
   private:
    td::actor::ActorId<HttpServer> id_;

   public:
    Callback(td::actor::ActorId<HttpServer> id) : id_(id) {
    }

    void accept(td::SocketFd fd) override {
      td::actor::send_closure(id_, &HttpServer::accepted, std::move(fd));
    }
  };

  listener_ = td::actor::create_actor<td::TcpInfiniteListener>(
      td::actor::ActorOptions().with_name("listener").with_poll(), address_.get_port(),
      std::make_unique<Callback>(actor_id(this)), address_.get_ip_host());
}

void HttpServer::accepted(td::SocketFd fd) {
  // The connection gauge counts live HttpInboundConnection actors; refusing
  // the socket here (it is closed when `fd` goes out of scope) keeps a
  // client that opens sockets and never speaks from exhausting descriptors
  // and connection actors. Slow or silent headers on accepted connections
  // are bounded by the per-connection request-header deadline.
  if (limits_.max_connections != 0 && metrics_.connections->get() >= limits_.max_connections) {
    LOG(WARNING) << "HTTP connection limit of " << limits_.max_connections << " reached, refusing new connection";
    return;
  }
  td::actor::create_actor<HttpInboundConnection>(td::actor::ActorOptions().with_name("inhttpconn").with_poll(),
                                                 std::move(fd), callback_, metrics_, limits_.request_header_timeout,
                                                 limits_.request_body_timeout)
      .release();
}

td::IPAddress HttpServer::make_any_address(td::uint16 port) {
  td::IPAddress addr;
  addr.init_ipv4_port("0.0.0.0", port).ensure();
  return addr;
}

}  // namespace http

}  // namespace tos
