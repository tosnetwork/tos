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

HttpServer::HttpServer(td::IPAddress address, std::shared_ptr<Callback> callback)
    : address_(address), callback_(std::move(callback)) {
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
  // Round 153 HIGH (deferred): no connection cap or header read
  // deadline.  An attacker can connect, send headers slowly (or
  // a never-terminated header block within max_one_header_size
  // per line), and pin a connection / actor indefinitely.  The
  // round-152 Content-Length gate handles oversize bodies but
  // not slow-start / never-finishing headers (slow loris).
  // Closing this requires (a) a max-concurrent-connections cap
  // here, (b) a deadline timer on the inbound connection that
  // expires if the request line + headers don't complete within
  // a few seconds.  Both are larger surgical changes than the
  // single-line gates added in round 152; tracked as a
  // dedicated follow-up.  Mitigating context: nodes typically
  // sit behind operator-deployed reverse proxies (nginx /
  // envoy) that already enforce these limits at the edge, so
  // the exposure boundary is "directly-internet-exposed
  // validator-engine without a proxy".
  td::actor::create_actor<HttpInboundConnection>(td::actor::ActorOptions().with_name("inhttpconn").with_poll(),
                                                 std::move(fd), callback_, metrics_)
      .release();
}

td::IPAddress HttpServer::make_any_address(td::uint16 port) {
  td::IPAddress addr;
  addr.init_ipv4_port("0.0.0.0", port).ensure();
  return addr;
}

}  // namespace http

}  // namespace tos
