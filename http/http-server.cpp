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
  add_collector("http_connections", collector_.get());
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
    ++refused_since_last_log_;
    if (next_limit_log_.is_in_past()) {
      LOG(WARNING) << "HTTP connection limit of " << limits_.max_connections
                   << " reached, refusing new connections (" << refused_since_last_log_
                   << " refused since last report)";
      refused_since_last_log_ = 0;
      next_limit_log_ = td::Timestamp::in(10.0);
    }
    return;
  }
  td::actor::create_actor<HttpInboundConnection>(
      td::actor::ActorOptions().with_name("inhttpconn").with_poll(), std::move(fd), callback_, metrics_,
      limits_.request_header_timeout, limits_.request_body_timeout, limits_.reject_request_bodies,
      limits_.io_buffer_bytes, limits_.response_timeout, limits_.close_after_early_answer)
      .release();
}

td::Result<td::IPAddress> HttpServer::parse_listen_address(td::Slice arg) {
  // Split host and port here rather than in IPAddress::init_host_port, which
  // resolves host names and service names and reads IPv6 ports leniently.
  td::Slice host;
  td::Slice port_text = arg;
  bool has_host = false;
  bool ipv6 = false;
  if (!arg.empty() && arg[0] == '[') {
    auto close = arg.find(']');
    if (close == td::Slice::npos || close + 1 >= arg.size() || arg[close + 1] != ':') {
      return td::Status::Error("expected [<ipv6>]:<port>");
    }
    host = arg.substr(1, close - 1);
    port_text = arg.substr(close + 2);
    has_host = true;
    ipv6 = true;
  } else {
    auto colon = arg.rfind(':');
    if (colon != td::Slice::npos) {
      host = arg.substr(0, colon);
      port_text = arg.substr(colon + 1);
      has_host = true;
      if (host.find(':') != td::Slice::npos) {
        return td::Status::Error("an IPv6 address is written [<ipv6>]:<port>");
      }
    }
  }
  // The whole port text must be the number: no sign, spaces or leading zeros.
  // Port 0 is refused by init_ipv4_port/init_ipv6_port.
  TRY_RESULT(port, td::to_integer_safe<td::uint16>(port_text));
  td::IPAddress addr;
  if (!has_host) {
    TRY_STATUS(addr.init_ipv4_port("127.0.0.1", port));
  } else if (ipv6) {
    TRY_STATUS(addr.init_ipv6_port(host.str(), port));
  } else {
    TRY_STATUS(addr.init_ipv4_port(host.str(), port));
  }
  return addr;
}

td::IPAddress HttpServer::make_any_address(td::uint16 port) {
  td::IPAddress addr;
  addr.init_ipv4_port("0.0.0.0", port).ensure();
  return addr;
}

}  // namespace http

}  // namespace tos
