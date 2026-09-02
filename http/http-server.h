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
#pragma once

#include "metrics/metrics-collectors.h"
#include "td/actor/actor.h"
#include "td/net/TcpListener.h"

#include "http.h"

namespace tos {

namespace http {

class HttpInboundConnection;

class HttpServer : public td::actor::Actor, public virtual metrics::CollectorWrapper {
 public:
  class Callback {
   public:
    virtual ~Callback() = default;
    virtual void receive_request(
        std::unique_ptr<HttpRequest> request, std::shared_ptr<HttpPayload> payload,
        td::Promise<std::pair<std::unique_ptr<HttpResponse>, std::shared_ptr<HttpPayload>>> promise) = 0;
  };

  // Limits applied to every inbound connection, so that a client which
  // opens many sockets or trickles request headers cannot pin file
  // descriptors and connection actors in the serving process indefinitely.
  struct Limits {
    // Maximum number of simultaneously open inbound connections; further
    // accepted sockets are closed immediately. 0 means unlimited.
    size_t max_connections = 0;
    // Seconds a connection may spend waiting for a complete request line
    // and headers (from accept, and again after each response) before it
    // is closed. 0 disables the deadline.
    double request_header_timeout = 30.0;
    // Seconds a client has to deliver a declared request body once the
    // headers are complete. Larger than the header window so a legitimate
    // slow uploader is not cut off, yet bounded so a withheld body cannot
    // pin the connection. 0 falls back to the header deadline. Only applies
    // while the header deadline machinery is enabled.
    double request_body_timeout = 120.0;
  };

  HttpServer(td::IPAddress address, std::shared_ptr<Callback> callback, Limits limits);
  HttpServer(td::IPAddress address, std::shared_ptr<Callback> callback)
      : HttpServer(address, std::move(callback), Limits()) {
  }

  HttpServer(td::uint16 port, std::shared_ptr<Callback> callback, Limits limits)
      : HttpServer(make_any_address(port), std::move(callback), limits) {
  }
  HttpServer(td::uint16 port, std::shared_ptr<Callback> callback)
      : HttpServer(make_any_address(port), std::move(callback), Limits()) {
  }

  void start_up() override;
  void accepted(td::SocketFd fd);

  static td::actor::ActorOwn<HttpServer> create(td::uint16 port, std::shared_ptr<Callback> callback) {
    return td::actor::create_actor<HttpServer>("httpserver", port, std::move(callback));
  }
  static td::actor::ActorOwn<HttpServer> create(td::uint16 port, std::shared_ptr<Callback> callback,
                                                Limits limits) {
    return td::actor::create_actor<HttpServer>("httpserver", port, std::move(callback), limits);
  }

  struct AllMetrics {
    metrics::AtomicGauge<size_t>::Ptr connections =
        std::make_shared<metrics::AtomicGauge<size_t>>("connections", "Current number of HTTP connections.");
    metrics::AtomicCounter<size_t>::Ptr connections_total = std::make_shared<metrics::AtomicCounter<size_t>>(
        "connections_total", "Total number of HTTP connections encountered.");
    metrics::AtomicCounter<size_t>::Ptr requests_total =
        std::make_shared<metrics::AtomicCounter<size_t>>("requests_total", "Total number of HTTP requests received.");
    metrics::Labeled<td::uint32, metrics::AtomicCounter<size_t>>::Ptr responses_total =
        metrics::Labeled<td::uint32, metrics::AtomicCounter<size_t>>::make("code", "responses_total",
                                                                           "Total number of HTTP responses sent.");
  };

 private:
  td::IPAddress address_;
  std::shared_ptr<Callback> callback_;
  Limits limits_;

  td::actor::ActorOwn<td::TcpInfiniteListener> listener_;

  td::actor::ActorOwn<metrics::MultiCollector> collector_ = metrics::MultiCollector::create("http_server");
  AllMetrics metrics_{};

  static td::IPAddress make_any_address(td::uint16 port);
};

}  // namespace http

}  // namespace tos
