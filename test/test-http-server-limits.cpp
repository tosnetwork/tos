/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The HTTP server embedded in the validator (JSON-RPC, metrics) accepts
// connections from anyone who can reach the port. These tests open raw TCP
// sockets against a real HttpServer and check the two limits that keep such
// a client from pinning descriptors and connection actors: the cap on
// simultaneously open connections, and the deadline for delivering request
// headers (which also covers idle keep-alive connections).

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "http/http-inbound-connection.h"
#include "http/http-server.h"
#include "http/http.h"
#include "td/actor/actor.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/tests.h"
#include "validator-engine/json-rpc-http-policy.h"

namespace {

class OkCallback : public tos::http::HttpServer::Callback {
 public:
  void receive_request(
      std::unique_ptr<tos::http::HttpRequest> request, std::shared_ptr<tos::http::HttpPayload> payload,
      td::Promise<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>>
          promise) override {
    // Refuse tunnels the way a non-proxy API server does.
    int status = request->method() == "CONNECT" ? 405 : 200;
    auto response =
        tos::http::HttpResponse::create("HTTP/1.1", status, status == 200 ? "OK" : "Method Not Allowed", false, false)
            .move_as_ok();
    response->add_header({"Content-Type", "text/plain"});
    response->add_header({"Transfer-Encoding", "Chunked"});
    response->complete_parse_header();
    auto out = response->create_empty_payload().move_as_ok();
    out->add_chunk(td::BufferSlice("ok"));
    out->complete_parse();
    promise.set_value({std::move(response), std::move(out)});
  }
};

class Client {
 public:
  explicit Client(int port, int receive_window = 0) : port_(port), receive_window_(receive_window) {
  }
  ~Client() {
    close();
  }

  bool connect_with_retries() {
    for (int attempt = 0; attempt < 100; attempt++) {
      fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
      if (fd_ < 0) {
        return false;
      }
      if (receive_window_ > 0) {
        CHECK(::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &receive_window_, sizeof(receive_window_)) == 0);
      }
      sockaddr_in addr{};
      addr.sin_family = AF_INET;
      addr.sin_port = htons(static_cast<uint16_t>(port_));
      addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
        return true;
      }
      ::close(fd_);
      fd_ = -1;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return false;
  }

  bool send_all(const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
      auto n = ::send(fd_, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
      if (n <= 0) {
        return false;
      }
      sent += static_cast<size_t>(n);
    }
    return true;
  }

  // Reads until the peer closes the connection or the timeout elapses.
  // Returns true only on a clean EOF from the server.
  bool wait_for_eof(int timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (true) {
      auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        return false;
      }
      int remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
      pollfd pfd{fd_, POLLIN, 0};
      int rc = ::poll(&pfd, 1, remaining);
      if (rc <= 0) {
        return false;
      }
      char buf[256];
      auto n = ::recv(fd_, buf, sizeof(buf), 0);
      if (n == 0) {
        return true;
      }
      if (n < 0) {
        return errno == ECONNRESET;
      }
      // Data before EOF (for example a late response) is fine; keep reading.
    }
  }

  // Reads everything until the server closes cleanly. Unlike wait_for_eof, a
  // reset or a timeout is a failure, so a pass shows the client received the
  // whole answer and then an orderly close.
  bool read_until_clean_eof(int timeout_ms, std::string &out) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (true) {
      auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        return false;
      }
      int remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
      pollfd pfd{fd_, POLLIN, 0};
      if (::poll(&pfd, 1, remaining) <= 0) {
        return false;
      }
      char buf[1024];
      auto n = ::recv(fd_, buf, sizeof(buf), 0);
      if (n == 0) {
        return true;
      }
      if (n < 0) {
        return false;
      }
      out.append(buf, static_cast<size_t>(n));
    }
  }

  // Reads for the whole window and succeeds only if the connection is still
  // open at the end: a clean close, a reset or a read error all fail it.
  bool stays_open(int window_ms, std::string &out) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(window_ms);
    while (true) {
      auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        return true;
      }
      int remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
      pollfd pfd{fd_, POLLIN, 0};
      int rc = ::poll(&pfd, 1, remaining);
      if (rc == 0) {
        return true;
      }
      if (rc < 0) {
        return false;
      }
      char buf[1024];
      auto n = ::recv(fd_, buf, sizeof(buf), 0);
      if (n <= 0) {
        return false;
      }
      out.append(buf, static_cast<size_t>(n));
    }
  }

  // Reads one chunked response through its terminating zero chunk.
  bool read_chunked_response(int timeout_ms, std::string &out) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (out.find("\r\n0\r\n\r\n") == std::string::npos) {
      auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        return false;
      }
      int remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
      pollfd pfd{fd_, POLLIN, 0};
      if (::poll(&pfd, 1, remaining) <= 0) {
        return false;
      }
      char buf[1024];
      auto n = ::recv(fd_, buf, sizeof(buf), 0);
      if (n <= 0) {
        return false;
      }
      out.append(buf, static_cast<size_t>(n));
    }
    return true;
  }

  // Sends a complete request and waits for a "200 OK" status line.
  bool request_ok(int timeout_ms) {
    if (!send_all("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")) {
      return false;
    }
    std::string received;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (received.find("\r\n\r\n") == std::string::npos) {
      auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        return false;
      }
      int remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
      pollfd pfd{fd_, POLLIN, 0};
      if (::poll(&pfd, 1, remaining) <= 0) {
        return false;
      }
      char buf[1024];
      auto n = ::recv(fd_, buf, sizeof(buf), 0);
      if (n <= 0) {
        return false;
      }
      received.append(buf, static_cast<size_t>(n));
    }
    return received.rfind("HTTP/1.1 200", 0) == 0;
  }

  void close() {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

 private:
  int port_;
  int receive_window_ = 0;
  int fd_ = -1;
};

int find_free_port() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  CHECK(::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
  socklen_t len = sizeof(addr);
  CHECK(::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
  int port = ntohs(addr.sin_port);
  ::close(fd);
  return port;
}

// Runs `scenario` on a client thread against a server started with `limits`,
// pumping the actor scheduler on the current thread until the scenario ends.
void with_server(tos::http::HttpServer::Limits limits, std::function<void(int port)> scenario,
                 std::shared_ptr<tos::http::HttpServer::Callback> callback = nullptr) {
  if (!callback)
    callback = std::make_shared<OkCallback>();
  int port = find_free_port();
  td::IPAddress addr;
  addr.init_ipv4_port("127.0.0.1", port).ensure();

  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<tos::http::HttpServer> server;
  scheduler.run_in_context(
      [&] { server = td::actor::create_actor<tos::http::HttpServer>("httpserver", addr, callback, limits); });

  std::atomic<bool> done{false};
  std::thread client([&] {
    scenario(port);
    done = true;
  });
  while (!done) {
    scheduler.run(0.05);
  }
  client.join();

  scheduler.run_in_context([&] {
    server.reset();
    td::actor::SchedulerContext::get().stop();
  });
  while (scheduler.run(1)) {
  }
}

}  // namespace

TEST(HttpServerLimits, connection_cap_refuses_extra_connections_and_recovers) {
  tos::http::HttpServer::Limits limits;
  limits.max_connections = 2;
  limits.request_header_timeout = 0;
  with_server(limits, [](int port) {
    Client first(port), second(port);
    ASSERT_TRUE(first.connect_with_retries());
    ASSERT_TRUE(second.connect_with_retries());
    // Let the server create the two connection actors before the third arrives.
    ASSERT_TRUE(first.request_ok(5000));
    ASSERT_TRUE(second.request_ok(5000));

    Client third(port);
    ASSERT_TRUE(third.connect_with_retries());
    ASSERT_TRUE(third.wait_for_eof(5000));

    // Closing one connection frees a slot.
    first.close();
    Client fourth(port);
    bool accepted = false;
    for (int attempt = 0; attempt < 50 && !accepted; attempt++) {
      if (fourth.connect_with_retries() && fourth.request_ok(500)) {
        accepted = true;
      } else {
        fourth.close();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
    }
    ASSERT_TRUE(accepted);
  });
}

TEST(HttpServerLimits, request_header_deadline_closes_silent_and_partial_connections) {
  tos::http::HttpServer::Limits limits;
  limits.max_connections = 0;
  limits.request_header_timeout = 0.3;
  limits.request_body_timeout = 0.4;
  with_server(limits, [](int port) {
    Client silent(port);
    ASSERT_TRUE(silent.connect_with_retries());
    ASSERT_TRUE(silent.wait_for_eof(5000));

    Client partial(port);
    ASSERT_TRUE(partial.connect_with_retries());
    ASSERT_TRUE(partial.send_all("GET / HTTP/1.1\r\nHost: localhost\r\n"));
    ASSERT_TRUE(partial.wait_for_eof(5000));

    // Completing the headers but withholding a declared body must not keep
    // the connection alive either: the deadline covers the whole request.
    Client body_stall(port);
    ASSERT_TRUE(body_stall.connect_with_retries());
    ASSERT_TRUE(body_stall.send_all(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\npartial"));
    ASSERT_TRUE(body_stall.wait_for_eof(5000));

    // A refused CONNECT must not linger as an exempt tunnel: the handler
    // answers non-2xx and the connection is closed right after the write.
    Client tunnel(port);
    ASSERT_TRUE(tunnel.connect_with_retries());
    ASSERT_TRUE(tunnel.send_all("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"));
    ASSERT_TRUE(tunnel.wait_for_eof(5000));

    // An oversized header block is rejected outright.
    Client fat_headers(port);
    ASSERT_TRUE(fat_headers.connect_with_retries());
    std::string many_headers = "GET / HTTP/1.1\r\nHost: localhost\r\n";
    for (int i = 0; i < 2000; i++) {
      many_headers += "X-H" + std::to_string(i) + ": v\r\n";
    }
    many_headers += "\r\n";
    ASSERT_TRUE(fat_headers.send_all(many_headers));
    ASSERT_TRUE(fat_headers.wait_for_eof(5000));

    // A complete request is served, and the idle keep-alive connection is
    // then closed once the next request's headers fail to arrive in time.
    Client served(port);
    ASSERT_TRUE(served.connect_with_retries());
    ASSERT_TRUE(served.request_ok(5000));
    ASSERT_TRUE(served.wait_for_eof(5000));
  });
}

TEST(HttpServerLimits, deadline_disabled_keeps_silent_connection_open) {
  tos::http::HttpServer::Limits limits;
  limits.max_connections = 0;
  limits.request_header_timeout = 0;
  with_server(limits, [](int port) {
    Client silent(port);
    ASSERT_TRUE(silent.connect_with_retries());
    ASSERT_TRUE(!silent.wait_for_eof(700));
    ASSERT_TRUE(silent.request_ok(5000));
  });
}

// The RLDP HTTP proxy does not read requests off a socket; it receives a
// serialized tos_api::http_request and rebuilds it with
// HttpRequest::create(const http_request&). That rebuild must run every header
// through add_header, which is where the Content-Length gate lives -- otherwise
// the gate that refuses an oversized socket request would never apply to a
// proxied one. These tests pin that the gate fires on the reconstruction path
// and, critically, that its rejection is propagated rather than dropped.
namespace {
tos::tl_object_ptr<tos::tos_api::http_request> make_tl_request(
    std::string method, std::string url, std::vector<std::pair<std::string, std::string>> headers) {
  std::vector<tos::tl_object_ptr<tos::tos_api::http_header>> tl_headers;
  tl_headers.reserve(headers.size());
  for (auto &h : headers) {
    tl_headers.push_back(tos::create_tl_object<tos::tos_api::http_header>(h.first, h.second));
  }
  td::Bits256 id;
  id.set_zero();
  return tos::create_tl_object<tos::tos_api::http_request>(id, std::move(method), std::move(url), "HTTP/1.1",
                                                           std::move(tl_headers));
}
}  // namespace

TEST(HttpServerLimits, rldp_request_rebuild_accepts_content_length_at_max) {
  // A body declared at exactly the cap is legal: the gate is `len > max`, so
  // the largest admissible request still rebuilds cleanly.
  auto f = make_tl_request(
      "POST", "/",
      {{"Host", "example.com"}, {"Content-Length", std::to_string(tos::http::HttpRequest::max_payload_size())}});
  auto r = tos::http::HttpRequest::create(*f);
  ASSERT_TRUE(r.is_ok());
}

TEST(HttpServerLimits, rldp_request_rebuild_rejects_oversized_content_length) {
  // One byte over the cap must be refused, and the refusal must surface as an
  // error from create() -- not be swallowed while the request is rebuilt
  // anyway. If add_header's status were dropped on this path (the regression
  // this guards against), create() would return ok here instead.
  auto f = make_tl_request(
      "POST", "/",
      {{"Host", "example.com"},
       {"Content-Length", std::to_string(static_cast<uint64_t>(tos::http::HttpRequest::max_payload_size()) + 1)}});
  auto r = tos::http::HttpRequest::create(*f);
  ASSERT_TRUE(r.is_error());
}

TEST(HttpServerLimits, default_connection_limit_is_finite) {
  // The library default must be a finite cap, not 0 ("unlimited"). Every
  // service that constructs an HttpServer without its own Limits inherits this
  // default, so a 0 here would silently leave those consumers unbounded -- the
  // dead guard this change removes. The connection_cap test above proves the
  // guard rejects the (limit+1)-th connection when the limit is positive;
  // this proves no consumer can end up with a non-positive (unlimited) limit
  // by default. Reverting Limits::max_connections to 0 makes this fail.
  tos::http::HttpServer::Limits limits;
  ASSERT_TRUE(limits.max_connections != 0);
  ASSERT_TRUE(limits.max_connections <= (static_cast<size_t>(1) << 20));
}

namespace {
struct TransportObservation {
  std::atomic<size_t> peak{0};
  std::atomic<size_t> output_peak{0};
  std::atomic<int> closed{0};
  std::atomic<int> calls{0};
};
class LargeResponseCallback final : public tos::http::HttpServer::Callback {
 public:
  explicit LargeResponseCallback(TransportObservation *observation, size_t response_bytes = 1024 * 1024)
      : observation_(observation), response_bytes_(response_bytes) {
  }
  void receive_request(
      std::unique_ptr<tos::http::HttpRequest>, std::shared_ptr<tos::http::HttpPayload>,
      td::Promise<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>> promise)
      override {
    ++observation_->calls;
    auto response = tos::http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
    response->add_header({"Transfer-Encoding", "Chunked"});
    response->complete_parse_header();
    auto payload = response->create_empty_payload().move_as_ok();
    payload->add_chunk(td::BufferSlice(std::string(response_bytes_, 'x')));
    payload->complete_parse();
    promise.set_value({std::move(response), std::move(payload)});
  }

 private:
  TransportObservation *observation_;
  size_t response_bytes_;
};
class ObservedInbound final : public tos::http::HttpInboundConnection {
 public:
  ObservedInbound(td::SocketFd fd, TransportObservation *observation)
      : HttpInboundConnection(std::move(fd), std::make_shared<LargeResponseCallback>(observation),
                              tos::http::HttpServer::AllMetrics{}, 5, 5, true, 4096, 0.15)
      , observation_(observation) {
  }
  ~ObservedInbound() override {
    ++observation_->closed;
  }
  void alarm() override {
    observation_->output_peak.store(std::max(observation_->output_peak.load(), buffered_fd_.ready_for_flush_write()));
    HttpInboundConnection::alarm();
  }
  void payload_written() override {
    observation_->output_peak.store(std::max(observation_->output_peak.load(), buffered_fd_.ready_for_flush_write()));
    HttpInboundConnection::payload_written();
  }
  td::Status receive(td::ChainBufferReader &input) override {
    observation_->peak.store(std::max(observation_->peak.load(), input.size()));
    return HttpInboundConnection::receive(input);
  }

 private:
  TransportObservation *observation_;
};

void with_observed_inbound(const std::string &request, std::function<void(int, TransportObservation &)> scenario) {
  int pair[2];
  int listener = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(listener >= 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(::bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
  socklen_t size = sizeof(address);
  CHECK(::getsockname(listener, reinterpret_cast<sockaddr *>(&address), &size) == 0);
  CHECK(::listen(listener, 1) == 0);
  pair[1] = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(pair[1] >= 0);
  int receive_window = 4096;
  CHECK(::setsockopt(pair[1], SOL_SOCKET, SO_RCVBUF, &receive_window, sizeof(receive_window)) == 0);
  CHECK(::connect(pair[1], reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
  pair[0] = ::accept(listener, nullptr, nullptr);
  CHECK(pair[0] >= 0);
  ::close(listener);
  int small = 4096;
  CHECK(::setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
  // Queue headers+body before the transport starts, to prove the actual socket
  // preparse window rather than only the header rejection policy.
  CHECK(::send(pair[1], request.data(), request.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(request.size()));
  TransportObservation observation;
  td::actor::Scheduler scheduler({2});
  scheduler.run_in_context([&] {
    auto fd = td::SocketFd::from_native_fd(td::NativeFd(pair[0])).move_as_ok();
    td::actor::create_actor<ObservedInbound>(td::actor::ActorOptions().with_name("observed-inbound").with_poll(),
                                             std::move(fd), &observation)
        .release();
  });
  std::atomic<bool> done{false};
  std::thread client([&] {
    scenario(pair[1], observation);
    done = true;
  });
  while (!done)
    scheduler.run(0.01);
  client.join();
  ::close(pair[1]);
  scheduler.run_in_context([&] { td::actor::SchedulerContext::get().stop(); });
  while (scheduler.run(1)) {
  }
}
}  // namespace

TEST(HttpServerLimits, bodiless_listener_limits_socket_read_before_body_refusal) {
  const std::string request =
      "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 65536\r\n\r\n" + std::string(65536, 'x');
  with_observed_inbound(request, [](int fd, TransportObservation &observation) {
    pollfd poller{fd, POLLIN, 0};
    ASSERT_TRUE(::poll(&poller, 1, 2000) > 0);
    char reply[1024];
    auto n = ::recv(fd, reply, sizeof(reply), 0);
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(std::string(reply, static_cast<size_t>(n)).find("HTTP/1.1 413 ") == 0);
    ASSERT_TRUE(observation.peak > 0 && observation.peak <= 4096);
    ASSERT_EQ(observation.calls.load(), 0);
  });
}

TEST(HttpServerLimits, response_deadline_releases_a_nonreading_client) {
  with_observed_inbound("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", [](int, TransportObservation &observation) {
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (observation.calls == 0 && std::chrono::steady_clock::now() < until)
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    ASSERT_EQ(observation.calls.load(), 1);
    // No read: the small send buffer forces the actual payload writer to stall.
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    ASSERT_EQ(observation.closed.load(), 1);
    ASSERT_TRUE(observation.output_peak > 0 && observation.output_peak <= 4096 + 1024 + 128);
  });
}

TEST(HttpServerLimits, eight_slow_replies_expire_and_the_listener_recovers_its_slots) {
  tos::http::HttpServer::Limits limits;
  limits.max_connections = 8;
  limits.io_buffer_bytes = 4096;
  limits.request_header_timeout = 5;
  limits.response_timeout = 0.5;
  TransportObservation observation;
  with_server(
      limits,
      [&](int port) {
        std::vector<std::unique_ptr<Client>> held;
        for (int i = 0; i < 8; ++i) {
          auto client = std::make_unique<Client>(port, 4096);
          ASSERT_TRUE(client->connect_with_retries());
          ASSERT_TRUE(client->send_all("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"));
          held.push_back(std::move(client));
        }
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (observation.calls < 8 && std::chrono::steady_clock::now() < until)
          std::this_thread::sleep_for(std::chrono::milliseconds(2));
        ASSERT_EQ(observation.calls.load(), 8);
        Client extra(port);
        ASSERT_TRUE(extra.connect_with_retries());
        // The ninth connection is closed at accept; the close is immediate on this
        // host but a loaded CI runner needs the same allowance the other EOF waits use.
        ASSERT_TRUE(extra.wait_for_eof(5000));
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        Client recovered(port);
        ASSERT_TRUE(recovered.connect_with_retries());
        ASSERT_TRUE(recovered.request_ok(1000));
        ASSERT_EQ(observation.calls.load(), 9);
      },
      std::make_shared<LargeResponseCallback>(&observation, 4 * 1024 * 1024));
}

// A handler that answers from the request headers (the JSON-RPC API key check,
// a 404, a refused method) must not leave the server reading and buffering a
// declared body of up to the payload limit for the whole body window: the
// connection closes once the answer is written. A request whose body has been
// read keeps the connection for reuse.
namespace {
class RefuseFromHeadersCallback final : public tos::http::HttpServer::Callback {
 public:
  void receive_request(
      std::unique_ptr<tos::http::HttpRequest>, std::shared_ptr<tos::http::HttpPayload>,
      td::Promise<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>> promise)
      override {
    promise.set_value(tos::json_rpc::unauthorized_response(""));
  }
};

class ErrorFromHeadersCallback final : public tos::http::HttpServer::Callback {
 public:
  void receive_request(
      std::unique_ptr<tos::http::HttpRequest>, std::shared_ptr<tos::http::HttpPayload>,
      td::Promise<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>> promise)
      override {
    promise.set_error(td::Status::Error("handler failed"));
  }
};

const std::string kLargeDeclaredBody =
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4000000\r\n\r\n" + std::string(1000, 'x');
}  // namespace

TEST(HttpServerLimits, an_answer_before_the_body_is_read_closes_after_the_response) {
  // Long header and body windows: any close inside the waits below comes from
  // the early answer, not from a deadline.
  auto limits = tos::json_rpc::listener_limits(0, 30, 30, 0);
  with_server(limits, [](int port) {
    Client early(port);
    ASSERT_TRUE(early.connect_with_retries());
    ASSERT_TRUE(early.send_all(kLargeDeclaredBody));
    std::string received;
    ASSERT_TRUE(early.read_until_clean_eof(3000, received));
    ASSERT_TRUE(received.rfind("HTTP/1.1 200", 0) == 0);
    ASSERT_TRUE(received.size() >= 7 && received.compare(received.size() - 7, 7, "\r\n0\r\n\r\n") == 0);
  });
}

TEST(HttpServerLimits, without_the_option_an_early_answer_keeps_reading_the_body) {
  // Control for the option: a listener that does not ask for it (a proxy
  // forwarding an upstream answer during an upload) keeps the connection.
  tos::http::HttpServer::Limits limits;
  limits.max_connections = 0;
  limits.request_header_timeout = 30;
  limits.request_body_timeout = 30;
  ASSERT_TRUE(!limits.close_after_early_answer);
  with_server(limits, [](int port) {
    Client early(port);
    ASSERT_TRUE(early.connect_with_retries());
    ASSERT_TRUE(early.send_all(kLargeDeclaredBody));
    std::string received;
    ASSERT_TRUE(early.stays_open(1500, received));
    ASSERT_TRUE(received.rfind("HTTP/1.1 200", 0) == 0);
  });
}

TEST(HttpServerLimits, a_handler_error_before_the_body_is_read_closes_after_the_response) {
  auto limits = tos::json_rpc::listener_limits(0, 30, 30, 0);
  with_server(
      limits,
      [](int port) {
        Client failed(port);
        ASSERT_TRUE(failed.connect_with_retries());
        ASSERT_TRUE(failed.send_all(kLargeDeclaredBody));
        std::string received;
        ASSERT_TRUE(failed.read_until_clean_eof(3000, received));
        ASSERT_TRUE(received.rfind("HTTP/1.1 502", 0) == 0);
        ASSERT_TRUE(received.find("Connection: close\r\n") != std::string::npos);
        ASSERT_TRUE(received.size() >= 4 && received.compare(received.size() - 4, 4, "\r\n\r\n") == 0);
      },
      std::make_shared<ErrorFromHeadersCallback>());
}

TEST(HttpServerLimits, an_answer_after_the_body_is_read_keeps_the_connection) {
  // Control for the test above: a request whose body has been read leaves the
  // connection open for the next request.
  auto limits = tos::json_rpc::listener_limits(0, 30, 30, 0);
  with_server(limits, [](int port) {
    Client reused(port);
    ASSERT_TRUE(reused.connect_with_retries());
    ASSERT_TRUE(reused.send_all("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello"));
    std::string first;
    ASSERT_TRUE(reused.read_chunked_response(3000, first));
    ASSERT_TRUE(first.rfind("HTTP/1.1 200", 0) == 0);
    ASSERT_TRUE(reused.request_ok(3000));
  });
}

TEST(JsonRpcHttpPolicy, a_refused_request_gets_the_whole_401_and_then_a_close) {
  auto limits = tos::json_rpc::listener_limits(0, 30, 30, 0);
  with_server(
      limits,
      [](int port) {
        Client refused(port);
        ASSERT_TRUE(refused.connect_with_retries());
        ASSERT_TRUE(refused.send_all(kLargeDeclaredBody));
        std::string received;
        ASSERT_TRUE(refused.read_until_clean_eof(3000, received));
        ASSERT_TRUE(received.rfind("HTTP/1.1 401", 0) == 0);
        ASSERT_TRUE(received.find("invalid or missing API key") != std::string::npos);
        ASSERT_TRUE(received.size() >= 7 && received.compare(received.size() - 7, 7, "\r\n0\r\n\r\n") == 0);
      },
      std::make_shared<RefuseFromHeadersCallback>());
}

TEST(JsonRpcHttpPolicy, timeout_arguments_must_parse_completely) {
  for (auto good : {"60", "0.5", "0", "120.25"}) {
    auto r = tos::json_rpc::parse_timeout_seconds(td::Slice(good));
    ASSERT_TRUE(r.is_ok());
  }
  ASSERT_EQ(tos::json_rpc::parse_timeout_seconds(td::Slice("60")).move_as_ok(), 60.0);
  ASSERT_EQ(tos::json_rpc::parse_timeout_seconds(td::Slice("0")).move_as_ok(), 0.0);
  // Each of these used to become 0 ("no deadline") or a negative number.
  for (auto bad : {"", "-1", "abc", "60s", " 60", "inf", "nan", "1e400", "6O"}) {
    ASSERT_TRUE(tos::json_rpc::parse_timeout_seconds(td::Slice(bad)).is_error());
  }
}

TEST(JsonRpcHttpPolicy, listener_has_a_response_deadline) {
  // A client that stops reading must not hold its connection and queued reply
  // forever; the mechanism is tested above, this pins that JSON-RPC uses it.
  ASSERT_TRUE(tos::json_rpc::kDefaultResponseTimeout > 0);
  auto limits = tos::json_rpc::listener_limits(1024, 30, 120, tos::json_rpc::kDefaultResponseTimeout);
  ASSERT_EQ(limits.response_timeout, tos::json_rpc::kDefaultResponseTimeout);
  ASSERT_EQ(limits.max_connections, static_cast<size_t>(1024));
  ASSERT_EQ(limits.request_header_timeout, 30.0);
  ASSERT_EQ(limits.request_body_timeout, 120.0);
  ASSERT_TRUE(limits.close_after_early_answer);
}

namespace {

// A local IPv4 address other than loopback, if this host has one.
std::string non_loopback_ipv4() {
  ifaddrs *list = nullptr;
  if (::getifaddrs(&list) != 0) {
    return {};
  }
  std::string found;
  for (auto *it = list; it != nullptr && found.empty(); it = it->ifa_next) {
    if (it->ifa_addr == nullptr || it->ifa_addr->sa_family != AF_INET || (it->ifa_flags & IFF_UP) == 0 ||
        (it->ifa_flags & IFF_LOOPBACK) != 0) {
      continue;
    }
    char text[INET_ADDRSTRLEN] = {};
    auto *in = reinterpret_cast<sockaddr_in *>(it->ifa_addr);
    if (::inet_ntop(AF_INET, &in->sin_addr, text, sizeof(text)) != nullptr) {
      found = text;
    }
  }
  ::freeifaddrs(list);
  return found;
}

bool tcp_connects(const std::string &ip, int port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  CHECK(::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) == 1);
  bool ok = ::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0;
  ::close(fd);
  return ok;
}

// The listener binds asynchronously; wait until loopback answers.
bool listener_is_up(int port) {
  for (int attempt = 0; attempt < 100; attempt++) {
    if (tcp_connects("127.0.0.1", port)) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return false;
}

// Runs `scenario` against a server listening on `address`.
void with_server_at(td::IPAddress address, std::function<void()> scenario) {
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<tos::http::HttpServer> server;
  scheduler.run_in_context([&] {
    server = tos::http::HttpServer::create(address, std::make_shared<OkCallback>(), tos::http::HttpServer::Limits{});
  });
  std::atomic<bool> done{false};
  std::thread client([&] {
    scenario();
    done = true;
  });
  while (!done) {
    scheduler.run(0.05);
  }
  client.join();
  scheduler.run_in_context([&] {
    server.reset();
    td::actor::SchedulerContext::get().stop();
  });
  while (scheduler.run(1)) {
  }
}

}  // namespace

TEST(HttpListenAddress, a_bare_port_means_loopback_and_an_address_must_be_explicit) {
  using tos::http::HttpServer;
  auto bare = HttpServer::parse_listen_address("8080").move_as_ok();
  ASSERT_EQ(bare.get_ip_str().str(), std::string("127.0.0.1"));
  ASSERT_EQ(bare.get_port(), 8080);
  auto any = HttpServer::parse_listen_address("0.0.0.0:8080").move_as_ok();
  ASSERT_EQ(any.get_ip_str().str(), std::string("0.0.0.0"));
  ASSERT_EQ(any.get_port(), 8080);
  auto v6 = HttpServer::parse_listen_address("[::1]:8080").move_as_ok();
  ASSERT_TRUE(v6.is_ipv6());
  ASSERT_EQ(v6.get_port(), 8080);
  for (std::string bad : {"",
                          "0",
                          "70000",
                          "80a",
                          " 8080",
                          "8080 ",
                          "+8080",
                          "08080",
                          "0.0.0.0:0",
                          "0.0.0.0:",
                          "0.0.0.0: 8080",
                          "0.0.0.0:8080 ",
                          " 0.0.0.0:8080",
                          "not-an-ip:80",
                          "localhost:8080",
                          "127.0.0.1:http",
                          "[::1]:0",
                          "[::1]:",
                          "[::1]:abc",
                          "[::1]:8080junk",
                          "[::1]: 8080",
                          "[::1]8080",
                          "::1:8080",
                          "[::1"}) {
    ASSERT_TRUE(HttpServer::parse_listen_address(bad).is_error());
  }
}

TEST(HttpListenAddress, a_bare_port_is_unreachable_from_other_interfaces) {
  auto other = non_loopback_ipv4();
  // Without a second address the refusal below would prove nothing, so the
  // test fails rather than passing unchecked.
  ASSERT_TRUE(!other.empty());
  int port = find_free_port();
  auto bare = tos::http::HttpServer::parse_listen_address(std::to_string(port)).move_as_ok();
  with_server_at(bare, [&] {
    ASSERT_TRUE(listener_is_up(port));
    ASSERT_TRUE(!tcp_connects(other, port));
  });
  // Control: asked for explicitly, the same listener is reachable there, so the
  // refusal above is the bind address and not a firewall or a dead listener.
  port = find_free_port();
  auto any = tos::http::HttpServer::parse_listen_address("0.0.0.0:" + std::to_string(port)).move_as_ok();
  with_server_at(any, [&] {
    ASSERT_TRUE(listener_is_up(port));
    ASSERT_TRUE(tcp_connects(other, port));
  });
}
