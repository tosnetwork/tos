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

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <ifaddrs.h>
#include <limits>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "http/http-client.h"
#include "http/http-inbound-connection.h"
#include "http/http-server.h"
#include "http/http.h"
#include "td/actor/actor.h"
#include "td/utils/Time.h"
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
    auto response = tos::http::HttpResponse::create("HTTP/1.1", status, status == 200 ? "OK" : "Method Not Allowed",
                                                    false, request->keep_alive())
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
  using ResponsePromise =
      td::Promise<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>>;

  explicit LargeResponseCallback(TransportObservation *observation, size_t response_bytes = 1024 * 1024,
                                 bool defer_responses = false)
      : observation_(observation)
      , response_bytes_(response_bytes)
      , released_(std::make_shared<std::atomic<bool>>(!defer_responses)) {
  }
  void receive_request(std::unique_ptr<tos::http::HttpRequest>, std::shared_ptr<tos::http::HttpPayload>,
                       ResponsePromise promise) override {
    ++observation_->calls;
    if (!released_->load()) {
      td::actor::create_actor<DeferredAnswer>("deferred-response", released_, std::move(promise), response_bytes_)
          .release();
      return;
    }
    answer(std::move(promise), response_bytes_);
  }

  void release_responses() {
    released_->store(true);
  }

 private:
  // Resolve the transport promise in its scheduler context, while the client
  // thread controls only an atomic release signal.
  class DeferredAnswer final : public td::actor::Actor {
   public:
    DeferredAnswer(std::shared_ptr<std::atomic<bool>> released, ResponsePromise promise, size_t response_bytes)
        : released_(std::move(released)), promise_(std::move(promise)), response_bytes_(response_bytes) {
    }
    void start_up() override {
      alarm_timestamp() = td::Timestamp::in(0.005);
    }
    void alarm() override {
      if (released_->load()) {
        answer(std::move(promise_), response_bytes_);
        stop();
      } else {
        alarm_timestamp() = td::Timestamp::in(0.005);
      }
    }

   private:
    std::shared_ptr<std::atomic<bool>> released_;
    ResponsePromise promise_;
    size_t response_bytes_;
  };

  static void answer(ResponsePromise promise, size_t response_bytes) {
    auto response = tos::http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
    response->add_header({"Transfer-Encoding", "Chunked"});
    response->complete_parse_header();
    auto payload = response->create_empty_payload().move_as_ok();
    payload->add_chunk(td::BufferSlice(std::string(response_bytes, 'x')));
    payload->complete_parse();
    promise.set_value({std::move(response), std::move(payload)});
  }

  TransportObservation *observation_;
  size_t response_bytes_;
  std::shared_ptr<std::atomic<bool>> released_;
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
  auto callback = std::make_shared<LargeResponseCallback>(&observation, 4 * 1024 * 1024, true);
  with_server(
      limits,
      [&](int port) {
        std::vector<std::unique_ptr<Client>> held;
        for (int i = 0; i < 8; ++i) {
          auto client = std::make_unique<Client>(port, 4096);
          ASSERT_TRUE(client->connect_with_retries());
          ASSERT_TRUE(client->send_all("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"));
          held.push_back(std::move(client));
          if (i == 0) {
            // Exercise a setup slower than the response deadline. No response
            // starts until all eight slots and the refusal have been observed.
            std::this_thread::sleep_for(std::chrono::milliseconds(600));
          }
        }
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (observation.calls < 8 && std::chrono::steady_clock::now() < until)
          std::this_thread::sleep_for(std::chrono::milliseconds(2));
        ASSERT_EQ(observation.calls.load(), 8);
        Client extra(port);
        ASSERT_TRUE(extra.connect_with_retries());
        // A complete request makes accidental admission observable in the
        // callback, rather than an idle-header timeout looking like refusal.
        extra.send_all("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        ASSERT_TRUE(extra.wait_for_eof(2000));
        ASSERT_EQ(observation.calls.load(), 8);
        callback->release_responses();
        // Keep the eight clients nonreading. Retry until the response deadline
        // frees a slot, rather than guessing when its actor runs on this host.
        const auto recovery_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        bool recovered = false;
        while (!recovered && std::chrono::steady_clock::now() < recovery_deadline) {
          Client client(port);
          recovered = client.connect_with_retries() && client.request_ok(1000);
          if (!recovered) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
          }
        }
        ASSERT_TRUE(recovered);
        ASSERT_EQ(observation.calls.load(), 9);
      },
      callback);
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
  auto limits = tos::json_rpc::listener_limits(0, 30, 30, tos::json_rpc::kDefaultResponseTimeout).move_as_ok();
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
  auto limits = tos::json_rpc::listener_limits(0, 30, 30, tos::json_rpc::kDefaultResponseTimeout).move_as_ok();
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
  auto limits = tos::json_rpc::listener_limits(0, 30, 30, tos::json_rpc::kDefaultResponseTimeout).move_as_ok();
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
  auto limits = tos::json_rpc::listener_limits(0, 30, 30, tos::json_rpc::kDefaultResponseTimeout).move_as_ok();
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
  auto limits_r = tos::json_rpc::listener_limits(1024, 30, 120, tos::json_rpc::kDefaultResponseTimeout);
  ASSERT_TRUE(limits_r.is_ok());
  auto limits = limits_r.move_as_ok();
  ASSERT_EQ(limits.response_timeout, tos::json_rpc::kDefaultResponseTimeout);
  ASSERT_EQ(limits.max_connections, static_cast<size_t>(1024));
  ASSERT_EQ(limits.request_header_timeout, 30.0);
  ASSERT_EQ(limits.request_body_timeout, 120.0);
  ASSERT_TRUE(limits.close_after_early_answer);
}

TEST(JsonRpcHttpPolicy, the_response_deadline_is_mandatory_and_bounded) {
  for (auto good : {"60", "0.5", "86400", "1e-3"}) {
    ASSERT_TRUE(tos::json_rpc::parse_response_timeout_seconds(td::Slice(good)).is_ok());
  }
  for (auto bad : {"0", "0.0", "-0", "-1", "", "inf", "nan", "1e400", "86400.5", "1e300", "60s"}) {
    ASSERT_TRUE(tos::json_rpc::parse_response_timeout_seconds(td::Slice(bad)).is_error());
  }
  // The listener cannot be constructed without one, whatever the caller
  // passes; the default is accepted.
  for (double bad : {0.0, -0.0, -1.0, std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity(),
                     std::numeric_limits<double>::quiet_NaN(), tos::json_rpc::kMaxResponseTimeout * 2, 1e300}) {
    ASSERT_TRUE(tos::json_rpc::listener_limits(0, 30, 120, bad).is_error());
  }
  ASSERT_TRUE(tos::json_rpc::listener_limits(0, 30, 120, tos::json_rpc::kMaxResponseTimeout).is_ok());
  ASSERT_EQ(tos::json_rpc::kDefaultResponseTimeout, 60.0);
}

namespace {
struct PipelineObservation {
  std::atomic<int> calls{0};
  std::atomic<bool> closed{false};
  std::atomic<size_t> output_peak{0};
  std::atomic<double> closed_at{0};
};

class SmallReplyCallback final : public tos::http::HttpServer::Callback {
 public:
  explicit SmallReplyCallback(PipelineObservation *observation) : observation_(observation) {
  }
  void receive_request(
      std::unique_ptr<tos::http::HttpRequest>, std::shared_ptr<tos::http::HttpPayload>,
      td::Promise<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>> promise)
      override {
    ++observation_->calls;
    auto response = tos::http::HttpResponse::create("HTTP/1.1", 200, "OK", false, true).move_as_ok();
    response->add_header({"Transfer-Encoding", "Chunked"});
    response->complete_parse_header();
    auto payload = response->create_empty_payload().move_as_ok();
    payload->add_chunk(td::BufferSlice(std::string(16 << 10, 'x')));
    payload->complete_parse();
    promise.set_value({std::move(response), std::move(payload)});
  }

 private:
  PipelineObservation *observation_;
};

class PipelinedInbound final : public tos::http::HttpInboundConnection {
 public:
  PipelinedInbound(td::SocketFd fd, PipelineObservation *observation, double response_timeout)
      : HttpInboundConnection(std::move(fd), std::make_shared<SmallReplyCallback>(observation),
                              tos::http::HttpServer::AllMetrics{}, 30, 30, false, 0, response_timeout)
      , observation_(observation) {
  }
  ~PipelinedInbound() override {
    observation_->closed_at = td::Time::now();
    observation_->closed = true;
  }
  void payload_written() override {
    observation_->output_peak.store(std::max(observation_->output_peak.load(), buffered_fd_.ready_for_flush_write()));
    HttpInboundConnection::payload_written();
  }

 private:
  PipelineObservation *observation_;
};

// Connects a client with small socket buffers on both ends to a
// PipelinedInbound and runs `scenario` with the client's descriptor.
void with_pipelined_inbound(double response_timeout, std::function<void(int, PipelineObservation &)> scenario) {
  int listener = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(listener >= 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(::bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
  socklen_t size = sizeof(address);
  CHECK(::getsockname(listener, reinterpret_cast<sockaddr *>(&address), &size) == 0);
  CHECK(::listen(listener, 1) == 0);
  int client = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(client >= 0);
  int small = 4096;
  CHECK(::setsockopt(client, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) == 0);
  CHECK(::connect(client, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
  // Bound send_for's own syscall as well as its retry loop when the server's
  // read window fills. Per-call flags alone need not bound a blocking socket.
  int flags = ::fcntl(client, F_GETFL, 0);
  CHECK(flags >= 0);
  CHECK(::fcntl(client, F_SETFL, flags | O_NONBLOCK) == 0);
  int accepted = ::accept(listener, nullptr, nullptr);
  CHECK(accepted >= 0);
  ::close(listener);
  CHECK(::setsockopt(accepted, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
  PipelineObservation observation;
  td::actor::Scheduler scheduler({2});
  scheduler.run_in_context([&] {
    auto fd = td::SocketFd::from_native_fd(td::NativeFd(accepted)).move_as_ok();
    td::actor::create_actor<PipelinedInbound>(td::actor::ActorOptions().with_name("pipelined-inbound").with_poll(),
                                              std::move(fd), &observation, response_timeout)
        .release();
  });
  std::atomic<bool> done{false};
  std::thread runner([&] {
    scenario(client, observation);
    done = true;
  });
  while (!done)
    scheduler.run(0.01);
  runner.join();
  ::close(client);
  scheduler.run_in_context([&] { td::actor::SchedulerContext::get().stop(); });
  while (scheduler.run(1)) {
  }
}
}  // namespace

// Replies queued behind output the client never read inherit the deadline of
// that output: a client that keeps sending small requests without reading
// cannot keep pushing the deadline out. The connection, and the replies it
// holds, are gone by the first unwritten reply's deadline.
TEST(HttpServerLimits, replies_queued_behind_unread_output_do_not_extend_its_deadline) {
  const double timeout = 0.5;
  with_pipelined_inbound(timeout, [timeout](int fd, PipelineObservation &observation) {
    const std::string request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    double start = td::Time::now();
    // One request every 20 ms for four deadlines, never reading.
    while (td::Time::now() < start + 4 * timeout && !observation.closed) {
      if (::send(fd, request.data(), request.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(request.size())) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!observation.closed && std::chrono::steady_clock::now() < until)
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    // The replies did pile up in the server's own buffer, behind the socket.
    ASSERT_TRUE(observation.output_peak > (64u << 10));
    ASSERT_TRUE(observation.calls > 10);
    ASSERT_TRUE(observation.closed);
    // The first reply that stayed unwritten was queued within the first few
    // requests; allow scheduling slack on top of its deadline.
    ASSERT_TRUE(observation.closed_at.load() - start < timeout + 0.5);
  });
}

// A client that reads a few bytes at a time makes progress on every write,
// and still loses the connection at the deadline: it is a total deadline,
// not one renewed by each write.
TEST(HttpServerLimits, a_trickle_reader_does_not_renew_the_response_deadline) {
  const double timeout = 0.5;
  with_pipelined_inbound(timeout, [timeout](int fd, PipelineObservation &observation) {
    // Queue enough replies to exceed kernel buffering on either platform;
    // the client reads only 64 bytes every 10 ms. An already-flushed reply
    // cannot exercise the response writing deadline.
    constexpr int reply_count = 64;
    std::string requests;
    for (int i = 0; i < reply_count; i++) {
      requests += "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    }
    double start = td::Time::now();
    CHECK(::send(fd, requests.data(), requests.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(requests.size()));
    size_t received = 0;
    while (!observation.closed && td::Time::now() < start + 5) {
      char buf[64];
      auto n = ::recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
      if (n > 0) {
        received += static_cast<size_t>(n);
      } else if (n == 0) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(received > 0);
    ASSERT_TRUE(received < reply_count * (16u << 10));
    ASSERT_TRUE(observation.closed);
    ASSERT_TRUE(observation.closed_at.load() - start < timeout + 0.5);
  });
}

// Header admission is an asynchronous barrier: while a request waits for it,
// the connection parses none of the body, reserves nothing and dispatches
// nothing, and holds no more input than the header read-ahead, however much
// body the client has already sent. These tests hold the admission answer
// open from the test thread.
namespace {
struct AdmissionGate {
  std::atomic<int> asked{0};
  std::atomic<int> decision{0};  // 0 pending, 1 admit, 2 refuse
  std::atomic<int> received{0};
  std::atomic<size_t> body_bytes{0};
  std::atomic<size_t> peak_input{0};
  std::atomic<bool> closed{false};
  // The listener's reservation, and what it held when the consumer saw the
  // whole body.
  tos::http::BodyBudget *budget = nullptr;
  std::atomic<size_t> reserved_at_completion{0};
};

class GateHolder final : public td::actor::Actor {
 public:
  GateHolder(AdmissionGate *gate, td::Promise<tos::http::HttpServer::Admission> promise)
      : gate_(gate), promise_(std::move(promise)) {
  }
  void start_up() override {
    alarm_timestamp() = td::Timestamp::in(0.005);
  }
  void alarm() override {
    int decision = gate_->decision.load();
    if (decision == 1) {
      promise_.set_value(tos::http::HttpServer::Admission::admit());
      stop();
    } else if (decision == 2) {
      auto refusal = tos::json_rpc::unauthorized_response("");
      promise_.set_value(tos::http::HttpServer::Admission::refuse(std::move(refusal.first), std::move(refusal.second)));
      stop();
    } else {
      alarm_timestamp() = td::Timestamp::in(0.005);
    }
  }

 private:
  AdmissionGate *gate_;
  td::Promise<tos::http::HttpServer::Admission> promise_;
};

class GatedCallback final : public tos::http::HttpServer::Callback {
 public:
  explicit GatedCallback(AdmissionGate *gate) : gate_(gate) {
  }
  void admit_request(const tos::http::HttpRequest &, td::Promise<tos::http::HttpServer::Admission> promise) override {
    ++gate_->asked;
    td::actor::create_actor<GateHolder>("gate", gate_, std::move(promise)).release();
  }
  // The body consumer: answers once the whole body has arrived, with its size.
  void receive_request(
      std::unique_ptr<tos::http::HttpRequest>, std::shared_ptr<tos::http::HttpPayload> payload,
      td::Promise<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>> promise)
      override {
    ++gate_->received;
    class Waiter final : public tos::http::HttpPayload::Callback {
     public:
      Waiter(AdmissionGate *gate, std::weak_ptr<tos::http::HttpPayload> payload,
             td::Promise<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>>
                 promise)
          : gate_(gate), payload_(std::move(payload)), promise_(std::move(promise)) {
      }
      void run(size_t) override {
      }
      void completed() override {
        if (auto payload = payload_.lock()) {
          gate_->body_bytes = payload->ready_bytes();
        }
        if (gate_->budget) {
          gate_->reserved_at_completion = gate_->budget->reserved();
        }
        auto response = tos::http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
        response->add_header({"Content-Length", "0"});
        response->complete_parse_header();
        auto out = response->create_empty_payload().move_as_ok();
        promise_.set_value({std::move(response), std::move(out)});
      }

     private:
      AdmissionGate *gate_;
      std::weak_ptr<tos::http::HttpPayload> payload_;
      td::Promise<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>>
          promise_;
    };
    payload->add_callback(std::make_unique<Waiter>(gate_, payload, std::move(promise)));
  }

 private:
  AdmissionGate *gate_;
};

class GatedInbound final : public tos::http::HttpInboundConnection {
 public:
  GatedInbound(td::SocketFd fd, AdmissionGate *gate, std::shared_ptr<tos::http::BodyBudget> budget,
               double header_timeout)
      : HttpInboundConnection(std::move(fd), std::make_shared<GatedCallback>(gate), tos::http::HttpServer::AllMetrics{},
                              header_timeout, 30, false, 0, 30, true, std::move(budget))
      , gate_(gate) {
  }
  ~GatedInbound() override {
    gate_->closed = true;
  }
  td::Status receive(td::ChainBufferReader &input) override {
    gate_->peak_input.store(std::max(gate_->peak_input.load(), input.size()));
    return HttpInboundConnection::receive(input);
  }

 private:
  AdmissionGate *gate_;
};

void with_gated_inbound(std::shared_ptr<tos::http::BodyBudget> budget,
                        std::function<void(int, AdmissionGate &)> scenario, double header_timeout = 30) {
  int listener = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(listener >= 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(::bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
  socklen_t size = sizeof(address);
  CHECK(::getsockname(listener, reinterpret_cast<sockaddr *>(&address), &size) == 0);
  CHECK(::listen(listener, 1) == 0);
  int client = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(client >= 0);
  // Enqueue more than the server's bounded read-ahead even on hosts with a
  // small default TCP send buffer. The client queue is not the server window.
  int send_buffer = 4 * tos::http::HttpInboundConnection::header_read_ahead();
  CHECK(::setsockopt(client, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) == 0);
  CHECK(::connect(client, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
  int accepted = ::accept(listener, nullptr, nullptr);
  CHECK(accepted >= 0);
  ::close(listener);
  AdmissionGate gate;
  gate.budget = budget.get();
  td::actor::Scheduler scheduler({2});
  scheduler.run_in_context([&] {
    auto fd = td::SocketFd::from_native_fd(td::NativeFd(accepted)).move_as_ok();
    td::actor::create_actor<GatedInbound>(td::actor::ActorOptions().with_name("gated-inbound").with_poll(),
                                          std::move(fd), &gate, budget, header_timeout)
        .release();
  });
  std::atomic<bool> done{false};
  std::thread runner([&] {
    scenario(client, gate);
    done = true;
  });
  while (!done)
    scheduler.run(0.01);
  runner.join();
  ::close(client);
  scheduler.run_in_context([&] { td::actor::SchedulerContext::get().stop(); });
  while (scheduler.run(1)) {
  }
}

// Sends as much of `data` from `offset` as the socket takes within `ms`.
void send_for(int fd, const std::string &data, size_t &offset, int ms) {
  auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
  while (offset < data.size() && std::chrono::steady_clock::now() < until) {
    auto n =
        ::send(fd, data.data() + offset, std::min(data.size() - offset, size_t{16 << 10}), MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n > 0) {
      offset += static_cast<size_t>(n);
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }
}

bool wait_for(const std::function<bool()> &condition, int ms) {
  auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
  while (!condition()) {
    if (std::chrono::steady_clock::now() >= until) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return true;
}

std::string read_status_line(int fd, int ms) {
  std::string got;
  auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
  while (got.find("\r\n") == std::string::npos && std::chrono::steady_clock::now() < until) {
    char buf[512];
    auto n = ::recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n > 0) {
      got.append(buf, static_cast<size_t>(n));
    } else if (n == 0) {
      break;
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
  }
  return got.substr(0, got.find("\r\n"));
}

const size_t kGatedBody = 1 << 20;
const std::string kGatedHeaders =
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(kGatedBody) + "\r\n\r\n";

// While admission is pending: nothing dispatched, nothing reserved, input
// held to the read-ahead and counted as such.
void expect_held(AdmissionGate &gate, tos::http::BodyBudget &budget) {
  ASSERT_TRUE(wait_for([&] { return gate.asked == 1; }, 2000));
  ASSERT_TRUE(wait_for([&] { return budget.read_ahead() > 0; }, 2000));
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  ASSERT_EQ(gate.received.load(), 0);
  ASSERT_EQ(gate.body_bytes.load(), static_cast<size_t>(0));
  ASSERT_EQ(budget.reserved(), static_cast<size_t>(0));
  ASSERT_TRUE(gate.peak_input.load() <= tos::http::HttpInboundConnection::header_read_ahead());
  ASSERT_TRUE(budget.read_ahead() > 0);
  ASSERT_TRUE(budget.read_ahead() <= tos::http::HttpInboundConnection::header_read_ahead());
}

// Admitting releases the body to the consumer, charged to the reservation
// while it is read, and the reservation is returned once it is answered.
void expect_admitted_and_released(int fd, const std::string &request, size_t &offset, AdmissionGate &gate,
                                  tos::http::BodyBudget &budget) {
  gate.decision = 1;
  send_for(fd, request, offset, 5000);
  ASSERT_EQ(offset, request.size());
  ASSERT_EQ(read_status_line(fd, 5000), std::string("HTTP/1.1 200 OK"));
  ASSERT_EQ(gate.received.load(), 1);
  ASSERT_EQ(gate.body_bytes.load(), kGatedBody);
  // The whole body was charged to the listener while the consumer held it.
  ASSERT_EQ(gate.reserved_at_completion.load(), kGatedBody);
  ASSERT_TRUE(wait_for([&] { return budget.reserved() == 0 && budget.read_ahead() == 0; }, 2000));
}
}  // namespace

TEST(HttpAdmission, a_pending_admission_holds_a_body_sent_with_the_headers) {
  auto budget = std::make_shared<tos::http::BodyBudget>(64 << 20);
  with_gated_inbound(budget, [budget](int fd, AdmissionGate &gate) {
    std::string request = kGatedHeaders + std::string(kGatedBody, 'b');
    size_t offset = 0;
    send_for(fd, request, offset, 300);
    ASSERT_TRUE(offset > tos::http::HttpInboundConnection::header_read_ahead());
    expect_held(gate, *budget);
    expect_admitted_and_released(fd, request, offset, gate, *budget);
  });
}

TEST(HttpAdmission, a_pending_admission_holds_a_body_sent_in_fragments) {
  auto budget = std::make_shared<tos::http::BodyBudget>(64 << 20);
  with_gated_inbound(budget, [budget](int fd, AdmissionGate &gate) {
    std::string request = kGatedHeaders + std::string(kGatedBody, 'b');
    size_t offset = 0;
    // The headers in three pieces, then the body 8 KiB at a time.
    for (size_t piece : {size_t{10}, size_t{30}, kGatedHeaders.size() - 40}) {
      std::string part = request.substr(offset, piece);
      ASSERT_EQ(::send(fd, part.data(), part.size(), MSG_NOSIGNAL), static_cast<ssize_t>(part.size()));
      offset += piece;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    while (offset < (256u << 10)) {
      size_t target = offset + (8 << 10);
      std::string part = request.substr(offset, target - offset);
      size_t sent = 0;
      send_for(fd, part, sent, 50);
      offset += sent;
      if (sent < part.size()) {
        break;
      }
    }
    expect_held(gate, *budget);
    expect_admitted_and_released(fd, request, offset, gate, *budget);
  });
}

TEST(HttpAdmission, a_refused_request_never_reaches_the_body_consumer) {
  auto budget = std::make_shared<tos::http::BodyBudget>(64 << 20);
  with_gated_inbound(budget, [budget](int fd, AdmissionGate &gate) {
    std::string request = kGatedHeaders + std::string(kGatedBody, 'b');
    size_t offset = 0;
    send_for(fd, request, offset, 300);
    expect_held(gate, *budget);
    gate.decision = 2;
    ASSERT_EQ(read_status_line(fd, 5000), std::string("HTTP/1.1 401 Unauthorized"));
    ASSERT_TRUE(wait_for([&] { return gate.closed.load(); }, 5000));
    ASSERT_EQ(gate.received.load(), 0);
    ASSERT_EQ(gate.body_bytes.load(), static_cast<size_t>(0));
    ASSERT_EQ(budget->reserved(), static_cast<size_t>(0));
    ASSERT_EQ(budget->read_ahead(), static_cast<size_t>(0));
  });
}

// A listener without a shared reservation (a proxy) still waits for
// admission before reading a body, and then reads it unreserved.
TEST(HttpAdmission, a_listener_without_a_reservation_still_waits_for_admission) {
  with_gated_inbound(nullptr, [](int fd, AdmissionGate &gate) {
    std::string request = kGatedHeaders + std::string(kGatedBody, 'b');
    size_t offset = 0;
    send_for(fd, request, offset, 300);
    ASSERT_TRUE(wait_for([&] { return gate.asked == 1; }, 2000));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    ASSERT_EQ(gate.received.load(), 0);
    ASSERT_TRUE(gate.peak_input.load() <= tos::http::HttpInboundConnection::header_read_ahead());
    gate.decision = 1;
    send_for(fd, request, offset, 5000);
    ASSERT_EQ(read_status_line(fd, 5000), std::string("HTTP/1.1 200 OK"));
    ASSERT_EQ(gate.body_bytes.load(), kGatedBody);
  });
}

// An admission that never answers does not pin the connection: the request
// is held to the header deadline, then the connection and its read-ahead go.
TEST(HttpAdmission, an_unanswered_admission_ends_at_the_header_deadline) {
  auto budget = std::make_shared<tos::http::BodyBudget>(64 << 20);
  with_gated_inbound(
      budget,
      [budget](int fd, AdmissionGate &gate) {
        std::string request = kGatedHeaders + std::string(kGatedBody, 'b');
        size_t offset = 0;
        auto start = std::chrono::steady_clock::now();
        send_for(fd, request, offset, 100);
        ASSERT_TRUE(wait_for([&] { return gate.asked == 1; }, 2000));
        ASSERT_TRUE(wait_for([&] { return gate.closed.load(); }, 3000));
        ASSERT_TRUE(std::chrono::steady_clock::now() - start < std::chrono::milliseconds(500 + 750));
        ASSERT_EQ(gate.received.load(), 0);
        ASSERT_EQ(budget->reserved(), static_cast<size_t>(0));
        ASSERT_EQ(budget->read_ahead(), static_cast<size_t>(0));
      },
      0.5);
}

// The consumer takes the body's reservation over when it drains the body and
// keeps it until the request is answered.
TEST(HttpAdmission, a_consumer_keeps_the_reservation_until_it_answers) {
  auto budget = std::make_shared<tos::http::BodyBudget>(64 << 20);
  auto reservation = budget->reserve(1000);
  ASSERT_TRUE(reservation != nullptr);
  auto payload = std::make_shared<tos::http::HttpPayload>(tos::http::HttpPayload::PayloadType::pt_content_length,
                                                          1 << 16, 4 << 20, 1000);
  payload->attach_reservation(std::move(reservation));
  bool answered = false;
  td::Promise<int> promise = td::PromiseCreator::lambda([&](td::Result<int>) { answered = true; });
  tos::json_rpc::hold_body_reservation_until_answered(payload, promise);
  payload.reset();
  // The payload (and with it the connection's view of the body) is gone; the
  // consumer's copy is still charged.
  ASSERT_EQ(budget->reserved(), static_cast<size_t>(1000));
  promise.set_value(1);
  ASSERT_TRUE(answered);
  promise = {};
  ASSERT_EQ(budget->reserved(), static_cast<size_t>(0));
  // Reservations never exceed the capacity.
  auto all = budget->reserve(64 << 20);
  ASSERT_TRUE(all != nullptr);
  ASSERT_TRUE(budget->reserve(1) == nullptr);
  all.reset();
  ASSERT_EQ(budget->reserved(), static_cast<size_t>(0));
}

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

namespace {

// A backend that completes TCP handshakes (the kernel does, from the listen
// backlog) and never answers.
struct SilentBackend {
  int fd = -1;
  int port = 0;
  SilentBackend() {
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    CHECK(::listen(fd, 64) == 0);
    socklen_t len = sizeof(addr);
    CHECK(::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
    port = ntohs(addr.sin_port);
  }
  ~SilentBackend() {
    ::close(fd);
  }
};

std::unique_ptr<tos::http::HttpRequest> get_request() {
  auto request = tos::http::HttpRequest::create("GET", "/", "HTTP/1.1").move_as_ok();
  request->add_header({"Host", "backend"});
  request->complete_parse_header().ensure();
  return request;
}

class NoopClientCallback : public tos::http::HttpClient::Callback {
 public:
  void on_ready() override {
  }
  void on_stop_ready() override {
  }
};

}  // namespace

TEST(HttpMultiClient, connections_are_capped_and_a_silent_backend_releases_them_at_the_deadline) {
  SilentBackend backend;
  td::IPAddress addr;
  addr.init_ipv4_port("127.0.0.1", backend.port).ensure();

  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<tos::http::HttpClient> client;
  std::vector<td::uint32> codes;
  std::vector<double> answered_after;
  auto start = td::Time::now();
  auto send = [&](double deadline) {
    auto request = get_request();
    auto payload = request->create_empty_payload().move_as_ok();
    td::actor::send_closure(
        client, &tos::http::HttpClient::send_request, std::move(request), std::move(payload),
        td::Timestamp::in(deadline),
        [&](td::Result<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>>
                R) {
          codes.push_back(R.is_ok() ? R.ok().first->code() : 0);
          answered_after.push_back(td::Time::now() - start);
        });
  };
  scheduler.run_in_context([&] {
    client = tos::http::HttpClient::create_multi("", addr, 2, 1, std::make_shared<NoopClientCallback>());
    // Two take the connections; the third is refused at once.
    send(0.5);
    send(0.5);
    send(0.5);
  });
  auto wait_for = [&](size_t n, double limit) {
    auto until = td::Timestamp::in(limit);
    while (codes.size() < n && !until.is_in_past()) {
      scheduler.run(0.05);
    }
  };
  wait_for(3, 10.0);
  ASSERT_EQ(codes.size(), static_cast<size_t>(3));
  ASSERT_EQ(codes[0], static_cast<td::uint32>(503));
  ASSERT_TRUE(answered_after[0] < 0.4);
  // The silent backend never answers: both expire at their deadline as 504.
  ASSERT_EQ(codes[1], static_cast<td::uint32>(504));
  ASSERT_EQ(codes[2], static_cast<td::uint32>(504));
  // Their connections are released, so a new request gets one again.
  scheduler.run(0.2);
  scheduler.run_in_context([&] { send(0.3); });
  wait_for(4, 10.0);
  ASSERT_EQ(codes.size(), static_cast<size_t>(4));
  ASSERT_EQ(codes[3], static_cast<td::uint32>(504));

  scheduler.run_in_context([&] {
    client.reset();
    td::actor::SchedulerContext::get().stop();
  });
  while (scheduler.run(1)) {
  }
}

namespace {

// A backend that answers each request with headers and the first bytes of a
// longer body, then stops sending while keeping the connection open.
class StallingBackend {
 public:
  StallingBackend() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listen_fd_ >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(::bind(listen_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    CHECK(::listen(listen_fd_, 16) == 0);
    socklen_t len = sizeof(addr);
    CHECK(::getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
    port_ = ntohs(addr.sin_port);
    thread_ = std::thread([this] { serve(); });
  }
  ~StallingBackend() {
    stop_ = true;
    thread_.join();
    for (int fd : accepted_) {
      ::close(fd);
    }
    ::close(listen_fd_);
  }
  int port() const {
    return port_;
  }

 private:
  void serve() {
    while (!stop_) {
      pollfd p{listen_fd_, POLLIN, 0};
      if (::poll(&p, 1, 50) <= 0) {
        continue;
      }
      int fd = ::accept(listen_fd_, nullptr, nullptr);
      if (fd < 0) {
        continue;
      }
      accepted_.push_back(fd);
      std::string request;
      char buf[1024];
      while (request.find("\r\n\r\n") == std::string::npos) {
        auto n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
          break;
        }
        request.append(buf, static_cast<size_t>(n));
      }
      std::string head = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n0123456789";
      ::send(fd, head.data(), head.size(), MSG_NOSIGNAL);
    }
  }

  int listen_fd_ = -1;
  int port_ = 0;
  std::atomic<bool> stop_{false};
  std::vector<int> accepted_;
  std::thread thread_;
};

class CompletionCounter : public tos::http::HttpPayload::Callback {
 public:
  explicit CompletionCounter(std::atomic<int> &completed) : completed_(completed) {
  }
  void run(size_t) override {
  }
  void completed() override {
    completed_++;
  }

 private:
  std::atomic<int> &completed_;
};

}  // namespace

TEST(HttpMultiClient, a_body_still_arriving_at_the_deadline_fails_and_frees_its_connection) {
  StallingBackend backend;
  td::IPAddress addr;
  addr.init_ipv4_port("127.0.0.1", backend.port()).ensure();

  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<tos::http::HttpClient> client;
  std::vector<td::uint32> codes;
  std::vector<std::shared_ptr<tos::http::HttpPayload>> bodies;
  std::atomic<int> completed{0};
  auto send = [&] {
    auto request = get_request();
    auto payload = request->create_empty_payload().move_as_ok();
    td::actor::send_closure(
        client, &tos::http::HttpClient::send_request, std::move(request), std::move(payload), td::Timestamp::in(0.5),
        [&](td::Result<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>>
                R) {
          if (R.is_error()) {
            codes.push_back(0);
            return;
          }
          auto answer = R.move_as_ok();
          codes.push_back(answer.first->code());
          answer.second->add_callback(std::make_unique<CompletionCounter>(completed));
          bodies.push_back(std::move(answer.second));
        });
  };
  auto run_until = [&](std::function<bool()> done, double limit) {
    auto until = td::Timestamp::in(limit);
    while (!done() && !until.is_in_past()) {
      scheduler.run(0.05);
    }
  };
  scheduler.run_in_context([&] {
    client = tos::http::HttpClient::create_multi("", addr, 1, 1, std::make_shared<NoopClientCallback>());
    send();
  });
  // The headers arrive in time, so the response itself is a 200.
  run_until([&] { return codes.size() == 1; }, 5.0);
  ASSERT_EQ(codes.size(), static_cast<size_t>(1));
  ASSERT_EQ(codes[0], static_cast<td::uint32>(200));
  ASSERT_TRUE(!bodies[0]->parse_completed());
  // At the deadline the body fails and its consumer is told once.
  run_until([&] { return completed.load() == 1; }, 5.0);
  ASSERT_EQ(completed.load(), 1);
  ASSERT_TRUE(bodies[0]->is_error());
  ASSERT_TRUE(!bodies[0]->parse_completed());
  // The connection was released: with a cap of one, a new request gets it.
  scheduler.run(0.2);
  scheduler.run_in_context([&] { send(); });
  run_until([&] { return codes.size() == 2; }, 5.0);
  ASSERT_EQ(codes.size(), static_cast<size_t>(2));
  ASSERT_EQ(codes[1], static_cast<td::uint32>(200));

  scheduler.run_in_context([&] {
    client.reset();
    td::actor::SchedulerContext::get().stop();
  });
  while (scheduler.run(1)) {
  }
}

namespace {

std::shared_ptr<tos::http::HttpPayload> response_body(const std::string &framing_header, const std::string &value) {
  auto response = tos::http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
  response->add_header({framing_header, value});
  response->complete_parse_header();
  return response->create_empty_payload().move_as_ok();
}

td::Status feed(tos::http::HttpPayload &payload, const std::string &bytes) {
  td::ChainBufferWriter writer;
  writer.append(bytes);
  auto reader = writer.extract_reader();
  reader.sync_with_writer();
  return payload.parse(reader);
}

}  // namespace

TEST(HttpPayloadEnd, AConsumerAddedAfterAFailureIsToldAtOnce) {
  auto body = response_body("Content-Length", "100");
  ASSERT_TRUE(feed(*body, "0123456789").is_ok());
  body->fail();
  std::atomic<int> completed{0};
  body->add_callback(std::make_unique<CompletionCounter>(completed));
  ASSERT_EQ(completed.load(), 1);
  ASSERT_TRUE(body->is_error());
}

TEST(HttpPayloadEnd, AFailedBodyNeitherCompletesNorNotifiesTwice) {
  for (auto framing : {std::make_pair(std::string("Content-Length"), std::string("10")),
                       std::make_pair(std::string("Transfer-Encoding"), std::string("chunked"))}) {
    auto body = response_body(framing.first, framing.second);
    std::atomic<int> completed{0};
    body->add_callback(std::make_unique<CompletionCounter>(completed));
    body->fail();
    body->fail();
    ASSERT_EQ(completed.load(), 1);
    // The rest of the body arriving late cannot complete it.
    auto rest =
        framing.first == "Content-Length" ? std::string("0123456789") : std::string("a\r\n0123456789\r\n0\r\n\r\n");
    ASSERT_TRUE(feed(*body, rest).is_error());
    body->complete_parse();
    ASSERT_TRUE(!body->parse_completed());
    ASSERT_EQ(completed.load(), 1);
  }
}

TEST(HttpPayloadEnd, ACompletedBodyCannotBeFailed) {
  for (auto framing : {std::make_pair(std::string("Content-Length"), std::string("10")),
                       std::make_pair(std::string("Transfer-Encoding"), std::string("chunked"))}) {
    auto body = response_body(framing.first, framing.second);
    std::atomic<int> completed{0};
    body->add_callback(std::make_unique<CompletionCounter>(completed));
    auto all =
        framing.first == "Content-Length" ? std::string("0123456789") : std::string("a\r\n0123456789\r\n0\r\n\r\n");
    ASSERT_TRUE(feed(*body, all).is_ok());
    ASSERT_TRUE(body->parse_completed());
    body->fail();
    ASSERT_TRUE(!body->is_error());
    ASSERT_EQ(completed.load(), 1);
  }
}
