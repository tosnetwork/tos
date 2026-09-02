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

#include "http/http-server.h"
#include "http/http.h"
#include "td/actor/actor.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/tests.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <string>
#include <thread>

namespace {

class OkCallback : public tos::http::HttpServer::Callback {
 public:
  void receive_request(
      std::unique_ptr<tos::http::HttpRequest> request, std::shared_ptr<tos::http::HttpPayload> payload,
      td::Promise<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>>
          promise) override {
    auto response = tos::http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
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
  explicit Client(int port) : port_(port) {
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
void with_server(tos::http::HttpServer::Limits limits, std::function<void(int port)> scenario) {
  int port = find_free_port();
  td::IPAddress addr;
  addr.init_ipv4_port("127.0.0.1", port).ensure();

  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<tos::http::HttpServer> server;
  scheduler.run_in_context([&] {
    server = td::actor::create_actor<tos::http::HttpServer>("httpserver", addr, std::make_shared<OkCallback>(),
                                                            limits);
  });

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
