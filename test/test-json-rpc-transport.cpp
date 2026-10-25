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

// Runs the real JSON-RPC server and its listener over loopback TCP, with no
// validator behind it: every request below is answered by the server itself
// (unknown method, invalid request, batch errors), which is enough to drive
// the transport and the id handling end to end. Each scenario runs with the
// API key disabled and enabled.

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <dirent.h>
#include <functional>
#include <limits>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "auto/tl/lite_api.hpp"
#include "http/http-inbound-connection.h"
#include "services/index-reader.h"
#include "services/service-common.h"
#include "td/actor/actor.h"
#include "td/utils/base64.h"
#include "td/utils/buffer.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/port/ServerSocketFd.h"
#include "td/utils/tests.h"
#include "tl-utils/lite-utils.hpp"

#include "json-rpc-http-policy.h"
#include "json-rpc-server-internal.h"
#include "json-rpc-server.h"

namespace {

using Clock = std::chrono::steady_clock;

const char *const kApiKey = "transport-test-key";

// Keep the address reserved until the fixture shuts down. Closing the probe
// before the asynchronous listener binds lets a client's ephemeral source bind
// claim the same port. Match the real listener's reuse options so it can
// share this bound, non-listening socket. Ordinary client binds do not enable
// reuse and cannot claim the reserved port.
class PortReservation {
 public:
  PortReservation() {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd_ >= 0);
    int reuse = 1;
    CHECK(::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);
#ifdef SO_REUSEPORT
    CHECK(::setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) == 0);
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(::bind(fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    CHECK(::getsockname(fd_, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
    port_ = ntohs(addr.sin_port);
  }
  PortReservation(const PortReservation &) = delete;
  PortReservation &operator=(const PortReservation &) = delete;
  ~PortReservation() {
    ::close(fd_);
  }
  int port() const {
    return port_;
  }

 private:
  int fd_ = -1;
  int port_ = 0;
};

size_t open_fd_count() {
  size_t count = 0;
  DIR *dir = ::opendir("/proc/self/fd");
  CHECK(dir != nullptr);
  while (::readdir(dir) != nullptr) {
    ++count;
  }
  ::closedir(dir);
  return count;
}

class Client {
 public:
  Client(int port, int receive_window, uint32_t source = INADDR_LOOPBACK)
      : port_(port), receive_window_(receive_window), source_(source) {
  }
  ~Client() {
    close();
  }

  bool connect() {
    for (int attempt = 0; attempt < 100; attempt++) {
      fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
      if (fd_ < 0) {
        return false;
      }
      if (receive_window_ > 0) {
        CHECK(::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &receive_window_, sizeof(receive_window_)) == 0);
      }
      sockaddr_in local{};
      local.sin_family = AF_INET;
      local.sin_addr.s_addr = htonl(source_);
      CHECK(::bind(fd_, reinterpret_cast<sockaddr *>(&local), sizeof(local)) == 0);
      sockaddr_in addr{};
      addr.sin_family = AF_INET;
      addr.sin_port = htons(static_cast<uint16_t>(port_));
      addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      if (::connect(fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0) {
        return true;
      }
      ::close(fd_);
      fd_ = -1;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return false;
  }

  bool send_all(const std::string &data) {
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

  // Reads one chunked HTTP response and returns its status line and its
  // de-chunked body. Bytes past the response stay buffered for the next call.
  bool read_response(int timeout_ms, std::string &status, std::string &body) {
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    size_t header_end;
    while ((header_end = pending_.find("\r\n\r\n")) == std::string::npos) {
      if (!fill(deadline)) {
        return false;
      }
    }
    status = pending_.substr(0, pending_.find("\r\n"));
    std::string headers = pending_.substr(0, header_end);
    size_t pos = header_end + 4;
    body.clear();
    bool chunked = headers.find("Transfer-Encoding: chunked") != std::string::npos ||
                   headers.find("Transfer-Encoding: Chunked") != std::string::npos;
    if (!chunked) {
      pending_ = pending_.substr(pos);
      return true;
    }
    while (true) {
      size_t line_end;
      while ((line_end = pending_.find("\r\n", pos)) == std::string::npos) {
        if (!fill(deadline)) {
          return false;
        }
      }
      size_t size = std::stoul(pending_.substr(pos, line_end - pos), nullptr, 16);
      while (pending_.size() < line_end + 2 + size + 2) {
        if (!fill(deadline)) {
          return false;
        }
      }
      body += pending_.substr(line_end + 2, size);
      pos = line_end + 2 + size + 2;
      if (size == 0) {
        break;
      }
    }
    pending_ = pending_.substr(pos);
    return true;
  }

  // True when the server has closed the connection: reading what is left
  // ends in EOF or a reset within the timeout.
  bool drains_to_close(int timeout_ms, size_t &received) {
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    received = pending_.size();
    while (true) {
      auto now = Clock::now();
      if (now >= deadline) {
        return false;
      }
      pollfd pfd{fd_, POLLIN, 0};
      int remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
      if (::poll(&pfd, 1, remaining) <= 0) {
        return false;
      }
      char buf[65536];
      auto n = ::recv(fd_, buf, sizeof(buf), 0);
      if (n == 0) {
        return true;
      }
      if (n < 0) {
        return errno == ECONNRESET;
      }
      received += static_cast<size_t>(n);
    }
  }

  // Sends as much of stream[offset..] as the socket takes without waiting.
  // Returns false once the connection is closed by the server.
  bool send_some(const std::string &stream, size_t &offset) {
    while (offset < stream.size()) {
      auto n = ::send(fd_, stream.data() + offset, stream.size() - offset, MSG_NOSIGNAL | MSG_DONTWAIT);
      if (n < 0) {
        return errno == EAGAIN || errno == EWOULDBLOCK;
      }
      if (n == 0) {
        return false;
      }
      offset += static_cast<size_t>(n);
    }
    return true;
  }

  // Reads at most `bytes` without waiting; returns false once the connection
  // is closed by the server.
  bool trickle(size_t bytes, size_t &received) {
    char buf[256];
    auto n = ::recv(fd_, buf, std::min(bytes, sizeof(buf)), MSG_DONTWAIT);
    if (n == 0) {
      return false;
    }
    if (n < 0) {
      return errno == EAGAIN || errno == EWOULDBLOCK;
    }
    received += static_cast<size_t>(n);
    return true;
  }

  void close() {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

 private:
  bool fill(Clock::time_point deadline) {
    auto now = Clock::now();
    if (now >= deadline) {
      return false;
    }
    pollfd pfd{fd_, POLLIN, 0};
    int remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
    if (::poll(&pfd, 1, remaining) <= 0) {
      return false;
    }
    char buf[65536];
    auto n = ::recv(fd_, buf, sizeof(buf), 0);
    if (n <= 0) {
      return false;
    }
    pending_.append(buf, static_cast<size_t>(n));
    return true;
  }

  int port_;
  int receive_window_;
  uint32_t source_;
  int fd_ = -1;
  std::string pending_;
};

std::string post(const std::string &body, bool with_key) {
  std::string request = "POST /jsonRPC HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n";
  if (with_key) {
    request += std::string("X-API-Key: ") + kApiKey + "\r\n";
  }
  request += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
  return request;
}

std::string request_object(const std::string &id_literal) {
  return "{\"jsonrpc\":\"2.0\",\"id\":" + id_literal + ",\"method\":\"noSuchMethod\"}";
}

// Runs `scenario` on a client thread against a JSON-RPC server, pumping the
// actor scheduler on this thread until the scenario ends.
void with_json_rpc(tos::JsonRpcServer::Options options, std::function<void(int port)> scenario) {
  PortReservation reservation;
  const int port = reservation.port();
  td::IPAddress addr;
  addr.init_ipv4_port("127.0.0.1", port).ensure();
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<tos::JsonRpcServer> server;
  scheduler.run_in_context([&] {
    server = tos::JsonRpcServer::create({}, std::move(options));
    td::actor::send_closure(server, &tos::JsonRpcServer::listen, addr);
  });
  std::atomic<bool> done{false};
  std::thread client([&] {
    scenario(port);
    done = true;
  });
  while (!done) {
    scheduler.run(0.02);
  }
  client.join();
  scheduler.run_in_context([&] {
    server.reset();
    td::actor::SchedulerContext::get().stop();
  });
  while (scheduler.run(1)) {
  }
}

tos::JsonRpcServer::Options options_for(bool with_key, double response_timeout = 60) {
  tos::JsonRpcServer::Options options;
  options.readonly = true;
  options.response_timeout = response_timeout;
  if (with_key) {
    options.api_key = kApiKey;
  }
  return options;
}

std::string id_field(const std::string &literal) {
  return "\"id\":" + literal + ",";
}

// 254 characters plus quotes: exactly the 256-byte bound.
const std::string kLongestStringId = "\"" + std::string(254, 'a') + "\"";
// 127 escaped quotes: 2 + 2 * 127 = 256 serialized bytes from 127 raw bytes.
const std::string kLongestEscapedId = "\"" + [] {
  std::string s;
  for (int i = 0; i < 127; i++) {
    s += "\\\"";
  }
  return s;
}() + "\"";
// One more escaped quote: 129 raw bytes serialize to 258.
const std::string kEscapedIdOverBound = "\"" + [] {
  std::string s;
  for (int i = 0; i < 128; i++) {
    s += "\\\"";
  }
  return s;
}() + "\"";
const std::string kStringIdOverBound = "\"" + std::string(255, 'a') + "\"";
const std::string kLongestNumberId = "1" + std::string(255, '0');
const std::string kNumberIdOverBound = "1" + std::string(256, '0');

}  // namespace

TEST(JsonRpcTransport, listener_port_stays_reserved_before_async_bind) {
  PortReservation reservation;
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_TRUE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(static_cast<uint16_t>(reservation.port()));
  const int result = ::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
  const int error = errno;
  ::close(fd);
  ASSERT_EQ(result, -1);
  ASSERT_EQ(error, EADDRINUSE);
  // The production listener can bind while the reservation is still held.
  auto listener = td::ServerSocketFd::open(reservation.port(), "127.0.0.1");
  ASSERT_TRUE(listener.is_ok());
}

TEST(JsonRpcTransport, connections_of_one_source_leave_other_sources_capacity) {
  for (bool with_key : {false, true}) {
    auto options = options_for(with_key);
    options.max_connections = 8;  // The production policy gives each source one slot.
    with_json_rpc(options, [with_key](int port) {
      Client hog(port, 0);
      ASSERT_TRUE(hog.connect());
      // Occupy the source allowance with a silent TCP connection. Neither a
      // key nor request headers are needed to reach connection admission.
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      Client excess(port, 0);
      ASSERT_TRUE(excess.connect());
      size_t received;
      ASSERT_TRUE(excess.drains_to_close(3000, received));
      ASSERT_EQ(received, 0u);

      Client honest(port, 0, 0x7f000002);
      ASSERT_TRUE(honest.connect());
      ASSERT_TRUE(honest.send_all(post(request_object("7"), with_key)));
      std::string status, body;
      ASSERT_TRUE(honest.read_response(3000, status, body));
      ASSERT_EQ(status, std::string("HTTP/1.1 200 OK"));
      ASSERT_TRUE(body.find(id_field("7")) != std::string::npos);

      hog.close();
      bool recovered = false;
      for (int attempt = 0; attempt < 30 && !recovered; ++attempt) {
        Client retry(port, 0);
        ASSERT_TRUE(retry.connect());
        if (retry.send_all("GET /healthcheck HTTP/1.1\r\nHost: localhost\r\n\r\n")) {
          recovered = retry.read_response(100, status, body) && body == "OK";
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      ASSERT_TRUE(recovered);
    });
  }
}

TEST(JsonRpcTransport, keyless_endpoints_close_even_when_keepalive_is_requested) {
  for (const auto &route : {"GET /healthcheck", "GET /api-info", "OPTIONS /"}) {
    with_json_rpc(options_for(true), [route](int port) {
      Client client(port, 0);
      ASSERT_TRUE(client.connect());
      ASSERT_TRUE(
          client.send_all(std::string(route) + " HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"));
      std::string status, body;
      ASSERT_TRUE(client.read_response(3000, status, body));
      if (std::string(route) == "OPTIONS /") {
        ASSERT_EQ(status, std::string("HTTP/1.1 204 No Content"));
        ASSERT_TRUE(body.empty());
      } else {
        ASSERT_EQ(status, std::string("HTTP/1.1 200 OK"));
        if (std::string(route) == "GET /healthcheck") {
          ASSERT_EQ(body, std::string("OK"));
        } else {
          auto parsed = td::json_decode(td::MutableSlice(body));
          ASSERT_TRUE(parsed.is_ok());
          auto metadata = parsed.move_as_ok();
          ASSERT_TRUE(metadata.type() == td::JsonValue::Type::Object);
          auto name = metadata.get_object().get_required_string_field("name");
          ASSERT_TRUE(name.is_ok());
          ASSERT_EQ(name.move_as_ok(), std::string("TOS JSON-RPC API"));
        }
      }
      size_t rest;
      ASSERT_TRUE(client.drains_to_close(3000, rest));
      ASSERT_EQ(rest, 0u);
    });
  }
}

TEST(JsonRpcTransport, rpc_response_honors_connection_close) {
  with_json_rpc(options_for(true), [](int port) {
    Client client(port, 0);
    ASSERT_TRUE(client.connect());
    auto request = post(request_object("7"), true);
    request.insert(request.find("\r\n") + 2, "Connection: close\r\n");
    ASSERT_TRUE(client.send_all(request));
    std::string status, body;
    ASSERT_TRUE(client.read_response(3000, status, body));
    ASSERT_TRUE(body.find(id_field("7")) != std::string::npos);
    size_t rest;
    ASSERT_TRUE(client.drains_to_close(3000, rest));
  });
}

TEST(JsonRpcTransport, ids_up_to_the_bound_are_echoed_and_longer_ones_are_refused_with_a_null_id) {
  for (bool with_key : {false, true}) {
    with_json_rpc(options_for(with_key), [with_key](int port) {
      Client client(port, 0);
      ASSERT_TRUE(client.connect());
      auto expect = [&](const std::string &id, const std::string &echoed, const std::string &code) {
        ASSERT_TRUE(client.send_all(post(request_object(id), with_key)));
        std::string status, body;
        ASSERT_TRUE(client.read_response(5000, status, body));
        ASSERT_EQ(status, std::string("HTTP/1.1 200 OK"));
        ASSERT_TRUE(body.find(id_field(echoed)) != std::string::npos);
        ASSERT_TRUE(body.find("\"code\":" + code) != std::string::npos);
      };
      expect(kLongestStringId, kLongestStringId, "-32601");
      expect(kLongestEscapedId, kLongestEscapedId, "-32601");
      expect(kLongestNumberId, kLongestNumberId, "-32601");
      expect("7", "7", "-32601");
      expect(kStringIdOverBound, "null", "-32600");
      expect(kEscapedIdOverBound, "null", "-32600");
      expect(kNumberIdOverBound, "null", "-32600");
      expect("{\"x\":1}", "null", "-32600");
      expect("[1]", "null", "-32600");
      expect("true", "null", "-32600");
      expect("1e+-.3", "null", "-32600");
      // A request id near the body limit is never echoed back.
      expect("\"" + std::string(1 << 20, 'b') + "\"", "null", "-32600");
    });
  }
}

TEST(JsonRpcTransport, a_wrong_key_is_refused_before_any_id_is_read) {
  with_json_rpc(options_for(true), [](int port) {
    Client client(port, 0);
    ASSERT_TRUE(client.connect());
    std::string request = post(request_object(kLongestStringId), false);
    ASSERT_TRUE(client.send_all(request));
    std::string status, body;
    ASSERT_TRUE(client.read_response(5000, status, body));
    ASSERT_EQ(status, std::string("HTTP/1.1 401 Unauthorized"));
    ASSERT_TRUE(body.find(std::string(254, 'a')) == std::string::npos);
  });
}

TEST(JsonRpcTransport, batch_elements_with_unechoable_ids_get_null_ids) {
  for (bool with_key : {false, true}) {
    with_json_rpc(options_for(with_key), [with_key](int port) {
      Client client(port, 0);
      ASSERT_TRUE(client.connect());
      std::string batch = "[" + request_object(kLongestEscapedId) + "," + request_object(kEscapedIdOverBound) + "," +
                          request_object(kNumberIdOverBound) + ",5," + request_object("42") + "]";
      ASSERT_TRUE(client.send_all(post(batch, with_key)));
      std::string status, body;
      ASSERT_TRUE(client.read_response(5000, status, body));
      ASSERT_EQ(status, std::string("HTTP/1.1 200 OK"));
      ASSERT_TRUE(body.find(id_field(kLongestEscapedId)) != std::string::npos);
      ASSERT_TRUE(body.find(id_field("42")) != std::string::npos);
      ASSERT_TRUE(body.find(std::string(256, '0')) == std::string::npos);
      ASSERT_TRUE(body.find(kEscapedIdOverBound) == std::string::npos);
      // Two unechoable ids and one non-object element: three null ids.
      size_t nulls = 0;
      for (size_t at = body.find("\"id\":null"); at != std::string::npos; at = body.find("\"id\":null", at + 1)) {
        ++nulls;
      }
      ASSERT_EQ(nulls, static_cast<size_t>(3));
    });
  }
}

namespace {
size_t count_of(const std::string &haystack, const std::string &needle) {
  size_t count = 0;
  for (size_t at = haystack.find(needle); at != std::string::npos; at = haystack.find(needle, at + 1)) {
    ++count;
  }
  return count;
}
}  // namespace

// A batch that runs out of time still validates its elements first: an
// element whose id cannot be echoed, or that is not an object, is an invalid
// request with id null; only a valid element gets the timeout, under its id.
TEST(JsonRpcTransport, a_timed_out_batch_still_refuses_invalid_ids) {
  for (bool with_key : {false, true}) {
    auto options = options_for(with_key);
    // Expires before the first element is dispatched, so every element is
    // answered from the batch timeout path.
    options.request_timeout = 1e-9;
    with_json_rpc(options, [with_key](int port) {
      Client client(port, 0);
      ASSERT_TRUE(client.connect());
      std::string batch = "[" + request_object(kLongestStringId) + "," + request_object(kStringIdOverBound) + "," +
                          request_object(kNumberIdOverBound) + "," + request_object("{\"x\":1}") + "," +
                          request_object("true") + ",7," + request_object("42") + "]";
      ASSERT_TRUE(client.send_all(post(batch, with_key)));
      std::string status, body;
      ASSERT_TRUE(client.read_response(5000, status, body));
      // Valid ids: the timeout error, under their own id.
      ASSERT_EQ(count_of(body, "\"id\":" + kLongestStringId + ",\"error\":{\"code\":-32603"), static_cast<size_t>(1));
      ASSERT_EQ(count_of(body, "\"id\":42,\"error\":{\"code\":-32603"), static_cast<size_t>(1));
      ASSERT_EQ(count_of(body, "Request batch timed out"), static_cast<size_t>(2));
      // Oversized string and number ids, object and boolean ids, and a
      // non-object element: invalid requests with id null.
      ASSERT_EQ(count_of(body, "\"id\":null,\"error\":{\"code\":-32600"), static_cast<size_t>(5));
      ASSERT_TRUE(body.find(std::string(255, 'a')) == std::string::npos);
      ASSERT_TRUE(body.find(std::string(256, '0')) == std::string::npos);
    });
  }
}

// After the deadline the remaining elements are still checked exactly as on
// the dispatch path, envelope included: an object without an id whose
// envelope is invalid is an invalid request, not a notification, and is
// answered; a valid notification still gets no entry. The deadline here has
// already passed when the first element is reached -- this test server has no
// backend that could make an element slow -- so the request ahead of the two
// is answered with the timeout, as a slow element would leave it.
TEST(JsonRpcTransport, a_timed_out_batch_validates_envelopes_before_dropping_notifications) {
  for (bool with_key : {false, true}) {
    auto options = options_for(with_key);
    options.request_timeout = 1e-9;
    with_json_rpc(options, [with_key](int port) {
      Client client(port, 0);
      ASSERT_TRUE(client.connect());
      std::string batch = R"([{"jsonrpc":"2.0","id":1,"method":"getMasterchainInfo"},)"
                          R"({"jsonrpc":"1.0","method":"x"},)"
                          R"({"jsonrpc":"2.0","method":"x"}])";
      ASSERT_TRUE(client.send_all(post(batch, with_key)));
      std::string status, body;
      ASSERT_TRUE(client.read_response(5000, status, body));
      ASSERT_EQ(status, std::string("HTTP/1.1 200 OK"));
      ASSERT_EQ(count_of(body, "\"id\":1,\"error\":{\"code\":-32603,\"message\":\"Request batch timed out\""),
                static_cast<size_t>(1));
      // The malformed element: answered, -32600, naming the jsonrpc member.
      ASSERT_EQ(count_of(body, "\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Invalid Request: 'jsonrpc' must"),
                static_cast<size_t>(1));
      // Exactly those two entries: the valid notification has none.
      ASSERT_EQ(count_of(body, "\"jsonrpc\":\"2.0\",\"id\":"), static_cast<size_t>(2));
    });
  }
}

TEST(JsonRpcTransport, a_listener_without_a_response_deadline_is_not_constructed) {
  for (double bad :
       {0.0, -1.0, std::numeric_limits<double>::infinity(), std::numeric_limits<double>::quiet_NaN(), 1e300}) {
    with_json_rpc(options_for(false, bad), [](int port) {
      // Give the listener time to come up if it were going to.
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      int fd = ::socket(AF_INET, SOCK_STREAM, 0);
      CHECK(fd >= 0);
      sockaddr_in addr{};
      addr.sin_family = AF_INET;
      addr.sin_port = htons(static_cast<uint16_t>(port));
      addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      ASSERT_TRUE(::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0);
      ::close(fd);
    });
  }
  // Control: the same scenario with a valid deadline connects.
  with_json_rpc(options_for(false, 1.0), [](int port) {
    Client client(port, 0);
    ASSERT_TRUE(client.connect());
  });
}

namespace {

constexpr double kResponseTimeout = 1.0;
// Scheduling allowance on top of the deadline: the alarm fires on the actor
// scheduler, which this test pumps in 20 ms slices on a shared CI runner.
constexpr double kTolerance = 1.0;

// A batch of 100 unknown-method requests, each with an id at the bound: about
// 34 KB of reply per request.
std::string fat_batch(bool with_key) {
  std::string batch = "[";
  for (int i = 0; i < 100; i++) {
    if (i) {
      batch += ",";
    }
    batch += request_object(kLongestStringId);
  }
  batch += "]";
  return post(batch, with_key);
}

// A client that stops reading (or reads a few bytes at a time) while it keeps
// sending requests as fast as the server takes them, for three deadlines. The
// replies outgrow the kernel's socket buffers and pile up in the server; none
// of them may move the deadline of the output the client has not read. The
// server must drop the connection, and every byte it held for it, by that
// deadline.
void stalled_client_is_released_by_the_deadline(bool with_key, bool trickle) {
  // Per-request logging would make the server too slow to outgrow the socket
  // buffers within the test.
  auto verbosity = GET_VERBOSITY_LEVEL();
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(WARNING));
  auto options = options_for(with_key, kResponseTimeout);
  // The source budget would refuse this client at header admission long
  // before its replies outgrew the socket; this test is about the deadline.
  options.per_ip_rate_requests = 0;
  options.per_ip_ingress_requests = 0;
  with_json_rpc(options, [with_key, trickle](int port) {
    auto baseline_mem = td::BufferAllocator::get_buffer_mem();
    Client client(port, 4096);
    ASSERT_TRUE(client.connect());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto fds_connected = open_fd_count();
    // 400 batches: about 12 MB of requests asking for about 14 MB of replies.
    std::string stream;
    auto request = fat_batch(with_key);
    for (int i = 0; i < 400; i++) {
      stream += request;
    }
    size_t offset = 0;
    auto start = Clock::now();
    auto give_up = start + std::chrono::seconds(20);
    // Once the server holds this much more than at the start, replies are
    // queued behind output the client has not read: the request read-ahead
    // alone stays far below it.
    const size_t stalled_mem = baseline_mem + (512 << 10);
    Clock::time_point stalled_at{};
    bool stalled = false;
    size_t peak_mem = 0;
    size_t trickled = 0;
    bool server_closed = false;
    double released_after = -1;
    while (Clock::now() < give_up) {
      if (!server_closed && !client.send_some(stream, offset)) {
        server_closed = true;
      }
      if (trickle && !server_closed && !client.trickle(64, trickled)) {
        server_closed = true;
      }
      auto mem = td::BufferAllocator::get_buffer_mem();
      peak_mem = std::max(peak_mem, mem);
      if (!stalled && mem > stalled_mem) {
        stalled = true;
        stalled_at = Clock::now();
      }
      if (stalled && mem <= baseline_mem + (256 << 10) && open_fd_count() < fds_connected) {
        released_after = std::chrono::duration<double>(Clock::now() - stalled_at).count();
        break;
      }
      if (stalled && Clock::now() > stalled_at + std::chrono::duration<double>(kResponseTimeout + kTolerance)) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    LOG(WARNING) << "peak buffer memory over baseline: " << (peak_mem - baseline_mem) << " bytes; sent " << offset
                 << " bytes; released " << released_after << " s after the stall was seen";
    // The stall was real: the server held well over a megabyte of replies
    // for this client.
    ASSERT_TRUE(stalled);
    ASSERT_TRUE(peak_mem > baseline_mem + (1 << 20));
    // Released by the deadline plus tolerance, counted from the moment the
    // stall was seen (the first unwritten reply was queued no later): the
    // server's socket is closed and its input and output buffers are freed.
    ASSERT_TRUE(released_after >= 0);
    // The client sees the close once it reads what was in flight, and never
    // gets the replies the server dropped.
    size_t received = 0;
    ASSERT_TRUE(client.drains_to_close(5000, received));
  });
  SET_VERBOSITY_LEVEL(verbosity);
}

}  // namespace

TEST(JsonRpcTransport, a_non_reading_client_is_released_by_the_response_deadline) {
  stalled_client_is_released_by_the_deadline(false, false);
  stalled_client_is_released_by_the_deadline(true, false);
}

TEST(JsonRpcTransport, a_trickle_reading_client_is_released_by_the_response_deadline) {
  stalled_client_is_released_by_the_deadline(false, true);
  stalled_client_is_released_by_the_deadline(true, true);
}

namespace {

bool wait_until(const std::function<bool()> &condition, int timeout_ms) {
  auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
  while (!condition()) {
    if (Clock::now() >= deadline) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return true;
}

std::string post_headers(size_t content_length, const std::string &key) {
  std::string request = "POST /jsonRPC HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n";
  if (!key.empty()) {
    request += "X-API-Key: " + key + "\r\n";
  }
  request += "Content-Length: " + std::to_string(content_length) + "\r\n\r\n";
  return request;
}

// A valid JSON-RPC request padded to exactly `size` bytes.
std::string padded_request(size_t size) {
  std::string head = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"noSuchMethod\",\"params\":{\"pad\":\"";
  std::string tail = "\"}}";
  CHECK(size > head.size() + tail.size());
  return head + std::string(size - head.size() - tail.size(), 'p') + tail;
}

tos::JsonRpcServer::Options budget_options(bool with_key, std::shared_ptr<tos::http::BodyBudget> budget) {
  auto options = options_for(with_key);
  options.body_budget = std::move(budget);
  return options;
}

}  // namespace

// A request with a wrong key is refused from its headers. Its body is never
// reserved, parsed or handed to the server, whether it arrives with the
// headers or in fragments after them, and the connection holds no more of it
// than the header read-ahead.
TEST(JsonRpcTransport, a_wrong_key_never_reaches_the_body_or_the_body_reservation) {
  auto budget = std::make_shared<tos::http::BodyBudget>(tos::json_rpc::kListenerBodyBudgetBytes);
  with_json_rpc(budget_options(true, budget), [budget](int port) {
    const size_t declared = 4000000;
    const std::string body = padded_request(declared);
    std::atomic<bool> sampling{true};
    std::atomic<size_t> max_reserved{0};
    std::atomic<size_t> max_read_ahead{0};
    std::thread sampler([&] {
      while (sampling) {
        max_reserved = std::max(max_reserved.load(), budget->reserved());
        max_read_ahead = std::max(max_read_ahead.load(), budget->read_ahead());
        std::this_thread::sleep_for(std::chrono::microseconds(200));
      }
    });

    // Headers and the first megabyte of the body in one write.
    Client together(port, 0);
    ASSERT_TRUE(together.connect());
    // Header rejection may close the socket before the client writes the whole
    // body fragment. The 401 and zero-reservation checks below remain required.
    (void)together.send_all(post_headers(declared, "wrong-key") + body.substr(0, 1 << 20));
    std::string status, reply;
    ASSERT_TRUE(together.read_response(5000, status, reply));
    ASSERT_EQ(status, std::string("HTTP/1.1 401 Unauthorized"));
    size_t rest = 0;
    ASSERT_TRUE(together.drains_to_close(5000, rest));

    // Headers in two pieces, then the body in 32 KiB fragments.
    Client fragments(port, 0);
    ASSERT_TRUE(fragments.connect());
    auto headers = post_headers(declared, "wrong-key");
    ASSERT_TRUE(fragments.send_all(headers.substr(0, 40)));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    ASSERT_TRUE(fragments.send_all(headers.substr(40)));
    for (size_t at = 0; at < (1u << 20); at += 32 << 10) {
      if (!fragments.send_all(body.substr(at, 32 << 10))) {
        break;  // the server has already answered and closed
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    ASSERT_TRUE(fragments.read_response(5000, status, reply));
    ASSERT_EQ(status, std::string("HTTP/1.1 401 Unauthorized"));
    ASSERT_TRUE(fragments.drains_to_close(5000, rest));

    sampling = false;
    sampler.join();
    ASSERT_EQ(max_reserved.load(), static_cast<size_t>(0));
    ASSERT_TRUE(max_read_ahead.load() <= tos::http::HttpInboundConnection::header_read_ahead());
    ASSERT_TRUE(wait_until([&] { return budget->read_ahead() == 0; }, 2000));

    // Control: the right key reserves the declared body before reading it,
    // and closing the connection mid-body releases it.
    Client admitted(port, 0);
    ASSERT_TRUE(admitted.connect());
    ASSERT_TRUE(admitted.send_all(post_headers(declared, kApiKey) + body.substr(0, 1 << 20)));
    ASSERT_TRUE(wait_until([&] { return budget->reserved() == declared; }, 5000));
    admitted.close();
    ASSERT_TRUE(wait_until([&] { return budget->reserved() == 0; }, 5000));
  });
}

// Admitted requests share the listener's 64 MiB body reservation: sixteen
// maximum-size bodies fill it, the seventeenth is refused from its headers,
// and the capacity comes back when a request is answered or its connection
// closes. Run with the API key off and on.
TEST(JsonRpcTransport, admitted_bodies_share_the_listener_reservation) {
  for (bool with_key : {false, true}) {
    auto budget = std::make_shared<tos::http::BodyBudget>(tos::json_rpc::kListenerBodyBudgetBytes);
    with_json_rpc(budget_options(with_key, budget), [budget, with_key](int port) {
      const size_t max_body = tos::http::HttpRequest::max_payload_size();
      const std::string key = with_key ? kApiKey : "";
      const std::string body = padded_request(max_body);
      std::vector<std::unique_ptr<Client>> held;
      for (int i = 0; i < 16; i++) {
        auto client = std::make_unique<Client>(port, 0);
        ASSERT_TRUE(client->connect());
        ASSERT_TRUE(client->send_all(post_headers(max_body, key) + body.substr(0, 1024)));
        held.push_back(std::move(client));
      }
      ASSERT_TRUE(wait_until([&] { return budget->reserved() == tos::json_rpc::kListenerBodyBudgetBytes; }, 5000));

      Client refused(port, 0);
      ASSERT_TRUE(refused.connect());
      ASSERT_TRUE(refused.send_all(post_headers(max_body, key) + body.substr(0, 1024)));
      std::string status, reply;
      ASSERT_TRUE(refused.read_response(5000, status, reply));
      ASSERT_EQ(status, std::string("HTTP/1.1 503 Service Unavailable"));
      size_t rest = 0;
      ASSERT_TRUE(refused.drains_to_close(5000, rest));
      ASSERT_EQ(budget->reserved(), tos::json_rpc::kListenerBodyBudgetBytes);

      // Completion: the first body arrives in full and is answered.
      ASSERT_TRUE(held[0]->send_all(body.substr(1024)));
      ASSERT_TRUE(held[0]->read_response(10000, status, reply));
      ASSERT_EQ(status, std::string("HTTP/1.1 200 OK"));
      ASSERT_TRUE(reply.find("-32601") != std::string::npos);
      ASSERT_TRUE(
          wait_until([&] { return budget->reserved() == tos::json_rpc::kListenerBodyBudgetBytes - max_body; }, 5000));

      // Teardown: a client that goes away mid-body.
      held[1]->close();
      ASSERT_TRUE(wait_until(
          [&] { return budget->reserved() == tos::json_rpc::kListenerBodyBudgetBytes - 2 * max_body; }, 5000));

      // The freed capacity admits new requests again.
      Client late(port, 0);
      ASSERT_TRUE(late.connect());
      ASSERT_TRUE(late.send_all(post_headers(max_body, key) + body.substr(0, 1024)));
      ASSERT_TRUE(
          wait_until([&] { return budget->reserved() == tos::json_rpc::kListenerBodyBudgetBytes - max_body; }, 5000));

      held.clear();
      late.close();
      ASSERT_TRUE(wait_until([&] { return budget->reserved() == 0 && budget->read_ahead() == 0; }, 5000));
    });
  }
}

// A body that is not delivered in time loses its connection at the body
// deadline, and its reservation with it.
TEST(JsonRpcTransport, a_withheld_body_releases_its_reservation_at_the_body_deadline) {
  for (bool with_key : {false, true}) {
    auto budget = std::make_shared<tos::http::BodyBudget>(tos::json_rpc::kListenerBodyBudgetBytes);
    auto options = budget_options(with_key, budget);
    options.request_body_timeout = 1.0;
    with_json_rpc(options, [budget, with_key](int port) {
      const size_t declared = 1 << 20;
      std::vector<std::unique_ptr<Client>> held;
      for (int i = 0; i < 4; i++) {
        auto client = std::make_unique<Client>(port, 0);
        ASSERT_TRUE(client->connect());
        ASSERT_TRUE(client->send_all(post_headers(declared, with_key ? kApiKey : "") + std::string(100, ' ')));
        held.push_back(std::move(client));
      }
      ASSERT_TRUE(wait_until([&] { return budget->reserved() == 4 * declared; }, 5000));
      auto admitted_at = Clock::now();
      ASSERT_TRUE(wait_until([&] { return budget->reserved() == 0; }, 5000));
      ASSERT_TRUE(Clock::now() - admitted_at < std::chrono::milliseconds(1000 + 750));
      for (auto &client : held) {
        size_t rest = 0;
        ASSERT_TRUE(client->drains_to_close(5000, rest));
      }
    });
  }
}

// Header admission spends the source's ingress budget atomically: of
// several requests whose headers arrive at once from one source, with their
// bodies held back, only the allowance is admitted (and reserves its body);
// the rest get 429 before any of their body is admitted. Admission resumes
// once the window refills.
TEST(JsonRpcTransport, concurrent_headers_from_one_source_spend_the_ingress_allowance) {
  for (bool with_key : {false, true}) {
    auto budget = std::make_shared<tos::http::BodyBudget>(tos::json_rpc::kListenerBodyBudgetBytes);
    auto options = budget_options(with_key, budget);
    options.per_ip_ingress_requests = 3;
    options.per_ip_ingress_window = 1.5;
    with_json_rpc(options, [budget, with_key](int port) {
      const size_t declared = 1 << 20;
      const std::string head = post_headers(declared, with_key ? kApiKey : "") + std::string(1024, ' ');
      std::vector<std::unique_ptr<Client>> clients;
      for (int i = 0; i < 6; i++) {
        clients.push_back(std::make_unique<Client>(port, 0));
        ASSERT_TRUE(clients.back()->connect());
      }
      auto start = Clock::now();
      for (auto &client : clients) {
        ASSERT_TRUE(client->send_all(head));
      }
      ASSERT_TRUE(wait_until([&] { return budget->reserved() == 3 * declared; }, 3000));
      size_t refused = 0;
      for (auto &client : clients) {
        std::string status, reply;
        if (client->read_response(300, status, reply)) {
          ASSERT_EQ(status, std::string("HTTP/1.1 429 Too Many Requests"));
          ASSERT_TRUE(reply.find("-32005") != std::string::npos);
          ++refused;
        }
      }
      ASSERT_EQ(refused, static_cast<size_t>(3));
      // Never more than the allowance was admitted.
      ASSERT_EQ(budget->reserved(), 3 * declared);
      // Within the window, a seventh request is refused as well...
      Client late(port, 0);
      ASSERT_TRUE(late.connect());
      ASSERT_TRUE(late.send_all(head));
      std::string status, reply;
      ASSERT_TRUE(late.read_response(3000, status, reply));
      ASSERT_EQ(status, std::string("HTTP/1.1 429 Too Many Requests"));
      // ...and once it has passed, the source is admitted again.
      std::this_thread::sleep_until(start + std::chrono::milliseconds(1700));
      Client refilled(port, 0);
      ASSERT_TRUE(refilled.connect());
      ASSERT_TRUE(refilled.send_all(head));
      ASSERT_TRUE(wait_until([&] { return budget->reserved() == 4 * declared; }, 3000));
    });
  }
}

namespace {
// Holds each drained request body until the test releases it.
struct BodyHold {
  std::atomic<int> held{0};
  std::atomic<bool> release{false};
};

class BodyHolder final : public td::actor::Actor {
 public:
  BodyHolder(BodyHold *hold, td::Promise<td::Unit> resume) : hold_(hold), resume_(std::move(resume)) {
  }
  void start_up() override {
    ++hold_->held;
    alarm_timestamp() = td::Timestamp::in(0.005);
  }
  void alarm() override {
    if (hold_->release) {
      --hold_->held;
      resume_.set_value(td::Unit());
      stop();
      return;
    }
    alarm_timestamp() = td::Timestamp::in(0.005);
  }

 private:
  BodyHold *hold_;
  td::Promise<td::Unit> resume_;
};

std::string post_to(const std::string &path, const std::string &body, const std::string &key) {
  std::string request = "POST " + path + " HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n";
  if (!key.empty()) {
    request += "X-API-Key: " + key + "\r\n";
  }
  return request + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
}
}  // namespace

// The server keeps a drained body charged to the listener until it has
// answered the request: with processing held after the drain, the
// reservation stays in place and a further request cannot exceed the shared
// budget; answering, on success or error, releases it. Covers the JSON-RPC
// envelope and REST routes, the body arriving with or after the headers.
TEST(JsonRpcTransport, a_drained_body_stays_charged_until_its_request_is_answered) {
  for (bool with_key : {false, true}) {
    const size_t max_body = tos::http::HttpRequest::max_payload_size();
    auto budget = std::make_shared<tos::http::BodyBudget>(max_body + (1 << 20));
    auto hold = std::make_shared<BodyHold>();
    auto options = budget_options(with_key, budget);
    options.body_drained_hook = [hold](td::Promise<td::Unit> resume) {
      td::actor::create_actor<BodyHolder>("body-hold", hold.get(), std::move(resume)).release();
    };
    with_json_rpc(options, [budget, hold, with_key, max_body](int port) {
      const std::string key = with_key ? kApiKey : "";
      struct Case {
        std::string path;
        std::string body;
        bool split;
        std::string expect;
      };
      std::vector<Case> cases = {
          {"/jsonRPC", padded_request(max_body), false, "-32601"},
          {"/jsonRPC", padded_request(max_body), true, "-32601"},
          {"/detectAddress", "{\"address\":\"" + std::string(max_body - 14, 'z') + "\"}", false, "\"code\":-32602"},
          {"/detectAddress", "{\"address\":\"" + std::string(max_body - 14, 'z') + "\"}", true, "\"code\":-32602"},
          {"/jsonRPC", std::string(max_body, 'x'), false, "-32700"},
      };
      for (auto &c : cases) {
        hold->release = false;
        Client client(port, 0);
        ASSERT_TRUE(client.connect());
        auto request = post_to(c.path, c.body, key);
        if (c.split) {
          auto header_end = request.find("\r\n\r\n") + 4;
          ASSERT_TRUE(client.send_all(request.substr(0, header_end)));
          std::this_thread::sleep_for(std::chrono::milliseconds(50));
          ASSERT_TRUE(client.send_all(request.substr(header_end)));
        } else {
          ASSERT_TRUE(client.send_all(request));
        }
        // Drained and held: the payload is gone, the reservation is not.
        ASSERT_TRUE(wait_until([&] { return hold->held == 1; }, 5000));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        ASSERT_EQ(budget->reserved(), c.body.size());
        // The budget left cannot take another maximum-size body.
        Client other(port, 0);
        ASSERT_TRUE(other.connect());
        ASSERT_TRUE(other.send_all(post_headers(max_body, key) + std::string(1024, ' ')));
        std::string status, reply;
        ASSERT_TRUE(other.read_response(5000, status, reply));
        ASSERT_EQ(status, std::string("HTTP/1.1 503 Service Unavailable"));
        ASSERT_EQ(budget->reserved(), c.body.size());
        // Answering releases it.
        hold->release = true;
        ASSERT_TRUE(client.read_response(10000, status, reply));
        ASSERT_TRUE(reply.find(c.expect) != std::string::npos);
        ASSERT_TRUE(wait_until([&] { return budget->reserved() == 0; }, 5000));
      }
      // A client that goes away while its body is held: still charged until
      // the server is done with the body, then released.
      hold->release = false;
      {
        Client gone(port, 0);
        ASSERT_TRUE(gone.connect());
        ASSERT_TRUE(gone.send_all(post_to("/jsonRPC", padded_request(max_body), key)));
        ASSERT_TRUE(wait_until([&] { return hold->held == 1; }, 5000));
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      ASSERT_EQ(budget->reserved(), max_body);
      hold->release = true;
      ASSERT_TRUE(wait_until([&] { return budget->reserved() == 0 && hold->held == 0; }, 5000));
    });
  }
}

TEST(JsonRpcTransport, proof_relay_refuses_send_and_nested_queries_without_backend) {
  auto send = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_sendMessage>(td::BufferSlice("public test")), true);
  auto info = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto nested = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(info)), true);
  const std::vector<std::string> requests = {"!", td::base64_encode(send.as_slice()),
                                             td::base64_encode(nested.as_slice())};
  for (bool with_key : {false, true}) {
    with_json_rpc(options_for(with_key), [with_key, &requests](int port) {
      Client client(port, 0);
      ASSERT_TRUE(client.connect());
      for (const auto &query : requests) {
        for (bool rest : {false, true}) {
          const std::string request =
              "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"getProofQuery\",\"params\":{\"query\":\"" + query + "\"}}";
          ASSERT_TRUE(
              client.send_all(rest ? post_to("/getProofQuery", "{\"query\":\"" + query + "\"}", with_key ? kApiKey : "")
                                   : post(request, with_key)));
          std::string status, body;
          ASSERT_TRUE(client.read_response(5000, status, body));
          ASSERT_EQ(status, std::string("HTTP/1.1 200 OK"));
          ASSERT_TRUE(body.find("\"code\":-32602") != std::string::npos);
          ASSERT_TRUE(body.find("\"reason\":\"INVALID_ARGUMENT\"") != std::string::npos);
          ASSERT_TRUE(body.find(id_field(rest ? "null" : "7")) != std::string::npos);
        }
      }
    });
  }
}

TEST(JsonRpcTransport, explorer_rejects_invalid_selectors_before_backend_access) {
  const std::vector<std::pair<std::string, std::string>> cases = {
      {"getMasterchainBlockSignatures", "{\"seqno\":0}"},
      {"getMasterchainBlockSignatures", "{\"seqno\":2147483648}"},
      {"getMasterchainBlockSignatures", "{\"seqno\":\"1\"}"},
      {"getMasterchainBlockSignatures", "{\"seqno\":1,\"with_proof\":1}"},
      {"getConfigParam", "{\"param\":48,\"block_id\":{}}"},
      {"getAccountCapability", "{\"address\":\"0:" + std::string(64, '0') + "\",\"with_proof\":true}"},
      {"getWalletInformation", "{\"include_pq\":true,\"address\":\"/tmp/key\"}"}};
  for (bool with_key : {false, true}) {
    with_json_rpc(options_for(with_key), [with_key, &cases](int port) {
      Client client(port, 0);
      ASSERT_TRUE(client.connect());
      for (const auto &item : cases) {
        for (bool rest : {false, true}) {
          const auto request =
              "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"" + item.first + "\",\"params\":" + item.second + "}";
          ASSERT_TRUE(client.send_all(rest ? post_to("/" + item.first, item.second, with_key ? kApiKey : "")
                                           : post(request, with_key)));
          std::string status, body;
          ASSERT_TRUE(client.read_response(5000, status, body));
          ASSERT_EQ(status, std::string("HTTP/1.1 200 OK"));
          ASSERT_TRUE(body.find("\"code\":-32602") != std::string::npos);
          ASSERT_TRUE(body.find("\"schema_version\":1") != std::string::npos);
          ASSERT_TRUE(body.find("\"retryable\":false") != std::string::npos);
        }
      }
    });
  }
}

TEST(JsonRpcTransport, explorer_output_ownership_holds_reservations_through_fan_in) {
  auto budget = std::make_shared<tos::http::BodyBudget>(100);
  auto reservation = budget->reserve(80);
  ASSERT_TRUE(reservation != nullptr);
  auto payload = tos::json_rpc::retain_lifetime(std::make_shared<int>(7), std::move(reservation));
  ASSERT_EQ(budget->reserved(), 80u);
  std::vector<std::shared_ptr<int>> batch;
  batch.push_back(std::move(payload));
  auto response = tos::json_rpc::retain_lifetime(std::make_shared<int>(8), std::move(batch));
  ASSERT_TRUE(budget->reserve(21) == nullptr);
  ASSERT_EQ(budget->reserved(), 80u);
  auto slow_writer = response;
  response.reset();
  ASSERT_EQ(budget->reserved(), 80u);
  slow_writer.reset();
  ASSERT_EQ(budget->reserved(), 0u);
  ASSERT_TRUE(budget->reserve(100) != nullptr);
}

TEST(JsonRpcTransport, explorer_output_saturation_refuses_before_backend_access) {
  auto held = tos::reserve_explorer_response(tos::kExplorerResponseBudgetBytes);
  ASSERT_TRUE(held != nullptr);
  auto info = tos::serialize_tl_object(tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  const std::vector<std::pair<std::string, std::string>> calls = {
      {"getMasterchainBlockSignatures", "{\"seqno\":1}"},
      {"getAccountCapability", "{\"address\":\"0:" + std::string(64, '0') + "\",\"include_pq\":true}"},
      {"getWalletInformation", "{\"address\":\"0:" + std::string(64, '0') + "\",\"include_pq\":true}"},
      {"getConfigParam", "{\"param\":8,\"include_decoded\":true}"},
      {"getProofQuery", "{\"query\":\"" + td::base64_encode(info.as_slice()) + "\"}"}};
  for (bool with_key : {false, true}) {
    with_json_rpc(options_for(with_key), [with_key, &calls](int port) {
      for (const auto &call : calls) {
        for (bool rest : {false, true}) {
          Client client(port, 0);
          ASSERT_TRUE(client.connect());
          auto body = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"" + call.first + "\",\"params\":" + call.second + "}";
          ASSERT_TRUE(client.send_all(rest ? post_to("/" + call.first, call.second, with_key ? kApiKey : "")
                                           : post(body, with_key)));
          std::string status, reply;
          ASSERT_TRUE(client.read_response(5000, status, reply));
          // A method refused for capacity is answered like any other method
          // error: HTTP 200, typed and retryable.
          ASSERT_EQ(status, std::string("HTTP/1.1 200 OK"));
          ASSERT_TRUE(reply.find("\"reason\":\"RATE_LIMITED\",\"retryable\":true") != std::string::npos);
          ASSERT_TRUE(reply.find(id_field(rest ? "null" : "7")) != std::string::npos);
        }
      }
    });
  }
  held.reset();
  ASSERT_TRUE(tos::reserve_explorer_response(tos::kExplorerResponseBudgetBytes) != nullptr);
}

TEST(JsonRpcTransport, explorer_get_normalizes_url_types_without_weakening_json) {
  auto held = tos::reserve_explorer_response(tos::kExplorerResponseBudgetBytes);
  ASSERT_TRUE(held != nullptr);
  const std::string account = "address=0:" + std::string(64, '0');
  const std::vector<std::pair<std::string, bool>> paths = {
      {"/getMasterchainBlockSignatures?seqno=1", true},
      {"/getMasterchainBlockSignatures?seqno=1&with_proof=true", true},
      {"/getAccountCapability?" + account + "&seqno=1&include_pq=true&with_proof=false", true},
      {"/getWalletInformation?" + account + "&seqno=1&include_pq=true&include_experimental=false", true},
      {"/getConfigParam?param=8&seqno=1&include_decoded=true&with_proof=true", true},
      {"/getMasterchainBlockSignatures?seqno=1.5", false},
      {"/getMasterchainBlockSignatures?seqno=0001", false},
      {"/getMasterchainBlockSignatures?seqno=true", false},
      {"/getMasterchainBlockSignatures?seqno=2147483648", false},
      {"/getMasterchainBlockSignatures?seqno=1&with_proof=1", false}};
  for (bool with_key : {false, true}) {
    with_json_rpc(options_for(with_key), [with_key, &paths](int port) {
      for (const auto &path : paths) {
        Client client(port, 0);
        ASSERT_TRUE(client.connect());
        auto request = "GET " + path.first + " HTTP/1.1\r\nHost: localhost\r\n";
        if (with_key)
          request += std::string("X-API-Key: ") + kApiKey + "\r\n";
        ASSERT_TRUE(client.send_all(request + "\r\n"));
        std::string status, body;
        ASSERT_TRUE(client.read_response(5000, status, body));
        ASSERT_EQ(status, std::string("HTTP/1.1 200 OK"));
        ASSERT_TRUE(body.find(path.second ? "\"reason\":\"RATE_LIMITED\"" : "\"code\":-32602") != std::string::npos);
      }
    });
  }
}

TEST(JsonRpcTransport, explorer_named_routes_require_the_configured_api_key) {
  for (const std::string route : {"/getProofQuery", "/getMasterchainBlockSignatures", "/getAccountCapability",
                                  "/getWalletInformation", "/getConfigParam"}) {
    with_json_rpc(options_for(true), [route](int port) {
      Client client(port, 0);
      ASSERT_TRUE(client.connect());
      ASSERT_TRUE(client.send_all(post_to(route, "{}", "")));
      std::string status, body;
      ASSERT_TRUE(client.read_response(5000, status, body));
      ASSERT_EQ(status, std::string("HTTP/1.1 401 Unauthorized"));
      ASSERT_TRUE(body.find("Unauthorized") != std::string::npos);
    });
  }
}

// The answers a client sees for the envelope rules, through the real listener:
// each invalid envelope is a -32600 (or -32602 for positional params) JSON-RPC
// error object at HTTP 200, a notification gets HTTP 204 with no body, and
// every body is free of anything outside the JSON-RPC 2.0 response object.
TEST(JsonRpcTransport, envelope_rules_are_enforced_on_the_wire) {
  struct Case {
    std::string request;
    std::string expect;  // empty: no body
  };
  const std::vector<Case> cases = {
      {R"({"id":1,"method":"noSuchMethod"})", "\"code\":-32600"},
      {R"({"jsonrpc":"1.0","id":1,"method":"noSuchMethod"})", "\"code\":-32600"},
      {R"({"jsonrpc":"2.0","id":1,"method":12})", "\"code\":-32600"},
      {R"({"jsonrpc":"2.0","id":1,"method":"getMasterchainInfo","params":"x"})", "\"code\":-32600"},
      {R"({"jsonrpc":"2.0","id":1,"method":"getAddressBalance","params":["x"]})", "\"code\":-32602"},
      {R"({"jsonrpc":"2.0","id":1,"method":"noSuchMethod"})", "\"code\":-32601"},
      {R"({"jsonrpc":"2.0","method":"noSuchMethod"})", ""},
      {R"([{"jsonrpc":"2.0","method":"noSuchMethod"}])", ""},
  };
  for (bool with_key : {false, true}) {
    with_json_rpc(options_for(with_key), [with_key, &cases](int port) {
      for (const auto &c : cases) {
        Client client(port, 0);
        ASSERT_TRUE(client.connect());
        ASSERT_TRUE(client.send_all(post(c.request, with_key)));
        std::string status, body;
        ASSERT_TRUE(client.read_response(5000, status, body));
        if (c.expect.empty()) {
          ASSERT_EQ(status, std::string("HTTP/1.1 204 No Content"));
          ASSERT_TRUE(body.empty());
          continue;
        }
        ASSERT_EQ(status, std::string("HTTP/1.1 200 OK"));
        ASSERT_TRUE(body.find(c.expect) != std::string::npos);
        ASSERT_TRUE(body.find("\"ok\"") == std::string::npos);
        ASSERT_TRUE(body.find("\"data\":{\"schema_version\":1,\"reason\":") != std::string::npos);
      }
    });
  }
}

// /api-info reads the method table, and the refusals built before a body
// exists carry the same object the shared builder writes.
TEST(JsonRpcTransport, api_info_and_early_refusals_follow_the_contract) {
  with_json_rpc(options_for(true), [](int port) {
    Client client(port, 0);
    ASSERT_TRUE(client.connect());
    ASSERT_TRUE(client.send_all("GET /api-info HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    std::string status, body;
    ASSERT_TRUE(client.read_response(3000, status, body));
    ASSERT_EQ(status, std::string("HTTP/1.1 200 OK"));
    auto parsed = td::json_decode(td::MutableSlice(body));
    ASSERT_TRUE(parsed.is_ok());
    auto &info = parsed.ok_ref().get_object();
    auto count = info.get_required_int_field("methods_count");
    ASSERT_TRUE(count.is_ok());
    // Every table entry but the admin method, which is off by default.
    std::size_t served = 0;
    for (const auto &entry : tos::JsonRpcServer::method_table()) {
      served += (entry.flags & tos::JsonRpcServer::kMethodAdmin) == 0 ? 1 : 0;
    }
    ASSERT_EQ(static_cast<std::size_t>(count.ok()), served);
  });
  auto drain = [](auto &answer) {
    std::string out;
    for (auto chunk = answer.second->get_slice(1u << 20); !chunk.empty(); chunk = answer.second->get_slice(1u << 20)) {
      out.append(chunk.as_slice().str());
    }
    return out;
  };
  auto unauthorized = tos::json_rpc::unauthorized_response("");
  auto unauthorized_body = drain(unauthorized);
  ASSERT_EQ(unauthorized_body, tos::json_rpc::error_body("null", tos::json_rpc::kUnauthorized,
                                                         "Unauthorized: invalid or missing API key"));
  auto limited = tos::json_rpc::rate_limited_response("");
  auto limited_body = drain(limited);
  ASSERT_EQ(limited_body,
            tos::json_rpc::error_body("null", tos::json_rpc::kRateLimited, "Rate limit exceeded (per-IP)"));
}

TEST(JsonRpcTransport, standalone_index_route_preserves_envelope_and_backend_failure) {
  auto options = options_for(false);
  std::atomic<int> calls{0};
  options.index_query_sender = [&](std::string request, std::string source, td::Promise<std::string> promise) {
    auto document = td::json_decode(td::MutableSlice(request)).move_as_ok();
    auto &object = document.get_object();
    ASSERT_EQ(object.get_required_string_field("method").move_as_ok(), "getAccountEvents");
    auto params = object.extract_required_field("params", td::JsonValue::Type::Object).move_as_ok();
    ASSERT_EQ(params.get_object().get_required_string_field("address").move_as_ok(), "test-address");
    auto call = calls.fetch_add(1);
    if (call == 0) {
      promise.set_value(R"({"jsonrpc":"2.0","id":"escaped\"id","result":{"events":[]}})");
    } else {
      promise.set_error(call == 1 ? td::Status::Error(429, "rate limited") : td::Status::Error("disconnected"));
    }
  };
  with_json_rpc(std::move(options), [&](int port) {
    for (int i = 0; i < 3; ++i) {
      Client client(port, 0);
      ASSERT_TRUE(client.connect());
      ASSERT_TRUE(client.send_all(post(
          R"({"jsonrpc":"2.0","id":"escaped\"id","method":"getAccountEvents","params":{"address":"test-address"}})",
          false)));
      std::string status, body;
      ASSERT_TRUE(client.read_response(5000, status, body));
      auto document = td::json_decode(td::MutableSlice(body)).move_as_ok();
      ASSERT_EQ(document.get_object().get_required_string_field("id").move_as_ok(), "escaped\"id");
      ASSERT_TRUE(body.find(i == 0 ? "events" : (i == 1 ? "rate limit exceeded" : "unavailable")) != std::string::npos);
    }
  });
  ASSERT_EQ(calls.load(), 3);
}

TEST(JsonRpcTransport, standalone_backend_transports_bound_and_release_inflight_requests) {
  class HeldLite final : public liteclient::ExtClient {
   public:
    explicit HeldLite(std::atomic<int> *received) : received_(received) {
    }
    void send_query(std::string, td::BufferSlice, td::Timestamp, td::Promise<td::BufferSlice> promise) override {
      received_->fetch_add(1);
      if (released_)
        promise.set_value(td::BufferSlice("ok"));
      else
        held_.push_back(std::move(promise));
    }
    void finish() {
      released_ = true;
      for (auto &promise : held_)
        promise.set_value(td::BufferSlice("ok"));
      held_.clear();
    }

   private:
    std::atomic<int> *received_;
    bool released_ = false;
    std::vector<td::Promise<td::BufferSlice>> held_;
  };
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<HeldLite> backend;
  std::atomic<int> received{0}, success{0}, refused{0}, index_done{0}, index_full{0};
  tos::JsonRpcServer::LiteQuerySender sender;
  tos::JsonRpcServer::IndexQuerySender index_sender;
  PortReservation reservation;
  td::IPAddress addr;
  addr.init_ipv4_port("127.0.0.1", reservation.port()).ensure();
  scheduler.run_in_context([&] {
    backend = td::actor::create_actor<HeldLite>("held-lite", &received);
    sender = tos::services::lite_sender(backend.get(), 1);
    auto answer = [&](td::Result<td::BufferSlice> r) {
      if (r.is_ok())
        ++success;
      else
        ++refused;
    };
    for (int i = 0; i < 129; ++i)
      sender(td::BufferSlice("query"), answer);
    sender(td::BufferSlice((4u << 20) + 1), answer);
    index_sender = tos::services::index_sender(addr, .1);
    for (int i = 0; i < 17; ++i) {
      index_sender("{}", "127.0.0.1", [&](td::Result<std::string> r) {
        ASSERT_TRUE(r.is_error());
        if (r.error().message().str().find("capacity") != std::string::npos)
          ++index_full;
        ++index_done;
      });
    }
  });
  auto deadline = Clock::now() + std::chrono::seconds(5);
  while ((received != 128 || index_done != 17) && Clock::now() < deadline)
    scheduler.run(.01);
  ASSERT_EQ(received.load(), 128);
  ASSERT_EQ(refused.load(), 2);
  ASSERT_EQ(index_full.load(), 1);
  ASSERT_EQ(index_done.load(), 17);
  scheduler.run_in_context([&] { td::actor::send_closure(backend, &HeldLite::finish); });
  while (success != 128 && Clock::now() < deadline)
    scheduler.run(.01);
  ASSERT_EQ(success.load(), 128);
  scheduler.run_in_context([&] {
    sender(td::BufferSlice("query"), [&](td::Result<td::BufferSlice> r) {
      ASSERT_TRUE(r.is_ok());
      ++success;
    });
    index_sender("{}", "127.0.0.1", [&](td::Result<std::string> r) {
      ASSERT_TRUE(r.is_error());
      ASSERT_TRUE(r.error().message().str().find("capacity") == std::string::npos);
      ++index_done;
    });
  });
  while ((success != 129 || index_done != 18) && Clock::now() < deadline)
    scheduler.run(.01);
  ASSERT_EQ(success.load(), 129);
  ASSERT_EQ(index_done.load(), 18);
  scheduler.run_in_context([&] {
    backend.reset();
    scheduler.stop();
  });
  while (scheduler.run(.01)) {
  }
}

namespace {
void standalone_method_refusal(const std::string &method) {
  for (bool readonly : {false, true}) {
    auto options = options_for(false);
    options.readonly = readonly;
    options.lite_query_sender = [](td::BufferSlice, td::Promise<td::BufferSlice> p) {
      p.set_error(td::Status::Error("unexpected backend query"));
    };
    with_json_rpc(std::move(options), [&](int port) {
      Client client(port, 0);
      ASSERT_TRUE(client.connect());
      ASSERT_TRUE(client.send_all(
          post("{\"jsonrpc\":\"2.0\",\"id\":17,\"method\":\"" + method + "\",\"params\":{\"seqno\":1}}", false)));
      std::string status, body;
      ASSERT_TRUE(client.read_response(5000, status, body));
      ASSERT_TRUE(body.find("-32601") != std::string::npos);
      ASSERT_TRUE(body.find("\"id\":17") != std::string::npos);
    });
  }
}
}  // namespace

TEST(JsonRpcTransport, standalone_manager_methods_consensus_refused) {
  standalone_method_refusal("getConsensusBlock");
}

TEST(JsonRpcTransport, standalone_manager_methods_signatures_refused) {
  standalone_method_refusal("getMasterchainBlockSignatures");
}

TEST(JsonRpcTransport, standalone_manager_methods_admin_refused) {
  standalone_method_refusal("getNodeConsensusStatus");
}

TEST(JsonRpcTransport, standalone_index_hop_keeps_client_rate_buckets) {
  auto backend = options_for(false);
  backend.trust_proxy_headers = true;
  backend.index_only = true;
  backend.per_ip_rate_window = 300;
  backend.per_ip_ingress_window = 300;
  backend.index_query_sender = [](std::string, std::string source, td::Promise<std::string> p) {
    ASSERT_TRUE(source == "198.51.100.1" || source == "198.51.100.2");
    p.set_value(R"({"jsonrpc":"2.0","id":1,"result":{"events":[]}})");
  };
  with_json_rpc(std::move(backend), [&](int backend_port) {
    td::IPAddress address;
    address.init_ipv4_port("127.0.0.1", backend_port).ensure();
    auto front = options_for(false);
    front.trust_proxy_headers = true;
    front.per_ip_rate_window = 300;
    front.per_ip_ingress_window = 300;
    front.index_query_sender = tos::services::index_sender(address, 5);
    with_json_rpc(std::move(front), [&](int port) {
      for (int i = 0; i < 601; ++i) {
        Client client(port, 0);
        ASSERT_TRUE(client.connect());
        auto request = post(R"({"jsonrpc":"2.0","id":1,"method":"getAccountEvents","params":{}})", false);
        request.insert(request.find("Content-Type:"),
                       std::string("X-Real-IP: ") + (i % 2 ? "198.51.100.1" : "198.51.100.2") + "\r\n");
        ASSERT_TRUE(client.send_all(request));
        std::string status, body;
        ASSERT_TRUE(client.read_response(5000, status, body));
        ASSERT_TRUE(body.find("\"events\":[]") != std::string::npos);
      }
    });
  });
}

TEST(JsonRpcTransport, standalone_source_cancellation_clears_mailbox) {
  using namespace tos::services;
  stop_requested = true;
  IndexReader reader({});
  int dispatched = 0;
  auto call = [&](auto, td::Promise<int> p) {
    ++dispatched;
    p.set_value(1);
  };
  for (int i = 0; i < 8; ++i)
    ASSERT_TRUE(reader.query<int>(call).is_error());
  reader.dispatch();
  ASSERT_EQ(dispatched, 0);
  stop_requested = false;
  IndexReader timeout_reader({}, std::chrono::milliseconds(1));
  ASSERT_TRUE(timeout_reader.query<int>(call).is_error());
  ASSERT_TRUE(timeout_reader.timed_out());
  for (int i = 0; i < 8; ++i)
    ASSERT_TRUE(timeout_reader.query<int>(call).is_error());
  timeout_reader.dispatch();
  ASSERT_EQ(dispatched, 0);
  stop_requested = false;
  // The cancelled undispatched closure is gone, including after a new service lifecycle.
  timeout_reader.dispatch();
  ASSERT_EQ(dispatched, 0);
}

TEST(JsonRpcTransport, standalone_submission_requires_backend_proxy_attribution) {
  for (bool trusted : {false, true}) {
    auto backend = options_for(false);
    backend.readonly = false;
    backend.trust_proxy_headers = trusted;
    with_json_rpc(std::move(backend), [&](int backend_port) {
      td::IPAddress address;
      address.init_ipv4_port("127.0.0.1", backend_port).ensure();
      auto front = options_for(false);
      front.readonly = false;
      front.trust_proxy_headers = true;
      front.submission_query_sender = tos::services::index_sender(address, 5);
      front.lite_query_sender = [](td::BufferSlice, td::Promise<td::BufferSlice>) {
        CHECK(false);  // Submissions must never use the shared liteserver identity.
      };
      with_json_rpc(std::move(front), [&](int port) {
        Client client(port, 0);
        ASSERT_TRUE(client.connect());
        auto request = post(
            R"({"jsonrpc":"2.0","id":9,"method":"sendBoc","params":{"boc":"!","_tos_relay_source":"forged"}})", false);
        request.insert(request.find("Content-Type:"), "X-Real-IP: 198.51.100.9\r\n");
        ASSERT_TRUE(client.send_all(request));
        std::string status, body;
        ASSERT_TRUE(client.read_response(5000, status, body));
        ASSERT_TRUE(body.find(trusted ? "Invalid base64" : "requires trusted client attribution") != std::string::npos);
        ASSERT_TRUE(body.find("\"id\":9") != std::string::npos);
      });
    });
  }
}
