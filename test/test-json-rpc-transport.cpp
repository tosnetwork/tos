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

#include "td/actor/actor.h"
#include "td/utils/buffer.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/tests.h"

#include "json-rpc-server.h"

namespace {

using Clock = std::chrono::steady_clock;

const char *const kApiKey = "transport-test-key";

int find_free_port() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
  socklen_t len = sizeof(addr);
  CHECK(::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
  int port = ntohs(addr.sin_port);
  ::close(fd);
  return port;
}

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
  Client(int port, int receive_window) : port_(port), receive_window_(receive_window) {
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
  int port = find_free_port();
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

TEST(JsonRpcTransport, a_timed_out_batch_echoes_only_ids_within_the_bound) {
  for (bool with_key : {false, true}) {
    auto options = options_for(with_key);
    // Expires before the first element is dispatched, so every element is
    // answered from the batch timeout path.
    options.request_timeout = 1e-9;
    with_json_rpc(options, [with_key](int port) {
      Client client(port, 0);
      ASSERT_TRUE(client.connect());
      std::string batch = "[" + request_object(kLongestStringId) + "," + request_object(kStringIdOverBound) + "," +
                          request_object(kNumberIdOverBound) + "]";
      ASSERT_TRUE(client.send_all(post(batch, with_key)));
      std::string status, body;
      ASSERT_TRUE(client.read_response(5000, status, body));
      ASSERT_TRUE(body.find("Request batch timed out") != std::string::npos);
      ASSERT_TRUE(body.find(id_field(kLongestStringId)) != std::string::npos);
      ASSERT_TRUE(body.find(std::string(255, 'a')) == std::string::npos);
      ASSERT_TRUE(body.find(std::string(256, '0')) == std::string::npos);
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
  with_json_rpc(options_for(with_key, kResponseTimeout), [with_key, trickle](int port) {
    auto baseline_mem = td::BufferAllocator::get_buffer_mem();
    Client client(port, 4096);
    ASSERT_TRUE(client.connect());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto fds_connected = open_fd_count();
    // 200 batches: about 6 MB of requests asking for about 7 MB of replies.
    std::string stream;
    auto request = fat_batch(with_key);
    for (int i = 0; i < 200; i++) {
      stream += request;
    }
    size_t offset = 0;
    auto start = Clock::now();
    auto release_by = start + std::chrono::duration<double>(kResponseTimeout + kTolerance);
    size_t peak_mem = 0;
    size_t trickled = 0;
    bool server_closed = false;
    double released_after = -1;
    while (Clock::now() < start + std::chrono::duration<double>(3 * kResponseTimeout)) {
      if (!server_closed && !client.send_some(stream, offset)) {
        server_closed = true;
      }
      if (trickle && !server_closed && !client.trickle(64, trickled)) {
        server_closed = true;
      }
      auto mem = td::BufferAllocator::get_buffer_mem();
      peak_mem = std::max(peak_mem, mem);
      if (released_after < 0 && peak_mem > baseline_mem + (1 << 20) && mem <= baseline_mem + (256 << 10) &&
          open_fd_count() < fds_connected) {
        released_after = std::chrono::duration<double>(Clock::now() - start).count();
      }
      if (released_after >= 0 || Clock::now() > release_by) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    LOG(INFO) << "peak buffer memory over baseline: " << (peak_mem - baseline_mem) << " bytes; sent " << offset
              << " bytes; released after " << released_after << " s";
    // The stall was real: the server held well over a megabyte of replies
    // and unread requests for this client.
    ASSERT_TRUE(peak_mem > baseline_mem + (1 << 20));
    // Released by the deadline plus tolerance: the server's socket is closed
    // and its input and output buffers are freed.
    ASSERT_TRUE(released_after >= 0);
    // The client sees the close once it reads what was in flight, and never
    // gets the replies the server dropped.
    size_t received = 0;
    ASSERT_TRUE(client.drains_to_close(5000, received));
  });
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
