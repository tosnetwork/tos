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

// A listener given a bare port must be unreachable from other interfaces.
// Showing that needs a second, non-loopback address on this host: a refused
// connection from it proves the bind address only when the same listener,
// bound to 0.0.0.0, is reachable from it.
//
// Without such an address these tests fail by default, so no CI host can pass
// them unchecked. A developer machine that genuinely has none can set
// TOS_TEST_ALLOW_LOOPBACK_ONLY=1: the tests are then reported as skipped
// (exit status 77, which ctest shows as "Skipped"), never as passed.

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "http/http-server.h"
#include "http/http.h"
#include "td/actor/actor.h"
#include "td/utils/Time.h"
#include "td/utils/misc.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/port/signals.h"
#include "td/utils/tests.h"

namespace {

constexpr int kSkipExitCode = 77;
std::atomic<bool> g_skipped{false};

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

// Finds the second address. Without one, records a skip when the developer
// opted in and otherwise reports why the test is about to fail.
std::string required_non_loopback_ipv4() {
  auto found = non_loopback_ipv4();
  if (!found.empty()) {
    return found;
  }
  const char *allow = std::getenv("TOS_TEST_ALLOW_LOOPBACK_ONLY");
  if (allow != nullptr && std::strcmp(allow, "1") == 0) {
    LOG(WARNING) << "SKIPPED: this host has no non-loopback IPv4 address";
    g_skipped = true;
  } else {
    LOG(ERROR) << "this host has no non-loopback IPv4 address, so the bind address cannot be checked; "
                  "set TOS_TEST_ALLOW_LOOPBACK_ONLY=1 to report the test as skipped instead";
  }
  return {};
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

// Listeners bind asynchronously; wait until `ip` answers.
bool eventually_connects(const std::string &ip, int port) {
  for (int attempt = 0; attempt < 250; attempt++) {
    if (tcp_connects(ip, port)) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return false;
}

// An ephemeral port nothing listens on right now.
int free_port() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
  socklen_t len = sizeof(addr);
  CHECK(::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
  ::close(fd);
  return ntohs(addr.sin_port);
}

class OkCallback : public tos::http::HttpServer::Callback {
 public:
  void receive_request(
      std::unique_ptr<tos::http::HttpRequest> request, std::shared_ptr<tos::http::HttpPayload> payload,
      td::Promise<std::pair<std::unique_ptr<tos::http::HttpResponse>, std::shared_ptr<tos::http::HttpPayload>>> promise)
      override {
    auto response = tos::http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
    response->add_header({"Content-Length", "0"});
    response->complete_parse_header();
    auto out = response->create_empty_payload().move_as_ok();
    out->complete_parse();
    promise.set_value({std::move(response), std::move(out)});
  }
};

// Runs `scenario` against an HttpServer listening on `address`.
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

// A running child process with its output discarded, killed when this goes
// out of scope.
struct Child {
  pid_t pid = -1;
  Child(const std::string &binary, const std::vector<std::string> &args) {
    pid = ::fork();
    CHECK(pid >= 0);
    if (pid == 0) {
      int null_fd = ::open("/dev/null", O_RDWR);
      if (null_fd >= 0) {
        ::dup2(null_fd, 1);
        ::dup2(null_fd, 2);
      }
      std::vector<char *> argv;
      argv.push_back(const_cast<char *>(binary.c_str()));
      for (auto &a : args) {
        argv.push_back(const_cast<char *>(a.c_str()));
      }
      argv.push_back(nullptr);
      ::execv(binary.c_str(), argv.data());
      ::_exit(127);
    }
  }
  ~Child() {
    ::kill(pid, SIGKILL);
    int status = 0;
    ::waitpid(pid, &status, 0);
  }
};

}  // namespace

TEST(HttpListenAddress, a_bare_port_is_unreachable_from_other_interfaces) {
  auto other = required_non_loopback_ipv4();
  if (other.empty()) {
    ASSERT_TRUE(g_skipped.load());
    return;
  }
  int port = free_port();
  auto bare = tos::http::HttpServer::parse_listen_address(std::to_string(port)).move_as_ok();
  with_server_at(bare, [&] {
    ASSERT_TRUE(eventually_connects("127.0.0.1", port));
    ASSERT_TRUE(!tcp_connects(other, port));
  });
  // Control: asked for explicitly, the same listener is reachable there, so the
  // refusal above is the bind address and not a firewall or a dead listener.
  port = free_port();
  auto any = tos::http::HttpServer::parse_listen_address("0.0.0.0:" + std::to_string(port)).move_as_ok();
  with_server_at(any, [&] {
    ASSERT_TRUE(eventually_connects("127.0.0.1", port));
    ASSERT_TRUE(tcp_connects(other, port));
  });
}

TEST(HttpProxyListenAddress, a_bare_port_is_unreachable_from_other_interfaces) {
  auto other = required_non_loopback_ipv4();
  if (other.empty()) {
    ASSERT_TRUE(g_skipped.load());
    return;
  }
  const std::string binary = HTTP_PROXY_BINARY;
  int port = free_port();
  {
    Child proxy(binary, {"-p", std::to_string(port)});
    ASSERT_TRUE(eventually_connects("127.0.0.1", port));
    ASSERT_TRUE(!tcp_connects(other, port));
  }
  // Control: asked for by address, the same binary is reachable there, so the
  // refusal above is the bind address and not a firewall.
  port = free_port();
  {
    Child proxy(binary, {"-p", "0.0.0.0:" + std::to_string(port)});
    ASSERT_TRUE(eventually_connects(other, port));
  }
}

int main(int argc, char **argv) {
  td::set_default_failure_signal_handler().ensure();
  auto &runner = td::TestsRunner::get_default();
  runner.set_pretty_output(true);
  for (int i = 1; i < argc; i++) {
    if (!std::strcmp(argv[i], "--filter")) {
      CHECK(i + 1 < argc);
      runner.add_substr_filter(argv[++i]);
    } else if (!std::strcmp(argv[i], "--verbosity")) {
      CHECK(i + 1 < argc);
      SET_VERBOSITY_LEVEL(td::to_integer<td::int32>(td::Slice(argv[++i])));
    }
  }
  runner.run_all();
  if (runner.any_test_failed()) {
    return 1;
  }
  return g_skipped.load() ? kSkipExitCode : 0;
}
