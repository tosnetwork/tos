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

// CONNECT tunnels of the RLDP HTTP proxy hold a TCP socket and an actor each.
// These tests drive real tunnel actors against a loopback backend, with the
// RLDP transport and the payload registry replaced by test actors, and check
// that every way a tunnel ends gives its socket and actor back, that
// admission is capped, and that idle and lifetime limits close tunnels.
// They also run the RLDP proxy binary to check how it reads its limits.

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <dirent.h>
#include <fcntl.h>
#include <functional>
#include <ifaddrs.h>
#include <map>
#include <memory>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "auto/tl/tos_api.hpp"
#include "rldp-http-proxy/tcp-tunnel.h"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/Time.h"
#include "td/utils/tests.h"
#include "tl-utils/tl-utils.hpp"

namespace {

using tos::rldp_http::RldpTcpTunnel;
using tos::rldp_http::TunnelAdmission;
using tos::rldp_http::TunnelStart;
using tos::rldp_http::TunnelTimeouts;

int open_fd_count() {
  int count = 0;
  // Linux lists a process's descriptors in /proc/self/fd, macOS in /dev/fd.
  DIR *dir = ::opendir("/proc/self/fd");
  if (dir == nullptr) {
    dir = ::opendir("/dev/fd");
  }
  CHECK(dir != nullptr);
  while (auto *entry = ::readdir(dir)) {
    if (entry->d_name[0] != '.') {
      count++;
    }
  }
  ::closedir(dir);
  return count;
}

// A loopback listener that never accepts: connections complete in the kernel
// backlog and hold no descriptor in this process, so every descriptor the
// count sees on our side belongs to a tunnel.
struct Backend {
  int fd = -1;
  td::IPAddress address;
  Backend() {
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    CHECK(::listen(fd, 1024) == 0);
    socklen_t len = sizeof(addr);
    CHECK(::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
    address.init_ipv4_port("127.0.0.1", ntohs(addr.sin_port)).ensure();
  }
  ~Backend() {
    ::close(fd);
  }
};

// A loopback backend that accepts connections and sends one byte on each
// every 0.1 s until the other side goes away.
class StreamingBackend {
 public:
  StreamingBackend() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listen_fd_ >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(::bind(listen_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    CHECK(::listen(listen_fd_, 16) == 0);
    socklen_t len = sizeof(addr);
    CHECK(::getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
    address.init_ipv4_port("127.0.0.1", ntohs(addr.sin_port)).ensure();
    thread_ = std::thread([this] { serve(); });
  }
  ~StreamingBackend() {
    stop_ = true;
    thread_.join();
    for (int fd : accepted_) {
      ::close(fd);
    }
    ::close(listen_fd_);
  }

  td::IPAddress address;

 private:
  void serve() {
    while (!stop_) {
      pollfd p{listen_fd_, POLLIN, 0};
      if (::poll(&p, 1, 0) > 0) {
        int fd = ::accept(listen_fd_, nullptr, nullptr);
        if (fd >= 0) {
          accepted_.push_back(fd);
        }
      }
      for (int fd : accepted_) {
        ::send(fd, "y", 1, MSG_NOSIGNAL);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }

  int listen_fd_ = -1;
  std::atomic<bool> stop_{false};
  std::vector<int> accepted_;
  std::thread thread_;
};

// Stands in for RLDP: every payload-part query the tunnel sends to its peer
// fails at once, is held unanswered, or is answered with one byte a little
// later.
class FakeRldp : public tos::adnl::AdnlSenderInterface {
 public:
  enum class Mode { fail, hold, trickle };
  FakeRldp(Mode mode, std::atomic<int> &held) : mode_(mode), held_count_(held) {
  }

  void send_message(tos::adnl::AdnlNodeIdShort, tos::adnl::AdnlNodeIdShort, td::BufferSlice) override {
  }
  void send_query(tos::adnl::AdnlNodeIdShort src, tos::adnl::AdnlNodeIdShort dst, std::string name,
                  td::Promise<td::BufferSlice> promise, td::Timestamp timeout, td::BufferSlice data) override {
    send_query_ex(src, dst, std::move(name), std::move(promise), timeout, std::move(data), 0);
  }
  void send_query_ex(tos::adnl::AdnlNodeIdShort, tos::adnl::AdnlNodeIdShort dst, std::string,
                     td::Promise<td::BufferSlice> promise, td::Timestamp, td::BufferSlice, td::uint64) override {
    switch (mode_) {
      case Mode::fail:
        promise.set_error(td::Status::Error("rldp query failed"));
        return;
      case Mode::hold:
        held_.emplace_back(dst, std::move(promise));
        held_count_ = static_cast<int>(held_.size());
        return;
      case Mode::trickle:
        held_.emplace_back(dst, std::move(promise));
        held_count_ = static_cast<int>(held_.size());
        alarm_timestamp().relax(td::Timestamp::in(0.1));
        return;
    }
  }
  void get_conn_ip_str(tos::adnl::AdnlNodeIdShort, tos::adnl::AdnlNodeIdShort,
                       td::Promise<td::string> promise) override {
    promise.set_error(td::Status::Error("not supported"));
  }

  void alarm() override {
    auto held = std::move(held_);
    held_.clear();
    held_count_ = 0;
    for (auto &q : held) {
      q.second.set_result(tos::create_serialize_tl_object<tos::tos_api::http_payloadPart>(
          td::BufferSlice("x"), std::vector<tos::tl_object_ptr<tos::tos_api::http_header>>(), false));
    }
  }

  // Fails the queries held for `peer`'s tunnels: an RLDP fetch that fails.
  void fail_held_for(tos::adnl::AdnlNodeIdShort peer) {
    std::vector<std::pair<tos::adnl::AdnlNodeIdShort, td::Promise<td::BufferSlice>>> keep;
    for (auto &q : held_) {
      if (q.first == peer) {
        q.second.set_error(td::Status::Error("rldp query failed"));
      } else {
        keep.push_back(std::move(q));
      }
    }
    held_ = std::move(keep);
    held_count_ = static_cast<int>(held_.size());
  }

 private:
  Mode mode_;
  std::atomic<int> &held_count_;
  std::vector<std::pair<tos::adnl::AdnlNodeIdShort, td::Promise<td::BufferSlice>>> held_;
};

// Stands in for the proxy's payload-part routing table.
// With `peer_polls`, it also plays the peer that reads the tunnel: it keeps
// one payload-part query outstanding for every registered tunnel.
class FakeRegistry : public tos::rldp_http::PayloadSenderRegistry {
 public:
  FakeRegistry(bool accept, bool peer_polls, std::atomic<int> &registered)
      : accept_(accept), peer_polls_(peer_polls), registered_(registered) {
  }
  void register_payload_sender(td::Bits256 id, tos::rldp_http::PayloadPartHandler handler,
                               td::Promise<tos::rldp_http::RegisteredPayloadSenderGuard> promise) override {
    if (!accept_) {
      promise.set_error(td::Status::Error("duplicate id"));
      return;
    }
    handlers_[id] = std::move(handler);
    registered_++;
    promise.set_result(make_guard(id));
    if (peer_polls_) {
      poll(id, 0);
    }
  }

  void poll(td::Bits256 id, td::int32 seqno) {
    auto it = handlers_.find(id);
    if (it == handlers_.end()) {
      return;
    }
    it->second(tos::create_tl_object<tos::tos_api::http_getNextPayloadPart>(id, seqno, 1 << 20),
               [SelfId = actor_id(this), id, seqno](td::Result<td::BufferSlice> R) {
                 if (R.is_ok()) {
                   td::actor::send_closure(SelfId, &FakeRegistry::poll, id, seqno + 1);
                 }
               });
  }
  void unregister_payload_sender(td::Bits256 id) override {
    if (handlers_.erase(id) != 0) {
      registered_--;
    }
  }

 private:
  bool accept_;
  bool peer_polls_;
  std::atomic<int> &registered_;
  std::map<td::Bits256, tos::rldp_http::PayloadPartHandler> handlers_;
};

tos::adnl::AdnlNodeIdShort peer_id(unsigned char tag) {
  td::Bits256 bits;
  bits.set_zero();
  bits.as_slice()[0] = static_cast<char>(tag);
  return tos::adnl::AdnlNodeIdShort{bits};
}

td::Bits256 random_transfer_id() {
  td::Bits256 id;
  td::Random::secure_bytes(id.as_slice());
  return id;
}

// One scheduler with a fake transport and registry, and a backend to tunnel to.
class Harness {
 public:
  Harness(FakeRldp::Mode mode, bool registry_accepts, std::size_t max_tunnels, std::size_t max_per_peer,
          TunnelTimeouts timeouts, bool backend_streams = false)
      : scheduler_({1}), admission_(std::make_shared<TunnelAdmission>(max_tunnels, max_per_peer)) {
    timeouts_ = timeouts;
    backend_address_ = backend_.address;
    if (backend_streams) {
      streaming_backend_ = std::make_unique<StreamingBackend>();
      backend_address_ = streaming_backend_->address;
    }
    scheduler_.run_in_context([&] {
      rldp_ = td::actor::create_actor<FakeRldp>("fake-rldp", mode, held_);
      registry_ =
          td::actor::create_actor<FakeRegistry>("fake-registry", registry_accepts, backend_streams, registered_);
    });
    scheduler_.run(0.05);
  }
  ~Harness() {
    scheduler_.run_in_context([&] {
      rldp_.reset();
      registry_.reset();
      td::actor::SchedulerContext::get().stop();
    });
    while (scheduler_.run(1)) {
    }
  }

  TunnelStart start(tos::adnl::AdnlNodeIdShort peer) {
    TunnelStart result = TunnelStart::unreachable;
    scheduler_.run_in_context([&] {
      tos::rldp_http::TunnelEnvironment env{rldp_.get(), registry_.get(), admission_, timeouts_};
      result = tos::rldp_http::start_tcp_tunnel(env, random_transfer_id(), peer, peer_id(0xee), backend_address_);
    });
    return result;
  }

  void fail_held_for(tos::adnl::AdnlNodeIdShort peer) {
    scheduler_.run_in_context([&] { td::actor::send_closure(rldp_, &FakeRldp::fail_held_for, peer); });
  }

  bool run_until(const std::function<bool()> &done, double limit) {
    auto until = td::Timestamp::in(limit);
    while (!done()) {
      if (until.is_in_past()) {
        return false;
      }
      scheduler_.run(0.02);
    }
    return true;
  }

  void run_for(double seconds) {
    auto until = td::Timestamp::in(seconds);
    while (!until.is_in_past()) {
      scheduler_.run(0.02);
    }
  }

  TunnelAdmission &admission() {
    return *admission_;
  }
  int registered() const {
    return registered_.load();
  }
  // Peer queries the fake transport holds unanswered.
  int held() const {
    return held_.load();
  }

 private:
  td::actor::Scheduler scheduler_;
  Backend backend_;
  std::unique_ptr<StreamingBackend> streaming_backend_;
  td::IPAddress backend_address_;
  std::shared_ptr<TunnelAdmission> admission_;
  TunnelTimeouts timeouts_;
  std::atomic<int> registered_{0};
  std::atomic<int> held_{0};
  td::actor::ActorOwn<FakeRldp> rldp_;
  td::actor::ActorOwn<FakeRegistry> registry_;
};

}  // namespace

TEST(RldpHttpTunnel, failed_tunnels_return_actors_and_descriptors_to_baseline) {
  Harness h(FakeRldp::Mode::fail, true, 1000, 1000, TunnelTimeouts{});
  auto baseline_fds = open_fd_count();
  ASSERT_EQ(RldpTcpTunnel::live_count(), static_cast<std::size_t>(0));
  for (int round = 0; round < 5; round++) {
    for (unsigned char peer = 1; peer <= 20; peer++) {
      ASSERT_TRUE(h.start(peer_id(peer)) == TunnelStart::started);
    }
    // Every RLDP fetch fails at once; each tunnel must end and give back its
    // socket, its actor, its registration and its admission.
    ASSERT_TRUE(h.run_until([] { return RldpTcpTunnel::live_count() == 0; }, 5.0));
    ASSERT_TRUE(h.run_until([&] { return h.registered() == 0; }, 5.0));
    ASSERT_EQ(open_fd_count(), baseline_fds);
    ASSERT_EQ(h.admission().active(), static_cast<std::size_t>(0));
  }
}

TEST(RldpHttpTunnel, a_tunnel_whose_registration_fails_ends_at_once) {
  // Held queries never complete, so only the registration failure can end
  // these tunnels within the wait below.
  Harness h(FakeRldp::Mode::hold, false, 1000, 1000, TunnelTimeouts{});
  auto baseline_fds = open_fd_count();
  for (unsigned char peer = 1; peer <= 10; peer++) {
    ASSERT_TRUE(h.start(peer_id(peer)) == TunnelStart::started);
  }
  ASSERT_TRUE(h.run_until([] { return RldpTcpTunnel::live_count() == 0; }, 5.0));
  ASSERT_EQ(open_fd_count(), baseline_fds);
  ASSERT_EQ(h.admission().active(), static_cast<std::size_t>(0));
}

TEST(RldpHttpTunnel, admission_is_capped_globally_and_per_peer_and_recovers) {
  Harness h(FakeRldp::Mode::hold, true, 3, 2, TunnelTimeouts{});
  auto a = peer_id(1), b = peer_id(2), c = peer_id(3);
  ASSERT_TRUE(h.start(a) == TunnelStart::started);
  ASSERT_TRUE(h.start(a) == TunnelStart::started);
  ASSERT_TRUE(h.run_until([&] { return h.held() == 2; }, 5.0));
  // A refused tunnel opens no socket.
  auto fds = open_fd_count();
  ASSERT_TRUE(h.start(a) == TunnelStart::refused);
  ASSERT_EQ(open_fd_count(), fds);
  ASSERT_EQ(h.admission().active_for(a), static_cast<std::size_t>(2));
  // Another peer still gets the last global slot, and then nobody does.
  ASSERT_TRUE(h.start(b) == TunnelStart::started);
  ASSERT_TRUE(h.start(c) == TunnelStart::refused);
  ASSERT_EQ(h.admission().active(), static_cast<std::size_t>(3));
  ASSERT_TRUE(h.run_until([&] { return h.held() == 3; }, 5.0));
  ASSERT_EQ(RldpTcpTunnel::live_count(), static_cast<std::size_t>(3));
  // When a's tunnels fail, their slots come back.
  h.fail_held_for(a);
  ASSERT_TRUE(h.run_until([] { return RldpTcpTunnel::live_count() == 1; }, 5.0));
  ASSERT_EQ(h.admission().active(), static_cast<std::size_t>(1));
  ASSERT_TRUE(h.start(c) == TunnelStart::started);
  ASSERT_TRUE(h.start(a) == TunnelStart::started);
  ASSERT_TRUE(h.run_until([&] { return h.held() == 3; }, 5.0));
  h.fail_held_for(a);
  h.fail_held_for(b);
  h.fail_held_for(c);
  ASSERT_TRUE(h.run_until([] { return RldpTcpTunnel::live_count() == 0; }, 5.0));
  ASSERT_EQ(h.admission().active(), static_cast<std::size_t>(0));
}

namespace {

// Starts one tunnel and returns how long it lived, or a negative value if it
// was still open after `limit` seconds.
double tunnel_lifetime(Harness &h, double limit) {
  auto start = td::Time::now();
  CHECK(h.start(peer_id(1)) == TunnelStart::started);
  if (!h.run_until([] { return RldpTcpTunnel::live_count() == 0; }, limit)) {
    return -1;
  }
  return td::Time::now() - start;
}

}  // namespace

// The bounds below are wide against scheduling delay, but each excludes the
// other limit: without the limit under test the tunnel lives ten seconds.
TEST(RldpHttpTunnel, an_idle_tunnel_is_closed_at_the_idle_timeout) {
  // Nothing moves: the peer never answers and the backend never sends.
  Harness h(FakeRldp::Mode::hold, true, 10, 10, TunnelTimeouts{0.3, 10.0});
  auto baseline_fds = open_fd_count();
  auto lived = tunnel_lifetime(h, 20.0);
  ASSERT_TRUE(lived >= 0.25);
  ASSERT_TRUE(lived < 3.0);
  ASSERT_EQ(open_fd_count(), baseline_fds);
  ASSERT_EQ(h.admission().active(), static_cast<std::size_t>(0));
}

TEST(RldpHttpTunnel, a_tunnel_is_closed_at_its_maximum_lifetime) {
  Harness h(FakeRldp::Mode::hold, true, 10, 10, TunnelTimeouts{10.0, 0.5});
  auto baseline_fds = open_fd_count();
  auto lived = tunnel_lifetime(h, 20.0);
  ASSERT_TRUE(lived >= 0.45);
  ASSERT_TRUE(lived < 3.0);
  ASSERT_EQ(open_fd_count(), baseline_fds);
  ASSERT_EQ(h.admission().active(), static_cast<std::size_t>(0));
}

TEST(RldpHttpTunnel, a_busy_tunnel_outlives_the_idle_timeout_and_ends_at_its_lifetime) {
  // The peer sends a byte every 0.1 s, well inside the 0.4 s idle timeout.
  Harness h(FakeRldp::Mode::trickle, true, 10, 10, TunnelTimeouts{0.4, 1.2});
  auto baseline_fds = open_fd_count();
  auto lived = tunnel_lifetime(h, 20.0);
  // Traffic kept it open past three idle timeouts; the lifetime ended it.
  ASSERT_TRUE(lived >= 1.1);
  ASSERT_TRUE(lived < 4.0);
  ASSERT_EQ(open_fd_count(), baseline_fds);
  ASSERT_EQ(h.admission().active(), static_cast<std::size_t>(0));
}

TEST(RldpHttpTunnel, bytes_from_the_backend_also_keep_a_tunnel_open) {
  // The backend sends a byte every 0.1 s and the peer reads them; the peer
  // sends nothing.
  Harness h(FakeRldp::Mode::hold, true, 10, 10, TunnelTimeouts{0.4, 1.2}, true);
  auto lived = tunnel_lifetime(h, 20.0);
  ASSERT_TRUE(lived >= 1.1);
  ASSERT_TRUE(lived < 4.0);
  ASSERT_EQ(h.admission().active(), static_cast<std::size_t>(0));
}

TEST(RldpHttpTunnel, option_values_parse_strictly_and_are_bounded) {
  using tos::rldp_http::parse_positive_seconds;
  using tos::rldp_http::parse_tunnel_limit;
  ASSERT_EQ(parse_tunnel_limit("1").move_as_ok(), static_cast<std::size_t>(1));
  ASSERT_EQ(parse_tunnel_limit("512").move_as_ok(), static_cast<std::size_t>(512));
  ASSERT_EQ(parse_tunnel_limit("65536").move_as_ok(), static_cast<std::size_t>(65536));
  for (std::string bad : {"", "0", "65537", "-1", "+5", " 5", "5 ", "05", "5x", "1e3", "4294967297"}) {
    ASSERT_TRUE(parse_tunnel_limit(bad).is_error());
  }
  auto max = tos::rldp_http::kMaxHttpForwardTimeout;
  ASSERT_EQ(parse_positive_seconds("60", max).move_as_ok(), 60.0);
  ASSERT_EQ(parse_positive_seconds("0.5", max).move_as_ok(), 0.5);
  ASSERT_EQ(parse_positive_seconds("3600", max).move_as_ok(), 3600.0);
  // Transfers longer than an hour are legitimate.
  ASSERT_EQ(parse_positive_seconds("7200", max).move_as_ok(), 7200.0);
  ASSERT_EQ(parse_positive_seconds("2147483", max).move_as_ok(), 2147483.0);
  for (std::string bad : {"", "0", "-1", "2147483.5", "1e300", "inf", "nan", "1e400", " 60", "60 ", "60s", "0x10000"}) {
    ASSERT_TRUE(parse_positive_seconds(bad, max).is_error());
  }
}

namespace {

// Runs `binary` with `args`, output discarded. Returns the exit status, or
// 128 + signal number if it was killed.
int run_binary(const std::string &binary, const std::vector<std::string> &args) {
  pid_t pid = ::fork();
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
  int status = 0;
  CHECK(::waitpid(pid, &status, 0) == pid);
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return 128 + WTERMSIG(status);
}

}  // namespace

// -h prints the help and exits 2 once the options before it were accepted; an
// option the binary refuses stops it before that.
TEST(RldpHttpProxyOptions, the_binary_refuses_unbounded_or_malformed_limits) {
  const std::string binary = RLDP_HTTP_PROXY_BINARY;
  ASSERT_EQ(run_binary(binary, {"--forward-timeout", "7200", "-h"}), 2);
  ASSERT_EQ(run_binary(binary, {"--forward-timeout", "2147483", "-h"}), 2);
  ASSERT_EQ(run_binary(binary, {"--max-tunnels", "512", "--max-tunnels-per-peer", "16", "-h"}), 2);
  ASSERT_EQ(run_binary(binary, {"--tunnel-idle-timeout", "600", "--tunnel-max-lifetime", "86400", "-h"}), 2);
  for (std::vector<std::string> bad : std::vector<std::vector<std::string>>{
           {"--forward-timeout", "1e300", "-h"},
           {"--forward-timeout", "inf", "-h"},
           {"--forward-timeout", "nan", "-h"},
           {"--forward-timeout", "2147484", "-h"},
           {"--max-tunnels", "0", "-h"},
           {"--max-tunnels-per-peer", "65537", "-h"},
           {"--tunnel-idle-timeout", "1e300", "-h"},
           {"--tunnel-max-lifetime", "0", "-h"},
       }) {
    ASSERT_TRUE(run_binary(binary, bad) != 2);
  }
}
