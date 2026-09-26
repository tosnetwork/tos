/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// In-process ADNL external client/server pair for unanswered-query regressions.
//
// Every control asserts that the client promise received the exact answer
// bytes the server produced for that request; a query that merely did not time
// out within a bound is never counted as answered. Characterization cases pin
// the behavior of the current tree for each candidate unanswered-query path.
// They are expected to change only together with a fix for a demonstrated
// cause, at which point the case must be rewritten to assert a received answer
// (or an explicit, attributable refusal) instead of the pinned outcome.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "adnl/adnl-ext-client.h"
#include "adnl/adnl-ext-client.hpp"
#include "adnl/adnl-ext-limits.h"
#include "adnl/adnl.h"
#include "auto/tl/lite_api.h"
#include "common/errorcode.h"
#include "keyring/keyring.h"
#include "td/utils/Random.h"
#include "td/utils/Time.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "tl-utils/lite-utils.hpp"
#include "tl-utils/tl-utils.hpp"

namespace {

using namespace tos;

[[noreturn]] void fail(const std::string& message) {
  std::fprintf(stderr, "ADNL_EXT_QUERY_ANSWER_FAILURE: %s\n", message.c_str());
  std::fflush(stderr);
  std::_Exit(1);
}

void require(bool condition, const std::string& message) {
  if (!condition) {
    fail(message);
  }
}

td::uint16 allocate_tcp_port() {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  require(fd >= 0, "cannot allocate TCP socket");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    ::close(fd);
    fail("cannot reserve TCP port");
  }
  socklen_t size = sizeof(address);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) {
    ::close(fd);
    fail("cannot read reserved TCP port");
  }
  const auto port = ntohs(address.sin_port);
  ::close(fd);
  return port;
}

// What the server-side query handler does with each delivered query.
enum class ServerMode {
  Echo,           // answer "answer:" + request bytes immediately
  Hold,           // keep the promise until the test releases it
  Error,          // fail the ADNL promise (generic error path, no lite contract)
  LiteError,      // answer with a serialized liteServer_error object
  Oversized,      // answer with a payload above the framed packet limit
};

struct ServerState {
  std::mutex mutex;
  ServerMode mode = ServerMode::Echo;
  std::vector<std::pair<std::string, td::Promise<td::BufferSlice>>> held;
  std::vector<std::string> delivered;
};

std::string expected_answer(const std::string& request) {
  return "answer:" + request;
}

class ServerHandler final : public adnl::Adnl::Callback {
 public:
  explicit ServerHandler(std::shared_ptr<ServerState> state) : state_(std::move(state)) {
  }
  void receive_message(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice) override {
  }
  void receive_query(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    std::string request = data.as_slice().str();
    ServerMode mode;
    {
      std::lock_guard lock(state_->mutex);
      state_->delivered.push_back(request);
      mode = state_->mode;
      if (mode == ServerMode::Hold) {
        LOG(INFO) << "Q02_HANDLER_RECEIPT nonce=" << request << " mode=hold";
        state_->held.emplace_back(std::move(request), std::move(promise));
        return;
      }
    }
    switch (mode) {
      case ServerMode::Echo:
        promise.set_value(td::BufferSlice{expected_answer(request)});
        return;
      case ServerMode::Error:
        promise.set_error(td::Status::Error(ErrorCode::error, "handler failed without a lite contract"));
        return;
      case ServerMode::LiteError:
        promise.set_value(create_serialize_tl_object<lite_api::liteServer_error>(-503, "timeout"));
        return;
      case ServerMode::Oversized:
        promise.set_value(td::BufferSlice{adnl::adnl_ext_max_packet_bytes});
        return;
      case ServerMode::Hold:
        fail("held query escaped the hold branch");
    }
  }

 private:
  std::shared_ptr<ServerState> state_;
};

class ReadyCallback final : public adnl::AdnlExtClient::Callback {
 public:
  explicit ReadyCallback(std::shared_ptr<std::atomic<int>> transitions) : transitions_(std::move(transitions)) {
  }
  void on_ready() override {
    transitions_->fetch_add(1, std::memory_order_acq_rel);
  }
  void on_stop_ready() override {
    transitions_->fetch_add(1000, std::memory_order_acq_rel);
  }

 private:
  std::shared_ptr<std::atomic<int>> transitions_;
};

// Raw td double-second values printed in hexadecimal preserve their stored
// precision; sequential mono/wall samples do not prove a cross-clock bound.
void clock_record(const char* phase, const std::string& nonce, double deadline) {
  const double before = td::Time::now();
  const double wall = td::Time::system_now();
  const double after = td::Time::now();
  std::printf("Q02_CALLER_CLOCK phase=%s nonce=%s td_mono_before=%a td_wall=%a td_mono_after=%a deadline_monotonic=%a precision=td-double-seconds\n",
              phase, nonce.c_str(), before, wall, after, deadline);
  std::fflush(stdout);
}

// One client-observed query result. `completions` counts promise invocations so
// a late answer delivered after a timeout would be visible as a second one.
struct Slot {
  std::string request;
  std::atomic<int> completions{0};
  std::mutex mutex;
  td::Result<td::BufferSlice> result{td::Status::Error("query not completed")};
  std::string logical;
  int attempt = 0;
  std::string retry_of_nonce = "-";
  double deadline = 0.0;
  double sent_at = 0.0;
  double completed_at = 0.0;
};

enum class Outcome { Answer, Timeout, Cancelled, OtherError, Pending };

const char* outcome_name(Outcome outcome) {
  switch (outcome) {
    case Outcome::Answer:
      return "answer";
    case Outcome::Timeout:
      return "timeout";
    case Outcome::Cancelled:
      return "cancelled";
    case Outcome::OtherError:
      return "other_error";
    case Outcome::Pending:
      return "pending";
  }
  return "unknown";
}

Outcome outcome_of(Slot& slot) {
  if (slot.completions.load(std::memory_order_acquire) == 0) {
    return Outcome::Pending;
  }
  std::lock_guard lock(slot.mutex);
  if (slot.result.is_ok()) {
    return Outcome::Answer;
  }
  auto code = slot.result.error().code();
  if (code == ErrorCode::timeout) {
    return Outcome::Timeout;
  }
  if (code == ErrorCode::cancelled) {
    return Outcome::Cancelled;
  }
  return Outcome::OtherError;
}

// Keyring + ADNL + external server on a loopback port, and one external client
// created the way lite-client creates it (by "host:port" string).
class Pair {
 public:
  explicit Pair(std::string name) : name_(std::move(name)) {
    port_ = allocate_tcp_port();
    db_root_ = "/tmp/tos-adnl-ext-query-answer-" + std::to_string(::getpid()) + "-" + name_;
    td::rmrf(db_root_).ignore();
    require(td::mkdir(db_root_).is_ok(), "cannot create db directory");
    scheduler_ = std::make_unique<td::actor::Scheduler>(std::vector<td::actor::Scheduler::NodeInfo>{2});
    state_ = std::make_shared<ServerState>();
    transitions_ = std::make_shared<std::atomic<int>>(0);
    start_server();
  }

  ~Pair() {
    scheduler_->run_in_context([&] {
      client_.reset();
      server_.reset();
      adnl_.reset();
      keyring_.reset();
    });
    scheduler_->run(0.2);
    scheduler_->stop();
    td::rmrf(db_root_).ignore();
  }

  Pair(const Pair&) = delete;
  Pair& operator=(const Pair&) = delete;

  void set_mode(ServerMode mode) {
    std::lock_guard lock(state_->mutex);
    state_->mode = mode;
  }

  void create_client() {
    scheduler_->run_in_context([&] {
      client_ = adnl::AdnlExtClient::create(server_id_, "127.0.0.1:" + std::to_string(port_),
                                            std::make_unique<ReadyCallback>(transitions_));
    });
  }

  void wait_client_ready() {
    wait_until([&] { return transitions_->load(std::memory_order_acquire) >= 1; }, 10.0,
               "client connection did not become ready");
  }

  std::shared_ptr<Slot> send(std::string request, double deadline_s, std::string logical, int attempt, std::string retry_of_nonce = "-") {
    auto slot = std::make_shared<Slot>();
    slot->request = std::move(request);
    slot->logical = std::move(logical);
    slot->attempt = attempt;
    slot->retry_of_nonce = std::move(retry_of_nonce);
    scheduler_->run_in_context([&] {
      slot->sent_at = td::Time::now();
      slot->deadline = slot->sent_at + deadline_s;
      clock_record("before_send", slot->request, slot->deadline);
      std::printf("Q02_CALLER_CREATE nonce=%s logical=%s attempt=%d retry_of_nonce=%s pid=%d endpoint=127.0.0.1:%u deadline_s=%.1f\n",
                  slot->request.c_str(), slot->logical.c_str(), slot->attempt, slot->retry_of_nonce.c_str(), ::getpid(), port_, deadline_s);
      std::fflush(stdout);
      td::actor::send_closure(client_, &adnl::AdnlExtClient::send_query, slot->request,
                              td::BufferSlice{slot->request}, td::Timestamp::at(slot->deadline),
                              td::PromiseCreator::lambda([slot](td::Result<td::BufferSlice> result) {
                                std::lock_guard lock(slot->mutex);
                                if (slot->completions.load(std::memory_order_acquire) == 0) {
                                  slot->result = std::move(result);
                                  slot->completed_at = td::Time::now();
                                  clock_record("terminal", slot->request, slot->deadline);
                                }
                                slot->completions.fetch_add(1, std::memory_order_acq_rel);
                                std::printf("Q02_CALLER_TERMINAL nonce=%s logical=%s attempt=%d retry_of_nonce=%s pid=%d outcome=%s code=%d answer_match=%d elapsed_ms=%.3f\n",
                                            slot->request.c_str(), slot->logical.c_str(), slot->attempt, slot->retry_of_nonce.c_str(), ::getpid(),
                                            slot->result.is_ok() ? "value" : "error",
                                            slot->result.is_ok() ? 0 : slot->result.error().code(),
                                            slot->result.is_ok() && slot->result.ok().as_slice().str() == expected_answer(slot->request),
                                            1000.0 * (slot->completed_at - slot->sent_at));
                                std::fflush(stdout);
                              }));
      clock_record("after_send", slot->request, slot->deadline);
    });
    return slot;
  }

  void wait_completed(const std::vector<std::shared_ptr<Slot>>& slots, double bound_s, const std::string& what) {
    wait_until(
        [&] {
          for (auto& slot : slots) {
            if (slot->completions.load(std::memory_order_acquire) == 0) {
              return false;
            }
          }
          return true;
        },
        bound_s, what);
  }

  size_t held_count() {
    std::lock_guard lock(state_->mutex);
    return state_->held.size();
  }

  size_t delivered_count() {
    std::lock_guard lock(state_->mutex);
    return state_->delivered.size();
  }

  void wait_held(size_t count, double bound_s) {
    wait_until([&] { return held_count() >= count; }, bound_s, "server did not receive the held queries");
  }

  // Answer every held query with its expected bytes.
  void release_held() {
    std::vector<std::pair<std::string, td::Promise<td::BufferSlice>>> held;
    {
      std::lock_guard lock(state_->mutex);
      held.swap(state_->held);
    }
    scheduler_->run_in_context([&] {
      for (auto& entry : held) {
        entry.second.set_value(td::BufferSlice{expected_answer(entry.first)});
      }
    });
  }

  void pump(double seconds) {
    auto until = td::Timestamp::in(seconds);
    while (!until.is_in_past()) {
      scheduler_->run(0.01);
    }
  }

 private:
  template <class F>
  void wait_until(F&& done, double bound_s, const std::string& what) {
    auto deadline = td::Timestamp::in(bound_s);
    while (!done()) {
      scheduler_->run(0.01);
      if (deadline.is_in_past()) {
        fail(name_ + ": " + what);
      }
    }
  }

  void start_server() {
    auto private_key = PrivateKey{privkeys::Ed25519::random()};
    auto public_key = private_key.compute_public_key();
    server_id_ = adnl::AdnlNodeIdFull{public_key};
    const adnl::AdnlNodeIdShort server_short{public_key.compute_short_id()};
    std::atomic<bool> key_ready{false};
    scheduler_->run_in_context([&] {
      keyring_ = keyring::Keyring::create(db_root_);
      adnl_ = adnl::Adnl::create(db_root_, keyring_.get());
      td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(private_key), true,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> result) {
                                require(result.is_ok(), "key install failed");
                                key_ready.store(true, std::memory_order_release);
                              }));
    });
    wait_until([&] { return key_ready.load(std::memory_order_acquire); }, 10.0, "key install timed out");

    std::atomic<bool> server_ready{false};
    scheduler_->run_in_context([&] {
      td::actor::send_closure(adnl_, &adnl::Adnl::add_id, server_id_, adnl::AdnlAddressList{},
                              static_cast<td::uint8>(0));
      td::actor::send_closure(adnl_, &adnl::Adnl::subscribe, server_short, std::string{},
                              std::make_unique<ServerHandler>(state_));
      td::actor::send_closure(
          adnl_, &adnl::Adnl::create_ext_server, std::vector<adnl::AdnlNodeIdShort>{server_short},
          std::vector<td::uint16>{port_},
          td::PromiseCreator::lambda([&](td::Result<td::actor::ActorOwn<adnl::AdnlExtServer>> result) {
            require(result.is_ok(), "ext server start failed");
            server_ = result.move_as_ok();
            server_ready.store(true, std::memory_order_release);
          }));
    });
    wait_until([&] { return server_ready.load(std::memory_order_acquire); }, 10.0, "ext server start timed out");

    std::atomic<bool> listening{false};
    bool listening_ok = false;
    scheduler_->run_in_context([&] {
      td::actor::send_closure(server_, &adnl::AdnlExtServer::wait_listening,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> result) {
                                listening_ok = result.is_ok();
                                listening.store(true, std::memory_order_release);
                              }));
    });
    wait_until([&] { return listening.load(std::memory_order_acquire); }, 10.0, "ext server listen timed out");
    require(listening_ok, "ext server failed to listen");
  }

  std::string name_;
  td::uint16 port_ = 0;
  std::string db_root_;
  std::unique_ptr<td::actor::Scheduler> scheduler_;
  std::shared_ptr<ServerState> state_;
  std::shared_ptr<std::atomic<int>> transitions_;
  adnl::AdnlNodeIdFull server_id_;
  td::actor::ActorOwn<keyring::Keyring> keyring_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<adnl::AdnlExtServer> server_;
  td::actor::ActorOwn<adnl::AdnlExtClient> client_;
};

// The one positive predicate: the promise completed exactly once, with a value
// equal to the bytes the server built from this very request.
void require_answered(Slot& slot, const std::string& where) {
  require(slot.completions.load(std::memory_order_acquire) == 1, where + ": promise did not complete exactly once");
  std::lock_guard lock(slot.mutex);
  require(slot.result.is_ok(), where + ": no answer received: " +
                                   (slot.result.is_error() ? slot.result.error().message().str() : std::string{}));
  require(slot.result.ok().as_slice().str() == expected_answer(slot.request),
          where + ": answer bytes do not match the request");
}

std::string request_tag(const std::string& name, size_t index) {
  return name + "#" + std::to_string(index) + "#" + std::to_string(td::Random::fast_uint64());
}


// Fixed before invocation in the resource manifest; unique within each run.
std::string nonce(int token) {
  return std::string(63, '0') + static_cast<char>('0' + token);
}

// Disable only connection creation, retaining the production send_query body.
// This models a stale outer caller directly invoking an absent inner connection.
class AbsentConnection final : public adnl::AdnlExtClientImpl {
 public:
  using AdnlExtClientImpl::AdnlExtClientImpl;
  void start_up() override {}
  void alarm() override {}
};

void disconnected_refusal() {
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<AbsentConnection> client;
  auto transitions = std::make_shared<std::atomic<int>>(0);
  auto slot = std::make_shared<Slot>();
  slot->request = nonce(1);
  auto id = adnl::AdnlNodeIdFull{PrivateKey{privkeys::Ed25519::random()}.compute_public_key()};
  scheduler.run_in_context([&] {
    client = td::actor::create_actor<AbsentConnection>("q02-absent", id,
        std::string{"127.0.0.1:1"}, std::make_unique<ReadyCallback>(transitions));
    slot->sent_at = td::Time::now();
    slot->deadline = slot->sent_at + 10.0;
    clock_record("before_send", slot->request, slot->deadline);
    std::printf("Q02_CALLER_CREATE nonce=%s logical=absent attempt=0 retry_of_nonce=- pid=%d deadline_s=10.0\n", slot->request.c_str(), ::getpid());
    td::actor::send_closure(client, &adnl::AdnlExtClientImpl::send_query, slot->request,
        td::BufferSlice{slot->request}, td::Timestamp::at(slot->deadline),
        td::PromiseCreator::lambda([slot](td::Result<td::BufferSlice> result) {
          std::lock_guard lock(slot->mutex);
          slot->result = std::move(result);
          slot->completed_at = td::Time::now();
                                  clock_record("terminal", slot->request, slot->deadline);
          slot->completions.fetch_add(1, std::memory_order_acq_rel);
          std::printf("Q02_CALLER_TERMINAL nonce=%s logical=absent attempt=0 retry_of_nonce=- pid=%d outcome=%s code=%d elapsed_ms=%.3f\n",
              slot->request.c_str(), ::getpid(), slot->result.is_ok() ? "value" : "error",
              slot->result.is_ok() ? 0 : slot->result.error().code(),
              1000.0 * (slot->completed_at - slot->sent_at));
          std::fflush(stdout);
        }));
    clock_record("after_send", slot->request, slot->deadline);
  });
  const auto bound = td::Timestamp::in(11.0);
  while (!slot->completions.load(std::memory_order_acquire)) {
    scheduler.run(0.01);
    require(!bound.is_in_past(), "absent caller did not complete within unchanged 10s deadline plus observation margin");
  }
  require(slot->completions == 1 && slot->result.is_error() &&
          slot->result.error().code() == ErrorCode::cancelled &&
          slot->result.error().message() == "conn not ready", "absent query retained to timeout instead of cancelled refusal");
  require(slot->completed_at - slot->sent_at < 1.0, "absent refusal waited for query deadline");
  require(transitions->load() == 0, "absent test unexpectedly connected");
  scheduler.run_in_context([&] { client.reset(); });
  scheduler.run(0.1);
  scheduler.stop();
  std::printf("Q02_REGRESSION case=absent outcome=cancelled production_deadline_s=10.0 historical_attribution=false\n");
}

// A loopback peer the test owns: it accepts the client's TCP connection and
// later closes it, so the client connection actor stops on a peer close.
struct RawPeer {
  int listener = -1;
  int accepted = -1;
  td::uint16 port = 0;
  RawPeer() {
    listener = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    require(listener >= 0, "cannot create raw peer socket");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 && ::listen(listener, 1) == 0,
            "cannot listen on raw peer socket");
    socklen_t size = sizeof(address);
    require(::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size) == 0, "cannot read raw peer port");
    port = ntohs(address.sin_port);
  }
  ~RawPeer() {
    if (accepted >= 0) ::close(accepted);
    if (listener >= 0) ::close(listener);
  }
};

// Shared between the test thread and the held client actor turn.
struct DeadWindowGate {
  std::atomic<bool> entered{false};
  std::atomic<bool> closed_while_held{false};
};

// Test-only client: its send_query override holds the client actor's own turn
// until the connection actor has published its stop, then runs the production
// send_query. conn_stopped() is queued behind this turn and only this actor
// clears conn_, so conn_ is still the same non-empty handle when the
// production guard runs; the production log line records present/alive.
class DeadWindowClient final : public adnl::AdnlExtClientImpl {
 public:
  DeadWindowClient(adnl::AdnlNodeIdFull dst, td::IPAddress addr, std::unique_ptr<Callback> callback,
                   std::shared_ptr<DeadWindowGate> gate)
      : AdnlExtClientImpl(std::move(dst), addr, std::move(callback)), gate_(std::move(gate)) {
  }
  void send_query(std::string name, td::BufferSlice data, td::Timestamp timeout,
                  td::Promise<td::BufferSlice> promise) override {
    gate_->entered.store(true, std::memory_order_release);
    const auto limit = td::Timestamp::in(5.0);
    while (!connection_closed_synchronously()) {
      require(!limit.is_in_past(), "client connection actor did not stop while the client turn was held");
      ::usleep(1000);
    }
    gate_->closed_while_held.store(true, std::memory_order_release);
    AdnlExtClientImpl::send_query(std::move(name), std::move(data), timeout, std::move(promise));
  }

 private:
  // check_ready answers synchronously, on this thread and inside this call,
  // only when conn_ is empty or its actor is closed; otherwise it forwards to
  // the connection actor, whose reply runs elsewhere and is ignored here.
  bool connection_closed_synchronously() {
    auto sync_not_ready = std::make_shared<std::atomic<bool>>(false);
    auto in_call = std::make_shared<std::atomic<bool>>(true);
    const auto self = std::this_thread::get_id();
    check_ready(td::PromiseCreator::lambda([sync_not_ready, in_call, self](td::Result<td::Unit> result) {
      if (in_call->load(std::memory_order_acquire) && std::this_thread::get_id() == self && result.is_error() &&
          result.error().code() == ErrorCode::notready && result.error().message() == "not ready") {
        sync_not_ready->store(true, std::memory_order_release);
      }
    }));
    in_call->store(false, std::memory_order_release);
    return sync_not_ready->load(std::memory_order_acquire);
  }
  std::shared_ptr<DeadWindowGate> gate_;
};

void dead_nonempty_refusal() {
  RawPeer peer;
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<DeadWindowClient> client;
  auto transitions = std::make_shared<std::atomic<int>>(0);
  auto gate = std::make_shared<DeadWindowGate>();
  auto slot = std::make_shared<Slot>();
  slot->request = nonce(5);
  td::IPAddress address;
  require(address.init_ipv4_port("127.0.0.1", peer.port).is_ok(), "cannot build raw peer address");
  auto id = adnl::AdnlNodeIdFull{PrivateKey{privkeys::Ed25519::random()}.compute_public_key()};
  scheduler.run_in_context([&] {
    client = td::actor::create_actor<DeadWindowClient>("q02-dead", id, address,
                                                       std::make_unique<ReadyCallback>(transitions), gate);
  });
  // The client's start_up alarm opened the connection; accept it so the
  // connection actor exists and is alive before the query is submitted.
  const auto accept_limit = td::Timestamp::in(5.0);
  while (peer.accepted < 0) {
    scheduler.run(0.01);
    peer.accepted = ::accept4(peer.listener, nullptr, nullptr, SOCK_NONBLOCK);
    require(peer.accepted >= 0 || !accept_limit.is_in_past(), "client never connected to the raw peer");
  }
  // No second connection can be accepted: a reconnect could not replace conn_
  // with a new live handle and mask the dead one.
  ::close(peer.listener);
  peer.listener = -1;
  scheduler.run_in_context([&] {
    slot->sent_at = td::Time::now();
    slot->deadline = slot->sent_at + 10.0;
    std::printf("Q02_CALLER_CREATE nonce=%s logical=dead-nonempty attempt=0 retry_of_nonce=- pid=%d deadline_s=10.0\n",
                slot->request.c_str(), ::getpid());
    td::actor::send_closure(client, &adnl::AdnlExtClientImpl::send_query, slot->request, td::BufferSlice{slot->request},
                            td::Timestamp::at(slot->deadline),
                            td::PromiseCreator::lambda([slot](td::Result<td::BufferSlice> result) {
                              std::lock_guard lock(slot->mutex);
                              slot->result = std::move(result);
                              slot->completed_at = td::Time::now();
                              slot->completions.fetch_add(1, std::memory_order_acq_rel);
                              std::printf("Q02_CALLER_TERMINAL nonce=%s logical=dead-nonempty attempt=0 retry_of_nonce=- pid=%d outcome=%s code=%d message=%s elapsed_ms=%.3f\n",
                                          slot->request.c_str(), ::getpid(), slot->result.is_ok() ? "value" : "error",
                                          slot->result.is_ok() ? 0 : slot->result.error().code(),
                                          slot->result.is_ok() ? "-" : slot->result.error().message().str().c_str(),
                                          1000.0 * (slot->completed_at - slot->sent_at));
                              std::fflush(stdout);
                            }));
  });
  const auto enter_limit = td::Timestamp::in(5.0);
  while (!gate->entered.load(std::memory_order_acquire)) {
    scheduler.run(0.01);
    require(!enter_limit.is_in_past(), "client never entered the held send_query turn");
  }
  // Peer close while the client turn is held: the connection actor sees EOF and stops.
  ::close(peer.accepted);
  peer.accepted = -1;
  const auto bound = td::Timestamp::in(11.0);
  while (!slot->completions.load(std::memory_order_acquire) || transitions->load() < 1000) {
    scheduler.run(0.01);
    require(!bound.is_in_past(), "dead-connection caller or stop callback did not complete");
  }
  require(gate->closed_while_held.load(), "connection stop was not observed inside the held client turn");
  require(slot->completions == 1 && slot->result.is_error() && slot->result.error().code() == ErrorCode::cancelled &&
              slot->result.error().message() == "conn not ready",
          "dead non-empty connection was not refused by the connection guard");
  require(slot->completed_at - slot->sent_at < 1.0, "dead-connection refusal waited for the query deadline");
  scheduler.run_in_context([&] { client.reset(); });
  scheduler.run(0.1);
  scheduler.stop();
  std::printf("Q02_REGRESSION case=dead-nonempty outcome=cancelled production_deadline_s=10.0 historical_attribution=false\n");
}

void tcp_controls() {
  Pair pair{"closure"};
  pair.create_client();
  pair.wait_client_ready();
  auto positive = pair.send(nonce(2), 10.0, "positive", 0);
  pair.wait_completed({positive}, 11.0, "positive caller did not complete");
  require_answered(*positive, "positive TCP answer");
  // Deliberately withhold the server promise after actual TCP delivery.
  pair.set_mode(ServerMode::Hold);
  auto unanswered = pair.send(nonce(3), 1.0, "controlled-withhold", 0);
  pair.wait_held(1, 2.0);
  LOG(INFO) << "Q02_PHASE nonce=" << unanswered->request << " phase=held";
  pair.wait_completed({unanswered}, 3.0, "controlled withheld caller did not time out");
  require(unanswered->completions == 1 && outcome_of(*unanswered) == Outcome::Timeout,
          "controlled withholding must produce exactly one caller timeout");
  LOG(INFO) << "Q02_PHASE nonce=" << unanswered->request << " phase=timeout_observed";
  // Explicit harness retry; no claim about an automatic application retry policy.
  pair.set_mode(ServerMode::Echo);
  auto retried = pair.send(nonce(4), 1.0, "controlled-withhold", 1, unanswered->request);
  pair.wait_completed({retried}, 3.0, "explicit retry did not receive answer");
  require_answered(*retried, "explicit retry TCP answer");
  LOG(INFO) << "Q02_PHASE nonce=" << unanswered->request << " phase=before_release";
  pair.release_held();
  pair.pump(0.2);
  LOG(INFO) << "Q02_PHASE nonce=" << unanswered->request << " phase=after_release";
  require(unanswered->completions == 1 && outcome_of(*unanswered) == Outcome::Timeout,
          "late answer resurrected a completed caller");
  require(pair.delivered_count() == 3, "TCP handler delivery count mismatch");
  std::printf("Q02_CONTROL transport=tcp positive_answer_match=true controlled_unanswered=true explicit_retry_answer_match=true repair_acceptance=false\n");
}
}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(DEBUG));
  const std::string only = argc > 1 ? argv[1] : "all";
  require(only == "all" || only == "absent" || only == "dead" || only == "tcp", "unknown case");
  if (only == "all" || only == "absent") disconnected_refusal();
  if (only == "all" || only == "dead") dead_nonempty_refusal();
  if (only == "all" || only == "tcp") tcp_controls();
  std::printf("Q02_SCOPE controlled-adnl-mechanism historical_cause=false application_success=false q02_signoff=false\n");
  return 0;
}
