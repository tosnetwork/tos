/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Every external query whose ID the server parsed must reach a prompt terminal state:
// a same-ID answer, or a closed connection that the client sees as an immediate
// failure. No refused query may be left to the client's transport timeout.
//
// Real ADNL external server and clients over loopback TCP. Each case asserts the
// exact bytes or the exact refusal, and that it arrived well before the client's
// own deadline; a query that merely did not time out is never counted as answered.
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "adnl/adnl-ext-client.h"
#include "adnl/adnl-ext-limits.h"
#include "adnl/adnl-ext-query-failure.h"
#include "adnl/adnl-ext-server-limits.h"
#include "adnl/adnl.h"
#include "auto/tl/lite_api.h"
#include "common/errorcode.h"
#include "keyring/keyring.h"
#include "lite-client/lite-ext-query-failure.h"
#include "td/utils/Random.h"
#include "td/utils/Time.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "tl-utils/lite-utils.hpp"
#include "tl-utils/tl-utils.hpp"

namespace {

using namespace tos;

// The client's own deadline in every case; refusals must arrive far sooner.
constexpr double kClientDeadline = 10.0;
constexpr double kPromptBound = 1.0;

[[noreturn]] void fail(const std::string& message) {
  std::fprintf(stderr, "ADNL_EXT_QUERY_REFUSAL_FAILURE: %s\n", message.c_str());
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

enum class ServerMode {
  Echo,                  // answer "answer:" + request bytes
  Hold,                  // keep the promise until the test releases it
  Error,                 // fail the promise with a handler error
  DefaultCallbackError,  // let the base Adnl::Callback answer, as a query-unaware service does
  Oversized,             // succeed with a payload above the external packet limit
};

struct ServerState {
  std::mutex mutex;
  ServerMode mode = ServerMode::Echo;
  std::vector<std::pair<std::string, td::Promise<td::BufferSlice>>> held;
  size_t delivered = 0;
};

std::string expected_answer(const std::string& request) {
  return "answer:" + request;
}

class ServerHandler final : public adnl::Adnl::Callback {
 public:
  explicit ServerHandler(std::shared_ptr<ServerState> state) : state_(std::move(state)) {
  }
  void receive_query(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    std::string request = data.as_slice().str();
    ServerMode mode;
    {
      std::lock_guard lock(state_->mutex);
      state_->delivered++;
      mode = state_->mode;
      if (mode == ServerMode::Hold) {
        state_->held.emplace_back(std::move(request), std::move(promise));
        return;
      }
    }
    switch (mode) {
      case ServerMode::Echo:
        promise.set_value(td::BufferSlice{expected_answer(request)});
        return;
      case ServerMode::Error:
        promise.set_error(td::Status::Error(ErrorCode::error, "internal handler detail that must not leak"));
        return;
      case ServerMode::DefaultCallbackError:
        adnl::Adnl::Callback::receive_query(src, dst, std::move(data), std::move(promise));
        return;
      case ServerMode::Oversized:
        promise.set_value(td::BufferSlice{adnl::adnl_ext_max_packet_bytes});
        return;
      case ServerMode::Hold:
        break;
    }
    fail("held query escaped the hold branch");
  }

 private:
  std::shared_ptr<ServerState> state_;
};

// Encodes the exact refusal kind into the Lite error text so a case can assert
// which budget refused, not only that something did.
class KindEncoder final : public adnl::ExtQueryFailureEncoder {
 public:
  td::Result<td::BufferSlice> encode(const adnl::ExtQueryFailure& failure) const override {
    return create_serialize_tl_object<lite_api::liteServer_error>(ErrorCode::notready,
                                                                  adnl::ext_query_failure_kind_name(failure.kind));
  }
};

// Returns more than the failure payload cap; the server must close rather than send it.
class OversizedEncoder final : public adnl::ExtQueryFailureEncoder {
 public:
  td::Result<td::BufferSlice> encode(const adnl::ExtQueryFailure&) const override {
    return td::BufferSlice{adnl::kMaxExtQueryFailurePayloadBytes + 1};
  }
};

enum class EncoderChoice { None, Kind, Lite, Oversized };

class ReadyCallback final : public adnl::AdnlExtClient::Callback {
 public:
  explicit ReadyCallback(std::shared_ptr<std::atomic<int>> ready) : ready_(std::move(ready)) {
  }
  void on_ready() override {
    ready_->fetch_add(1, std::memory_order_acq_rel);
  }
  void on_stop_ready() override {
  }

 private:
  std::shared_ptr<std::atomic<int>> ready_;
};

struct Slot {
  std::string request;
  std::atomic<int> completions{0};
  std::mutex mutex;
  td::Result<td::BufferSlice> result{td::Status::Error("query not completed")};
  double sent_at = 0.0;
  double completed_at = 0.0;

  double elapsed() {
    std::lock_guard lock(mutex);
    return completed_at - sent_at;
  }
};

class Harness {
 public:
  Harness(std::string name, EncoderChoice encoder) : name_(std::move(name)) {
    port_ = allocate_tcp_port();
    db_root_ = "/tmp/tos-adnl-ext-query-refusal-" + std::to_string(::getpid()) + "-" + name_;
    td::rmrf(db_root_).ignore();
    require(td::mkdir(db_root_).is_ok(), "cannot create db directory");
    scheduler_ = std::make_unique<td::actor::Scheduler>(std::vector<td::actor::Scheduler::NodeInfo>{2});
    state_ = std::make_shared<ServerState>();
    start_server(encoder);
  }

  ~Harness() {
    scheduler_->run_in_context([&] {
      clients_.clear();
      server_.reset();
      adnl_.reset();
      keyring_.reset();
    });
    scheduler_->run(0.2);
    scheduler_->stop();
    td::rmrf(db_root_).ignore();
  }

  Harness(const Harness&) = delete;
  Harness& operator=(const Harness&) = delete;

  void set_mode(ServerMode mode) {
    std::lock_guard lock(state_->mutex);
    state_->mode = mode;
  }

  // Opens one more client connection and waits until it is ready; returns its index.
  size_t connect() {
    auto ready = std::make_shared<std::atomic<int>>(0);
    scheduler_->run_in_context([&] {
      clients_.push_back(adnl::AdnlExtClient::create(server_id_, "127.0.0.1:" + std::to_string(port_),
                                                     std::make_unique<ReadyCallback>(ready)));
    });
    wait_until([&] { return ready->load(std::memory_order_acquire) >= 1; }, 10.0, "client did not become ready");
    return clients_.size() - 1;
  }

  std::shared_ptr<Slot> send(size_t client, std::string request) {
    auto slot = std::make_shared<Slot>();
    slot->request = std::move(request);
    scheduler_->run_in_context([&] {
      slot->sent_at = td::Time::now();
      td::actor::send_closure(clients_.at(client), &adnl::AdnlExtClient::send_query, slot->request,
                              td::BufferSlice{slot->request}, td::Timestamp::in(kClientDeadline),
                              td::PromiseCreator::lambda([slot](td::Result<td::BufferSlice> result) {
                                std::lock_guard lock(slot->mutex);
                                if (slot->completions.load(std::memory_order_acquire) == 0) {
                                  slot->result = std::move(result);
                                  slot->completed_at = td::Time::now();
                                }
                                slot->completions.fetch_add(1, std::memory_order_acq_rel);
                              }));
    });
    return slot;
  }

  void wait_completed(const std::vector<std::shared_ptr<Slot>>& slots, const std::string& what) {
    wait_until(
        [&] {
          for (auto& slot : slots) {
            if (slot->completions.load(std::memory_order_acquire) == 0) {
              return false;
            }
          }
          return true;
        },
        kClientDeadline + 1.0, what);
  }

  size_t delivered() {
    std::lock_guard lock(state_->mutex);
    return state_->delivered;
  }

  size_t held() {
    std::lock_guard lock(state_->mutex);
    return state_->held.size();
  }

  void wait_held(size_t count) {
    wait_until([&] { return held() >= count; }, 5.0, "server did not receive the held queries");
  }

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

  std::string tag(size_t index) const {
    return name_ + "#" + std::to_string(index) + "#" + std::to_string(td::Random::fast_uint64());
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

  void start_server(EncoderChoice encoder) {
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
      if (encoder == EncoderChoice::Kind) {
        td::actor::send_closure(server_, &adnl::AdnlExtServer::set_query_failure_encoder,
                                std::make_shared<const KindEncoder>());
      } else if (encoder == EncoderChoice::Lite) {
        td::actor::send_closure(server_, &adnl::AdnlExtServer::set_query_failure_encoder,
                                liteclient::LiteExtQueryFailureEncoder::create());
      } else if (encoder == EncoderChoice::Oversized) {
        td::actor::send_closure(server_, &adnl::AdnlExtServer::set_query_failure_encoder,
                                std::make_shared<const OversizedEncoder>());
      }
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
  adnl::AdnlNodeIdFull server_id_;
  td::actor::ActorOwn<keyring::Keyring> keyring_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<adnl::AdnlExtServer> server_;
  std::vector<td::actor::ActorOwn<adnl::AdnlExtClient>> clients_;
};

// Sends and completes `count` queries inside one rate window: batches of 16 stay under
// the 32 in-flight cap, so none of them is refused, and 64 fit well within one second.
void fill_rate_window(Harness& harness, size_t client, size_t count, bool require_echo);

void require_answered(Slot& slot, const std::string& where) {
  require(slot.completions.load(std::memory_order_acquire) == 1, where + ": promise did not complete exactly once");
  std::lock_guard lock(slot.mutex);
  require(slot.result.is_ok(),
          where + ": no answer: " + (slot.result.is_error() ? slot.result.error().message().str() : std::string{}));
  require(slot.result.ok().as_slice().str() == expected_answer(slot.request), where + ": answer bytes differ");
}

// A same-ID Lite error answer, within the prompt bound; returns its (code, message).
std::pair<td::int32, std::string> require_lite_error(Slot& slot, const std::string& where) {
  require(slot.completions.load(std::memory_order_acquire) == 1, where + ": promise did not complete exactly once");
  require(slot.elapsed() < kPromptBound, where + ": refusal was not prompt");
  std::lock_guard lock(slot.mutex);
  require(slot.result.is_ok(), where + ": expected a same-ID failure answer, got a transport error: " +
                                   (slot.result.is_error() ? slot.result.error().message().str() : std::string{}));
  auto error = fetch_tl_object<lite_api::liteServer_error>(slot.result.ok().clone(), true);
  require(error.is_ok(), where + ": answer is not a liteServer.error");
  auto value = error.move_as_ok();
  return {value->code_, value->message_};
}

// The connection was closed under the query: the client fails it at once, never by timeout.
void require_closed_promptly(Slot& slot, const std::string& where) {
  require(slot.completions.load(std::memory_order_acquire) == 1, where + ": promise did not complete exactly once");
  require(slot.elapsed() < kPromptBound, where + ": closed connection was not observed promptly");
  std::lock_guard lock(slot.mutex);
  require(slot.result.is_error() && slot.result.error().code() == ErrorCode::cancelled,
          where + ": expected a prompt connection failure, got " +
              (slot.result.is_ok() ? std::string{"an answer"} : slot.result.error().message().str()));
}

void fill_rate_window(Harness& harness, size_t client, size_t count, bool require_echo) {
  for (size_t first = 0; first < count; first += 16) {
    std::vector<std::shared_ptr<Slot>> batch;
    for (size_t index = first; index < std::min(count, first + 16); index++) {
      batch.push_back(harness.send(client, harness.tag(index)));
    }
    harness.wait_completed(batch, "accepted query did not complete");
    if (require_echo) {
      for (auto& slot : batch) {
        require_answered(*slot, "accepted query");
      }
    }
  }
}

// A: the 65th query in one window on one connection is answered with the same ID,
// by the production Lite encoder; the connection stays usable and the refused query
// never reaches the service.
void sixty_fifth_query() {
  Harness harness("sixty-fifth", EncoderChoice::Lite);
  auto client = harness.connect();
  auto started = td::Time::now();
  fill_rate_window(harness, client, 64, true);
  require(td::Time::now() - started < 0.9, "the 64 accepted queries did not fit one rate window; case is not the 65th");
  auto refused = harness.send(client, harness.tag(64));
  harness.wait_completed({refused}, "65th query did not complete");
  require(harness.delivered() == 64, "the refused query reached the service");
  auto expected = liteclient::LiteExtQueryFailureEncoder().encode(
      adnl::ExtQueryFailure{adnl::ExtQueryFailureKind::PerConnectionRateLimit, td::Status::OK()});
  require(expected.is_ok(), "Lite encoder failed");
  {
    std::lock_guard lock(refused->mutex);
    require(refused->result.is_ok() && refused->result.ok().as_slice() == expected.ok().as_slice(),
            "65th answer is not the Lite encoder's bytes for its own ID");
  }
  auto [code, message] = require_lite_error(*refused, "65th query");
  require(code == ErrorCode::notready && message == "liteserver admission limit exceeded", "65th Lite error differs");
  harness.pump(1.1);
  auto after = harness.send(client, harness.tag(65));
  harness.wait_completed({after}, "query after the window did not complete");
  require_answered(*after, "same connection after the rate window");
  std::printf(
      "B64_CASE sixty_fifth refused_elapsed_ms=%.3f same_id_lite_error=true connection_kept=true delivered=64\n",
      1000.0 * refused->elapsed());
}

// B: the 33rd concurrently held query on one connection is refused by the in-flight
// cap with its own ID; the 32 accepted ones still complete.
void inflight_limit() {
  Harness harness("inflight", EncoderChoice::Kind);
  auto client = harness.connect();
  harness.set_mode(ServerMode::Hold);
  std::vector<std::shared_ptr<Slot>> accepted;
  for (size_t index = 0; index < 32; index++) {
    accepted.push_back(harness.send(client, harness.tag(index)));
  }
  harness.wait_held(32);
  auto refused = harness.send(client, harness.tag(32));
  harness.wait_completed({refused}, "33rd query did not complete");
  auto [code, message] = require_lite_error(*refused, "33rd in-flight query");
  require(code == ErrorCode::notready && message == "per_connection_inflight", "33rd refusal kind differs: " + message);
  require(harness.held() == 32, "the refused query reached the service");
  harness.release_held();
  harness.wait_completed(accepted, "held queries did not complete");
  for (auto& slot : accepted) {
    require_answered(*slot, "held query after release");
  }
  std::printf("B64_CASE inflight refused_kind=%s accepted_completed=32\n", message.c_str());
}

// B: one address may hold at most 256 queries across all its connections. Eight
// connections of 32 fill it; the next query from a ninth is refused per IP. After
// the held queries finish, the full per-IP capacity is available again (no leak).
void per_ip_limit() {
  Harness harness("per-ip", EncoderChoice::Kind);
  harness.set_mode(ServerMode::Hold);
  std::vector<std::shared_ptr<Slot>> accepted;
  for (size_t connection = 0; connection < 8; connection++) {
    auto client = harness.connect();
    for (size_t index = 0; index < 32; index++) {
      accepted.push_back(harness.send(client, harness.tag(connection * 32 + index)));
    }
    harness.wait_held((connection + 1) * 32);
  }
  auto ninth = harness.connect();
  auto refused = harness.send(ninth, harness.tag(1000));
  harness.wait_completed({refused}, "per-IP refusal did not complete");
  auto [code, message] = require_lite_error(*refused, "257th query from one address");
  require(message == "per_ip", "per-IP refusal kind differs: " + message);
  require(harness.held() == 256, "the refused query reached the service");
  harness.release_held();
  harness.wait_completed(accepted, "held queries did not complete");
  for (auto& slot : accepted) {
    require_answered(*slot, "held query after release");
  }
  // Server-level counters returned to zero: the whole per-IP budget is usable again.
  std::vector<std::shared_ptr<Slot>> again;
  for (size_t index = 0; index < 32; index++) {
    again.push_back(harness.send(ninth, harness.tag(2000 + index)));
  }
  harness.wait_held(32);
  harness.release_held();
  harness.wait_completed(again, "queries after release did not complete");
  for (auto& slot : again) {
    require_answered(*slot, "query after per-IP release");
  }
  std::printf("B64_CASE per_ip refused_kind=%s held=256 released_and_reusable=true\n", message.c_str());
}

// C: rejections cannot be turned into unbounded failure answers. Past the
// per-connection reply budget the connection is closed; every remaining query on it
// fails at once instead of waiting.
void reply_budget_exhaustion() {
  Harness harness("reply-budget", EncoderChoice::Kind);
  auto client = harness.connect();
  auto started = td::Time::now();
  fill_rate_window(harness, client, 64, true);
  require(td::Time::now() - started < 0.9, "the 64 accepted queries did not fit one rate window");
  std::vector<std::shared_ptr<Slot>> flood;
  for (size_t index = 0; index < 40; index++) {
    flood.push_back(harness.send(client, harness.tag(100 + index)));
  }
  harness.wait_completed(flood, "flooded queries did not complete");
  size_t replies = 0;
  size_t closed = 0;
  size_t reply_bytes = 0;
  for (auto& slot : flood) {
    require(slot->elapsed() < kPromptBound, "a flooded query was not terminal promptly");
    std::lock_guard lock(slot->mutex);
    if (slot->result.is_ok()) {
      replies++;
      reply_bytes += slot->result.ok().size();
    } else {
      require(slot->result.error().code() == ErrorCode::cancelled, "flooded query ended in an unexpected error");
      closed++;
    }
  }
  require(replies == adnl::ExtQueryFailurePolicy::kMaxRepliesPerConnection,
          "failure answers exceeded or fell short of the per-connection budget: " + std::to_string(replies));
  require(closed == flood.size() - replies, "a flooded query was neither answered nor failed by the close");
  require(reply_bytes <= replies * adnl::kMaxExtQueryFailurePayloadBytes, "failure answers exceeded their byte bound");
  require(harness.delivered() == 64, "a refused query reached the service");
  std::printf("B64_CASE reply_budget replies=%zu closed=%zu reply_bytes=%zu\n", replies, closed, reply_bytes);
}

// D: a handler error is answered with the same ID and a sanitized message, both for
// an explicit error and for the base callback's default refusal.
void handler_error_answered() {
  for (auto mode : {ServerMode::Error, ServerMode::DefaultCallbackError}) {
    Harness harness(mode == ServerMode::Error ? "handler-error" : "default-callback", EncoderChoice::Lite);
    auto client = harness.connect();
    harness.set_mode(mode);
    auto slot = harness.send(client, harness.tag(0));
    harness.wait_completed({slot}, "handler error did not complete");
    auto [code, message] = require_lite_error(*slot, "handler error");
    require(code == ErrorCode::error && message == "liteserver query failed", "handler error answer differs");
    require(message.find("internal") == std::string::npos && message.find("Callback") == std::string::npos,
            "handler error text was reflected to the client");
    harness.set_mode(ServerMode::Echo);
    auto after = harness.send(client, harness.tag(1));
    harness.wait_completed({after}, "query after handler error did not complete");
    require_answered(*after, "connection after handler error");
  }
  std::printf("B64_CASE handler_error same_id_answer=true sanitized=true connection_kept=true\n");
}

// E: a result too large to frame is replaced by a small same-ID failure.
void oversized_answered() {
  Harness harness("oversized", EncoderChoice::Lite);
  auto client = harness.connect();
  harness.set_mode(ServerMode::Oversized);
  auto slot = harness.send(client, harness.tag(0));
  harness.wait_completed({slot}, "oversized result did not complete");
  auto [code, message] = require_lite_error(*slot, "oversized result");
  require(code == ErrorCode::error && message == "liteserver response too large", "oversized answer differs");
  std::printf("B64_CASE oversized same_id_answer=true\n");
}

// F: a service that installed no encoder (not Lite) never receives a Lite payload.
// Overload, a handler error and an oversized result each close the connection, and
// every query on it fails at once.
void no_encoder_closes() {
  {
    Harness harness("no-encoder-inflight", EncoderChoice::None);
    auto client = harness.connect();
    harness.set_mode(ServerMode::Hold);
    std::vector<std::shared_ptr<Slot>> held;
    for (size_t index = 0; index < 32; index++) {
      held.push_back(harness.send(client, harness.tag(index)));
    }
    harness.wait_held(32);
    auto refused = harness.send(client, harness.tag(32));
    harness.wait_completed({refused}, "refused query did not complete");
    require_closed_promptly(*refused, "no-encoder overload");
    harness.wait_completed(held, "held queries did not fail with the closed connection");
    for (auto& slot : held) {
      require_closed_promptly(*slot, "held query on the closed connection");
    }
    harness.release_held();
  }
  for (auto mode : {ServerMode::Error, ServerMode::Oversized}) {
    Harness harness(mode == ServerMode::Error ? "no-encoder-error" : "no-encoder-oversized", EncoderChoice::None);
    auto client = harness.connect();
    harness.set_mode(mode);
    auto slot = harness.send(client, harness.tag(0));
    harness.wait_completed({slot}, "query did not complete");
    require_closed_promptly(*slot, mode == ServerMode::Error ? "no-encoder handler error" : "no-encoder oversized");
  }
  std::printf(
      "B64_CASE no_encoder overload_closed=true handler_error_closed=true oversized_closed=true lite_payload=false\n");
}

// An encoder whose output exceeds the failure payload cap is never sent: the
// refused query and every query held on the connection fail at once instead.
void oversized_encoder_closes() {
  Harness harness("oversized-encoder", EncoderChoice::Oversized);
  auto client = harness.connect();
  harness.set_mode(ServerMode::Hold);
  std::vector<std::shared_ptr<Slot>> held;
  for (size_t index = 0; index < 32; index++) {
    held.push_back(harness.send(client, harness.tag(index)));
  }
  harness.wait_held(32);
  auto refused = harness.send(client, harness.tag(32));
  harness.wait_completed({refused}, "refused query did not complete");
  require_closed_promptly(*refused, "oversized failure payload");
  harness.wait_completed(held, "held queries did not fail with the closed connection");
  for (auto& slot : held) {
    require_closed_promptly(*slot, "held query after an oversized failure payload");
  }
  harness.release_held();
  std::printf("B64_CASE oversized_encoder closed=true payload_sent=false\n");
}

// Value-level checks of the pieces the connection composes.
void unit_checks() {
  using adnl::ExtQueryFailure;
  using adnl::ExtQueryFailureKind;
  liteclient::LiteExtQueryFailureEncoder encoder;
  for (auto kind : {ExtQueryFailureKind::PerConnectionRateLimit, ExtQueryFailureKind::PerConnectionInflightLimit,
                    ExtQueryFailureKind::ServerInflightLimit, ExtQueryFailureKind::PerIpInflightLimit,
                    ExtQueryFailureKind::HandlerError, ExtQueryFailureKind::ResponseTooLarge}) {
    auto encoded = encoder.encode(ExtQueryFailure{kind, td::Status::Error(ErrorCode::error, "secret detail 10.0.0.7")});
    require(encoded.is_ok() && encoded.ok().size() <= adnl::kMaxExtQueryFailurePayloadBytes,
            "Lite encoding failed or exceeded its bound");
    auto parsed = fetch_tl_object<lite_api::liteServer_error>(encoded.ok().clone(), true);
    require(parsed.is_ok(), "Lite encoding is not a liteServer.error");
    require(parsed.ok()->message_.find("secret") == std::string::npos, "Lite encoding reflected handler text");
  }

  adnl::ExtFailureReplyLimits limits(1.0, 2, 3, 2);
  auto now = td::Timestamp::at(100.0);
  require(limits.try_acquire("192.0.2.1", now) && limits.try_acquire("192.0.2.1", now), "per-IP budget too small");
  require(!limits.try_acquire("192.0.2.1", now), "per-IP failure budget not enforced");
  require(limits.try_acquire("192.0.2.2", now), "second address refused below the global budget");
  require(!limits.try_acquire("192.0.2.2", now), "global failure budget not enforced");
  require(!limits.try_acquire("192.0.2.3", now), "tracked-address bound not enforced within the window");
  auto later = td::Timestamp::at(101.5);
  require(limits.try_acquire("192.0.2.3", later), "expired windows were not released");
  require(limits.tracked_ips() <= 2, "tracked addresses exceeded their bound");

  adnl::ExtServerQueryLimits server(1, 1);
  require(server.try_acquire("192.0.2.1") == adnl::ExtAdmission::Acquired, "server admission failed");
  require(server.try_acquire("192.0.2.2") == adnl::ExtAdmission::ServerInflightLimited,
          "server-wide in-flight cap not reported as such");
  server.release("192.0.2.1");
  require(server.inflight() == 0, "server in-flight counter did not return to zero");

  // Output bound: the frame of the largest legal payload, and two of them, fit;
  // one byte more queued than that does not, and no input wraps around.
  const size_t max_payload = adnl::adnl_ext_max_packet_bytes - adnl::adnl_ext_packet_framing_bytes;
  const size_t max_frame = max_payload + 4 + 32 + 32;
  require(max_frame == adnl::adnl_ext_max_frame_bytes, "largest legal frame differs from the declared frame bound");
  require(adnl::adnl_ext_output_fits(0, max_frame), "a maximal reply does not fit an empty queue");
  require(adnl::adnl_ext_output_fits(max_frame, max_frame), "a maximal reply cannot queue behind one in flight");
  require(!adnl::adnl_ext_output_fits(max_frame + 1, max_frame), "output bound not enforced");
  require(!adnl::adnl_ext_output_fits(0, adnl::adnl_ext_max_pending_output_bytes + 1),
          "a frame larger than the whole bound fits");
  require(!adnl::adnl_ext_output_fits(std::numeric_limits<size_t>::max(), 1), "pending size wrapped around");
  require(!adnl::adnl_ext_output_fits(1, std::numeric_limits<size_t>::max()), "frame size wrapped around");

  // Server-wide bound: what all connections hold together.
  const size_t server_max = adnl::adnl_ext_max_server_pending_output_bytes;
  require(adnl::adnl_ext_server_output_fits(0, 0, max_frame), "a maximal reply does not fit an idle server");
  require(adnl::adnl_ext_server_output_fits(server_max - max_frame - 10, 10, max_frame),
          "a reply exactly filling the server bound was refused");
  require(!adnl::adnl_ext_server_output_fits(server_max - max_frame - 10, 11, max_frame),
          "server output bound not enforced");
  require(!adnl::adnl_ext_server_output_fits(server_max + 1, 0, 1), "other connections over the bound not refused");
  require(!adnl::adnl_ext_server_output_fits(std::numeric_limits<size_t>::max(), 1, 1), "server total wrapped around");
  require(!adnl::adnl_ext_server_output_fits(1, std::numeric_limits<size_t>::max(), 1), "pending wrapped around");
  require(adnl::adnl_ext_max_server_pending_output_bytes < 1024 * adnl::adnl_ext_max_pending_output_bytes,
          "server bound is no tighter than the per-connection bound times the connection limit");
  std::printf("B64_CASE unit lite_encoder_bounded=true reply_limits=true server_limit_reason=true output_bound=true\n");
}

}  // namespace

int main(int argc, char** argv) {
  // "trace" as a second argument keeps the server's per-query ADNL_EXT_QUERY lines.
  const bool trace = argc > 2 && std::string(argv[2]) == "trace";
  SET_VERBOSITY_LEVEL(trace ? VERBOSITY_NAME(DEBUG) : VERBOSITY_NAME(WARNING));
  const std::string only = argc > 1 ? argv[1] : "all";
  const std::vector<std::pair<std::string, void (*)()>> cases = {
      {"unit", unit_checks},
      {"sixty-fifth", sixty_fifth_query},
      {"inflight", inflight_limit},
      {"per-ip", per_ip_limit},
      {"reply-budget", reply_budget_exhaustion},
      {"handler-error", handler_error_answered},
      {"oversized", oversized_answered},
      {"no-encoder", no_encoder_closes},
      {"oversized-encoder", oversized_encoder_closes},
  };
  bool ran = false;
  for (auto& [name, run] : cases) {
    if (only == "all" || only == name) {
      run();
      ran = true;
    }
  }
  require(ran, "unknown case: " + only);
  std::printf("B64_REFUSAL_TESTS passed=%s\n", only.c_str());
  return 0;
}
