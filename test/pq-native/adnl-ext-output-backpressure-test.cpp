/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Unread output on an ADNL external connection is bounded per connection and
// across a server, and the bound is enforced where it matters: on the real
// connection actor, through its real send() and BufferedFd, while the transport
// refuses every write.
//
// The transport is a test double installed in place of the socket's write side,
// so a stalled peer is exact and does not depend on how much a kernel socket
// buffer absorbs. Queries still arrive over a real socket and through the
// connection's real decrypting reader. Budgets are small so each case needs only
// a handful of kilobyte-sized replies.
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "adnl/adnl-ext-connection.hpp"
#include "adnl/adnl-ext-limits.h"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/Time.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/port/detail/NativeFd.h"

namespace {

using namespace tos;

// A reply payload of this size is a frame of exactly kFrame bytes on the wire.
constexpr size_t kPayload = 932;
constexpr size_t kFrame = kPayload + 4 + 32 + 32;
static_assert(kFrame == 1000);

[[noreturn]] void fail(const std::string& message) {
  std::fprintf(stderr, "ADNL_EXT_OUTPUT_BACKPRESSURE_FAILURE: %s\n", message.c_str());
  std::fflush(stderr);
  std::_Exit(1);
}

void require(bool condition, const std::string& message) {
  if (!condition) {
    fail(message);
  }
}

// A peer that reads nothing: every write would block.
class StalledTransport final : public adnl::AdnlExtTransportWriter {
 public:
  td::Result<size_t> writev(td::Span<td::IoSlice> slices) override {
    require(!slices.empty(), "asked to write nothing");
    attempts_.fetch_add(1, std::memory_order_acq_rel);
    return 0;
  }
  size_t attempts() const {
    return attempts_.load(std::memory_order_acquire);
  }

 private:
  std::atomic<size_t> attempts_{0};
};

// A peer that keeps reading, at most kChunk bytes per write, and keeps what it read.
class DrainingTransport final : public adnl::AdnlExtTransportWriter {
 public:
  static constexpr size_t kChunk = 700;
  td::Result<size_t> writev(td::Span<td::IoSlice> slices) override {
    std::lock_guard lock(mutex_);
    size_t taken = 0;
    for (auto& slice : slices) {
      auto n = std::min(slice.iov_len, kChunk - taken);
      received_.append(static_cast<const char*>(slice.iov_base), n);
      taken += n;
      if (taken == kChunk) {
        break;
      }
    }
    return taken;
  }
  std::string received() {
    std::lock_guard lock(mutex_);
    return received_;
  }

 private:
  std::mutex mutex_;
  std::string received_;
};

struct Observation {
  std::mutex mutex;
  size_t dispatched = 0;
  size_t queued = 0;
  size_t refused = 0;
  bool closed = false;
  bool overflowed = false;
};

// The real connection actor with the smallest possible protocol on top: the
// init packet is the key material itself, and every query asks for a reply of
// a given size, which is answered through send() as the query is read.
class ProbeConnection final : public adnl::AdnlExtConnection {
 public:
  ProbeConnection(td::SocketFd fd, std::shared_ptr<adnl::AdnlExtTransportWriter> transport,
                  std::shared_ptr<adnl::AdnlExtOutputBudget> budget, size_t pending_limit,
                  std::shared_ptr<Observation> observation, std::shared_ptr<adnl::AdnlExtByteBudget> input_budget)
      : AdnlExtConnection(std::move(fd), nullptr, false), observation_(std::move(observation)) {
    // Reads go through the server's input budget, as a server connection's do.
    set_input_limits(std::move(input_budget));
    set_transport_writer(std::move(transport));
    set_pending_output_limit(pending_limit);
    set_shared_output_budget(std::move(budget));
  }

  td::Status process_init_packet(td::BufferSlice data) override {
    return init_crypto(data.as_slice());
  }
  td::Status process_custom_packet(td::BufferSlice&, bool& processed) override {
    processed = false;
    return td::Status::OK();
  }
  td::Status process_packet(td::BufferSlice data) override {
    require(data.size() == 4, "query is not a reply size");
    td::uint32 reply_size;
    std::memcpy(&reply_size, data.as_slice().data(), 4);
    {
      std::lock_guard lock(observation_->mutex);
      observation_->dispatched++;
    }
    bool queued = send(td::BufferSlice{reply_size});
    std::lock_guard lock(observation_->mutex);
    (queued ? observation_->queued : observation_->refused)++;
    return td::Status::OK();
  }

 protected:
  void tear_down() override {
    AdnlExtConnection::tear_down();
    std::lock_guard lock(observation_->mutex);
    observation_->closed = true;
    observation_->overflowed = output_overflowed();
  }

 private:
  std::shared_ptr<Observation> observation_;
};

// The client end: writes the init packet and encrypted queries over a real
// socket pair, and can decrypt what the connection sent.
class Peer {
 public:
  Peer() {
    int pair[2];
    require(::socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "socketpair failed");
    client_fd_ = pair[0];
    auto server = td::SocketFd::from_native_fd(td::NativeFd(pair[1]));
    require(server.is_ok(), "cannot wrap the server end");
    server_fd_ = server.move_as_ok();

    init_packet_ = std::string(256, '\0');
    td::Random::secure_bytes(td::MutableSlice(init_packet_));
    // The server reads with (s2, v2) and writes with (s1, v1).
    td::Slice key(init_packet_);
    to_server_.init(key.substr(32, 32), key.substr(80, 16));
    from_server_.init(key.substr(0, 32), key.substr(64, 16));
  }
  ~Peer() {
    ::close(client_fd_);
  }
  Peer(const Peer&) = delete;
  Peer& operator=(const Peer&) = delete;

  td::SocketFd take_server_end() {
    return std::move(server_fd_);
  }

  void send_init() {
    write_all(init_packet_);
  }

  // `count` queries in one write, each asking for a kPayload reply.
  void send_queries(size_t count) {
    std::string bytes;
    for (size_t i = 0; i < count; i++) {
      bytes += encrypted_query(static_cast<td::uint32>(kPayload));
    }
    write_all(bytes);
  }

  // Decrypts the connection's output and counts well-formed kPayload frames.
  size_t count_reply_frames(const std::string& wire) {
    std::string plain(wire.size(), '\0');
    from_server_.encrypt(td::Slice(wire), td::MutableSlice(plain));
    size_t frames = 0;
    td::Slice rest(plain);
    while (!rest.empty()) {
      require(rest.size() >= 4, "truncated length prefix");
      td::uint32 len;
      std::memcpy(&len, rest.data(), 4);
      rest.remove_prefix(4);
      require(len == kPayload + 64 && rest.size() >= len, "unexpected frame length");
      auto packet = rest.substr(0, len);
      require(td::sha256(packet.substr(0, len - 32)) == packet.substr(len - 32).str(), "frame checksum mismatch");
      rest.remove_prefix(len);
      frames++;
    }
    return frames;
  }

 private:
  std::string encrypted_query(td::uint32 reply_size) {
    std::string payload(4, '\0');
    std::memcpy(payload.data(), &reply_size, 4);
    std::string nonce(32, '\0');
    td::Random::secure_bytes(td::MutableSlice(nonce));
    std::string body = nonce + payload;
    body += td::sha256(body);
    td::uint32 len = static_cast<td::uint32>(body.size());
    std::string plain(4, '\0');
    std::memcpy(plain.data(), &len, 4);
    plain += body;
    std::string wire(plain.size(), '\0');
    to_server_.encrypt(td::Slice(plain), td::MutableSlice(wire));
    return wire;
  }

  void write_all(const std::string& bytes) {
    size_t sent = 0;
    while (sent < bytes.size()) {
      auto n = ::send(client_fd_, bytes.data() + sent, bytes.size() - sent, MSG_NOSIGNAL);
      require(n > 0, "client write failed");
      sent += static_cast<size_t>(n);
    }
  }

  int client_fd_ = -1;
  td::SocketFd server_fd_;
  std::string init_packet_;
  td::AesCtrState to_server_;
  td::AesCtrState from_server_;
};

class Harness {
 public:
  Harness() : scheduler_(std::vector<td::actor::Scheduler::NodeInfo>{2}) {
  }
  ~Harness() {
    scheduler_.run_in_context([&] { connections_.clear(); });
    scheduler_.run(0.2);
    require(input_budget_->used() == 0, "teardown left input bytes reserved");
    scheduler_.stop();
  }
  Harness(const Harness&) = delete;
  Harness& operator=(const Harness&) = delete;

  size_t open(Peer& peer, std::shared_ptr<adnl::AdnlExtTransportWriter> transport,
              std::shared_ptr<adnl::AdnlExtOutputBudget> budget, size_t pending_limit,
              std::shared_ptr<Observation> observation) {
    auto fd = peer.take_server_end();
    scheduler_.run_in_context([&] {
      connections_.push_back(td::actor::create_actor<ProbeConnection>(
          td::actor::ActorOptions().with_name("probe").with_poll(), std::move(fd), std::move(transport),
          std::move(budget), pending_limit, std::move(observation), input_budget_));
    });
    return connections_.size() - 1;
  }

  void close(size_t index) {
    scheduler_.run_in_context([&] { connections_.at(index).reset(); });
  }

  template <class F>
  void wait_until(F&& done, const std::string& what) {
    auto deadline = td::Timestamp::in(10.0);
    while (!done()) {
      scheduler_.run(0.01);
      if (deadline.is_in_past()) {
        fail(what);
      }
    }
  }

  // Lets the actors run with nothing expected to change, to show nothing does.
  void settle() {
    auto until = td::Timestamp::in(0.2);
    while (!until.is_in_past()) {
      scheduler_.run(0.01);
    }
  }

 private:
  td::actor::Scheduler scheduler_;
  std::vector<td::actor::ActorOwn<ProbeConnection>> connections_;
  std::shared_ptr<adnl::AdnlExtByteBudget> input_budget_ = std::make_shared<adnl::AdnlExtByteBudget>(1 << 20);
};

struct Snapshot {
  size_t dispatched, queued, refused;
  bool closed, overflowed;
};

Snapshot snapshot(const std::shared_ptr<Observation>& observation) {
  std::lock_guard lock(observation->mutex);
  return {observation->dispatched, observation->queued, observation->refused, observation->closed,
          observation->overflowed};
}

// Sends single queries one write at a time, so each is read, answered and
// flushed before the next arrives; returns once all were answered.
void accumulate(Harness& harness, Peer& peer, const std::shared_ptr<Observation>& observation, size_t count,
                const std::string& who) {
  auto start = snapshot(observation).dispatched;
  for (size_t i = 1; i <= count; i++) {
    peer.send_queries(1);
    harness.wait_until([&] { return snapshot(observation).queued >= start + i; }, who + ": legal reply not queued");
  }
}

// One connection whose peer reads nothing hits its own bound.
void per_connection_bound() {
  Harness harness;
  auto budget = std::make_shared<adnl::AdnlExtOutputBudget>(std::size_t{1} << 20);
  auto transport = std::make_shared<StalledTransport>();
  auto observation = std::make_shared<Observation>();
  Peer peer;
  harness.open(peer, transport, budget, 3 * kFrame, observation);
  peer.send_init();

  // Three individually legal replies accumulate, each from its own query.
  for (size_t i = 1; i <= 3; i++) {
    accumulate(harness, peer, observation, 1, "per-connection");
    require(budget->used() == i * kFrame, "unread output not held in the budget after reply " + std::to_string(i));
    require(!snapshot(observation).closed, "connection closed below its bound");
  }
  require(transport->attempts() > 0, "the transport was never asked to write; the stall was not exercised");

  // The fourth reply would pass the bound. Three more queries ride in the same
  // read and must never reach the handler.
  peer.send_queries(4);
  harness.wait_until(
      [&] {
        auto s = snapshot(observation);
        return s.closed || s.dispatched >= 7;
      },
      "per-connection: neither closed nor dispatched every query");
  auto s = snapshot(observation);
  require(s.closed && s.overflowed, "connection was not closed for unread output");
  require(s.dispatched == 4, "queries buffered behind the overflow were dispatched: " + std::to_string(s.dispatched));
  require(s.queued == 3 && s.refused == 1, "replies past the per-connection bound were queued");
  require(budget->used() == 0, "teardown left " + std::to_string(budget->used()) + " bytes reserved");
  harness.settle();
  require(snapshot(observation).dispatched == 4, "a buffered query was dispatched after close");
  std::printf("B02_CASE per_connection queued=%zu refused=%zu dispatched=%zu used_after_close=%zu\n", s.queued,
              s.refused, s.dispatched, budget->used());
}

// Connections that each stay under their own bound hit the shared one; the
// overflowing connection gives back exactly what it held, and another
// connection can then use it.
void shared_budget_and_recovery() {
  Harness harness;
  auto budget = std::make_shared<adnl::AdnlExtOutputBudget>(5 * kFrame);
  const size_t own_limit = 100 * kFrame;

  auto b_transport = std::make_shared<StalledTransport>();
  auto b = std::make_shared<Observation>();
  Peer b_peer;
  harness.open(b_peer, b_transport, budget, own_limit, b);
  b_peer.send_init();
  accumulate(harness, b_peer, b, 2, "shared/B");
  require(budget->used() == 2 * kFrame, "B's unread output not held");

  auto a_transport = std::make_shared<StalledTransport>();
  auto a = std::make_shared<Observation>();
  Peer a_peer;
  harness.open(a_peer, a_transport, budget, own_limit, a);
  a_peer.send_init();
  accumulate(harness, a_peer, a, 3, "shared/A");
  require(budget->used() == 5 * kFrame, "A and B together do not hold the full budget");
  require(!snapshot(a).closed && !snapshot(b).closed, "a connection closed at the budget, not past it");
  require(a_transport->attempts() > 0 && b_transport->attempts() > 0, "a transport was never asked to write");

  a_peer.send_queries(4);
  harness.wait_until(
      [&] {
        auto s = snapshot(a);
        return s.closed || s.dispatched >= 7;
      },
      "shared/A: neither closed nor dispatched every query");
  auto sa = snapshot(a);
  require(sa.closed && sa.overflowed, "A was not closed at the shared budget");
  require(sa.dispatched == 4, "queries buffered behind A's overflow were dispatched: " + std::to_string(sa.dispatched));
  require(sa.queued == 3 && sa.refused == 1, "a reply past the shared budget was queued");
  // Exactly once: B's bytes are still held, A's are all back.
  require(budget->used() == 2 * kFrame, "after A closed the budget holds " + std::to_string(budget->used()) +
                                            " bytes, B holds " + std::to_string(2 * kFrame));
  require(!snapshot(b).closed, "B was closed by A's overflow");

  // A new connection reserves exactly the capacity A gave back.
  auto c_transport = std::make_shared<StalledTransport>();
  auto c = std::make_shared<Observation>();
  Peer c_peer;
  size_t c_index = harness.open(c_peer, c_transport, budget, own_limit, c);
  c_peer.send_init();
  accumulate(harness, c_peer, c, 3, "shared/C");
  require(budget->used() == 5 * kFrame && !snapshot(c).closed, "C could not reserve the recovered capacity");

  // The budget is full again and still binds: B's next reply is refused.
  b_peer.send_queries(1);
  harness.wait_until([&] { return snapshot(b).closed; }, "shared/B: not closed past the full budget");
  require(snapshot(b).refused == 1 && budget->used() == 3 * kFrame, "B's close did not return exactly its bytes");

  // A healthy connection closed by the server returns its bytes too.
  harness.close(c_index);
  harness.wait_until([&] { return snapshot(c).closed; }, "shared/C: did not close");
  require(budget->used() == 0 && !snapshot(c).overflowed, "C's close did not return its bytes");
  std::printf("B02_CASE shared a_dispatched=%zu b_after_a_close=%zu c_reserved=%zu final_used=%zu\n", sa.dispatched,
              2 * kFrame, 3 * kFrame, budget->used());
}

// A peer that reads keeps its connection however much it is sent in total,
// and the budget is given back as the bytes leave.
void progressing_peer_stays_connected() {
  Harness harness;
  auto budget = std::make_shared<adnl::AdnlExtOutputBudget>(5 * kFrame);
  auto transport = std::make_shared<DrainingTransport>();
  auto observation = std::make_shared<Observation>();
  Peer peer;
  harness.open(peer, transport, budget, 3 * kFrame, observation);
  peer.send_init();

  constexpr size_t kReplies = 20;
  for (size_t i = 1; i <= kReplies; i++) {
    accumulate(harness, peer, observation, 1, "progressing");
    harness.wait_until([&] { return budget->used() == 0; }, "progressing: written output was not released");
  }
  auto s = snapshot(observation);
  require(!s.closed && s.refused == 0 && s.queued == kReplies, "a reading peer was refused or disconnected");
  auto wire = transport->received();
  require(wire.size() == kReplies * kFrame, "transport received " + std::to_string(wire.size()) + " bytes");
  require(peer.count_reply_frames(wire) == kReplies, "transport did not receive every reply intact");
  std::printf("B02_CASE progressing replies=%zu bytes=%zu used=%zu\n", s.queued, wire.size(), budget->used());
}

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(WARNING));
  const std::string only = argc > 1 ? argv[1] : "all";
  const std::vector<std::pair<std::string, void (*)()>> cases = {
      {"per-connection", per_connection_bound},
      {"shared", shared_budget_and_recovery},
      {"progressing", progressing_peer_stays_connected},
  };
  bool ran = false;
  for (auto& [name, run] : cases) {
    if (only == "all" || only == name) {
      run();
      ran = true;
    }
  }
  require(ran, "unknown case: " + only);
  std::printf("B02_BACKPRESSURE_TESTS passed=%s\n", only.c_str());
  return 0;
}
