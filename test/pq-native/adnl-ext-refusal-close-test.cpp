/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// A refusal that closes an ADNL external connection still delivers every
// answer queued before it, within one bounded closing sequence:
//   a. a peer that pauses before reading gets all answers, then EOF;
//   b. a peer that never reads is released by the closing deadline;
//   c. an answer completing after the refusal is not written;
//   d. a peer that half-closes after its batch still gets all answers;
//   e. frames that arrive together with a reset are delivered, and the reset
//      still closes the connection;
//   f. a query whose service result succeeds only after the refusal neither
//      stops the closing connection nor spends the failure-reply allowance;
//   g. the same for a service result that fails after the refusal;
//   h. a peer that sends far more than one discard chunk after the refusal
//      and then half-closes still gets all answers, then a clean end of file.
// Cases a, b, c and d run the real connection actor over a real socket pair
// with small kernel buffers, so answers queue in the connection itself while
// the peer is not reading. Case e scripts the input side, so "bytes, then an
// error" in one read is deterministic. Cases f, g and h run a real external
// server over loopback TCP with a raw client that speaks the wire protocol
// itself, so it can stop reading and tell an end of file from a reset.
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "adnl/adnl-ext-connection.hpp"
#include "adnl/adnl-ext-query-failure.h"
#include "adnl/adnl.h"
#include "auto/tl/tos_api.h"
#include "common/errorcode.h"
#include "keyring/keyring.h"
#include "keys/encryptor.h"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/Time.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/port/detail/NativeFd.h"
#include "td/utils/port/path.h"
#include "td/utils/port/sleep.h"
#include "tl-utils/tl-utils.hpp"

namespace {

using namespace tos;

constexpr size_t kPayload = 932;
// Answers the probe gives before refusing; matches the server's reply budget.
constexpr size_t kAnswers = 16;
constexpr size_t kBatch = 20;

[[noreturn]] void fail(const std::string& message) {
  std::fprintf(stderr, "ADNL_EXT_REFUSAL_CLOSE_FAILURE: %s\n", message.c_str());
  std::exit(1);
}

void require(bool condition, const std::string& message) {
  if (!condition) {
    fail(message);
  }
}

// A peer whose reading can be paused: while paused every write would block.
class PausableTransport final : public adnl::AdnlExtTransportWriter {
 public:
  explicit PausableTransport(bool paused) : paused_(paused) {
  }
  td::Result<size_t> writev(td::Span<td::IoSlice> slices) override {
    if (paused_.load(std::memory_order_acquire)) {
      return 0;
    }
    std::lock_guard lock(mutex_);
    size_t taken = 0;
    for (auto& slice : slices) {
      received_.append(static_cast<const char*>(slice.iov_base), slice.iov_len);
      taken += slice.iov_len;
    }
    return taken;
  }
  void resume() {
    paused_.store(false, std::memory_order_release);
  }
  std::string received() {
    std::lock_guard lock(mutex_);
    return received_;
  }

 private:
  std::atomic<bool> paused_;
  std::mutex mutex_;
  std::string received_;
};

// Input scripted for one connection: everything in `bytes` at the first read,
// then the error.
class ScriptedReader final : public adnl::AdnlExtTransportReader {
 public:
  explicit ScriptedReader(std::string bytes) : bytes_(std::move(bytes)) {
  }
  td::Result<size_t> read(td::MutableSlice slice) override {
    if (offset_ < bytes_.size()) {
      auto n = std::min(slice.size(), bytes_.size() - offset_);
      std::memcpy(slice.data(), bytes_.data() + offset_, n);
      offset_ += n;
      return n;
    }
    return td::Status::PosixError(ECONNRESET, "scripted reset");
  }

 private:
  std::string bytes_;
  size_t offset_ = 0;
};

struct Observation {
  std::mutex mutex;
  size_t dispatched = 0;
  size_t answered = 0;
  bool closed = false;
  double refused_at = 0;
  double closed_at = 0;
  int late_sent = -1;
};

// The real connection actor with a minimal protocol: the init packet is the
// key material, every query is answered with a kPayload frame until kAnswers
// have been sent, and the next query is refused with a close.
class RefusingConnection final : public adnl::AdnlExtConnection {
 public:
  RefusingConnection(td::SocketFd fd, std::shared_ptr<adnl::AdnlExtTransportWriter> writer,
                     std::shared_ptr<adnl::AdnlExtTransportReader> reader, std::shared_ptr<Observation> observation)
      : AdnlExtConnection(std::move(fd), nullptr, false), observation_(std::move(observation)) {
    set_transport_writer(std::move(writer));
    if (reader) {
      set_transport_reader(std::move(reader));
    }
  }

  td::Status process_init_packet(td::BufferSlice data) override {
    return init_crypto(data.as_slice());
  }
  td::Status process_custom_packet(td::BufferSlice&, bool& processed) override {
    processed = false;
    return td::Status::OK();
  }
  td::Status process_packet(td::BufferSlice) override {
    std::lock_guard lock(observation_->mutex);
    observation_->dispatched++;
    if (observation_->answered < kAnswers) {
      require(send(td::BufferSlice{kPayload}), "an answer before the refusal was not queued");
      observation_->answered++;
      return td::Status::OK();
    }
    observation_->refused_at = td::Time::now();
    return td::Status::Error(ErrorCode::notready, "refused: reply budget exhausted");
  }

  // An answer whose work completed after the refusal began.
  void late_answer() {
    bool sent = send(td::BufferSlice{kPayload});
    std::lock_guard lock(observation_->mutex);
    observation_->late_sent = sent ? 1 : 0;
  }

 protected:
  void tear_down() override {
    AdnlExtConnection::tear_down();
    std::lock_guard lock(observation_->mutex);
    observation_->closed = true;
    observation_->closed_at = td::Time::now();
  }

 private:
  std::shared_ptr<Observation> observation_;
};

// The client end of a socket pair: produces the init packet and encrypted
// queries, and decrypts and counts answer frames.
class Peer {
 public:
  Peer() {
    int pair[2];
    require(::socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "socketpair failed");
    client_fd_ = pair[0];
    // Small kernel buffers on both ends: 16 answers of 1000 bytes cannot all
    // fit in them, so most stay in the connection's own output buffer while
    // the peer is not reading, which is what a refusal-close must not drop.
    int small = 4096;
    require(::setsockopt(pair[1], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0, "SO_SNDBUF failed");
    require(::setsockopt(client_fd_, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) == 0, "SO_RCVBUF failed");
    auto server = td::SocketFd::from_native_fd(td::NativeFd(pair[1]));
    require(server.is_ok(), "cannot wrap the server end");
    server_fd_ = server.move_as_ok();
    init_packet_ = std::string(256, '\0');
    td::Random::secure_bytes(td::MutableSlice(init_packet_));
    td::Slice key(init_packet_);
    to_server_.init(key.substr(32, 32), key.substr(80, 16));
    from_server_.init(key.substr(0, 32), key.substr(64, 16));
  }
  ~Peer() {
    close_client();
  }
  Peer(const Peer&) = delete;
  Peer& operator=(const Peer&) = delete;

  td::SocketFd take_server_end() {
    return std::move(server_fd_);
  }
  // The init packet and `count` queries, as the bytes the server would read.
  std::string script(size_t count) {
    std::string bytes = init_packet_;
    for (size_t i = 0; i < count; i++) {
      bytes += encrypted_query();
    }
    return bytes;
  }
  void write(const std::string& bytes) {
    size_t sent = 0;
    while (sent < bytes.size()) {
      auto n = ::send(client_fd_, bytes.data() + sent, bytes.size() - sent, MSG_NOSIGNAL);
      require(n > 0, "client write failed");
      sent += static_cast<size_t>(n);
    }
  }
  void shutdown_write() {
    require(::shutdown(client_fd_, SHUT_WR) == 0, "client shutdown failed");
  }
  void close_client() {
    if (client_fd_ >= 0) {
      ::close(client_fd_);
      client_fd_ = -1;
    }
  }
  // Reads what the server sends until end of file; false if no end of file
  // came within the timeout or the connection was reset.
  bool read_to_eof(std::string& received, int timeout_ms) {
    auto deadline = td::Timestamp::in(timeout_ms / 1000.0);
    char buf[4096];
    while (!deadline.is_in_past()) {
      pollfd pfd{client_fd_, POLLIN, 0};
      if (::poll(&pfd, 1, 50) <= 0) {
        continue;
      }
      auto n = ::recv(client_fd_, buf, sizeof(buf), MSG_DONTWAIT);
      if (n == 0) {
        return true;
      }
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          continue;
        }
        return false;
      }
      received.append(buf, static_cast<size_t>(n));
    }
    return false;
  }
  size_t count_frames(const std::string& wire) {
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
  std::string encrypted_query() {
    std::string body(32, '\0');
    td::Random::secure_bytes(td::MutableSlice(body));
    body += std::string(4, '\x01');
    body += td::sha256(body);
    td::uint32 len = static_cast<td::uint32>(body.size());
    std::string plain(4, '\0');
    std::memcpy(plain.data(), &len, 4);
    plain += body;
    std::string wire(plain.size(), '\0');
    to_server_.encrypt(td::Slice(plain), td::MutableSlice(wire));
    return wire;
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
    scheduler_.run_in_context([&] { connection_.reset(); });
    scheduler_.run(0.2);
    scheduler_.stop();
  }
  Harness(const Harness&) = delete;
  Harness& operator=(const Harness&) = delete;

  void open(Peer& peer, std::shared_ptr<adnl::AdnlExtTransportWriter> writer,
            std::shared_ptr<adnl::AdnlExtTransportReader> reader, std::shared_ptr<Observation> observation) {
    auto fd = peer.take_server_end();
    scheduler_.run_in_context([&] {
      connection_ = td::actor::create_actor<RefusingConnection>(
          td::actor::ActorOptions().with_name("refusing").with_poll(), std::move(fd), std::move(writer),
          std::move(reader), std::move(observation));
    });
  }
  void late_answer() {
    scheduler_.run_in_context([&] { td::actor::send_closure(connection_, &RefusingConnection::late_answer); });
  }
  template <class F>
  void wait_until(F&& done, double seconds, const std::string& what) {
    auto deadline = td::Timestamp::in(seconds);
    while (!done()) {
      scheduler_.run(0.01);
      if (deadline.is_in_past()) {
        fail(what);
      }
    }
  }
  void run_for(double seconds) {
    auto until = td::Timestamp::in(seconds);
    while (!until.is_in_past()) {
      scheduler_.run(0.01);
    }
  }

 private:
  td::actor::Scheduler scheduler_;
  td::actor::ActorOwn<RefusingConnection> connection_;
};

template <class F>
auto locked(const std::shared_ptr<Observation>& observation, F&& read) {
  std::lock_guard lock(observation->mutex);
  return read(*observation);
}

bool refused(const std::shared_ptr<Observation>& o) {
  return locked(o, [](Observation& s) { return s.refused_at > 0; });
}
bool closed(const std::shared_ptr<Observation>& o) {
  return locked(o, [](Observation& s) { return s.closed; });
}

// Reads the peer's side to end of file on its own thread, so the actors keep
// running on the test's thread meanwhile.
class PeerReader {
 public:
  PeerReader(Peer& peer, int timeout_ms) {
    thread_ = std::thread([this, &peer, timeout_ms] {
      eof_ = peer.read_to_eof(received_, timeout_ms);
      done_.store(true, std::memory_order_release);
    });
  }
  ~PeerReader() {
    if (thread_.joinable()) {
      thread_.join();
    }
  }
  bool done() const {
    return done_.load(std::memory_order_acquire);
  }
  // Valid once done().
  bool eof() const {
    return eof_;
  }
  const std::string& received() const {
    return received_;
  }

 private:
  std::thread thread_;
  std::atomic<bool> done_{false};
  bool eof_ = false;
  std::string received_;
};

// a. The peer is not reading when the refusal comes, and reads 0.3 s later.
void paused_peer_gets_every_answer() {
  Harness harness;
  Peer peer;
  auto observation = std::make_shared<Observation>();
  harness.open(peer, nullptr, nullptr, observation);
  peer.write(peer.script(kBatch));
  harness.wait_until([&] { return refused(observation); }, 5.0, "a: the refusal never came");
  harness.run_for(0.3);
  require(!closed(observation), "a: the connection closed while the peer was not reading");
  PeerReader reader(peer, 3000);
  harness.wait_until([&] { return reader.done(); }, 4.0, "a: the peer's read did not finish");
  require(reader.eof(), "a: the peer got no end of file after the answers");
  auto frames = peer.count_frames(reader.received());
  require(frames == kAnswers, "a: the peer got " + std::to_string(frames) + " answers, expected 16");
  peer.close_client();
  harness.wait_until([&] { return closed(observation); }, 2.0, "a: the connection did not close after the peer");
  std::printf("REFUSAL_CLOSE_CASE paused frames=%zu\n", frames);
}

// b. The peer never reads: the closing deadline releases the connection.
void silent_peer_is_released_by_the_deadline() {
  Harness harness;
  Peer peer;
  auto observation = std::make_shared<Observation>();
  harness.open(peer, nullptr, nullptr, observation);
  peer.write(peer.script(kBatch));
  harness.wait_until([&] { return refused(observation); }, 5.0, "b: the refusal never came");
  harness.wait_until([&] { return closed(observation); }, 4.0, "b: a non-reading peer held the connection");
  auto held = locked(observation, [](Observation& s) { return s.closed_at - s.refused_at; });
  require(held >= 1.5, "b: released after " + std::to_string(held) + " s, before the answers had their chance");
  require(held <= 2.5, "b: released " + std::to_string(held) + " s after the refusal, bound is 2.5 s");
  std::printf("REFUSAL_CLOSE_CASE silent held=%.2f\n", held);
}

// c. An answer completing after the refusal is dropped, not written.
void late_answer_is_not_written() {
  Harness harness;
  Peer peer;
  auto observation = std::make_shared<Observation>();
  harness.open(peer, nullptr, nullptr, observation);
  peer.write(peer.script(kBatch));
  harness.wait_until([&] { return refused(observation); }, 5.0, "c: the refusal never came");
  harness.late_answer();
  harness.wait_until([&] { return locked(observation, [](Observation& s) { return s.late_sent >= 0; }); }, 2.0,
                     "c: the late answer was never attempted");
  require(locked(observation, [](Observation& s) { return s.late_sent; }) == 0, "c: a late answer was queued");
  PeerReader reader(peer, 3000);
  harness.wait_until([&] { return reader.done(); }, 4.0, "c: the peer's read did not finish");
  auto frames = peer.count_frames(reader.received());
  require(frames == kAnswers, "c: the peer got " + std::to_string(frames) + " frames, expected exactly 16");
  std::printf("REFUSAL_CLOSE_CASE late frames=%zu\n", frames);
}

// d. The peer half-closes right after its batch, then reads 0.3 s later.
void half_closed_peer_gets_every_answer() {
  Harness harness;
  Peer peer;
  auto observation = std::make_shared<Observation>();
  harness.open(peer, nullptr, nullptr, observation);
  peer.write(peer.script(kBatch));
  peer.shutdown_write();
  harness.wait_until([&] { return refused(observation); }, 5.0, "d: the refusal never came");
  harness.run_for(0.3);
  require(!closed(observation), "d: the connection closed before draining its answers");
  PeerReader reader(peer, 3000);
  harness.wait_until([&] { return reader.done() && closed(observation); }, 4.0,
                     "d: the answers were not drained and the connection closed");
  require(reader.eof(), "d: the peer got no end of file after the answers");
  auto frames = peer.count_frames(reader.received());
  auto detail = locked(observation, [](Observation& s) {
    return " (dispatched " + std::to_string(s.dispatched) + ", answered " + std::to_string(s.answered) + ", closed " +
           std::to_string(s.closed_at - s.refused_at) + " s after the refusal)";
  });
  require(frames == kAnswers, "d: the peer got " + std::to_string(frames) + " answers, expected 16" + detail);
  std::printf("REFUSAL_CLOSE_CASE half-closed frames=%zu\n", frames);
}

// e. Two complete queries arrive in the same read that then reports a reset.
void frames_before_a_reset_are_delivered() {
  Harness harness;
  Peer peer;
  auto observation = std::make_shared<Observation>();
  auto transport = std::make_shared<PausableTransport>(false);
  auto reader = std::make_shared<ScriptedReader>(peer.script(2));
  harness.open(peer, transport, reader, observation);
  peer.write("x");  // makes the socket readable; the scripted reader supplies the bytes
  harness.wait_until([&] { return closed(observation); }, 3.0, "e: the reset did not close the connection");
  auto dispatched = locked(observation, [](Observation& s) { return s.dispatched; });
  require(dispatched == 2, "e: " + std::to_string(dispatched) + " of the 2 queries before the reset were delivered");
  std::printf("REFUSAL_CLOSE_CASE reset dispatched=%zu\n", dispatched);
}

// Cases f and g: a real external server, a raw client.

// Queries answered at once before the refusal; with the late query they fill
// the connection's 64-query rate window, so the next query is refused.
constexpr size_t kPromptQueries = 63;
// Large enough that the prompt answers together (4 MiB) cannot all sit in
// the kernel's socket buffers while the client is not reading: most of them
// wait in the connection's own output buffer, which a stop() would drop.
constexpr size_t kPromptAnswerBytes = 64 << 10;
// The server's per-source in-flight query limit.
constexpr size_t kSourceInflight = 256;
constexpr size_t kConnectionInflight = 32;

// Counts every failure answer the server encoded, per kind. The server encodes
// only after both the per-connection and the shared failure-reply allowance
// granted the answer, so these counts are exactly the allowance it spent.
// Refuses to encode the rate-limit kind, which turns that refusal into the
// ordered close the cases need while every other refusal stays answerable.
class CountingEncoder final : public adnl::ExtQueryFailureEncoder {
 public:
  td::Result<td::BufferSlice> encode(const adnl::ExtQueryFailure& failure) const override {
    calls_[static_cast<size_t>(failure.kind)].fetch_add(1, std::memory_order_acq_rel);
    if (failure.kind == adnl::ExtQueryFailureKind::PerConnectionRateLimit) {
      return td::Status::Error("rate-limit refusals close the connection in this test");
    }
    return td::BufferSlice{std::string("refused:") + adnl::ext_query_failure_kind_name(failure.kind)};
  }
  size_t calls(adnl::ExtQueryFailureKind kind) const {
    return calls_[static_cast<size_t>(kind)].load(std::memory_order_acquire);
  }

 private:
  mutable std::array<std::atomic<size_t>, static_cast<size_t>(adnl::ExtQueryFailureKind::ResponseTooLarge) + 1>
      calls_{};
};

// Requests starting with "hold" or "late" are held until the test completes
// them; every other request is answered at once with a kPromptAnswerBytes
// payload that starts with the request.
struct ServiceState {
  std::mutex mutex;
  size_t delivered = 0;
  std::vector<std::pair<std::string, td::Promise<td::BufferSlice>>> held;
};

std::string prompt_answer(const std::string& request) {
  std::string answer = "answer:" + request;
  answer.resize(kPromptAnswerBytes, '.');
  return answer;
}

class Service final : public adnl::Adnl::Callback {
 public:
  explicit Service(std::shared_ptr<ServiceState> state) : state_(std::move(state)) {
  }
  void receive_message(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice) override {
  }
  void receive_query(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    std::string request = data.as_slice().str();
    {
      std::lock_guard lock(state_->mutex);
      state_->delivered++;
      if (request.rfind("hold", 0) == 0 || request.rfind("late", 0) == 0) {
        state_->held.emplace_back(std::move(request), std::move(promise));
        return;
      }
    }
    promise.set_value(td::BufferSlice{prompt_answer(request)});
  }

 private:
  std::shared_ptr<ServiceState> state_;
};

td::uint16 free_tcp_port() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  require(fd >= 0, "cannot open a TCP socket");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t size = sizeof(address);
  bool ok = ::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
            ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) == 0;
  ::close(fd);
  require(ok, "cannot reserve a TCP port");
  return ntohs(address.sin_port);
}

class ServerHarness {
 public:
  explicit ServerHarness(const std::string& name)
      : scheduler_(std::vector<td::actor::Scheduler::NodeInfo>{2})
      , state_(std::make_shared<ServiceState>())
      , encoder_(std::make_shared<CountingEncoder>()) {
    port_ = free_tcp_port();
    db_root_ = "/tmp/tos-adnl-ext-refusal-close-" + std::to_string(::getpid()) + "-" + name;
    td::rmrf(db_root_).ignore();
    require(td::mkdir(db_root_).is_ok(), "cannot create the server's directory");
    start();
  }
  ~ServerHarness() {
    scheduler_.run_in_context([&] {
      std::lock_guard lock(state_->mutex);
      state_->held.clear();
      server_.reset();
      adnl_.reset();
      keyring_.reset();
    });
    scheduler_.run(0.2);
    scheduler_.stop();
    td::rmrf(db_root_).ignore();
  }
  ServerHarness(const ServerHarness&) = delete;
  ServerHarness& operator=(const ServerHarness&) = delete;

  td::uint16 port() const {
    return port_;
  }
  const adnl::AdnlNodeIdFull& id() const {
    return server_id_;
  }
  const CountingEncoder& encoder() const {
    return *encoder_;
  }
  size_t delivered() {
    std::lock_guard lock(state_->mutex);
    return state_->delivered;
  }
  // Held queries whose request starts with `prefix`.
  size_t held(const std::string& prefix) {
    std::lock_guard lock(state_->mutex);
    return std::count_if(state_->held.begin(), state_->held.end(),
                         [&](const auto& entry) { return entry.first.rfind(prefix, 0) == 0; });
  }
  // Completes every held query whose request starts with `prefix`: with an
  // answer, or with a service error.
  void complete_held(const std::string& prefix, bool success) {
    std::vector<std::pair<std::string, td::Promise<td::BufferSlice>>> taken;
    {
      std::lock_guard lock(state_->mutex);
      for (auto it = state_->held.begin(); it != state_->held.end();) {
        if (it->first.rfind(prefix, 0) == 0) {
          taken.push_back(std::move(*it));
          it = state_->held.erase(it);
        } else {
          ++it;
        }
      }
    }
    require(!taken.empty(), "no held query starts with " + prefix);
    scheduler_.run_in_context([&] {
      for (auto& [request, promise] : taken) {
        if (success) {
          promise.set_value(td::BufferSlice{"answer:" + request});
        } else {
          promise.set_error(td::Status::Error(ErrorCode::error, "service failed after the refusal"));
        }
      }
    });
  }
  template <class F>
  void wait_until(F&& done, double seconds, const std::string& what) {
    auto deadline = td::Timestamp::in(seconds);
    while (!done()) {
      scheduler_.run(0.01);
      if (deadline.is_in_past()) {
        fail(what);
      }
    }
  }
  void run_for(double seconds) {
    auto until = td::Timestamp::in(seconds);
    while (!until.is_in_past()) {
      scheduler_.run(0.01);
    }
  }

 private:
  void start() {
    auto private_key = PrivateKey{privkeys::Ed25519::random()};
    auto public_key = private_key.compute_public_key();
    server_id_ = adnl::AdnlNodeIdFull{public_key};
    adnl::AdnlNodeIdShort server_short{public_key.compute_short_id()};
    std::atomic<bool> key_ready{false};
    scheduler_.run_in_context([&] {
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
    scheduler_.run_in_context([&] {
      td::actor::send_closure(adnl_, &adnl::Adnl::add_id, server_id_, adnl::AdnlAddressList{},
                              static_cast<td::uint8>(0));
      td::actor::send_closure(adnl_, &adnl::Adnl::subscribe, server_short, std::string{},
                              std::make_unique<Service>(state_));
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
    std::atomic<bool> listening_ok{false};
    scheduler_.run_in_context([&] {
      td::actor::send_closure(server_, &adnl::AdnlExtServer::set_query_failure_encoder,
                              std::shared_ptr<const adnl::ExtQueryFailureEncoder>(encoder_));
      td::actor::send_closure(server_, &adnl::AdnlExtServer::wait_listening,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> result) {
                                listening_ok.store(result.is_ok(), std::memory_order_release);
                                listening.store(true, std::memory_order_release);
                              }));
    });
    wait_until([&] { return listening.load(std::memory_order_acquire); }, 10.0, "ext server listen timed out");
    require(listening_ok.load(std::memory_order_acquire), "ext server failed to listen");
  }

  td::actor::Scheduler scheduler_;
  std::shared_ptr<ServiceState> state_;
  std::shared_ptr<CountingEncoder> encoder_;
  td::uint16 port_ = 0;
  std::string db_root_;
  adnl::AdnlNodeIdFull server_id_;
  td::actor::ActorOwn<keyring::Keyring> keyring_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<adnl::AdnlExtServer> server_;
};

enum class ReadEnd { Eof, Reset, Timeout };

const char* read_end_name(ReadEnd end) {
  switch (end) {
    case ReadEnd::Eof:
      return "end of file";
    case ReadEnd::Reset:
      return "reset";
    case ReadEnd::Timeout:
      return "timeout";
  }
  return "unknown";
}

// An external client written against the wire format, not the client actor:
// it can leave answers unread, and it reports how the stream ended.
class RawClient {
 public:
  RawClient(td::uint16 port, const adnl::AdnlNodeIdFull& server) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    require(fd_ >= 0, "cannot open the client socket");
    // A small receive window, fixed before the handshake, keeps the server's
    // answers queued on the server side while this client is not reading.
    int small = 4096;
    require(::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) == 0, "SO_RCVBUF failed");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    require(::connect(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "client connect failed");

    // The init packet: the server's short id, then 160 bytes of key material
    // encrypted to the server's key.
    std::string material(160, '\0');
    td::Random::secure_bytes(td::MutableSlice(material));
    auto encryptor = server.pubkey().create_encryptor();
    require(encryptor.is_ok(), "cannot create an encryptor for the server key");
    auto encrypted = encryptor.ok()->encrypt(td::Slice(material));
    require(encrypted.is_ok() && encrypted.ok().size() == 224, "init packet encryption failed");
    init_ = server.compute_short_id().as_slice().str() + encrypted.ok().as_slice().str();
    td::Slice key(material);
    to_server_.init(key.substr(32, 32), key.substr(80, 16));
    from_server_.init(key.substr(0, 32), key.substr(64, 16));
  }
  ~RawClient() {
    close();
  }
  RawClient(const RawClient&) = delete;
  RawClient& operator=(const RawClient&) = delete;

  // The init packet; included once, ahead of the first queries written.
  std::string init() {
    return std::exchange(init_, std::string{});
  }
  // A query frame for `request`; remembers its id.
  std::string query(const std::string& request) {
    td::Bits256 query_id;
    td::Random::secure_bytes(query_id.as_slice());
    requests_[query_id.as_slice().str()] = request;
    auto message = create_tl_object<tos_api::adnl_message_query>(query_id, td::BufferSlice{request});
    return frame(serialize_tl_object(message, true).as_slice().str());
  }
  void write(const std::string& bytes) {
    size_t sent = 0;
    while (sent < bytes.size()) {
      auto n = ::send(fd_, bytes.data() + sent, bytes.size() - sent, MSG_NOSIGNAL);
      require(n > 0, "client write failed");
      sent += static_cast<size_t>(n);
    }
  }
  // One send that never blocks: the bytes taken, 0 if none fit, -1 on error.
  ssize_t try_write(td::Slice bytes) {
    auto n = ::send(fd_, bytes.data(), bytes.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return 0;
    }
    return n;
  }
  void shutdown_write() {
    require(::shutdown(fd_, SHUT_WR) == 0, "client shutdown failed");
  }
  ReadEnd read_to_end(int timeout_ms) {
    auto deadline = td::Timestamp::in(timeout_ms / 1000.0);
    char buf[16384];
    while (!deadline.is_in_past()) {
      pollfd pfd{fd_, POLLIN, 0};
      if (::poll(&pfd, 1, 50) <= 0) {
        continue;
      }
      auto n = ::recv(fd_, buf, sizeof(buf), MSG_DONTWAIT);
      if (n == 0) {
        return ReadEnd::Eof;
      }
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          continue;
        }
        return ReadEnd::Reset;
      }
      wire_.append(buf, static_cast<size_t>(n));
    }
    return ReadEnd::Timeout;
  }
  void close() {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }
  // Every complete answer received, as (request, answer bytes), in order.
  // Empty keepalive frames are skipped. `unfinished` is set to the bytes of a
  // frame the stream ended inside of, which a connection stopped mid-write
  // leaves behind.
  std::vector<std::pair<std::string, std::string>> answers(size_t& unfinished) {
    std::string plain(wire_.size(), '\0');
    from_server_.encrypt(td::Slice(wire_), td::MutableSlice(plain));
    std::vector<std::pair<std::string, std::string>> result;
    td::Slice rest(plain);
    unfinished = 0;
    while (!rest.empty()) {
      td::uint32 len = 0;
      if (rest.size() >= 4) {
        std::memcpy(&len, rest.data(), 4);
        require(len >= 64 && len <= adnl::adnl_ext_max_packet_bytes, "malformed frame length");
      }
      if (rest.size() < 4 || rest.size() - 4 < len) {
        unfinished = rest.size();
        break;
      }
      rest.remove_prefix(4);
      auto packet = rest.substr(0, len);
      rest.remove_prefix(len);
      require(td::sha256(packet.substr(0, len - 32)) == packet.substr(len - 32).str(), "frame checksum mismatch");
      auto body = packet.substr(32, len - 64);
      if (body.empty()) {
        continue;
      }
      auto answer = fetch_tl_object<tos_api::adnl_message_answer>(td::BufferSlice{body}, true);
      require(answer.is_ok(), "a server frame is not an answer");
      auto it = requests_.find(answer.ok()->query_id_.as_slice().str());
      require(it != requests_.end(), "an answer for a query id this client never sent");
      result.emplace_back(it->second, answer.ok()->answer_.as_slice().str());
    }
    return result;
  }

 private:
  std::string frame(const std::string& payload) {
    std::string body(32, '\0');
    td::Random::secure_bytes(td::MutableSlice(body));
    body += payload;
    body += td::sha256(body);
    td::uint32 len = static_cast<td::uint32>(body.size());
    std::string plain(4, '\0');
    std::memcpy(plain.data(), &len, 4);
    plain += body;
    std::string wire(plain.size(), '\0');
    to_server_.encrypt(td::Slice(plain), td::MutableSlice(wire));
    return wire;
  }

  int fd_ = -1;
  std::string init_;
  td::AesCtrState to_server_;
  td::AesCtrState from_server_;
  std::map<std::string, std::string> requests_;
  std::string wire_;
};

// The peer sends a query the service completes late, then queries answered at
// once, and leaves the answers unread; its next query is refused with a close.
// The late query then completes, with a result or with an error, while the
// connection is closing.
void late_completion_during_close(bool success) {
  const std::string tag = success ? "f" : "g";
  using Kind = adnl::ExtQueryFailureKind;
  ServerHarness server(success ? "late-success" : "late-error");
  {
    RawClient client(server.port(), server.id());
    // Batches of 16 stay under the 32-query in-flight limit, so the only
    // refusal is the rate window's, which needs all 65 queries in one second.
    std::string batch = client.init() + client.query("late");
    double started = 0;
    for (size_t i = 0; i < kPromptQueries; i++) {
      batch += client.query("prompt#" + std::to_string(i));
      if ((i + 2) % 16 != 0 && i + 1 != kPromptQueries) {
        continue;
      }
      if (started == 0) {
        started = td::Time::now();
      }
      client.write(std::exchange(batch, std::string{}));
      server.wait_until([&] { return server.delivered() == i + 2; }, 2.0,
                        tag + ": the service did not receive a batch");
      // Let this batch's answers reach the connection's output, freeing their
      // in-flight slots, before the next batch.
      server.run_for(0.05);
    }
    server.run_for(0.1);
    require(td::Time::now() - started < 0.85, tag + ": the 64 accepted queries did not fit one rate window");
    client.write(client.query("refused"));
    server.wait_until([&] { return server.encoder().calls(Kind::PerConnectionRateLimit) == 1; }, 2.0,
                      tag + ": the query past the rate window was not refused");
    server.run_for(0.05);
    server.complete_held("late", success);
    server.run_for(0.2);

    // The late completion spent no failure-reply allowance: no failure answer
    // was encoded for it.
    auto too_large = server.encoder().calls(Kind::ResponseTooLarge);
    auto handler_error = server.encoder().calls(Kind::HandlerError);
    require(too_large == 0 && handler_error == 0,
            tag + ": the late completion spent the failure-reply allowance (response_too_large=" +
                std::to_string(too_large) + " handler_error=" + std::to_string(handler_error) + ")");

    std::atomic<bool> read_done{false};
    ReadEnd end = ReadEnd::Timeout;
    std::thread reader([&] {
      end = client.read_to_end(3000);
      read_done.store(true, std::memory_order_release);
    });
    server.wait_until([&] { return read_done.load(std::memory_order_acquire); }, 4.0,
                      tag + ": the client's read did not finish");
    reader.join();
    size_t unfinished = 0;
    auto answers = client.answers(unfinished);
    size_t prompt = 0;
    for (auto& [request, answer] : answers) {
      require(request != "late", tag + ": the late result reached the peer");
      require(request != "refused", tag + ": the refused query was answered");
      require(answer == prompt_answer(request), tag + ": answer bytes differ for " + request);
      prompt++;
    }
    require(prompt == kPromptQueries,
            tag + ": the peer got " + std::to_string(prompt) + " of the " + std::to_string(kPromptQueries) +
                " answers queued before the refusal; the stream ended by " + read_end_name(end) + " after " +
                std::to_string(unfinished) + " bytes of an unfinished frame");
    require(end == ReadEnd::Eof,
            tag + ": the stream ended by " + std::string(read_end_name(end)) + ", not by end of file");
    require(unfinished == 0, tag + ": the stream ended inside a frame");
    client.close();
  }

  // The late query's server-wide in-flight slot was given back: one source can
  // again hold the whole per-source limit, across fresh connections.
  std::vector<std::unique_ptr<RawClient>> clients;
  for (size_t c = 0; c < kSourceInflight / kConnectionInflight; c++) {
    clients.push_back(std::make_unique<RawClient>(server.port(), server.id()));
    std::string batch = clients.back()->init();
    for (size_t i = 0; i < kConnectionInflight; i++) {
      batch += clients.back()->query("hold#" + std::to_string(c) + "#" + std::to_string(i));
    }
    clients.back()->write(batch);
  }
  server.wait_until(
      [&] { return server.held("hold") == kSourceInflight || server.encoder().calls(Kind::PerIpInflightLimit) > 0; },
      5.0, tag + ": the service did not receive the in-flight queries");
  require(server.held("hold") == kSourceInflight && server.encoder().calls(Kind::PerIpInflightLimit) == 0,
          tag + ": the source could not hold its full in-flight limit after the late completion (held " +
              std::to_string(server.held("hold")) + " of " + std::to_string(kSourceInflight) + ")");
  require(server.encoder().calls(Kind::ServerInflightLimit) == 0,
          tag + ": a query within the server limit was refused");
  server.complete_held("hold", true);
  server.run_for(0.1);
  std::printf("REFUSAL_CLOSE_CASE late-%s prompt_answers=%zu end=eof allowance_spent=0 inflight_reusable=%zu\n",
              success ? "success" : "error", kPromptQueries, kSourceInflight);
}

// h. The peer's queries are answered and left unread, its next query is
// refused with a close, and it then sends far more than one discard chunk and
// half-closes. The closing connection must consume all of it before closing:
// input left unread at close makes the kernel reset the connection, which
// drops the answers still queued for the peer.
constexpr size_t kSurplusBytes = 512 << 10;
// What one closing pass reads at most; the surplus spans several of them.
constexpr size_t kDiscardChunkBytes = 64 << 10;
// The connection's closing deadline, from the refusal.
constexpr double kClosingSeconds = 2.0;
// Answered queries before the refusal: they fill the 64-query rate window.
constexpr size_t kSurplusCaseQueries = 64;

void half_close_after_surplus() {
  using Kind = adnl::ExtQueryFailureKind;
  ServerHarness server("half-close-after-surplus");
  RawClient client(server.port(), server.id());
  std::string batch = client.init();
  double started = 0;
  for (size_t i = 0; i < kSurplusCaseQueries; i++) {
    batch += client.query("prompt#" + std::to_string(i));
    if ((i + 1) % 16 != 0) {
      continue;
    }
    if (started == 0) {
      started = td::Time::now();
    }
    client.write(std::exchange(batch, std::string{}));
    server.wait_until([&] { return server.delivered() == i + 1; }, 2.0, "h: the service did not receive a batch");
    server.run_for(0.05);
  }
  server.run_for(0.1);
  require(td::Time::now() - started < 0.85, "h: the 64 accepted queries did not fit one rate window");
  client.write(client.query("refused"));
  server.wait_until([&] { return server.encoder().calls(Kind::PerConnectionRateLimit) == 1; }, 2.0,
                    "h: the query past the rate window was not refused");
  auto refused_at = td::Time::now();
  auto& totals = adnl::adnl_ext_closing_discard_totals();
  auto passes_before = totals.passes.load();
  auto bytes_before = totals.bytes.load();
  auto after_close_before = totals.bytes_after_peer_close.load();

  // The surplus goes out while the server is not running, so as much of it
  // as the kernels hold is queued together with the half-close. Whatever does
  // not fit is sent while the server runs, never with a blocking send.
  std::string surplus(kSurplusBytes, '\0');
  td::Random::secure_bytes(td::MutableSlice(surplus));
  size_t queued_unscheduled = 0;
  size_t sent = 0;
  bool pumped = false;
  auto write_deadline = td::Timestamp::in(1.0);
  while (sent < surplus.size()) {
    auto n = client.try_write(td::Slice(surplus).substr(sent));
    require(n >= 0, "h: the client's surplus write failed");
    sent += static_cast<size_t>(n);
    if (!pumped) {
      queued_unscheduled = sent;
    }
    if (sent < surplus.size()) {
      require(!write_deadline.is_in_past(), "h: the server did not take the surplus within 1 s (" +
                                                std::to_string(sent) + " of " + std::to_string(surplus.size()) +
                                                " bytes sent)");
      server.run_for(0.01);
      pumped = true;
    }
  }
  client.shutdown_write();
  // Let the kernel deliver the queued bytes and the half-close before the
  // server's next pass.
  td::usleep_for(50000);

  std::atomic<bool> read_done{false};
  ReadEnd end = ReadEnd::Timeout;
  double ended_at = 0;
  std::thread reader([&] {
    end = client.read_to_end(3000);
    ended_at = td::Time::now();
    read_done.store(true, std::memory_order_release);
  });
  server.wait_until([&] { return read_done.load(std::memory_order_acquire); }, 4.0,
                    "h: the client's read did not finish");
  reader.join();
  size_t unfinished = 0;
  auto answers = client.answers(unfinished);
  size_t prompt = 0;
  for (auto& [request, answer] : answers) {
    require(request != "refused", "h: the refused query was answered");
    require(answer == prompt_answer(request), "h: answer bytes differ for " + request);
    prompt++;
  }
  require(prompt == kSurplusCaseQueries,
          "h: the peer got " + std::to_string(prompt) + " of the " + std::to_string(kSurplusCaseQueries) +
              " answers queued before the refusal; the stream ended by " + read_end_name(end) + " after " +
              std::to_string(unfinished) + " bytes of an unfinished frame");
  require(end == ReadEnd::Eof, "h: the stream ended by " + std::string(read_end_name(end)) + ", not by end of file");
  require(unfinished == 0, "h: the stream ended inside a frame");
  auto took = ended_at - refused_at;
  require(took <= kClosingSeconds + 0.25,
          "h: end of file came " + std::to_string(took) + " s after the refusal, past the closing deadline");

  // Evidence that the case exercised what it is about: the surplus was
  // consumed over several passes, and more than one chunk of it was still
  // queued when the peer's half-close was already known.
  auto passes = totals.passes.load() - passes_before;
  auto discarded = totals.bytes.load() - bytes_before;
  auto after_close = totals.bytes_after_peer_close.load() - after_close_before;
  require(discarded >= kSurplusBytes,
          "h: the close discarded " + std::to_string(discarded) + " bytes, less than the surplus");
  require(passes > 1, "h: the surplus was discarded in " + std::to_string(passes) + " pass(es)");
  require(after_close > kDiscardChunkBytes, "h: only " + std::to_string(after_close) +
                                                " bytes were left to discard once the half-close was known;"
                                                " the case did not queue the surplus together with it");
  client.close();
  std::printf(
      "REFUSAL_CLOSE_CASE half-close-after-surplus prompt_answers=%zu end=eof closed_after=%.2fs "
      "surplus=%zu queued_before_server_ran=%zu discard_passes=%llu discarded=%llu "
      "discarded_after_half_close=%llu\n",
      prompt, took, kSurplusBytes, queued_unscheduled, static_cast<unsigned long long>(passes),
      static_cast<unsigned long long>(discarded), static_cast<unsigned long long>(after_close));
}

void late_success_during_close() {
  late_completion_during_close(true);
}

void late_error_during_close() {
  late_completion_during_close(false);
}

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(WARNING));
  const std::string only = argc > 1 ? argv[1] : "all";
  const std::vector<std::pair<std::string, void (*)()>> cases = {
      {"paused", paused_peer_gets_every_answer},      {"silent", silent_peer_is_released_by_the_deadline},
      {"late", late_answer_is_not_written},           {"half-closed", half_closed_peer_gets_every_answer},
      {"reset", frames_before_a_reset_are_delivered}, {"late-success", late_success_during_close},
      {"late-error", late_error_during_close},        {"half-close-after-surplus", half_close_after_surplus},
  };
  bool ran = false;
  for (auto& [name, run] : cases) {
    if (only == "all" || only == name) {
      run();
      ran = true;
    }
  }
  require(ran, "unknown case: " + only);
  std::printf("ADNL_EXT_REFUSAL_CLOSE_TESTS passed=%s\n", only.c_str());
  return 0;
}
