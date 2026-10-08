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
//      still closes the connection.
// Cases a, b, c and d run the real connection actor over a real socket pair
// with small kernel buffers, so answers queue in the connection itself while
// the peer is not reading. Case e scripts the input side, so "bytes, then an
// error" in one read is deterministic.
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "adnl/adnl-ext-connection.hpp"
#include "common/errorcode.h"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/Time.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/port/detail/NativeFd.h"

namespace {

using namespace tos;

constexpr size_t kPayload = 932;
constexpr size_t kFrame = kPayload + 4 + 32 + 32;
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

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(WARNING));
  const std::string only = argc > 1 ? argv[1] : "all";
  const std::vector<std::pair<std::string, void (*)()>> cases = {
      {"paused", paused_peer_gets_every_answer},      {"silent", silent_peer_is_released_by_the_deadline},
      {"late", late_answer_is_not_written},           {"half-closed", half_closed_peer_gets_every_answer},
      {"reset", frames_before_a_reset_are_delivered},
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
