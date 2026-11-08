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
//   i. a peer whose half-close is known while more than one discard chunk of
//      its input is unread has all of it read, over several closing passes,
//      before the connection shuts its write side and stops.
// Cases a, b, c, d and i run the real connection actor over a real socket
// pair with small kernel buffers, so answers queue in the connection itself
// while the peer is not reading. Cases e and i script the input side, so
// "bytes, then an error" in one read, and "half-close known, input still
// queued", are deterministic.
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

// Input scripted for one connection: the bytes in `bytes`, each read taking
// no more than the connection asks for, then `end`: a reset, or the end of the
// stream, which a socket whose peer has half-closed reports as a read of 0.
class ScriptedReader final : public adnl::AdnlExtTransportReader {
 public:
  enum class End { Reset, EndOfStream };
  explicit ScriptedReader(std::string bytes, End end = End::Reset) : bytes_(std::move(bytes)), end_(end) {
  }
  td::Result<size_t> read(td::MutableSlice slice) override {
    reads_.fetch_add(1, std::memory_order_acq_rel);
    if (offset_ < bytes_.size()) {
      auto n = std::min(slice.size(), bytes_.size() - offset_);
      std::memcpy(slice.data(), bytes_.data() + offset_, n);
      offset_ += n;
      consumed_.store(offset_, std::memory_order_release);
      return n;
    }
    if (end_ == End::Reset) {
      return td::Status::PosixError(ECONNRESET, "scripted reset");
    }
    end_reads_.fetch_add(1, std::memory_order_acq_rel);
    return 0;
  }
  size_t size() const {
    return bytes_.size();
  }
  // Bytes the connection has taken.
  size_t consumed() const {
    return consumed_.load(std::memory_order_acquire);
  }
  // Read calls, and those that found the end of the stream.
  size_t reads() const {
    return reads_.load(std::memory_order_acquire);
  }
  size_t end_reads() const {
    return end_reads_.load(std::memory_order_acquire);
  }

 private:
  std::string bytes_;
  End end_;
  size_t offset_ = 0;
  std::atomic<size_t> consumed_{0};
  std::atomic<size_t> reads_{0};
  std::atomic<size_t> end_reads_{0};
};

struct Observation {
  std::mutex mutex;
  size_t dispatched = 0;
  size_t answered = 0;
  bool closed = false;
  double refused_at = 0;
  double closed_at = 0;
  int late_sent = -1;
  // When set, how much of it the connection had taken when it refused.
  std::shared_ptr<ScriptedReader> input;
  size_t consumed_at_refusal = 0;
};

// The real connection actor with a minimal protocol: the init packet is the
// key material, every query is answered with a kPayload frame until kAnswers
// have been sent, and the next query is refused with a close.
class RefusingConnection final : public adnl::AdnlExtConnection {
 public:
  RefusingConnection(td::SocketFd fd, std::shared_ptr<adnl::AdnlExtTransportWriter> writer,
                     std::shared_ptr<adnl::AdnlExtTransportReader> reader, std::shared_ptr<Observation> observation,
                     std::shared_ptr<adnl::AdnlExtByteBudget> input_budget)
      : AdnlExtConnection(std::move(fd), nullptr, false), observation_(std::move(observation)) {
    if (writer) {
      set_transport_writer(std::move(writer));
    }
    if (reader) {
      set_transport_reader(std::move(reader));
    }
    if (input_budget) {
      // Reads in bounded chunks, as a server connection does, so input behind
      // the refused query is left for the closing sequence.
      set_input_limits(std::move(input_budget));
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
    if (observation_->input) {
      observation_->consumed_at_refusal = observation_->input->consumed();
    }
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
            std::shared_ptr<adnl::AdnlExtTransportReader> reader, std::shared_ptr<Observation> observation,
            std::shared_ptr<adnl::AdnlExtByteBudget> input_budget = nullptr) {
    auto fd = peer.take_server_end();
    scheduler_.run_in_context([&] {
      connection_ = td::actor::create_actor<RefusingConnection>(
          td::actor::ActorOptions().with_name("refusing").with_poll(), std::move(fd), std::move(writer),
          std::move(reader), std::move(observation), std::move(input_budget));
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

// What one closing pass reads at most.
constexpr size_t kDiscardChunkBytes = 64 << 10;
// The connection's closing deadline, from the refusal.
constexpr double kClosingSeconds = 2.0;

// i. The peer's half-close is known before the close begins, while more than
// one discard chunk of its input is still unread. The closing connection must
// keep reading over several passes, each bounded by its allowance, write every
// queued answer, and only then shut its write side and stop.
constexpr size_t kQueuedSurplusBytes = 5 * kDiscardChunkBytes + 1000;
// The input budget of the connection; large enough never to limit a read.
constexpr size_t kInputBudgetBytes = 1 << 20;

void drain_after_half_close_is_known() {
  Harness harness;
  Peer peer;
  auto observation = std::make_shared<Observation>();
  // Every byte the peer sent comes from the script; the socket itself
  // carries only the peer's half-close, so the poll layer reports the socket
  // readable and closed before the connection's first pass, with nothing in
  // the kernel's queue.
  auto input = std::make_shared<ScriptedReader>(peer.script(kAnswers + 1) + std::string(kQueuedSurplusBytes, '\0'),
                                                ScriptedReader::End::EndOfStream);
  observation->input = input;
  peer.shutdown_write();
  auto& totals = adnl::adnl_ext_closing_discard_totals();
  auto passes_before = totals.passes.load();
  auto bytes_before = totals.bytes.load();
  auto after_close_before = totals.bytes_after_peer_close.load();
  harness.open(peer, nullptr, input, observation, std::make_shared<adnl::AdnlExtByteBudget>(kInputBudgetBytes));
  harness.wait_until([&] { return refused(observation); }, 2.0, "i: the refusal never came");
  auto unread_at_refusal = input->size() - locked(observation, [](Observation& s) { return s.consumed_at_refusal; });
  require(unread_at_refusal > kDiscardChunkBytes, "i: only " + std::to_string(unread_at_refusal) +
                                                      " bytes were unread at the refusal, not more than one chunk");

  // The peer reads nothing yet, so the answers stay queued while the
  // connection drains its input. The wait ends either way: the input is read
  // to its end, or the connection stops, at the latest at its deadline.
  harness.wait_until(
      [&] { return (input->consumed() == input->size() && input->end_reads() > 0) || closed(observation); }, 4.0,
      "i: the connection neither read its input to the end nor stopped");
  require(input->consumed() == input->size(),
          "i: the connection stopped with " + std::to_string(input->size() - input->consumed()) +
              " bytes of the peer's input unread (" + std::to_string(input->consumed()) + " of " +
              std::to_string(input->size()) + " taken)");
  require(!closed(observation), "i: the connection stopped before its answers were read");
  auto passes = totals.passes.load() - passes_before;
  auto discarded = totals.bytes.load() - bytes_before;
  auto after_close = totals.bytes_after_peer_close.load() - after_close_before;
  require(discarded == unread_at_refusal, "i: the closing passes read " + std::to_string(discarded) + " bytes, but " +
                                              std::to_string(unread_at_refusal) + " were unread at the refusal");
  require(after_close == discarded, "i: a closing pass began before the half-close was known (" +
                                        std::to_string(after_close) + " of " + std::to_string(discarded) + " bytes)");
  require(passes > 1, "i: the input was drained in " + std::to_string(passes) + " pass(es)");

  PeerReader reader(peer, 3000);
  harness.wait_until([&] { return reader.done() && closed(observation); }, 4.0,
                     "i: the answers were not drained and the connection closed");
  require(reader.eof(), "i: the peer got no end of file after the answers");
  auto frames = peer.count_frames(reader.received());
  require(frames == kAnswers, "i: the peer got " + std::to_string(frames) + " answers, expected 16");
  auto held = locked(observation, [](Observation& s) { return s.closed_at - s.refused_at; });
  require(held < kClosingSeconds,
          "i: the connection was stopped by its deadline, " + std::to_string(held) + " s after the refusal");
  std::printf(
      "REFUSAL_CLOSE_CASE drain-after-half-close frames=%zu unread_at_refusal=%zu discard_passes=%llu "
      "discarded=%llu reads=%zu closed_after=%.2fs\n",
      frames, unread_at_refusal, static_cast<unsigned long long>(passes), static_cast<unsigned long long>(discarded),
      input->reads(), held);
}

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(WARNING));
  const std::string only = argc > 1 ? argv[1] : "all";
  const std::vector<std::pair<std::string, void (*)()>> cases = {
      {"paused", paused_peer_gets_every_answer},      {"silent", silent_peer_is_released_by_the_deadline},
      {"late", late_answer_is_not_written},           {"half-closed", half_closed_peer_gets_every_answer},
      {"reset", frames_before_a_reset_are_delivered}, {"drain-after-half-close", drain_after_half_close_is_known},
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
