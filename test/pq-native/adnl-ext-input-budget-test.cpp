/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// What an ADNL external server connection may hold of frames it has not finished
// receiving: a per-connection bound, a budget shared by the server's connections
// that is reserved before the buffer grows, an absolute lifetime for an unfinished
// frame, and every reservation returned when the connection closes for any reason.
//
// The real connection actor and BufferedFd run over a socketpair. The peer is
// this test, writing a fixed handful of bytes; nothing floods. Budgets are small
// and injected, so each bound is reached with kilobytes.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "adnl/adnl-ext-connection.hpp"
#include "adnl/adnl-ext-limits.h"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/Time.h"
#include "td/utils/buffer.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/port/detail/NativeFd.h"

namespace {

using namespace tos;

[[noreturn]] void fail(const std::string& message) {
  std::fflush(stdout);
  std::fprintf(stderr, "ADNL_EXT_INPUT_BUDGET_FAILURE: %s\n", message.c_str());
  std::fflush(stderr);
  std::_Exit(1);
}

void require(bool condition, const std::string& message) {
  if (!condition) {
    fail(message);
  }
}

struct Probe {
  size_t packets = 0;
  size_t last_payload = 0;
  bool closed = false;
};

class TestConnection final : public adnl::AdnlExtConnection {
 public:
  TestConnection(td::SocketFd fd, std::shared_ptr<Probe> probe, std::shared_ptr<adnl::AdnlExtByteBudget> budget,
                 size_t max_pending, double lifetime)
      : AdnlExtConnection(std::move(fd), nullptr, false), probe_(std::move(probe)) {
    set_input_limits(std::move(budget), max_pending, lifetime);
  }
  td::Status process_packet(td::BufferSlice data) override {
    probe_->packets++;
    probe_->last_payload = data.size();
    return td::Status::OK();
  }
  td::Status process_custom_packet(td::BufferSlice& data, bool& processed) override {
    processed = false;
    return td::Status::OK();
  }
  td::Status process_init_packet(td::BufferSlice data) override {
    return init_crypto(data.as_slice());
  }

 protected:
  void tear_down() override {
    AdnlExtConnection::tear_down();
    probe_->closed = true;
  }

 private:
  std::shared_ptr<Probe> probe_;
};

// The peer side: writes the init block and encrypted frames by hand.
class Peer {
 public:
  explicit Peer(int fd) : fd_(fd) {
    td::SecureString init(256);
    td::Random::secure_bytes(init.as_mutable_slice());
    // The server decrypts its input with the second key and IV of the block.
    td::SecureString key(32);
    td::SecureString iv(16);
    key.as_mutable_slice().copy_from(init.as_slice().substr(32, 32));
    iv.as_mutable_slice().copy_from(init.as_slice().substr(80, 16));
    out_.init(key, iv);
    write_raw(init.as_slice());
  }
  ~Peer() {
    close();
  }
  Peer(const Peer&) = delete;
  Peer& operator=(const Peer&) = delete;

  // The encrypted bytes of a frame carrying `payload_size` bytes.
  std::string frame(size_t payload_size) {
    td::uint32 len = static_cast<td::uint32>(payload_size + adnl::adnl_ext_packet_framing_bytes);
    std::string plain(4 + len, '\0');
    std::memcpy(plain.data(), &len, 4);
    td::MutableSlice body(plain.data() + 4, len);
    td::Random::secure_bytes(body.substr(0, 32 + payload_size));
    td::sha256(body.substr(0, 32 + payload_size), body.substr(32 + payload_size, 32));
    return encrypt(plain);
  }
  // The encrypted length prefix of a frame announcing `packet_bytes`.
  std::string header(td::uint32 packet_bytes) {
    std::string plain(4, '\0');
    std::memcpy(plain.data(), &packet_bytes, 4);
    return encrypt(plain);
  }
  void write(td::Slice bytes) {
    write_raw(bytes);
  }
  void close() {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

 private:
  std::string encrypt(const std::string& plain) {
    std::string out(plain.size(), '\0');
    out_.encrypt(td::Slice(plain), td::MutableSlice(out));
    return out;
  }
  void write_raw(td::Slice bytes) {
    while (!bytes.empty()) {
      auto n = ::send(fd_, bytes.data(), bytes.size(), MSG_NOSIGNAL);
      require(n > 0, "peer write failed");
      bytes.remove_prefix(static_cast<size_t>(n));
    }
  }
  int fd_;
  td::AesCtrState out_;
};

class Harness {
 public:
  explicit Harness(size_t budget_bytes) : budget_(std::make_shared<adnl::AdnlExtByteBudget>(budget_bytes)) {
    scheduler_ = std::make_unique<td::actor::Scheduler>(std::vector<td::actor::Scheduler::NodeInfo>{1});
  }
  ~Harness() {
    scheduler_->run_in_context([&] { connections_.clear(); });
    scheduler_->run(0.1);
    scheduler_->stop();
  }
  Harness(const Harness&) = delete;
  Harness& operator=(const Harness&) = delete;

  struct Opened {
    std::unique_ptr<Peer> peer;
    std::shared_ptr<Probe> probe;
  };

  Opened open(size_t max_pending, double lifetime) {
    int fds[2];
    require(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair failed");
    auto socket = td::SocketFd::from_native_fd(td::NativeFd(fds[0]));
    require(socket.is_ok(), "cannot wrap the server end");
    auto probe = std::make_shared<Probe>();
    scheduler_->run_in_context([&] {
      connections_.push_back(
          td::actor::create_actor<TestConnection>(td::actor::ActorOptions().with_name("inconn").with_poll(),
                                                  socket.move_as_ok(), probe, budget_, max_pending, lifetime));
    });
    return Opened{std::make_unique<Peer>(fds[1]), probe};
  }

  adnl::AdnlExtByteBudget& budget() {
    return *budget_;
  }

  // Runs the scheduler until `done` holds, checking after every step that the
  // shared budget never passed its limit.
  template <class F>
  void wait_until(F&& done, double bound_s, const std::string& what) {
    auto deadline = td::Timestamp::in(bound_s);
    while (!done()) {
      scheduler_->run(0.005);
      require(budget_->used() <= budget_->limit(), "shared input budget exceeded its limit");
      if (deadline.is_in_past()) {
        fail(what);
      }
    }
  }
  void pump(double seconds) {
    auto until = td::Timestamp::in(seconds);
    while (!until.is_in_past()) {
      scheduler_->run(0.005);
      require(budget_->used() <= budget_->limit(), "shared input budget exceeded its limit");
    }
  }

 private:
  std::shared_ptr<adnl::AdnlExtByteBudget> budget_;
  std::unique_ptr<td::actor::Scheduler> scheduler_;
  std::vector<td::actor::ActorOwn<TestConnection>> connections_;
};

constexpr double kLongLifetime = 60.0;

// An unfinished frame is held, and charged, byte for byte; finishing it hands
// the packet on and returns the reservation. Also measures what holding costs.
void holds_and_returns() {
  Harness h(1 << 20);
  auto c = h.open(128 << 10, kLongLifetime);
  const size_t payload = 100000;
  auto frame = c.peer->frame(payload);
  const size_t first = 50000;
  // Let the connection start and take the init block before the baseline.
  h.pump(0.05);
  auto memory_before = td::BufferAllocator::get_buffer_mem();
  c.peer->write(td::Slice(frame).substr(0, first));
  // The four length bytes are taken off the buffer when the length is parsed.
  h.wait_until([&] { return h.budget().used() == first - 4; }, 5.0, "unfinished frame not held as reserved");
  auto memory_held = td::BufferAllocator::get_buffer_mem() - memory_before;
  std::printf("ADNL_EXT_INPUT_MEASURE held_bytes=%zu buffer_bytes=%zu\n", first - 4, memory_held);
  require(memory_held <= (first - 4) + (first - 4) / 10 + (8 << 10), "holding costs more buffer than it is charged");
  h.pump(0.05);
  require(c.probe->packets == 0 && !c.probe->closed, "an unfinished frame was dispatched or closed");
  c.peer->write(td::Slice(frame).substr(first));
  h.wait_until([&] { return c.probe->packets == 1; }, 5.0, "finished frame not dispatched");
  require(c.probe->last_payload == payload, "dispatched payload has the wrong size");
  h.wait_until([&] { return h.budget().used() == 0; }, 5.0, "finished frame did not return its reservation");
  // Several frames in one write are all taken, and nothing stays charged.
  std::string batch;
  for (int i = 0; i < 4; i++) {
    batch += c.peer->frame(30000);
  }
  c.peer->write(batch);
  h.wait_until([&] { return c.probe->packets == 5; }, 5.0, "pipelined frames not dispatched");
  h.wait_until([&] { return h.budget().used() == 0; }, 5.0, "pipelined frames left a reservation behind");
  require(!c.probe->closed, "a connection within its bounds was closed");
  std::printf("ADNL_EXT_INPUT_CASE holds_and_returns ok\n");
}

// A frame larger than the connection may hold is refused at its length, before
// any of it is read; one that just fits is accepted.
void per_connection_bound() {
  Harness h(1 << 20);
  const size_t max_pending = 64 << 10;
  auto fits = h.open(max_pending, kLongLifetime);
  auto largest_payload = max_pending - 4 - adnl::adnl_ext_packet_framing_bytes;
  fits.peer->write(fits.peer->frame(largest_payload));
  h.wait_until([&] { return fits.probe->packets == 1; }, 5.0, "a frame of exactly the bound was refused");

  auto over = h.open(max_pending, kLongLifetime);
  // One write: the server may close as soon as it parses the length.
  over.peer->write(over.peer->header(static_cast<td::uint32>(max_pending - 4 + 1)) + std::string(1000, 'x'));
  h.wait_until([&] { return over.probe->closed; }, 5.0, "a frame over the per-connection bound was not refused");
  require(over.probe->packets == 0, "an over-bound frame was dispatched");
  h.wait_until([&] { return h.budget().used() == 0; }, 5.0, "refused connection kept its reservation");
  require(!fits.probe->closed, "refusing one connection closed another");
  std::printf("ADNL_EXT_INPUT_CASE per_connection_bound ok\n");
}

// The shared budget bounds what all connections hold together. The connection
// whose read cannot be reserved is closed; the others keep what they hold, and
// capacity a closed connection gave back can be reserved by a new one.
void shared_budget() {
  const size_t limit = 100000;
  Harness h(limit);
  const size_t max_pending = 128 << 10;
  auto a = h.open(max_pending, kLongLifetime);
  auto b = h.open(max_pending, kLongLifetime);
  auto c = h.open(max_pending, kLongLifetime);
  // The first frame fits beside the second holder; the third does not.
  auto frame_a = a.peer->frame(55000);
  auto frame_b = b.peer->frame(100000);
  auto frame_c = c.peer->frame(100000);
  a.peer->write(td::Slice(frame_a).substr(0, 50004));
  h.wait_until([&] { return h.budget().used() == 50000; }, 5.0, "first holder not charged");
  b.peer->write(td::Slice(frame_b).substr(0, 30004));
  h.wait_until([&] { return h.budget().used() == 80000; }, 5.0, "second holder not charged");
  c.peer->write(td::Slice(frame_c).substr(0, 30004));
  h.wait_until([&] { return c.probe->closed; }, 5.0, "a read past the shared budget did not close its connection");
  h.wait_until([&] { return h.budget().used() == 80000; }, 5.0, "closed connection kept its reservation");
  h.pump(0.05);
  require(!a.probe->closed && !b.probe->closed, "connections within the budget were closed");

  // The first holder finishes its frame, then its peer closes: all of its
  // share returns.
  a.peer->write(td::Slice(frame_a).substr(50004));
  h.wait_until([&] { return a.probe->packets == 1; }, 5.0, "frame within the budget not dispatched");
  h.wait_until([&] { return h.budget().used() == 30000; }, 5.0, "finished frame kept its reservation");
  a.peer->close();
  h.wait_until([&] { return a.probe->closed; }, 5.0, "peer close not noticed");
  require(h.budget().used() == 30000, "closing an idle connection changed the budget");

  // A new connection can now hold more than the third could.
  auto d = h.open(max_pending, kLongLifetime);
  auto frame_d = d.peer->frame(100000);
  d.peer->write(td::Slice(frame_d).substr(0, 60004));
  h.wait_until([&] { return h.budget().used() == 90000; }, 5.0, "recovered capacity not reservable");
  require(!d.probe->closed && !b.probe->closed, "connections within the recovered budget were closed");
  // And a peer closing while it holds an unfinished frame returns that too.
  d.peer->close();
  h.wait_until([&] { return d.probe->closed; }, 5.0, "peer close not noticed");
  h.wait_until([&] { return h.budget().used() == 30000; }, 5.0, "closed holder kept its reservation");
  std::printf("ADNL_EXT_INPUT_CASE shared_budget ok\n");
}

// An unfinished frame has an absolute lifetime: bytes that keep trickling in do
// not extend it. Each finished frame starts the next one's lifetime afresh.
void partial_frame_lifetime() {
  Harness h(1 << 20);
  const double lifetime = 1.0;
  auto slow = h.open(64 << 10, lifetime);
  auto frame = slow.peer->frame(20000);
  size_t sent = 1000;
  slow.peer->write(td::Slice(frame).substr(0, sent));
  auto started = td::Time::now();
  while (!slow.probe->closed) {
    require(td::Time::now() - started < lifetime + 2.0, "a trickled frame outlived its lifetime");
    slow.peer->write(td::Slice(frame).substr(sent, 10));
    sent += 10;
    h.pump(0.1);
  }
  auto closed_after = td::Time::now() - started;
  require(closed_after >= lifetime - 0.05, "an unfinished frame was cut before its lifetime");
  // Checked here too: a scheduler step can outlast the loop's own check.
  require(closed_after < lifetime + 2.0, "a trickled frame outlived its lifetime");
  require(slow.probe->packets == 0, "a trickled frame was dispatched");
  h.wait_until([&] { return h.budget().used() == 0; }, 5.0, "expired connection kept its reservation");

  // Two frames, each finished within its own lifetime, but together taking
  // longer than one lifetime, are both delivered.
  auto steady = h.open(64 << 10, lifetime);
  auto first = steady.peer->frame(20000);
  auto second = steady.peer->frame(20000);
  steady.peer->write(td::Slice(first).substr(0, 10000));
  h.pump(lifetime * 0.6);
  steady.peer->write(first.substr(10000) + second.substr(0, 10000));
  h.pump(lifetime * 0.6);
  require(!steady.probe->closed, "a frame finished within its own lifetime was cut");
  steady.peer->write(td::Slice(second).substr(10000));
  h.wait_until([&] { return steady.probe->packets == 2; }, 5.0, "frames within their lifetimes not dispatched");
  require(!steady.probe->closed, "a connection within its lifetimes was closed");
  std::printf("ADNL_EXT_INPUT_CASE partial_frame_lifetime ok closed_after=%.3f\n", closed_after);
}

// A protocol error mid-stream, after other frames held budget, returns all of it.
void release_on_error() {
  Harness h(1 << 20);
  auto c = h.open(64 << 10, kLongLifetime);
  auto good = c.peer->frame(1000);
  auto bad = c.peer->frame(30000);
  // Corrupt the checksum region of the second frame.
  bad[bad.size() - 1] = static_cast<char>(bad[bad.size() - 1] ^ 0x5a);
  c.peer->write(good);
  c.peer->write(td::Slice(bad).substr(0, 20000));
  h.wait_until([&] { return c.probe->packets == 1 && h.budget().used() == 20000 - 4; }, 5.0,
               "held bytes before the error not charged");
  c.peer->write(td::Slice(bad).substr(20000));
  h.wait_until([&] { return c.probe->closed; }, 5.0, "corrupt frame did not close the connection");
  h.wait_until([&] { return h.budget().used() == 0; }, 5.0, "errored connection kept its reservation");
  std::printf("ADNL_EXT_INPUT_CASE release_on_error ok\n");
}

void unit_checks() {
  adnl::AdnlExtByteBudget budget(100);
  require(budget.try_reserve_up_to(60) == 60, "partial reservation under the limit not taken whole");
  require(budget.try_reserve_up_to(60) == 40, "partial reservation did not stop at the limit");
  require(budget.try_reserve_up_to(1) == 0 && budget.used() == 100, "spent budget still handed out bytes");
  require(budget.release(100) && budget.used() == 0, "release did not return the bytes");
  require(adnl::adnl_ext_max_server_pending_input_bytes < 1024 * adnl::adnl_ext_max_pending_input_bytes,
          "server input bound is no tighter than the per-connection bound times the connection limit");
  require(adnl::adnl_ext_max_pending_input_bytes >= adnl::adnl_ext_max_frame_bytes,
          "default per-connection bound refuses a legal frame");
  require(adnl::adnl_ext_partial_frame_lifetime_seconds > 0, "partial-frame lifetime disabled by default");
  std::printf("ADNL_EXT_INPUT_CASE unit ok\n");
}

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(WARNING));
  const std::string only = argc > 1 ? argv[1] : "all";
  const std::vector<std::pair<std::string, void (*)()>> cases = {
      {"unit", unit_checks},     {"holds", holds_and_returns},         {"per-connection", per_connection_bound},
      {"shared", shared_budget}, {"lifetime", partial_frame_lifetime}, {"error", release_on_error},
  };
  bool ran = false;
  for (auto& [name, run] : cases) {
    if (only == "all" || only == name) {
      run();
      ran = true;
    }
  }
  require(ran, "unknown case: " + only);
  std::printf("ADNL_EXT_INPUT_BUDGET_TESTS passed=%s\n", only.c_str());
  return 0;
}
