/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// What an ADNL external server connection may hold of frames it has not finished
// receiving: a per-connection bound, a budget shared by the server's connections
// that is reserved before the buffer grows, an absolute lifetime for an unfinished
// frame, a per-source share of that budget summed across one source's
// connections, and every reservation returned when the connection closes for any
// reason.
//
// The real connection actor and BufferedFd run over a socketpair. The peer is
// this test, writing a fixed handful of bytes; nothing floods. Budgets are small
// and injected, so each bound is reached with kilobytes. One case runs the real
// external server over loopback TCP with its production budgets, to show the
// server charges each accepted connection to its source; it writes a bounded
// amount (tens of MiB) once and reads what the server answers.
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "adnl/adnl-ext-connection.hpp"
#include "adnl/adnl-ext-limits.h"
#include "adnl/adnl-source-share.h"
#include "adnl/adnl.h"
#include "auto/tl/tos_api.h"
#include "keyring/keyring.h"
#include "keys/encryptor.h"
#include "keys/keys.hpp"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/Time.h"
#include "td/utils/buffer.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/port/detail/NativeFd.h"
#include "td/utils/port/path.h"
#include "tl-utils/tl-utils.hpp"

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
                 size_t max_pending, double lifetime, std::shared_ptr<adnl::SourceShareLedger> shares,
                 std::string source)
      : AdnlExtConnection(std::move(fd), nullptr, false), probe_(std::move(probe)) {
    set_input_limits(std::move(budget), max_pending, lifetime);
    if (shares) {
      set_input_source_share(std::move(shares), std::move(source));
    }
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
  explicit Harness(size_t budget_bytes, size_t source_share_bytes = 0)
      : budget_(std::make_shared<adnl::AdnlExtByteBudget>(budget_bytes))
      , shares_(source_share_bytes > 0 ? std::make_shared<adnl::SourceShareLedger>(source_share_bytes) : nullptr) {
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

  Opened open(size_t max_pending, double lifetime, std::string source = "v4:192.0.2.1") {
    int fds[2];
    require(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair failed");
    auto socket = td::SocketFd::from_native_fd(td::NativeFd(fds[0]));
    require(socket.is_ok(), "cannot wrap the server end");
    auto probe = std::make_shared<Probe>();
    scheduler_->run_in_context([&] {
      connections_.push_back(td::actor::create_actor<TestConnection>(
          td::actor::ActorOptions().with_name("inconn").with_poll(), socket.move_as_ok(), probe, budget_, max_pending,
          lifetime, shares_, source));
    });
    return Opened{std::make_unique<Peer>(fds[1]), probe};
  }

  adnl::AdnlExtByteBudget& budget() {
    return *budget_;
  }
  adnl::SourceShareLedger& shares() {
    return *shares_;
  }

  // Runs the scheduler until `done` holds, checking after every step that the
  // shared budget never passed its limit.
  template <class F>
  void wait_until(F&& done, double bound_s, const std::string& what) {
    auto deadline = td::Timestamp::in(bound_s);
    while (!done()) {
      scheduler_->run(0.005);
      require(budget_->used() <= budget_->limit(), "shared input budget exceeded its limit");
      check_shares();
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
      check_shares();
    }
  }

 private:
  // Every byte charged to a source is charged to the server budget too.
  void check_shares() {
    if (!shares_) {
      return;
    }
    for (const auto& source : {"v4:192.0.2.1", "v4:192.0.2.2", "v4:192.0.2.3"}) {
      require(shares_->used(source) <= shares_->per_source_limit(),
              std::string("source ") + source + " exceeded its share");
    }
  }

  std::shared_ptr<adnl::AdnlExtByteBudget> budget_;
  std::shared_ptr<adnl::SourceShareLedger> shares_;
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

// A frame larger than the connection may hold is refused as soon as its length
// is parsed, without reading past the bounded read that carried the length; one
// that just fits is accepted.
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

// One source's connections together hold at most the source's share of the
// input budget. The source's connection that asks for more than its share is
// closed while the server budget still has room; the source's other connection
// and every connection of an unrelated source keep reading and completing
// frames. When the saturating source lets go, its share returns to zero, its
// ledger entry is gone, and it can connect and hold input again.
void source_share() {
  const size_t limit = 100000;
  const size_t share = adnl::default_source_share(limit);
  require(share == limit / 8, "default source share is not one eighth of the budget");
  Harness h(limit, share);
  const size_t max_pending = 64 << 10;
  const std::string hog = "v4:192.0.2.1";
  const std::string other = "v4:192.0.2.2";

  // The saturating source holds most of its share with one unfinished frame.
  auto hog1 = h.open(max_pending, kLongLifetime, hog);
  auto hog1_frame = hog1.peer->frame(20000);
  hog1.peer->write(td::Slice(hog1_frame).substr(0, 10004));
  h.wait_until([&] { return h.shares().used(hog) == 10000; }, 5.0, "first hog connection not charged to its source");

  // An unrelated source holds an unfinished frame of its own.
  auto other1 = h.open(max_pending, kLongLifetime, other);
  auto other1_frame = other1.peer->frame(9000);
  other1.peer->write(td::Slice(other1_frame).substr(0, 5004));
  h.wait_until([&] { return h.shares().used(other) == 5000; }, 5.0, "unrelated source not charged");

  // The saturating source's second connection asks for more than the share has
  // left. It is the one closed; the server budget is far from spent.
  auto hog2 = h.open(max_pending, kLongLifetime, hog);
  auto hog2_frame = hog2.peer->frame(20000);
  hog2.peer->write(td::Slice(hog2_frame).substr(0, 5004));
  h.wait_until([&] { return hog2.probe->closed; }, 5.0, "a connection past its source's share was not closed");
  require(h.budget().used() < limit / 2, "the source share was not what refused the read");
  h.wait_until([&] { return h.shares().used(hog) == 10000; }, 5.0, "refused connection kept its source charge");
  h.pump(0.05);
  require(!hog1.probe->closed, "refusing a source's connection closed the source's other connection");
  require(!other1.probe->closed, "refusing one source closed an unrelated source's connection");

  // The unrelated source keeps completing frames while the other is at its share.
  other1.peer->write(td::Slice(other1_frame).substr(5004));
  h.wait_until([&] { return other1.probe->packets == 1; }, 5.0, "unrelated source's frame not completed");
  auto other2 = h.open(max_pending, kLongLifetime, other);
  std::string frames;
  for (int i = 0; i < 3; i++) {
    frames += other2.peer->frame(8000);
  }
  other2.peer->write(frames);
  h.wait_until([&] { return other2.probe->packets == 3; }, 5.0, "unrelated source's new connection made no progress");
  h.wait_until([&] { return h.shares().used(other) == 0; }, 5.0, "completed frames kept their source charge");
  require(!other1.probe->closed && !other2.probe->closed, "unrelated source's connections were closed");

  // Every byte the ledger holds is held in the server budget too.
  require(h.budget().used() == h.shares().used(hog) + h.shares().used(other), "ledger and budget disagree");

  // The saturating source lets go: its share and its ledger entry are gone.
  hog1.peer->close();
  h.wait_until([&] { return hog1.probe->closed; }, 5.0, "peer close not noticed");
  h.wait_until([&] { return h.shares().used(hog) == 0 && h.budget().used() == 0; }, 5.0,
               "closed connection kept its source charge");
  require(h.shares().sources() == 0, "a source holding nothing kept a ledger entry");

  // And it can connect and hold input again.
  auto hog3 = h.open(max_pending, kLongLifetime, hog);
  auto hog3_frame = hog3.peer->frame(12000);
  hog3.peer->write(td::Slice(hog3_frame).substr(0, 11004));
  h.wait_until([&] { return h.shares().used(hog) == 11000; }, 5.0, "reconnected source could not hold input");
  hog3.peer->write(td::Slice(hog3_frame).substr(11004));
  h.wait_until([&] { return hog3.probe->packets == 1; }, 5.0, "reconnected source's frame not completed");
  require(!hog3.probe->closed, "reconnected source within its share was closed");
  std::printf("ADNL_EXT_INPUT_CASE source_share ok share=%zu\n", share);
}

// The real external server, accepting real TCP connections with its production
// budgets: a source's connections are charged to the source. Two connections
// from 127.0.0.1 hold most of the source's 32 MiB share with unfinished frames;
// a third asking for more is closed though the 256 MiB server budget is mostly
// free. A connection from 127.0.0.2 meanwhile holds input and is answered.
// After the first source closes, it connects again and is served.
class RawExtPeer {
 public:
  RawExtPeer(const std::string& source_ip, td::uint16 port, const adnl::AdnlNodeIdFull& server) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    require(fd_ >= 0, "cannot open TCP socket");
    sockaddr_in local{};
    local.sin_family = AF_INET;
    require(::inet_pton(AF_INET, source_ip.c_str(), &local.sin_addr) == 1, "bad source address");
    require(::bind(fd_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0, "cannot bind source " + source_ip);
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    require(::inet_pton(AF_INET, "127.0.0.1", &remote.sin_addr) == 1, "bad server address");
    require(::connect(fd_, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) == 0, "cannot connect");

    // The init block: the server's short id, then 160 random bytes encrypted
    // to the server's key. The server reads the second key and IV of those
    // bytes as the key of what this peer sends.
    td::SecureString secret(160);
    td::Random::secure_bytes(secret.as_mutable_slice());
    td::SecureString key(32);
    td::SecureString iv(16);
    key.as_mutable_slice().copy_from(secret.as_slice().substr(32, 32));
    iv.as_mutable_slice().copy_from(secret.as_slice().substr(80, 16));
    out_.init(key, iv);
    auto encryptor = server.pubkey().create_encryptor();
    require(encryptor.is_ok(), "cannot create encryptor");
    auto encrypted = encryptor.ok()->encrypt(secret.as_slice());
    require(encrypted.is_ok() && encrypted.ok().size() == 224, "cannot encrypt init block");
    std::string init = server.compute_short_id().as_slice().str() + encrypted.ok().as_slice().str();
    pending_ = init;
  }
  ~RawExtPeer() {
    close();
  }
  RawExtPeer(const RawExtPeer&) = delete;
  RawExtPeer& operator=(const RawExtPeer&) = delete;

  // Queue the length prefix of a frame announcing `packet_bytes` and `body`
  // bytes of it.
  void queue_partial_frame(td::uint32 packet_bytes, size_t body) {
    std::string plain(4 + body, 'p');
    std::memcpy(plain.data(), &packet_bytes, 4);
    pending_ += encrypt(plain);
  }
  // Queue a complete keepalive-sized ping; the server answers with a pong.
  void queue_ping() {
    auto ping = serialize_tl_object(create_tl_object<tos_api::tcp_ping>(td::Random::fast_uint64()), true);
    td::uint32 len = static_cast<td::uint32>(ping.size() + adnl::adnl_ext_packet_framing_bytes);
    std::string plain(4 + len, '\0');
    std::memcpy(plain.data(), &len, 4);
    td::MutableSlice body(plain.data() + 4, len);
    td::Random::secure_bytes(body.substr(0, 32));
    body.substr(32, ping.size()).copy_from(ping.as_slice());
    td::sha256(body.substr(0, 32 + ping.size()), body.substr(32 + ping.size(), 32));
    pending_ += encrypt(plain);
  }
  // Write what is queued without blocking, and take whatever the server sent.
  // Returns false once the server has closed this connection.
  bool pump() {
    if (fd_ < 0) {
      return false;
    }
    while (!pending_.empty()) {
      auto n = ::send(fd_, pending_.data(), pending_.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        }
        closed_by_server_ = true;
        return false;
      }
      pending_.erase(0, static_cast<size_t>(n));
    }
    char buffer[4096];
    while (true) {
      auto n = ::recv(fd_, buffer, sizeof(buffer), MSG_DONTWAIT);
      if (n > 0) {
        received_ += static_cast<size_t>(n);
        continue;
      }
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return true;
      }
      closed_by_server_ = true;
      return false;
    }
  }
  bool flushed() const {
    return pending_.empty();
  }
  bool closed_by_server() const {
    return closed_by_server_;
  }
  // Bytes the server sent: 68 for the empty frame that acknowledges the init
  // block, 80 for each pong.
  size_t received() const {
    return received_;
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
  int fd_ = -1;
  td::AesCtrState out_;
  std::string pending_;
  size_t received_ = 0;
  bool closed_by_server_ = false;
};

td::uint16 free_tcp_port() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  require(fd >= 0, "cannot open TCP socket");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  require(::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "cannot reserve a port");
  socklen_t size = sizeof(address);
  require(::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) == 0, "cannot read the port");
  ::close(fd);
  return ntohs(address.sin_port);
}

void server_source_share() {
  constexpr size_t kInitAck = 68;
  constexpr size_t kPong = 80;
  const auto max_packet = static_cast<td::uint32>(adnl::adnl_ext_max_pending_input_bytes - 4);
  const size_t share = adnl::adnl_ext_max_source_pending_input_bytes;
  require(share == adnl::adnl_ext_max_server_pending_input_bytes / 8, "server source share is not one eighth");
  require(share >= 2 * adnl::adnl_ext_max_frame_bytes - 8, "a source's share cannot hold two maximal frames");

  std::string db_root = "/tmp/tos-adnl-ext-source-share-" + std::to_string(::getpid());
  td::rmrf(db_root).ignore();
  require(td::mkdir(db_root).is_ok(), "cannot create db directory");
  auto scheduler = std::make_unique<td::actor::Scheduler>(std::vector<td::actor::Scheduler::NodeInfo>{1});
  td::actor::ActorOwn<keyring::Keyring> keyring_actor;
  td::actor::ActorOwn<adnl::Adnl> adnl_actor;
  td::actor::ActorOwn<adnl::AdnlExtServer> server;
  auto private_key = PrivateKey{privkeys::Ed25519::random()};
  auto public_key = private_key.compute_public_key();
  adnl::AdnlNodeIdFull server_id{public_key};
  adnl::AdnlNodeIdShort server_short{public_key.compute_short_id()};
  auto port = free_tcp_port();
  bool listening = false;
  scheduler->run_in_context([&] {
    keyring_actor = keyring::Keyring::create(db_root);
    adnl_actor = adnl::Adnl::create(db_root, keyring_actor.get());
    td::actor::send_closure(
        keyring_actor, &keyring::Keyring::add_key, std::move(private_key), true,
        td::PromiseCreator::lambda([](td::Result<td::Unit> result) { require(result.is_ok(), "key install failed"); }));
    td::actor::send_closure(adnl_actor, &adnl::Adnl::add_id, server_id, adnl::AdnlAddressList{},
                            static_cast<td::uint8>(0));
    td::actor::send_closure(
        adnl_actor, &adnl::Adnl::create_ext_server, std::vector<adnl::AdnlNodeIdShort>{server_short},
        std::vector<td::uint16>{port},
        td::PromiseCreator::lambda([&](td::Result<td::actor::ActorOwn<adnl::AdnlExtServer>> result) {
          require(result.is_ok(), "ext server start failed");
          server = result.move_as_ok();
          td::actor::send_closure(server, &adnl::AdnlExtServer::wait_listening,
                                  td::PromiseCreator::lambda([&](td::Result<td::Unit> status) {
                                    require(status.is_ok(), "ext server did not listen");
                                    listening = true;
                                  }));
        }));
  });
  auto run_until = [&](auto&& done, double bound_s, const std::string& what, std::vector<RawExtPeer*> peers) {
    auto deadline = td::Timestamp::in(bound_s);
    while (!done()) {
      scheduler->run(0.005);
      for (auto* peer : peers) {
        peer->pump();
      }
      if (deadline.is_in_past()) {
        fail(what);
      }
    }
  };
  run_until([&] { return listening; }, 10.0, "ext server did not start", {});

  // Every connection's init block is acknowledged before it sends anything else.
  auto connect = [&](const std::string& ip) {
    auto peer = std::make_unique<RawExtPeer>(ip, port, server_id);
    auto* raw = peer.get();
    run_until([&] { return raw->received() >= kInitAck; }, 10.0, "init block from " + ip + " not acknowledged", {raw});
    return peer;
  };

  // The first source holds two unfinished frames: one maximal frame less a
  // KiB, and 15 MiB of another, together under its 32 MiB share.
  auto hog1 = connect("127.0.0.1");
  auto hog2 = connect("127.0.0.1");
  hog1->queue_partial_frame(max_packet, max_packet - 1024);
  hog2->queue_partial_frame(max_packet, size_t{15} << 20);
  // An unrelated source holds an unfinished frame of its own meanwhile.
  auto other1 = connect("127.0.0.2");
  other1->queue_partial_frame(max_packet, size_t{2} << 20);
  run_until([&] { return hog1->flushed() && hog2->flushed() && other1->flushed(); }, 20.0, "held frames were not taken",
            {hog1.get(), hog2.get(), other1.get()});

  // The first source's third connection sends 3 MiB with about 1 MiB of its
  // share left: it is closed, though the server budget is almost all free.
  auto hog3 = connect("127.0.0.1");
  hog3->queue_partial_frame(max_packet, size_t{3} << 20);
  run_until([&] { return hog3->closed_by_server(); }, 20.0, "a connection past its source's share was not closed",
            {hog1.get(), hog2.get(), hog3.get(), other1.get()});

  // Nothing else was touched, and the unrelated source is answered.
  auto other2 = connect("127.0.0.2");
  other2->queue_ping();
  run_until([&] { return other2->received() >= kInitAck + kPong; }, 10.0, "unrelated source was not answered",
            {hog1.get(), hog2.get(), other1.get(), other2.get()});
  other1->queue_ping();
  run_until([&] { return other1->flushed(); }, 10.0, "unrelated source's write not taken",
            {hog1.get(), hog2.get(), other1.get(), other2.get()});
  hog1->queue_ping();
  run_until([&] { return hog1->flushed(); }, 10.0, "first source's write not taken",
            {hog1.get(), hog2.get(), other1.get(), other2.get()});
  require(!hog1->closed_by_server() && !hog2->closed_by_server(),
          "refusing a source's connection closed the source's other connections");
  require(!other1->closed_by_server() && !other2->closed_by_server(),
          "refusing one source closed an unrelated source's connection");

  // The first source lets go of everything and connects again: its share is
  // whole again, so it can hold more than the refused connection could.
  hog1->close();
  hog2->close();
  hog3->close();
  scheduler->run(0.2);
  auto hog4 = connect("127.0.0.1");
  hog4->queue_partial_frame(max_packet, size_t{12} << 20);
  run_until([&] { return hog4->flushed(); }, 20.0, "reconnected source could not hold input",
            {hog4.get(), other1.get(), other2.get()});
  auto hog5 = connect("127.0.0.1");
  hog5->queue_ping();
  run_until([&] { return hog5->received() >= kInitAck + kPong; }, 10.0, "reconnected source was not answered",
            {hog4.get(), hog5.get(), other1.get(), other2.get()});
  require(!hog4->closed_by_server() && !hog5->closed_by_server(), "reconnected source within its share was closed");

  hog4.reset();
  hog5.reset();
  other1.reset();
  other2.reset();
  scheduler->run_in_context([&] {
    server.reset();
    adnl_actor.reset();
    keyring_actor.reset();
  });
  scheduler->run(0.2);
  scheduler->stop();
  td::rmrf(db_root).ignore();
  std::printf("ADNL_EXT_INPUT_CASE server_source_share ok\n");
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
  require(adnl::adnl_ext_max_source_pending_input_bytes * adnl::kSourceShareDivisor ==
              adnl::adnl_ext_max_server_pending_input_bytes,
          "a source's input share is not one eighth of the server budget");

  // The ledger: all-or-nothing and partial reservation, release, and an entry
  // only while a source holds something.
  adnl::SourceShareLedger ledger(10);
  require(ledger.try_reserve("a", 6) && !ledger.try_reserve("a", 5), "source share passed its limit");
  require(ledger.try_reserve_up_to("a", 9) == 4 && ledger.try_reserve_up_to("a", 1) == 0,
          "partial source reservation did not stop at the share");
  require(ledger.try_reserve("b", 10), "one source's use limited another's");
  require(!ledger.release("a", 11) && ledger.used("a") == 10, "over-release changed a source's use");
  require(ledger.release("a", 10) && ledger.release("b", 10) && ledger.sources() == 0,
          "sources holding nothing kept their entries");
  require(!ledger.release("c", 1), "release from an unknown source succeeded");
  require(ledger.sources() == 0, "a refused release created an entry");
  require(adnl::default_source_share(7) == 1 && adnl::default_source_share(0) == 0,
          "small budgets give no source its first unit");

  // Source keys: IPv4 by address, IPv6 by /64, IPv4-mapped IPv6 as IPv4.
  auto key = [](const std::string& host) {
    td::IPAddress address;
    auto status =
        host.find(':') == std::string::npos ? address.init_ipv4_port(host, 1) : address.init_ipv6_port(host, 1);
    require(status.is_ok(), "bad address " + host);
    return adnl::network_source_key(address);
  };
  require(key("192.0.2.1") == "v4:192.0.2.1", "IPv4 key is not the address");
  require(key("192.0.2.1") != key("192.0.2.2"), "distinct IPv4 sources share a key");
  require(key("2001:db8:1:2::1") == key("2001:db8:1:2:ffff::7"), "one IPv6 /64 split into several sources");
  require(key("2001:db8:1:2::1") != key("2001:db8:1:3::1"), "distinct IPv6 /64 prefixes share a key");
  require(key("2001:db8:1:2::1").rfind("v6:", 0) == 0, "IPv6 key is not marked as IPv6");
  require(key("::ffff:192.0.2.1") == key("192.0.2.1"), "IPv4-mapped IPv6 keyed apart from its IPv4 address");
  require(adnl::network_source_key(td::IPAddress{}) == "unknown", "an invalid address has a source key");
  std::printf("ADNL_EXT_INPUT_CASE unit ok\n");
}

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(WARNING));
  const std::string only = argc > 1 ? argv[1] : "all";
  const std::vector<std::pair<std::string, void (*)()>> cases = {
      {"unit", unit_checks},
      {"holds", holds_and_returns},
      {"per-connection", per_connection_bound},
      {"shared", shared_budget},
      {"lifetime", partial_frame_lifetime},
      {"error", release_on_error},
      {"source-share", source_share},
      {"server-source-share", server_source_share},
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
