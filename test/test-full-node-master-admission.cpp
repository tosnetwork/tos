/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The full-node master service is allowlist-only. Two real masters, each with
// its own ADNL id and external port, share one admission limiter, and real
// external clients query them over loopback TCP:
//
//   - clients that do not sign in, and clients that sign in with a key that is
//     not configured, are refused on both listeners, and their traffic, sent
//     before any slave asks, takes nothing from any slave;
//   - each configured slave, signing in with its key, is served exactly its
//     equal share of the burst and of the refill, summed across both
//     listeners and across reconnects, and the slaves together are served
//     exactly the unchanged aggregate ceiling;
//   - an empty allowlist cannot be built into a limiter;
//   - a slave whose sign-in key is missing from its keyring, or is not the
//     key of its configured id, gets no key to connect with.
//
// The limiter's clock is held still and advanced by the test, so every count
// is exact.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <netinet/in.h>
#include <set>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "adnl/adnl-ext-client.h"
#include "adnl/adnl.h"
#include "auto/tl/tos_api.hpp"
#include "keyring/keyring.h"
#include "td/utils/Time.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "tl-utils/tl-utils.hpp"
#include "validator/full-node-master.h"
#include "validator/full-node-slave-key.h"

namespace {

using namespace tos;
using validator::fullnode::FullNodeMaster;
using validator::fullnode::FullNodeMasterLimiter;

[[noreturn]] void fail(const std::string &message) {
  std::fprintf(stderr, "FULL_NODE_MASTER_ADMISSION_FAILURE: %s\n", message.c_str());
  std::fflush(stderr);
  std::_Exit(1);
}

void require(bool condition, const std::string &message) {
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
  if (::bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
    ::close(fd);
    fail("cannot reserve TCP port");
  }
  socklen_t size = sizeof(address);
  if (::getsockname(fd, reinterpret_cast<sockaddr *>(&address), &size) != 0) {
    ::close(fd);
    fail("cannot read reserved TCP port");
  }
  const auto port = ntohs(address.sin_port);
  ::close(fd);
  return port;
}

bool tcp_port_accepts(td::uint16 port) {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return false;
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(port);
  bool ok = ::connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0;
  ::close(fd);
  return ok;
}

td::BufferSlice capabilities_query() {
  return create_serialize_tl_object_suffix<tos_api::tosNode_query>(
      serialize_tl_object(create_tl_object<tos_api::tosNode_getCapabilities>(), true));
}

bool is_capabilities_answer(const td::BufferSlice &answer) {
  return fetch_tl_object<tos_api::tosNode_capabilities>(answer.clone(), true).is_ok();
}

class ReadyFlag final : public adnl::AdnlExtClient::Callback {
 public:
  explicit ReadyFlag(std::shared_ptr<std::atomic<bool>> ready) : ready_(std::move(ready)) {
  }
  void on_ready() override {
    ready_->store(true, std::memory_order_release);
  }
  void on_stop_ready() override {
    ready_->store(false, std::memory_order_release);
  }

 private:
  std::shared_ptr<std::atomic<bool>> ready_;
};

struct Listener {
  adnl::AdnlNodeIdFull id;
  td::uint16 port = 0;
};

class Harness {
 public:
  Harness() {
    db_root_ = "/tmp/tos-full-node-master-admission-" + std::to_string(::getpid());
    td::rmrf(db_root_).ignore();
    require(td::mkdir(db_root_).is_ok(), "cannot create db directory");
    scheduler_ = std::make_unique<td::actor::Scheduler>(std::vector<td::actor::Scheduler::NodeInfo>{2});
    clock_ms_ = std::make_shared<std::atomic<td::uint64>>(1000000);
    scheduler_->run_in_context([&] {
      keyring_ = keyring::Keyring::create(db_root_ + "/keyring");
      adnl_ = adnl::Adnl::create(db_root_, keyring_.get());
    });
  }

  ~Harness() {
    scheduler_->run_in_context([&] {
      masters_.clear();
      adnl_.reset();
      keyring_.reset();
    });
    scheduler_->run(0.2);
    scheduler_->stop();
    td::rmrf(db_root_).ignore();
  }

  void advance_clock(td::uint64 ms) {
    clock_ms_->fetch_add(ms);
  }

  std::unique_ptr<FullNodeMasterLimiter> build_limiter(std::set<adnl::AdnlNodeIdShort> trusted, std::string *error) {
    auto clock = [ms = clock_ms_]() -> td::uint64 { return ms->load(); };
    auto R = FullNodeMasterLimiter::create(std::move(trusted), clock);
    if (R.is_error()) {
      *error = R.error().message().str();
      return nullptr;
    }
    return R.move_as_ok();
  }

  // Start one master per listener, all sharing `limiter`, the way the engine
  // starts every configured master.
  std::vector<Listener> start_masters(size_t count, std::shared_ptr<FullNodeMasterLimiter> limiter) {
    std::vector<Listener> listeners;
    for (size_t i = 0; i < count; i++) {
      auto private_key = PrivateKey{privkeys::Ed25519::random()};
      Listener listener{adnl::AdnlNodeIdFull{private_key.compute_public_key()}, allocate_tcp_port()};
      install_key(std::move(private_key));
      auto short_id = listener.id.compute_short_id();
      scheduler_->run_in_context([&] {
        td::actor::send_closure(adnl_, &adnl::Adnl::add_id, listener.id, adnl::AdnlAddressList{},
                                static_cast<td::uint8>(0));
        masters_.push_back(FullNodeMaster::create(short_id, listener.port, FileHash{}, keyring_.get(), adnl_.get(),
                                                  td::actor::ActorId<validator::ValidatorManagerInterface>{}, limiter));
      });
      wait_until([&] { return tcp_port_accepts(listener.port); }, "master did not start listening");
      listeners.push_back(listener);
    }
    return listeners;
  }

  void install_key(PrivateKey key) {
    std::atomic<int> done{0};
    scheduler_->run_in_context([&] {
      td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(key), false,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> result) {
                                done.store(result.is_ok() ? 1 : -1, std::memory_order_release);
                              }));
    });
    wait_until([&] { return done.load(std::memory_order_acquire) != 0; }, "key install timed out");
    require(done.load() == 1, "key install failed");
  }

  td::Result<PrivateKey> export_key(const adnl::AdnlNodeIdShort &id) {
    std::atomic<bool> done{false};
    td::Result<PrivateKey> exported = td::Status::Error("not exported");
    scheduler_->run_in_context([&] {
      td::actor::send_closure(keyring_, &keyring::Keyring::export_private_key, id.pubkey_hash(),
                              td::PromiseCreator::lambda([&](td::Result<PrivateKey> R) {
                                exported = std::move(R);
                                done.store(true, std::memory_order_release);
                              }));
    });
    wait_until([&] { return done.load(std::memory_order_acquire); }, "key export timed out");
    return exported;
  }

  // Connect a fresh client to `listener`, signing in with `local_key` (or not
  // at all when it is empty), send the queries one after another and return
  // how many were answered. The first refusal closes the connection, which
  // ends the session; the client is torn down afterwards, so every call is a
  // new connection.
  size_t session(const Listener &listener, PrivateKey local_key, size_t queries) {
    auto ready = std::make_shared<std::atomic<bool>>(false);
    td::actor::ActorOwn<adnl::AdnlExtClient> client;
    td::IPAddress address;
    require(address.init_host_port("127.0.0.1", listener.port).is_ok(), "cannot build server address");
    scheduler_->run_in_context([&] {
      client =
          adnl::AdnlExtClient::create(listener.id, std::move(local_key), address, std::make_unique<ReadyFlag>(ready));
    });
    wait_until([&] { return ready->load(std::memory_order_acquire); }, "client did not become ready");
    size_t answered = 0;
    for (size_t i = 0; i < queries; i++) {
      std::atomic<int> outcome{0};
      scheduler_->run_in_context([&] {
        td::actor::send_closure(client, &adnl::AdnlExtClient::send_query, "capabilities", capabilities_query(),
                                td::Timestamp::in(10.0), td::PromiseCreator::lambda([&](td::Result<td::BufferSlice> R) {
                                  outcome.store(R.is_ok() && is_capabilities_answer(R.ok()) ? 1 : -1,
                                                std::memory_order_release);
                                }));
      });
      wait_until([&] { return outcome.load(std::memory_order_acquire) != 0; }, "query did not complete");
      if (outcome.load() != 1) {
        break;
      }
      answered++;
    }
    scheduler_->run_in_context([&] { client.reset(); });
    scheduler_->run(0.05);
    return answered;
  }

  // Ask until refused, reconnecting after every `per_connection` answers,
  // alternating listeners on each reconnect. Returns the total answered.
  size_t drain(const std::vector<Listener> &listeners, const PrivateKey &key, size_t per_connection) {
    size_t total = 0;
    for (size_t connection = 0; connection < 64; connection++) {
      const auto &listener = listeners[connection % listeners.size()];
      size_t answered = session(listener, key, per_connection);
      total += answered;
      if (answered < per_connection) {
        return total;
      }
    }
    fail("a slave was never refused: its share has no ceiling");
  }

 private:
  template <class F>
  void wait_until(F &&done, const std::string &what) {
    auto deadline = td::Timestamp::in(20.0);
    while (!done()) {
      scheduler_->run(0.01);
      if (deadline.is_in_past()) {
        fail(what);
      }
    }
  }

  std::string db_root_;
  std::unique_ptr<td::actor::Scheduler> scheduler_;
  std::shared_ptr<std::atomic<td::uint64>> clock_ms_;
  td::actor::ActorOwn<keyring::Keyring> keyring_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  std::vector<td::actor::ActorOwn<FullNodeMaster>> masters_;
};

PrivateKey random_key() {
  return PrivateKey{privkeys::Ed25519::random()};
}

adnl::AdnlNodeIdShort id_of(const PrivateKey &key) {
  return adnl::AdnlNodeIdShort{key.compute_public_key().compute_short_id()};
}

void empty_allowlist_is_refused(Harness &harness) {
  std::string error;
  auto limiter = harness.build_limiter({}, &error);
  require(limiter == nullptr, "an empty allowlist built a limiter");
  require(error.find("allowlist-only") != std::string::npos, "unexpected refusal: " + error);
  std::printf("FULL_NODE_MASTER_ADMISSION empty_allowlist=refused\n");
}

void slave_sign_in_key(Harness &harness) {
  using validator::fullnode::full_node_slave_sign_in_key;
  auto slave_key = random_key();
  auto slave_id = id_of(slave_key);
  auto other_key = random_key();
  harness.install_key(slave_key);
  harness.install_key(other_key);

  // The configured key is in the keyring: the slave signs in with it.
  auto loaded = full_node_slave_sign_in_key(slave_id, harness.export_key(slave_id));
  require(loaded.is_ok(), "the slave's own key was refused");
  require(id_of(loaded.ok()) == slave_id, "the slave would sign in with another key");

  // The configured id's key is missing from the keyring.
  auto missing_id = id_of(random_key());
  auto missing_export = harness.export_key(missing_id);
  require(missing_export.is_error(), "the keyring exported a key it does not hold");
  auto missing = full_node_slave_sign_in_key(missing_id, std::move(missing_export));
  require(missing.is_error(), "a slave with a missing key got a key to connect with");

  // The keyring returned a key, but not the configured id's.
  auto mismatched = full_node_slave_sign_in_key(slave_id, harness.export_key(id_of(other_key)));
  require(mismatched.is_error(), "a slave would sign in with a key that is not its configured id's");

  // No full-node id configured at all.
  auto unconfigured = full_node_slave_sign_in_key(adnl::AdnlNodeIdShort::zero(), harness.export_key(slave_id));
  require(unconfigured.is_error(), "a slave without a full-node id got a key to connect with");
  require(validator::fullnode::check_full_node_slave_id(adnl::AdnlNodeIdShort::zero()).is_error(),
          "a slave without a full-node id passed the startup check");

  // An empty key is never a sign-in key, even if the keyring reported success.
  auto empty = full_node_slave_sign_in_key(slave_id, td::Result<PrivateKey>(PrivateKey{}));
  require(empty.is_error(), "an empty key was accepted as the slave's sign-in key");
  std::printf("FULL_NODE_MASTER_ADMISSION slave_key=checked\n");
}

void allowlist_only_service(Harness &harness) {
  auto slave_a = random_key();
  auto slave_b = random_key();
  auto unlisted = random_key();
  std::string error;
  auto built = harness.build_limiter({id_of(slave_a), id_of(slave_b)}, &error);
  require(built != nullptr, "cannot build the limiter: " + error);
  std::shared_ptr<FullNodeMasterLimiter> limiter(std::move(built));
  auto listeners = harness.start_masters(2, limiter);

  // Two slaves split the ceiling of 16 burst and 4 per second equally.
  constexpr size_t kShareBurst = FullNodeMasterLimiter::kBurst / 2;
  constexpr size_t kSharePerSecond = FullNodeMasterLimiter::kPerSecond / 2;

  // Hostile traffic first, on both listeners, before any slave has asked:
  // connections that never sign in and connections that sign in with a key
  // nobody configured. Each refusal closes the connection, so every attempt
  // is a fresh connection.
  size_t hostile_answered = 0;
  for (int round = 0; round < 6; round++) {
    for (const auto &listener : listeners) {
      hostile_answered += harness.session(listener, PrivateKey{}, 4);
      hostile_answered += harness.session(listener, unlisted, 4);
      hostile_answered += harness.session(listener, random_key(), 4);
    }
  }
  require(hostile_answered == 0,
          "an unlisted or unauthenticated client was served " + std::to_string(hostile_answered) + " request(s)");

  // Each slave gets exactly its burst, summed across both listeners and
  // across reconnects (three answers per connection, alternating listeners).
  size_t a_burst = harness.drain(listeners, slave_a, 3);
  require(a_burst == kShareBurst,
          "slave A was served " + std::to_string(a_burst) + " of its burst of " + std::to_string(kShareBurst));
  // A has spent its share; B's is untouched by A and by the hostile traffic.
  require(harness.session(listeners[1], slave_a, 1) == 0, "slave A was served beyond its share");
  size_t b_burst = harness.drain(listeners, slave_b, 5);
  require(b_burst == kShareBurst,
          "slave B was served " + std::to_string(b_burst) + " of its burst of " + std::to_string(kShareBurst));

  // More hostile traffic at the refill instant, ahead of the slaves.
  harness.advance_clock(1000);
  for (const auto &listener : listeners) {
    hostile_answered += harness.session(listener, PrivateKey{}, 4);
    hostile_answered += harness.session(listener, unlisted, 4);
  }
  require(hostile_answered == 0, "an unlisted client was served after the refill");

  // One second of refill: exactly 2 more each, whichever listener they use.
  size_t a_refill = harness.drain({listeners[1], listeners[0]}, slave_a, 1);
  size_t b_refill = harness.drain(listeners, slave_b, 1);
  require(a_refill == kSharePerSecond, "slave A refilled " + std::to_string(a_refill) + " in one second");
  require(b_refill == kSharePerSecond, "slave B refilled " + std::to_string(b_refill) + " in one second");

  // The slaves together got exactly the aggregate ceiling for the elapsed
  // second, across both listeners: one limiter, not one per listener.
  size_t total = a_burst + b_burst + a_refill + b_refill;
  require(total == FullNodeMasterLimiter::kBurst + FullNodeMasterLimiter::kPerSecond,
          "the slaves were served " + std::to_string(total) + " in total");
  std::printf(
      "FULL_NODE_MASTER_ADMISSION hostile_answered=0 a_burst=%zu b_burst=%zu a_refill=%zu b_refill=%zu "
      "total=%zu listeners=%zu\n",
      a_burst, b_burst, a_refill, b_refill, total, listeners.size());
}

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  Harness harness;
  empty_allowlist_is_refused(harness);
  slave_sign_in_key(harness);
  allowlist_only_service(harness);
  std::printf("FULL_NODE_MASTER_ADMISSION_OK\n");
  return 0;
}
