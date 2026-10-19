/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// An external multi-client given a local key must sign in to its server with
// that key on every connection, so the server sees one stable authenticated
// source id. A full-node master relies on this to admit a configured slave as
// trusted. Runs one in-process loopback server; each client sends one query.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "adnl/adnl-ext-client.h"
#include "adnl/adnl.h"
#include "keyring/keyring.h"
#include "td/utils/Time.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"

namespace {

using namespace tos;

[[noreturn]] void fail(const std::string &message) {
  std::fprintf(stderr, "ADNL_EXT_CLIENT_IDENTITY_FAILURE: %s\n", message.c_str());
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

struct Seen {
  std::mutex mutex;
  std::vector<adnl::AdnlNodeIdShort> sources;
};

class RecordingHandler final : public adnl::Adnl::Callback {
 public:
  explicit RecordingHandler(std::shared_ptr<Seen> seen) : seen_(std::move(seen)) {
  }
  void receive_message(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice) override {
  }
  void receive_query(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    {
      std::lock_guard lock(seen_->mutex);
      seen_->sources.push_back(src);
    }
    promise.set_value(std::move(data));
  }

 private:
  std::shared_ptr<Seen> seen_;
};

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

class Harness {
 public:
  Harness() {
    port_ = allocate_tcp_port();
    db_root_ = "/tmp/tos-adnl-ext-client-identity-" + std::to_string(::getpid());
    td::rmrf(db_root_).ignore();
    require(td::mkdir(db_root_).is_ok(), "cannot create db directory");
    scheduler_ = std::make_unique<td::actor::Scheduler>(std::vector<td::actor::Scheduler::NodeInfo>{2});
    seen_ = std::make_shared<Seen>();
    start_server();
  }

  ~Harness() {
    scheduler_->run_in_context([&] {
      server_.reset();
      adnl_.reset();
      keyring_.reset();
    });
    scheduler_->run(0.2);
    scheduler_->stop();
    td::rmrf(db_root_).ignore();
  }

  // Connect a fresh multi-client, send one query, and return the source id
  // the server attributed it to. The client is torn down afterwards, so each
  // call is a new connection.
  adnl::AdnlNodeIdShort source_of_one_query(PrivateKey local_key) {
    auto ready = std::make_shared<std::atomic<bool>>(false);
    td::actor::ActorOwn<adnl::AdnlExtMultiClient> client;
    td::IPAddress address;
    require(address.init_host_port("127.0.0.1", port_).is_ok(), "cannot build server address");
    scheduler_->run_in_context([&] {
      client = adnl::AdnlExtMultiClient::create({{server_id_, address}}, std::move(local_key),
                                                std::make_unique<ReadyFlag>(ready));
    });
    wait_until([&] { return ready->load(std::memory_order_acquire); }, "client did not become ready");

    size_t before = seen_count();
    std::atomic<int> answered{0};
    scheduler_->run_in_context([&] {
      td::actor::send_closure(client, &adnl::AdnlExtClient::send_query, "identity", td::BufferSlice{"ping"},
                              td::Timestamp::in(10.0), td::PromiseCreator::lambda([&](td::Result<td::BufferSlice> R) {
                                answered.store(R.is_ok() ? 1 : -1, std::memory_order_release);
                              }));
    });
    wait_until([&] { return answered.load(std::memory_order_acquire) != 0; }, "query did not complete");
    require(answered.load() == 1, "query was not answered");
    require(seen_count() == before + 1, "server did not record exactly one query");
    scheduler_->run_in_context([&] { client.reset(); });
    scheduler_->run(0.1);
    std::lock_guard lock(seen_->mutex);
    return seen_->sources.back();
  }

 private:
  size_t seen_count() {
    std::lock_guard lock(seen_->mutex);
    return seen_->sources.size();
  }

  template <class F>
  void wait_until(F &&done, const std::string &what) {
    auto deadline = td::Timestamp::in(10.0);
    while (!done()) {
      scheduler_->run(0.01);
      if (deadline.is_in_past()) {
        fail(what);
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
    wait_until([&] { return key_ready.load(std::memory_order_acquire); }, "key install timed out");

    std::atomic<bool> server_ready{false};
    scheduler_->run_in_context([&] {
      td::actor::send_closure(adnl_, &adnl::Adnl::add_id, server_id_, adnl::AdnlAddressList{},
                              static_cast<td::uint8>(0));
      td::actor::send_closure(adnl_, &adnl::Adnl::subscribe, server_short, std::string{},
                              std::make_unique<RecordingHandler>(seen_));
      td::actor::send_closure(
          adnl_, &adnl::Adnl::create_ext_server, std::vector<adnl::AdnlNodeIdShort>{server_short},
          std::vector<td::uint16>{port_},
          td::PromiseCreator::lambda([&](td::Result<td::actor::ActorOwn<adnl::AdnlExtServer>> result) {
            require(result.is_ok(), "ext server start failed");
            server_ = result.move_as_ok();
            server_ready.store(true, std::memory_order_release);
          }));
    });
    wait_until([&] { return server_ready.load(std::memory_order_acquire); }, "ext server start timed out");

    std::atomic<bool> listening{false};
    bool listening_ok = false;
    scheduler_->run_in_context([&] {
      td::actor::send_closure(server_, &adnl::AdnlExtServer::wait_listening,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> result) {
                                listening_ok = result.is_ok();
                                listening.store(true, std::memory_order_release);
                              }));
    });
    wait_until([&] { return listening.load(std::memory_order_acquire); }, "ext server listen timed out");
    require(listening_ok, "ext server failed to listen");
  }

  td::uint16 port_ = 0;
  std::string db_root_;
  std::unique_ptr<td::actor::Scheduler> scheduler_;
  std::shared_ptr<Seen> seen_;
  adnl::AdnlNodeIdFull server_id_;
  td::actor::ActorOwn<keyring::Keyring> keyring_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<adnl::AdnlExtServer> server_;
};

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  Harness harness;

  auto slave_key = PrivateKey{privkeys::Ed25519::random()};
  const adnl::AdnlNodeIdShort slave_id{slave_key.compute_public_key().compute_short_id()};

  // Two separate connections with the same key: both attributed to it.
  auto first = harness.source_of_one_query(slave_key);
  auto second = harness.source_of_one_query(slave_key);
  require(first == slave_id, "keyed connection was not attributed to the slave key");
  require(second == slave_id, "reconnection was not attributed to the same slave key");

  // Without a key every connection gets an unrelated identity.
  auto anonymous_a = harness.source_of_one_query(PrivateKey{});
  auto anonymous_b = harness.source_of_one_query(PrivateKey{});
  require(anonymous_a != slave_id && anonymous_b != slave_id, "anonymous connection carried the slave id");
  require(anonymous_a != anonymous_b, "two anonymous connections shared one id");

  std::printf("ADNL_EXT_CLIENT_IDENTITY_OK keyed=%s\n", slave_id.bits256_value().to_hex().c_str());
  return 0;
}
