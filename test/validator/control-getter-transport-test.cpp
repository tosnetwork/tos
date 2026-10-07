/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <atomic>
#include <cstdio>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "adnl/adnl-ext-client.h"
#include "adnl/adnl-ext-server.h"
#include "adnl/adnl.h"
#include "keyring/keyring.h"
#include "td/utils/port/path.h"
#include "tl-utils/common-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "validator-engine/control-getter-service.h"
#include "vm/vm.h"

#include "control-getter-fixture.h"

namespace cg = tos::control_getter;
using namespace tos;
using namespace getter_fixture;
int failures = 0;
void check(const char* name, bool ok) {
  if (!ok) {
    ++failures;
    std::fprintf(stderr, "CONTROL_TRANSPORT_FAIL %s\n", name);
  }
}

class Ready final : public adnl::AdnlExtClient::Callback {
 public:
  explicit Ready(std::atomic<bool>* value) : value_(value) {
  }
  void on_ready() override {
    *value_ = true;
  }
  void on_stop_ready() override {
    *value_ = false;
  }

 private:
  std::atomic<bool>* value_;
};
class Callback final : public adnl::Adnl::Callback {
 public:
  Callback(td::actor::ActorId<cg::Service> service, PublicKeyHash authorized)
      : service_(service), authorized_(authorized) {
  }
  void receive_message(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice) override {
  }
  void receive_query(adnl::AdnlNodeIdShort source, adnl::AdnlNodeIdShort, td::BufferSlice bytes,
                     td::Promise<td::BufferSlice> promise) override {
    auto envelope = must(fetch_tl_object<tos_api::engine_validator_controlQuery>(bytes, true), "control envelope");
    auto query =
        must(fetch_tl_object<tos_api::engine_validator_getElectorState>(envelope->data_, true), "elector query");
    cg::Request request{cg::ReadKind::Elector, std::move(query->wallets_), {}};
    td::actor::send_closure(service_, &cg::Service::query, source.pubkey_hash() == authorized_ ? 1 : 0, query->flags_,
                            td::optional<BlockIdExt>{}, std::move(request), std::move(promise));
  }

 private:
  td::actor::ActorId<cg::Service> service_;
  PublicKeyHash authorized_;
};
int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  vm::init_vm().ensure();
  require(argc == 3, "transport test ZEROSTATE FIXTURES");
  char directory[] = "/tmp/control-getter-transport-XXXXXX";
  require(mkdtemp(directory) != nullptr, "transport directory");
  auto state = control_fixture::production_build(argv[1], argv[2], "");
  std::atomic<int> lookups{0};
  td::actor::Scheduler scheduler{std::vector<td::actor::Scheduler::NodeInfo>{2}};
  td::actor::ActorOwn<keyring::Keyring> keyring;
  td::actor::ActorOwn<adnl::Adnl> adnl;
  td::actor::ActorOwn<adnl::AdnlExtServer> server;
  td::actor::ActorOwn<cg::Service> service;
  auto server_key = PrivateKey{privkeys::Ed25519::random()};
  auto client_key = PrivateKey{privkeys::Ed25519::random()};
  adnl::AdnlNodeIdFull server_id{server_key.compute_public_key()};
  auto authorized = client_key.compute_public_key().compute_short_id();
  auto wait = [&](const std::function<bool()>& condition) {
    const auto deadline = td::Timestamp::in(20);
    while (!condition()) {
      scheduler.run(0.001);
      require(!deadline.is_in_past(), "transport watchdog");
    }
  };
  int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  require(socket_fd >= 0, "port socket");
  sockaddr_in local{};
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  require(bind(socket_fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0, "port bind");
  socklen_t local_size = sizeof(local);
  require(getsockname(socket_fd, reinterpret_cast<sockaddr*>(&local), &local_size) == 0, "port number");
  auto port = ntohs(local.sin_port);
  close(socket_fd);
  scheduler.run_in_context([&] {
    keyring = keyring::Keyring::create(std::string(directory) + "/keyring");
    adnl = adnl::Adnl::create(directory, keyring.get());
    service = td::actor::create_actor<cg::Service>("transport-control-service",
                                                   [&](td::optional<BlockIdExt>, td::Promise<cg::LoadedState> promise) {
                                                     ++lookups;
                                                     promise.set_value(cg::LoadedState{state.id, state.root});
                                                   });
  });
  std::atomic<bool> installed{false};
  scheduler.run_in_context([&] {
    td::actor::send_closure(keyring.get(), &keyring::Keyring::add_key, server_key, false,
                            [&](td::Result<td::Unit> result) {
                              result.ensure();
                              installed = true;
                            });
    td::actor::send_closure(adnl.get(), &adnl::Adnl::add_id, server_id, adnl::AdnlAddressList{},
                            static_cast<td::uint8>(0));
    td::actor::send_closure(adnl.get(), &adnl::Adnl::subscribe, server_id.compute_short_id(), std::string{},
                            std::make_unique<Callback>(service.get(), authorized));
    td::actor::send_closure(
        adnl.get(), &adnl::Adnl::create_ext_server, std::vector<adnl::AdnlNodeIdShort>{server_id.compute_short_id()},
        std::vector<td::uint16>{port}, [&](td::Result<td::actor::ActorOwn<adnl::AdnlExtServer>> result) {
          server = must(std::move(result), "transport listener");
        });
  });
  wait([&] { return installed.load() && !server.empty(); });
  wait([&] {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    require(fd >= 0, "listener probe socket");
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons(port);
    bool accepted = connect(fd, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == 0;
    close(fd);
    return accepted;
  });
  for (int identity : {0, 1, 2}) {
    PrivateKey key;
    if (identity == 1) {
      key = PrivateKey{privkeys::Ed25519::random()};
    }
    if (identity == 2) {
      key = client_key;
    }
    td::IPAddress address;
    address.init_host_port("127.0.0.1", port).ensure();
    std::atomic<bool> ready{false};
    td::actor::ActorOwn<adnl::AdnlExtClient> client;
    scheduler.run_in_context(
        [&] { client = adnl::AdnlExtClient::create(server_id, key, address, std::make_unique<Ready>(&ready)); });
    wait([&] { return ready.load(); });
    std::atomic<bool> done{false};
    td::Result<td::BufferSlice> answer{td::Status::Error("no answer")};
    auto query = create_serialize_tl_object<tos_api::engine_validator_controlQuery>(
        create_serialize_tl_object<tos_api::engine_validator_getElectorState>(0, nullptr, std::vector<td::Bits256>{}));
    scheduler.run_in_context([&] {
      td::actor::send_closure(client.get(), &adnl::AdnlExtClient::send_query, "elector state", std::move(query),
                              td::Timestamp::in(10), [&](td::Result<td::BufferSlice> result) {
                                answer = std::move(result);
                                done = true;
                              });
    });
    wait([&] { return done.load(); });
    if (identity == 2) {
      check("authenticated-reader-answered",
            answer.is_ok() && fetch_tl_object<tos_api::engine_validator_electorState>(answer.ok(), true).is_ok() &&
                lookups.load() == 1);
    } else {
      auto error = answer.is_ok()
                       ? fetch_tl_object<tos_api::engine_validator_controlQueryError>(answer.ok(), true)
                       : td::Result<tl_object_ptr<tos_api::engine_validator_controlQueryError>>{answer.error().clone()};
      check(identity == 0 ? "anonymous-no-state-read" : "unlisted-no-state-read",
            error.is_ok() && error.ok()->message_ == "not authorized" && lookups.load() == 0);
    }
    scheduler.run_in_context([&] { client.reset(); });
  }
  scheduler.run_in_context([&] {
    server.reset();
    adnl.reset();
    keyring.reset();
    service.reset();
  });
  scheduler.run(0.01);
  scheduler.stop();
  td::rmrf(td::CSlice{static_cast<const char*>(directory)}).ensure();
  std::printf("CONTROL_TRANSPORT_RESULT checks=3 failures=%d\n", failures);
  return failures ? 1 : 0;
}
