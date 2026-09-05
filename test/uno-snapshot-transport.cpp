#include "uno-snapshot-transport.h"
#include <atomic>

#include "adnl/adnl-ext-client.h"
#include "adnl/adnl.h"
#include "keys/keys.hpp"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/port/ServerSocketFd.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "tos/tos-tl.hpp"
#include "validator/net/download-state.hpp"

namespace {
using namespace tos;
using namespace tos::validator;

// Start at remote acquisition, deliberately excluding manager lookup/discovery.
class RemoteDownload final : public fullnode::DownloadState {
 public:
  using DownloadState::DownloadState;
  void start_up() override {
    alarm_timestamp() = td::Timestamp::in(15);
    got_node_to_download(adnl::AdnlNodeIdShort::zero());
  }
};

class Transport final : public td::actor::Actor {
 public:
  Transport(td::BufferSlice source, td::Result<td::BufferSlice>& result, std::atomic<bool>& completed, bool truncate)
      : source_(std::move(source)), result_(result), completed_(completed), truncate_(truncate) {}

  class Queries final : public adnl::Adnl::Callback {
   public:
    explicit Queries(td::actor::ActorId<Transport> owner) : owner_(owner) {}
    void receive_query(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice query,
                       td::Promise<td::BufferSlice> promise) override {
      td::actor::send_closure(owner_, &Transport::query, std::move(query), std::move(promise));
    }
   private:
    td::actor::ActorId<Transport> owner_;
  };
  class Ready final : public adnl::AdnlExtClient::Callback {
   public:
    explicit Ready(td::actor::ActorId<Transport> owner) : owner_(owner) {}
    void on_ready() override { td::actor::send_closure(owner_, &Transport::ready); }
    void on_stop_ready() override {}
   private:
    td::actor::ActorId<Transport> owner_;
  };

  void start_up() override {
    alarm_timestamp() = td::Timestamp::in(25);
    // Probe a random port; the short close/rebind race is test-only. A collision
    // causes a bounded test failure, never an unbounded retry or fallback.
    for (unsigned attempt = 0; attempt < 100; ++attempt) {
      port_ = static_cast<td::uint16>(td::Random::fast(20000, 60000));
      auto probe = td::ServerSocketFd::open(port_);
      if (probe.is_ok()) { probe.move_as_ok().close(); break; }
      port_ = 0;
    }
    ASSERT_TRUE(port_ != 0);
    auto directory = td::mkdtemp("/tmp", "uno-snapshot-transport-").move_as_ok();
    keyring_ = keyring::Keyring::create(directory);
    adnl_ = adnl::Adnl::create(directory, keyring_.get());
    auto private_key = PrivateKey{privkeys::Ed25519::random()};
    public_key_ = private_key.compute_public_key();
    auto id = adnl::AdnlNodeIdShort{public_key_.compute_short_id()};
    td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(private_key), true,
                            [](td::Result<td::Unit> r) { r.ensure(); });
    td::actor::send_closure(adnl_, &adnl::Adnl::add_id, adnl::AdnlNodeIdFull{public_key_},
                            adnl::AdnlAddressList{}, static_cast<td::uint8>(0));
    td::actor::send_closure(adnl_, &adnl::Adnl::subscribe, id, std::string{},
                            std::make_unique<Queries>(actor_id(this)));
    td::actor::send_closure(adnl_, &adnl::Adnl::create_ext_server,
                            std::vector<adnl::AdnlNodeIdShort>{id}, std::vector<td::uint16>{port_},
                            [self = actor_id(this)](td::Result<td::actor::ActorOwn<adnl::AdnlExtServer>> r) {
                              td::actor::send_closure(self, &Transport::listening, r.move_as_ok());
                            });
  }
  void listening(td::actor::ActorOwn<adnl::AdnlExtServer> server) {
    server_ = std::move(server);
    td::IPAddress address;
    address.init_ipv4_port("127.0.0.1", port_).ensure();
    client_ = adnl::AdnlExtClient::create(adnl::AdnlNodeIdFull{public_key_}, address,
                                        std::make_unique<Ready>(actor_id(this)));
  }
  void ready() {
    if (started_) return;
    started_ = true;
    downloader_ = td::actor::create_actor<RemoteDownload>(
        "uno-remote-state", BlockIdExt{BlockId{2, shardIdAll, 1}},
        BlockIdExt{BlockId{masterchainId, shardIdAll, 1}}, UnsplitStateType{},
        adnl::AdnlNodeIdShort::zero(), overlay::OverlayIdShort{}, adnl::AdnlNodeIdShort::zero(),
        0, td::Timestamp::in(15), td::actor::ActorId<ValidatorManagerInterface>{},
        td::actor::ActorId<adnl::AdnlSenderInterface>{}, td::actor::ActorId<overlay::Overlays>{},
        td::actor::ActorId<adnl::Adnl>{}, client_.get(),
        [self = actor_id(this)](td::Result<fullnode::DownloadedPersistentState> r) {
          td::actor::send_closure(self, &Transport::downloaded, std::move(r));
        });
  }
  void query(td::BufferSlice data, td::Promise<td::BufferSlice> promise) {
    fetch_tl_prefix<tos_api::tosNode_query>(data, true).ensure();
    auto function = fetch_tl_object<tos_api::Function>(std::move(data), true).move_as_ok();
    if (function->get_id() == tos_api::tosNode_preparePersistentState::ID) {
      ++descriptions_;
      promise.set_value(create_serialize_tl_object<tos_api::tosNode_preparedState>());
    } else if (function->get_id() == tos_api::tosNode_getPersistentStateSizeV2::ID) {
      ++sizes_;
      promise.set_value(create_serialize_tl_object<tos_api::tosNode_persistentStateSize>(source_.size()));
    } else if (function->get_id() == tos_api::tosNode_downloadPersistentStateSliceV2::ID) {
      auto& request = static_cast<tos_api::tosNode_downloadPersistentStateSliceV2&>(*function);
      ASSERT_EQ(request.state_->block_->workchain_, 2);
      ASSERT_EQ(static_cast<td::uint64>(request.offset_), sent_);
      ASSERT_TRUE(request.max_size_ > 0);
      auto count = std::min<std::size_t>(request.max_size_, source_.size() - sent_);
      ASSERT_TRUE(count > 1);
      if (truncate_ && slices_ == 0) --count;
      promise.set_value(td::BufferSlice(source_.as_slice().substr(sent_, count)));
      sent_ += count;
      ++slices_;
    } else {
      promise.set_error(td::Status::Error("unexpected snapshot query"));
    }
  }
  void downloaded(td::Result<fullnode::DownloadedPersistentState> r) {
    ASSERT_EQ(descriptions_, 1u);
    ASSERT_EQ(sizes_, 1u);
    ASSERT_TRUE(slices_ > 0);
    if (truncate_) {
      ASSERT_EQ(slices_, 1u);
      ASSERT_TRUE(r.is_error());
      ASSERT_EQ(r.error().code(), ErrorCode::protoviolation);
      result_ = r.move_as_error();
    } else {
      auto downloaded = r.move_as_ok();
      ASSERT_TRUE(downloaded.is_memory());
      ASSERT_EQ(sent_, source_.size());
      ASSERT_EQ(slices_, (source_.size() + (1u << 21) - 1) / (1u << 21));
      ASSERT_TRUE(downloaded.memory().data.as_slice() == source_.as_slice());
      result_ = downloaded.memory().data.clone();
    }
    completed_.store(true, std::memory_order_release);
    td::actor::SchedulerContext::get().stop();
  }
  void alarm() override { LOG(FATAL) << "UNO TCP snapshot transfer timed out"; }
 private:
  td::BufferSlice source_;
  td::Result<td::BufferSlice>& result_;
  std::atomic<bool>& completed_;
  bool truncate_;
  td::uint16 port_ = 0;
  bool started_ = false;
  std::size_t sent_ = 0;
  unsigned descriptions_ = 0, sizes_ = 0, slices_ = 0;
  PublicKey public_key_;
  td::actor::ActorOwn<keyring::Keyring> keyring_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<adnl::AdnlExtServer> server_;
  td::actor::ActorOwn<adnl::AdnlExtClient> client_;
  td::actor::ActorOwn<RemoteDownload> downloader_;
};
}  // namespace

td::Result<td::BufferSlice> download_uno_snapshot_over_tcp(td::BufferSlice source, bool truncate) {
  td::Result<td::BufferSlice> result = td::Status::Error("download did not complete");
  std::atomic<bool> completed{false};
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<Transport> actor;
  scheduler.run_in_context([&] {
    actor = td::actor::create_actor<Transport>("uno-snapshot-tcp", std::move(source), result, completed, truncate);
  });
  scheduler.run();
  ASSERT_TRUE(completed.load(std::memory_order_acquire));
  return result;
}
