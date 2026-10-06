// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#include <filesystem>

#include "auto/tl/lite_api.hpp"
#include "quic/quic-sender.h"
#include "td/actor/TestScheduler.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "tl-utils/lite-utils.hpp"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/liteserver-cache.hpp"
#include "validator/impl/liteserver.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager.hpp"
#include "vm/boc.h"

namespace tos::validator {

// Exercise production manager handlers without starting databases or networking.
class ExtMessageManagerTestHarness final : public ValidatorManagerImpl {
 public:
  explicit ExtMessageManagerTestHarness(td::Ref<ValidatorManagerOptions> options)
      : ValidatorManagerImpl(std::move(options), "", {}, {}, {}, {}, {}) {
  }
  void start_up() override {
  }
  td::actor::Task<> initialize(td::Ref<MasterchainState> state, std::shared_ptr<adnl::AdnlExtByteBudget> bytes) {
    ext_message_pool_ = td::actor::create_actor<ExtMessagePool>("shared-manager-pool", opts_, actor_id(this), bytes);
    co_await td::actor::ask(ext_message_pool_, &ExtMessagePool::update_last_masterchain_state, std::move(state));
    started_ = true;
    co_return td::Unit{};
  }
  td::actor::Task<> verify_exhausted() {
    auto stats = co_await td::actor::ask(ext_message_pool_, &ExtMessagePool::prepare_stats);
    bool found = false;
    for (const auto& stat : stats) {
      if (stat.first == "ext_msg_admission_work") {
        EXPECT_EQ(stat.second, "available:0 supported:true");
        found = true;
      }
    }
    EXPECT(found);
    co_return td::Unit{};
  }
};

TEST(ExtMessageManager, BroadcastQueryAndLiteServerShareWorkBudget) {
  auto file =
      td::read_file((std::filesystem::path(__FILE__).parent_path() / "pq-native/data/c04-pq-genesis.boc").string());
  ASSERT_TRUE(file.is_ok());
  auto decoded = vm::std_boc_deserialize(file.move_as_ok());
  ASSERT_TRUE(decoded.is_ok());
  auto root = decoded.move_as_ok();
  BlockIdExt id{masterchainId, shardIdAll, 0, root->get_hash().bits(), FileHash::zero()};
  auto loaded = MasterchainStateQ::fetch(id, td::BufferSlice{}, root);
  ASSERT_TRUE(loaded.is_ok());
  td::Ref<MasterchainState> state = loaded.move_as_ok();
  auto config = block::ConfigInfo::extract_config(root, id, 0xFFFF);
  ASSERT_TRUE(config.is_ok());
  ExtMessageWorkProfile profile;
  profile.config_root = config.ok()->get_root_cell()->get_hash().bits();
  profile.capacity = 3;
  profile.refill_units = 1;
  profile.refill_interval_ns = std::numeric_limits<std::int64_t>::max();
  profile.attempt_units = 1;
  profile.max_bytes = 65535;
  profile.max_depth = 512;
  auto options = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
  ASSERT_TRUE(options.write().set_ext_message_work_profile(profile).is_ok());
  auto bytes = std::make_shared<adnl::AdnlExtByteBudget>(65535);
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<> {
    auto manager = td::actor::create_actor<ExtMessageManagerTestHarness>("admission-manager", options);
    auto cache = td::actor::create_actor<LiteServerCacheImpl>("admission-cache");
    co_await td::actor::ask(manager, &ExtMessageManagerTestHarness::initialize, state, bytes);
    for (unsigned i = 0; i < 6; ++i) {
      td::optional<PublicKeyHash> peer;
      if (i % 2) {
        auto hash = td::Bits256::zero();
        hash.data()[0] = static_cast<unsigned char>(i);
        peer = PublicKeyHash{hash};
      }
      auto input = td::BufferSlice{"malformed input " + std::to_string(i)};
      std::string error;
      if (i % 3 == 0) {
        auto result = co_await td::actor::ask(manager, &ValidatorManager::new_external_message_broadcast,
                                              std::move(input), 0, peer)
                          .wrap();
        ASSERT_TRUE(result.is_error());
        error = result.error().message().str();
      } else if (i % 3 == 1) {
        auto result =
            co_await td::actor::ask(manager, &ValidatorManager::new_external_message_query, std::move(input), peer)
                .wrap();
        ASSERT_TRUE(result.is_error());
        error = result.error().message().str();
      } else {
        auto wire = create_serialize_tl_object<lite_api::liteServer_sendMessage>(std::move(input));
        auto [pending, promise] = td::actor::StartedTask<td::BufferSlice>::make_bridge();
        LiteQuery::run_query(std::move(wire), manager.get(), cache.get(), peer, std::move(promise));
        auto result = co_await std::move(pending).wrap();
        ASSERT_TRUE(result.is_error());
        error = result.error().message().str();
      }
      const char* expected =
          i < 3 ? "cannot deserialize bag-of-cells" : "external message admission work budget exhausted";
      EXPECT(error.find(expected) != std::string::npos);
      EXPECT_EQ(bytes->used(), 0u);
    }
    co_await td::actor::ask(manager, &ExtMessageManagerTestHarness::verify_exhausted);
    co_return td::Unit{};
  });
}
}  // namespace tos::validator
