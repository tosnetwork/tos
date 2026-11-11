// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#include <filesystem>

#include "auto/tl/lite_api.hpp"
#include "quic/quic-sender.h"
#include "td/actor/TestScheduler.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "validator/fabric.h"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/liteserver-cache.hpp"
#include "validator/impl/liteserver.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager.hpp"
#include "vm/boc.h"

namespace tos::validator {

// The liteserver's default head and its shard client's state differ while the shard client
// catches up: do_get_last_liteserver_state() may already answer with a newer masterchain
// state. Here the two are made distinct on purpose, so the test sees which one each
// getMasterchainInfo mode is answered from.
class ShardClientStateManagerProbe final : public ValidatorManagerImpl {
 public:
  explicit ShardClientStateManagerProbe(td::Ref<ValidatorManagerOptions> options)
      : ValidatorManagerImpl(std::move(options), "", {}, {}, {}, {}, {}) {
  }
  void start_up() override {
  }
  // The advertised head, as do_get_last_liteserver_state() returns it after its fallback.
  void get_last_liteserver_state_block(td::Promise<std::pair<td::Ref<MasterchainState>, BlockIdExt>> promise) override {
    promise.set_value(std::pair<td::Ref<MasterchainState>, BlockIdExt>{state_, advertised_});
  }
  td::actor::Task<> set_heads(td::Ref<MasterchainState> state, BlockIdExt advertised) {
    state_ = std::move(state);
    advertised_ = advertised;
    co_return td::Unit{};
  }
  // What update_shard_client_block_handle() leaves behind once the shard client has applied `applied`.
  td::actor::Task<> set_shard_client(BlockIdExt applied) {
    shard_client_handle_ = create_empty_block_handle(applied);
    shard_client_state_ = state_;
    co_return td::Unit{};
  }

 private:
  td::Ref<MasterchainState> state_;
  BlockIdExt advertised_;
};

namespace {

BlockIdExt masterchain_id(BlockSeqno seqno, unsigned char tag) {
  auto hash = td::Bits256::zero();
  hash.data()[0] = tag;
  return BlockIdExt{masterchainId, shardIdAll, seqno, hash, FileHash::zero()};
}

// Started on the caller's turn, as a production liteserver connection starts a query.
td::actor::StartedTask<td::BufferSlice> query(td::actor::ActorId<ShardClientStateManagerProbe> manager,
                                              td::actor::ActorId<LiteServerCache> cache, td::BufferSlice wire) {
  auto [pending, promise] = td::actor::StartedTask<td::BufferSlice>::make_bridge();
  LiteQuery::run_query(std::move(wire), manager, cache, {}, std::move(promise));
  return std::move(pending);
}

td::actor::StartedTask<td::BufferSlice> info_ext(td::actor::ActorId<ShardClientStateManagerProbe> manager,
                                                 td::actor::ActorId<LiteServerCache> cache, int mode) {
  return query(manager, cache, create_serialize_tl_object<lite_api::liteServer_getMasterchainInfoExt>(mode));
}

td::Result<tl_object_ptr<lite_api::liteServer_masterchainInfoExt>> parse_ext(td::Result<td::BufferSlice> reply) {
  if (reply.is_error()) {
    return reply.move_as_error();
  }
  return fetch_tl_object<lite_api::liteServer_masterchainInfoExt>(reply.move_as_ok(), true);
}

}  // namespace

TEST(LiteServerShardClientState, ModeOneAnswersFromTheShardClientState) {
  auto file =
      td::read_file((std::filesystem::path(__FILE__).parent_path() / "pq-native/data/c04-pq-genesis.boc").string());
  ASSERT_TRUE(file.is_ok());
  auto decoded = vm::std_boc_deserialize(file.move_as_ok());
  ASSERT_TRUE(decoded.is_ok());
  auto root = decoded.move_as_ok();
  BlockIdExt genesis{masterchainId, shardIdAll, 0, root->get_hash().bits(), FileHash::zero()};
  auto loaded = MasterchainStateQ::fetch(genesis, td::BufferSlice{}, root);
  ASSERT_TRUE(loaded.is_ok());
  td::Ref<MasterchainState> state = loaded.move_as_ok();
  const auto advertised = masterchain_id(7, 0xa7);
  const auto applied = masterchain_id(5, 0x5a);

  auto options = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
  bool completed = false;  // a coroutine that stalls must fail the test, not end it quietly
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<> {
    auto manager = td::actor::create_actor<ShardClientStateManagerProbe>("shard-client-state-manager", options);
    auto cache = td::actor::create_actor<LiteServerCacheImpl>("shard-client-state-cache");
    co_await td::actor::ask(manager, &ShardClientStateManagerProbe::set_heads, state, advertised);

    // Before the shard client has applied anything, mode 1 is refused as not ready.
    auto early = parse_ext(co_await info_ext(manager.get(), cache.get(), 1).wrap());
    ASSERT_TRUE(early.is_error());
    EXPECT(early.error().message().str().find("shard client state is not ready") != std::string::npos);

    co_await td::actor::ask(manager, &ShardClientStateManagerProbe::set_shard_client, applied);

    // Mode 0 and the legacy query keep answering from the advertised head.
    auto by_default = parse_ext(co_await info_ext(manager.get(), cache.get(), 0).wrap());
    ASSERT_TRUE(by_default.is_ok());
    EXPECT_EQ(by_default.ok()->mode_, 0);
    EXPECT(create_block_id(by_default.ok()->last_) == advertised);
    EXPECT((by_default.ok()->capabilities_ & 8) != 0);
    auto legacy_reply = co_await query(manager.get(), cache.get(),
                                       create_serialize_tl_object<lite_api::liteServer_getMasterchainInfo>())
                            .wrap();
    ASSERT_TRUE(legacy_reply.is_ok());
    auto legacy = fetch_tl_object<lite_api::liteServer_masterchainInfo>(legacy_reply.move_as_ok(), true);
    ASSERT_TRUE(legacy.is_ok());
    EXPECT(create_block_id(legacy.ok()->last_) == advertised);

    // Mode 1 answers from the shard client's state, not the advertised head.
    auto from_shard_client = parse_ext(co_await info_ext(manager.get(), cache.get(), 1).wrap());
    ASSERT_TRUE(from_shard_client.is_ok());
    EXPECT_EQ(from_shard_client.ok()->mode_, 1);
    EXPECT(create_block_id(from_shard_client.ok()->last_) == applied);

    // Every other mode bit stays refused.
    for (int mode : {2, 3, 4, 0x40000000}) {
      auto refused = parse_ext(co_await info_ext(manager.get(), cache.get(), mode).wrap());
      ASSERT_TRUE(refused.is_error());
      EXPECT(refused.error().message().str().find("unsupported getMasterchainInfo mode") != std::string::npos);
    }
    completed = true;
    co_return td::Unit{};
  });
  ASSERT_TRUE(completed);
}
}  // namespace tos::validator
