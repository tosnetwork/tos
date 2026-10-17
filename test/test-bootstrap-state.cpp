/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include "td/actor/TestScheduler.h"
#include "td/actor/coro_utils.h"
#include "td/utils/tests.h"
#include "validator/bootstrap-state.h"
#include "validator/downloaders/download-state.hpp"

#include "test-bootstrap-state-fixture.h"

namespace {
using namespace tos;
using namespace tos::validator;

BlockIdExt block_id(WorkchainId workchain, td::uint8 marker, BlockSeqno seqno = 10) {
  td::Bits256 root, file;
  root.as_slice().fill(marker);
  file.as_slice().fill(static_cast<td::uint8>(marker + 1));
  return {workchain, shardIdAll, seqno, root, file};
}

struct Archive {
  struct File {
    std::string bytes{"persistent state"};
    td::uint64 registered_size{bytes.size()};
    bool registered{true};
    bool readable{true};
  };

  BlockIdExt mc = block_id(masterchainId, 1);
  BlockIdExt shard = block_id(basechainId, 3);
  td::Ref<PersistentStateDescription> description{true};
  std::map<std::string, File> files;
  std::map<BlockIdExt, RootHash> proof_roots;
  std::set<BlockIdExt> zero_states;
  std::size_t reads{0};

  Archive() {
    description.write().masterchain_id = mc;
    description.write().start_time = 1000;
    description.write().end_time = 10000;
    description.write().shard_blocks = {{shard, 0}};
    proof_roots.emplace(mc, mc.root_hash);
    proof_roots.emplace(shard, shard.root_hash);
    files.emplace(key(mc, UnsplitStateType{}), File{});
    files.emplace(key(shard, UnsplitStateType{}), File{});
  }

  std::string key(BlockIdExt block, PersistentStateType type) const {
    return block.to_str() + ":" + std::to_string(persistent_state_to_effective_shard(block.shard_full(), type));
  }

  BootstrapStateReader reader() {
    BootstrapStateReader source;
    source.proof_state_root = [this](BlockIdExt block) -> td::actor::Task<RootHash> {
      ++reads;
      auto it = proof_roots.find(block);
      if (it == proof_roots.end()) {
        co_return td::Status::Error("archived proof is absent");
      }
      co_return it->second;
    };
    source.state_size = [this](BlockIdExt block, BlockIdExt anchor,
                               PersistentStateType type) -> td::actor::Task<td::uint64> {
      ++reads;
      auto it = files.find(key(block, type));
      if (anchor != mc || it == files.end() || !it->second.registered) {
        co_return td::Status::Error("state file is not registered");
      }
      co_return it->second.registered_size;
    };
    source.state_slice = [this](BlockIdExt block, BlockIdExt anchor, PersistentStateType type, td::int64 offset,
                                td::int64 length) -> td::actor::Task<td::BufferSlice> {
      ++reads;
      auto it = files.find(key(block, type));
      if (anchor != mc || it == files.end() || !it->second.registered || !it->second.readable) {
        co_return td::Status::Error("state file cannot be served");
      }
      if (offset < 0 || length < 0) {
        co_return td::Status::Error("invalid slice");
      }
      if (static_cast<td::uint64>(offset) >= it->second.bytes.size()) {
        co_return td::BufferSlice{};
      }
      co_return td::BufferSlice(
          it->second.bytes.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(length)));
    };
    source.zero_state = [this](BlockIdExt block) -> td::actor::Task<td::Unit> {
      ++reads;
      if (zero_states.count(block) == 0) {
        co_return td::Status::Error("zero state cannot be served");
      }
      co_return td::Unit{};
    };
    return source;
  }
};

BootstrapStateStatus run_readiness(std::shared_ptr<Archive> archive, UnixTime now = 2000,
                                   bool expired_deadline = false) {
  td::actor::TestScheduler scheduler;
  std::optional<BootstrapStateStatus> result;
  scheduler.run([&]() -> td::actor::Task<> {
    auto query = check_bootstrap_state(archive->description, 604800, now, archive->reader(),
                                       td::Timestamp::in(expired_deadline ? -1.0 : 10.0))
                     .start();
    co_await scheduler.wait_sync_work();
    result = co_await std::move(query);
    co_return td::Unit{};
  });
  CHECK(result.has_value());
  return std::move(*result);
}

std::shared_ptr<Archive> split_archive() {
  auto archive = std::make_shared<Archive>();
  auto fixture = bootstrap_test::make_split_fixture(TOS_BOOTSTRAP_GENESIS);
  archive->description.write().shard_blocks = {{archive->shard, 1}};
  archive->proof_roots[archive->shard] = fixture.state_root_hash;
  archive->files.erase(archive->key(archive->shard, UnsplitStateType{}));
  archive->files.emplace(archive->key(archive->shard, SplitPersistentStateType{}),
                         Archive::File{fixture.header_boc.as_slice().str(), fixture.header_boc.size()});
  archive->files.emplace(archive->key(archive->shard, SplitAccountStateType{fixture.effective_shard}),
                         Archive::File{fixture.part_boc.as_slice().str(), fixture.part_boc.size()});
  return archive;
}

}  // namespace

TEST(BootstrapState, RequiresEveryRegisteredSnapshot) {
  auto archive = std::make_shared<Archive>();
  auto ready = run_readiness(archive);
  ASSERT_TRUE(ready.ready);
  ASSERT_EQ("ready", ready.reason);
  ASSERT_TRUE(ready.id == archive->mc);
  ASSERT_EQ(1000u, ready.gen_utime);
  ASSERT_EQ(10000u, ready.expires_at);
  ASSERT_EQ(604800.0, ready.archive_ttl);

  archive->files.at(archive->key(archive->mc, UnsplitStateType{})).registered = false;
  ASSERT_TRUE(!run_readiness(archive).ready);
  archive->files.at(archive->key(archive->mc, UnsplitStateType{})).registered = true;
  archive->files.erase(archive->key(archive->shard, UnsplitStateType{}));
  auto missing = run_readiness(archive);
  ASSERT_TRUE(!missing.ready);
  ASSERT_EQ("state_unavailable", missing.reason);
}

TEST(BootstrapState, CachedSizeDoesNotProveReadableFile) {
  auto archive = std::make_shared<Archive>();
  auto &file = archive->files.at(archive->key(archive->shard, UnsplitStateType{}));
  file.readable = false;
  ASSERT_TRUE(!run_readiness(archive).ready);
  file.readable = true;
  file.bytes.resize(1);
  ASSERT_TRUE(!run_readiness(archive).ready);
  file.registered_size = 1;
  ASSERT_TRUE(run_readiness(archive).ready);
}

TEST(BootstrapState, RequiresArchivedShardProof) {
  auto archive = std::make_shared<Archive>();
  archive->proof_roots.erase(archive->shard);
  auto missing = run_readiness(archive);
  ASSERT_TRUE(!missing.ready);
  ASSERT_EQ("proof_unavailable", missing.reason);
  archive->proof_roots.emplace(archive->shard, archive->shard.root_hash);
  ASSERT_TRUE(run_readiness(archive).ready);
}

TEST(BootstrapState, SplitHeaderRequiresOnlyNonemptyParts) {
  auto archive = split_archive();
  ASSERT_EQ(3u, archive->files.size());
  ASSERT_TRUE(run_readiness(archive).ready);
  auto fixture = bootstrap_test::make_split_fixture(TOS_BOOTSTRAP_GENESIS);
  archive->files.erase(archive->key(archive->shard, SplitAccountStateType{fixture.effective_shard}));
  auto missing_part = run_readiness(archive);
  ASSERT_TRUE(!missing_part.ready);
  ASSERT_EQ("state_unavailable", missing_part.reason);
}

TEST(BootstrapState, RejectsMismatchedSplitHeader) {
  auto archive = split_archive();
  archive->proof_roots[archive->shard] = archive->shard.root_hash;
  auto mismatch = run_readiness(archive);
  ASSERT_TRUE(!mismatch.ready);
  ASSERT_EQ("invalid_state", mismatch.reason);
}

TEST(BootstrapState, ZeroSeqnoShardUsesZeroStateServingPath) {
  auto archive = std::make_shared<Archive>();
  auto zero = block_id(basechainId, 5, 0);
  archive->description.write().shard_blocks = {{zero, 0}};
  ASSERT_TRUE(!run_readiness(archive).ready);
  archive->zero_states.insert(zero);
  ASSERT_TRUE(run_readiness(archive).ready);
}

TEST(BootstrapState, ExpiryAndDeadlineRefuseBeforeArchiveWork) {
  auto expired = std::make_shared<Archive>();
  auto expiry = run_readiness(expired, 10000);
  ASSERT_TRUE(!expiry.ready);
  ASSERT_EQ("snapshot_expired", expiry.reason);
  ASSERT_EQ(0u, expired->reads);
  auto timeout = run_readiness(expired, 2000, true);
  ASSERT_TRUE(!timeout.ready);
  ASSERT_EQ("timeout", timeout.reason);
  ASSERT_EQ(0u, expired->reads);
}

TEST(BootstrapState, ResourceBudgetsRefuseBeforeUnboundedReads) {
  auto manifest = std::make_shared<Archive>();
  manifest->description.write().shard_blocks.assign(4096, {manifest->shard, 0});
  auto too_many = run_readiness(manifest);
  ASSERT_TRUE(!too_many.ready);
  ASSERT_EQ("resource_limit", too_many.reason);
  ASSERT_EQ(0u, manifest->reads);

  auto header = std::make_shared<Archive>();
  header->description.write().shard_blocks = {{header->shard, 1}};
  header->files.erase(header->key(header->shard, UnsplitStateType{}));
  constexpr std::size_t oversized_header = (4U << 20) + 1;
  header->files.emplace(header->key(header->shard, SplitPersistentStateType{}),
                        Archive::File{std::string(oversized_header, 'x'), oversized_header});
  auto too_large = run_readiness(header);
  ASSERT_TRUE(!too_large.ready);
  ASSERT_EQ("resource_limit", too_large.reason);
  // Two proofs, two registered sizes and four one-byte probes. The oversized
  // header must never reach the whole-header read or BOC parser.
  ASSERT_EQ(8u, header->reads);
}

TEST(BootstrapState, DeadlineRespondsWhileReadIsStalledAndKeepsAdmissionLease) {
  struct Lease {
    explicit Lease(unsigned &active) : active_(active) {
      ++active_;
    }
    ~Lease() {
      --active_;
    }
    unsigned &active_;
  };
  auto archive = std::make_shared<Archive>();
  td::actor::TestScheduler scheduler;
  unsigned active = 0;
  std::optional<td::Promise<td::uint64>> stalled;
  bool completed = false;
  scheduler.run([&]() -> td::actor::Task<> {
    auto reader = archive->reader();
    reader.lease = std::make_shared<Lease>(active);
    reader.state_size = [&](BlockIdExt, BlockIdExt, PersistentStateType) -> td::actor::Task<td::uint64> {
      auto [pending, promise] = td::actor::StartedTask<td::uint64>::make_bridge();
      stalled = std::move(promise);
      co_return co_await std::move(pending);
    };
    auto query =
        check_bootstrap_state(archive->description, 604800, 2000, std::move(reader), td::Timestamp::in(1)).start();
    co_await scheduler.wait_sync_work();
    ASSERT_TRUE(stalled.has_value());
    ASSERT_EQ(1u, active);
    scheduler.advance_time(1.0);
    co_await scheduler.wait_sync_work();
    auto result = co_await std::move(query);
    ASSERT_TRUE(!result.ready);
    ASSERT_EQ("timeout", result.reason);
    ASSERT_EQ(1u, active);
    stalled->set_value(16);
    stalled.reset();
    co_await scheduler.wait_sync_work();
    ASSERT_EQ(0u, active);
    ASSERT_EQ(1u, archive->reads);  // Only the proof read; no file read starts after the deadline.
    completed = true;
    co_return td::Unit{};
  });
  ASSERT_TRUE(completed);
}
