/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The bounded archive import attempt of the startup catch-up mode, exercised on
// the production ArchiveImporter. Only its external children are substituted
// (archive downloads, proof checks, applies, state and handle reads); the package
// files are real, and the settlement, draining, joining and outcome code is the
// importer's own.

#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <vector>

#include "common/checksum.h"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "validator/db/fileref.hpp"
#include "validator/db/package.hpp"
#include "validator/fabric.h"
#include "validator/impl/shard.hpp"
#include "validator/import-db-slice.hpp"
#include "validator/validator-options.hpp"
#include "vm/cells.h"

namespace tos::validator {
namespace {

using startup_catchup::ImportOutcome;

constexpr BlockSeqno kLocal = 10;  // local masterchain and shard-client seqno
constexpr BlockSeqno kTop = 15;    // the archive holds masterchain blocks up to this

td::Bits256 h(td::Slice s) {
  return td::sha256_bits256(s);
}
std::string mc_data(BlockSeqno s) {
  return PSTRING() << "mc-data-" << s;
}
BlockIdExt mc_id(BlockSeqno s) {
  return BlockIdExt{masterchainId, shardIdAll, s, h(PSTRING() << "mc-root-" << s), h(mc_data(s))};
}
std::string sh_data(ShardId shard, BlockSeqno s) {
  return PSTRING() << "sh-data-" << shard << "-" << s;
}
BlockIdExt sh_id(ShardId shard, BlockSeqno s) {
  return BlockIdExt{basechainId, shard, s, h(PSTRING() << "sh-root-" << shard << "-" << s), h(sh_data(shard, s))};
}

struct Layout {
  std::vector<ShardId> shards{shardIdAll};
  td::uint32 monitor_min_split = 0;
};

class FakeMcState : public MasterchainStateQ {
 public:
  FakeMcState(BlockSeqno seqno, Layout layout)
      : MasterchainStateQ(mc_id(seqno), vm::CellBuilder{}.finalize_novm()), layout_(std::move(layout)) {
  }
  bool get_old_mc_block_id(BlockSeqno seqno, BlockIdExt& blkid, LogicalTime* = nullptr) const override {
    if (seqno > get_seqno()) {
      return false;
    }
    blkid = mc_id(seqno);
    return true;
  }
  bool check_old_mc_block_id(const BlockIdExt& blkid, bool strict = false) const override {
    if (!blkid.is_masterchain() || blkid.seqno() > get_seqno() || (strict && blkid.seqno() == get_seqno())) {
      return false;
    }
    return blkid == mc_id(blkid.seqno());
  }
  std::vector<td::Ref<McShardHash>> get_shards() const override {
    std::vector<td::Ref<McShardHash>> out;
    for (auto shard : layout_.shards) {
      out.push_back(td::Ref<McShardHash>{td::make_ref<block::McShardHash>(sh_id(shard, get_seqno()), 0, 0)});
    }
    return out;
  }
  td::Ref<McShardHash> get_shard_from_config(ShardIdFull shard, bool) const override {
    for (auto& s : get_shards()) {
      if (s->shard() == shard) {
        return s;
      }
    }
    return {};
  }
  td::uint32 monitor_min_split_depth(WorkchainId) const override {
    return layout_.monitor_min_split;
  }
  td::uint32 persistent_state_split_depth(WorkchainId) const override {
    return 0;
  }
  bool is_key_state() const override {
    return false;
  }

 private:
  Layout layout_;
};

class FakeBlock : public BlockData {
 public:
  explicit FakeBlock(BlockIdExt id) : id_(id) {
  }
  td::BufferSlice data() const override {
    return {};
  }
  FileHash file_hash() const override {
    return id_.file_hash;
  }
  BlockIdExt block_id() const override {
    return id_;
  }
  td::Ref<vm::Cell> root_cell() const override {
    return {};
  }

 private:
  BlockIdExt id_;
};

// The substituted children and everything observed about them. Every hook call is
// counted in `inflight` until its promise completes, independently of the
// importer's own accounting.
// Hooks complete promises while holding the lock, and completing a tracked promise
// takes it again.
using WorldLock = std::lock_guard<std::recursive_mutex>;

struct World {
  std::recursive_mutex mu;
  std::string tmp;
  Layout layout;
  std::set<BlockIdExt> applied;
  int inflight = 0;
  int inflight_at_publish = -1;
  bool attempt_active = false;
  bool overlap_seen = false;
  int mc_checks = 0;
  std::vector<double> mc_check_timeout_seconds;
  std::vector<std::string> delivered_files;
  double clock_offset = 0;

  // Behaviours; the defaults succeed at once.
  std::function<void(ShardIdFull, td::Promise<std::string>)> on_archive;
  std::function<void(BlockIdExt, td::Promise<td::Unit>)> on_apply;
  std::function<void(BlockIdExt, td::Promise<BlockHandle>)> on_link_check;

  std::vector<td::Promise<std::string>> held_archives;
  std::vector<td::Promise<td::Unit>> held_applies;
  std::vector<td::Promise<BlockHandle>> held_link_checks;

  bool contains(BlockIdExt id) {
    return applied.count(id) > 0;
  }

  // A real package file with the blocks of the given prefix.
  std::string make_package(ShardIdFull prefix) {
    auto path = PSTRING() << tmp << "/slice-" << td::Random::fast_uint32() << ".pack";
    auto pkg = Package::open(path, false, true).move_as_ok();
    for (BlockSeqno s = kLocal + 1; s <= kTop; ++s) {
      if (prefix.is_masterchain()) {
        pkg.append(fileref::Proof{mc_id(s)}.filename(), td::Slice("mc-proof"), false);
        pkg.append(fileref::Block{mc_id(s)}.filename(), mc_data(s), false);
      } else {
        for (auto shard : layout.shards) {
          if (!shard_intersects(prefix, ShardIdFull{basechainId, shard})) {
            continue;
          }
          pkg.append(fileref::ProofLink{sh_id(shard, s)}.filename(), td::Slice("sh-proof"), false);
          pkg.append(fileref::Block{sh_id(shard, s)}.filename(), sh_data(shard, s), false);
        }
      }
    }
    pkg.sync();
    delivered_files.push_back(path);
    return path;
  }
};

template <class T>
td::Promise<T> tracked(std::shared_ptr<World> world, td::Promise<T> inner) {
  {
    WorldLock lock(world->mu);
    world->inflight++;
  }
  return [world, inner = std::move(inner)](td::Result<T> R) mutable {
    {
      WorldLock lock(world->mu);
      world->inflight--;
    }
    inner.set_result(std::move(R));
  };
}

BlockHandle make_handle(World& world, BlockIdExt id) {
  auto handle = create_empty_block_handle(id);
  handle->set_merge(false);
  handle->set_split(false);
  if (id.seqno() > 0) {
    handle->set_prev(id.is_masterchain() ? mc_id(id.seqno() - 1) : sh_id(id.id.shard, id.seqno() - 1));
  }
  if (id.seqno() <= kLocal || world.contains(id)) {
    handle->set_applied();
  }
  handle->flushed_upto(handle->version());
  return handle;
}

class TestImporter : public ArchiveImporter {
 public:
  template <class... Args>
  TestImporter(std::shared_ptr<World> world, Args&&... args)
      : ArchiveImporter(std::forward<Args>(args)...), world_(std::move(world)) {
  }
  void start_up() override {
    {
      WorldLock lock(world_->mu);
      if (world_->attempt_active || world_->inflight != 0) {
        world_->overlap_seen = true;
      }
      world_->attempt_active = true;
    }
    ArchiveImporter::start_up();
  }

 protected:
  double clock_now() const override {
    WorldLock lock(world_->mu);
    return td::Time::now() + world_->clock_offset;
  }
  void request_archive(BlockSeqno, ShardIdFull prefix, td::Timestamp, td::Promise<std::string> promise) override {
    auto p = tracked(world_, std::move(promise));
    std::function<void(ShardIdFull, td::Promise<std::string>)> behaviour;
    {
      WorldLock lock(world_->mu);
      behaviour = world_->on_archive;
    }
    if (behaviour) {
      behaviour(prefix, std::move(p));
      return;
    }
    std::string path;
    {
      WorldLock lock(world_->mu);
      path = world_->make_package(prefix);
    }
    p.set_value(std::move(path));
  }
  td::Result<td::Ref<Proof>> parse_proof(BlockIdExt, td::BufferSlice) override {
    return td::Ref<Proof>{};
  }
  td::Result<td::Ref<ProofLink>> parse_proof_link(BlockIdExt, td::BufferSlice) override {
    return td::Ref<ProofLink>{};
  }
  td::Result<td::Ref<BlockData>> parse_block(BlockIdExt id, td::BufferSlice) override {
    return td::Ref<BlockData>{td::make_ref<FakeBlock>(id)};
  }
  void request_masterchain_proof_check(BlockIdExt id, td::Ref<Proof>, td::Ref<MasterchainState>, bool,
                                       td::Timestamp timeout, td::Promise<BlockHandle> promise) override {
    auto p = tracked(world_, std::move(promise));
    BlockHandle handle;
    {
      WorldLock lock(world_->mu);
      world_->mc_checks++;
      world_->mc_check_timeout_seconds.push_back(timeout.at() - td::Time::now());
      handle = make_handle(*world_, id);
    }
    p.set_value(std::move(handle));
  }
  void request_proof_link_check(BlockIdExt id, td::Ref<ProofLink>, td::Timestamp,
                                td::Promise<BlockHandle> promise) override {
    auto p = tracked(world_, std::move(promise));
    std::function<void(BlockIdExt, td::Promise<BlockHandle>)> behaviour;
    {
      WorldLock lock(world_->mu);
      behaviour = world_->on_link_check;
    }
    if (behaviour) {
      behaviour(id, std::move(p));
      return;
    }
    BlockHandle handle;
    {
      WorldLock lock(world_->mu);
      handle = make_handle(*world_, id);
    }
    p.set_value(std::move(handle));
  }
  void request_apply(BlockIdExt id, td::Ref<BlockData>, BlockIdExt, td::Timestamp,
                     td::Promise<td::Unit> promise) override {
    auto p = tracked(world_, std::move(promise));
    std::function<void(BlockIdExt, td::Promise<td::Unit>)> behaviour;
    {
      WorldLock lock(world_->mu);
      behaviour = world_->on_apply;
    }
    if (behaviour) {
      behaviour(id, std::move(p));
      return;
    }
    {
      WorldLock lock(world_->mu);
      world_->applied.insert(id);
    }
    p.set_value(td::Unit());
  }
  void request_state_download(BlockIdExt, BlockIdExt, td::uint32, td::Timestamp,
                              td::Promise<td::Ref<ShardState>> promise) override {
    tracked(world_, std::move(promise)).set_error(td::Status::Error("state download is not part of these tests"));
  }
  void request_masterchain_state(BlockHandle handle, td::Promise<td::Ref<ShardState>> promise) override {
    auto p = tracked(world_, std::move(promise));
    p.set_value(td::Ref<ShardState>{td::make_ref<FakeMcState>(handle->id().seqno(), world_->layout)});
  }
  void request_masterchain_state_short(BlockIdExt id, td::Promise<td::Ref<ShardState>> promise) override {
    auto p = tracked(world_, std::move(promise));
    p.set_value(td::Ref<ShardState>{td::make_ref<FakeMcState>(id.seqno(), world_->layout)});
  }
  void request_block_handle(BlockIdExt id, bool, td::Promise<BlockHandle> promise) override {
    auto p = tracked(world_, std::move(promise));
    BlockHandle handle;
    {
      WorldLock lock(world_->mu);
      handle = make_handle(*world_, id);
    }
    p.set_value(std::move(handle));
  }

 private:
  std::shared_ptr<World> world_;
};

struct Published {
  BlockSeqno masterchain_top = 0;
  BlockSeqno coherent = 0;
  bool error = false;
  int error_code = 0;
  std::string error_text;
  double at = 0;
};

class Harness {
 public:
  explicit Harness(Layout layout = {}) : scheduler_({1}) {
    world = std::make_shared<World>();
    world->layout = layout;
    world->tmp = td::mkdtemp("/tmp", "startup-catchup-importer").move_as_ok();
  }
  ~Harness() {
    scheduler_.run_in_context([&] {
      importer_.reset();
      td::actor::SchedulerContext::get().stop();
    });
    while (scheduler_.run(1)) {
    }
    td::rmrf(world->tmp).ignore();
  }

  void start_bounded(double deadline_in) {
    {
      std::lock_guard<std::mutex> lock(mu_);
      published_.reset();
    }
    scheduler_.run_in_context([&] {
      auto opts = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
      auto promise = [this, w = world](td::Result<ImportOutcome> R) {
        Published p;
        if (R.is_error()) {
          p.error = true;
          p.error_text = "promise failed: " + R.error().to_string();
        } else {
          auto o = R.move_as_ok();
          p.masterchain_top = o.masterchain_top;
          p.coherent = o.coherent_shard_client_seqno;
          p.error = o.first_error.is_error();
          if (p.error) {
            p.error_code = o.first_error.code();
            p.error_text = o.first_error.to_string();
          }
        }
        p.at = td::Time::now();
        {
          WorldLock wl(w->mu);
          w->inflight_at_publish = w->inflight;
          w->attempt_active = false;
        }
        std::lock_guard<std::mutex> lock(mu_);
        published_ = p;
      };
      importer_ = td::actor::create_actor<TestImporter>(
          "bounded-import", world, world->tmp, td::Ref<MasterchainState>{td::make_ref<FakeMcState>(kLocal, world->layout)},
          kLocal, opts, td::actor::ActorId<ValidatorManager>{}, td::Timestamp::in(deadline_in),
          td::Promise<ImportOutcome>(std::move(promise)));
    });
  }

  void start_legacy(std::function<void(td::Result<std::pair<BlockSeqno, BlockSeqno>>)> done) {
    scheduler_.run_in_context([&] {
      auto opts = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
      importer_ = td::actor::create_actor<TestImporter>(
          "legacy-import", world, world->tmp, td::Ref<MasterchainState>{td::make_ref<FakeMcState>(kLocal, world->layout)},
          kLocal, opts, td::actor::ActorId<ValidatorManager>{}, std::vector<std::string>{},
          td::Promise<std::pair<BlockSeqno, BlockSeqno>>(std::move(done)));
    });
  }

  std::optional<Published> published() {
    std::lock_guard<std::mutex> lock(mu_);
    return published_;
  }

  bool wait(const std::function<bool()>& cond, double timeout) {
    auto deadline = td::Timestamp::in(timeout);
    while (!deadline.is_in_past()) {
      if (cond()) {
        return true;
      }
      scheduler_.run(0.01);
    }
    return cond();
  }
  bool wait_published(double timeout) {
    return wait([&] { return published().has_value(); }, timeout);
  }
  void run_for(double seconds) {
    auto deadline = td::Timestamp::in(seconds);
    while (!deadline.is_in_past()) {
      scheduler_.run(0.01);
    }
  }
  void in_ctx(const std::function<void()>& f) {
    scheduler_.run_in_context([&] { f(); });
  }
  template <class T>
  void release(std::vector<td::Promise<T>>& held, size_t index, td::Result<T> value) {
    in_ctx([&] {
      td::Promise<T> p;
      {
        WorldLock lock(world->mu);
        p = std::move(held.at(index));
      }
      p.set_result(std::move(value));
    });
  }
  template <class T>
  size_t count(std::vector<td::Promise<T>>& held) {
    WorldLock lock(world->mu);
    return held.size();
  }
  bool tmp_empty() {
    bool empty = true;
    td::WalkPath::run(world->tmp, [&](td::CSlice, td::WalkPath::Type type) {
      if (type == td::WalkPath::Type::RegularFile) {
        empty = false;
      }
    }).ignore();
    return empty;
  }

  std::shared_ptr<World> world;

 private:
  td::actor::Scheduler scheduler_;
  td::actor::ActorOwn<TestImporter> importer_;
  std::mutex mu_;
  std::optional<Published> published_;
};

const ShardId kLeft = shard_child(shardIdAll, true);
const ShardId kRight = shard_child(shardIdAll, false);

Layout two_shards(td::uint32 monitor_min_split = 0) {
  Layout layout;
  layout.shards = {kLeft, kRight};
  layout.monitor_min_split = monitor_min_split;
  return layout;
}

}  // namespace
}  // namespace tos::validator

using namespace tos;
using namespace tos::validator;

// A bounded attempt that meets no error imports every masterchain and shard step,
// settles every child and leaves no temporary file.
TEST(StartupCatchupImporter, BoundedHappyPath) {
  Harness t;
  t.start_bounded(60.0);
  ASSERT_TRUE(t.wait_published(20.0));
  auto p = *t.published();
  ASSERT_TRUE(!p.error);
  ASSERT_EQ(kTop, p.masterchain_top);
  ASSERT_EQ(kTop, p.coherent);
  ASSERT_EQ(0, t.world->inflight_at_publish);
  ASSERT_TRUE(t.tmp_empty());
}

// The legacy mode keeps its interface and result.
TEST(StartupCatchupImporter, LegacyModeUnchanged) {
  Harness t;
  std::mutex mu;
  std::optional<std::pair<BlockSeqno, BlockSeqno>> result;
  t.start_legacy([&](td::Result<std::pair<BlockSeqno, BlockSeqno>> R) {
    R.ensure();
    std::lock_guard<std::mutex> lock(mu);
    result = R.move_as_ok();
  });
  ASSERT_TRUE(t.wait(
      [&] {
        std::lock_guard<std::mutex> lock(mu);
        return result.has_value();
      },
      20.0));
  ASSERT_EQ(kTop, result->first);
  ASSERT_EQ(kTop, result->second);
}

// T8. A shard archive download that never succeeds (the legacy importer retries it
// forever) ends at the attempt deadline: the attempt settles within Da + 5 s with
// every child reported, and the next attempt never overlaps it.
TEST(StartupCatchupImporter, T8_EndlessShardRetryEndsAtDeadline) {
  Harness t;
  t.world->on_archive = [w = t.world](ShardIdFull prefix, td::Promise<std::string> p) {
    if (prefix.is_masterchain()) {
      std::string path;
      {
        WorldLock lock(w->mu);
        path = w->make_package(prefix);
      }
      p.set_value(std::move(path));
    } else {
      p.set_error(td::Status::Error(ErrorCode::notready, "no peer has this shard archive"));
    }
  };
  const double deadline_in = 1.5;
  auto started = td::Time::now();
  t.start_bounded(deadline_in);
  ASSERT_TRUE(t.wait_published(deadline_in + 5.0));
  auto p = *t.published();
  ASSERT_TRUE(p.error);
  ASSERT_TRUE(p.at <= started + deadline_in + 5.0);
  ASSERT_EQ(kTop, p.masterchain_top);
  ASSERT_EQ(kLocal, p.coherent);
  ASSERT_EQ(0, t.world->inflight_at_publish);
  ASSERT_TRUE(t.tmp_empty());
  // The next attempt starts only now; it must find nothing of the first one running.
  t.start_bounded(deadline_in);
  ASSERT_TRUE(t.wait_published(deadline_in + 5.0));
  ASSERT_TRUE(!t.world->overlap_seen);
}

// T18. A temporary file delivered after the attempt began draining is unlinked by the
// importer, which is still alive because that download was outstanding.
TEST(StartupCatchupImporter, T18_LateTemporaryFileIsUnlinked) {
  Harness t;
  t.world->on_archive = [w = t.world](ShardIdFull, td::Promise<std::string> p) {
    WorldLock lock(w->mu);
    w->held_archives.push_back(std::move(p));
  };
  t.start_bounded(0.5);
  ASSERT_TRUE(t.wait([&] { return t.count(t.world->held_archives) == 1; }, 5.0));
  t.run_for(1.0);  // past the deadline: the attempt drains but the download is outstanding
  ASSERT_TRUE(!t.published().has_value());
  std::string late;
  {
    WorldLock lock(t.world->mu);
    late = t.world->make_package(ShardIdFull{masterchainId});
  }
  t.release(t.world->held_archives, 0, td::Result<std::string>(late));
  ASSERT_TRUE(t.wait_published(5.0));
  ASSERT_TRUE(t.published()->error);
  ASSERT_TRUE(td::stat(late).is_error());
  ASSERT_TRUE(t.tmp_empty());
}

// T24. One required shard application fails at once while its sibling is suspended:
// no outcome is delivered until the sibling settles.
TEST(StartupCatchupImporter, T24_OutcomeWaitsForSuspendedSibling) {
  Harness t(two_shards());
  t.world->on_apply = [w = t.world](BlockIdExt id, td::Promise<td::Unit> p) {
    WorldLock lock(w->mu);
    if (!id.is_masterchain() && id.seqno() == kLocal + 1) {
      if (id.id.shard == kLeft) {
        p.set_error(td::Status::Error(ErrorCode::error, "apply failed"));
      } else {
        w->held_applies.push_back(std::move(p));
      }
      return;
    }
    w->applied.insert(id);
    p.set_value(td::Unit());
  };
  t.start_bounded(60.0);
  ASSERT_TRUE(t.wait([&] { return t.count(t.world->held_applies) == 1; }, 10.0));
  t.run_for(0.5);
  ASSERT_TRUE(!t.published().has_value());
  t.release(t.world->held_applies, 0, td::Result<td::Unit>(td::Unit()));
  ASSERT_TRUE(t.wait_published(5.0));
  auto p = *t.published();
  ASSERT_TRUE(p.error);
  ASSERT_EQ(kLocal, p.coherent);
  ASSERT_EQ(0, t.world->inflight_at_publish);
}

// T25. One shard download fails at the deadline while a sibling download delivers its
// file later: the importer outlives the deadline failure and unlinks that file.
TEST(StartupCatchupImporter, T25_SiblingDownloadOutlivesDeadlineFailure) {
  Harness t(two_shards(1));
  t.world->on_archive = [w = t.world](ShardIdFull prefix, td::Promise<std::string> p) {
    WorldLock lock(w->mu);
    if (prefix.is_masterchain()) {
      p.set_value(w->make_package(prefix));
      return;
    }
    w->held_archives.push_back(std::move(p));
  };
  t.start_bounded(1.0);
  ASSERT_TRUE(t.wait([&] { return t.count(t.world->held_archives) == 2; }, 10.0));
  t.run_for(1.2);
  t.release(t.world->held_archives, 0,
            td::Result<std::string>(td::Status::Error(ErrorCode::timeout, "download deadline")));
  t.run_for(0.3);
  ASSERT_TRUE(!t.published().has_value());
  std::string late;
  {
    WorldLock lock(t.world->mu);
    late = t.world->make_package(ShardIdFull{basechainId, kRight});
  }
  t.release(t.world->held_archives, 1, td::Result<std::string>(late));
  ASSERT_TRUE(t.wait_published(5.0));
  ASSERT_TRUE(td::stat(late).is_error());
  ASSERT_TRUE(t.tmp_empty());
}

// T26. A proof check started 0.5 s before the deadline gets a 0.5 s timeout, not its
// fixed 2 s; one with no time left is not started.
TEST(StartupCatchupImporter, T26_ProofCheckCappedAtDeadline) {
  {
    Harness t;
    t.world->clock_offset = 100.0 - 0.5;  // the importer sees a clock 0.5 s before its deadline
    t.start_bounded(100.0);
    ASSERT_TRUE(t.wait([&] {
      WorldLock lock(t.world->mu);
      return t.world->mc_checks > 0;
    }, 10.0));
    double first;
    {
      WorldLock lock(t.world->mu);
      first = t.world->mc_check_timeout_seconds.at(0);
    }
    ASSERT_TRUE(first > 0.3 && first < 0.7);
  }
  {
    Harness t;
    t.world->clock_offset = 100.0 + 0.1;  // past the deadline as the importer sees it
    t.start_bounded(100.0);
    ASSERT_TRUE(t.wait_published(10.0));
    auto p = *t.published();
    ASSERT_TRUE(p.error);
    ASSERT_EQ(static_cast<int>(ErrorCode::timeout), p.error_code);
    WorldLock lock(t.world->mu);
    ASSERT_EQ(0, t.world->mc_checks);
  }
}

// T27. A masterchain apply that times out yields a structured outcome naming the
// timeout and the last coherent frontier, with no assertion.
TEST(StartupCatchupImporter, T27_MasterchainApplyTimeoutIsAnOutcome) {
  Harness t;
  t.world->on_apply = [w = t.world](BlockIdExt id, td::Promise<td::Unit> p) {
    if (id == mc_id(kLocal + 3)) {
      p.set_error(td::Status::Error(ErrorCode::timeout, "apply timed out"));
      return;
    }
    {
      WorldLock lock(w->mu);
      w->applied.insert(id);
    }
    p.set_value(td::Unit());
  };
  t.start_bounded(60.0);
  ASSERT_TRUE(t.wait_published(10.0));
  auto p = *t.published();
  ASSERT_TRUE(p.error);
  ASSERT_EQ(static_cast<int>(ErrorCode::timeout), p.error_code);
  ASSERT_EQ(kLocal + 2, p.masterchain_top);
  ASSERT_EQ(kLocal, p.coherent);
}

// T32. A required shard fails and its sibling succeeds for the same masterchain block:
// the coherent frontier does not advance to it.
TEST(StartupCatchupImporter, T32_FrontierNeedsEveryRequiredShard) {
  Harness t(two_shards());
  t.world->on_apply = [w = t.world](BlockIdExt id, td::Promise<td::Unit> p) {
    WorldLock lock(w->mu);
    if (!id.is_masterchain() && id.seqno() == kLocal + 1 && id.id.shard == kLeft) {
      p.set_error(td::Status::Error(ErrorCode::error, "apply failed"));
      return;
    }
    w->applied.insert(id);
    p.set_value(td::Unit());
  };
  t.start_bounded(60.0);
  ASSERT_TRUE(t.wait_published(10.0));
  auto p = *t.published();
  ASSERT_TRUE(p.error);
  ASSERT_EQ(kLocal, p.coherent);
}

// T33. Between the masterchain phase and the shard-download phase nothing is
// outstanding; that publishes nothing.
TEST(StartupCatchupImporter, T33_TransientZeroDoesNotPublish) {
  Harness t;
  t.world->on_archive = [w = t.world](ShardIdFull prefix, td::Promise<std::string> p) {
    WorldLock lock(w->mu);
    if (prefix.is_masterchain()) {
      p.set_value(w->make_package(prefix));
      return;
    }
    w->held_archives.push_back(std::move(p));
  };
  t.start_bounded(60.0);
  ASSERT_TRUE(t.wait([&] { return t.count(t.world->held_archives) == 1; }, 10.0));
  t.run_for(0.3);
  ASSERT_TRUE(!t.published().has_value());
  std::string path;
  {
    WorldLock lock(t.world->mu);
    path = t.world->make_package(ShardIdFull{basechainId, shardIdAll});
  }
  t.release(t.world->held_archives, 0, td::Result<std::string>(path));
  ASSERT_TRUE(t.wait_published(10.0));
  auto p = *t.published();
  ASSERT_TRUE(!p.error);
  ASSERT_EQ(kTop, p.coherent);
}

// T34. While draining, a shard chain whose next step is suppressed completes its
// promise as cancelled, so the count reaches zero and the outcome is published.
TEST(StartupCatchupImporter, T34_SuppressedStepSettlesItsParent) {
  Harness t;
  t.world->on_link_check = [w = t.world](BlockIdExt id, td::Promise<BlockHandle> p) {
    WorldLock lock(w->mu);
    if (id.seqno() == kLocal + 1) {
      w->held_link_checks.push_back(std::move(p));
      return;
    }
    p.set_value(make_handle(*w, id));
  };
  t.start_bounded(1.0);
  ASSERT_TRUE(t.wait([&] { return t.count(t.world->held_link_checks) == 1; }, 10.0));
  t.run_for(1.3);  // the deadline passes: the attempt drains with the link check outstanding
  ASSERT_TRUE(!t.published().has_value());
  BlockHandle handle;
  {
    WorldLock lock(t.world->mu);
    handle = make_handle(*t.world, sh_id(shardIdAll, kLocal + 1));
  }
  // The check succeeds; the next step (cont2) is suppressed while draining.
  t.release(t.world->held_link_checks, 0, td::Result<BlockHandle>(handle));
  ASSERT_TRUE(t.wait_published(5.0));
  auto p = *t.published();
  ASSERT_TRUE(p.error);
  ASSERT_EQ(kLocal, p.coherent);
  ASSERT_EQ(0, t.world->inflight_at_publish);
  WorldLock lock(t.world->mu);
  ASSERT_TRUE(!t.world->contains(sh_id(shardIdAll, kLocal + 1)));
}

// T20 (importer half). Progress, then the deadline: the outcome carries the coherent
// frontier reached before the deadline, together with the error.
TEST(StartupCatchupImporter, T20_PartialProgressThenDeadline) {
  Harness t;
  t.world->on_apply = [w = t.world](BlockIdExt id, td::Promise<td::Unit> p) {
    WorldLock lock(w->mu);
    if (!id.is_masterchain() && id.seqno() == kLocal + 3) {
      w->held_applies.push_back(std::move(p));
      return;
    }
    w->applied.insert(id);
    p.set_value(td::Unit());
  };
  t.start_bounded(1.0);
  ASSERT_TRUE(t.wait([&] { return t.count(t.world->held_applies) == 1; }, 10.0));
  t.run_for(1.2);
  ASSERT_TRUE(!t.published().has_value());
  t.release(t.world->held_applies, 0, td::Result<td::Unit>(td::Status::Error(ErrorCode::timeout, "apply timeout")));
  ASSERT_TRUE(t.wait_published(5.0));
  auto p = *t.published();
  ASSERT_TRUE(p.error);
  ASSERT_EQ(kLocal + 2, p.coherent);
  ASSERT_EQ(kTop, p.masterchain_top);
}
