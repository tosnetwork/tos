/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Block application with the wallet index enabled must never wait for the
// index: not for a read of block data the index needs, not for the index's
// WAL sync, and not for room in its queue.
//
// The real ApplyBlock actor runs against a stand-in manager that answers what
// ApplyBlock asks at once, except a block-data read, which it never answers:
// an apply that read anything back for the index would hang there. The hook
// is the real one, queueing into a real wallet index database with its real
// worker; each test blocks one part of the index and requires every apply to
// complete while that part is still blocked.
#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "td/actor/actor.h"
#include "td/utils/Time.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "validator-engine/wallet-index-writer.h"
#include "validator-engine/wallet-index.h"
#include "validator/block-handle.hpp"
#include "validator/db/archive-gc-floor.h"
#include "validator/fabric.h"
#include "validator/manager-disk.hpp"
#include "validator/wc0-block-hook.h"

namespace {

using namespace tos::validator;

std::atomic<long> g_apply_reads{0};

class StandInManager : public ValidatorManagerImpl {
 public:
  StandInManager()
      : ValidatorManagerImpl(tos::PublicKeyHash::zero(), {}, tos::ShardIdFull{tos::masterchainId}, tos::BlockIdExt{},
                             "") {
  }
  void start_up() override {
  }
  // As read from the database: nothing in it is waiting to be written.
  void add_handle(BlockHandle handle) {
    handle->flushed_upto(handle->version());
    handles_[handle->id()] = std::move(handle);
  }
  void get_block_handle(tos::BlockIdExt id, bool, td::Promise<BlockHandle> promise) override {
    auto it = handles_.find(id);
    if (it == handles_.end()) {
      promise.set_error(td::Status::Error("unknown block"));
      return;
    }
    promise.set_value(BlockHandle{it->second});
  }
  void wait_block_state(BlockHandle, td::uint32, td::Timestamp, bool,
                        td::Promise<td::Ref<ShardState>> promise) override {
    promise.set_value(td::Ref<ShardState>{});
  }
  void set_next_block(tos::BlockIdExt, tos::BlockIdExt, td::Promise<td::Unit> promise) override {
    promise.set_value(td::Unit());
  }
  void new_block(BlockHandle, td::Ref<ShardState>, td::Promise<td::Unit> promise) override {
    if (hold_new_block_) {
      held_new_blocks_.push_back(std::move(promise));
      return;
    }
    promise.set_value(td::Unit());
  }
  // Holds the next applies before they are filed into the archive.
  void hold_new_blocks(bool hold) {
    hold_new_block_ = hold;
    if (!hold) {
      for (auto &promise : held_new_blocks_) {
        promise.set_value(td::Unit());
      }
      held_new_blocks_.clear();
    }
  }
  // A read of block data never answers: an apply that waits for one hangs.
  void get_block_data_from_db(ConstBlockHandle, td::Promise<td::Ref<BlockData>> promise) override {
    g_apply_reads.fetch_add(1);
    held_reads_.push_back(std::move(promise));
  }
  void write_handle(BlockHandle handle, td::Promise<td::Unit> promise) override {
    handle->flushed_upto(handle->version());
    promise.set_value(td::Unit());
  }
  void add_perf_timer_stat(std::string, double) override {
  }
  void cleanup_applied_external_messages(BlockHandle, td::Ref<BlockData>) override {
  }

 private:
  std::map<tos::BlockIdExt, BlockHandle> handles_;
  std::vector<td::Promise<td::Ref<BlockData>>> held_reads_;
  bool hold_new_block_ = false;
  std::vector<td::Promise<td::Unit>> held_new_blocks_;
};

tos::BlockIdExt basechain_id(tos::BlockSeqno seqno) {
  td::Bits256 root;
  td::Bits256 file;
  root.set_zero();
  file.set_zero();
  root.as_slice().copy_from(td::Slice(reinterpret_cast<const char *>(&seqno), sizeof(seqno)));
  file.as_slice().copy_from(td::Slice(reinterpret_cast<const char *>(&seqno), sizeof(seqno)));
  return tos::BlockIdExt{0, tos::shardIdAll, seqno, root, file};
}

// A stored, accepted block with its state, not yet applied; its data is in
// the database, not in hand.
BlockHandle stored_block(tos::BlockSeqno seqno, const tos::BlockIdExt &prev) {
  auto handle = BlockHandleImpl::create_empty(basechain_id(seqno));
  handle->set_received();
  handle->set_proof_link();
  handle->set_merge(false);
  handle->set_split(false);
  handle->set_prev(prev);
  handle->set_logical_time(1000 + seqno);
  handle->set_unix_time(1000 + seqno);
  handle->set_state_root_hash(basechain_id(seqno).root_hash);
  handle->set_state_boc();
  handle->set_moved_to_archive();
  handle->set_handle_moved_to_archive();
  return handle;
}

// A fetcher for the worker whose reads stay unanswered until released.
struct BlockedFetcher {
  std::mutex mutex;
  std::vector<std::function<void(td::Result<tos_wallet_index::Wc0FetchedBlock>)>> pending;
  std::atomic<int> calls{0};

  void install() {
    tos_wallet_index::set_wc0_index_block_fetcher(
        [this](const tos::BlockIdExt &, bool, std::function<void(td::Result<tos_wallet_index::Wc0FetchedBlock>)> done) {
          std::lock_guard<std::mutex> guard(mutex);
          pending.push_back(std::move(done));
          calls++;
        });
  }
  void release() {
    decltype(pending) taken;
    {
      std::lock_guard<std::mutex> guard(mutex);
      taken.swap(pending);
    }
    for (auto &done : taken) {
      done(td::Status::Error("read released by the test"));
    }
  }
};

template <class F>
bool eventually(F &&condition, std::chrono::milliseconds limit = std::chrono::milliseconds(10000)) {
  auto deadline = std::chrono::steady_clock::now() + limit;
  while (!condition()) {
    if (std::chrono::steady_clock::now() > deadline) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return true;
}

// The real ApplyBlock actor, the real hook and worker, a real index.
class ApplyHarness {
 public:
  explicit ApplyHarness(std::string name) : path_("test-wallet-index-apply-" + std::move(name)) {
    td::rmrf(path_).ignore();
    auto db = tos_wallet_index::WalletIndexDb::open(path_);
    db.ensure();
    tos_wallet_index::set_wallet_index_db(db.move_as_ok());
    g_apply_reads = 0;
    scheduler_.run_in_context([&] {
      manager_ = td::actor::create_actor<StandInManager>("stand-in-manager");
      auto first = stored_block(1, basechain_id(0));
      first->set_applied();
      first->set_applied_stored();
      first->set_processed();
      td::actor::send_closure(manager_, &StandInManager::add_handle, first);
    });
  }

  ~ApplyHarness() {
    tos::validator::g_wc0_block_index_hook = nullptr;
    tos_wallet_index::set_wc0_index_marking_stall_for_testing(false);
    tos_wallet_index::stop_wc0_index_worker();
    tos_wallet_index::set_wc0_index_block_fetcher(nullptr);
    scheduler_.run_in_context([&] {
      manager_.reset();
      td::actor::SchedulerContext::get().stop();
    });
    while (scheduler_.run(1)) {
    }
    tos_wallet_index::set_wallet_index_db(nullptr);
    td::rmrf(path_).ignore();
  }

  bool start_index() {
    if (!tos_wallet_index::start_wc0_index_worker(false)) {
      return false;
    }
    tos::validator::g_wc0_block_index_hook = &tos_wallet_index::enqueue_wc0_index_block;
    return true;
  }

  // Applies the next block, with no block data in hand. True when the apply
  // completed successfully within `limit`.
  // Starts applying the next block, filed under masterchain reference
  // `mc_seqno`, without waiting for it.
  void start_next(tos::BlockSeqno mc_seqno, std::atomic<bool> &done) {
    auto seqno = next_seqno_++;
    auto handle = stored_block(seqno, basechain_id(seqno - 1));
    scheduler_.run_in_context([&, handle] {
      td::actor::send_closure(manager_, &StandInManager::add_handle, handle);
      tos::BlockIdExt mc{tos::masterchainId, tos::shardIdAll, mc_seqno, td::Bits256::zero(), td::Bits256::zero()};
      run_apply_block_query(handle->id(), td::Ref<BlockData>{}, mc, manager_.get(), td::Timestamp::in(60.0),
                            [&done](td::Result<td::Unit> R) { done = R.is_ok(); });
    });
  }
  void run_for(double seconds) {
    auto deadline = td::Timestamp::in(seconds);
    while (!deadline.is_in_past()) {
      scheduler_.run(0.001);
    }
  }
  void hold_new_blocks(bool hold) {
    scheduler_.run_in_context([&] { td::actor::send_closure(manager_, &StandInManager::hold_new_blocks, hold); });
  }

  bool apply_next(double limit = 5.0) {
    auto seqno = next_seqno_++;
    auto handle = stored_block(seqno, basechain_id(seqno - 1));
    std::atomic<bool> done{false};
    bool ok = false;
    scheduler_.run_in_context([&] {
      td::actor::send_closure(manager_, &StandInManager::add_handle, handle);
      run_apply_block_query(handle->id(), td::Ref<BlockData>{}, tos::BlockIdExt{}, manager_.get(),
                            td::Timestamp::in(60.0), [&](td::Result<td::Unit> R) {
                              ok = R.is_ok();
                              done = true;
                            });
    });
    auto deadline = td::Timestamp::in(limit);
    while (!done.load() && !deadline.is_in_past()) {
      scheduler_.run(0.001);
    }
    return done.load() && ok;
  }

  tos_wallet_index::WalletIndexDb &db() {
    return *tos_wallet_index::wallet_index_db();
  }

  tos::BlockSeqno last_seqno() const {
    return next_seqno_ - 1;
  }

 private:
  std::string path_;
  td::actor::Scheduler scheduler_{{1}};
  td::actor::ActorOwn<StandInManager> manager_;
  tos::BlockSeqno next_seqno_ = 2;
};

}  // namespace

// The worker's read of the block data is stuck; applies still complete, and
// ApplyBlock itself reads nothing for the index.
TEST(WalletIndexApply, ApplyCompletesWhileTheWorkersReadIsBlocked) {
  BlockedFetcher reads;
  reads.install();
  ApplyHarness harness("blocked-read");
  ASSERT_TRUE(harness.start_index());
  for (int i = 0; i < 3; i++) {
    ASSERT_TRUE(harness.apply_next());
  }
  // The worker is waiting on its read of the first block, still unanswered.
  ASSERT_TRUE(eventually([&] { return reads.calls.load() == 1; }));
  ASSERT_TRUE(harness.apply_next());
  ASSERT_EQ(reads.calls.load(), 1);
  ASSERT_EQ(g_apply_reads.load(), 0);
  // Every applied block is marked for recovery while its indexing waits.
  ASSERT_TRUE(
      eventually([&] { return harness.db().has_incomplete_block(basechain_id(harness.last_seqno())).move_as_ok(); }));
  reads.release();
}

// The recorder's WAL sync hangs; applies still complete.
TEST(WalletIndexApply, ApplyCompletesWhileTheWalIsBlocked) {
  BlockedFetcher reads;
  reads.install();
  ApplyHarness harness("blocked-wal");
  ASSERT_TRUE(harness.start_index());
  tos_wallet_index::set_wc0_index_marking_stall_for_testing(true);
  for (int i = 0; i < 3; i++) {
    ASSERT_TRUE(harness.apply_next());
  }
  // Nothing was marked yet: the recorder is still stuck in its write.
  ASSERT_TRUE(!harness.db().has_incomplete_block(basechain_id(2)).move_as_ok());
  ASSERT_EQ(g_apply_reads.load(), 0);
  tos_wallet_index::set_wc0_index_marking_stall_for_testing(false);
  ASSERT_TRUE(
      eventually([&] { return harness.db().has_incomplete_block(basechain_id(harness.last_seqno())).move_as_ok(); }));
  reads.release();
}

// The worker is stuck and its queue is full; applies still complete, and a
// block that found no room is marked for recovery instead.
TEST(WalletIndexApply, ApplyCompletesWithAFullQueue) {
  BlockedFetcher reads;
  reads.install();
  ApplyHarness harness("full-queue");
  ASSERT_TRUE(harness.start_index());
  ASSERT_TRUE(harness.apply_next());
  ASSERT_TRUE(eventually([&] { return reads.calls.load() == 1; }));
  for (size_t i = 0; i < tos_wallet_index::kWc0IndexQueueCapacity + 4; i++) {
    ASSERT_TRUE(harness.apply_next());
  }
  ASSERT_EQ(reads.calls.load(), 1);
  ASSERT_EQ(g_apply_reads.load(), 0);
  ASSERT_TRUE(
      eventually([&] { return harness.db().has_incomplete_block(basechain_id(harness.last_seqno())).move_as_ok(); }));
  reads.release();
}

namespace {

bool no_leases() {
  std::lock_guard<std::mutex> guard(tos::validator::g_archive_retention.mutex);
  return tos::validator::g_archive_retention.leases.empty();
}

}  // namespace

// While a basechain block is being applied, before it is filed, archive
// pruning cannot admit deleting the package it will be filed in: ApplyBlock
// holds a lease on its masterchain reference until the index has taken over.
TEST(WalletIndexApply, ApplyLeasesTheBlocksPackageUntilTheIndexTakesOver) {
  tos::validator::reset_archive_retention_for_testing();
  BlockedFetcher reads;
  reads.install();
  ApplyHarness harness("lease");
  ASSERT_TRUE(harness.start_index());
  harness.hold_new_blocks(true);
  std::atomic<bool> done{false};
  harness.start_next(77, done);
  harness.run_for(0.2);
  ASSERT_TRUE(!done.load());
  // The package holding references 70..77 may not go; one ending at 77 may.
  ASSERT_TRUE(!tos::validator::archive_admit_deletion(78, tos::validator::kNoArchiveGcFloor));
  ASSERT_TRUE(!no_leases());
  harness.hold_new_blocks(false);
  harness.run_for(0.2);
  ASSERT_TRUE(done.load());
  // The index holds it now, and the apply's lease is gone.
  ASSERT_TRUE(no_leases());
  ASSERT_TRUE(!tos::validator::archive_admit_deletion(78, tos::validator::kNoArchiveGcFloor));
  reads.release();
  tos::validator::reset_archive_retention_for_testing();
}
