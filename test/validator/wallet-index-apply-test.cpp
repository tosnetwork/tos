/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Block application cannot reach the retired wallet-index embedding seam.
// The source manager deliberately never answers block-data readbacks.
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

class ApplyHarness {
 public:
  ApplyHarness() {
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
    scheduler_.run_in_context([&] {
      manager_.reset();
      td::actor::SchedulerContext::get().stop();
    });
    while (scheduler_.run(1)) {
    }
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

  tos::BlockSeqno last_seqno() const {
    return next_seqno_ - 1;
  }

 private:
  td::actor::Scheduler scheduler_{{1}};
  td::actor::ActorOwn<StandInManager> manager_;
  tos::BlockSeqno next_seqno_ = 2;
};

}  // namespace

TEST(WalletIndexApply, ApplicationDoesNotCallTheRetiredIndexHookOrLeaseForIt) {
  tos::validator::reset_archive_retention_for_testing();
  ApplyHarness harness;
  std::atomic<int> calls{0};
  tos::validator::g_wc0_block_index_hook = [&](auto, auto, auto, auto) { ++calls; };
  harness.hold_new_blocks(true);
  std::atomic<bool> done{false};
  harness.start_next(77, done);
  harness.run_for(0.1);
  ASSERT_TRUE(!done.load());
  {
    std::lock_guard<std::mutex> guard(tos::validator::g_archive_retention.mutex);
    ASSERT_TRUE(tos::validator::g_archive_retention.leases.empty());
  }
  harness.hold_new_blocks(false);
  harness.run_for(0.1);
  ASSERT_TRUE(done.load());
  for (int i = 0; i < 64; ++i)
    ASSERT_TRUE(harness.apply_next());
  ASSERT_EQ(calls.load(), 0);
  ASSERT_EQ(g_apply_reads.load(), 0);
  tos::validator::reset_archive_retention_for_testing();
}
