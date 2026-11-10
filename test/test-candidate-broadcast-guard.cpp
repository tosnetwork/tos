// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//
// The candidate-broadcast admission guard must be released on the manager
// actor. set_block_data fails from the database callback, on the database's
// thread; if that error escaped the await, the coroutine would end without
// resuming on the manager and the frame (and its guard) would be destroyed on
// the failing thread, mutating the manager's admission set off the actor.
//
// The probe drives the production entry point through a detached ask, as the
// full node does, holds the set_block_data promise, parks the manager on a
// latch, fails the promise from another actor and reads the admission set
// while the manager is still parked.
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "crypto/block/block-db.h"
#include "quic/quic-sender.h"
#include "td/actor/actor.h"
#include "td/actor/coro.h"
#include "td/utils/Time.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "validator/block-handle.hpp"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager.hpp"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"

namespace tos::validator {

class CandidateBroadcastGuardProbe;

namespace {

constexpr auto kStageTimeout = std::chrono::seconds(30);
constexpr auto kWatchdogTimeout = std::chrono::seconds(120);
constexpr std::size_t kUnset = std::numeric_limits<std::size_t>::max();

// Every field is guarded by `mutex`; each stage is published under it, which
// orders the manager's admission writes before the helper's read.
struct ProbeState {
  std::mutex mutex;
  std::condition_variable cv;
  CandidateBroadcastGuardProbe *manager = nullptr;
  bool entered = false;
  std::size_t size_at_entry = kUnset;
  td::Promise<td::Unit> pending;
  bool parked = false;
  bool park_timed_out = false;
  bool released = false;
  bool injected = false;
  std::size_t helper_size_before_injection = kUnset;
  std::size_t helper_size_after_injection = kUnset;
  bool manager_read = false;
  std::size_t manager_size_after_release = kUnset;
  bool done = false;
  std::string failure;

  template <class Pred>
  bool wait(std::unique_lock<std::mutex> &lock, Pred pred) {
    return cv.wait_for(lock, kStageTimeout, pred);
  }
};

}  // namespace

class CandidateBroadcastGuardProbe final : public ValidatorManagerImpl {
 public:
  CandidateBroadcastGuardProbe(td::Ref<ValidatorManagerOptions> options, td::Ref<MasterchainState> state,
                               BlockHandle masterchain_handle, BlockHandle shard_client_handle,
                               std::shared_ptr<ProbeState> probe)
      : ValidatorManagerImpl(std::move(options), "", {}, {}, {}, {}, {}), probe_(std::move(probe)) {
    last_masterchain_state_ = std::move(state);
    last_masterchain_block_handle_ = std::move(masterchain_handle);
    shard_client_handle_ = std::move(shard_client_handle);
  }

  void start_up() override {
  }

  void get_block_handle(BlockIdExt id, bool force, td::Promise<BlockHandle> promise) override {
    promise.set_value(BlockHandleImpl::create_empty(id));
  }

  void set_block_data(BlockHandle handle, td::Ref<BlockData> data, td::Promise<td::Unit> promise) override {
    std::lock_guard<std::mutex> lock(probe_->mutex);
    probe_->manager = this;
    probe_->size_at_entry = active_candidate_broadcasts_.size();
    probe_->pending = std::move(promise);
    probe_->entered = true;
    probe_->cv.notify_all();
  }

  // Blocks the manager's worker until the driver releases it, so nothing can
  // run on the manager while the helper fails the promise and reads the set.
  void park() {
    std::unique_lock<std::mutex> lock(probe_->mutex);
    probe_->parked = true;
    probe_->cv.notify_all();
    if (!probe_->wait(lock, [&] { return probe_->released; })) {
      probe_->park_timed_out = true;
    }
  }

  void read_after_release() {
    std::lock_guard<std::mutex> lock(probe_->mutex);
    probe_->manager_size_after_release = active_candidate_broadcasts_.size();
    probe_->manager_read = true;
    probe_->cv.notify_all();
  }

  // Read while the manager is parked; ordered by the probe mutex.
  std::size_t active_candidate_broadcasts_size() const {
    return active_candidate_broadcasts_.size();
  }

 private:
  std::shared_ptr<ProbeState> probe_;
};

namespace {

// Stands in for the database actor: fails the held promise on its own thread.
class FailingDbHelper final : public td::actor::Actor {
 public:
  explicit FailingDbHelper(std::shared_ptr<ProbeState> probe) : probe_(std::move(probe)) {
  }

  void fail_and_read() {
    td::Promise<td::Unit> pending;
    CandidateBroadcastGuardProbe *manager = nullptr;
    {
      std::lock_guard<std::mutex> lock(probe_->mutex);
      manager = probe_->manager;
      pending = std::move(probe_->pending);
      probe_->helper_size_before_injection = manager->active_candidate_broadcasts_size();
    }
    // Outside the lock: an escaped error destroys the frame right here.
    pending.set_error(td::Status::Error("injected block data store failure"));
    std::lock_guard<std::mutex> lock(probe_->mutex);
    probe_->helper_size_after_injection = manager->active_candidate_broadcasts_size();
    probe_->injected = true;
    probe_->cv.notify_all();
  }

 private:
  std::shared_ptr<ProbeState> probe_;
};

class ProbeDriver final : public td::actor::Actor {
 public:
  ProbeDriver(std::shared_ptr<ProbeState> probe, td::actor::ActorId<CandidateBroadcastGuardProbe> manager,
              td::actor::ActorId<FailingDbHelper> helper, BlockIdExt block_id, td::BufferSlice data)
      : probe_(std::move(probe))
      , manager_(std::move(manager))
      , helper_(std::move(helper))
      , block_id_(block_id)
      , data_(std::move(data)) {
  }

  void start_up() override {
    run();
    std::lock_guard<std::mutex> lock(probe_->mutex);
    // Never leave the manager parked, whatever stage failed.
    probe_->released = true;
    probe_->done = true;
    probe_->cv.notify_all();
  }

 private:
  void fail(std::string what) {
    std::lock_guard<std::mutex> lock(probe_->mutex);
    if (probe_->failure.empty()) {
      probe_->failure = std::move(what);
    }
  }

  void run() {
    // The production path: the full node starts the manager task with a
    // detached ask and keeps nothing of it.
    td::actor::ActorId<ValidatorManagerInterface> manager = manager_;
    std::move(td::actor::ask(manager, &ValidatorManagerInterface::new_block_candidate_broadcast, block_id_, 0,
                             std::move(data_), BroadcastSource::public_overlay))
        .detach("probe candidate broadcast");
    {
      std::unique_lock<std::mutex> lock(probe_->mutex);
      if (!probe_->wait(lock, [&] { return probe_->entered; })) {
        lock.unlock();
        fail("timeout waiting for set_block_data");
        return;
      }
    }
    td::actor::send_closure_later(manager_, &CandidateBroadcastGuardProbe::park);
    {
      std::unique_lock<std::mutex> lock(probe_->mutex);
      if (!probe_->wait(lock, [&] { return probe_->parked; })) {
        lock.unlock();
        fail("timeout waiting for the manager to park");
        return;
      }
    }
    td::actor::send_closure_later(helper_, &FailingDbHelper::fail_and_read);
    {
      std::unique_lock<std::mutex> lock(probe_->mutex);
      if (!probe_->wait(lock, [&] { return probe_->injected; })) {
        lock.unlock();
        fail("timeout waiting for the injected failure");
        return;
      }
      probe_->released = true;
      probe_->cv.notify_all();
    }
    // Queued after the resumption the failure scheduled on the manager, if any.
    td::actor::send_closure_later(manager_, &CandidateBroadcastGuardProbe::read_after_release);
    {
      std::unique_lock<std::mutex> lock(probe_->mutex);
      if (!probe_->wait(lock, [&] { return probe_->manager_read; })) {
        lock.unlock();
        fail("timeout waiting for the manager read");
        return;
      }
    }
  }

  std::shared_ptr<ProbeState> probe_;
  td::actor::ActorId<CandidateBroadcastGuardProbe> manager_;
  td::actor::ActorId<FailingDbHelper> helper_;
  BlockIdExt block_id_;
  td::BufferSlice data_;
};

td::Ref<MasterchainState> load_masterchain_state() {
  auto file =
      td::read_file((std::filesystem::path(__FILE__).parent_path() / "pq-native/data/c04-pq-genesis.boc").string());
  if (file.is_error()) {
    return {};
  }
  auto decoded = vm::std_boc_deserialize(file.move_as_ok());
  if (decoded.is_error()) {
    return {};
  }
  auto root = decoded.move_as_ok();
  BlockIdExt id{masterchainId, shardIdAll, 0, root->get_hash().bits(), FileHash::zero()};
  auto loaded = MasterchainStateQ::fetch(id, td::BufferSlice{}, root);
  if (loaded.is_error()) {
    return {};
  }
  return loaded.move_as_ok();
}

}  // namespace

TEST(CandidateBroadcastGuard, SetBlockDataFailureReleasesAdmissionOnManager) {
  auto state = load_masterchain_state();
  ASSERT_TRUE(state.not_null());

  // A one-cell block whose root and file hashes match its id, so BlockQ::init accepts it.
  vm::CellBuilder cb;
  ASSERT_TRUE(cb.store_long_bool(0x5ca1ab1e, 32));
  auto cell = cb.finalize();
  auto serialized = vm::std_boc_serialize(cell, vm::BagOfCells::Mode::WithCRC32C);
  ASSERT_TRUE(serialized.is_ok());
  auto data = serialized.move_as_ok();
  BlockIdExt block_id{basechainId, shardIdAll, 1, cell->get_hash().bits(), block::compute_file_hash(data)};

  auto options = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
  options.write().set_nonfinal_ls_queries_enabled(true);
  auto masterchain_handle = BlockHandleImpl::create_empty(state->get_block_id());
  auto shard_client_handle = BlockHandleImpl::create_empty(state->get_block_id());
  shard_client_handle->set_unix_time(static_cast<UnixTime>(td::Clocks::system()));
  // Nothing persists these handles; mark them written so their destructor does not expect a flush.
  shard_client_handle->flushed_upto(shard_client_handle->version());

  auto probe = std::make_shared<ProbeState>();

  std::mutex watchdog_mutex;
  std::condition_variable watchdog_cv;
  bool finished = false;
  std::thread watchdog([&] {
    std::unique_lock<std::mutex> lock(watchdog_mutex);
    if (!watchdog_cv.wait_for(lock, kWatchdogTimeout, [&] { return finished; })) {
      std::fprintf(stderr, "FAIL candidate broadcast guard probe watchdog expired\n");
      std::_Exit(1);
    }
  });

  {
    // Manager, driver and helper each need a worker of their own while one is blocked.
    td::actor::Scheduler scheduler({td::actor::Scheduler::NodeInfo{6}});
    td::actor::ActorOwn<CandidateBroadcastGuardProbe> manager;
    td::actor::ActorOwn<FailingDbHelper> helper;
    td::actor::ActorOwn<ProbeDriver> driver;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<CandidateBroadcastGuardProbe>("guard-probe-manager", options, state,
                                                                      masterchain_handle, shard_client_handle, probe);
      helper = td::actor::create_actor<FailingDbHelper>("guard-probe-db", probe);
      driver = td::actor::create_actor<ProbeDriver>("guard-probe-driver", probe, manager.get(), helper.get(), block_id,
                                                    data.clone());
    });
    while (true) {
      {
        std::lock_guard<std::mutex> lock(probe->mutex);
        if (probe->done) {
          break;
        }
      }
      scheduler.run(0.05);
    }
    scheduler.run_in_context([&] {
      driver.reset();
      helper.reset();
      manager.reset();
      td::actor::SchedulerContext::get().stop();
    });
    scheduler.run();
  }

  {
    std::lock_guard<std::mutex> lock(watchdog_mutex);
    finished = true;
  }
  watchdog_cv.notify_all();
  watchdog.join();

  std::lock_guard<std::mutex> lock(probe->mutex);
  if (!probe->failure.empty()) {
    std::fprintf(stderr, "FAIL %s\n", probe->failure.c_str());
  }
  ASSERT_TRUE(probe->failure.empty());
  EXPECT(!probe->park_timed_out);
  // Admitted, and the candidate reached set_block_data.
  EXPECT_EQ(probe->size_at_entry, 1u);
  EXPECT_EQ(probe->helper_size_before_injection, 1u);
  // The failure is delivered back to the parked manager; nothing released it here.
  EXPECT_EQ(probe->helper_size_after_injection, 1u);
  // Once the manager runs again the coroutine ends there and releases its admission.
  EXPECT_EQ(probe->manager_size_after_release, 0u);
}

}  // namespace tos::validator
