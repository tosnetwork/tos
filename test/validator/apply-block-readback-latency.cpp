/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// How long applying a block takes when the wallet index needs the block's data
// and ApplyBlock does not have it in hand, against the same apply with no
// index.
//
// The real ApplyBlock actor runs with no block data in hand. The hook is the
// real one, queueing into a real wallet index database; the indexing worker
// reads the block data itself through a fetcher that answers after a
// configurable delay, as a slow database would. A stand-in manager answers
// every request of ApplyBlock at once; it also counts block-data reads made
// through it, which ApplyBlock must no longer make.
//
// Apply completion is measured from starting the query to its promise, which
// resolves after the handle flush. A run fails unless no sample of any mode
// made a block-data read through the manager.
//
// Usage: test-apply-block-readback-latency <parent dir> [samples] [delay ms...]
// The index is created in a new, uniquely named directory under <parent dir>,
// and only that directory is removed afterwards; nothing already in <parent
// dir> is touched, so pointing it at a node's database root by mistake cannot
// erase that node's index.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "common/delay.h"
#include "td/actor/actor.h"
#include "td/utils/Time.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "validator-engine/wallet-index-writer.h"
#include "validator-engine/wallet-index.h"
#include "validator/block-handle.hpp"
#include "validator/fabric.h"
#include "validator/manager-disk.hpp"
#include "validator/wc0-block-hook.h"

namespace {

using namespace tos::validator;

std::atomic<long> g_reads{0};
std::atomic<long> g_worker_reads{0};
std::atomic<long> g_read_delay_us{0};

// The worker's read: answered (with a failure, so the block stays marked)
// after the configured delay. It sleeps on the worker thread, which is where
// a slow read would hold things up.
void slow_worker_read(const tos::BlockIdExt &, bool,
                      std::function<void(td::Result<tos_wallet_index::Wc0FetchedBlock>)> done) {
  g_worker_reads.fetch_add(1);
  auto delay = g_read_delay_us.load();
  if (delay > 0) {
    std::this_thread::sleep_for(std::chrono::microseconds(delay));
  }
  done(td::Status::Error("block data read answered after the delay"));
}

// Answers what ApplyBlock asks of the manager for a block whose data is
// already stored and whose state is at hand.
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
    promise.set_value(td::Unit());
  }
  // ApplyBlock must not read block data for the index; any read is counted
  // and fails the run.
  void get_block_data_from_db(ConstBlockHandle, td::Promise<td::Ref<BlockData>> promise) override {
    g_reads.fetch_add(1);
    promise.set_error(td::Status::Error("block data read by the manager"));
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

// A stored, accepted block with its state, not yet applied.
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

struct Distribution {
  size_t n = 0;
  double p50 = 0;
  double p99 = 0;
  double max = 0;
};

Distribution distribution(std::vector<double> samples) {
  Distribution d;
  d.n = samples.size();
  if (samples.empty()) {
    return d;
  }
  std::sort(samples.begin(), samples.end());
  auto at = [&](double q) {
    auto index = static_cast<size_t>(q * static_cast<double>(samples.size() - 1));
    return samples[index];
  };
  d.p50 = at(0.50);
  d.p99 = at(0.99);
  d.max = samples.back();
  return d;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s <parent dir> [samples] [delay ms...]\n", argv[0]);
    return 2;
  }
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  std::string parent = argv[1];
  size_t samples = argc > 2 ? static_cast<size_t>(std::strtoul(argv[2], nullptr, 10)) : 2000;
  std::vector<long> delays_us;
  for (int i = 3; i < argc; i++) {
    delays_us.push_back(std::strtol(argv[i], nullptr, 10) * 1000);
  }
  if (delays_us.empty()) {
    delays_us = {1000, 10000};
  }
  if (samples == 0) {
    std::fprintf(stderr, "samples must be positive\n");
    return 2;
  }

  auto own_dir_r = td::mkdtemp(parent, "apply-readback-");
  if (own_dir_r.is_error()) {
    std::fprintf(stderr, "cannot create a scratch directory under %s: %s\n", parent.c_str(),
                 own_dir_r.error().message().c_str());
    return 2;
  }
  auto own_dir = own_dir_r.move_as_ok();
  auto index_path = own_dir + "/wc0-index";
  auto db = tos_wallet_index::WalletIndexDb::open(index_path);
  if (db.is_error()) {
    std::fprintf(stderr, "cannot open the index: %s\n", db.error().message().c_str());
    td::rmrf(own_dir).ignore();
    return 1;
  }
  tos_wallet_index::set_wallet_index_db(db.move_as_ok());
  tos_wallet_index::set_wc0_index_block_fetcher(slow_worker_read);
  if (!tos_wallet_index::start_wc0_index_worker(false)) {
    std::fprintf(stderr, "the index worker did not start\n");
    tos_wallet_index::set_wallet_index_db(nullptr);
    td::rmrf(own_dir).ignore();
    return 1;
  }

  struct Mode {
    std::string name;
    bool hook;
    long delay_us;
  };
  std::vector<Mode> modes = {{"off", false, 0}, {"on", true, 0}};
  for (auto delay : delays_us) {
    modes.push_back({"on-worker-read-delay-" + std::to_string(delay / 1000) + "ms", true, delay});
  }

  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<StandInManager> manager;
  auto prev = basechain_id(1);
  scheduler.run_in_context([&] {
    manager = td::actor::create_actor<StandInManager>("stand-in-manager");
    auto prev_handle = stored_block(1, basechain_id(0));
    prev_handle->set_applied();
    prev_handle->set_applied_stored();
    prev_handle->set_processed();
    td::actor::send_closure(manager, &StandInManager::add_handle, prev_handle);
  });

  tos::BlockSeqno next_seqno = 2;
  bool ok = true;
  std::printf("{\"samples_per_mode\":%zu,\"modes\":[", samples);
  for (size_t m = 0; m < modes.size(); m++) {
    const auto &mode = modes[m];
    g_read_delay_us.store(mode.delay_us);
    g_wc0_block_index_hook =
        mode.hook ? std::function<void(td::Ref<vm::Cell>, td::Ref<vm::Cell>, tos::BlockIdExt, tos::UnixTime)>(
                        &tos_wallet_index::enqueue_wc0_index_block)
                  : nullptr;
    auto reads_before = g_reads.load();
    auto worker_reads_before = g_worker_reads.load();
    std::vector<double> durations;
    durations.reserve(samples);
    size_t failures = 0;
    for (size_t i = 0; i < samples; i++) {
      auto seqno = next_seqno++;
      auto handle = stored_block(seqno, prev);
      std::atomic<bool> done{false};
      double started = 0;
      double finished = 0;
      scheduler.run_in_context([&] {
        td::actor::send_closure(manager, &StandInManager::add_handle, handle);
        started = td::Time::now();
        run_apply_block_query(handle->id(), td::Ref<BlockData>{}, tos::BlockIdExt{}, manager.get(),
                              td::Timestamp::in(10.0), [&](td::Result<td::Unit> R) {
                                finished = td::Time::now();
                                if (R.is_error()) {
                                  failures++;
                                }
                                done = true;
                              });
      });
      while (!done.load()) {
        scheduler.run(0.001);
      }
      durations.push_back(finished - started);
    }
    auto reads = g_reads.load() - reads_before;
    auto worker_reads = g_worker_reads.load() - worker_reads_before;
    if (reads != 0 || failures != 0) {
      ok = false;
    }
    auto d = distribution(durations);
    std::printf(
        "%s{\"mode\":\"%s\",\"worker_read_delay_us\":%ld,\"apply_read_backs\":%ld,\"worker_reads\":%ld,"
        "\"failed_applies\":%zu,\"n\":%zu,\"p50_us\":%.1f,\"p99_us\":%.1f,\"max_us\":%.1f}",
        m == 0 ? "" : ",", mode.name.c_str(), mode.delay_us, reads, worker_reads, failures, d.n, d.p50 * 1e6,
        d.p99 * 1e6, d.max * 1e6);
  }
  g_wc0_block_index_hook = nullptr;
  bool flushed = tos_wallet_index::flush_wc0_index_for_exit(tos_wallet_index::Wc0IndexProducers::Quiesced);
  tos_wallet_index::stop_wc0_index_worker();
  tos_wallet_index::set_wc0_index_block_fetcher(nullptr);
  std::printf("],\"index_flushed_cleanly\":%s,\"no_apply_read_backs\":%s}\n", flushed ? "true" : "false",
              ok ? "true" : "false");
  scheduler.run_in_context([&] {
    manager.reset();
    td::actor::SchedulerContext::get().stop();
  });
  while (scheduler.run(1)) {
  }
  tos_wallet_index::set_wallet_index_db(nullptr);
  td::rmrf(own_dir).ignore();
  return ok && flushed ? 0 : 1;
}
