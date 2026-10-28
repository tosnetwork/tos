/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
// The standalone wallet index's source pipeline: request hand-off, the shared
// request limit and prefetch budget, ordering, errors, reset and shutdown,
// and the replay loop's readiness, all against a fixture source served
// through the production inbox, replies and prefetcher.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include "services/index-prefetch.h"
#include "services/index-reader.h"
#include "services/index-replay-loop.h"
#include "services/service-common.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/port/thread.h"
#include "td/utils/tests.h"
#include "validator/fabric.h"
#include "vm/boc.h"

#include "wallet-index-chain-fixture.h"

namespace {
using namespace tos;
using namespace tos::services;
using Clock = std::chrono::steady_clock;

// Assert success, logging the error otherwise.
#define ASSERT_OK(result)                                \
  do {                                                   \
    if ((result).is_error()) {                           \
      LOG(ERROR) << #result << ": " << (result).error(); \
    }                                                    \
    ASSERT_TRUE((result).is_ok());                       \
  } while (0)

// Wait for `done`, at most `limit`; false when it did not happen in time.
template <class F>
bool eventually(F done, std::chrono::milliseconds limit = std::chrono::seconds(10)) {
  auto deadline = Clock::now() + limit;
  while (!done()) {
    if (Clock::now() >= deadline)
      return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return true;
}

// Runs a scheduler with the inbox actor on its own thread. `poll_timeout`
// is how long the scheduler sleeps when nothing wakes it.
class SchedulerThread {
 public:
  SchedulerThread(std::shared_ptr<SourceCore> core, double poll_timeout) : core_(std::move(core)) {
    thread_ = td::thread([this, poll_timeout] {
      td::actor::Scheduler scheduler({1});
      td::actor::ActorOwn<SourceInbox> inbox;
      scheduler.run_in_context([&] { inbox = SourceInbox::create(core_); });
      while (!quit_.load())
        scheduler.run(poll_timeout);
      scheduler.run_in_context([&] { inbox.reset(); });
      scheduler.run_in_context([] { td::actor::SchedulerContext::get().stop(); });
      while (scheduler.run(0.01)) {
      }
    });
  }
  ~SchedulerThread() {
    quit_ = true;
    thread_.join();
  }

 private:
  std::shared_ptr<SourceCore> core_;
  std::atomic<bool> quit_{false};
  td::thread thread_;
};

BlockIdExt master_id(uint32_t seqno) {
  td::Bits256 hash;
  hash.set_zero();
  hash.as_slice().copy_from(td::Slice(reinterpret_cast<const char*>(&seqno), sizeof(seqno)));
  return BlockIdExt{masterchainId, shardIdAll, seqno, hash, hash};
}

// A payload of about `bytes` bytes hanging off a block root, so the block's
// serialized size can be chosen.
td::Ref<vm::Cell> payload(size_t bytes, uint32_t salt) {
  std::vector<td::Ref<vm::Cell>> level;
  for (size_t i = 0; i < std::max<size_t>(1, bytes / 128); ++i) {
    vm::CellBuilder cb;
    std::string data(120, static_cast<char>((i + salt) & 0xff));
    cb.store_bytes(data);
    cb.store_long(static_cast<long long>(i), 32);
    level.push_back(cb.finalize());
  }
  // Four children per cell keeps the tree shallow.
  while (level.size() > 1) {
    std::vector<td::Ref<vm::Cell>> up;
    for (size_t i = 0; i < level.size(); i += 4) {
      vm::CellBuilder cb;
      for (size_t j = i; j < std::min(level.size(), i + 4); ++j)
        cb.store_ref(level[j]);
      up.push_back(cb.finalize());
    }
    level = std::move(up);
  }
  return level.front();
}

// Masterchain blocks 1..masters; interval n holds `per_interval` basechain
// blocks, each the child of the one before, the first the child of the last
// block of interval n-1.
struct FakeChain {
  std::map<uint32_t, validator::BlockHandle> masters;
  std::map<uint32_t, std::vector<BlockIdExt>> heads;
  std::map<uint32_t, std::vector<BlockIdExt>> order;
  std::map<BlockIdExt, validator::BlockHandle> shards;
  std::map<BlockIdExt, std::string> data;
  uint32_t tip = 0;
};

std::shared_ptr<FakeChain> make_chain(uint32_t masters, uint32_t per_interval, size_t payload_bytes = 0) {
  auto chain = std::make_shared<FakeChain>();
  BlockIdExt previous_shard{0, shardIdAll, 0, td::Bits256::zero(), td::Bits256::zero()};
  uint32_t shard_seqno = 0;
  for (uint32_t n = 1; n <= masters; ++n) {
    auto master = validator::create_empty_block_handle(master_id(n));
    master->set_merge(false);
    if (n > 1)
      master->set_prev(master_id(n - 1));
    master->set_applied();
    // A fixture handle is never written; mark it as such.
    master->flushed_upto(master->version());
    chain->masters[n] = master;
    for (uint32_t j = 0; j < per_interval; ++j) {
      ++shard_seqno;
      td::Bits256 account;
      account.set_zero();
      account.as_slice().copy_from(td::Slice(reinterpret_cast<const char*>(&shard_seqno), sizeof(shard_seqno)));
      auto root = wallet_index_fixture::block(shard_seqno, 1000ull * shard_seqno, 1000 + shard_seqno,
                                              {wallet_index_fixture::Tx{account, 1000ull * shard_seqno - 10, 0}});
      if (payload_bytes) {
        vm::CellBuilder cb;
        cb.store_long(shard_seqno, 32);
        cb.store_ref(root);
        cb.store_ref(payload(payload_bytes, shard_seqno));
        root = cb.finalize();
      }
      auto boc = vm::std_boc_serialize(root, 31).move_as_ok();
      td::Bits256 file_hash;
      td::sha256(boc.as_slice(), file_hash.as_slice());
      BlockIdExt id{0, shardIdAll, shard_seqno, root->get_hash().bits(), file_hash};
      auto handle = validator::create_empty_block_handle(id);
      handle->set_merge(false);
      handle->set_prev(previous_shard);
      handle->set_masterchain_ref_block(n);
      handle->set_applied();
      handle->flushed_upto(handle->version());
      chain->shards[id] = handle;
      chain->data[id] = boc.as_slice().str();
      chain->order[n].push_back(id);
      previous_shard = id;
    }
    chain->heads[n] = {previous_shard};
  }
  chain->tip = masters;
  return chain;
}

// What the fixture source does with requests: answer at once, or hold them
// until the test releases them, and fail chosen ones.
struct Gate {
  std::mutex mutex;
  bool hold_blocks = false;
  bool hold_tips = false;
  std::vector<std::pair<BlockIdExt, td::Promise<td::Ref<validator::BlockData>>>> held_blocks;
  std::vector<td::Promise<BlockIdExt>> held_tips;
  // Errors for the next request of these blocks, then cleared.
  std::map<BlockIdExt, std::string> block_errors;
  std::map<uint32_t, std::string> master_errors;
  std::map<BlockIdExt, int> block_requests;
  size_t held_count() {
    std::lock_guard<std::mutex> lock(mutex);
    return held_blocks.size();
  }
};

td::Result<td::Ref<validator::BlockData>> block_from(const FakeChain& chain, const BlockIdExt& id) {
  auto it = chain.data.find(id);
  if (it == chain.data.end())
    return td::Status::Error("no such block in the fixture");
  return validator::create_block(id, td::BufferSlice(it->second));
}

void release_blocks(Gate& gate, const FakeChain& chain, bool reverse) {
  std::vector<std::pair<BlockIdExt, td::Promise<td::Ref<validator::BlockData>>>> held;
  {
    std::lock_guard<std::mutex> lock(gate.mutex);
    held.swap(gate.held_blocks);
  }
  if (reverse)
    std::reverse(held.begin(), held.end());
  for (auto& [id, promise] : held)
    promise.set_result(block_from(chain, id));
}

class FakeReader final : public IndexReader {
 public:
  FakeReader(std::shared_ptr<SourceCore> core, std::shared_ptr<FakeChain> chain, std::shared_ptr<Gate> gate,
             ReplayStats* stats = nullptr, std::chrono::milliseconds timeout = std::chrono::seconds(20))
      : IndexReader({}, std::move(core), timeout, stats), chain_(std::move(chain)), gate_(std::move(gate)) {
  }
  using IndexReader::handle;
  using IndexReader::masterchain;
  td::Result<validator::ConstBlockHandle> masterchain(uint32_t seqno, Context context) override {
    return query<validator::ConstBlockHandle>(
        [chain = chain_, gate = gate_, seqno](auto, td::Promise<validator::ConstBlockHandle> promise) {
          {
            std::lock_guard<std::mutex> lock(gate->mutex);
            auto error = gate->master_errors.find(seqno);
            if (error != gate->master_errors.end()) {
              auto message = error->second;
              gate->master_errors.erase(error);
              promise.set_error(td::Status::Error(message));
              return;
            }
          }
          auto it = chain->masters.find(seqno);
          if (it == chain->masters.end())
            return promise.set_error(td::Status::Error("no such masterchain block"));
          promise.set_value(it->second);
        },
        context);
  }
  td::Result<validator::BlockHandle> handle(BlockIdExt id, Context context) override {
    return query<validator::BlockHandle>(
        [chain = chain_, id](auto, td::Promise<validator::BlockHandle> promise) {
          auto shard = chain->shards.find(id);
          if (shard != chain->shards.end())
            return promise.set_value(validator::BlockHandle(shard->second));
          if (id.is_masterchain()) {
            auto master = chain->masters.find(id.seqno());
            if (master != chain->masters.end() && master->second->id() == id)
              return promise.set_value(validator::BlockHandle(master->second));
          }
          promise.set_error(td::Status::Error("no such block handle"));
        },
        context);
  }
  td::Result<std::vector<BlockIdExt>> shard_heads(validator::ConstBlockHandle master, Context context) override {
    return query<std::vector<BlockIdExt>>(
        [chain = chain_, seqno = master->id().seqno()](auto, td::Promise<std::vector<BlockIdExt>> promise) {
          promise.set_value(std::vector<BlockIdExt>(chain->heads[seqno]));
        },
        context, kSourceBlockReserveBytes);
  }
  td::Result<std::shared_ptr<SourceReply<td::Ref<validator::BlockData>>>> submit_block(
      validator::ConstBlockHandle handle, Context context) override {
    return submit<td::Ref<validator::BlockData>>(
        [chain = chain_, gate = gate_, id = handle->id()](auto, td::Promise<td::Ref<validator::BlockData>> promise) {
          std::unique_lock<std::mutex> lock(gate->mutex);
          gate->block_requests[id]++;
          auto error = gate->block_errors.find(id);
          if (error != gate->block_errors.end()) {
            auto message = error->second;
            gate->block_errors.erase(error);
            lock.unlock();
            return promise.set_error(td::Status::Error(message));
          }
          if (gate->hold_blocks) {
            gate->held_blocks.emplace_back(id, std::move(promise));
            return;
          }
          lock.unlock();
          promise.set_result(block_from(*chain, id));
        },
        context, kSourceBlockReserveBytes,
        [](const td::Result<td::Ref<validator::BlockData>>& r) { return block_charge(r); });
  }
  td::Result<td::Ref<vm::Cell>> state(validator::ConstBlockHandle) override {
    return td::Status::Error("the fixture source keeps no states");
  }
  td::Result<BlockIdExt> tip() override {
    return query<BlockIdExt>([chain = chain_, gate = gate_](auto, td::Promise<BlockIdExt> promise) {
      std::unique_lock<std::mutex> lock(gate->mutex);
      if (gate->hold_tips) {
        gate->held_tips.push_back(std::move(promise));
        return;
      }
      lock.unlock();
      promise.set_value(chain->masters.at(chain->tip)->id());
    });
  }

 private:
  std::shared_ptr<FakeChain> chain_;
  std::shared_ptr<Gate> gate_;
};

std::shared_ptr<SourceCore> make_core(SourceLimits limits = {}) {
  stop_requested = false;
  return SourceCore::create(limits).move_as_ok();
}

// Read intervals first..last from the prefetcher as the replay thread does,
// returning the shard block ids in the order they were handed over.
td::Result<std::vector<BlockIdExt>> consume(Prefetcher& prefetcher, uint32_t first, uint32_t last) {
  std::vector<BlockIdExt> seen;
  for (uint32_t n = first; n <= last; ++n) {
    TRY_RESULT(interval, prefetcher.interval(n));
    if (interval->error.is_error())
      return interval->error.clone();
    for (size_t i = 0; i < interval->blocks.size(); ++i) {
      TRY_RESULT(data, prefetcher.block_data(*interval, i));
      TRY_STATUS(IndexReader::checked_root(interval->blocks[i].handle, data));
      seen.push_back(interval->blocks[i].handle->id());
    }
    interval.reset();
    prefetcher.pop(n);
  }
  return seen;
}

std::vector<BlockIdExt> expected_order(const FakeChain& chain, uint32_t first, uint32_t last) {
  std::vector<BlockIdExt> all;
  for (uint32_t n = first; n <= last; ++n)
    all.insert(all.end(), chain.order.at(n).begin(), chain.order.at(n).end());
  return all;
}

BlockIdExt before_first() {
  return BlockIdExt{};
}

}  // namespace

// A request is run as soon as it is queued: with the scheduler asleep for up
// to 10 s at a time, 200 sequential reads still take well under a second each.
TEST(WalletIndexSource, requests_wake_the_scheduler_instead_of_waiting_for_its_loop) {
  auto core = make_core();
  auto chain = make_chain(2, 1);
  auto gate = std::make_shared<Gate>();
  SchedulerThread scheduler(core, 10.0);
  FakeReader reader(core, chain, gate, nullptr, std::chrono::seconds(3));
  auto started = Clock::now();
  for (int i = 0; i < 200; ++i) {
    auto handle = reader.masterchain(1);
    ASSERT_OK(handle);
    ASSERT_TRUE(handle.ok()->id() == master_id(1));
  }
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started);
  ASSERT_TRUE(elapsed < std::chrono::milliseconds(2000));
  // Leave the scheduler loop promptly: one more request wakes it.
  core->shutdown();
  reader.masterchain(1).ignore();
}

// Blocks complete in reverse and in shuffled order; the replay thread still
// receives every interval, and every block in it, in chain order.
TEST(WalletIndexSource, out_of_order_completions_are_handed_over_in_order) {
  for (unsigned seed : {0u, 1u, 7u}) {
    auto core = make_core();
    auto chain = make_chain(12, 3);
    auto gate = std::make_shared<Gate>();
    gate->hold_blocks = true;
    SchedulerThread scheduler(core, 0.05);
    FakeReader reader(core, chain, gate);
    Prefetcher prefetcher(reader, Prefetcher::Options{});
    prefetcher.start();
    prefetcher.follow(1, before_first(), chain->tip);
    std::atomic<bool> done{false};
    td::thread releaser([&] {
      std::mt19937 random(seed);
      while (!done.load()) {
        std::vector<std::pair<BlockIdExt, td::Promise<td::Ref<validator::BlockData>>>> held;
        {
          std::lock_guard<std::mutex> lock(gate->mutex);
          // Let several pile up so their completions can be reordered.
          if (gate->held_blocks.size() >= 3 || (!gate->held_blocks.empty() && random() % 4 == 0))
            held.swap(gate->held_blocks);
        }
        if (seed == 0)
          std::reverse(held.begin(), held.end());
        else
          std::shuffle(held.begin(), held.end(), random);
        for (auto& [id, promise] : held)
          promise.set_result(block_from(*chain, id));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    });
    auto seen = consume(prefetcher, 1, chain->tip);
    done = true;
    releaser.join();
    ASSERT_OK(seen);
    ASSERT_TRUE(seen.ok() == expected_order(*chain, 1, chain->tip));
    core->shutdown();
  }
}

// Later results fill the byte budget and the earliest completes last; the
// replay thread still advances. With a budget of one block reservation, the
// handles a prefetched interval keeps already exceed what is left, and the
// interval's first block is admitted anyway.
TEST(WalletIndexSource, the_result_needed_next_is_admitted_when_later_ones_fill_the_budget) {
  {
    auto core = make_core(SourceLimits{8, 1, 2 * kSourceBlockReserveBytes});
    auto chain = make_chain(6, 2, 3u << 20);
    auto gate = std::make_shared<Gate>();
    gate->hold_blocks = true;
    SchedulerThread scheduler(core, 0.05);
    FakeReader reader(core, chain, gate);
    Prefetcher prefetcher(reader, Prefetcher::Options{});
    prefetcher.start();
    prefetcher.follow(1, before_first(), chain->tip);
    std::atomic<bool> done{false};
    td::thread releaser([&] {
      while (!done.load()) {
        // Hold the earliest until a later one has completed and kept its
        // bytes, then release the earliest last.
        std::vector<std::pair<BlockIdExt, td::Promise<td::Ref<validator::BlockData>>>> held;
        {
          std::lock_guard<std::mutex> lock(gate->mutex);
          if (gate->held_blocks.size() >= 2)
            held.swap(gate->held_blocks);
        }
        std::reverse(held.begin(), held.end());
        for (auto& [id, promise] : held)
          promise.set_result(block_from(*chain, id));
        // A lone request is released after a pause, so the test also
        // covers the case where nothing later is outstanding.
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        {
          std::lock_guard<std::mutex> lock(gate->mutex);
          held.clear();
          if (gate->held_blocks.size() == 1)
            held.swap(gate->held_blocks);
        }
        for (auto& [id, promise] : held)
          promise.set_result(block_from(*chain, id));
      }
    });
    td::Result<std::vector<BlockIdExt>> seen = td::Status::Error("not run");
    std::atomic<bool> finished{false};
    td::thread consumer([&] {
      seen = consume(prefetcher, 1, chain->tip);
      finished = true;
    });
    ASSERT_TRUE(eventually([&] { return finished.load(); }));
    consumer.join();
    done = true;
    releaser.join();
    ASSERT_OK(seen);
    ASSERT_TRUE(seen.ok() == expected_order(*chain, 1, chain->tip));
    // Never more than the budget plus the one result admitted past it.
    ASSERT_TRUE(core->counters().prefetch_bytes_high_water.load() <=
                2 * kSourceBlockReserveBytes + kSourceBlockReserveBytes + 8 * kSourceHandleBytes);
    core->shutdown();
  }
  {
    auto core = make_core(SourceLimits{8, 1, kSourceBlockReserveBytes});
    auto chain = make_chain(3, 1);
    auto gate = std::make_shared<Gate>();
    SchedulerThread scheduler(core, 0.05);
    FakeReader reader(core, chain, gate);
    Prefetcher prefetcher(reader, Prefetcher::Options{});
    prefetcher.start();
    prefetcher.follow(1, before_first(), chain->tip);
    td::Result<std::vector<BlockIdExt>> seen = td::Status::Error("not run");
    std::atomic<bool> finished{false};
    td::thread consumer([&] {
      seen = consume(prefetcher, 1, chain->tip);
      finished = true;
    });
    bool in_time = eventually([&] { return finished.load(); }, std::chrono::seconds(5));
    core->shutdown();
    consumer.join();
    ASSERT_TRUE(in_time);
    ASSERT_OK(seen);
  }
}

// A consumer that takes nothing: the prefetch lane stops at its share of the
// request limit, the interval count and the byte budget, and everything is
// released again once the consumer has taken it.
TEST(WalletIndexSource, prefetch_stops_at_its_limits_and_gives_everything_back) {
  SourceLimits limits{8, 1, size_t{64} << 20};
  auto core = make_core(limits);
  auto chain = make_chain(40, 2, 64u << 10);
  auto gate = std::make_shared<Gate>();
  SchedulerThread scheduler(core, 0.05);
  FakeReader reader(core, chain, gate);
  Prefetcher prefetcher(reader, Prefetcher::Options{8});
  prefetcher.start();
  prefetcher.follow(1, before_first(), chain->tip);
  // Seven places for the prefetch lane: three full intervals and one block
  // of the fourth, whose next block waits for a place.
  ASSERT_TRUE(eventually([&] {
    std::lock_guard<std::mutex> lock(core->mutex());
    return core->prefetch_outstanding_locked() == limits.requests - limits.consumer_reserve;
  }));
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  {
    std::lock_guard<std::mutex> lock(core->mutex());
    ASSERT_EQ(core->prefetch_outstanding_locked(), limits.requests - limits.consumer_reserve);
    ASSERT_TRUE(core->outstanding_locked() <= limits.requests);
    ASSERT_TRUE(core->prefetch_bytes_locked() <= limits.prefetch_bytes);
  }
  ASSERT_TRUE(prefetcher.buffered() <= 8);
  ASSERT_TRUE(core->counters().outstanding_high_water.load() <= limits.requests);
  ASSERT_TRUE(core->counters().prefetch_bytes_high_water.load() <= limits.prefetch_bytes);
  // The replay thread's own read still gets the reserved place.
  ASSERT_OK(reader.masterchain(1));
  auto seen = consume(prefetcher, 1, chain->tip);
  ASSERT_OK(seen);
  ASSERT_TRUE(seen.ok() == expected_order(*chain, 1, chain->tip));
  ASSERT_TRUE(eventually([&] {
    std::lock_guard<std::mutex> lock(core->mutex());
    return core->outstanding_locked() == 0 && core->prefetch_bytes_locked() == 0;
  }));
  ASSERT_EQ(prefetcher.buffered(), 0u);
  core->shutdown();
}

// A failure is reported where it happened: the intervals before it are handed
// over intact, the failing block reports the source's own message, and after
// a reset the pipeline requests that block again instead of keeping the error.
TEST(WalletIndexSource, errors_surface_at_their_block_and_a_retry_requests_again) {
  auto core = make_core();
  auto chain = make_chain(8, 2);
  auto gate = std::make_shared<Gate>();
  const std::string refusal = "archive package needs repair by the node";
  auto failing = chain->order.at(4).at(1);
  gate->block_errors[failing] = refusal;
  gate->master_errors[7] = "source has no such masterchain block";
  SchedulerThread scheduler(core, 0.05);
  FakeReader reader(core, chain, gate);
  Prefetcher prefetcher(reader, Prefetcher::Options{});
  prefetcher.start();
  prefetcher.follow(1, before_first(), chain->tip);
  auto first = consume(prefetcher, 1, 3);
  ASSERT_OK(first);
  ASSERT_TRUE(first.ok() == expected_order(*chain, 1, 3));
  auto interval = prefetcher.interval(4).move_as_ok();
  ASSERT_OK(interval->error);
  ASSERT_TRUE(prefetcher.block_data(*interval, 0).is_ok());
  auto failed = prefetcher.block_data(*interval, 1);
  ASSERT_TRUE(failed.is_error());
  ASSERT_EQ(failed.error().message().str(), refusal);
  interval.reset();
  int requested_before;
  {
    std::lock_guard<std::mutex> lock(gate->mutex);
    requested_before = gate->block_requests[failing];
  }
  prefetcher.reset();
  prefetcher.follow(4, master_id(3), chain->tip);
  auto retried = consume(prefetcher, 4, 6);
  ASSERT_OK(retried);
  ASSERT_TRUE(retried.ok() == expected_order(*chain, 4, 6));
  {
    std::lock_guard<std::mutex> lock(gate->mutex);
    ASSERT_EQ(gate->block_requests[failing], requested_before + 1);
  }
  // A masterchain lookup failure is the interval's own error.
  auto missing = prefetcher.interval(7);
  ASSERT_OK(missing);
  ASSERT_TRUE(missing.ok()->error.is_error());
  ASSERT_EQ(missing.ok()->error.message().str(), std::string("source has no such masterchain block"));
  core->shutdown();
}

// Shutdown with requests queued, dispatched and waiting for a place: every
// waiter returns at once, the threads join, and replies that complete after
// the reader, the prefetcher and the statistics are gone touch none of them.
TEST(WalletIndexSource, shutdown_wakes_every_waiter_and_late_replies_are_harmless) {
  auto core = make_core(SourceLimits{3, 1, size_t{64} << 20});
  auto chain = make_chain(6, 3);
  auto gate = std::make_shared<Gate>();
  gate->hold_blocks = true;
  gate->hold_tips = true;
  {
    SchedulerThread scheduler(core, 0.05);
    auto stats = std::make_unique<ReplayStats>();
    auto reader = std::make_unique<FakeReader>(core, chain, gate, stats.get(), std::chrono::seconds(60));
    auto prefetcher = std::make_unique<Prefetcher>(*reader, Prefetcher::Options{});
    prefetcher->start();
    prefetcher->follow(1, before_first(), chain->tip);
    // Two prefetch places, both dispatched and held.
    ASSERT_TRUE(eventually([&] { return gate->held_count() == 2; }));
    // The replay thread waits for the first block; another consumer-lane
    // read holds the reserved place; a third waits for a place.
    td::Result<std::vector<BlockIdExt>> consumed = td::Status::Error("not run");
    td::thread consumer([&] { consumed = consume(*prefetcher, 1, chain->tip); });
    td::Result<BlockIdExt> tip = td::Status::Error("not run");
    td::thread tip_reader([&] { tip = reader->tip(); });
    ASSERT_TRUE(eventually([&] {
      std::lock_guard<std::mutex> lock(gate->mutex);
      return gate->held_tips.size() == 1;
    }));
    td::Result<validator::ConstBlockHandle> queued = td::Status::Error("not run");
    td::thread waiter([&] { queued = reader->masterchain(1); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto stopped_at = Clock::now();
    core->shutdown();
    consumer.join();
    tip_reader.join();
    waiter.join();
    prefetcher.reset();
    auto stopped = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - stopped_at);
    ASSERT_TRUE(stopped < std::chrono::milliseconds(1000));
    ASSERT_TRUE(consumed.is_error());
    ASSERT_TRUE(tip.is_error());
    ASSERT_TRUE(queued.is_error());
    ASSERT_EQ(queued.error().message().str(), std::string("source request cancelled"));
    reader.reset();
    stats.reset();
  }
  // The scheduler, reader, prefetcher and statistics are gone; complete the
  // held requests now. Only the core is touched, and every place returns.
  release_blocks(*gate, *chain, false);
  {
    std::vector<td::Promise<BlockIdExt>> tips;
    {
      std::lock_guard<std::mutex> lock(gate->mutex);
      tips.swap(gate->held_tips);
    }
    for (auto& promise : tips)
      promise.set_value(master_id(1));
  }
  std::lock_guard<std::mutex> lock(core->mutex());
  ASSERT_EQ(core->outstanding_locked(), 0u);
  ASSERT_EQ(core->prefetch_bytes_locked(), 0u);
}

// The deadline holds for every request, not only for ones a thread waits on:
// a request dropped by a reset that never completes still stops the process.
// A result that has completed is not timed out however long it waits to be
// taken.
TEST(WalletIndexSource, abandoned_requests_still_time_out_and_completed_ones_do_not) {
  {
    auto core = make_core();
    auto chain = make_chain(4, 1);
    auto gate = std::make_shared<Gate>();
    gate->hold_blocks = true;
    SchedulerThread scheduler(core, 0.05);
    FakeReader reader(core, chain, gate, nullptr, std::chrono::milliseconds(300));
    Prefetcher prefetcher(reader, Prefetcher::Options{});
    prefetcher.start();
    prefetcher.follow(1, before_first(), chain->tip);
    ASSERT_TRUE(eventually([&] { return gate->held_count() > 0; }));
    prefetcher.reset();
    ASSERT_TRUE(eventually([&] { return core->timed_out(); }, std::chrono::seconds(3)));
    ASSERT_TRUE(stop_requested.load());
    stop_requested = false;
    release_blocks(*gate, *chain, false);
  }
  {
    auto core = make_core();
    auto chain = make_chain(4, 1);
    auto gate = std::make_shared<Gate>();
    SchedulerThread scheduler(core, 0.05);
    FakeReader reader(core, chain, gate, nullptr, std::chrono::milliseconds(300));
    Prefetcher prefetcher(reader, Prefetcher::Options{});
    prefetcher.start();
    prefetcher.follow(1, before_first(), chain->tip);
    ASSERT_TRUE(eventually([&] { return prefetcher.buffered() == 4; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    ASSERT_TRUE(!core->timed_out());
    auto seen = consume(prefetcher, 1, chain->tip);
    ASSERT_OK(seen);
    core->shutdown();
  }
}

// Resets race completions: each round lets some blocks complete while the
// pipeline is reset and restarted, so completions, cancellations and
// retries interleave. Every interval handed over belongs to the current
// generation, every block is the one its handle names, and the places all
// return once the last late reply is in.
TEST(WalletIndexSource, resets_racing_completions_never_leak_an_old_generation) {
  auto core = make_core();
  auto chain = make_chain(30, 2);
  auto gate = std::make_shared<Gate>();
  gate->hold_blocks = true;
  SchedulerThread scheduler(core, 0.05);
  FakeReader reader(core, chain, gate);
  Prefetcher prefetcher(reader, Prefetcher::Options{});
  prefetcher.start();
  std::atomic<bool> done{false};
  td::thread releaser([&] {
    std::mt19937 random(11);
    while (!done.load()) {
      std::vector<std::pair<BlockIdExt, td::Promise<td::Ref<validator::BlockData>>>> held;
      {
        std::lock_guard<std::mutex> lock(gate->mutex);
        held.swap(gate->held_blocks);
      }
      std::shuffle(held.begin(), held.end(), random);
      for (auto& [id, promise] : held)
        promise.set_result(block_from(*chain, id));
      std::this_thread::sleep_for(std::chrono::microseconds(random() % 500));
    }
  });
  std::mt19937 random(5);
  uint32_t cursor = 0;
  for (int round = 0; round < 200 && cursor < chain->tip; ++round) {
    auto previous = cursor == 0 ? before_first() : master_id(cursor);
    prefetcher.follow(cursor + 1, previous, chain->tip);
    auto steps = 1 + random() % 3;
    for (uint32_t s = 0; s < steps && cursor < chain->tip; ++s) {
      auto interval = prefetcher.interval(cursor + 1);
      ASSERT_OK(interval);
      ASSERT_EQ(interval.ok()->generation, core->generation());
      bool whole = true;
      for (size_t i = 0; i < interval.ok()->blocks.size(); ++i) {
        // Sometimes give up mid-interval, as an index failure would.
        if (random() % 5 == 0) {
          whole = false;
          break;
        }
        auto data = prefetcher.block_data(*interval.ok(), i);
        ASSERT_OK(data);
        ASSERT_TRUE(IndexReader::checked_root(interval.ok()->blocks[i].handle, data.ok()).is_ok());
      }
      if (!whole)
        break;
      interval = td::Status::Error("released");
      prefetcher.pop(cursor + 1);
      ++cursor;
    }
    prefetcher.reset();
  }
  ASSERT_TRUE(cursor > 0);
  done = true;
  releaser.join();
  release_blocks(*gate, *chain, false);
  ASSERT_TRUE(eventually([&] {
    release_blocks(*gate, *chain, false);
    std::lock_guard<std::mutex> lock(core->mutex());
    return core->outstanding_locked() == 0 && core->prefetch_bytes_locked() == 0;
  }));
  core->shutdown();
}

namespace {
std::string temporary_directory() {
  return td::mkdtemp(td::get_temporary_dir(), "wallet-index-source").move_as_ok();
}

// Removes a test's directory when the test scope ends.
struct RemoveOnExit {
  std::string path;
  ~RemoveOnExit() {
    td::rmrf(path).ignore();
  }
};

// A replay loop over the fixture source and the index database in `path`,
// as one run of the service: destroying it is the process stopping.
struct ReplayHarness {
  ReplayHarness(std::shared_ptr<FakeChain> chain_in, uint32_t ceiling, std::string path_in)
      : core(make_core()), chain(std::move(chain_in)), gate(std::make_shared<Gate>()), path(std::move(path_in)) {
    tos_wallet_index::set_wallet_index_db(tos_wallet_index::WalletIndexDb::open(path + "/index").move_as_ok());
    scheduler = std::make_unique<SchedulerThread>(core, 0.05);
    reader = std::make_unique<FakeReader>(core, chain, gate, &stats);
    prefetcher = std::make_unique<Prefetcher>(*reader, Prefetcher::Options{});
    prefetcher->start();
    replay = std::make_unique<ReplayLoop>(*reader, *prefetcher, progress, stats, ceiling);
  }
  ~ReplayHarness() {
    core->shutdown();
    replay.reset();
    prefetcher.reset();
    reader.reset();
    scheduler.reset();
    tos_wallet_index::release_wc0_index_state();
    tos_wallet_index::set_wallet_index_db(nullptr);
    stop_requested = false;
  }
  td::Status run_until_idle() {
    for (int i = 0; i < 1000; ++i) {
      TRY_STATUS(replay->step());
      if (replay->idle())
        return td::Status::OK();
    }
    return td::Status::Error("replay never went idle");
  }
  std::shared_ptr<SourceCore> core;
  std::shared_ptr<FakeChain> chain;
  std::shared_ptr<Gate> gate;
  std::string path;
  Progress progress;
  ReplayStats stats;
  std::unique_ptr<SchedulerThread> scheduler;
  std::unique_ptr<FakeReader> reader;
  std::unique_ptr<Prefetcher> prefetcher;
  std::unique_ptr<ReplayLoop> replay;
};

// Every key and value of a stopped index, in key order.
std::vector<std::pair<std::string, std::string>> index_content(const std::string& path) {
  std::vector<std::pair<std::string, std::string>> rows;
  auto db = td::RocksDb::open(path + "/index").move_as_ok();
  db.for_each([&](td::Slice key, td::Slice value) {
      rows.emplace_back(key.str(), value.str());
      return td::Status::OK();
    }).ensure();
  return rows;
}
}  // namespace

// Readiness belongs to the observation of the source, not to the end of the
// replay that followed it: a blocked source and a slow consumer both leave
// /readyz unready, and a ceiling below the tip never makes it ready.
TEST(WalletIndexSource, readiness_expires_from_the_observation_and_a_ceiling_is_not_the_tip) {
  {
    auto dir = temporary_directory();
    RemoveOnExit remove{dir};
    ReplayHarness h(make_chain(5, 1), 0, dir);
    ASSERT_OK(h.run_until_idle());
    ASSERT_EQ(h.progress.cursor.load(), 5u);
    ASSERT_TRUE(h.progress.is_ready(td::Time::now()));
    // The source stops answering: the step blocks in its observation, and
    // readiness expires five seconds after the last one.
    {
      std::lock_guard<std::mutex> lock(h.gate->mutex);
      h.gate->hold_tips = true;
    }
    td::Status blocked;
    td::thread stepper([&] { blocked = h.replay->step(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(5500));
    ASSERT_TRUE(!h.progress.is_ready(td::Time::now()));
    {
      std::lock_guard<std::mutex> lock(h.gate->mutex);
      h.gate->hold_tips = false;
      for (auto& promise : h.gate->held_tips)
        promise.set_value(h.chain->masters.at(h.chain->tip)->id());
      h.gate->held_tips.clear();
    }
    stepper.join();
    ASSERT_OK(blocked);
    // That step's observation was asked for 5.5 s ago: still not fresh.
    ASSERT_TRUE(!h.progress.is_ready(td::Time::now()));
    ASSERT_OK(h.replay->step());
    ASSERT_TRUE(h.progress.is_ready(td::Time::now()));
  }
  {
    // One block behind; its data arrives six seconds after the tip was
    // observed. Replay catches up, but what it caught up to is six seconds
    // old, so it is not reported as freshly checked.
    auto dir = temporary_directory();
    RemoveOnExit remove{dir};
    ReplayHarness h(make_chain(4, 1), 0, dir);
    h.chain->tip = 3;
    ASSERT_OK(h.run_until_idle());
    ASSERT_TRUE(h.progress.is_ready(td::Time::now()));
    h.chain->tip = 4;
    {
      std::lock_guard<std::mutex> lock(h.gate->mutex);
      h.gate->hold_blocks = true;
    }
    td::Status slow;
    td::thread stepper([&] { slow = h.replay->step(); });
    ASSERT_TRUE(eventually([&] { return h.gate->held_count() == 1; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(6000));
    release_blocks(*h.gate, *h.chain, false);
    stepper.join();
    ASSERT_OK(slow);
    ASSERT_EQ(h.progress.cursor.load(), 4u);
    ASSERT_TRUE(h.progress.ready.load());
    ASSERT_TRUE(!h.progress.is_ready(td::Time::now()));
    {
      std::lock_guard<std::mutex> lock(h.gate->mutex);
      h.gate->hold_blocks = false;
    }
    ASSERT_OK(h.replay->step());
    ASSERT_TRUE(h.progress.is_ready(td::Time::now()));
  }
  {
    auto dir = temporary_directory();
    RemoveOnExit remove{dir};
    ReplayHarness h(make_chain(6, 1), 4, dir);
    ASSERT_OK(h.run_until_idle());
    ASSERT_EQ(h.progress.cursor.load(), 4u);
    ASSERT_EQ(h.progress.tip.load(), 6u);
    ASSERT_TRUE(h.progress.settled.load());
    ASSERT_TRUE(!h.progress.ready.load());
    ASSERT_TRUE(!h.progress.is_ready(td::Time::now()));
  }
}

// An index replayed with interruptions (a source failure in the middle of an
// interval, and the service stopping and starting again from its durable
// checkpoint) holds exactly the content of one replayed straight through.
TEST(WalletIndexSource, a_restarted_replay_matches_an_uninterrupted_one) {
  auto chain = make_chain(24, 2);
  auto straight_dir = temporary_directory();
  auto restarted_dir = temporary_directory();
  {
    ReplayHarness h(chain, 0, straight_dir);
    ASSERT_OK(h.run_until_idle());
    ASSERT_EQ(h.progress.cursor.load(), 24u);
  }
  {
    ReplayHarness h(chain, 7, restarted_dir);
    ASSERT_OK(h.run_until_idle());
    ASSERT_EQ(h.progress.cursor.load(), 7u);
  }
  {
    // The second block of interval 8 fails once, after the first was walked.
    ReplayHarness h(chain, 12, restarted_dir);
    h.gate->block_errors[chain->order.at(8).at(1)] = "transient source failure";
    auto failed = h.replay->step();
    ASSERT_TRUE(failed.is_error());
    ASSERT_EQ(h.progress.cursor.load(), 7u);
    ASSERT_OK(h.run_until_idle());
    ASSERT_EQ(h.progress.cursor.load(), 12u);
  }
  {
    ReplayHarness h(chain, 0, restarted_dir);
    ASSERT_OK(h.run_until_idle());
    ASSERT_EQ(h.progress.cursor.load(), 24u);
  }
  auto straight = index_content(straight_dir);
  auto restarted = index_content(restarted_dir);
  td::rmrf(straight_dir).ignore();
  td::rmrf(restarted_dir).ignore();
  // More than the schema and the checkpoint: every block left events.
  ASSERT_TRUE(straight.size() > 48);
  ASSERT_TRUE(straight == restarted);
}
