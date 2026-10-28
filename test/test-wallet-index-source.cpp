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

#include "common/errorcode.h"
#include "services/index-prefetch.h"
#include "services/index-reader.h"
#include "services/index-replay-loop.h"
#include "services/service-common.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/port/thread.h"
#include "td/utils/tests.h"
#include "validator/db/package.hpp"
#include "validator/fabric.h"
#include "vm/boc.h"
#include "vm/cells/DataCell.h"

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

// A masterchain block of the fixture: only its identity matters, so its root
// is one cell naming its seqno, or that cell with a payload hanging off it.
td::Ref<vm::Cell> master_root(uint32_t seqno, td::Ref<vm::Cell> payload = {}) {
  vm::CellBuilder cb;
  cb.store_long(0x6d617374, 32);
  cb.store_long(seqno, 32);
  if (payload.not_null())
    cb.store_ref(payload);
  return cb.finalize();
}

BlockIdExt block_id_of(int workchain, uint32_t seqno, const td::Ref<vm::Cell>& root, const td::BufferSlice& boc) {
  td::Bits256 file_hash;
  td::sha256(boc.as_slice(), file_hash.as_slice());
  if (workchain == masterchainId)
    return BlockIdExt{masterchainId, shardIdAll, seqno, root->get_hash().bits(), file_hash};
  return BlockIdExt{workchain, shardIdAll, seqno, root->get_hash().bits(), file_hash};
}

// The identity of the plain fixture masterchain block `seqno`.
BlockIdExt master_id(uint32_t seqno) {
  auto root = master_root(seqno);
  return block_id_of(masterchainId, seqno, root, vm::std_boc_serialize(root, 31).move_as_ok());
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

// The fixture block `root` with `payload` hanging off its value flow, which
// the index never reads: a block of a chosen size that still indexes.
td::Ref<vm::Cell> with_payload(const td::Ref<vm::Cell>& root, const td::Ref<vm::Cell>& payload) {
  auto cs = vm::load_cell_slice(root);
  vm::CellBuilder flow;
  flow.store_long(0, 1);
  flow.store_ref(payload);
  vm::CellBuilder out;
  CHECK(out.store_bits_bool(cs.data_bits(), static_cast<unsigned>(cs.size())) &&
        out.store_ref_bool(cs.prefetch_ref(0)) && out.store_ref_bool(flow.finalize()) &&
        out.store_ref_bool(cs.prefetch_ref(2)) && out.store_ref_bool(cs.prefetch_ref(3)));
  return out.finalize();
}

struct ChainOptions {
  // Payload hung off each shard block, and off every `oversized_every`-th
  // shard block instead `oversized_bytes` of it (0: none).
  size_t payload_bytes = 0;
  uint32_t oversized_every = 0;
  size_t oversized_bytes = (size_t{9} << 20) / 2;
  // Payload hung off each masterchain block, and off masterchain block
  // `oversized_master` instead `oversized_bytes` of it (0: none).
  size_t master_payload_bytes = 0;
  uint32_t oversized_master = 0;
  // Serialization mode of every block; 0 stores no hashes, so decoding a
  // block's root materializes every cell under it.
  int boc_mode = 31;
  // When set, every block is also stored in a package file in this
  // directory and raw reads go through the archive's size-limited read.
  std::string package_dir;
};

// Masterchain blocks 1..masters; interval n holds `per_interval` basechain
// blocks, each the child of the one before, the first the child of the last
// block of interval n-1.
struct FakeChain {
  std::map<uint32_t, validator::BlockHandle> masters;
  std::map<uint32_t, std::vector<BlockIdExt>> heads;
  std::map<uint32_t, std::vector<BlockIdExt>> order;
  std::map<BlockIdExt, validator::BlockHandle> shards;
  std::map<BlockIdExt, std::string> data;
  std::shared_ptr<Package> package;
  std::map<BlockIdExt, td::uint64> offsets;
  uint32_t tip = 0;
};

std::shared_ptr<FakeChain> make_chain(uint32_t masters, uint32_t per_interval, ChainOptions options) {
  auto chain = std::make_shared<FakeChain>();
  if (!options.package_dir.empty()) {
    chain->package =
        std::make_shared<Package>(Package::open(options.package_dir + "/blocks.pack", false, true).move_as_ok());
  }
  auto store = [&](const BlockIdExt& id, const td::BufferSlice& boc) {
    chain->data[id] = boc.as_slice().str();
    if (chain->package)
      chain->offsets[id] = chain->package->append(id.to_str(), boc.as_slice(), false);
  };
  BlockIdExt previous_shard{0, shardIdAll, 0, td::Bits256::zero(), td::Bits256::zero()};
  BlockIdExt previous_master;
  uint32_t shard_seqno = 0;
  for (uint32_t n = 1; n <= masters; ++n) {
    size_t master_bytes = n == options.oversized_master ? options.oversized_bytes : options.master_payload_bytes;
    auto master_cell = master_root(n, master_bytes ? payload(master_bytes, n) : td::Ref<vm::Cell>());
    auto master_boc = vm::std_boc_serialize(master_cell, options.boc_mode).move_as_ok();
    auto mid = block_id_of(masterchainId, n, master_cell, master_boc);
    master_cell = {};
    store(mid, master_boc);
    auto master = validator::create_empty_block_handle(mid);
    master->set_merge(false);
    if (n > 1)
      master->set_prev(previous_master);
    master->set_applied();
    // A fixture handle is never written; mark it as such.
    master->flushed_upto(master->version());
    chain->masters[n] = master;
    previous_master = mid;
    for (uint32_t j = 0; j < per_interval; ++j) {
      ++shard_seqno;
      td::Bits256 account;
      account.set_zero();
      account.as_slice().copy_from(td::Slice(reinterpret_cast<const char*>(&shard_seqno), sizeof(shard_seqno)));
      auto root = wallet_index_fixture::block(shard_seqno, 1000ull * shard_seqno, 1000 + shard_seqno,
                                              {wallet_index_fixture::Tx{account, 1000ull * shard_seqno - 10, 0}});
      bool oversized = options.oversized_every != 0 && shard_seqno % options.oversized_every == 0;
      size_t bytes = oversized ? options.oversized_bytes : options.payload_bytes;
      if (bytes)
        root = with_payload(root, payload(bytes, shard_seqno));
      auto boc = vm::std_boc_serialize(root, options.boc_mode).move_as_ok();
      auto id = block_id_of(0, shard_seqno, root, boc);
      root = {};
      auto handle = validator::create_empty_block_handle(id);
      handle->set_merge(false);
      handle->set_prev(previous_shard);
      handle->set_masterchain_ref_block(n);
      handle->set_applied();
      handle->flushed_upto(handle->version());
      chain->shards[id] = handle;
      store(id, boc);
      chain->order[n].push_back(id);
      previous_shard = id;
    }
    chain->heads[n] = {previous_shard};
  }
  if (chain->package)
    chain->package->sync();
  chain->tip = masters;
  return chain;
}

std::shared_ptr<FakeChain> make_chain(uint32_t masters, uint32_t per_interval, size_t payload_bytes = 0) {
  ChainOptions options;
  options.payload_bytes = payload_bytes;
  return make_chain(masters, per_interval, options);
}

// What the fixture source does with requests: answer at once, or hold shard
// block reads until the test releases them, and fail chosen ones.
struct Gate {
  std::mutex mutex;
  bool hold_blocks = false;
  bool hold_tips = false;
  std::vector<std::pair<BlockIdExt, td::Promise<td::BufferSlice>>> held_blocks;
  std::vector<td::Promise<BlockIdExt>> held_tips;
  // Errors for the next request of these blocks, then cleared.
  std::map<BlockIdExt, std::string> block_errors;
  std::map<uint32_t, std::string> master_errors;
  std::map<BlockIdExt, int> block_requests;
  // Blocks the replay thread read on its own lane.
  std::map<BlockIdExt, int> replay_reads;
  size_t held_count() {
    std::lock_guard<std::mutex> lock(mutex);
    return held_blocks.size();
  }
};

// A block as the archive's size-limited read returns it: from the package
// file when the chain has one, otherwise refusing a block over the limit the
// way the archive does.
td::Result<td::BufferSlice> raw_from(const FakeChain& chain, const BlockIdExt& id) {
  if (chain.package) {
    auto offset = chain.offsets.find(id);
    if (offset == chain.offsets.end())
      return td::Status::Error("no such block in the fixture");
    TRY_RESULT(entry, chain.package->read(offset->second, static_cast<td::uint32>(kPrefetchBlockBytesMax)));
    return std::move(entry.second);
  }
  auto it = chain.data.find(id);
  if (it == chain.data.end())
    return td::Status::Error("no such block in the fixture");
  if (it->second.size() > kPrefetchBlockBytesMax)
    return td::Status::Error(ErrorCode::error, td::Slice(kFileOverReadLimit));
  return td::BufferSlice(it->second);
}

td::Result<td::Ref<validator::BlockData>> block_from(const FakeChain& chain, const BlockIdExt& id) {
  auto it = chain.data.find(id);
  if (it == chain.data.end())
    return td::Status::Error("no such block in the fixture");
  return validator::create_block(id, td::BufferSlice(it->second));
}

void release_blocks(Gate& gate, const FakeChain& chain, bool reverse) {
  std::vector<std::pair<BlockIdExt, td::Promise<td::BufferSlice>>> held;
  {
    std::lock_guard<std::mutex> lock(gate.mutex);
    held.swap(gate.held_blocks);
  }
  if (reverse)
    std::reverse(held.begin(), held.end());
  for (auto& [id, promise] : held)
    promise.set_result(raw_from(chain, id));
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
  td::Result<std::vector<BlockIdExt>> shard_heads(validator::ConstBlockHandle master) override {
    return query<std::vector<BlockIdExt>>(
        [chain = chain_, seqno = master->id().seqno()](auto, td::Promise<std::vector<BlockIdExt>> promise) {
          promise.set_value(std::vector<BlockIdExt>(chain->heads[seqno]));
        });
  }
  td::Result<std::shared_ptr<SourceReply<RawBlock>>> submit_block(validator::ConstBlockHandle handle,
                                                                  Context context) override {
    return submit_raw_block(
        [chain = chain_, gate = gate_, id = handle->id()](auto, td::Promise<td::BufferSlice> promise) {
          std::unique_lock<std::mutex> lock(gate->mutex);
          if (!id.is_masterchain()) {
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
          }
          lock.unlock();
          promise.set_result(raw_from(*chain, id));
        },
        context);
  }
  td::Result<td::Ref<validator::BlockData>> read_block(validator::ConstBlockHandle handle) override {
    return query<td::Ref<validator::BlockData>>(
        [chain = chain_, gate = gate_, id = handle->id()](auto, td::Promise<td::Ref<validator::BlockData>> promise) {
          {
            std::lock_guard<std::mutex> lock(gate->mutex);
            gate->replay_reads[id]++;
          }
          promise.set_result(block_from(*chain, id));
        });
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

 protected:
  // The fixture's masterchain blocks record no shard configuration: decode
  // and check the block as the source does, then supply its heads.
  td::Result<std::vector<BlockIdExt>> decoded_shard_heads(const validator::ConstBlockHandle& master,
                                                          td::BufferSlice data) override {
    TRY_RESULT(block, decode_block(master->id(), std::move(data)));
    TRY_STATUS(checked_root(master, block));
    return std::vector<BlockIdExt>(chain_->heads.at(master->id().seqno()));
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
        std::vector<std::pair<BlockIdExt, td::Promise<td::BufferSlice>>> held;
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
          promise.set_result(raw_from(*chain, id));
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
        std::vector<std::pair<BlockIdExt, td::Promise<td::BufferSlice>>> held;
        {
          std::lock_guard<std::mutex> lock(gate->mutex);
          if (gate->held_blocks.size() >= 2)
            held.swap(gate->held_blocks);
        }
        std::reverse(held.begin(), held.end());
        for (auto& [id, promise] : held)
          promise.set_result(raw_from(*chain, id));
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
          promise.set_result(raw_from(*chain, id));
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
      std::vector<std::pair<BlockIdExt, td::Promise<td::BufferSlice>>> held;
      {
        std::lock_guard<std::mutex> lock(gate->mutex);
        held.swap(gate->held_blocks);
      }
      std::shuffle(held.begin(), held.end(), random);
      for (auto& [id, promise] : held)
        promise.set_result(raw_from(*chain, id));
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

// A restart with a ceiling below the durable cursor is refused instead of
// replaying nothing and never going idle; the ceiling at the cursor settles.
TEST(WalletIndexSource, a_ceiling_below_the_durable_cursor_is_refused) {
  auto dir = temporary_directory();
  RemoveOnExit remove{dir};
  {
    ReplayHarness h(make_chain(5, 1), 0, dir);
    ASSERT_OK(h.run_until_idle());
    ASSERT_EQ(h.progress.cursor.load(), 5u);
  }
  {
    ReplayHarness h(make_chain(5, 1), 3, dir);
    auto status = h.replay->step();
    ASSERT_TRUE(status.is_error());
    ASSERT_TRUE(status.message().str().find("past the replay ceiling") != std::string::npos);
    ASSERT_TRUE(!h.replay->idle());
  }
  {
    ReplayHarness h(make_chain(5, 1), 5, dir);
    ASSERT_OK(h.run_until_idle());
    ASSERT_EQ(h.progress.cursor.load(), 5u);
  }
}

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

namespace {
// Prefetch-lane bytes held and places taken, read under the core mutex.
struct Held {
  size_t bytes = 0;
  size_t outstanding = 0;
};
Held held(SourceCore& core) {
  std::lock_guard<std::mutex> lock(core.mutex());
  return Held{core.prefetch_bytes_locked(), core.outstanding_locked()};
}

// Requests issued and completed so far are equal, and stay equal for a
// moment: nothing more is being read.
bool quiet(SourceCore& core) {
  auto settled = [&] { return core.counters().requests.load() == core.counters().completed.load(); };
  if (!settled())
    return false;
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  return settled();
}
}  // namespace

// The archive's size-limited read refuses an entry over the limit from its
// header alone, and reads one within it whole; without a limit it reads
// anything, as every node path does.
TEST(WalletIndexSource, a_size_limited_archive_read_refuses_before_reading_the_bytes) {
  auto dir = temporary_directory();
  RemoveOnExit remove{dir};
  auto package = Package::open(dir + "/limit.pack", false, true).move_as_ok();
  std::string big(kPrefetchBlockBytesMax + 1, 'b');
  std::string fits(kPrefetchBlockBytesMax, 'f');
  auto big_at = package.append("big", big, false);
  auto fits_at = package.append("fits", fits, false);
  auto refused = package.read(big_at, static_cast<td::uint32>(kPrefetchBlockBytesMax));
  ASSERT_TRUE(refused.is_error());
  ASSERT_EQ(refused.error().message().str(), std::string(kFileOverReadLimit));
  auto as_raw = raw_block(refused.move_as_error());
  ASSERT_OK(as_raw);
  ASSERT_TRUE(as_raw.ok().too_large);
  ASSERT_EQ(as_raw.ok().data.size(), 0u);
  ASSERT_EQ(raw_block_charge(as_raw), kSourceResultOverheadBytes);
  auto read = package.read(fits_at, static_cast<td::uint32>(kPrefetchBlockBytesMax));
  ASSERT_OK(read);
  ASSERT_TRUE(read.ok().second.as_slice() == td::Slice(fits));
  auto unlimited = package.read(big_at);
  ASSERT_OK(unlimited);
  ASSERT_EQ(unlimited.ok().second.size(), big.size());
}

// Large and oversized blocks complete together while nothing is consumed:
// every read reserved the largest result before it was issued, so the
// completions never take the prefetch lane past its budget, the oversized
// ones hold no bytes, and the buffers retained are the charged ones. The
// replay thread then reads each oversized block on its own lane, and every
// reservation is returned.
TEST(WalletIndexSource, large_and_oversized_results_completing_together_stay_within_the_budget) {
  auto dir = temporary_directory();
  RemoveOnExit remove{dir};
  ChainOptions options;
  options.payload_bytes = (size_t{7} << 20) / 2;  // serialized: about 3.9 MiB, under the limit
  options.oversized_every = 3;                    // serialized: about 4.8 MiB, over it
  options.package_dir = dir;
  auto chain = make_chain(8, 2, options);
  SourceLimits limits{8, 1, 4 * kSourceBlockReserveBytes};
  for (auto& [id, data] : chain->data) {
    if (!id.is_masterchain() && data.size() <= kPrefetchBlockBytesMax)
      ASSERT_TRUE(data.size() > (size_t{7} << 20) / 2);
  }
  // What a prefetched interval charges for its handles, outside the
  // reservation of any read.
  const size_t handles = 8 * 3 * kSourceHandleBytes;
  auto core = make_core(limits);
  auto gate = std::make_shared<Gate>();
  gate->hold_blocks = true;
  SchedulerThread scheduler(core, 0.05);
  FakeReader reader(core, chain, gate);
  auto buffers_before = td::BufferAllocator::get_buffer_mem();
  Prefetcher prefetcher(reader, Prefetcher::Options{});
  prefetcher.start();
  prefetcher.follow(1, before_first(), chain->tip);
  size_t released = 0;
  // The most results of each kind completed in one release.
  size_t most_large = 0, most_oversized = 0;
  for (int round = 0; round < 50; ++round) {
    // Let the prefetch lane fill to its limits with every block held, then
    // complete all of them at once.
    ASSERT_TRUE(eventually([&] { return gate->held_count() > 0 || quiet(*core); }));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto before = held(*core);
    ASSERT_TRUE(before.bytes <= limits.prefetch_bytes + handles);
    auto count = gate->held_count();
    if (count == 0)
      break;
    released += count;
    {
      std::lock_guard<std::mutex> lock(gate->mutex);
      size_t large = 0, oversized = 0;
      for (auto& entry : gate->held_blocks)
        ++(chain->data.at(entry.first).size() > kPrefetchBlockBytesMax ? oversized : large);
      most_large = std::max(most_large, large);
      most_oversized = std::max(most_oversized, oversized);
    }
    release_blocks(*gate, *chain, round % 2 == 1);
    auto after = held(*core);
    ASSERT_TRUE(after.bytes <= limits.prefetch_bytes + handles);
  }
  ASSERT_TRUE(released >= 4);
  ASSERT_TRUE(most_large >= 2);
  ASSERT_TRUE(most_oversized >= 1);
  ASSERT_TRUE(eventually([&] { return quiet(*core); }));
  auto full = held(*core);
  ASSERT_TRUE(full.bytes <= limits.prefetch_bytes + handles);
  ASSERT_TRUE(core->counters().prefetch_bytes_high_water.load() <= limits.prefetch_bytes + handles);
  // The buffers kept alive are the charged ones: nothing beyond the charge
  // (bytes plus a fixed allowance each) is retained for a completed result.
  auto buffers_held =
      td::BufferAllocator::get_buffer_mem() - std::min(buffers_before, td::BufferAllocator::get_buffer_mem());
  ASSERT_TRUE(buffers_held <= full.bytes + (size_t{1} << 20));
  {
    std::lock_guard<std::mutex> lock(gate->mutex);
    ASSERT_TRUE(gate->replay_reads.empty());
    gate->hold_blocks = false;
  }
  release_blocks(*gate, *chain, false);
  auto seen = consume(prefetcher, 1, chain->tip);
  ASSERT_OK(seen);
  ASSERT_TRUE(seen.ok() == expected_order(*chain, 1, chain->tip));
  size_t oversized = 0;
  {
    std::lock_guard<std::mutex> lock(gate->mutex);
    for (auto& [id, data] : chain->data) {
      if (!id.is_masterchain() && data.size() > kPrefetchBlockBytesMax) {
        ++oversized;
        ASSERT_EQ(gate->replay_reads[id], 1);
      }
    }
  }
  ASSERT_EQ(oversized, 5u);
  ASSERT_TRUE(eventually([&] {
    auto now = held(*core);
    return now.bytes == 0 && now.outstanding == 0;
  }));
  core->shutdown();
}

// A block over the prefetch limit is read by the replay thread on its own
// lane and indexed like any other: replay reaches the tip, every shard block
// is walked, and only the oversized block was read on the replay lane.
TEST(WalletIndexSource, an_oversized_block_is_read_on_the_replay_lane_and_applied) {
  auto dir = temporary_directory();
  RemoveOnExit remove{dir};
  ChainOptions options;
  options.oversized_every = 5;
  auto chain = make_chain(4, 2, options);
  ReplayHarness h(chain, 0, dir);
  ASSERT_OK(h.run_until_idle());
  ASSERT_EQ(h.progress.cursor.load(), 4u);
  ASSERT_EQ(h.stats.shard_blocks.load(), 8u);
  auto oversized = chain->order.at(3).at(0);
  ASSERT_TRUE(chain->data.at(oversized).size() > kPrefetchBlockBytesMax);
  std::lock_guard<std::mutex> lock(h.gate->mutex);
  ASSERT_EQ(h.gate->replay_reads.size(), 1u);
  ASSERT_EQ(h.gate->replay_reads[oversized], 1);
}

// A masterchain block over the prefetch limit: the prefetch lane reads none
// of its interval, and the replay thread reads that interval's shard heads,
// handles and blocks itself, then continues from what was read ahead.
TEST(WalletIndexSource, an_oversized_masterchain_block_is_replayed_on_the_replay_lane) {
  auto dir = temporary_directory();
  RemoveOnExit remove{dir};
  ChainOptions options;
  options.oversized_master = 2;
  auto chain = make_chain(4, 2, options);
  ASSERT_TRUE(chain->data.at(chain->masters.at(2)->id()).size() > kPrefetchBlockBytesMax);
  ReplayHarness h(chain, 0, dir);
  ASSERT_OK(h.run_until_idle());
  ASSERT_EQ(h.progress.cursor.load(), 4u);
  ASSERT_EQ(h.stats.shard_blocks.load(), 8u);
  std::lock_guard<std::mutex> lock(h.gate->mutex);
  ASSERT_EQ(h.gate->replay_reads.size(), 2u);
  for (auto& id : chain->order.at(2)) {
    ASSERT_EQ(h.gate->replay_reads[id], 1);
    ASSERT_EQ(h.gate->block_requests.count(id), 0u);
  }
}

// Blocks serialized without stored hashes decode into every cell they hold.
// The prefetch lane keeps such shard blocks as bytes until the replay thread
// takes them, and decodes each masterchain block only long enough to read
// its shard heads: with the whole read-ahead done, no decoded cells remain.
TEST(WalletIndexSource, prefetch_leaves_no_decoded_blocks_behind) {
  ChainOptions options;
  options.payload_bytes = 256u << 10;
  options.master_payload_bytes = 256u << 10;
  options.boc_mode = 0;
  auto chain = make_chain(4, 2, options);
  auto core = make_core();
  auto gate = std::make_shared<Gate>();
  SchedulerThread scheduler(core, 0.05);
  FakeReader reader(core, chain, gate);
  // One decoded block of this chain is about this many cells.
  auto cells_per_block = static_cast<td::int64>(options.payload_bytes / 128);
  auto cells_before = vm::DataCell::get_total_data_cells();
  Prefetcher prefetcher(reader, Prefetcher::Options{});
  prefetcher.start();
  prefetcher.follow(1, before_first(), chain->tip);
  ASSERT_TRUE(eventually([&] { return prefetcher.buffered() == 4 && quiet(*core); }));
  // Four masterchain reads and eight shard block reads, all complete.
  ASSERT_TRUE(core->counters().completed.load() >= 12u);
  auto cells_prefetched = vm::DataCell::get_total_data_cells() - cells_before;
  ASSERT_TRUE(cells_prefetched < cells_per_block / 4);
  // Taking a block decodes it on the taking thread.
  auto interval = prefetcher.interval(1);
  ASSERT_OK(interval);
  auto data = prefetcher.block_data(*interval.ok(), 0);
  ASSERT_OK(data);
  ASSERT_OK(IndexReader::checked_root(interval.ok()->blocks[0].handle, data.ok()));
  ASSERT_TRUE(vm::DataCell::get_total_data_cells() - cells_before > cells_per_block);
  data = td::Status::Error("released");
  auto second = prefetcher.block_data(*interval.ok(), 1);
  ASSERT_OK(second);
  ASSERT_OK(IndexReader::checked_root(interval.ok()->blocks[1].handle, second.ok()));
  second = td::Status::Error("released");
  interval = td::Status::Error("released");
  prefetcher.pop(1);
  auto rest = consume(prefetcher, 2, chain->tip);
  ASSERT_OK(rest);
  ASSERT_TRUE(rest.ok() == expected_order(*chain, 2, chain->tip));
  core->shutdown();
}

// A completion at or after the request's deadline is a timeout: the result
// is never handed over, whether a waiter was blocked on it or nobody waits.
// One that arrives before the deadline is handed over. Either way the
// reservation returns when the reply is released.
TEST(WalletIndexSource, a_completion_after_the_deadline_is_a_timeout) {
  const auto deadline = std::chrono::milliseconds(10);
  const size_t reserve = 64u << 10;
  for (bool waited : {true, false}) {
    auto core = make_core();
    auto generation = core->generation();
    auto started = Clock::now();
    auto ticket = core->acquire(SourceLane::Prefetch, generation, reserve, deadline);
    ASSERT_OK(ticket);
    auto reply = std::make_shared<SourceReply<int>>(core, ticket.move_as_ok(), SourceLane::Prefetch, generation);
    td::Result<int> taken = td::Status::Error("not taken");
    if (waited) {
      td::thread waiter([&] { taken = reply->take(); });
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
      {
        // The waiter cannot get the mutex back between its deadline and the
        // completion at 50 ms.
        std::unique_lock<std::mutex> lock(core->mutex());
        std::this_thread::sleep_until(started + std::chrono::milliseconds(50));
        reply->complete_locked(42, 8);
      }
      waiter.join();
      ASSERT_TRUE(taken.is_error());
      ASSERT_TRUE(taken.error().message().str().find("timed out") != std::string::npos);
    } else {
      std::this_thread::sleep_until(started + std::chrono::milliseconds(50));
      reply->complete(42, 8);
    }
    ASSERT_TRUE(core->timed_out());
    ASSERT_TRUE(stop_requested.load());
    // The late result was never published: its reservation is unchanged and
    // nothing can take it.
    ASSERT_EQ(held(*core).bytes, reserve);
    ASSERT_TRUE(reply->take().is_error());
    reply.reset();
    auto now = held(*core);
    ASSERT_EQ(now.bytes, 0u);
    ASSERT_EQ(now.outstanding, 0u);
    stop_requested = false;
  }
  // In time: handed over, and nothing times out.
  bool checked = false;
  for (int attempt = 0; attempt < 5 && !checked; ++attempt) {
    auto core = make_core();
    auto generation = core->generation();
    auto ticket = core->acquire(SourceLane::Prefetch, generation, reserve, deadline);
    ASSERT_OK(ticket);
    auto issued = Clock::now();
    auto reply = std::make_shared<SourceReply<int>>(core, ticket.move_as_ok(), SourceLane::Prefetch, generation);
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    if (Clock::now() - issued >= std::chrono::milliseconds(9))
      continue;  // the host stalled this thread past the deadline; try again
    reply->complete(42, 8);
    auto result = reply->take();
    ASSERT_OK(result);
    ASSERT_EQ(result.ok(), 42);
    ASSERT_TRUE(!core->timed_out());
    reply.reset();
    auto now = held(*core);
    ASSERT_EQ(now.bytes, 0u);
    ASSERT_EQ(now.outstanding, 0u);
    checked = true;
  }
  ASSERT_TRUE(checked);
}
