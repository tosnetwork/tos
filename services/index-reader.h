/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <memory>
#include <optional>

#include "validator/db/rootdb.hpp"
#include "validator/interfaces/block.h"

#include "index-progress.h"
#include "index-source.h"
#include "service-common.h"

namespace tos::services {

// The largest block the prefetch lane reads. The archive refuses a larger
// block after reading only its entry header, before allocating its bytes,
// and the replay thread then reads that block itself on its own lane.
inline constexpr size_t kPrefetchBlockBytesMax = size_t{4} << 20;
// Objects a buffered result keeps besides its bytes: the reply, the raw
// block and the rounding of its buffer.
inline constexpr size_t kSourceResultOverheadBytes = 4096;
// A handle lookup's result, and each handle a prefetched interval keeps.
inline constexpr size_t kSourceHandleBytes = 1024;
// Reserved against the prefetch byte budget before a block read is issued:
// the most a prefetched block can hold. On completion the reservation
// becomes the result's own charge (raw_block_charge), which is never larger.
inline constexpr size_t kSourceBlockReserveBytes = kPrefetchBlockBytesMax + kSourceResultOverheadBytes;

// A block as the prefetch lane reads it: its serialized bytes, undecoded.
// Cells are decoded only by the thread that uses the block, when it does.
struct RawBlock {
  td::BufferSlice data;
  // Larger than kPrefetchBlockBytesMax: `data` is empty, nothing of the
  // block was read, and the replay thread reads it on its own lane.
  bool too_large = false;
};

// The raw block a size-limited read produced. Its buffer holds only this
// block's bytes: a buffer small enough to have come from a shared slab is
// copied into one of its own, so a result never keeps other memory alive.
td::Result<RawBlock> raw_block(td::Result<td::BufferSlice> read);
// What a completed block read holds until it is taken: its bytes plus the
// fixed allowance; a refusal or an error holds only the allowance.
size_t raw_block_charge(const td::Result<RawBlock>& result);
// Decode a block's bytes, checking they are the block `id` names.
td::Result<td::Ref<validator::BlockData>> decode_block(const BlockIdExt& id, td::BufferSlice data);

// Source reads for the replay. Requests are handed to the inbox actor, which
// runs them in actor context as soon as they are queued; no node actor is
// invoked from a plain worker thread. A request that outlives its timeout
// stops the process, so abandoned requests cannot accumulate across retries.
// The lane a request is made in, and for the prefetch lane its generation.
struct SourceContext {
  SourceLane lane = SourceLane::Consumer;
  uint64_t generation = 0;
};

class IndexReader {
 public:
  using Context = SourceContext;

  IndexReader(td::actor::ActorId<validator::RootDb> db, std::shared_ptr<SourceCore> core,
              std::chrono::milliseconds timeout = std::chrono::seconds(30), ReplayStats* stats = nullptr)
      : db_(db), core_(std::move(core)), timeout_(timeout), stats_(stats) {
  }
  virtual ~IndexReader() = default;
  IndexReader(const IndexReader&) = delete;
  IndexReader& operator=(const IndexReader&) = delete;

  // Queue one request and return its reply without waiting. Blocks, and can
  // be cancelled, while the outstanding-request limit or the prefetch budget
  // is full; never fails because of it.
  template <class T, class F, class Charge>
  td::Result<std::shared_ptr<SourceReply<T>>> submit(F call, Context context, size_t reserve_bytes, Charge charge) {
    TRY_RESULT(ticket, core_->acquire(context.lane, context.generation, reserve_bytes, timeout_));
    auto reply = std::make_shared<SourceReply<T>>(core_, std::move(ticket), context.lane, context.generation);
    if (stats_ != nullptr) {
      stats_->source_requests.fetch_add(1, std::memory_order_relaxed);
    }
    // The closure holds the reply, never this reader: a callback that runs
    // after the replay has gone touches only the shared core.
    bool queued = core_->push([db = db_, call = std::move(call), reply, charge]() mutable {
      call(db, td::PromiseCreator::lambda([reply, charge](td::Result<T> result) mutable {
             auto bytes = charge(result);
             reply->complete(std::move(result), bytes);
           }));
    });
    if (!queued) {
      return td::Status::Error("source request cancelled");
    }
    return reply;
  }

  // Wait for a reply and take its result. The replay thread's waits, and
  // only those, are counted as source wait.
  template <class T>
  td::Result<T> take(SourceReply<T>& reply, bool replay_thread = true) {
    std::optional<StageTimer> waited;
    if (stats_ != nullptr && replay_thread) {
      waited.emplace(stats_->source_wait_us);
    }
    return reply.take();
  }

  template <class T, class F>
  td::Result<T> query(F call, Context context = {}, size_t reserve_bytes = kSourceHandleBytes) {
    auto charge = [reserve_bytes](const td::Result<T>&) { return reserve_bytes; };
    TRY_RESULT(reply, (submit<T>(std::move(call), context, reserve_bytes, charge)));
    return take(*reply, context.lane == SourceLane::Consumer);
  }

  // The source reads replay makes. Virtual so a test can serve them from a
  // fixture through the same request limit, inbox and replies.
  virtual td::Result<validator::ConstBlockHandle> masterchain(uint32_t seqno, Context context);
  virtual td::Result<validator::BlockHandle> handle(BlockIdExt id, Context context);
  // The wc=0 shard heads a masterchain block records, read and decoded on the
  // replay thread's lane.
  virtual td::Result<std::vector<BlockIdExt>> shard_heads(validator::ConstBlockHandle master);
  // A block's raw bytes, at most kPrefetchBlockBytesMax of them; a larger
  // block completes as too_large without being read.
  virtual td::Result<std::shared_ptr<SourceReply<RawBlock>>> submit_block(validator::ConstBlockHandle handle,
                                                                          Context context);
  // A block read and decoded on the replay thread's lane, whatever its size.
  virtual td::Result<td::Ref<validator::BlockData>> read_block(validator::ConstBlockHandle handle);
  virtual td::Result<td::Ref<vm::Cell>> state(validator::ConstBlockHandle handle);
  virtual td::Result<BlockIdExt> tip();
  td::Result<validator::ConstBlockHandle> masterchain(uint32_t seqno) {
    return masterchain(seqno, Context{});
  }
  td::Result<validator::BlockHandle> handle(BlockIdExt id) {
    return handle(id, Context{});
  }
  // The checked root of a block read on the replay thread's lane.
  td::Result<td::Ref<vm::Cell>> block(validator::ConstBlockHandle handle);

  // The shard heads of a masterchain block, for the prefetch lane: the raw
  // block is read within the prefetch budget and decoded on the calling
  // thread, and only the heads are kept; the decoded block is gone when this
  // returns. Empty when the block is too large for the prefetch lane.
  td::Result<std::optional<std::vector<BlockIdExt>>> prefetch_shard_heads(validator::ConstBlockHandle master,
                                                                          Context context);

  // The block's root after checking it is the block the handle names.
  static td::Result<td::Ref<vm::Cell>> checked_root(const validator::ConstBlockHandle& handle,
                                                    const td::Ref<validator::BlockData>& data);

  bool timed_out() const {
    return core_->timed_out();
  }
  const std::shared_ptr<SourceCore>& core() const {
    return core_;
  }
  ReplayStats* stats() const {
    return stats_;
  }

 protected:
  // Queue a raw block read: `call(db, promise)` reads at most
  // kPrefetchBlockBytesMax bytes of the block and answers with them, or with
  // the archive's kFileOverReadLimit refusal.
  template <class F>
  td::Result<std::shared_ptr<SourceReply<RawBlock>>> submit_raw_block(F call, Context context) {
    return submit<RawBlock>(
        [call = std::move(call)](auto db, td::Promise<RawBlock> promise) mutable {
          call(db, td::PromiseCreator::lambda([promise = std::move(promise)](td::Result<td::BufferSlice> read) mutable {
                 promise.set_result(raw_block(std::move(read)));
               }));
        },
        context, kSourceBlockReserveBytes, [](const td::Result<RawBlock>& result) { return raw_block_charge(result); });
  }
  // The shard heads recorded in a masterchain block's raw bytes. Virtual so a
  // fixture whose masterchain blocks record no shard configuration can supply
  // its heads after the same decoding.
  virtual td::Result<std::vector<BlockIdExt>> decoded_shard_heads(const validator::ConstBlockHandle& master,
                                                                  td::BufferSlice data);

 private:
  td::actor::ActorId<validator::RootDb> db_;
  std::shared_ptr<SourceCore> core_;
  std::chrono::milliseconds timeout_;
  ReplayStats* stats_;
};

// Extract only wc=0 heads from a committed masterchain block; the head ids
// include hashes so split/merge traversal never identifies a block by seqno
// alone. Reject excessive fan-out before queueing work.
td::Result<std::vector<BlockIdExt>> index_shard_heads(td::Ref<vm::Cell> root);
}  // namespace tos::services
