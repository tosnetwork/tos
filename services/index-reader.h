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

// Reservations against the prefetch byte budget, before a result's size is
// known. A block reserves the largest block any ingress accepts plus the
// fixed allowance below; when it completes the reservation becomes its
// measured charge (block_charge).
inline constexpr size_t kSourceMaxBlockBytes = size_t{4} << 20;
// Objects a buffered block keeps besides its serialized bytes: the block
// object, its lazy bag-of-cells reader, the decoded root cell and the handle.
inline constexpr size_t kSourceResultOverheadBytes = 4096;
// A handle lookup's result, and each handle a prefetched interval keeps.
inline constexpr size_t kSourceHandleBytes = 1024;
inline constexpr size_t kSourceBlockReserveBytes = kSourceMaxBlockBytes + kSourceResultOverheadBytes;

// What a completed block read holds until it is walked: its serialized bytes
// (the block keeps exactly the buffer the package read allocated, and its
// lazy reader decodes cells from it on demand) plus the fixed allowance.
// Cells the walk decodes are created by the replay thread after the result
// is taken, as before prefetching.
size_t block_charge(const td::Result<td::Ref<validator::BlockData>>& result);

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
  // The wc=0 shard heads a masterchain block records.
  virtual td::Result<std::vector<BlockIdExt>> shard_heads(validator::ConstBlockHandle master, Context context);
  virtual td::Result<std::shared_ptr<SourceReply<td::Ref<validator::BlockData>>>> submit_block(
      validator::ConstBlockHandle handle, Context context);
  virtual td::Result<td::Ref<vm::Cell>> state(validator::ConstBlockHandle handle);
  virtual td::Result<BlockIdExt> tip();
  td::Result<validator::ConstBlockHandle> masterchain(uint32_t seqno) {
    return masterchain(seqno, Context{});
  }
  td::Result<validator::BlockHandle> handle(BlockIdExt id) {
    return handle(id, Context{});
  }
  td::Result<td::Ref<vm::Cell>> block(validator::ConstBlockHandle handle, Context context = {});

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
