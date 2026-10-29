/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <algorithm>
#include <optional>

#include "index-prefetch.h"
#include "index-replay.h"

namespace tos::services {

Prefetcher::Prefetcher(IndexReader& reader, Options options)
    : reader_(reader), core_(reader.core()), options_(options) {
  if (options_.max_intervals == 0) {
    options_.max_intervals = 1;
  }
}

Prefetcher::~Prefetcher() {
  {
    std::lock_guard<std::mutex> lock(core_->mutex());
    quit_ = true;
    core_->cv().notify_all();
  }
  join();
  // Intervals are destroyed here, outside the core mutex: their replies and
  // charges take it when they release their places.
  std::deque<std::shared_ptr<PrefetchedInterval>> drop;
  {
    std::lock_guard<std::mutex> lock(core_->mutex());
    drop.swap(buffer_);
  }
}

void Prefetcher::start() {
  thread_ = td::thread([this] { run(); });
}

void Prefetcher::join() {
  thread_.join();
}

size_t Prefetcher::buffered() {
  std::lock_guard<std::mutex> lock(core_->mutex());
  return buffer_.size();
}

void Prefetcher::follow(uint32_t next, const BlockIdExt& previous, uint32_t limit) {
  std::deque<std::shared_ptr<PrefetchedInterval>> drop;
  {
    std::lock_guard<std::mutex> lock(core_->mutex());
    if (following_ && consumer_next_ == next) {
      limit_ = std::max(limit_, limit);
      core_->cv().notify_all();
      return;
    }
    core_->reset_prefetch_locked();
    drop.swap(buffer_);
    following_ = true;
    halted_ = false;
    next_ = next;
    consumer_next_ = next;
    limit_ = limit;
    previous_ = previous;
    core_->cv().notify_all();
  }
}

void Prefetcher::reset() {
  std::deque<std::shared_ptr<PrefetchedInterval>> drop;
  {
    std::lock_guard<std::mutex> lock(core_->mutex());
    core_->reset_prefetch_locked();
    drop.swap(buffer_);
    following_ = false;
    halted_ = false;
    core_->cv().notify_all();
  }
}

td::Result<std::shared_ptr<PrefetchedInterval>> Prefetcher::interval(uint32_t seqno) {
  std::unique_lock<std::mutex> lock(core_->mutex());
  while (true) {
    if (core_->stopping_locked() || quit_) {
      return core_->cancelled_locked();
    }
    if (!following_ || consumer_next_ != seqno) {
      return td::Status::Error("source prefetch is not following this block");
    }
    if (!buffer_.empty()) {
      auto front = buffer_.front();
      if (front->seqno != seqno) {
        return td::Status::Error("source prefetch out of order");
      }
      return front;
    }
    core_->wait_locked(lock, std::chrono::steady_clock::time_point::max());
  }
}

td::Result<RawBlock> Prefetcher::take_block(PrefetchedInterval& interval, size_t index) {
  std::optional<StageTimer> waited;
  if (reader_.stats() != nullptr) {
    waited.emplace(reader_.stats()->prefetch_wait_us);
  }
  if (index >= interval.blocks.size()) {
    return td::Status::Error("source prefetch block index out of range");
  }
  std::shared_ptr<SourceReply<RawBlock>> reply;
  {
    std::unique_lock<std::mutex> lock(core_->mutex());
    while (true) {
      if (core_->stopping_locked() || quit_) {
        return core_->cancelled_locked();
      }
      if (!core_->current_locked(SourceLane::Prefetch, interval.generation)) {
        return td::Status::Error("source prefetch reset");
      }
      if (interval.issued > index) {
        reply = interval.blocks[index].data;
        break;
      }
      if (interval.issue_error.is_error()) {
        return interval.issue_error.clone();
      }
      core_->wait_locked(lock, std::chrono::steady_clock::time_point::max());
    }
  }
  if (reply == nullptr) {
    return td::Status::Error("source prefetch result already taken");
  }
  auto result = reader_.take(*reply);
  // Release this block's place and bytes now rather than with the interval:
  // the bytes have moved to the caller.
  std::shared_ptr<SourceReply<RawBlock>> drop;
  {
    std::lock_guard<std::mutex> lock(core_->mutex());
    drop = std::move(interval.blocks[index].data);
  }
  drop.reset();
  reply.reset();
  return result;
}

td::Result<td::Ref<validator::BlockData>> Prefetcher::block_data(PrefetchedInterval& interval, size_t index) {
  TRY_RESULT(raw, take_block(interval, index));
  const auto& handle = interval.blocks[index].handle;
  if (raw.too_large) {
    return reader_.read_block(handle);
  }
  std::optional<StageTimer> decoding;
  if (reader_.stats() != nullptr) {
    decoding.emplace(reader_.stats()->walk_us);
  }
  return decode_block(handle->id(), std::move(raw.data));
}

void Prefetcher::pop(uint32_t seqno) {
  std::shared_ptr<PrefetchedInterval> drop;
  {
    std::lock_guard<std::mutex> lock(core_->mutex());
    if (!buffer_.empty() && buffer_.front()->seqno == seqno) {
      drop = std::move(buffer_.front());
      buffer_.pop_front();
      consumer_next_ = seqno + 1;
      core_->cv().notify_all();
    }
  }
}

td::Status Prefetcher::read_interval(PrefetchedInterval& interval, const BlockIdExt& previous) {
  IndexReader::Context context{SourceLane::Prefetch, interval.generation};
  TRY_RESULT(master, reader_.masterchain(interval.seqno, context));
  if (!master->is_applied()) {
    return td::Status::Error("masterchain block not applied");
  }
  if (interval.seqno > 1 && (!master->inited_prev() || master->one_prev(true) != previous)) {
    return td::Status::Error("noncontiguous masterchain replay");
  }
  interval.master = master;
  // One masterchain block is decoded at a time, on this thread, and only its
  // shard heads outlive the call.
  TRY_RESULT(heads, reader_.prefetch_shard_heads(master, context));
  if (!heads) {
    interval.replay_reads = true;
    interval.handles = SourceCharge(core_, kSourceHandleBytes);
    return td::Status::OK();
  }
  TRY_RESULT(blocks, replay_interval(std::move(heads.value()), interval.seqno,
                                     [this, context](BlockIdExt id) { return reader_.handle(id, context); }));
  // The handles stay with the interval until the replay thread has walked
  // it: charge them, without blocking, against the prefetch budget.
  interval.handles = SourceCharge(core_, (blocks.size() + 1) * kSourceHandleBytes);
  interval.blocks.reserve(blocks.size());
  for (auto& handle : blocks) {
    interval.blocks.push_back(PrefetchedBlock{std::move(handle), nullptr});
  }
  return td::Status::OK();
}

void Prefetcher::issue_blocks(const std::shared_ptr<PrefetchedInterval>& interval) {
  IndexReader::Context context{SourceLane::Prefetch, interval->generation};
  for (size_t i = 0; i < interval->blocks.size(); ++i) {
    // Issued in order: every block before this one already holds its place,
    // so the block the replay thread waits for is never behind one that is
    // waiting for space.
    auto reply = reader_.submit_block(interval->blocks[i].handle, context);
    std::lock_guard<std::mutex> lock(core_->mutex());
    if (quit_ || core_->stopping_locked() || !core_->current_locked(SourceLane::Prefetch, interval->generation)) {
      // `reply` is released after the lock, when this scope ends.
      return;
    }
    if (reply.is_error()) {
      interval->issue_error = reply.move_as_error();
      halted_ = true;
      core_->cv().notify_all();
      return;
    }
    interval->blocks[i].data = reply.move_as_ok();
    interval->issued = i + 1;
    core_->cv().notify_all();
  }
}

void Prefetcher::run() {
  while (true) {
    auto interval = std::make_shared<PrefetchedInterval>();
    BlockIdExt previous;
    {
      std::unique_lock<std::mutex> lock(core_->mutex());
      while (true) {
        if (quit_ || core_->stopping_locked()) {
          return;
        }
        if (following_ && !halted_ && next_ <= limit_ && buffer_.size() < options_.max_intervals) {
          break;
        }
        core_->wait_locked(lock, std::chrono::steady_clock::time_point::max());
      }
      interval->seqno = next_;
      interval->generation = core_->generation_locked();
      previous = previous_;
    }
    auto status = read_interval(*interval, previous);
    bool issue = false;
    {
      std::lock_guard<std::mutex> lock(core_->mutex());
      if (quit_ || core_->stopping_locked() || !core_->current_locked(SourceLane::Prefetch, interval->generation)) {
        // A reset or a stop overtook this read; it is dropped below, after
        // the lock is released.
      } else {
        if (status.is_error()) {
          interval->error = std::move(status);
          halted_ = true;
        } else {
          next_ = interval->seqno + 1;
          previous_ = interval->master->id();
          issue = true;
        }
        buffer_.push_back(interval);
        core_->cv().notify_all();
      }
    }
    if (issue) {
      issue_blocks(interval);
    }
  }
}

}  // namespace tos::services
