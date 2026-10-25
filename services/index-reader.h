/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <condition_variable>
#include <mutex>

#include "validator/db/rootdb.hpp"

#include "service-common.h"

namespace tos::services {

// The replay thread submits one request at a time; only the main scheduler
// thread dispatches it. A timeout terminates replay, so abandoned requests
// cannot accumulate across retries. No node actor is invoked from a plain
// worker thread.
class IndexReader {
 public:
  explicit IndexReader(td::actor::ActorId<validator::RootDb> db) : db_(db) {
  }
  template <class T, class F>
  td::Result<T> query(F call) {
    struct Reply {
      std::mutex mutex;
      std::condition_variable cv;
      td::Result<T> result = td::Status::Error("source request cancelled");
      bool done = false;
    };
    auto reply = std::make_shared<Reply>();
    {
      std::lock_guard<std::mutex> lock(mutex_);
      CHECK(!pending_);
      pending_ = [db = db_, call = std::move(call), reply]() mutable {
        call(db, td::PromiseCreator::lambda([reply](td::Result<T> result) {
               std::lock_guard<std::mutex> lock(reply->mutex);
               reply->result = std::move(result);
               reply->done = true;
               reply->cv.notify_one();
             }));
      };
    }
    std::unique_lock<std::mutex> lock(reply->mutex);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (!reply->done && !stop_requested.load()) {
      reply->cv.wait_for(lock, std::chrono::milliseconds(100));
      if (std::chrono::steady_clock::now() >= deadline) {
        timed_out_.store(true);
        stop_requested.store(true);
        return td::Status::Error("source request timed out; restart to retry from the durable checkpoint");
      }
    }
    return std::move(reply->result);
  }
  void dispatch() {
    std::function<void()> call;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      call = std::move(pending_);
      pending_ = {};
    }
    if (call)
      call();
  }
  td::Result<validator::ConstBlockHandle> masterchain(uint32_t seqno);
  td::Result<validator::BlockHandle> handle(BlockIdExt id);
  td::Result<td::Ref<vm::Cell>> block(validator::ConstBlockHandle handle);
  td::Result<td::Ref<vm::Cell>> state(validator::ConstBlockHandle handle);
  td::Result<BlockIdExt> tip();
  bool timed_out() const {
    return timed_out_.load();
  }

 private:
  td::actor::ActorId<validator::RootDb> db_;
  std::mutex mutex_;
  std::atomic<bool> timed_out_{false};
  std::function<void()> pending_;
};

// Extract only wc=0 heads from a committed masterchain block; the head ids
// include hashes so split/merge traversal never identifies a block by seqno
// alone. Reject excessive fan-out before queueing work.
td::Result<std::vector<BlockIdExt>> index_shard_heads(td::Ref<vm::Cell> root);
}  // namespace tos::services
