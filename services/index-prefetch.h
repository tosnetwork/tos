/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <deque>
#include <memory>
#include <vector>

#include "td/utils/port/thread.h"

#include "index-reader.h"

namespace tos::services {

// One shard block of a prefetched interval: its handle, and once the prefetch
// thread has issued it, the reply its data arrives in.
struct PrefetchedBlock {
  validator::BlockHandle handle;
  std::shared_ptr<SourceReply<td::Ref<validator::BlockData>>> data;  // guarded by the core mutex
};

// The source records for one masterchain block, read ahead of the replay
// cursor. It carries only full block identities and handles; nothing here is
// durable, and the replay thread repeats every check before it walks.
struct PrefetchedInterval {
  uint32_t seqno = 0;
  uint64_t generation = 0;
  // Set when reading this interval failed; nothing after it is prefetched in
  // this generation, and the replay thread reports it on reaching it.
  td::Status error;
  validator::ConstBlockHandle master;
  // Parents before children, as replay_interval returns them.
  std::vector<PrefetchedBlock> blocks;
  // How many of `blocks` have their data request issued, or `issue_error`.
  size_t issued = 0;       // guarded by the core mutex
  td::Status issue_error;  // guarded by the core mutex
  SourceCharge handles;
};

// Reads masterchain intervals ahead of the replay cursor, at most
// `max_intervals` of them, within the core's request limit and byte budget.
// Only the replay thread changes index state, the checkpoint or the published
// cursor; this only fills replies.
class Prefetcher {
 public:
  struct Options {
    size_t max_intervals = 8;
  };
  Prefetcher(IndexReader& reader, Options options);
  ~Prefetcher();
  Prefetcher(const Prefetcher&) = delete;
  Prefetcher& operator=(const Prefetcher&) = delete;

  void start();
  // Join the prefetch thread. The caller has shut the core down or set the
  // stop flag first, which wakes it.
  void join();

  // The replay thread will want `next` (whose predecessor is `previous`) and
  // then every block up to `limit`. Keeps what is already read when it
  // continues the current pipeline; otherwise starts a new one at `next`.
  void follow(uint32_t next, const BlockIdExt& previous, uint32_t limit);
  // Drop everything read ahead; the next follow() starts over. Results still
  // in flight belong to the previous generation and are discarded.
  void reset();

  // The interval for `seqno`, waiting until it has been read.
  td::Result<std::shared_ptr<PrefetchedInterval>> interval(uint32_t seqno);
  // Block `index` of `interval`, waiting until its data has arrived.
  td::Result<td::Ref<validator::BlockData>> block_data(PrefetchedInterval& interval, size_t index);
  // The replay thread has finished with the front interval.
  void pop(uint32_t seqno);

  // For tests: intervals currently held.
  size_t buffered();

 private:
  void run();
  td::Status read_interval(PrefetchedInterval& interval, const BlockIdExt& previous);
  void issue_blocks(const std::shared_ptr<PrefetchedInterval>& interval);

  IndexReader& reader_;
  std::shared_ptr<SourceCore> core_;
  Options options_;
  // td::thread releases the thread's td thread-local state when it ends.
  td::thread thread_;
  // All guarded by the core mutex.
  bool quit_ = false;
  bool following_ = false;
  bool halted_ = false;  // an interval failed; wait for reset
  uint32_t next_ = 0;    // the next interval to read
  uint32_t consumer_next_ = 0;
  uint32_t limit_ = 0;
  BlockIdExt previous_;
  std::deque<std::shared_ptr<PrefetchedInterval>> buffer_;
};

}  // namespace tos::services
