/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <algorithm>
#include <memory>
#include <vector>

#include "block/block-auto.h"
#include "validator-engine/wallet-index-writer.h"
#include "validator-engine/wallet-index.h"

#include "index-prefetch.h"
#include "index-progress.h"
#include "index-reader.h"
#include "index-replay.h"

namespace tos::services {
using tos_wallet_index::WalletIndexDb;
using tos_wallet_index::Wc0IndexResult;
using tos_wallet_index::Wc0NewestState;

// The replay thread: observes the source, walks each masterchain interval the
// prefetch thread read, and alone advances the durable checkpoint and the
// published cursor.
class ReplayLoop {
 public:
  // `ceiling`, when nonzero, is the last masterchain block replay goes to.
  // It never makes the index ready: readiness is reaching the source tip.
  ReplayLoop(IndexReader& reader, Prefetcher& prefetcher, Progress& progress, ReplayStats& stats, uint32_t ceiling)
      : reader_(reader), prefetcher_(prefetcher), progress_(progress), stats_(stats), ceiling_(ceiling) {
  }
  // Nothing to do until the source moves: replay is at its limit (the tip,
  // or the ceiling below it) and the last drain did no work.
  bool idle() const {
    return at_limit_ && !background_progress_;
  }
  td::Status step() {
    auto status = step_impl();
    if (status.is_error()) {
      // Everything read ahead is dropped; the next step reads again from the
      // durable checkpoint.
      prefetcher_.reset();
      progress_.settled = false;
    }
    return status;
  }
  td::Result<Wc0NewestState> newest(const td::Bits256& address) {
    for (auto id : heads_) {
      if (!tos_wallet_index::wallet_index_state_contains(id.shard_full(), address))
        continue;
      TRY_RESULT(handle, reader_.handle(id));
      TRY_RESULT(root, reader_.state(handle));
      block::gen::ShardStateUnsplit::Record state;
      if (!tlb::unpack_cell(root, state))
        return td::Status::Error("invalid latest shard state");
      return Wc0NewestState{id, state.gen_lt, std::move(root)};
    }
    return td::Status::Error("source has no shard for this account");
  }

 private:
  // How long one step replays before it observes the source again. A step
  // checks it between masterchain blocks: it never interrupts a source
  // request or a walk.
  static constexpr double kBatchSeconds = 1.0;

  td::Status step_impl() {
    background_progress_ = false;
    at_limit_ = false;
    progress_.settled = false;
    td::Result<BlockIdExt> observed;
    // The observation is as old as the moment it was asked for.
    double observed_at = td::Time::now();
    {
      StageTimer timer(stats_.catch_up_us);
      stats_.catch_ups.fetch_add(1, std::memory_order_relaxed);
      observed = reader_.tip();
    }
    TRY_RESULT(tip, std::move(observed));
    if (!tip.is_masterchain() || !tip.seqno())
      return td::Status::Error("source has no applied masterchain block");
    progress_.tip = tip.seqno();
    progress_.tip_known = true;
    if (checkpoint_.committed != tip)
      progress_.ready = false;
    TRY_RESULT(top, reader_.handle(tip));
    TRY_RESULT(heads, reader_.shard_heads(top));
    heads_ = std::move(heads);
    auto db = tos_wallet_index::wallet_index_db();
    if (!initialized_) {
      auto first = reader_.masterchain(1);
      if (first.is_error()) {
        return td::Status::Error(PSTRING() << "source has no masterchain block 1 (" << first.error().message()
                                           << "); a node that joined at a persistent state cannot serve a full "
                                              "replay: prepare the source as described in "
                                              "doc/standalone-wallet-services.md, \"Preparing the source node\"");
      }
      auto anchor = first.move_as_ok();
      TRY_STATUS(db->initialize_replay(anchor->id()));
      TRY_RESULT(stored, db->replay_checkpoint());
      CHECK(stored);
      checkpoint_ = stored.value();
      if (checkpoint_.committed.seqno()) {
        TRY_RESULT(committed, reader_.masterchain(checkpoint_.committed.seqno()));
        if (committed->id() != checkpoint_.committed)
          return td::Status::Error("source differs from committed replay chain");
      }
      initialized_ = true;
      progress_.cursor = checkpoint_.committed.seqno();
      progress_.cursor_known = true;
    }
    if (checkpoint_.committed.seqno() > tip.seqno())
      return td::Status::Error("source is behind durable index progress");
    auto limit = ceiling_ != 0 ? std::min(ceiling_, tip.seqno()) : tip.seqno();
    bool replayed = false;
    if (checkpoint_.committed.seqno() < limit) {
      prefetcher_.follow(checkpoint_.committed.seqno() + 1, checkpoint_.committed, limit);
      auto batch_end = td::Time::now() + kBatchSeconds;
      do {
        TRY_RESULT(advanced, replay_next());
        if (!advanced) {
          // The token backlog is at its cap: the interval is retried from
          // the checkpoint after this drain made room.
          prefetcher_.reset();
          return td::Status::OK();
        }
        replayed = true;
        if (stop_requested.load())
          return td::Status::Error("replay interrupted");
        // One drain per masterchain block, as when a step replayed one block.
        background_progress_ = drain();
      } while (checkpoint_.committed.seqno() < limit && td::Time::now() < batch_end);
    }
    if (stop_requested.load())
      return td::Status::Error("replay interrupted");
    if (!replayed)
      background_progress_ = drain();
    // HTTP handlers independently report the persisted token backlog. This
    // flag only says the block replay has reached the observed source tip.
    progress_.checked_at = observed_at;
    progress_.ready = checkpoint_.committed == tip;
    at_limit_ = checkpoint_.committed.seqno() == limit;
    progress_.settled = at_limit_ && !background_progress_;
    return td::Status::OK();
  }

  // Replay the block after the checkpoint from what the prefetch thread read.
  // Returns false, without advancing, when the token backlog is at its cap.
  td::Result<bool> replay_next() {
    auto next = checkpoint_.committed.seqno() + 1;
    std::shared_ptr<PrefetchedInterval> interval;
    {
      StageTimer timer(stats_.prefetch_wait_us);
      TRY_RESULT_ASSIGN(interval, prefetcher_.interval(next));
    }
    if (interval->error.is_error())
      return interval->error.clone();
    auto master = interval->master;
    // The prefetch thread checked these too; only this thread's checks
    // decide what is committed.
    if (master == nullptr || master->id().seqno() != next || !master->id().is_masterchain())
      return td::Status::Error("prefetched masterchain block has the wrong identity");
    if (!master->is_applied())
      return td::Status::Error("masterchain block not applied");
    if (next > 1 && (!master->inited_prev() || master->one_prev(true) != checkpoint_.committed)) {
      return td::Status::Error("noncontiguous masterchain replay");
    }
    auto db = tos_wallet_index::wallet_index_db();
    // A masterchain block too large for the prefetch lane: this thread reads
    // the interval itself, on its own lane, as replay did before prefetching.
    std::vector<validator::BlockHandle> own_blocks;
    if (interval->replay_reads) {
      TRY_RESULT(heads, reader_.shard_heads(master));
      TRY_RESULT_ASSIGN(own_blocks,
                        replay_interval(std::move(heads), next, [this](BlockIdExt id) { return reader_.handle(id); }));
    }
    size_t count = interval->replay_reads ? own_blocks.size() : interval->blocks.size();
    for (size_t i = 0; i < count; ++i) {
      if (stop_requested.load())
        return td::Status::Error("replay interrupted");
      auto& handle = interval->replay_reads ? own_blocks[i] : interval->blocks[i].handle;
      if (handle == nullptr || handle->id().id.workchain != 0 || !handle->is_applied() ||
          !handle->inited_masterchain_ref_block() || handle->masterchain_ref_block() != next) {
        return td::Status::Error("invalid prefetched shard block");
      }
      // Waiting for prefetched bytes counts as prefetch wait, decoding them
      // as walk time (both inside block_data).
      auto data = interval->replay_reads ? reader_.read_block(handle) : prefetcher_.block_data(*interval, i);
      TRY_RESULT(block_data, std::move(data));
      TRY_RESULT(block, IndexReader::checked_root(handle, block_data));
      block_data = {};
      Wc0IndexResult result;
      {
        StageTimer timer(stats_.walk_us);
        result = tos_wallet_index::wc0_index_block(std::move(block), {}, handle->id(), true);
      }
      if (result != Wc0IndexResult::Done) {
        if (drain() && result == Wc0IndexResult::AtPendingCap)
          return false;
        return td::Status::Error("index block not committed; retrying from checkpoint");
      }
      stats_.shard_blocks.fetch_add(1, std::memory_order_relaxed);
    }
    auto committed = checkpoint_;
    committed.committed = master->id();
    {
      StageTimer timer(stats_.commit_us);
      stats_.commits.fetch_add(1, std::memory_order_relaxed);
      std::lock_guard<std::mutex> guard(db->write_mutex());
      TRY_STATUS(db->commit_replay_checkpoint(committed));
    }
    checkpoint_ = committed;
    progress_.cursor = committed.committed.seqno();
    stats_.mc_blocks.fetch_add(1, std::memory_order_relaxed);
    interval.reset();
    prefetcher_.pop(next);
    return true;
  }

  bool drain() {
    StageTimer timer(stats_.drain_us);
    stats_.drains.fetch_add(1, std::memory_order_relaxed);
    return tos_wallet_index::drain_wc0_index(&stop_requested);
  }

  IndexReader& reader_;
  Prefetcher& prefetcher_;
  Progress& progress_;
  ReplayStats& stats_;
  uint32_t ceiling_;
  bool initialized_ = false;
  bool background_progress_ = false;
  bool at_limit_ = false;
  WalletIndexDb::ReplayCheckpoint checkpoint_;
  std::vector<BlockIdExt> heads_;
};

}  // namespace tos::services
