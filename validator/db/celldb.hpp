/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>

#include "auto/tl/tos_api.h"
#include "crypto/vm/db/CellDbExtCell.h"
#include "crypto/vm/db/CellStorage.h"
#include "crypto/vm/db/DynamicBagOfCellsDb.h"
#include "interfaces/block-handle.h"
#include "td/actor/actor.h"
#include "td/db/KeyValue.h"
#include "td/db/RocksDb.h"
#include "tos/tos-types.h"

#include "db-utils.h"
#include "validator.h"

namespace rocksdb {
class Statistics;
class DB;
}  // namespace rocksdb

namespace tos {

namespace validator {

class RootDb;

class CellDb;
class CellDbAsyncExecutor;

// Late-binding CellDb reader provider for streaming-import lazy ExtCells.
//
// The streaming-state importer mints CellDb-backed ExtCells DURING parse,
// while the per-import RocksDB write batch is still open. The reader
// snapshot taken at sink construction may pre-date that batch's commit;
// baking it into every ExtCell would let post-commit lazy materializations
// miss the cells we just streamed. This provider lets the sink swap
// (or invalidate) the canonical reader on commit / abort:
//
//   * Constructed with the import-time reader; lazy ExtCells emitted
//     during parse all reach this same provider.
//   * On `commit_after_root_verified`, the sink calls `publish(...)` to
//     swap in a post-commit reader that observes the just-flushed cells.
//     If the underlying reader was already live (non-snapshot), the swap
//     is functionally a no-op but it still resets the provider to a
//     fresh handle so the post-commit semantics stay explicit.
//   * On `abort()`, the sink calls `invalidate()` so any subsequent lazy
//     materialization fails closed with a structured Status::Error
//     ("reader provider invalidated") instead of silently reading from
//     a stale snapshot.
//
// Thread-safety: every accessor takes a mutex so calls from the sink
// thread (publish/invalidate) and from arbitrary downstream consumer
// threads (current_reader) are serialized. Lock hold time is O(1) — a
// shared_ptr copy / move under a tiny critical section.
class LiveCellDbReaderProvider : public vm::CellDbReaderProvider {
 public:
  LiveCellDbReaderProvider() = default;
  explicit LiveCellDbReaderProvider(std::shared_ptr<vm::CellDbReader> initial)
      : current_(std::move(initial)) {
  }
  std::shared_ptr<vm::CellDbReader> current_reader() override {
    std::lock_guard<std::mutex> lock(mu_);
    return current_;
  }
  // Atomically replace the canonical reader. Called by the sink AFTER
  // commit_after_root_verified flushes the write batch so lazy ExtCells
  // emitted during parse pick up the post-commit reader on next access.
  // Pass a non-null reader; pass nullptr only via invalidate().
  void publish(std::shared_ptr<vm::CellDbReader> next) override {
    std::lock_guard<std::mutex> lock(mu_);
    current_ = std::move(next);
  }
  // Invalidate the provider. After this call current_reader() returns
  // null; any lazy ExtCell still holding a reference observes the null
  // and surfaces a structured Status::Error from CellDbExtCellLoader.
  void invalidate() override {
    std::lock_guard<std::mutex> lock(mu_);
    current_ = nullptr;
  }

 private:
  std::mutex mu_;
  std::shared_ptr<vm::CellDbReader> current_;
};

// Per-import streaming writer for the state-download sink. Wraps the
// existing CellDb KeyValue handle in a small begin/commit/abort surface
// so the streaming sink can append cells one at a time without going
// through the whole-DAG `prepare_commit` / `commit` path on
// `DynamicBagOfCellsDb`.
//
// Lifecycle:
//   - The sink calls `begin_batch()` once before the first cell.
//   - It then calls `store_cell()` per parsed cell.
//   - On successful import it calls `commit_batch()`; on any error
//     it calls `abort_batch()` to discard any partial writes.
//
// IMPORT-ONLY. Not exposed via the validator-engine RPC / actor
// surface. The instance owns no actor thread of its own; the caller
// is responsible for serializing access (the sink is single-threaded
// inside its parser).
//
// TODO(tos25 W6): regression tests for CellDbStreamingWriter
//   - begin/store/commit happy path
//   - begin/store/abort leaves the DB unchanged
//   - same hash + different bytes during a batch returns Error
//   - 1M cells in one batch does not OOM
class CellDbStreamingWriter {
 public:
  virtual ~CellDbStreamingWriter() = default;
  virtual td::Status begin_batch() = 0;
  // Slice form: caller has already serialized the cell value using
  // `vm::CellStorer::serialize_value`. `hash` must be the cell's
  // canonical hash (Cell::hash_bytes long).
  virtual td::Status store_cell(td::Slice hash, td::Slice serialized_cell_bytes) = 0;
  // Convenience form: serializes the cell value with refcount = 1
  // and the non-BoC encoding, matching what the dynamic BoC writes
  // for a freshly observed cell.
  virtual td::Status store_cell(const td::Ref<vm::DataCell>& cell) = 0;
  virtual td::Status commit_batch() = 0;
  virtual td::Status abort_batch() = 0;
};

class CellDbBase : public td::actor::Actor {
 public:
  void start_up() override;

 protected:
  std::shared_ptr<vm::DynamicBagOfCellsDb::AsyncExecutor> async_executor;

 private:
  void execute_sync(std::function<void()> f);
  friend CellDbAsyncExecutor;
};

class CellDbIn : public CellDbBase {
 public:
  using KeyHash = td::Bits256;

  std::vector<std::pair<std::string, std::string>> prepare_stats();
  void load_cell(RootHash hash, td::Promise<td::Ref<vm::DataCell>> promise);
  void store_cell(BlockIdExt block_id, td::Ref<vm::Cell> cell, vm::StoreCellHint hint,
                  td::Promise<td::Ref<vm::DataCell>> promise);
  void get_cell_db_reader(td::Promise<std::shared_ptr<vm::CellDbReader>> promise);
  void store_block_state_permanent(td::Ref<BlockData> block, td::Promise<td::Ref<vm::DataCell>> promise);
  void store_block_state_permanent_bulk(std::vector<td::Ref<BlockData>> blocks,
                                        td::Promise<std::map<BlockIdExt, RootHash>> promise);

  void migrate_cell(td::Bits256 hash);

  // Construct an import-only streaming writer that shares this
  // CellDb's underlying KeyValue handle. The returned writer's
  // commit_batch / abort_batch operate on the same RocksDB instance
  // queried by the existing `CellDbReader`, so cells written through
  // the streaming writer become visible to subsequent reader
  // snapshots without any additional plumbing.
  //
  // IMPORT-ONLY. The streaming writer is not safe to use concurrently
  // with the CellDbIn store_cell / store_block_state_permanent
  // batched writes; in addition, only ONE streaming writer batch may
  // be in flight per CellDb at any moment. The shared
  // `streaming_writer_in_use_` flag is set on a successful
  // begin_batch() and cleared on commit_batch() / abort_batch() (or
  // by the writer destructor on a dropped batch). A second concurrent
  // begin_batch() observes the flag set and returns Status::Error
  // with "another streaming import is in flight"; the first writer's
  // commit/abort then re-enables a fresh import.
  std::unique_ptr<CellDbStreamingWriter> create_streaming_writer();

  // Actor-message wrapper around create_streaming_writer(). Resolves
  // the promise with a fresh writer. The single-import gate is
  // checked at begin_batch() time on the writer, not here, so this
  // method always succeeds — a second concurrent caller that tries
  // to begin_batch() while another writer is mid-batch will see the
  // begin_batch() error surface directly. Used by the validator
  // manager (`ValidatorManager::create_celldb_streaming_writer`) to
  // pipe a writer back to the persistent-state download actor.
  void create_streaming_writer_async(td::Promise<std::unique_ptr<CellDbStreamingWriter>> promise);

  void flush_db_stats();

  CellDbIn(td::actor::ActorId<RootDb> root_db, td::actor::ActorId<CellDb> parent, std::string path,
           td::Ref<ValidatorManagerOptions> opts);

  void validate_meta();
  void start_up() override;
  void alarm() override;

 private:
  struct DbEntry {
    BlockIdExt block_id;
    KeyHash prev;
    KeyHash next;
    RootHash root_hash;

    DbEntry(tl_object_ptr<tos_api::db_celldb_value> entry);
    DbEntry() = default;
    DbEntry(BlockIdExt block_id, KeyHash prev, KeyHash next, RootHash root_hash)
        : block_id(block_id), prev(prev), next(next), root_hash(root_hash) {
    }
    td::BufferSlice release();
    bool is_empty() const {
      return !block_id.is_valid();
    }
  };
  td::Result<DbEntry> get_block(KeyHash key);
  void set_block(KeyHash key, DbEntry e);

  static std::string get_key(KeyHash key);
  static KeyHash get_key_hash(BlockIdExt block_id);
  static BlockIdExt get_empty_key();
  KeyHash get_empty_key_hash();

  void gc(BlockIdExt block_id);
  void gc_cont(BlockHandle handle);
  void gc_cont2(BlockHandle handle);
  void skip_gc();

  void migrate_cells();

  td::actor::ActorId<RootDb> root_db_;
  td::actor::ActorId<CellDb> parent_;

  std::string path_;
  td::Ref<ValidatorManagerOptions> opts_;

  std::shared_ptr<vm::DynamicBagOfCellsDb> boc_;
  std::shared_ptr<vm::KeyValue> cell_db_;
  std::shared_ptr<rocksdb::DB> rocks_db_;

  // Phase B single-import gate. The flag is held in a shared_ptr so
  // the writer (returned to the caller as a unique_ptr) can flip it
  // from its dtor / commit / abort even after this actor has shut
  // down. Set true on a successful begin_batch(); cleared on
  // commit_batch / abort_batch / writer dtor. A second concurrent
  // begin_batch() observes the flag set and fails with a clear
  // "another streaming import is in flight" error so misconfigured
  // callers cannot interleave two RocksDB write batches against the
  // same CellDb instance.
  std::shared_ptr<std::atomic<bool>> streaming_writer_in_use_ = std::make_shared<std::atomic<bool>>(false);

  std::function<void(const vm::CellLoader::LoadResult&)> on_load_callback_;
  std::set<td::Bits256> cells_to_migrate_;
  td::Timestamp migrate_after_ = td::Timestamp::never();
  bool migration_active_ = false;
  std::optional<double> in_memory_load_time_;

  struct MigrationStats {
    td::Timer start_;
    td::Timestamp end_at_ = td::Timestamp::in(60.0);
    size_t batches_ = 0;
    size_t migrated_cells_ = 0;
    size_t checked_cells_ = 0;
    double total_time_ = 0.0;
  };
  std::unique_ptr<MigrationStats> migration_stats_;

  struct CellDbStatistics {
    bool permanent_mode_;
    PercentileStats store_cell_time_;
    PercentileStats store_cell_prepare_time_;
    PercentileStats store_cell_write_time_;
    size_t store_cell_bulk_queries_ = 0;
    size_t store_cell_bulk_total_blocks_ = 0;
    PercentileStats gc_cell_time_;
    td::Timestamp stats_start_time_ = td::Timestamp::now();
    std::optional<double> in_memory_load_time_;
    std::optional<vm::DynamicBagOfCellsDb::Stats> boc_stats_;

    std::vector<std::pair<std::string, std::string>> prepare_stats();
    void clear() {
      *this = CellDbStatistics{};
    }
  };

  std::shared_ptr<rocksdb::Statistics> statistics_;
  std::shared_ptr<td::RocksDbSnapshotStatistics> snapshot_statistics_;
  CellDbStatistics cell_db_statistics_;
  td::Timestamp statistics_flush_at_ = td::Timestamp::never();
  BlockSeqno last_deleted_mc_state_ = 0;
  bool permanent_mode_ = false;

  bool db_busy_ = false;
  std::deque<td::Promise<td::Unit>> action_queue_;
  size_t action_queue_cnt_store_ = 0, action_queue_cnt_load_ = 0;

  void release_db() {
    db_busy_ = false;
    while (!db_busy_ && !action_queue_.empty()) {
      auto action = std::move(action_queue_.front());
      action_queue_.pop_front();
      action.set_value(td::Unit());
    }
  }

 public:
  class MigrationProxy : public td::actor::Actor {
   public:
    explicit MigrationProxy(td::actor::ActorId<CellDbIn> cell_db) : cell_db_(cell_db) {
    }
    void migrate_cell(td::Bits256 hash) {
      td::actor::send_closure(cell_db_, &CellDbIn::migrate_cell, hash);
    }

   private:
    td::actor::ActorId<CellDbIn> cell_db_;
  };
};

class CellDb : public CellDbBase {
 public:
  void prepare_stats(td::Promise<std::vector<std::pair<std::string, std::string>>> promise);
  td::actor::Task<Ref<vm::DataCell>> load_cell(RootHash hash);
  td::actor::Task<Ref<vm::DataCell>> store_cell(BlockIdExt block_id, Ref<vm::Cell> cell, vm::StoreCellHint hint);
  td::actor::Task<Ref<vm::DataCell>> store_block_state_permanent(Ref<BlockData> block);
  td::actor::Task<std::map<BlockIdExt, RootHash>> store_block_state_permanent_bulk(std::vector<Ref<BlockData>> blocks);
  void update_snapshot(std::unique_ptr<td::KeyValueReader> snapshot) {
    CHECK(!opts_->get_celldb_in_memory());
    if (!started_) {
      alarm();
    }
    started_ = true;
    boc_->set_loader(std::make_unique<vm::CellLoader>(std::move(snapshot), on_load_callback_)).ensure();
  }
  void set_thread_safe_boc(std::shared_ptr<const vm::DynamicBagOfCellsDb> thread_safe_boc) {
    CHECK(opts_->get_celldb_in_memory() || opts_->get_celldb_v2());
    if (!started_) {
      alarm();
    }
    started_ = true;
    thread_safe_boc_ = std::move(thread_safe_boc);
  }
  void get_cell_db_reader(td::Promise<std::shared_ptr<vm::CellDbReader>> promise);
  // Phase B persistent-state catch-up: forward to
  // CellDbIn::create_streaming_writer() and resolve the promise with
  // the resulting writer (or surface the error verbatim if CellDbIn's
  // single-import flag is already taken).
  void create_celldb_streaming_writer(td::Promise<std::unique_ptr<CellDbStreamingWriter>> promise);

  void flush_db_stats(std::string stats);

  CellDb(td::actor::ActorId<RootDb> root_db, std::string path, td::Ref<ValidatorManagerOptions> opts)
      : root_db_(root_db), path_(path), opts_(opts) {
  }

  void start_up() override;

 private:
  td::actor::ActorId<RootDb> root_db_;
  std::string path_;
  td::Ref<ValidatorManagerOptions> opts_;

  td::actor::ActorOwn<CellDbIn> cell_db_;

  std::unique_ptr<vm::DynamicBagOfCellsDb> boc_;
  std::shared_ptr<const vm::DynamicBagOfCellsDb> thread_safe_boc_;
  bool started_ = false;
  std::vector<std::pair<std::string, std::string>> prepared_stats_{{"started", "false"}};

  std::function<void(const vm::CellLoader::LoadResult&)> on_load_callback_;

  void update_stats(td::Result<std::vector<std::pair<std::string, std::string>>> stats);
  void alarm() override;

  struct CellDbStatistics {
    size_t queries_load_ok_immediate_{0}, queries_load_ok_inner_{0}, queries_load_error_{0};
    size_t queries_store_ok_{0}, queries_store_error_{0};

    void prepare_stats(std::vector<std::pair<std::string, std::string>>& vec) const;
    std::vector<std::pair<std::string, std::string>> prepare_stats() const {
      std::vector<std::pair<std::string, std::string>> vec;
      prepare_stats(vec);
      return vec;
    }
    void clear() {
      *this = CellDbStatistics{};
    }
  };
  CellDbStatistics cell_db_statistics_;
};

}  // namespace validator

}  // namespace tos
