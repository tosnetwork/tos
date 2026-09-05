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
#include "crypto/vm/boc.h"
#include "crypto/vm/db/CellDbExtCell.h"
#include "crypto/vm/db/CellStorage.h"
#include "crypto/vm/db/DynamicBagOfCellsDb.h"
#include "interfaces/block-handle.h"
#include "interfaces/validator-manager.h"
#include "td/actor/actor.h"
#include "td/db/KeyValue.h"
#include "td/db/RocksDb.h"
#include "td/utils/port/thread.h"
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
class CellDbIn;

// tos27/tos29 streaming-import budgets. The streaming-import worker
// thread (see `StreamingImportJob` below) checks the parse budgets per
// cell inside its per-cell sink callback. When EITHER the cell-count
// budget OR the wall-clock deadline is exceeded the worker calls
// `td::this_thread::yield()` to relinquish its OS scheduler slot.
//
// The parse budgets do NOT bound the CellDbIn actor's message-loop hold
// time directly — the worker runs OFF the CellDbIn actor, so the
// message loop is free to interleave `load_cell`, `store_cell`,
// `store_block_state_permanent`, GC, and `update_snapshot` messages
// concurrently with the parse. The budgets instead bound how long the
// worker thread monopolizes a single OS scheduler slot before
// cooperating with co-resident work, which is the second-order fairness
// concern. The CellDbIn liveness DoS (the primary tos27 P0-2 finding)
// is structurally eliminated by moving the parse off the actor entirely.
//
// tos29: the worker never writes KeyValue / RocksDB. It serializes
// parsed cells into an import spool only after the parsed root has been
// verified. CellDbIn then drains that spool through actor-serialized
// bounded write batches; these constants cap each actor batch so normal
// CellDb messages can interleave between batches without sharing an
// open KeyValue write batch with a worker thread.
//
// `kMaxConcurrentStreamingImports = 1` is enforced on the production
// path by `streaming_job_ != nullptr`. The legacy unsafe-for-tests-only
// writer still has its own `streaming_writer_in_use_` CAS because it
// hands a writer object to test code.
constexpr td::uint32 kMaxImportCellsPerSlice = 1024;       // ~1k cells per slice
constexpr double kMaxImportSliceWallMs = 5.0;              // 5 ms wall deadline
constexpr td::uint32 kMaxImportActorBatchCells = 1024;     // actor-side CellDb write batch cell cap
constexpr td::uint64 kMaxImportActorBatchBytes = 4ULL << 20;  // actor-side CellDb write batch byte cap
constexpr td::uint32 kMaxConcurrentStreamingImports = 1;   // serialized by streaming_job_

// Forward declaration. Full definition is in celldb.cpp because the
// struct holds the worker thread + the import spool/sink the worker
// drives, neither of which need to be visible to consumers of
// celldb.hpp.
struct StreamingImportJob;
struct StreamingImportRollbackJob;

// tos27 P0-1 / tos30: GC pause + rollback lease bound to root-store
// completion.
//
// Issued by `CellDbIn::import_persistent_state_streaming` on the
// success path; held by the downloader actor through the
// `set_block_state` callback. The lease's destructor releases the
// pause exactly once via send_closure to CellDbIn. If the importer
// attached a rollback manifest, dropping the lease before explicit
// root-store release also asks CellDbIn to conditionally erase every
// newly-created imported cell whose current serialized value still
// matches the imported refcnt=1 value. Cells that already existed, or
// cells whose refcount was later changed by `store_cell` /
// `store_block_state_part`, are skipped by rollback.
//
// The watchdog timer remains in place but is downgraded to a
// LOG(WARNING) only — it must NOT call `resume_gc_for_import()`.
// This prevents the prior "fixed 60-second timer can fire while the
// canonical root store is still committing, allowing GC to
// mis-collect imported cells" hazard.
//
// Move-only: the lease tracks a single pause that must be released
// exactly once. Copying would create a double-release on destruction.
class CellDbGcPauseLease {
 public:
  CellDbGcPauseLease() = default;
  explicit CellDbGcPauseLease(td::actor::ActorId<CellDbIn> db) noexcept;
  CellDbGcPauseLease(td::actor::ActorId<CellDbIn> db, std::string rollback_manifest_path,
                     td::uint64 rollback_cells, td::uint64 rollback_bytes) noexcept;
  CellDbGcPauseLease(CellDbGcPauseLease&&) noexcept;
  CellDbGcPauseLease& operator=(CellDbGcPauseLease&&) noexcept;
  CellDbGcPauseLease(const CellDbGcPauseLease&) = delete;
  CellDbGcPauseLease& operator=(const CellDbGcPauseLease&) = delete;
  ~CellDbGcPauseLease();

  // Caller invokes after the canonical root-store completion (e.g.
  // when `ValidatorManager::set_block_state` has resolved). After
  // this call the lease is inert; the destructor is a no-op.
  // Idempotent: a second call on an already-released lease is a
  // no-op so cancel/shutdown paths cannot double-release.
  void release_after_root_store_committed() noexcept;

  // True iff the lease still holds a live pause that the destructor
  // (or `release_after_root_store_committed`) would release.
  bool active() const noexcept {
    return !db_.empty();
  }

 private:
  void drop_uncommitted() noexcept;
  void clear_rollback_manifest() noexcept;

  td::actor::ActorId<CellDbIn> db_;
  std::string rollback_manifest_path_;
  td::uint64 rollback_cells_ = 0;
  td::uint64 rollback_bytes_ = 0;
};

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

// tos26 P1-4: PersistentStateImportRequest / PersistentStateImportResult
// are declared in validator/interfaces/validator-manager.h so both the
// Db interface and the ValidatorManager interface can route the
// request without dragging celldb.hpp into every TU that includes the
// manager header. This file consumes those types via the include of
// validator.h above.

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

  // Test-only. Production state-sync uses
  // `import_persistent_state_streaming`. Cross-actor direct KV access
  // is unsafe; do not call from a production path.
  //
  // Hands a writer holding `vm::KeyValue` back to the caller, which
  // is unsafe for any actor that does not run inside CellDbIn's
  // serialized message loop (audit P1-4 / P1-5). The
  // `unsafe_for_tests_only` suffix is intentional — production paths
  // must use `import_persistent_state_streaming`, which keeps the
  // writer entirely inside CellDbIn.
  //
  // Actor-message wrapper around create_streaming_writer(). Resolves
  // the promise with a fresh writer. The single-import gate is
  // checked at begin_batch() time on the writer, not here, so this
  // method always succeeds — a second concurrent caller that tries
  // to begin_batch() while another writer is mid-batch will see the
  // begin_batch() error surface directly.
  void create_streaming_writer_unsafe_for_tests_only_async(td::Promise<std::unique_ptr<CellDbStreamingWriter>> promise);

  // tos26 P1-4 / tos29 High-1: production persistent-state import is
  // split at the actor boundary:
  //   * worker thread: parse BoC, build hash-only ExtCell replacements,
  //     serialize parsed cells into a spool, verify parsed root;
  //   * CellDbIn actor: after root verification, drain the spool through
  //     bounded KeyValue write batches.
  //
  // Concurrency contract:
  //   * CellDb writes serialize naturally with `store_cell`,
  //     `store_block_state_*`, `gc_cont2`, `migrate_cells`, and
  //     `update_snapshot` because the worker never calls KeyValue APIs;
  //     only CellDbIn drains the verified spool.
  //   * `streaming_job_ != nullptr` prevents two concurrent production
  //     streaming imports. A second concurrent import receives a
  //     structured "another streaming import is in flight" error.
  //   * The downloader actor never sees a `vm::KeyValue` handle, and
  //     the worker thread never receives one either.
  //
  // Failure modes:
  //   * Tempfile open / read errors -> sink.abort(), promise.set_error.
  //   * Streaming importer rejection -> sink.abort(), promise.set_error.
  //   * Parsed-root != expected_root_hash -> sink.abort(),
  //     promise.set_error("...root hash mismatch...").
  //   * spool sealing / actor-side CellDb batch failure -> sink.abort()
  //     or fail_streaming_import(), promise.set_error.
  //   * In every failure case `streaming_job_` is cleared so a future
  //     import can claim the single production slot.
  void import_persistent_state_streaming(PersistentStateImportRequest request,
                                         td::Promise<PersistentStateImportResult> promise);
  void poll_streaming_import_worker();

  // tos27 P0-2 / tos29 High-1: continuation entry point posted from the
  // worker thread after the off-actor BoC parse + root verification
  // completes. Runs on the CellDbIn actor's serialized message loop,
  // joins the worker, and then starts actor-side spool draining. This
  // method does NOT resolve the promise on success; the promise resolves
  // only after `commit_streaming_import_spool_batch` has durably written
  // every spooled cell and refreshed the post-commit reader.
  //
  // This is the only path that can resolve the import promise; the
  // worker thread NEVER touches the promise directly because the
  // promise must only be set on the actor's loop.
  //
  // Named `continue_import_after_worker` so the hardening Check 22
  // grep ("continue_import|import_slice|import_worker") finds it.
  void continue_import_after_worker();

  // tos29 High-1: actor-only CellDb write stage. Drains the verified
  // worker-created import spool through bounded KeyValue write batches.
  // The worker never calls this directly; the actor-local completion poll
  // invokes `continue_import_after_worker`, and that continuation owns the
  // transition into this method.
  void commit_streaming_import_spool_batch();

  // Success/failure endpoints for the production import job. Both run on
  // the CellDbIn actor and tear down `streaming_job_` exactly once.
  void finish_streaming_import_after_actor_commit();
  void fail_streaming_import(td::Status error);
  void fail_streaming_import_rollback(td::Status error);
  void drain_streaming_import_rollback_batch();

  // tos26 P1-5: re-entrant GC interlock for streaming-import refcount
  // reconciliation.
  //
  // The streaming importer writes each cell with refcnt=1. By itself
  // that refcount is enough to keep the cells alive against GC, but
  // the canonical block-state root that USES those cells is recorded
  // by a SUBSEQUENT `set_block_state -> CellDb::store_cell` call (the
  // downloader runs this after `import_persistent_state_streaming`
  // resolves). Between commit-of-import and store-cell-of-root there
  // is a small window where the cells exist with refcnt=1 but no
  // canonical block-state desc-list entry references them; if the
  // periodic GC alarm fires inside that window it could begin tearing
  // down a state root and inadvertently mark the freshly imported
  // cells dead.
  //
  // We close the window by pausing the GC trigger for the duration
  // of the streaming import + until the downloader actor has had a
  // chance to drive set_block_state. The counter is re-entrant so
  // overlapping (or nested) imports compose correctly: GC is paused
  // while ANY import holds a pause, and resumes only after every
  // pause is released.
  //
  // The store_cell path that set_block_state ultimately drives runs
  // through `boc_->inc(cell)` + `prepare_commit` which walks the DAG
  // and updates descendant refcounts via the existing CellDb logic;
  // see DynamicBagOfCellsDb::prepare_commit / dfs_new_cells_in_db.
  // Once that store_cell completes, the imported cells are accounted
  // for under the canonical block-state desc list and the standard
  // GC walk will not mis-delete them, so we can safely release the
  // pause.
  //
  // Both functions are intended to be called from this actor's own
  // message loop (or via send_closure into it); they mutate
  // gc_pause_count_ without any external synchronization.
  void pause_gc_for_import();
  void resume_gc_for_import();

  // tos30: conditional rollback for actor-local streaming imports. The
  // manifest contains only cells that were absent before the import and
  // were written with the import's refcnt=1 serialized value. Rollback
  // runs on CellDbIn in bounded batches; each cell is erased only if the
  // current DB value still equals that manifest value. This makes lease
  // destruction / cancel / retry fail-closed without deleting cells that
  // a later canonical store has already adopted by changing refcounts.
  void rollback_streaming_import_manifest(std::string rollback_manifest_path, td::uint64 rollback_cells,
                                          td::uint64 rollback_bytes, std::string reason,
                                          bool resume_gc_after);
  void release_streaming_import_after_root_store_committed(std::string rollback_manifest_path,
                                                           td::uint64 rollback_cells,
                                                           td::uint64 rollback_bytes);

  void flush_db_stats();

  CellDbIn(td::actor::ActorId<RootDb> root_db, td::actor::ActorId<CellDb> parent, std::string path,
           td::Ref<ValidatorManagerOptions> opts);
  ~CellDbIn() override;

  void validate_meta();
  void start_up() override;
  void alarm() override;

 private:
  td::Result<td::uint64> recover_streaming_import_rollbacks_at_startup();
  td::Status rollback_streaming_import_manifest_sync(std::string rollback_manifest_path,
                                                     std::string reason,
                                                     bool tolerate_trailing_partial);

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
  void gc_cont(BlockIdExt block_id, td::Result<BlockHandle> R);
  void gc_cont2(BlockIdExt block_id);
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

  // tos26 P1-5: re-entrant GC pause counter. While > 0 the periodic
  // alarm() short-circuits to skip_gc() instead of advancing the
  // desc-list / running gc_cont. Mutated only on this actor's
  // message loop by pause_gc_for_import / resume_gc_for_import; no
  // external synchronization required.
  uint32_t gc_pause_count_ = 0;

  // tos27/tos29 streaming-import worker job. Holds the worker thread
  // running the BoC parse, the verified spool path, the per-import
  // provider/promise, and the actor-side spool-drain cursor. At most
  // one production import is in flight at a time. A nullptr
  // `streaming_job_` means no import is in flight.
  std::unique_ptr<StreamingImportJob> streaming_job_;
  std::deque<std::unique_ptr<StreamingImportRollbackJob>> streaming_rollback_jobs_;

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
    td::uint64 streaming_import_started_ = 0;
    td::uint64 streaming_import_committed_ = 0;
    td::uint64 streaming_import_failed_ = 0;
    td::uint64 streaming_import_cells_committed_ = 0;
    td::uint64 streaming_import_actor_batches_ = 0;
    td::uint64 streaming_import_rollback_jobs_started_ = 0;
    td::uint64 streaming_import_rollback_jobs_finished_ = 0;
    td::uint64 streaming_import_rollback_cells_processed_ = 0;
    td::uint64 streaming_import_rollback_cells_erased_ = 0;
    td::uint64 streaming_import_startup_rollback_manifests_ = 0;
    td::uint64 streaming_import_startup_rollback_cells_erased_ = 0;
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

  td::Status refresh_loader_after_celldb_mutation(td::Slice context);

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
    auto status = boc_->set_loader(std::make_unique<vm::CellLoader>(std::move(snapshot), on_load_callback_));
    LOG_IF(ERROR, status.is_error()) << "CellDb::update_snapshot: failed to refresh CellDb loader: " << status;
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
  // Test-only. Production state-sync uses
  // `import_persistent_state_streaming`. Cross-actor direct KV access
  // is unsafe; do not call from a production path.
  //
  // Phase B persistent-state catch-up: forward to
  // CellDbIn::create_streaming_writer() and resolve the promise with
  // the resulting writer (or surface the error verbatim if CellDbIn's
  // single-import flag is already taken). The `unsafe_for_tests_only`
  // suffix is intentional (audit P1-5).
  void create_celldb_streaming_writer_unsafe_for_tests_only(td::Promise<std::unique_ptr<CellDbStreamingWriter>> promise);

  // tos26 P1-4: forward the actor-local import request to CellDbIn
  // so the entire streaming-import lifecycle runs inside CellDbIn's
  // serialized actor loop. The downloader actor invokes this via
  // ValidatorManager::import_persistent_state_streaming.
  void import_persistent_state_streaming(PersistentStateImportRequest request,
                                         td::Promise<PersistentStateImportResult> promise);

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
