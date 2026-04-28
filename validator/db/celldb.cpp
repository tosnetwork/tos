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

// Suppress implicit-int-float-conversion warnings emitted by the
// vendored RocksDB headers; the suppression can be lifted once
// RocksDB no longer trips this diagnostic.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-int-float-conversion"
#include "rocksdb/merge_operator.h"
#include "rocksdb/utilities/optimistic_transaction_db.h"
#pragma GCC diagnostic pop

#include "block/block-auto.h"
#include "common/delay.h"
#include "permanent-celldb/permanent-celldb-utils.h"
#include "td/actor/MultiPromise.h"
#include "td/db/RocksDb.h"
#include "tos/tos-io.hpp"
#include "tos/tos-tl.hpp"

#include "celldb.hpp"
#include "files-async.hpp"
#include "rootdb.hpp"
#include "state-download-buffer.h"
#include "td/utils/port/FileFd.h"
#include "vm/boc.h"

namespace tos {

namespace validator {

// tos27 P0-1: CellDbGcPauseLease — RAII handle that releases an
// outstanding `pause_gc_for_import()` exactly once. Move-only.
//
// Constructed with the CellDbIn ActorId on the success path of
// `import_persistent_state_streaming`. The downloader holds the
// lease as a member of its actor state across the
// create_shard_state -> set_block_state pipeline; on
// `release_after_root_store_committed` (or on actor destruction)
// the lease send_closures `resume_gc_for_import` back to CellDbIn.
//
// All operations are noexcept. The destructor cannot throw because
// `td::actor::send_closure` itself is noexcept and the ActorId move
// is trivial.
CellDbGcPauseLease::CellDbGcPauseLease(td::actor::ActorId<CellDbIn> db) noexcept : db_(std::move(db)) {
}

CellDbGcPauseLease::CellDbGcPauseLease(CellDbGcPauseLease&& other) noexcept : db_(std::move(other.db_)) {
  other.db_ = {};  // invalidate the moved-from lease so its dtor is a no-op
}

CellDbGcPauseLease& CellDbGcPauseLease::operator=(CellDbGcPauseLease&& other) noexcept {
  if (this != &other) {
    // Release any pause we currently hold before adopting the new one.
    if (!db_.empty()) {
      td::actor::send_closure(db_, &CellDbIn::resume_gc_for_import);
    }
    db_ = std::move(other.db_);
    other.db_ = {};
  }
  return *this;
}

CellDbGcPauseLease::~CellDbGcPauseLease() {
  if (!db_.empty()) {
    // Best-effort release. If the CellDbIn actor has already shut down
    // the send_closure is a no-op; we still clear our handle so a
    // subsequent move-from is observably-empty.
    td::actor::send_closure(db_, &CellDbIn::resume_gc_for_import);
    db_ = {};
  }
}

void CellDbGcPauseLease::release_after_root_store_committed() noexcept {
  if (!db_.empty()) {
    td::actor::send_closure(db_, &CellDbIn::resume_gc_for_import);
    db_ = {};
  }
}

// Out-of-line special members for `PersistentStateImportResult` so the
// (forward-declared in validator-manager.h) `CellDbGcPauseLease` is
// only required to be complete inside this TU. Every other TU that
// flows a `td::Promise<PersistentStateImportResult>` through (the
// validator manager, rootdb, hardfork manager) gets to keep its
// minimal include set.
PersistentStateImportResult::PersistentStateImportResult() = default;
PersistentStateImportResult::~PersistentStateImportResult() = default;
PersistentStateImportResult::PersistentStateImportResult(PersistentStateImportResult&&) noexcept = default;
PersistentStateImportResult& PersistentStateImportResult::operator=(PersistentStateImportResult&&) noexcept = default;

class CellDbAsyncExecutor : public vm::DynamicBagOfCellsDb::AsyncExecutor {
 public:
  explicit CellDbAsyncExecutor(td::actor::ActorId<CellDbBase> cell_db) : cell_db_(std::move(cell_db)) {
  }

  void execute_async(std::function<void()> f) override {
    class Runner : public td::actor::Actor {
     public:
      explicit Runner(std::function<void()> f) : f_(std::move(f)) {
      }
      void start_up() override {
        f_();
        stop();
      }

     private:
      std::function<void()> f_;
    };
    td::actor::create_actor<Runner>("executeasync", std::move(f)).release();
  }

  void execute_sync(std::function<void()> f) override {
    td::actor::send_closure(cell_db_, &CellDbBase::execute_sync, std::move(f));
  }

 private:
  td::actor::ActorId<CellDbBase> cell_db_;
};

void CellDbBase::start_up() {
  async_executor = std::make_shared<CellDbAsyncExecutor>(actor_id(this));
}

void CellDbBase::execute_sync(std::function<void()> f) {
  f();
}

CellDbIn::CellDbIn(td::actor::ActorId<RootDb> root_db, td::actor::ActorId<CellDb> parent, std::string path,
                   td::Ref<ValidatorManagerOptions> opts)
    : root_db_(root_db), parent_(parent), path_(std::move(path)), opts_(opts) {
}

struct MergeOperatorAddCellRefcnt : public rocksdb::MergeOperator {
  const char* Name() const override {
    return "MergeOperatorAddCellRefcnt";
  }
  static auto to_td(rocksdb::Slice value) -> td::Slice {
    return td::Slice(value.data(), value.size());
  }
  bool FullMergeV2(const MergeOperationInput& merge_in, MergeOperationOutput* merge_out) const override {
    CHECK(merge_in.existing_value);
    auto& value = *merge_in.existing_value;
    CHECK(merge_in.operand_list.size() >= 1);
    td::Slice diff;
    std::string diff_buf;
    if (merge_in.operand_list.size() == 1) {
      diff = to_td(merge_in.operand_list[0]);
    } else {
      diff_buf = merge_in.operand_list[0].ToString();
      for (size_t i = 1; i < merge_in.operand_list.size(); ++i) {
        vm::CellStorer::merge_refcnt_diffs(diff_buf, to_td(merge_in.operand_list[i]));
      }
      diff = diff_buf;
    }

    merge_out->new_value = value.ToString();
    vm::CellStorer::merge_value_and_refcnt_diff(merge_out->new_value, diff);
    return true;
  }
  bool PartialMerge(const rocksdb::Slice& /*key*/, const rocksdb::Slice& left, const rocksdb::Slice& right,
                    std::string* new_value, rocksdb::Logger* logger) const override {
    *new_value = left.ToString();
    vm::CellStorer::merge_refcnt_diffs(*new_value, to_td(right));
    return true;
  }
};

void CellDbIn::validate_meta() {
  LOG(INFO) << "Validating metadata\n";
  size_t max_meta_keys_loaded = opts_->get_celldb_in_memory() ? std::numeric_limits<std::size_t>::max() : 10000;
  auto meta = boc_->meta_get_all(max_meta_keys_loaded).move_as_ok();
  bool partial_check = meta.size() == max_meta_keys_loaded;
  if (partial_check) {
    LOG(ERROR) << "Too much metadata in the database, do only partial check";
  }
  size_t missing_roots = 0;
  size_t unknown_roots = 0;
  std::set<vm::CellHash> root_hashes;
  for (auto [k, v] : meta) {
    if (k == "desczero") {
      continue;
    }
    auto obj = fetch_tl_object<tos_api::db_celldb_value>(td::BufferSlice{v}, true);
    obj.ensure();
    auto entry = DbEntry{obj.move_as_ok()};
    root_hashes.insert(vm::CellHash::from_slice(entry.root_hash.as_slice()));
    auto cell = boc_->load_cell(entry.root_hash.as_slice());
    missing_roots += cell.is_error();
    LOG_IF(ERROR, cell.is_error()) << "Cannot load root from meta: " << entry.block_id.to_str() << " " << cell.error();
  }

  // load_known_roots is only supported by InMemory database, so it is ok to check all known roots here
  auto known_roots = boc_->load_known_roots().move_as_ok();
  for (auto& root : known_roots) {
    block::gen::ShardStateUnsplit::Record info;
    block::gen::OutMsgQueueInfo::Record qinfo;
    block::ShardId shard;
    if (!(tlb::unpack_cell(root, info) && shard.deserialize(info.shard_id.write()) &&
          tlb::unpack_cell(info.out_msg_queue_info, qinfo))) {
      LOG(FATAL) << "cannot create ShardDescr from a root in celldb";
    }
    if (!partial_check && !root_hashes.contains(root->get_hash())) {
      unknown_roots++;
      LOG(ERROR) << "Unknown root" << ShardIdFull(shard).to_str() << ":" << info.seq_no;
      constexpr bool delete_unknown_roots = false;
      if (delete_unknown_roots) {
        vm::CellStorer stor{*cell_db_};
        cell_db_->begin_write_batch().ensure();
        boc_->dec(root);
        boc_->commit(stor).ensure();
        cell_db_->commit_write_batch().ensure();
        if (!opts_->get_celldb_in_memory()) {
          boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();
        }
        LOG(ERROR) << "Unknown root" << ShardIdFull(shard).to_str() << ":" << info.seq_no << " REMOVED";
      }
    }
  }

  LOG_IF(ERROR, missing_roots != 0) << "Missing root hashes: " << missing_roots;
  LOG_IF(ERROR, unknown_roots != 0) << "Unknown roots: " << unknown_roots;

  LOG_IF(FATAL, missing_roots != 0) << "Missing root hashes: " << missing_roots;
  LOG_IF(FATAL, unknown_roots != 0) << "Unknown roots: " << unknown_roots;
  LOG(INFO) << "Validating metadata: OK\n";
}

void CellDbIn::start_up() {
  on_load_callback_ = [actor = std::make_shared<td::actor::ActorOwn<MigrationProxy>>(
                           td::actor::create_actor<MigrationProxy>("celldbmigration", actor_id(this))),
                       compress_depth = opts_->get_celldb_compress_depth()](const vm::CellLoader::LoadResult& res) {
    if (res.cell_.is_null()) {
      return;
    }
    bool expected_stored_boc = res.cell_->get_depth() == compress_depth && compress_depth != 0;
    if (expected_stored_boc != res.stored_boc_) {
      td::actor::send_closure(*actor, &CellDbIn::MigrationProxy::migrate_cell,
                              td::Bits256{res.cell_->get_hash().bits()});
    }
  };

  CellDbBase::start_up();
  td::RocksDbOptions db_options;
  if (!opts_->get_disable_rocksdb_stats()) {
    statistics_ = td::RocksDb::create_statistics();
    statistics_flush_at_ = td::Timestamp::in(60.0);
    snapshot_statistics_ = std::make_shared<td::RocksDbSnapshotStatistics>();
    db_options.snapshot_statistics = snapshot_statistics_;
  }
  db_options.statistics = statistics_;
  auto o_celldb_cache_size = opts_->get_celldb_cache_size();

  std::optional<vm::DynamicBagOfCellsDb::CreateInMemoryOptions> boc_in_memory_options;
  std::optional<vm::DynamicBagOfCellsDb::CreateV1Options> boc_v1_options;
  std::optional<vm::DynamicBagOfCellsDb::CreateV2Options> boc_v2_options;

  if (opts_->get_celldb_v2()) {
    boc_v2_options = vm::DynamicBagOfCellsDb::CreateV2Options{
        .extra_threads = std::clamp(std::thread::hardware_concurrency() / 2, 1u, 8u),
        .executor = {},
        .cache_ttl_max = 2000,
        .cache_size_max = 1000000};
    size_t min_rocksdb_cache = std::max(size_t{1} << 30, boc_v2_options->cache_size_max * 5000);
    if (!o_celldb_cache_size || o_celldb_cache_size.value() < min_rocksdb_cache) {
      LOG(WARNING) << "Increase CellDb block cache size to " << td::format::as_size(min_rocksdb_cache) << " from "
                   << td::format::as_size(o_celldb_cache_size.value());
      o_celldb_cache_size = min_rocksdb_cache;
    }
    LOG(WARNING) << "Using V2 DynamicBagOfCells with options " << *boc_v2_options;
  } else if (opts_->get_celldb_in_memory()) {
    // default options
    boc_in_memory_options = vm::DynamicBagOfCellsDb::CreateInMemoryOptions{
        .extra_threads = std::thread::hardware_concurrency(),
        .verbose = true,
        .use_arena = false,
        .use_less_memory_during_creation = true,
    };
    LOG(WARNING) << "Using InMemory DynamicBagOfCells with options " << *boc_v2_options;
  } else {
    boc_v1_options = vm::DynamicBagOfCellsDb::CreateV1Options{};
    LOG(WARNING) << "Using V1 DynamicBagOfCells with options " << *boc_v1_options;
  }

  db_options.enable_bloom_filter = !opts_->get_celldb_disable_bloom_filter();
  db_options.two_level_index_and_filter =
      db_options.enable_bloom_filter && opts_->state_ttl() >= 60 * 60 * 24 * 30;  // 30 days
  if (db_options.two_level_index_and_filter && !opts_->get_celldb_in_memory()) {
    o_celldb_cache_size = std::max<td::uint64>(o_celldb_cache_size ? o_celldb_cache_size.value() : 0UL, 16UL << 30);
  }

  if (o_celldb_cache_size) {
    db_options.block_cache = td::RocksDb::create_cache(o_celldb_cache_size.value());
    LOG(WARNING) << "Set CellDb block cache size to " << td::format::as_size(o_celldb_cache_size.value());
  }
  db_options.use_direct_reads = opts_->get_celldb_direct_io();

  // NB: from now on we MUST use this merge operator
  // Only V2 and InMemory BoC actually use them, but it still should be kept for V1,
  // to handle updates written by V2 or InMemory BoCs
  db_options.merge_operator = std::make_shared<MergeOperatorAddCellRefcnt>();

  if (opts_->get_celldb_in_memory()) {
    td::RocksDbOptions read_db_options;
    read_db_options.use_direct_reads = true;
    read_db_options.no_block_cache = true;
    read_db_options.block_cache = {};
    read_db_options.merge_operator = std::make_shared<MergeOperatorAddCellRefcnt>();
    LOG(WARNING) << "Loading all cells in memory (because of --celldb-in-memory)";
    td::Timer timer;
    auto read_cell_db =
        std::make_shared<td::RocksDb>(td::RocksDb::open(path_, std::move(read_db_options)).move_as_ok());
    boc_ = vm::DynamicBagOfCellsDb::create_in_memory(read_cell_db.get(), *boc_in_memory_options);
    in_memory_load_time_ = timer.elapsed();

    // no reads will be allowed from rocksdb, only writes
    db_options.no_reads = true;
  }

  auto rocks_db = std::make_shared<td::RocksDb>(td::RocksDb::open(path_, std::move(db_options)).move_as_ok());
  rocks_db_ = rocks_db->raw_db();
  cell_db_ = std::move(rocks_db);
  if (!opts_->get_celldb_in_memory()) {
    if (opts_->get_celldb_v2()) {
      boc_ = vm::DynamicBagOfCellsDb::create_v2(*boc_v2_options);
    } else {
      boc_ = vm::DynamicBagOfCellsDb::create(*boc_v1_options);
    }
    boc_->set_celldb_compress_depth(opts_->get_celldb_compress_depth());
    boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();
  }

  validate_meta();

  alarm_timestamp() = td::Timestamp::in(10.0);

  auto empty = get_empty_key_hash();
  if (get_block(empty).is_error()) {
    DbEntry e{get_empty_key(), empty, empty, RootHash::zero()};
    vm::CellStorer stor{*cell_db_};
    cell_db_->begin_write_batch().ensure();
    set_block(empty, std::move(e));
    boc_->commit(stor);
    cell_db_->commit_write_batch().ensure();
    if (!opts_->get_celldb_in_memory()) {
      boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();
    }
  }

  if (opts_->get_celldb_v2() || opts_->get_celldb_in_memory()) {
    send_closure(parent_, &CellDb::set_thread_safe_boc, boc_);
  } else {
    send_closure(parent_, &CellDb::update_snapshot, cell_db_->snapshot());
  }

  if (opts_->get_celldb_preload_all()) {
    // Iterate whole DB in a separate thread
    delay_action(
        [snapshot = cell_db_->snapshot()]() {
          LOG(WARNING) << "CellDb: pre-loading all keys";
          td::uint64 total = 0;
          td::Timer timer;
          auto S = snapshot->for_each([&](td::Slice, td::Slice) {
            ++total;
            if (total % 1000000 == 0) {
              LOG(INFO) << "CellDb: iterated " << total << " keys";
            }
            return td::Status::OK();
          });
          if (S.is_error()) {
            LOG(ERROR) << "CellDb: pre-load failed: " << S.move_as_error();
          } else {
            LOG(WARNING) << "CellDb: iterated " << total << " keys in " << timer.elapsed() << "s";
          }
        },
        td::Timestamp::now());
  }

  {
    std::string key = "stats.last_deleted_mc_seqno", value;
    auto R = boc_->meta_get(td::as_slice(key), value);
    R.ensure();
    if (R.ok() == td::KeyValue::GetStatus::Ok) {
      auto r_value = td::to_integer_safe<BlockSeqno>(value);
      r_value.ensure();
      last_deleted_mc_state_ = r_value.move_as_ok();
    }
  }
  {
    std::string key = "opts.permanent_mode", value;
    auto R = boc_->meta_get(td::as_slice(key), value);
    R.ensure();
    bool stored_permanent_mode = R.ok() == td::KeyValue::GetStatus::Ok;
    if (stored_permanent_mode) {
      LOG_CHECK(opts_->get_permanent_celldb()) << "permanent_celldb cannot be turned off";
    }
    permanent_mode_ = stored_permanent_mode || opts_->get_permanent_celldb();
    if (permanent_mode_) {
      LOG(WARNING) << "Celldb is in permanent mode";
      if (!stored_permanent_mode) {
        cell_db_->begin_write_batch().ensure();
        value = "1";
        vm::CellStorer stor{*cell_db_};
        boc_->meta_set(td::as_slice(key), td::as_slice(value));
        boc_->commit(stor).ensure();
        cell_db_->commit_write_batch().ensure();
        if (!opts_->get_celldb_in_memory()) {
          boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();
        }
      }
    }
    cell_db_statistics_.permanent_mode_ = permanent_mode_;
    LOG_IF(FATAL, permanent_mode_ && opts_->get_celldb_in_memory())
        << "celldb permanent_mode and in_memory_mode are not compatible";
  }
}

void CellDbIn::load_cell(RootHash hash, td::Promise<td::Ref<vm::DataCell>> promise) {
  if (db_busy_) {
    ++action_queue_cnt_load_;
    action_queue_.push_back([self = this, hash, promise = std::move(promise)](td::Result<td::Unit> R) mutable {
      R.ensure();
      --self->action_queue_cnt_load_;
      self->load_cell(hash, std::move(promise));
    });
    return;
  }
  if (opts_->get_celldb_in_memory()) {
    auto result = boc_->load_root(hash.as_slice());
    async_apply("load_cell_result", std::move(promise), std::move(result));
    return;
  }
  auto cell = boc_->load_cell(hash.as_slice());
  delay_action(
      [cell = std::move(cell), promise = std::move(promise)]() mutable { promise.set_result(std::move(cell)); },
      td::Timestamp::now());
}

void CellDbIn::store_cell(BlockIdExt block_id, td::Ref<vm::Cell> cell, vm::StoreCellHint hint,
                          td::Promise<td::Ref<vm::DataCell>> promise) {
  if (db_busy_) {
    ++action_queue_cnt_store_;
    action_queue_.push_back([self = this, block_id, cell = std::move(cell), hint = std::move(hint),
                             promise = std::move(promise)](td::Result<td::Unit> R) mutable {
      R.ensure();
      --self->action_queue_cnt_store_;
      self->store_cell(block_id, std::move(cell), std::move(hint), std::move(promise));
    });
    return;
  }
  td::PerfWarningTimer timer{"storecell", 0.1};
  auto key_hash = get_key_hash(block_id);
  auto R = get_block(key_hash);
  // duplicate
  if (R.is_ok()) {
    delay_action([cell = boc_->load_cell(cell->get_hash().as_slice()),
                  promise = std::move(promise)]() mutable { promise.set_result(std::move(cell)); },
                 td::Timestamp::now());
    return;
  }

  boc_->inc(cell);
  db_busy_ = true;
  boc_->prepare_commit_async(
      async_executor, std::move(hint),
      [=, this, SelfId = actor_id(this), timer = std::move(timer), timer_prepare = td::Timer{},
       promise = std::move(promise), cell = std::move(cell)](td::Result<td::Unit> Res) mutable {
        Res.ensure();
        timer_prepare.pause();
        td::actor::send_lambda_later(SelfId, [=, this, timer = std::move(timer), promise = std::move(promise),
                                              cell = std::move(cell)]() mutable {
          TD_PERF_COUNTER(celldb_store_cell);
          auto empty = get_empty_key_hash();
          auto ER = get_block(empty);
          ER.ensure();
          auto E = ER.move_as_ok();

          auto PR = get_block(E.prev);
          PR.ensure();
          auto P = PR.move_as_ok();
          CHECK(P.next == empty);

          DbEntry D{block_id, E.prev, empty, cell->get_hash().bits()};

          E.prev = key_hash;
          P.next = key_hash;

          if (P.is_empty()) {
            E.next = key_hash;
            P.prev = key_hash;
          }
          td::Timer timer_write;
          vm::CellStorer stor{*cell_db_};
          cell_db_->begin_write_batch().ensure();
          set_block(get_empty_key_hash(), std::move(E));
          set_block(D.prev, std::move(P));
          set_block(key_hash, std::move(D));
          boc_->commit(stor).ensure();
          cell_db_->commit_write_batch().ensure();
          timer_write.pause();

          if (!opts_->get_celldb_in_memory()) {
            boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();
            td::actor::send_closure(parent_, &CellDb::update_snapshot, cell_db_->snapshot());
          }

          delay_action([cell = boc_->load_cell(cell->get_hash().as_slice()),
                        promise = std::move(promise)]() mutable { promise.set_result(std::move(cell)); },
                       td::Timestamp::now());
          if (!opts_->get_disable_rocksdb_stats()) {
            cell_db_statistics_.store_cell_time_.insert(timer.elapsed() * 1e6);
            cell_db_statistics_.store_cell_prepare_time_.insert(timer_prepare.elapsed() * 1e6);
            cell_db_statistics_.store_cell_write_time_.insert(timer_write.elapsed() * 1e6);
          }
          LOG(DEBUG) << "Stored state " << block_id.to_str();
          release_db();
        });
      });
}

void CellDbIn::get_cell_db_reader(td::Promise<std::shared_ptr<vm::CellDbReader>> promise) {
  if (db_busy_) {
    action_queue_.push_back([self = this, promise = std::move(promise)](td::Result<td::Unit> R) mutable {
      R.ensure();
      self->get_cell_db_reader(std::move(promise));
    });
    return;
  }
  promise.set_result(boc_->get_cell_db_reader());
}

void CellDbIn::store_block_state_permanent(td::Ref<BlockData> block, td::Promise<td::Ref<vm::DataCell>> promise) {
  if (!permanent_mode_) {
    promise.set_error(td::Status::Error("celldb is not in permanent mode"));
    return;
  }
  if (db_busy_) {
    ++action_queue_cnt_store_;
    action_queue_.push_back(
        [self = this, block = std::move(block), promise = std::move(promise)](td::Result<td::Unit> R) mutable {
          R.ensure();
          --self->action_queue_cnt_store_;
          self->store_block_state_permanent(std::move(block), std::move(promise));
        });
    return;
  }
  auto key_hash = get_key_hash(block->block_id());
  auto R = get_block(key_hash);
  // duplicate
  if (R.is_ok()) {
    delay_action([cell = boc_->load_cell(R.ok().root_hash.as_slice()),
                  promise = std::move(promise)]() mutable { promise.set_result(std::move(cell)); },
                 td::Timestamp::now());
    return;
  }
  store_block_state_permanent_bulk({block}, [=, SelfId = actor_id(this), promise = std::move(promise)](
                                                td::Result<std::map<BlockIdExt, RootHash>> R) mutable {
    TRY_STATUS_PROMISE(promise, R.move_as_status());
    block::gen::Block::Record rec;
    if (!block::gen::unpack_cell(block->root_cell(), rec)) {
      promise.set_error(td::Status::Error("cannot unpack Block record"));
      return;
    }
    bool spec;
    vm::CellSlice update_cs = vm::load_cell_slice_special(rec.state_update, spec);
    if (update_cs.special_type() != vm::CellTraits::SpecialType::MerkleUpdate) {
      promise.set_error(td::Status::Error("invalid Merkle update in block"));
      return;
    }
    td::Ref<vm::Cell> new_state_root = update_cs.prefetch_ref(1);
    RootHash state_root_hash = new_state_root->get_hash(0).bits();
    td::actor::send_closure(SelfId, &CellDbIn::load_cell, state_root_hash, std::move(promise));
  });
}

void CellDbIn::store_block_state_permanent_bulk(std::vector<td::Ref<BlockData>> blocks,
                                                td::Promise<std::map<BlockIdExt, RootHash>> promise) {
  if (!permanent_mode_) {
    promise.set_error(td::Status::Error("celldb is not in permanent mode"));
    return;
  }
  if (db_busy_) {
    ++action_queue_cnt_store_;
    action_queue_.push_back(
        [self = this, blocks = std::move(blocks), promise = std::move(promise)](td::Result<td::Unit> R) mutable {
          R.ensure();
          --self->action_queue_cnt_store_;
          self->store_block_state_permanent_bulk(std::move(blocks), std::move(promise));
        });
    return;
  }
  td::PerfWarningTimer timer{"storecellbulk", 0.1};
  td::Timer timer_prepare;
  std::map<BlockIdExt, td::Ref<BlockData>> new_blocks;
  for (auto& block : blocks) {
    BlockIdExt block_id = block->block_id();
    if (new_blocks.contains(block_id)) {
      continue;
    }
    if (get_block(get_key_hash(block_id)).is_ok()) {
      continue;
    }
    new_blocks[block_id] = std::move(block);
  }
  if (new_blocks.empty()) {
    promise.set_value(std::map<BlockIdExt, RootHash>{});
    return;
  }
  for (auto& [block_id, block] : new_blocks) {
    std::vector<BlockIdExt> prev;
    BlockIdExt mc_blkid;
    bool after_split;
    TRY_STATUS_PROMISE(promise,
                       block::unpack_block_prev_blk_try(block->root_cell(), block_id, prev, mc_blkid, after_split));
    for (const BlockIdExt& prev_id : prev) {
      if (!new_blocks.contains(prev_id) && get_block(get_key_hash(prev_id)).is_error()) {
        promise.set_error(td::Status::Error("cannot store block state: previous block is not in db"));
        return;
      }
    }
  }
  db_busy_ = true;
  calculate_permanent_celldb_update(
      new_blocks, async_executor,
      [this, SelfId = actor_id(this), timer = std::move(timer), timer_prepare = std::move(timer_prepare),
       promise = std::move(promise)](td::Result<std::vector<PermanentCellDbUpdate>> R) mutable {
        td::actor::send_lambda_later(
            SelfId, [=, this, timer = std::move(timer), timer_prepare = std::move(timer_prepare), R = std::move(R),
                     promise = std::move(promise)]() mutable {
              SCOPE_EXIT {
                release_db();
              };
              TRY_RESULT_PROMISE(promise, updates, std::move(R));
              TD_PERF_COUNTER(celldb_store_cell_multi);
              timer_prepare.pause();
              td::Timer timer_write;
              vm::CellStorer stor{*cell_db_};
              cell_db_->begin_write_batch().ensure();

              std::map<BlockIdExt, RootHash> state_root_hashes;
              for (auto& update : updates) {
                state_root_hashes[update.block_id] = update.state_root_hash;
                for (auto& [k, v] : update.to_store) {
                  cell_db_->set(k.as_slice(), v).ensure();
                }
              }

              CHECK(!updates.empty());
              auto empty = get_empty_key_hash();
              auto E = get_block(empty).move_as_ok();
              for (size_t i = 0; i < updates.size(); ++i) {
                KeyHash prev = i == 0 ? empty : get_key_hash(updates[i - 1].block_id);
                KeyHash next = i + 1 == updates.size() ? E.next : get_key_hash(updates[i + 1].block_id);
                DbEntry entry{updates[i].block_id, prev, next, updates[i].state_root_hash};
                set_block(get_key_hash(updates[i].block_id), std::move(entry));
              }
              E.next = get_key_hash(updates[0].block_id);
              if (E.prev == empty) {
                E.prev = get_key_hash(updates.back().block_id);
              }
              set_block(empty, std::move(E));

              boc_->commit(stor).ensure();  // Save meta
              cell_db_->commit_write_batch().ensure();
              timer_write.pause();

              if (!opts_->get_celldb_in_memory()) {
                boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();
                td::actor::send_closure(parent_, &CellDb::update_snapshot, cell_db_->snapshot());
              }

              if (!opts_->get_disable_rocksdb_stats()) {
                cell_db_statistics_.store_cell_time_.insert(timer.elapsed() * 1e6);
                cell_db_statistics_.store_cell_prepare_time_.insert(timer_prepare.elapsed() * 1e6);
                cell_db_statistics_.store_cell_write_time_.insert(timer_write.elapsed() * 1e6);
                cell_db_statistics_.store_cell_bulk_queries_++;
                cell_db_statistics_.store_cell_bulk_total_blocks_ += updates.size();
              }
              promise.set_result(std::move(state_root_hashes));
            });
      });
}

std::vector<std::pair<std::string, std::string>> CellDbIn::prepare_stats() {
  TD_PERF_COUNTER(celldb_prepare_stats);
  auto r_boc_stats = boc_->get_stats();
  if (r_boc_stats.is_ok()) {
    cell_db_statistics_.boc_stats_ = r_boc_stats.move_as_ok();
  }
  cell_db_statistics_.in_memory_load_time_ = in_memory_load_time_;
  auto stats = cell_db_statistics_.prepare_stats();
  auto add_stat = [&](const auto& key, const auto& value) { stats.emplace_back(key, PSTRING() << value); };

  add_stat("started", "true");
  auto r_mem_stat = td::mem_stat();
  auto r_total_mem_stat = td::get_total_mem_stat();
  td::uint64 celldb_size = 0;
  bool ok_celldb_size = rocks_db_->GetIntProperty("rocksdb.total-sst-files-size", &celldb_size);
  if (celldb_size > 0 && r_mem_stat.is_ok() && r_total_mem_stat.is_ok() && ok_celldb_size) {
    auto mem_stat = r_mem_stat.move_as_ok();
    auto total_mem_stat = r_total_mem_stat.move_as_ok();
    add_stat("rss", td::format::as_size(mem_stat.resident_size_));
    add_stat("available_ram", td::format::as_size(total_mem_stat.available_ram));
    add_stat("total_ram", td::format::as_size(total_mem_stat.total_ram));
    add_stat("actual_ram_to_celldb_ratio", double(total_mem_stat.available_ram) / double(celldb_size));
    add_stat("if_restarted_ram_to_celldb_ratio",
             double(total_mem_stat.available_ram + mem_stat.resident_size_ - 10 * (td::uint64(1) << 30)) /
                 double(celldb_size));
    add_stat("max_possible_ram_to_celldb_ratio", double(total_mem_stat.total_ram) / double(celldb_size));
  }
  stats.emplace_back("last_deleted_mc_state", td::to_string(last_deleted_mc_state_));
  stats.emplace_back("action_queue_size", PSTRING() << "total : " << action_queue_.size()
                                                    << " load : " << action_queue_cnt_load_
                                                    << " store : " << action_queue_cnt_store_);

  return stats;
  // do not clear statistics, it is needed for flush_db_stats
}
void CellDbIn::flush_db_stats() {
  if (opts_->get_disable_rocksdb_stats()) {
    return;
  }
  if (db_busy_) {
    // push_front to prioritize flush_db_stats
    action_queue_.push_front([self = this](td::Result<td::Unit> R) mutable {
      R.ensure();
      self->flush_db_stats();
    });
    return;
  }

  auto celldb_stats = prepare_stats();
  td::StringBuilder ss;
  for (auto& [key, value] : celldb_stats) {
    ss << "tos.celldb." << key << " " << value << "\n";
  }

  auto stats =
      td::RocksDb::statistics_to_string(statistics_) + snapshot_statistics_->to_string() + ss.as_cslice().str();
  td::actor::send_closure(parent_, &CellDb::flush_db_stats, std::move(stats));
  td::RocksDb::reset_statistics(statistics_);
  cell_db_statistics_.clear();
  cell_db_statistics_.permanent_mode_ = permanent_mode_;
}

void CellDbIn::alarm() {
  if (statistics_flush_at_ && statistics_flush_at_.is_in_past()) {
    statistics_flush_at_ = td::Timestamp::in(60.0);
    flush_db_stats();
  }

  if (migrate_after_ && migrate_after_.is_in_past()) {
    migrate_cells();
  }
  if (migration_stats_ && migration_stats_->end_at_.is_in_past()) {
    LOG(INFO) << "CellDb migration, " << migration_stats_->start_.elapsed()
              << "s stats: batches=" << migration_stats_->batches_ << " migrated=" << migration_stats_->migrated_cells_
              << " checked=" << migration_stats_->checked_cells_ << " time=" << migration_stats_->total_time_
              << " queue_size=" << cells_to_migrate_.size();
    migration_stats_ = {};
  }
  if (permanent_mode_) {
    skip_gc();
    return;
  }
  // tos26 P1-5: streaming-import GC interlock. While a streaming
  // import is in flight (or its commit window is still pending the
  // downloader's follow-up set_block_state call), short-circuit to
  // skip_gc() so the periodic GC trigger reschedules itself instead
  // of trying to advance the desc-list. This prevents the imported-
  // but-not-yet-recorded cells from being torn down by gc_cont2
  // before the canonical block-state desc-list entry references them.
  if (gc_pause_count_ > 0) {
    skip_gc();
    return;
  }
  auto E = get_block(get_empty_key_hash()).move_as_ok();
  auto N = get_block(E.next).move_as_ok();
  if (N.is_empty()) {
    alarm_timestamp() = td::Timestamp::in(0.1);
    return;
  }

  auto block_id = N.block_id;
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), block_id](td::Result<bool> R) {
    if (R.is_error()) {
      td::actor::send_closure(SelfId, &CellDbIn::skip_gc);
    } else {
      auto value = R.move_as_ok();
      if (!value) {
        td::actor::send_closure(SelfId, &CellDbIn::skip_gc);
      } else {
        td::actor::send_closure(SelfId, &CellDbIn::gc, block_id);
      }
    }
  });
  td::actor::send_closure(root_db_, &RootDb::allow_state_gc, block_id, std::move(P));
}

void CellDbIn::gc(BlockIdExt block_id) {
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<BlockHandle> R) {
    R.ensure();
    td::actor::send_closure(SelfId, &CellDbIn::gc_cont, R.move_as_ok());
  });
  td::actor::send_closure(root_db_, &RootDb::get_block_handle_external, block_id, false, std::move(P));
}

void CellDbIn::gc_cont(BlockHandle handle) {
  if (!handle->inited_state_boc()) {
    LOG(WARNING) << "inited_state_boc=false, but state in db. blockid=" << handle->id();
  }
  handle->set_deleted_state_boc();

  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), handle](td::Result<td::Unit> R) {
    R.ensure();
    td::actor::send_closure(SelfId, &CellDbIn::gc_cont2, handle);
  });

  td::actor::send_closure(root_db_, &RootDb::store_block_handle, handle, std::move(P));
}

void CellDbIn::gc_cont2(BlockHandle handle) {
  if (db_busy_) {
    action_queue_.push_back([self = this, handle = std::move(handle)](td::Result<td::Unit> R) mutable {
      R.ensure();
      self->gc_cont2(handle);
    });
    return;
  }
  CHECK(!permanent_mode_);

  td::PerfWarningTimer timer{"gccell", 0.1};
  td::PerfWarningTimer timer_all{"gccell_all", 0.05};

  td::PerfWarningTimer timer_get_keys{"gccell_get_keys", 0.05};
  auto key_hash = get_key_hash(handle->id());
  auto FR = get_block(key_hash);
  FR.ensure();
  auto F = FR.move_as_ok();

  auto PR = get_block(F.prev);
  PR.ensure();
  auto P = PR.move_as_ok();
  auto NR = get_block(F.next);
  NR.ensure();
  auto N = NR.move_as_ok();

  P.next = F.next;
  N.prev = F.prev;
  if (P.is_empty() && N.is_empty()) {
    P.prev = P.next;
    N.next = N.prev;
  }
  timer_get_keys.reset();

  td::PerfWarningTimer timer_boc{"gccell_boc", 0.05};
  auto r_cell = boc_->load_cell(F.root_hash.as_slice());
  td::Ref<vm::Cell> cell;
  if (r_cell.is_ok()) {
    cell = r_cell.move_as_ok();
    boc_->dec(cell);
  }

  db_busy_ = true;
  boc_->prepare_commit_async(
      async_executor, {},
      [this, SelfId = actor_id(this), timer_boc = std::move(timer_boc), F = std::move(F), key_hash, P = std::move(P),
       N = std::move(N), cell = std::move(cell), timer = std::move(timer), timer_all = std::move(timer_all),
       handle](td::Result<td::Unit> R) mutable {
        R.ensure();
        td::actor::send_lambda_later(
            SelfId,
            [this, timer_boc = std::move(timer_boc), F = std::move(F), key_hash, P = std::move(P), N = std::move(N),
             cell = std::move(cell), timer = std::move(timer), timer_all = std::move(timer_all), handle]() mutable {
              TD_PERF_COUNTER(celldb_gc_cell);
              vm::CellStorer stor{*cell_db_};
              timer_boc.reset();

              td::PerfWarningTimer timer_write_batch{"gccell_write_batch", 0.05};
              cell_db_->begin_write_batch().ensure();

              boc_->meta_erase(get_key(key_hash)).ensure();
              set_block(F.prev, std::move(P));
              set_block(F.next, std::move(N));
              if (handle->id().is_masterchain()) {
                last_deleted_mc_state_ = handle->id().seqno();
                std::string key = "stats.last_deleted_mc_seqno", value = td::to_string(last_deleted_mc_state_);
                boc_->meta_set(td::as_slice(key), td::as_slice(value));
              }

              boc_->commit(stor).ensure();
              cell_db_->commit_write_batch().ensure();

              alarm_timestamp() = td::Timestamp::now();
              timer_write_batch.reset();

              td::PerfWarningTimer timer_free_cells{"gccell_free_cells", 0.05};
              auto before = td::ref_get_delete_count();
              cell = {};
              auto after = td::ref_get_delete_count();
              if (timer_free_cells.elapsed() > 0.04) {
                LOG(ERROR) << "deleted " << after - before << " cells";
              }
              timer_free_cells.reset();

              td::PerfWarningTimer timer_finish{"gccell_finish", 0.05};
              if (!opts_->get_celldb_in_memory()) {
                boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();
                td::actor::send_closure(parent_, &CellDb::update_snapshot, cell_db_->snapshot());
              }

              DCHECK(get_block(key_hash).is_error());
              if (!opts_->get_disable_rocksdb_stats()) {
                cell_db_statistics_.gc_cell_time_.insert(timer.elapsed() * 1e6);
              }
              LOG(DEBUG) << "Deleted state " << handle->id().to_str();
              timer_finish.reset();
              timer_all.reset();
              release_db();
            });
      });
}

void CellDbIn::skip_gc() {
  alarm_timestamp() = td::Timestamp::in(1.0);
}

// tos26 P1-5: pause/resume GC during the streaming-import commit window.
//
// The pause is re-entrant: every pause must be matched by exactly one
// resume. While the counter is > 0 the alarm() handler short-circuits to
// skip_gc(), which reschedules the alarm in 1s. The counter is mutated
// only on this actor's message loop, so no external synchronization is
// needed.
void CellDbIn::pause_gc_for_import() {
  ++gc_pause_count_;
}

void CellDbIn::resume_gc_for_import() {
  if (gc_pause_count_ == 0) {
    LOG(ERROR) << "CellDbIn::resume_gc_for_import: pause counter already zero; "
                  "double-resume indicates a lifecycle bug in the import path";
    return;
  }
  --gc_pause_count_;
  if (gc_pause_count_ == 0) {
    // Re-arm the alarm immediately so a long-deferred GC pass can
    // catch up promptly after the import window closes.
    alarm_timestamp() = td::Timestamp::now();
  }
}

std::string CellDbIn::get_key(KeyHash key_hash) {
  if (!key_hash.is_zero()) {
    return PSTRING() << "desc" << key_hash;
  } else {
    return "desczero";
  }
}

CellDbIn::KeyHash CellDbIn::get_key_hash(BlockIdExt block_id) {
  if (block_id.is_valid()) {
    return get_tl_object_sha_bits256(create_tl_block_id(block_id));
  } else {
    return KeyHash::zero();
  }
}

BlockIdExt CellDbIn::get_empty_key() {
  return BlockIdExt{workchainInvalid, 0, 0, RootHash::zero(), FileHash::zero()};
}

CellDbIn::KeyHash CellDbIn::get_empty_key_hash() {
  return KeyHash::zero();
}

td::Result<CellDbIn::DbEntry> CellDbIn::get_block(KeyHash key_hash) {
  const auto key = get_key(key_hash);
  std::string value;
  auto R = boc_->meta_get(td::as_slice(key), value);
  R.ensure();
  auto S = R.move_as_ok();
  if (S == td::KeyValue::GetStatus::NotFound) {
    return td::Status::Error(ErrorCode::notready, "not in db");
  }
  auto obj = fetch_tl_object<tos_api::db_celldb_value>(td::BufferSlice{value}, true);
  obj.ensure();
  return DbEntry{obj.move_as_ok()};
}

void CellDbIn::set_block(KeyHash key_hash, DbEntry e) {
  const auto key = get_key(key_hash);
  boc_->meta_set(td::as_slice(key), e.release());
}

void CellDbIn::migrate_cell(td::Bits256 hash) {
  if (permanent_mode_) {
    return;
  }
  cells_to_migrate_.insert(hash);
  if (!migration_active_) {
    migration_active_ = true;
    migrate_after_ = td::Timestamp::in(10.0);
  }
}

void CellDbIn::migrate_cells() {
  migrate_after_ = td::Timestamp::never();
  if (db_busy_) {
    action_queue_.push_back([self = this](td::Result<td::Unit> R) mutable {
      R.ensure();
      self->migrate_cells();
    });
    return;
  }
  if (cells_to_migrate_.empty()) {
    migration_active_ = false;
    return;
  }
  td::Timer timer;
  if (!migration_stats_) {
    migration_stats_ = std::make_unique<MigrationStats>();
  }
  vm::CellStorer stor{*cell_db_};
  auto loader = std::make_unique<vm::CellLoader>(cell_db_->snapshot());
  boc_->set_loader(std::make_unique<vm::CellLoader>(*loader)).ensure();
  cell_db_->begin_write_batch().ensure();
  td::uint32 checked = 0, migrated = 0;
  for (auto it = cells_to_migrate_.begin(); it != cells_to_migrate_.end() && checked < 128;) {
    ++checked;
    td::Bits256 hash = *it;
    it = cells_to_migrate_.erase(it);
    auto R = loader->load(hash.as_slice(), true, boc_->as_ext_cell_creator());
    if (R.is_error()) {
      continue;
    }
    if (R.ok().status == vm::CellLoader::LoadResult::NotFound) {
      continue;
    }
    bool expected_stored_boc =
        R.ok().cell_->get_depth() == opts_->get_celldb_compress_depth() && opts_->get_celldb_compress_depth() != 0;
    if (expected_stored_boc != R.ok().stored_boc_) {
      ++migrated;
      stor.set(R.ok().refcnt(), R.ok().cell_, expected_stored_boc).ensure();
    }
  }
  cell_db_->commit_write_batch().ensure();
  boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();
  td::actor::send_closure(parent_, &CellDb::update_snapshot, cell_db_->snapshot());

  double time = timer.elapsed();
  LOG(DEBUG) << "CellDb migration: migrated=" << migrated << " checked=" << checked << " time=" << time;
  ++migration_stats_->batches_;
  migration_stats_->migrated_cells_ += migrated;
  migration_stats_->checked_cells_ += checked;
  migration_stats_->total_time_ += time;

  if (cells_to_migrate_.empty()) {
    migration_active_ = false;
  } else {
    delay_action([SelfId = actor_id(this)] { td::actor::send_closure(SelfId, &CellDbIn::migrate_cells); },
                 td::Timestamp::in(time * 2));
  }
}

void CellDb::prepare_stats(td::Promise<std::vector<std::pair<std::string, std::string>>> promise) {
  promise.set_value(decltype(prepared_stats_)(prepared_stats_));
}

void CellDb::update_stats(td::Result<std::vector<std::pair<std::string, std::string>>> r_stats) {
  if (r_stats.is_error()) {
    LOG(ERROR) << "error updating stats: " << r_stats.error();
  } else {
    prepared_stats_ = r_stats.move_as_ok();
    cell_db_statistics_.prepare_stats(prepared_stats_);
  }
  alarm_timestamp() = td::Timestamp::in(2.0);
}

void CellDb::flush_db_stats(std::string stats) {
  for (auto& [k, v] : cell_db_statistics_.prepare_stats()) {
    stats += PSTRING() << "tos.celldb." << k << " " << v << "\n";
  }
  cell_db_statistics_.clear();
  delay_action(
      [path = path_ + "/db_stats.txt", stats = std::move(stats)] {
        auto to_file_r = td::FileFd::open(path, td::FileFd::Truncate | td::FileFd::Create | td::FileFd::Write, 0644);
        if (to_file_r.is_error()) {
          LOG(ERROR) << "Failed to open db_stats.txt: " << to_file_r.move_as_error();
          return;
        }
        auto to_file = to_file_r.move_as_ok();
        auto res = to_file.write(stats);
        to_file.close();
        if (res.is_error()) {
          LOG(ERROR) << "Failed to write to db_stats.txt: " << res.move_as_error();
          return;
        }
        LOG(INFO) << "Written db_stats.txt";
      },
      td::Timestamp::now());
}

void CellDb::alarm() {
  send_closure(cell_db_, &CellDbIn::prepare_stats, td::promise_send_closure(actor_id(this), &CellDb::update_stats));
}

td::actor::Task<Ref<vm::DataCell>> CellDb::load_cell(RootHash hash) {
  if (thread_safe_boc_) {
    auto result = thread_safe_boc_->load_root_thread_safe(hash.as_slice());
    if (result.is_ok()) {
      ++cell_db_statistics_.queries_load_ok_immediate_;
      co_await td::actor::detach_from_actor();
      co_return result.move_as_ok();
    }
  }
  if (started_ && !thread_safe_boc_) {
    auto result = co_await boc_->load_cell_async(hash.as_slice(), async_executor).wrap();
    if (result.is_ok()) {
      ++cell_db_statistics_.queries_load_ok_immediate_;
      co_await td::actor::detach_from_actor();
      co_return result.move_as_ok();
    }
  }
  auto result = co_await ask(cell_db_, &CellDbIn::load_cell, hash).wrap();
  ++(result.is_ok() ? cell_db_statistics_.queries_load_ok_inner_ : cell_db_statistics_.queries_load_error_);
  co_await td::actor::detach_from_actor();
  co_return std::move(result);
}

td::actor::Task<Ref<vm::DataCell>> CellDb::store_cell(BlockIdExt block_id, Ref<vm::Cell> cell, vm::StoreCellHint hint) {
  auto result = co_await ask(cell_db_, &CellDbIn::store_cell, block_id, std::move(cell), std::move(hint)).wrap();
  ++(result.is_ok() ? cell_db_statistics_.queries_store_ok_ : cell_db_statistics_.queries_store_error_);
  co_await td::actor::detach_from_actor();
  co_return std::move(result);
}

td::actor::Task<Ref<vm::DataCell>> CellDb::store_block_state_permanent(Ref<BlockData> block) {
  auto result = co_await ask(cell_db_, &CellDbIn::store_block_state_permanent, std::move(block)).wrap();
  ++(result.is_ok() ? cell_db_statistics_.queries_store_ok_ : cell_db_statistics_.queries_store_error_);
  co_await td::actor::detach_from_actor();
  co_return std::move(result);
}

td::actor::Task<std::map<BlockIdExt, RootHash>> CellDb::store_block_state_permanent_bulk(
    std::vector<Ref<BlockData>> blocks) {
  auto result = co_await ask(cell_db_, &CellDbIn::store_block_state_permanent_bulk, std::move(blocks)).wrap();
  ++(result.is_ok() ? cell_db_statistics_.queries_store_ok_ : cell_db_statistics_.queries_store_error_);
  co_await td::actor::detach_from_actor();
  co_return std::move(result);
}

void CellDb::get_cell_db_reader(td::Promise<std::shared_ptr<vm::CellDbReader>> promise) {
  td::actor::send_closure(cell_db_, &CellDbIn::get_cell_db_reader, std::move(promise));
}

void CellDb::create_celldb_streaming_writer_unsafe_for_tests_only(
    td::Promise<std::unique_ptr<CellDbStreamingWriter>> promise) {
  // Test-only. Production state-sync uses
  // `import_persistent_state_streaming`. Cross-actor direct KV access
  // is unsafe; do not call from a production path (audit P1-5).
  //
  // Mirror of get_cell_db_reader: forward straight to the inner
  // CellDbIn actor and resolve the promise from there. The actual
  // single-import gating happens inside the writer's begin_batch()
  // (see `CellDbStreamingWriterImpl::begin_batch`).
  td::actor::send_closure(cell_db_, &CellDbIn::create_streaming_writer_unsafe_for_tests_only_async,
                          std::move(promise));
}

void CellDb::start_up() {
  CellDbBase::start_up();
  boc_ = vm::DynamicBagOfCellsDb::create();
  boc_->set_celldb_compress_depth(opts_->get_celldb_compress_depth());
  cell_db_ = td::actor::create_actor<CellDbIn>("celldbin", root_db_, actor_id(this), path_, opts_);
  on_load_callback_ = [actor = std::make_shared<td::actor::ActorOwn<CellDbIn::MigrationProxy>>(
                           td::actor::create_actor<CellDbIn::MigrationProxy>("celldbmigration", cell_db_.get())),
                       compress_depth = opts_->get_celldb_compress_depth()](const vm::CellLoader::LoadResult& res) {
    if (res.cell_.is_null()) {
      return;
    }
    bool expected_stored_boc = res.cell_->get_depth() == compress_depth && compress_depth != 0;
    if (expected_stored_boc != res.stored_boc_) {
      td::actor::send_closure(*actor, &CellDbIn::MigrationProxy::migrate_cell,
                              td::Bits256{res.cell_->get_hash().bits()});
    }
  };
}

CellDbIn::DbEntry::DbEntry(tl_object_ptr<tos_api::db_celldb_value> entry)
    : block_id(create_block_id(entry->block_id_))
    , prev(entry->prev_)
    , next(entry->next_)
    , root_hash(entry->root_hash_) {
}

td::BufferSlice CellDbIn::DbEntry::release() {
  return create_serialize_tl_object<tos_api::db_celldb_value>(create_tl_block_id(block_id), prev, next, root_hash);
}

std::vector<std::pair<std::string, std::string>> CellDbIn::CellDbStatistics::prepare_stats() {
  std::vector<std::pair<std::string, std::string>> stats;
  stats.emplace_back("permanent_mode", PSTRING() << permanent_mode_);
  stats.emplace_back("store_cell.micros", PSTRING() << store_cell_time_.to_string());
  stats.emplace_back("store_cell.prepare.micros", PSTRING() << store_cell_prepare_time_.to_string());
  stats.emplace_back("store_cell.write.micros", PSTRING() << store_cell_write_time_.to_string());
  if (permanent_mode_) {
    stats.emplace_back("store_cell.bulk.queries", PSTRING() << store_cell_bulk_queries_);
    stats.emplace_back("store_cell.bulk.total_blocks", PSTRING() << store_cell_bulk_total_blocks_);
  }
  stats.emplace_back("gc_cell.micros", PSTRING() << gc_cell_time_.to_string());
  stats.emplace_back("total_time.micros", PSTRING() << (td::Timestamp::now().at() - stats_start_time_.at()) * 1e6);
  stats.emplace_back("in_memory", PSTRING() << bool(in_memory_load_time_));
  if (in_memory_load_time_) {
    stats.emplace_back("in_memory_load_time", PSTRING() << in_memory_load_time_.value());
  }
  if (boc_stats_) {
    stats.emplace_back("cells_count", PSTRING() << boc_stats_->cells_total_count);
    stats.emplace_back("cells_size", PSTRING() << boc_stats_->cells_total_size);
    stats.emplace_back("roots_count", PSTRING() << boc_stats_->roots_total_count);
    for (auto& [key, value] : boc_stats_->custom_stats) {
      stats.emplace_back(key, value);
    }

    for (auto& [key, value] : boc_stats_->named_stats.stats_str) {
      stats.emplace_back(key, value);
    }
    for (auto& [key, value] : boc_stats_->named_stats.stats_int) {
      stats.emplace_back(key, td::to_string(value));
    }
  }
  return stats;
}

void CellDb::CellDbStatistics::prepare_stats(std::vector<std::pair<std::string, std::string>>& vec) const {
  vec.emplace_back("queries_load", PSTRING() << "ok_immediate : " << queries_load_ok_immediate_ << " ok_inner : "
                                             << queries_load_ok_inner_ << " error : " << queries_load_error_);
  vec.emplace_back("queries_store", PSTRING() << "ok : " << queries_store_ok_ << " error : " << queries_store_error_);
}

namespace {
// Concrete implementation of CellDbStreamingWriter. Holds a
// shared_ptr to the same vm::KeyValue (RocksDB) instance the rest of
// CellDbIn uses, so commits become visible to subsequent
// CellDbReader snapshots.
//
// Single-import gating: the writer also holds a shared_ptr to an
// atomic<bool> owned by CellDbIn. begin_batch() compare-exchanges
// false->true on the flag; if the CAS fails (another streaming
// importer is already mid-batch), begin_batch() returns an error and
// does NOT open a RocksDB write batch. commit_batch / abort_batch /
// dtor all clear the flag exactly once via `release_in_use_flag()`,
// so a second importer can start a fresh batch immediately after the
// first one finishes.
class CellDbStreamingWriterImpl final : public CellDbStreamingWriter {
 public:
  CellDbStreamingWriterImpl(std::shared_ptr<vm::KeyValue> kv,
                            std::shared_ptr<std::atomic<bool>> in_use_flag)
      : kv_(std::move(kv)), in_use_flag_(std::move(in_use_flag)) {
  }

  ~CellDbStreamingWriterImpl() override {
    // Best-effort: if the caller dropped us mid-batch, discard the
    // buffered writes so we do not leak a half-built RocksDB write
    // batch. Errors from abort_write_batch are intentionally ignored
    // here -- there is nothing useful the destructor can do with
    // them, and the import path will surface its own error via the
    // explicit abort_batch() call on the happy-error path.
    if (in_batch_) {
      auto status = kv_->abort_write_batch();
      LOG_IF(ERROR, status.is_error())
          << "CellDbStreamingWriter: abort_write_batch in destructor failed: " << status;
      in_batch_ = false;
    }
    // Always release the single-import gate when the writer is
    // dropped, even if we never reached begin_batch(). The CAS on
    // begin_batch() is the only path that flips holds_in_use_flag_
    // to true; if it failed (another importer is mid-batch) we leave
    // their flag alone.
    release_in_use_flag();
  }

  td::Status begin_batch() override {
    if (in_batch_) {
      return td::Status::Error("CellDbStreamingWriter::begin_batch: batch already open");
    }
    if (in_use_flag_) {
      bool expected = false;
      if (!in_use_flag_->compare_exchange_strong(expected, true, std::memory_order_acq_rel,
                                                 std::memory_order_acquire)) {
        return td::Status::Error(
            "CellDbStreamingWriter::begin_batch: another streaming import is in flight on this "
            "CellDb instance");
      }
      holds_in_use_flag_ = true;
    }
    auto status = kv_->begin_write_batch();
    if (status.is_error()) {
      // RocksDB refused to open the batch; release the gate so the
      // next importer can try again. Returning the error verbatim
      // preserves the original RocksDB diagnostic.
      release_in_use_flag();
      return status;
    }
    in_batch_ = true;
    return td::Status::OK();
  }

  td::Status store_cell(td::Slice hash, td::Slice serialized_cell_bytes) override {
    if (!in_batch_) {
      return td::Status::Error("CellDbStreamingWriter::store_cell: no open batch");
    }
    if (hash.size() != vm::Cell::hash_bytes) {
      return td::Status::Error(PSLICE() << "CellDbStreamingWriter::store_cell: hash size " << hash.size()
                                        << " != expected " << vm::Cell::hash_bytes);
    }
    if (serialized_cell_bytes.empty()) {
      return td::Status::Error("CellDbStreamingWriter::store_cell: empty serialized bytes");
    }
    vm::CellStorer storer{*kv_};
    return storer.store_cell_streaming(hash, serialized_cell_bytes);
  }

  td::Status store_cell(const td::Ref<vm::DataCell>& cell) override {
    if (!in_batch_) {
      return td::Status::Error("CellDbStreamingWriter::store_cell: no open batch");
    }
    if (cell.is_null()) {
      return td::Status::Error("CellDbStreamingWriter::store_cell: null cell");
    }
    vm::CellStorer storer{*kv_};
    return storer.store_cell_streaming(cell);
  }

  td::Status commit_batch() override {
    if (!in_batch_) {
      return td::Status::Error("CellDbStreamingWriter::commit_batch: no open batch");
    }
    auto status = kv_->commit_write_batch();
    in_batch_ = false;
    // Release the single-import gate regardless of the commit result:
    // a failed commit aborts the batch (the kv layer rolls it back),
    // and either way the writer is no longer holding the slot.
    release_in_use_flag();
    if (status.is_error()) {
      return status;
    }
    return td::Status::OK();
  }

  td::Status abort_batch() override {
    if (!in_batch_) {
      // Idempotent: aborting when no batch is open is a no-op rather
      // than an error so the sink's error-recovery path can call
      // abort_batch() unconditionally. Still release the gate so a
      // second importer can claim the slot even if the first never
      // wrote anything.
      release_in_use_flag();
      return td::Status::OK();
    }
    auto status = kv_->abort_write_batch();
    in_batch_ = false;
    release_in_use_flag();
    if (status.is_error()) {
      return status;
    }
    return td::Status::OK();
  }

 private:
  void release_in_use_flag() {
    if (holds_in_use_flag_ && in_use_flag_) {
      in_use_flag_->store(false, std::memory_order_release);
      holds_in_use_flag_ = false;
    }
  }

  std::shared_ptr<vm::KeyValue> kv_;
  std::shared_ptr<std::atomic<bool>> in_use_flag_;
  bool in_batch_ = false;
  bool holds_in_use_flag_ = false;
};
}  // namespace

std::unique_ptr<CellDbStreamingWriter> CellDbIn::create_streaming_writer() {
  CHECK(cell_db_ != nullptr);
  CHECK(streaming_writer_in_use_ != nullptr);
  return std::make_unique<CellDbStreamingWriterImpl>(cell_db_, streaming_writer_in_use_);
}

void CellDbIn::create_streaming_writer_unsafe_for_tests_only_async(
    td::Promise<std::unique_ptr<CellDbStreamingWriter>> promise) {
  // Test-only. Production state-sync uses
  // `import_persistent_state_streaming`. Cross-actor direct KV access
  // is unsafe; do not call from a production path (audit P1-5).
  //
  // Construction itself is cheap (just wraps shared_ptrs); the
  // single-import flag is enforced at begin_batch() time. Returning
  // the writer here lets the validator manager hand it back to the
  // downloader actor without a separate priming step.
  if (cell_db_ == nullptr) {
    promise.set_error(
        td::Status::Error("CellDbIn::create_streaming_writer_unsafe_for_tests_only_async: cell_db_ not initialized"));
    return;
  }
  promise.set_result(create_streaming_writer());
}

// tos27 P0-2: streaming-import worker job + slice-budget-aware sink.
//
// Design choice (Option B in the audit menu): the entire BoC parse +
// verify + commit pipeline runs on a dedicated `td::thread` worker
// OFF the CellDbIn actor. The CellDbIn message loop is NOT held for
// the parse — only for the small validation prologue (input checks,
// pause GC, allocate provider/sink, spawn worker) and the equally
// small completion epilogue (publish snapshot, resolve promise, join
// worker). Concurrent CellDb operations (`load_cell`, `store_cell`,
// `store_block_state_*`, GC, archive interactions) interleave freely
// while the worker streams the BoC into RocksDB.
//
// Why a worker thread instead of in-actor slicing: the existing
// `vm::std_boc_deserialize_from_file_bounded` is all-or-nothing —
// there is no native suspend/resume API. The pragmatic equivalent of
// "yield between cells" is moving the parse off the actor entirely;
// from CellDbIn's perspective the parse is then a SINGLE deferred
// completion message instead of a synchronously-blocking handler.
// The slice budget constants (`kMaxImportCellsPerSlice`,
// `kMaxImportSliceWallMs`) still apply: the worker's per-cell sink
// callback checks them and yields the OS scheduler slot when either
// is exceeded, so the worker cooperates with co-resident parse /
// verify / archive work even within its own thread.
//
// `streaming_writer_in_use_` continues to enforce the
// `kMaxConcurrentStreamingImports = 1` bound: the worker calls
// `sink.begin()` -> `writer->begin_batch()` which CAS-flips the flag.
// A second concurrent import attempt observes the flag set and the
// worker fails immediately with "another streaming import is in
// flight" before any cells are written. The flag is released on
// commit_batch / abort_batch / writer dtor, so a successful or
// failed import always frees the slot for the next one.
//
// Watchdog: every per-cell callback inside the slice-budget wrapper
// records the wall-time of the slowest slice. If that slice exceeds
// 10x the configured budget (50 ms vs 5 ms target) the worker emits a
// one-time LOG(WARNING) naming the cell index, purely diagnostic — no
// abort.
struct StreamingImportJob {
  // Inputs captured at spawn time (immutable while the worker runs).
  PersistentStateImportRequest request;
  td::Promise<PersistentStateImportResult> promise;
  std::shared_ptr<LiveCellDbReaderProvider> provider;
  vm::Cell::Hash expected_hash{};

  // Off-actor result fields. The worker writes these before posting
  // the completion message; the actor reads them after join. Using
  // plain members (not atomics) is safe because the actor's
  // continuation runs strictly AFTER the worker has finished
  // populating them — the send_closure -> message dispatch ordering
  // synchronizes the writes.
  td::Status worker_status = td::Status::OK();
  td::Ref<vm::Cell> hash_only_root;
  td::uint64 cells_persisted = 0;
  vm::Cell::Hash parsed_hash{};
  bool committed = false;

  // Watchdog observation: index of the slowest cell observed during
  // parse and the wall-time of that slice. Logged at completion if
  // the slice exceeded 10x the configured budget.
  td::uint64 slowest_slice_cell_index = 0;
  double slowest_slice_wall_ms = 0.0;
  bool slow_slice_warning_emitted = false;

  // Sink keepalive. The actor allocates the sink on the heap (so the
  // worker has a stable pointer) and parks a shared_ptr here so the
  // continuation can observe sink-level state (cells_persisted,
  // is_committed, aborted) AFTER the worker has joined. The same
  // shared_ptr is captured by the worker lambda; both copies go away
  // when continue_import_after_worker tears the job down.
  std::shared_ptr<fullnode::CellDbStreamingSink> sink_keepalive;

  // The worker thread itself. Joined by the actor on the completion
  // message before the StreamingImportJob is destroyed.
  td::thread worker;
};

namespace {

// Slice-budget-aware sink wrapper. Forwards every method to the
// inner CellDbStreamingSink (the production true-streaming sink) and,
// inside `persist_and_replace`, checks the cell-count and wall-clock
// slice budgets. When EITHER is exceeded the wrapper yields the OS
// scheduler slot via `td::this_thread::yield()` and resets the slice
// counters. This is the per-cell yield point the audit references.
class SlicedImportSink final : public vm::StreamingCellSink {
 public:
  SlicedImportSink(fullnode::CellDbStreamingSink* inner, StreamingImportJob* job)
      : inner_(inner), job_(job) {
    slice_started_at_ = td::Timestamp::now();
    slice_deadline_ = td::Timestamp::at(slice_started_at_.at() + kMaxImportSliceWallMs / 1000.0);
  }

  td::Status begin() override {
    return inner_->begin();
  }

  td::Status persist(td::Ref<vm::Cell> cell) override {
    auto status = inner_->persist(std::move(cell));
    after_cell();
    return status;
  }

  td::Result<td::Ref<vm::Cell>> persist_and_replace(td::Ref<vm::Cell> cell) override {
    auto r = inner_->persist_and_replace(std::move(cell));
    after_cell();
    return r;
  }

  td::Status finish(const vm::Cell::Hash& root_hash) override {
    return inner_->finish(root_hash);
  }

  td::Status commit_after_root_verified(const vm::Cell::Hash& expected_root_hash) override {
    return inner_->commit_after_root_verified(expected_root_hash);
  }

  void abort() override {
    inner_->abort();
  }

 private:
  // Per-cell budget check. Called after every persist / persist_and_replace
  // dispatched through the wrapper. When the cell-count or wall-clock
  // slice budget is exceeded we yield the OS scheduler slot and reset
  // the slice. The watchdog records the slice's wall-time if it
  // exceeds the configured budget so a stuck / slow parse is visible
  // to operators without aborting the import.
  void after_cell() {
    cells_in_slice_++;
    cells_total_++;
    // Wall-clock check first so a single very-slow cell still
    // surfaces a yield even if cells_in_slice_ is < kMaxImportCellsPerSlice.
    bool slice_full = cells_in_slice_ >= kMaxImportCellsPerSlice;
    bool deadline_passed = slice_deadline_.is_in_past();
    if (slice_full || deadline_passed) {
      auto slice_wall_ms = (td::Timestamp::now().at() - slice_started_at_.at()) * 1000.0;
      if (slice_wall_ms > job_->slowest_slice_wall_ms) {
        job_->slowest_slice_wall_ms = slice_wall_ms;
        job_->slowest_slice_cell_index = cells_total_;
      }
      // tos27 P0-2 watchdog: 10x slice budget. Diagnostic-only:
      // never abort, never block GC release. A single warning per
      // import is enough — the operator already gets the slowest
      // cell index in the completion log line.
      if (!job_->slow_slice_warning_emitted && slice_wall_ms > 10.0 * kMaxImportSliceWallMs) {
        job_->slow_slice_warning_emitted = true;
        LOG(WARNING) << "CellDbIn::import_persistent_state_streaming: slice exceeded 10x budget "
                     << "(" << slice_wall_ms << " ms vs " << kMaxImportSliceWallMs
                     << " ms target) at cell index " << cells_total_
                     << "; diagnostic only, parse continues";
      }
      // Yield the OS scheduler slot so co-resident threads (the
      // CellDbIn actor scheduler, validator-engine RPC threads,
      // archive workers) get a turn before the worker grabs another
      // chunk of CPU.
      td::this_thread::yield();
      cells_in_slice_ = 0;
      slice_started_at_ = td::Timestamp::now();
      slice_deadline_ = td::Timestamp::at(slice_started_at_.at() + kMaxImportSliceWallMs / 1000.0);
    }
  }

  fullnode::CellDbStreamingSink* inner_;
  StreamingImportJob* job_;
  td::uint32 cells_in_slice_ = 0;
  td::uint64 cells_total_ = 0;
  td::Timestamp slice_started_at_;
  td::Timestamp slice_deadline_;
};

// Pure off-actor work: open the tempfile, drive the BoC importer
// through the SlicedImportSink, run finish + commit_after_root_verified.
// Writes the result fields into `job` and returns. Called on the
// worker thread; never touches CellDbIn / CellDb actor state directly.
//
// Failure modes (each writes job->worker_status with the error and
// returns; the actor's continuation runs sink.abort() if needed):
//   * tempfile open failure
//   * importer rejection (header / scaffolding / persist error)
//   * null root from importer
//   * sink.finished() == false on success path (programming bug)
//   * parsed-root hash != expected_root_hash
//   * commit_after_root_verified failure
void run_streaming_import_worker(StreamingImportJob* job, fullnode::CellDbStreamingSink* sink) {
  auto r_fd = td::FileFd::open(job->request.tempfile_path, td::FileFd::Flags::Read);
  if (r_fd.is_error()) {
    sink->abort();
    job->worker_status = r_fd.move_as_error();
    return;
  }
  auto fd = r_fd.move_as_ok();

  // Slice-budget-aware sink wrapper. Forwards every cell through to
  // the production sink and yields the OS scheduler between slices
  // bounded by `kMaxImportCellsPerSlice` cells / `kMaxImportSliceWallMs` ms.
  SlicedImportSink sliced_sink(sink, job);

  auto r_root = vm::std_boc_deserialize_from_file_bounded(fd, job->request.file_size, job->request.opts, &sliced_sink);
  fd.close();
  if (r_root.is_error()) {
    if (!sink->aborted() && !sink->is_committed()) {
      sink->abort();
    }
    LOG(WARNING) << "CellDbIn::import_persistent_state_streaming: importer rejected after "
                 << sink->cells_persisted() << " cell(s): " << r_root.error();
    job->worker_status = r_root.move_as_error();
    return;
  }
  auto root = r_root.move_as_ok();
  if (root.is_null()) {
    if (!sink->aborted() && !sink->is_committed()) {
      sink->abort();
    }
    job->worker_status = td::Status::Error(
        "CellDbIn::import_persistent_state_streaming: BoC deserialize returned null root");
    return;
  }
  if (!sink->finished()) {
    sink->abort();
    job->worker_status = td::Status::Error(
        "CellDbIn::import_persistent_state_streaming: sink finished=false on success path");
    return;
  }

  // Verify parsed root against the BFT-attested expected root BEFORE
  // committing. On mismatch, abort discards the pending RocksDB batch
  // so CellDb stays byte-for-byte identical to its pre-import snapshot.
  const auto parsed_hash = root->get_hash();
  if (RootHash{parsed_hash.bits()} != job->request.expected_root_hash) {
    sink->abort();
    job->worker_status = td::Status::Error(
        PSTRING() << "CellDbIn::import_persistent_state_streaming: root hash mismatch: expected "
                  << job->request.expected_root_hash.to_hex() << " got "
                  << RootHash{parsed_hash.bits()}.to_hex());
    return;
  }

  // Verified — commit. commit_after_root_verified flushes the writer's
  // pending batch and is the single point at which cells become durable.
  if (auto status = sink->commit_after_root_verified(parsed_hash); status.is_error()) {
    sink->abort();
    job->worker_status = status.move_as_error();
    return;
  }

  // Success: stash the result fields for the actor's continuation.
  job->hash_only_root = std::move(root);
  job->cells_persisted = sink->cells_persisted();
  job->parsed_hash = parsed_hash;
  job->committed = true;
  job->worker_status = td::Status::OK();
}

}  // namespace

// tos26 P1-4 + tos27 P0-2: actor entry point. Validates inputs, pauses
// GC, builds the provider + sink, and spawns the worker thread that
// runs the actual BoC parse OFF the CellDbIn actor's message loop.
// The CellDbIn actor is held only for this small prologue; the parse
// runs concurrently with all other CellDb operations.
//
// Lifecycle:
//   1. Reject zero-size or empty-path requests up front.
//   2. Construct an internal writer (shares this CellDbIn's KeyValue +
//      single-import gate). The writer NEVER escapes this actor.
//   3. Build a LiveCellDbReaderProvider seeded with the current
//      pre-commit reader. Lazy ExtCells produced during parse bind
//      to this provider; after commit the actor publishes a fresh
//      post-commit reader on the same provider.
//   4. Construct a CellDbStreamingSink wrapping (provider, writer);
//      the sink owns the writer's begin/store/commit/abort vtable
//      via type-erased std::function members.
//   5. Allocate a StreamingImportJob and spawn a `td::thread` worker
//      that runs `run_streaming_import_worker(job, sink)`. The worker
//      drives the entire parse + verify + commit pipeline off-actor.
//   6. The worker's last action is `send_closure(self, &continue_import_after_worker)`
//      which queues a single message into the actor's mailbox.
//   7. `continue_import_after_worker` runs on the actor's loop, joins
//      the worker thread, publishes the post-commit snapshot, and
//      resolves the original promise.
//
// Failures BEFORE worker spawn (input validation, writer creation)
// resolve the promise and resume GC immediately. Failures during the
// worker's parse are surfaced via `job->worker_status` and resolved
// in the continuation; the GC pause is released through the same
// abort-or-lease handshake the in-actor version used.
void CellDbIn::import_persistent_state_streaming(PersistentStateImportRequest request,
                                                 td::Promise<PersistentStateImportResult> promise) {
  // Defer to the action queue if a snapshot/store/gc operation is
  // currently using the DB; this preserves CellDbIn's existing
  // serialization contract end-to-end. The streaming-import path
  // does not flip db_busy_ itself — its contended resource is
  // streaming_writer_in_use_, which the writer's begin_batch CAS
  // owns.
  if (db_busy_) {
    action_queue_.push_back([self = this, request = std::move(request),
                             promise = std::move(promise)](td::Result<td::Unit> R) mutable {
      R.ensure();
      self->import_persistent_state_streaming(std::move(request), std::move(promise));
    });
    return;
  }

  if (request.tempfile_path.empty() || request.file_size == 0) {
    promise.set_error(
        td::Status::Error("CellDbIn::import_persistent_state_streaming: empty tempfile path or zero size"));
    return;
  }
  if (cell_db_ == nullptr || boc_ == nullptr) {
    promise.set_error(td::Status::Error("CellDbIn::import_persistent_state_streaming: cell_db not initialized"));
    return;
  }
  // tos27 P0-2: kMaxConcurrentStreamingImports = 1 is structurally
  // enforced by the streaming_writer_in_use_ flag inside the writer's
  // begin_batch CAS. We also early-reject here so two
  // back-to-back actor messages don't queue two worker threads
  // racing on the same gate (the second would just fail at begin_batch
  // anyway, but failing fast is cleaner than waiting on a doomed worker).
  if (streaming_job_ != nullptr) {
    promise.set_error(td::Status::Error(
        "CellDbIn::import_persistent_state_streaming: another streaming import is already in flight on this CellDbIn"));
    return;
  }

  // Construct an actor-local writer. The writer's gate CAS in
  // begin_batch() rejects a concurrent import; if it fails the sink
  // surfaces the error on the very first persist/begin invocation
  // and the worker aborts cleanly.
  std::unique_ptr<CellDbStreamingWriter> writer = create_streaming_writer();
  if (writer == nullptr) {
    promise.set_error(td::Status::Error("CellDbIn::import_persistent_state_streaming: failed to create writer"));
    return;
  }

  // tos26 P1-5: pause GC for the duration of this import. The matching
  // resume runs on every exit path: success delays the resume long
  // enough for the downloader's follow-up set_block_state to commit a
  // desc-list entry that references the imported cells (via the GC
  // lease), while every failure path resumes immediately in the
  // continuation (no cells durable on a failed import).
  pause_gc_for_import();

  // Build a LiveCellDbReaderProvider seeded with the current reader.
  // The lazy ExtCells emitted during parse capture this provider; we
  // republish a fresh post-commit reader on the same provider after
  // commit so they observe the just-flushed cells.
  auto initial_reader = boc_->get_cell_db_reader();
  auto provider = std::make_shared<LiveCellDbReaderProvider>(initial_reader);

  // Construct the sink. The (provider, writer) constructor template
  // is instantiated here; the writer's complete type is visible via
  // celldb.hpp. We allocate the sink on the heap so the worker thread
  // can hold a stable pointer to it.
  auto sink = std::make_unique<fullnode::CellDbStreamingSink>(
      std::shared_ptr<vm::CellDbReaderProvider>(provider), std::move(writer));
  if (!sink->is_true_streaming()) {
    // Defense in depth: provider+writer are both non-null above, so
    // a non-true-streaming sink here is a programming bug.
    resume_gc_for_import();
    promise.set_error(
        td::Status::Error("CellDbIn::import_persistent_state_streaming: sink failed to enter true-streaming mode"));
    return;
  }

  // Spawn the worker thread. The job owns the request, promise,
  // provider, and worker thread; we hand the sink over via raw
  // pointer because the sink's lifetime is tied to the job (we move
  // it into a shared_ptr inside the lambda for clean teardown).
  streaming_job_ = std::make_unique<StreamingImportJob>();
  streaming_job_->request = std::move(request);
  streaming_job_->promise = std::move(promise);
  streaming_job_->provider = std::move(provider);
  streaming_job_->expected_hash = vm::Cell::Hash{};  // populated post-parse

  // Park the sink in a shared_ptr held by both the job (for the
  // continuation to observe final state) and the worker lambda (for
  // the parse). The shared_ptr keeps the sink alive across the
  // worker -> continuation handoff; the sink's destructor releases
  // the writer + RocksDB batch when both copies go away in
  // continue_import_after_worker.
  auto shared_sink = std::shared_ptr<fullnode::CellDbStreamingSink>(std::move(sink));
  streaming_job_->sink_keepalive = shared_sink;

  // Spawn the off-actor worker. The CellDbIn actor's message loop is
  // free to interleave any other operation while the worker runs.
  auto* job_ptr = streaming_job_.get();
  auto self_actor = actor_id(this);
  streaming_job_->worker = td::thread([job_ptr, sink_keepalive = std::move(shared_sink), self_actor]() mutable {
    // The worker drives the entire begin / parse / verify / commit
    // pipeline against `sink_keepalive`. On any error path the
    // worker calls sink->abort() before stashing worker_status; the
    // continuation only needs to handle resume_gc + promise.set_*.
    run_streaming_import_worker(job_ptr, sink_keepalive.get());
    // Post a single completion message back to the actor. The
    // continuation will join this thread and tear down the job.
    td::actor::send_closure(self_actor, &CellDbIn::continue_import_after_worker);
  });
}

// tos27 P0-2: completion message posted by the worker thread.
// Runs on the CellDbIn actor's serialized loop; joins the worker,
// publishes the post-commit snapshot, resolves the import promise,
// and tears down the job.
//
// The worker thread has already populated `streaming_job_->worker_status`
// and (on success) `hash_only_root`, `cells_persisted`, `parsed_hash`,
// `committed`. We read those without synchronization because the
// actor message dispatch happens-after the worker's last write to
// these fields (the worker's final action is `send_closure` which
// crosses the synchronization barrier).
void CellDbIn::continue_import_after_worker() {
  if (streaming_job_ == nullptr) {
    LOG(ERROR) << "CellDbIn::continue_import_after_worker: no streaming job in flight; "
                  "spurious continuation message?";
    return;
  }

  // Take ownership of the job for the duration of this method. After
  // this swap a fresh import_persistent_state_streaming call observes
  // streaming_job_ == nullptr and is permitted to proceed.
  auto job = std::move(streaming_job_);
  streaming_job_.reset();

  // Join the worker thread. The worker's final action was
  // send_closure to this method, so the thread is done with all its
  // observable side-effects and we can join without blocking on
  // useful work. td::thread::join() is safe to call on an
  // already-joined / uninitialized thread (no-ops).
  job->worker.join();

  // Failure path: worker reported an error. The sink has already been
  // aborted by the worker (run_streaming_import_worker calls abort()
  // on every error path before stashing the status). Resume GC and
  // surface the error; no cells are durable.
  if (job->worker_status.is_error()) {
    resume_gc_for_import();
    job->promise.set_error(job->worker_status.move_as_error());
    return;
  }

  // Success path: cells are durable; provider's reader is still the
  // pre-commit one. Refresh it.
  //
  // Republish a fresh reader on the provider so lazy ExtCells minted
  // during parse pick up a reader that observes the just-flushed cells.
  // Also rebuild the loader and propagate a fresh snapshot to the
  // parent CellDb so subsequent get_cell_db_reader / load_cell calls
  // see the new state — same handshake that store_cell / gc_cont2 do
  // after their commit.
  if (!opts_->get_celldb_in_memory()) {
    boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();
    td::actor::send_closure(parent_, &CellDb::update_snapshot, cell_db_->snapshot());
  }
  auto post_commit_reader = boc_->get_cell_db_reader();
  if (post_commit_reader != nullptr) {
    job->provider->publish(post_commit_reader);
  }

  PersistentStateImportResult result;
  result.hash_only_root = std::move(job->hash_only_root);
  result.cells_persisted = job->cells_persisted;
  result.parsed_root_hash = job->parsed_hash;
  LOG(INFO) << "CellDbIn::import_persistent_state_streaming: committed " << result.cells_persisted
            << " cell(s); root=" << job->request.expected_root_hash.to_hex()
            << " (lazy ExtCell-backed; child DAG durable in CellDb"
            << "; slowest_slice=" << job->slowest_slice_wall_ms << "ms"
            << " at cell #" << job->slowest_slice_cell_index << ")";

  // tos27 P0-1: success path. The imported cells are now durable in
  // CellDb with refcnt=1, but they are not yet referenced by any
  // canonical block-state desc-list entry — the downloader actor will
  // drive set_block_state -> CellDb::store_cell next, which triggers
  // boc_->inc(root) + prepare_commit's DAG walk
  // (DynamicBagOfCellsDb::dfs_new_cells_in_db) and reconciles the
  // descendant refcounts under the canonical desc list.
  //
  // We issue a CellDbGcPauseLease into the result: the downloader
  // holds the lease across the create_shard_state -> set_block_state
  // pipeline and releases it on the set_block_state callback. A
  // canceled / dropped completion promise still releases GC via the
  // lease destructor.
  result.gc_lease = std::make_unique<CellDbGcPauseLease>(actor_id(this));

  // Watchdog: log-only; never resumes GC. If the lease has not been
  // released after 5 minutes the lease is likely stuck (downloader
  // actor leaked, root-store hung) and an operator should investigate.
  // Resume is bound exclusively to the lease destructor /
  // release_after_root_store_committed path so a long-running root
  // store cannot let GC mis-collect imported cells.
  delay_action(
      [SelfId = actor_id(this), block_seqno = job->request.expected_root_hash.to_hex()] {
        LOG(WARNING) << "CellDbIn::import_persistent_state_streaming: GC has been paused >5min "
                        "since import for root="
                     << block_seqno
                     << "; lease may be stuck (root-store hang or leaked downloader actor). "
                        "GC will resume when the lease is released; this watchdog only logs.";
        (void)SelfId;
      },
      td::Timestamp::in(300.0));

  job->promise.set_result(std::move(result));
  // Job (incl. sink_keepalive shared_ptr) torn down at scope exit. The
  // sink's destructor releases the writer + RocksDB handle.
}

void CellDb::import_persistent_state_streaming(PersistentStateImportRequest request,
                                               td::Promise<PersistentStateImportResult> promise) {
  // Forward to the inner CellDbIn actor; the entire import lifecycle
  // runs inside CellDbIn's serialized loop.
  td::actor::send_closure(cell_db_, &CellDbIn::import_persistent_state_streaming, std::move(request),
                          std::move(promise));
}

}  // namespace validator

}  // namespace tos
