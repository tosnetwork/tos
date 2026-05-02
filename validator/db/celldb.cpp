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
#include "td/utils/PathView.h"
#include "td/utils/Random.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/path.h"
#include "vm/boc.h"
#include "vm/cells/DataCell.h"
#include "vm/db/CellDbExtCell.h"
#include "vm/db/CellStorage.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <set>
#include <vector>

namespace tos {

namespace validator {

// tos27 P0-1 / tos30: CellDbGcPauseLease — RAII handle that releases an
// outstanding `pause_gc_for_import()` exactly once and, when dropped
// before root-store completion, asks CellDbIn to rollback newly-created
// streaming-import cells from a manifest. Move-only.
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

CellDbGcPauseLease::CellDbGcPauseLease(td::actor::ActorId<CellDbIn> db, std::string rollback_manifest_path,
                                       td::uint64 rollback_cells, td::uint64 rollback_bytes) noexcept
    : db_(std::move(db))
    , rollback_manifest_path_(std::move(rollback_manifest_path))
    , rollback_cells_(rollback_cells)
    , rollback_bytes_(rollback_bytes) {
}

CellDbGcPauseLease::CellDbGcPauseLease(CellDbGcPauseLease&& other) noexcept : db_(std::move(other.db_)) {
  rollback_manifest_path_ = std::move(other.rollback_manifest_path_);
  rollback_cells_ = other.rollback_cells_;
  rollback_bytes_ = other.rollback_bytes_;
  other.db_ = {};  // invalidate the moved-from lease so its dtor is a no-op
  other.rollback_manifest_path_.clear();
  other.rollback_cells_ = 0;
  other.rollback_bytes_ = 0;
}

CellDbGcPauseLease& CellDbGcPauseLease::operator=(CellDbGcPauseLease&& other) noexcept {
  if (this != &other) {
    // Release or rollback any pause we currently hold before adopting
    // the new one. Assignment is semantically equivalent to dropping
    // the previous lease.
    drop_uncommitted();
    db_ = std::move(other.db_);
    rollback_manifest_path_ = std::move(other.rollback_manifest_path_);
    rollback_cells_ = other.rollback_cells_;
    rollback_bytes_ = other.rollback_bytes_;
    other.db_ = {};
    other.rollback_manifest_path_.clear();
    other.rollback_cells_ = 0;
    other.rollback_bytes_ = 0;
  }
  return *this;
}

CellDbGcPauseLease::~CellDbGcPauseLease() {
  drop_uncommitted();
}

void CellDbGcPauseLease::drop_uncommitted() noexcept {
  if (!db_.empty()) {
    // Best-effort release. If a rollback manifest exists, CellDbIn will
    // erase only cells whose current serialized bytes still match the
    // imported refcnt=1 value, then resume GC. Without a manifest this
    // degenerates to the original resume-only lease.
    if (!rollback_manifest_path_.empty() && rollback_cells_ > 0) {
      td::actor::send_closure(db_, &CellDbIn::rollback_streaming_import_manifest,
                              std::move(rollback_manifest_path_), rollback_cells_, rollback_bytes_,
                              std::string{"streaming import lease dropped before root-store commit"},
                              /*resume_gc_after=*/true);
    } else {
      td::actor::send_closure(db_, &CellDbIn::resume_gc_for_import);
      clear_rollback_manifest();
    }
    db_ = {};
  }
}

void CellDbGcPauseLease::release_after_root_store_committed() noexcept {
  if (!db_.empty()) {
    td::actor::send_closure(db_, &CellDbIn::release_streaming_import_after_root_store_committed,
                            std::move(rollback_manifest_path_), rollback_cells_, rollback_bytes_);
    rollback_manifest_path_.clear();
    rollback_cells_ = 0;
    rollback_bytes_ = 0;
    db_ = {};
  }
}

void CellDbGcPauseLease::clear_rollback_manifest() noexcept {
  if (!rollback_manifest_path_.empty()) {
    auto status = td::unlink(rollback_manifest_path_);
    LOG_IF(WARNING, status.is_error()) << "failed to unlink committed streaming-import rollback manifest "
                                       << rollback_manifest_path_ << ": " << status;
    rollback_manifest_path_.clear();
  }
  rollback_cells_ = 0;
  rollback_bytes_ = 0;
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
    CHECK(merge_in.existing_value);  // CELDB_LEGACY_FATAL_INVARIANT: RocksDB merge operator provides existing value.
    auto& value = *merge_in.existing_value;
    CHECK(merge_in.operand_list.size() >= 1);  // CELDB_LEGACY_FATAL_INVARIANT: RocksDB never calls merge with no operands.
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
    obj.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: startup validates local CellDb metadata before serving peers.
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
        cell_db_->begin_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: disabled local startup repair path.
        boc_->dec(root);
        boc_->commit(stor).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: disabled local startup repair path.
        cell_db_->commit_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: disabled local startup repair path.
        if (!opts_->get_celldb_in_memory()) {
          boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: disabled local startup repair path.
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
    auto read_cell_db =
        std::make_shared<td::RocksDb>(td::RocksDb::open(path_, std::move(read_db_options)).move_as_ok());
    cell_db_ = read_cell_db;
    auto recovered_manifests = recover_streaming_import_rollbacks_at_startup();
    if (recovered_manifests.is_error()) {
      LOG(FATAL) << "CellDb streaming import rollback recovery failed before in-memory load: "
                 << recovered_manifests.move_as_error();
    }
    td::Timer timer;
    boc_ = vm::DynamicBagOfCellsDb::create_in_memory(read_cell_db.get(), *boc_in_memory_options);
    in_memory_load_time_ = timer.elapsed();
    // Drop the recovery handle before opening the write-only RocksDB
    // instance below; the in-memory BoC has already loaded its snapshot.
    cell_db_.reset();

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
    boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: startup must fail fast if local CellDb loader cannot initialize.
    auto recovered_manifests = recover_streaming_import_rollbacks_at_startup();
    if (recovered_manifests.is_error()) {
      LOG(FATAL) << "CellDb streaming import rollback recovery failed before metadata validation: "
                 << recovered_manifests.move_as_error();
    }
    if (recovered_manifests.ok() > 0) {
      boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: startup rollback replay requires a fresh local snapshot.
    }
  }

  validate_meta();

  alarm_timestamp() = td::Timestamp::in(10.0);

  auto empty = get_empty_key_hash();
  if (get_block(empty).is_error()) {
    DbEntry e{get_empty_key(), empty, empty, RootHash::zero()};
    vm::CellStorer stor{*cell_db_};
    cell_db_->begin_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: startup bootstrap of the local empty root.
    set_block(empty, std::move(e));
    boc_->commit(stor);
    cell_db_->commit_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: startup bootstrap of the local empty root.
    if (!opts_->get_celldb_in_memory()) {
      boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: startup bootstrap snapshot refresh.
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
    R.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: startup reads local CellDb metadata stats.
    if (R.ok() == td::KeyValue::GetStatus::Ok) {
      auto r_value = td::to_integer_safe<BlockSeqno>(value);
      r_value.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: malformed local CellDb stats metadata is fatal at startup.
      last_deleted_mc_state_ = r_value.move_as_ok();
    }
  }
  {
    std::string key = "opts.permanent_mode", value;
    auto R = boc_->meta_get(td::as_slice(key), value);
    R.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: startup reads local permanent-mode metadata.
    bool stored_permanent_mode = R.ok() == td::KeyValue::GetStatus::Ok;
    if (stored_permanent_mode) {
      LOG_CHECK(opts_->get_permanent_celldb()) << "permanent_celldb cannot be turned off";
    }
    permanent_mode_ = stored_permanent_mode || opts_->get_permanent_celldb();
    if (permanent_mode_) {
      LOG(WARNING) << "Celldb is in permanent mode";
      if (!stored_permanent_mode) {
        cell_db_->begin_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: startup persists local permanent-mode metadata.
        value = "1";
        vm::CellStorer stor{*cell_db_};
        boc_->meta_set(td::as_slice(key), td::as_slice(value));
        boc_->commit(stor).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: startup persists local permanent-mode metadata.
        cell_db_->commit_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: startup persists local permanent-mode metadata.
        if (!opts_->get_celldb_in_memory()) {
          boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: startup permanent-mode snapshot refresh.
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
      R.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: queued load resumes only after actor-local DB mutation completion.
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
      R.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: queued store resumes only after actor-local DB mutation completion.
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
        Res.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: legacy non-streaming store prepare failure is local DB fatal.
        timer_prepare.pause();
        td::actor::send_lambda_later(SelfId, [=, this, timer = std::move(timer), promise = std::move(promise),
                                              cell = std::move(cell)]() mutable {
          TD_PERF_COUNTER(celldb_store_cell);
          auto empty = get_empty_key_hash();
          auto ER = get_block(empty);
          ER.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: local CellDb linked-list sentinel must exist during store.
          auto E = ER.move_as_ok();

          auto PR = get_block(E.prev);
          PR.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: local CellDb linked-list predecessor must exist during store.
          auto P = PR.move_as_ok();
          CHECK(P.next == empty);  // CELDB_LEGACY_FATAL_INVARIANT: local CellDb linked-list tail invariant.

          DbEntry D{block_id, E.prev, empty, cell->get_hash().bits()};

          E.prev = key_hash;
          P.next = key_hash;

          if (P.is_empty()) {
            E.next = key_hash;
            P.prev = key_hash;
          }
          td::Timer timer_write;
          vm::CellStorer stor{*cell_db_};
          cell_db_->begin_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: legacy non-streaming store writes actor-local batch.
          set_block(get_empty_key_hash(), std::move(E));
          set_block(D.prev, std::move(P));
          set_block(key_hash, std::move(D));
          boc_->commit(stor).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: legacy non-streaming store commits local BoC metadata.
          cell_db_->commit_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: legacy non-streaming store commits local batch.
          timer_write.pause();

          if (!opts_->get_celldb_in_memory()) {
            boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: legacy non-streaming store snapshot refresh.
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
      R.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: queued reader request resumes only after actor-local DB mutation completion.
      self->get_cell_db_reader(std::move(promise));
    });
    return;
  }
  promise.set_result(boc_->get_cell_db_reader());
}

td::Status CellDbIn::refresh_loader_after_celldb_mutation(td::Slice context) {
  if (opts_->get_celldb_in_memory()) {
    return td::Status::OK();
  }
  auto status = boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_));
  if (status.is_error()) {
    return status.move_as_error_prefix(PSLICE() << "CellDbIn::" << context
                                                << ": failed to refresh CellDb loader after CellDb mutation: ");
  }
  td::actor::send_closure(parent_, &CellDb::update_snapshot, cell_db_->snapshot());
  return td::Status::OK();
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
          R.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: queued permanent store resumes only after actor-local DB mutation completion.
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
          R.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: queued permanent bulk store resumes only after actor-local DB mutation completion.
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
              cell_db_->begin_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: permanent bulk store writes actor-local batch.

              std::map<BlockIdExt, RootHash> state_root_hashes;
              for (auto& update : updates) {
                state_root_hashes[update.block_id] = update.state_root_hash;
                for (auto& [k, v] : update.to_store) {
                  cell_db_->set(k.as_slice(), v).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: permanent bulk cell value write is local DB fatal.
                }
              }

              CHECK(!updates.empty());  // CELDB_LEGACY_FATAL_INVARIANT: permanent bulk path returns only non-empty updates.
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

              boc_->commit(stor).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: permanent bulk store commits local BoC metadata.
              cell_db_->commit_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: permanent bulk store commits local batch.
              timer_write.pause();

              if (!opts_->get_celldb_in_memory()) {
                boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: permanent bulk store snapshot refresh.
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
  stats.emplace_back("streaming_import.inflight", PSTRING() << (streaming_job_ != nullptr));
  stats.emplace_back("streaming_import.rollback_queue_size", PSTRING() << streaming_rollback_jobs_.size());
  stats.emplace_back("streaming_import.gc_pause_count", PSTRING() << gc_pause_count_);

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
      R.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: stats flush is actor-local maintenance after DB mutation completion.
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
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), block_id](td::Result<BlockHandle> R) {
    td::actor::send_closure(SelfId, &CellDbIn::gc_cont, block_id, std::move(R));
  });
  td::actor::send_closure(root_db_, &RootDb::get_block_handle_external, block_id, false, std::move(P));
}

void CellDbIn::gc_cont(BlockIdExt block_id, td::Result<BlockHandle> R) {
  if (R.is_ok()) {
    auto handle = R.move_as_ok();
    if (!handle->inited_state_boc()) {
      LOG(WARNING) << "inited_state_boc=false, but state in db. blockid=" << block_id.to_str();
    }
    handle->set_deleted_state_boc();
    td::actor::send_closure(root_db_, &RootDb::store_block_handle, handle,
                            [SelfId = actor_id(this), block_id](td::Result<td::Unit> R2) {
                              R2.ensure();
                              td::actor::send_closure(SelfId, &CellDbIn::gc_cont2, block_id);
                            });
  } else {
    LOG(WARNING) << "handle not found, but state in db. blockid=" << block_id.to_str();
    gc_cont2(block_id);
  }
}

void CellDbIn::gc_cont2(BlockIdExt block_id) {
  if (db_busy_) {
    action_queue_.push_back([self = this, block_id](td::Result<td::Unit> R) mutable {
      R.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: queued GC resumes only after actor-local DB mutation completion.
      self->gc_cont2(block_id);
    });
    return;
  }
  CHECK(!permanent_mode_);  // CELDB_LEGACY_FATAL_INVARIANT: GC is disabled for permanent CellDb mode.

  td::PerfWarningTimer timer{"gccell", 0.1};
  td::PerfWarningTimer timer_all{"gccell_all", 0.05};

  td::PerfWarningTimer timer_get_keys{"gccell_get_keys", 0.05};
  auto key_hash = get_key_hash(block_id);
  auto FR = get_block(key_hash);
  FR.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: GC target must exist in local CellDb metadata.
  auto F = FR.move_as_ok();

  auto PR = get_block(F.prev);
  PR.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: GC predecessor must exist in local CellDb metadata.
  auto P = PR.move_as_ok();
  auto NR = get_block(F.next);
  NR.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: GC successor must exist in local CellDb metadata.
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
       block_id](td::Result<td::Unit> R) mutable {
        R.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: legacy GC prepare failure is local DB fatal.
        td::actor::send_lambda_later(
            SelfId,
            [this, timer_boc = std::move(timer_boc), F = std::move(F), key_hash, P = std::move(P), N = std::move(N),
             cell = std::move(cell), timer = std::move(timer), timer_all = std::move(timer_all), block_id]() mutable {
              TD_PERF_COUNTER(celldb_gc_cell);
              vm::CellStorer stor{*cell_db_};
              timer_boc.reset();

              td::PerfWarningTimer timer_write_batch{"gccell_write_batch", 0.05};
              cell_db_->begin_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: legacy GC writes actor-local batch.

              boc_->meta_erase(get_key(key_hash)).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: legacy GC erases local metadata.
              set_block(F.prev, std::move(P));
              set_block(F.next, std::move(N));
              if (block_id.is_masterchain()) {
                last_deleted_mc_state_ = block_id.seqno();
                std::string key = "stats.last_deleted_mc_seqno", value = td::to_string(last_deleted_mc_state_);
                boc_->meta_set(td::as_slice(key), td::as_slice(value));
              }

              boc_->commit(stor).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: legacy GC commits local BoC metadata.
              cell_db_->commit_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: legacy GC commits local batch.

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
                boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: legacy GC snapshot refresh.
                td::actor::send_closure(parent_, &CellDb::update_snapshot, cell_db_->snapshot());
              }

              DCHECK(get_block(key_hash).is_error());
              if (!opts_->get_disable_rocksdb_stats()) {
                cell_db_statistics_.gc_cell_time_.insert(timer.elapsed() * 1e6);
              }
              LOG(DEBUG) << "Deleted state " << block_id.to_str();
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
  R.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: local CellDb metadata read failed.
  auto S = R.move_as_ok();
  if (S == td::KeyValue::GetStatus::NotFound) {
    return td::Status::Error(ErrorCode::notready, "not in db");
  }
  auto obj = fetch_tl_object<tos_api::db_celldb_value>(td::BufferSlice{value}, true);
  obj.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: local CellDb metadata record is malformed.
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
      R.ensure();  // CELDB_LEGACY_FATAL_INVARIANT: queued migration resumes only after actor-local DB mutation completion.
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
  boc_->set_loader(std::make_unique<vm::CellLoader>(*loader)).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: local migration installs a private snapshot loader.
  cell_db_->begin_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: local migration writes actor-local batch.
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
      stor.set(R.ok().refcnt(), R.ok().cell_, expected_stored_boc).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: local migration rewrites cell storage format.
    }
  }
  cell_db_->commit_write_batch().ensure();  // CELDB_LEGACY_FATAL_INVARIANT: local migration commits actor-local batch.
  boc_->set_loader(std::make_unique<vm::CellLoader>(cell_db_->snapshot(), on_load_callback_)).ensure();  // CELDB_LEGACY_FATAL_INVARIANT: local migration restores the shared snapshot loader.
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
  stats.emplace_back("streaming_import.started", PSTRING() << streaming_import_started_);
  stats.emplace_back("streaming_import.committed", PSTRING() << streaming_import_committed_);
  stats.emplace_back("streaming_import.failed", PSTRING() << streaming_import_failed_);
  stats.emplace_back("streaming_import.cells_committed", PSTRING() << streaming_import_cells_committed_);
  stats.emplace_back("streaming_import.actor_batches", PSTRING() << streaming_import_actor_batches_);
  stats.emplace_back("streaming_import.rollback.jobs_started", PSTRING() << streaming_import_rollback_jobs_started_);
  stats.emplace_back("streaming_import.rollback.jobs_finished", PSTRING() << streaming_import_rollback_jobs_finished_);
  stats.emplace_back("streaming_import.rollback.cells_processed",
                     PSTRING() << streaming_import_rollback_cells_processed_);
  stats.emplace_back("streaming_import.rollback.cells_erased", PSTRING() << streaming_import_rollback_cells_erased_);
  stats.emplace_back("streaming_import.startup_rollback.manifests",
                     PSTRING() << streaming_import_startup_rollback_manifests_);
  stats.emplace_back("streaming_import.startup_rollback.cells_erased",
                     PSTRING() << streaming_import_startup_rollback_cells_erased_);
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
  CHECK(cell_db_ != nullptr);  // CELDB_LEGACY_FATAL_INVARIANT: test-only writer requires initialized CellDb.
  CHECK(streaming_writer_in_use_ != nullptr);  // CELDB_LEGACY_FATAL_INVARIANT: test-only writer requires import gate.
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

// tos27 P0-2 + tos29 High-1: streaming-import worker job +
// slice-budget-aware sink.
//
// Design choice (Option B in the audit menu, corrected by tos29): the
// BoC parse and root verification run on a dedicated `td::thread`
// worker OFF the CellDbIn actor. The worker does NOT write KeyValue /
// RocksDB. It serializes each parsed cell into a private spool file and
// returns hash-only ExtCell replacements immediately to keep parse
// residency bounded. After the parsed root matches the BFT-attested
// root, the CellDbIn actor drains the spool through bounded write
// batches. Concurrent CellDb operations (`load_cell`, `store_cell`,
// `store_block_state_*`, GC, archive interactions) can interleave
// between actor-side import batches, but no worker thread ever shares an
// open KeyValue write batch with them.
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
// The production `kMaxConcurrentStreamingImports = 1` bound is enforced
// by `streaming_job_ != nullptr`, not by the legacy test writer's
// `streaming_writer_in_use_` CAS. A second concurrent import attempt is
// rejected by the CellDbIn actor before a worker thread is spawned.
//
// Watchdog: every per-cell callback inside the slice-budget wrapper
// records the wall-time of the slowest slice. If that slice exceeds
// 10x the configured budget (50 ms vs 5 ms target) the worker emits a
// one-time LOG(WARNING) naming the cell index, purely diagnostic — no
// abort.
struct StreamingImportSpool {
  std::string path;
  td::uint64 cells = 0;
  td::uint64 bytes = 0;

  StreamingImportSpool() = default;
  StreamingImportSpool(const StreamingImportSpool&) = delete;
  StreamingImportSpool& operator=(const StreamingImportSpool&) = delete;
  ~StreamingImportSpool() {
    if (!path.empty()) {
      auto status = td::unlink(path);
      LOG_IF(WARNING, status.is_error()) << "failed to unlink streaming-import spool " << path << ": " << status;
    }
  }
};

struct StreamingImportJob {
  // Inputs captured at spawn time (immutable while the worker runs).
  PersistentStateImportRequest request;
  td::Promise<PersistentStateImportResult> promise;
  std::shared_ptr<LiveCellDbReaderProvider> provider;
  std::shared_ptr<StreamingImportSpool> spool;
  std::shared_ptr<StreamingImportSpool> rollback_spool;
  std::shared_ptr<std::atomic<bool>> cancel_requested = std::make_shared<std::atomic<bool>>(false);
  std::shared_ptr<fullnode::PersistentStateSpoolReservation> spool_reservation;
  td::uint64 spool_budget_bytes = 0;
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
  bool worker_joined = false;

  // Watchdog observation: index of the slowest cell observed during
  // parse and the wall-time of that slice. Logged at completion if
  // the slice exceeded 10x the configured budget.
  td::uint64 slowest_slice_cell_index = 0;
  double slowest_slice_wall_ms = 0.0;
  bool slow_slice_warning_emitted = false;

  // Actor-side spool-drain cursor. The worker closes the write side
  // before posting the continuation; CellDbIn opens this read handle and
  // advances the counters only from its serialized actor loop.
  td::FileFd spool_reader;
  td::FileFd rollback_writer;
  td::uint64 spool_cells_committed = 0;
  td::uint64 spool_bytes_committed = 0;
  td::uint64 rollback_cells_recorded = 0;
  td::uint64 rollback_bytes_recorded = 0;
  td::uint64 actor_write_batches = 0;

  // Sink keepalive. The actor allocates the sink on the heap (so the
  // worker has a stable pointer) and parks a shared_ptr here so teardown
  // happens only after the worker has joined and the actor-side commit
  // has resolved or failed.
  std::shared_ptr<vm::StreamingCellSink> sink_keepalive;

  // The worker thread itself. Joined by the actor on the completion
  // message before the StreamingImportJob is destroyed.
  td::thread worker;
};

struct StreamingImportRollbackJob {
  std::string path;
  std::string reason;
  td::uint64 cells = 0;
  td::uint64 bytes = 0;
  td::FileFd reader;
  td::uint64 cells_processed = 0;
  td::uint64 bytes_processed = 0;
  td::uint64 cells_erased = 0;
  td::uint64 batches = 0;
  bool resume_gc_after = false;

  bool resolve_import_promise = false;
  td::Promise<PersistentStateImportResult> promise;
  td::Status promise_error = td::Status::OK();
};

CellDbIn::~CellDbIn() {
  if (streaming_job_ != nullptr) {
    auto job = std::move(streaming_job_);
    streaming_job_.reset();
    if (job->cancel_requested != nullptr) {
      job->cancel_requested->store(true, std::memory_order_relaxed);
    }
    if (job->provider != nullptr) {
      job->provider->invalidate();
    }
    job->worker.join();
    job->worker_joined = true;
    if (job->sink_keepalive != nullptr && !job->committed) {
      job->sink_keepalive->abort();
    }
    if (!job->spool_reader.empty()) {
      job->spool_reader.close();
    }
    if (!job->rollback_writer.empty()) {
      auto sync_status = job->rollback_writer.sync();
      LOG_IF(WARNING, sync_status.is_error())
          << "CellDbIn shutdown: failed to sync streaming-import rollback manifest before preserving it: "
          << sync_status;
      job->rollback_writer.close();
    }
    if (job->rollback_spool != nullptr && !job->rollback_spool->path.empty() &&
        job->rollback_spool->cells > 0) {
      auto preserved_path = std::move(job->rollback_spool->path);
      job->rollback_spool->path.clear();
      LOG(ERROR) << "CellDbIn shutdown preserved streaming-import rollback manifest "
                 << preserved_path << " cells=" << job->rollback_spool->cells
                 << " bytes=" << job->rollback_spool->bytes
                 << "; startup recovery will replay it before metadata validation";
    }
    job->promise.set_error(
        td::Status::Error("CellDbIn::import_persistent_state_streaming cancelled by CellDbIn shutdown"));
  }

  for (auto& rollback : streaming_rollback_jobs_) {
    if (rollback == nullptr) {
      continue;
    }
    if (!rollback->reader.empty()) {
      rollback->reader.close();
    }
    LOG(ERROR) << "CellDbIn shutdown left streaming-import rollback manifest "
               << rollback->path << " reason=\"" << rollback->reason
               << "\"; startup recovery will replay it";
    if (rollback->resolve_import_promise) {
      rollback->promise.set_error(
          td::Status::Error("CellDbIn shutdown before streaming-import rollback completed"));
    }
  }
  streaming_rollback_jobs_.clear();
}

namespace {

constexpr td::uint32 kStreamingImportSpoolRecordHeaderBytes =
    static_cast<td::uint32>(vm::Cell::hash_bytes + sizeof(td::uint32));
constexpr td::uint32 kMaxStreamingImportSerializedCellBytes = 1U << 20;
constexpr const char* kStreamingImportRollbackManifestMarker = ".celldb-rollback.";
constexpr const char* kStreamingImportPartialSuffix = ".partial";
constexpr const char* kStreamingImportAdoptedSuffix = ".adopted";
constexpr const char* kStreamingImportCommittedSuffix = ".committed";

bool has_suffix(const std::string& value, td::Slice suffix) {
  return value.size() >= suffix.size() &&
         std::memcmp(value.data() + value.size() - suffix.size(), suffix.data(), suffix.size()) == 0;
}

bool is_streaming_import_rollback_manifest_path(const std::string& path) {
  return path.find(kStreamingImportRollbackManifestMarker) != std::string::npos &&
         has_suffix(path, td::Slice(kStreamingImportPartialSuffix));
}

std::string streaming_import_adopted_marker_path(const std::string& manifest_path) {
  return PSTRING() << manifest_path << kStreamingImportAdoptedSuffix;
}

std::string streaming_import_committed_manifest_path(const std::string& manifest_path) {
  return PSTRING() << manifest_path << kStreamingImportCommittedSuffix;
}

bool is_streaming_import_adopted_marker_path(const std::string& path) {
  return path.find(kStreamingImportRollbackManifestMarker) != std::string::npos &&
         has_suffix(path, td::Slice(".partial.adopted"));
}

bool is_streaming_import_committed_manifest_path(const std::string& path) {
  return path.find(kStreamingImportRollbackManifestMarker) != std::string::npos &&
         has_suffix(path, td::Slice(".partial.committed"));
}

std::string streaming_import_manifest_path_from_adopted_marker(const std::string& marker_path) {
  constexpr std::size_t suffix_len = sizeof(".adopted") - 1;
  if (marker_path.size() < suffix_len) {
    return {};
  }
  return marker_path.substr(0, marker_path.size() - suffix_len);
}

td::Status write_streaming_import_adopted_marker(const std::string& manifest_path,
                                                 td::uint64 rollback_cells,
                                                 td::uint64 rollback_bytes) {
  auto marker_path = streaming_import_adopted_marker_path(manifest_path);
  auto r_fd = td::FileFd::open(marker_path, td::FileFd::Flags::Write |
                                               td::FileFd::Flags::Create |
                                               td::FileFd::Flags::Truncate);
  if (r_fd.is_error()) {
    return r_fd.move_as_error_prefix("create streaming-import adopted marker: ");
  }
  auto fd = r_fd.move_as_ok();
  auto payload = PSTRING() << "adopted\ncells=" << rollback_cells << "\nbytes=" << rollback_bytes << "\n";
  TRY_STATUS(fd.write_all(td::Slice(payload.data(), payload.size())));
  TRY_STATUS(fd.sync());
  fd.close();
  return td::Status::OK();
}

td::Result<td::uint64> streaming_import_spool_reservation_bytes(td::uint64 file_size) {
  auto cfg = fullnode::persistent_state_budget_config();
  if (file_size == 0) {
    return td::Status::Error("streaming import spool reservation requires a non-zero file size");
  }
  const auto ratio = static_cast<td::uint64>(cfg.spool_reservation_ratio_percent);
  if (ratio == 0 || file_size > (std::numeric_limits<td::uint64>::max() - 99) / ratio) {
    return td::Status::Error(PSTRING() << "streaming import spool reservation overflow: "
                                       << "file_size=" << file_size
                                       << " ratio_percent=" << cfg.spool_reservation_ratio_percent);
  }
  auto reservation_bytes = (file_size * ratio + 99) / 100;
  if (reservation_bytes > cfg.max_spool_bytes_per_import) {
    return td::Status::Error(PSTRING() << "streaming import spool budget exceeded before import: "
                                       << "file_size=" << file_size
                                       << " ratio_percent=" << cfg.spool_reservation_ratio_percent
                                       << " reservation=" << reservation_bytes
                                       << " > max_spool_bytes_per_import "
                                       << cfg.max_spool_bytes_per_import);
  }
  if (reservation_bytes == 0) {
    return td::Status::Error("streaming import spool reservation rounded to zero");
  }
  return reservation_bytes;
}

td::Result<std::pair<td::FileFd, std::string>> create_streaming_import_sidecar_file(
    const std::string& source_path, td::Slice kind) {
  td::PathView source_view{td::Slice(source_path)};
  auto dir = source_view.parent_dir_noslash().str();
  td::Status last_error = td::Status::Error("streaming import spool path was not attempted");
  for (int attempt = 0; attempt < 16; ++attempt) {
    auto path = PSTRING() << source_path << ".celldb-" << kind << "." << td::Random::fast_uint64()
                          << ".partial";
    auto r_fd = td::FileFd::open(path, td::FileFd::Flags::Write | td::FileFd::Flags::CreateNew);
    if (r_fd.is_ok()) {
      return std::make_pair(r_fd.move_as_ok(), std::move(path));
    }
    last_error = r_fd.move_as_error();
  }
  return last_error.move_as_error_prefix(PSLICE() << "cannot create streaming import spool in " << dir << ": ");
}

td::Result<std::pair<td::FileFd, std::string>> create_streaming_import_spool_file(
    const std::string& source_path) {
  return create_streaming_import_sidecar_file(source_path, "spool");
}

td::Result<std::pair<td::FileFd, std::string>> create_streaming_import_rollback_file(
    const std::string& source_path) {
  return create_streaming_import_sidecar_file(source_path, "rollback");
}

td::Status write_spooled_cell_record(td::FileFd& fd, td::Slice hash, td::Slice serialized_cell_bytes) {
  if (hash.size() != vm::Cell::hash_bytes) {
    return td::Status::Error(PSLICE() << "streaming import spool: hash size " << hash.size()
                                      << " != expected " << vm::Cell::hash_bytes);
  }
  if (serialized_cell_bytes.empty()) {
    return td::Status::Error("streaming import spool: empty serialized cell");
  }
  if (serialized_cell_bytes.size() > kMaxStreamingImportSerializedCellBytes) {
    return td::Status::Error(PSLICE() << "streaming import spool: serialized cell too large: "
                                      << serialized_cell_bytes.size() << " > "
                                      << kMaxStreamingImportSerializedCellBytes);
  }
  std::array<char, kStreamingImportSpoolRecordHeaderBytes> header{};
  std::memcpy(header.data(), hash.data(), vm::Cell::hash_bytes);
  auto len = static_cast<td::uint32>(serialized_cell_bytes.size());
  std::memcpy(header.data() + vm::Cell::hash_bytes, &len, sizeof(len));
  TRY_STATUS(fd.write_all(td::Slice(header.data(), header.size())));
  TRY_STATUS(fd.write_all(serialized_cell_bytes));
  return td::Status::OK();
}

td::Result<bool> read_exact_maybe_trailing_partial(td::FileFd& fd, td::MutableSlice out, td::Slice what,
                                                   bool tolerate_trailing_partial) {
  size_t offset = 0;
  while (offset < out.size()) {
    TRY_RESULT(read, fd.read(out.substr(offset)));
    if (read == 0) {
      if (offset == 0) {
        return false;
      }
      if (tolerate_trailing_partial) {
        LOG(WARNING) << "ignoring trailing partial streaming-import rollback manifest record while reading "
                     << what << " (" << offset << "/" << out.size() << " bytes)";
        return false;
      }
      return td::Status::Error(PSLICE() << "short read from streaming import spool while reading " << what
                                        << " (" << offset << "/" << out.size() << " bytes)");
    }
    offset += read;
  }
  return true;
}

td::Result<bool> read_spooled_cell_record_maybe(
    td::FileFd& fd, std::array<char, vm::Cell::hash_bytes>& hash, std::string& value,
    bool tolerate_trailing_partial) {
  std::array<char, kStreamingImportSpoolRecordHeaderBytes> header{};
  TRY_RESULT(has_header, read_exact_maybe_trailing_partial(
                             fd, td::MutableSlice(header.data(), header.size()), "record header",
                             tolerate_trailing_partial));
  if (!has_header) {
    return false;
  }
  std::memcpy(hash.data(), header.data(), hash.size());
  td::uint32 len = 0;
  std::memcpy(&len, header.data() + vm::Cell::hash_bytes, sizeof(len));
  if (len == 0) {
    return td::Status::Error("streaming import spool contains an empty cell record");
  }
  if (len > kMaxStreamingImportSerializedCellBytes) {
    return td::Status::Error(PSLICE() << "streaming import spool cell record too large: " << len
                                      << " > " << kMaxStreamingImportSerializedCellBytes);
  }
  value.resize(len);
  TRY_RESULT(has_payload, read_exact_maybe_trailing_partial(
                              fd, td::MutableSlice(value.data(), value.size()), "record payload",
                              tolerate_trailing_partial));
  if (!has_payload) {
    value.clear();
    return false;
  }
  return true;
}

td::Result<std::pair<std::array<char, vm::Cell::hash_bytes>, std::string>> read_spooled_cell_record(
    td::FileFd& fd) {
  std::array<char, vm::Cell::hash_bytes> hash{};
  std::string value;
  TRY_RESULT(has_record, read_spooled_cell_record_maybe(fd, hash, value, /*tolerate_trailing_partial=*/false));
  if (!has_record) {
    return td::Status::Error("unexpected EOF while reading streaming import spool record");
  }
  return std::make_pair(hash, std::move(value));
}

class SpoolingImportSink final : public vm::StreamingCellSink {
 public:
  SpoolingImportSink(std::shared_ptr<vm::CellDbReaderProvider> reader_provider,
                     std::shared_ptr<StreamingImportSpool> spool, td::FileFd spool_fd,
                     td::uint64 max_spool_bytes)
      : reader_provider_(std::move(reader_provider))
      , spool_(std::move(spool))
      , spool_fd_(std::move(spool_fd))
      , max_spool_bytes_(max_spool_bytes) {
  }

  td::Status begin() override {
    if (begun_) {
      return td::Status::Error("SpoolingImportSink::begin called twice");
    }
    if (finished_ || aborted_) {
      return td::Status::Error("SpoolingImportSink::begin called after finish/abort");
    }
    if (spool_ == nullptr || spool_->path.empty() || spool_fd_.empty()) {
      return td::Status::Error("SpoolingImportSink::begin called without an open spool");
    }
    begun_ = true;
    return td::Status::OK();
  }

  td::Status persist(td::Ref<vm::Cell> cell) override {
    auto r_replacement = persist_and_replace(std::move(cell));
    if (r_replacement.is_error()) {
      return r_replacement.move_as_error();
    }
    return td::Status::OK();
  }

  td::Result<td::Ref<vm::Cell>> persist_and_replace(td::Ref<vm::Cell> cell) override {
    if (!begun_) {
      return td::Status::Error("SpoolingImportSink::persist_and_replace called before begin");
    }
    if (finished_ || aborted_) {
      return td::Status::Error("SpoolingImportSink::persist_and_replace called after finish/abort");
    }
    if (cell.is_null()) {
      return td::Status::Error("SpoolingImportSink::persist_and_replace received null cell");
    }
    td::Ref<vm::DataCell> data_cell{cell};
    if (data_cell.is_null()) {
      return td::Status::Error("SpoolingImportSink::persist_and_replace received non-DataCell from importer");
    }

    auto declared_hash = cell->get_hash();
    const auto level_mask = cell->get_level_mask();
    const auto level = cell->get_level();

    std::string serialized = vm::CellStorer::serialize_value(/*refcnt=*/1, data_cell, /*as_boc=*/false);
    const auto record_bytes = kStreamingImportSpoolRecordHeaderBytes + serialized.size();
    if (max_spool_bytes_ != 0 && spool_ != nullptr &&
        (spool_->bytes > max_spool_bytes_ || record_bytes > max_spool_bytes_ - spool_->bytes)) {
      auto attempted = spool_->bytes <= max_spool_bytes_ - std::min<td::uint64>(record_bytes, max_spool_bytes_)
                           ? spool_->bytes + record_bytes
                           : std::numeric_limits<td::uint64>::max();
      return td::Status::Error(PSTRING() << "SpoolingImportSink: import spool budget exceeded: "
                                         << attempted << " > "
                                         << max_spool_bytes_);
    }
    TRY_STATUS(write_spooled_cell_record(spool_fd_, declared_hash.as_slice(),
                                         td::Slice(serialized.data(), serialized.size())));
    ++cells_persisted_;
    if (spool_ != nullptr) {
      ++spool_->cells;
      spool_->bytes += record_bytes;
    }

    const auto hashes_count = level_mask.get_hashes_count();
    std::string hashes;
    std::string depths;
    hashes.reserve(static_cast<size_t>(hashes_count) * vm::Cell::hash_bytes);
    depths.reserve(static_cast<size_t>(hashes_count) * vm::Cell::depth_bytes);
    for (unsigned i = 0; i <= level; ++i) {
      if (!level_mask.is_significant(i)) {
        continue;
      }
      const auto& level_hash = cell->get_hash(i);
      hashes.append(level_hash.as_slice().data(), vm::Cell::hash_bytes);
      td::uint8 depth_buf[vm::Cell::depth_bytes];
      vm::DataCell::store_depth(depth_buf, cell->get_depth(i));
      depths.append(reinterpret_cast<const char*>(depth_buf), vm::Cell::depth_bytes);
    }

    TRY_RESULT(replacement, vm::make_celldb_ext_cell(level_mask, td::Slice(hashes), td::Slice(depths),
                                                    reader_provider_));
    if (replacement.is_null()) {
      return td::Status::Error("SpoolingImportSink::persist_and_replace: make_celldb_ext_cell returned null");
    }
    if (replacement->get_hash() != declared_hash) {
      return td::Status::Error("SpoolingImportSink::persist_and_replace: ExtCell replacement hash differs from input");
    }
    return replacement;
  }

  td::Status finish(const vm::Cell::Hash& root_hash) override {
    if (!begun_) {
      return td::Status::Error("SpoolingImportSink::finish called before begin");
    }
    if (finished_) {
      return td::Status::Error("SpoolingImportSink::finish called twice");
    }
    if (aborted_) {
      return td::Status::Error("SpoolingImportSink::finish called after abort");
    }
    finished_ = true;
    root_hash_ = root_hash;
    return td::Status::OK();
  }

  td::Status commit_after_root_verified(const vm::Cell::Hash& expected_root_hash) override {
    if (!finished_) {
      return td::Status::Error("SpoolingImportSink::commit_after_root_verified called before finish");
    }
    if (aborted_) {
      return td::Status::Error("SpoolingImportSink::commit_after_root_verified called after abort");
    }
    if (committed_) {
      return td::Status::Error("SpoolingImportSink::commit_after_root_verified called twice");
    }
    if (root_hash_ != expected_root_hash) {
      return td::Status::Error(PSTRING() << "SpoolingImportSink::commit_after_root_verified: root hash mismatch: "
                                         << "parsed=" << root_hash_.to_hex()
                                         << " expected=" << expected_root_hash.to_hex());
    }
    TRY_STATUS(spool_fd_.sync());
    spool_fd_.close();
    committed_ = true;
    LOG(INFO) << "SpoolingImportSink sealed " << cells_persisted_ << " cell(s), "
              << (spool_ ? spool_->bytes : 0) << " spool byte(s); root=" << expected_root_hash.to_hex()
              << " (CellDb write deferred to actor)";
    return td::Status::OK();
  }

  void abort() override {
    if (aborted_) {
      return;
    }
    aborted_ = true;
    spool_fd_.close();
    if (reader_provider_ != nullptr) {
      reader_provider_->invalidate();
    }
    if (spool_ != nullptr && !spool_->path.empty()) {
      auto path = spool_->path;
      auto status = td::unlink(path);
      LOG_IF(WARNING, status.is_error()) << "failed to unlink aborted streaming-import spool " << path << ": "
                                         << status;
      spool_->path.clear();
    }
  }

  bool finished() const {
    return finished_;
  }
  bool aborted() const {
    return aborted_;
  }
  bool is_committed() const {
    return committed_;
  }
  td::uint64 cells_persisted() const {
    return cells_persisted_;
  }

 private:
  std::shared_ptr<vm::CellDbReaderProvider> reader_provider_;
  std::shared_ptr<StreamingImportSpool> spool_;
  td::FileFd spool_fd_;
  td::uint64 max_spool_bytes_ = 0;
  td::uint64 cells_persisted_ = 0;
  bool begun_ = false;
  bool finished_ = false;
  bool aborted_ = false;
  bool committed_ = false;
  vm::Cell::Hash root_hash_{};
};

// Slice-budget-aware sink wrapper. Forwards every method to the
// inner spooling sink and,
// inside `persist_and_replace`, checks the cell-count and wall-clock
// slice budgets. When EITHER is exceeded the wrapper yields the OS
// scheduler slot via `td::this_thread::yield()` and resets the slice
// counters. This is the per-cell yield point the audit references.
class SlicedImportSink final : public vm::StreamingCellSink {
 public:
  SlicedImportSink(vm::StreamingCellSink* inner, StreamingImportJob* job)
      : inner_(inner), job_(job) {
    slice_started_at_ = td::Timestamp::now();
    slice_deadline_ = td::Timestamp::at(slice_started_at_.at() + kMaxImportSliceWallMs / 1000.0);
  }

  td::Status begin() override {
    TRY_STATUS(check_cancelled());
    return inner_->begin();
  }

  td::Status persist(td::Ref<vm::Cell> cell) override {
    TRY_STATUS(check_cancelled());
    auto status = inner_->persist(std::move(cell));
    after_cell();
    TRY_STATUS(check_cancelled());
    return status;
  }

  td::Result<td::Ref<vm::Cell>> persist_and_replace(td::Ref<vm::Cell> cell) override {
    TRY_STATUS(check_cancelled());
    auto r = inner_->persist_and_replace(std::move(cell));
    after_cell();
    TRY_STATUS(check_cancelled());
    return r;
  }

  td::Status finish(const vm::Cell::Hash& root_hash) override {
    TRY_STATUS(check_cancelled());
    return inner_->finish(root_hash);
  }

  td::Status commit_after_root_verified(const vm::Cell::Hash& expected_root_hash) override {
    TRY_STATUS(check_cancelled());
    return inner_->commit_after_root_verified(expected_root_hash);
  }

  void abort() override {
    inner_->abort();
  }

 private:
  td::Status check_cancelled() const {
    if (job_ != nullptr && job_->cancel_requested != nullptr &&
        job_->cancel_requested->load(std::memory_order_relaxed)) {
      return td::Status::Error("CellDbIn::import_persistent_state_streaming: streaming import cancelled");
    }
    return td::Status::OK();
  }

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

  vm::StreamingCellSink* inner_;
  StreamingImportJob* job_;
  td::uint32 cells_in_slice_ = 0;
  td::uint64 cells_total_ = 0;
  td::Timestamp slice_started_at_;
  td::Timestamp slice_deadline_;
};

// Pure off-actor work: open the tempfile, drive the BoC importer
// through the SlicedImportSink, run finish + root verification, and
// seal the spool. The worker never touches CellDb KeyValue / RocksDB.
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
//   * spool sync/close failure while sealing the verified import
void run_streaming_import_worker(StreamingImportJob* job, SpoolingImportSink* sink) {
  auto is_cancelled = [&]() {
    return job != nullptr && job->cancel_requested != nullptr &&
           job->cancel_requested->load(std::memory_order_relaxed);
  };
  if (is_cancelled()) {
    sink->abort();
    job->worker_status = td::Status::Error("CellDbIn::import_persistent_state_streaming: streaming import cancelled");
    return;
  }
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

  auto import_opts = job->request.opts;
  auto caller_cancelled = std::move(import_opts.is_cancelled);
  import_opts.is_cancelled = [caller_cancelled = std::move(caller_cancelled),
                              cancel_requested = job->cancel_requested]() mutable {
    if (cancel_requested != nullptr && cancel_requested->load(std::memory_order_relaxed)) {
      return true;
    }
    return caller_cancelled && caller_cancelled();
  };

  auto r_root = vm::std_boc_deserialize_from_file_bounded(fd, job->request.file_size, import_opts, &sliced_sink);
  fd.close();
  if (is_cancelled()) {
    if (!sink->aborted() && !sink->is_committed()) {
      sink->abort();
    }
    job->worker_status = td::Status::Error("CellDbIn::import_persistent_state_streaming: streaming import cancelled");
    return;
  }
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

  // Verify parsed root against the BFT-attested expected root BEFORE any
  // CellDb write. On mismatch, abort discards only the private spool, so
  // CellDb stays byte-for-byte identical to its pre-import snapshot.
  const auto parsed_hash = root->get_hash();
  if (RootHash{parsed_hash.bits()} != job->request.expected_root_hash) {
    sink->abort();
    job->worker_status = td::Status::Error(
        PSTRING() << "CellDbIn::import_persistent_state_streaming: root hash mismatch: expected "
                  << job->request.expected_root_hash.to_hex() << " got "
                  << RootHash{parsed_hash.bits()}.to_hex());
    return;
  }

  // Verified — seal the spool. commit_after_root_verified does NOT write
  // CellDb on this production sink; it syncs/closes the spool. CellDbIn's
  // actor-side `commit_streaming_import_spool_batch` is the single place
  // where cells become durable.
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

td::Status CellDbIn::rollback_streaming_import_manifest_sync(std::string rollback_manifest_path,
                                                             std::string reason,
                                                             bool tolerate_trailing_partial) {
  if (rollback_manifest_path.empty()) {
    return td::Status::OK();
  }
  if (cell_db_ == nullptr) {
    return td::Status::Error("CellDbIn::rollback_streaming_import_manifest_sync: cell_db not initialized");
  }

  auto r_fd = td::FileFd::open(rollback_manifest_path, td::FileFd::Flags::Read);
  if (r_fd.is_error()) {
    return r_fd.move_as_error_prefix("open streaming-import rollback manifest: ");
  }
  auto reader = r_fd.move_as_ok();

  td::uint64 cells_processed = 0;
  td::uint64 bytes_processed = 0;
  td::uint64 cells_erased = 0;
  td::uint64 batches = 0;
  bool done = false;
  while (!done) {
    TRY_STATUS(cell_db_->begin_write_batch());
    bool batch_open = true;
    auto abort_batch = [&]() {
      if (batch_open) {
        auto abort_status = cell_db_->abort_write_batch();
        LOG_IF(ERROR, abort_status.is_error())
            << "CellDbIn::rollback_streaming_import_manifest_sync: abort_write_batch failed: "
            << abort_status;
        batch_open = false;
      }
    };
    SCOPE_EXIT {
      abort_batch();
    };

    td::uint32 batch_cells = 0;
    td::uint64 batch_bytes = 0;
    while (batch_cells < kMaxImportActorBatchCells &&
           batch_bytes < kMaxImportActorBatchBytes) {
      std::array<char, vm::Cell::hash_bytes> hash{};
      std::string value;
      TRY_RESULT(has_record, read_spooled_cell_record_maybe(reader, hash, value, tolerate_trailing_partial));
      if (!has_record) {
        done = true;
        break;
      }

      td::Slice hash_slice(hash.data(), hash.size());
      td::Slice value_slice(value.data(), value.size());
      std::string current;
      TRY_RESULT(get_status, cell_db_->get(hash_slice, current));
      if (get_status == td::KeyValue::GetStatus::Ok && td::Slice(current) == value_slice) {
        TRY_STATUS(cell_db_->erase(hash_slice));
        ++cells_erased;
      }
      ++cells_processed;
      ++batch_cells;
      batch_bytes += kStreamingImportSpoolRecordHeaderBytes + value.size();
      bytes_processed += kStreamingImportSpoolRecordHeaderBytes + value.size();
    }

    if (batch_cells == 0) {
      abort_batch();
      break;
    }

    auto commit_status = cell_db_->commit_write_batch();
    batch_open = false;
    if (commit_status.is_error()) {
      return commit_status.move_as_error_prefix("commit streaming-import startup rollback batch: ");
    }
    ++batches;
  }

  reader.close();
  TRY_STATUS(td::unlink(rollback_manifest_path));
  cell_db_statistics_.streaming_import_startup_rollback_manifests_++;
  cell_db_statistics_.streaming_import_rollback_cells_processed_ += cells_processed;
  cell_db_statistics_.streaming_import_rollback_cells_erased_ += cells_erased;
  cell_db_statistics_.streaming_import_startup_rollback_cells_erased_ += cells_erased;
  LOG(WARNING) << "CellDbIn replayed streaming import rollback manifest " << rollback_manifest_path
               << " reason=\"" << reason << "\""
               << " processed=" << cells_processed
               << " erased=" << cells_erased
               << " batches=" << batches
               << " bytes=" << bytes_processed;
  return td::Status::OK();
}

td::Result<td::uint64> CellDbIn::recover_streaming_import_rollbacks_at_startup() {
  if (cell_db_ == nullptr) {
    return td::Status::Error("CellDbIn::recover_streaming_import_rollbacks_at_startup: cell_db not initialized");
  }

  auto tempfile_dir = fullnode::get_persistent_state_tempfile_dir();
  if (tempfile_dir.empty()) {
    return 0;
  }
  auto root = PSTRING() << tempfile_dir << "/persistent-state";
  auto stat = td::stat(root);
  if (stat.is_error()) {
    return 0;
  }

  std::vector<std::string> manifests;
  std::vector<std::string> adopted_markers;
  std::vector<std::string> committed_manifests;
  TRY_STATUS(td::walk_path(root, [&manifests, &adopted_markers, &committed_manifests](
                                     td::CSlice path, td::WalkPath::Type type) {
    if (type != td::WalkPath::Type::RegularFile) {
      return td::WalkPath::Action::Continue;
    }
    auto str = path.str();
    if (is_streaming_import_rollback_manifest_path(str)) {
      manifests.push_back(std::move(str));
    } else if (is_streaming_import_adopted_marker_path(str)) {
      adopted_markers.push_back(std::move(str));
    } else if (is_streaming_import_committed_manifest_path(str)) {
      committed_manifests.push_back(std::move(str));
    }
    return td::WalkPath::Action::Continue;
  }));

  if (manifests.empty() && adopted_markers.empty() && committed_manifests.empty()) {
    return 0;
  }
  std::sort(manifests.begin(), manifests.end());
  std::sort(adopted_markers.begin(), adopted_markers.end());
  std::sort(committed_manifests.begin(), committed_manifests.end());
  std::set<std::string> adopted_manifests;
  for (const auto& marker : adopted_markers) {
    adopted_manifests.insert(streaming_import_manifest_path_from_adopted_marker(marker));
  }
  LOG(WARNING) << "CellDbIn found " << manifests.size()
               << " residual streaming-import rollback manifest(s) and "
               << adopted_markers.size()
               << " adopted marker(s), plus " << committed_manifests.size()
               << " committed manifest(s); replaying only unadopted manifests before metadata validation";
  td::uint64 recovered = 0;
  for (auto& path : manifests) {
    if (adopted_manifests.count(path) != 0) {
      auto unlink_manifest = td::unlink(path);
      LOG_IF(WARNING, unlink_manifest.is_error())
          << "failed to unlink adopted streaming-import rollback manifest " << path
          << ": " << unlink_manifest;
      if (unlink_manifest.is_ok()) {
        auto marker = streaming_import_adopted_marker_path(path);
        auto unlink_marker = td::unlink(marker);
        LOG_IF(WARNING, unlink_marker.is_error())
            << "failed to unlink streaming-import adopted marker " << marker
            << ": " << unlink_marker;
      }
      continue;
    }
    TRY_STATUS(rollback_streaming_import_manifest_sync(
        std::move(path), "startup recovery after interrupted streaming import",
        /*tolerate_trailing_partial=*/true));
    ++recovered;
  }
  for (auto& marker : adopted_markers) {
    auto manifest_path = streaming_import_manifest_path_from_adopted_marker(marker);
    if (std::find(manifests.begin(), manifests.end(), manifest_path) != manifests.end()) {
      continue;
    }
    auto unlink_marker = td::unlink(marker);
    LOG_IF(WARNING, unlink_marker.is_error())
        << "failed to unlink orphaned streaming-import adopted marker " << marker
        << ": " << unlink_marker;
  }
  for (auto& committed : committed_manifests) {
    auto unlink_committed = td::unlink(committed);
    LOG_IF(WARNING, unlink_committed.is_error())
        << "failed to unlink committed streaming-import rollback manifest " << committed
        << ": " << unlink_committed;
  }
  return recovered;
}

// tos26 P1-4 + tos27 P0-2 + tos29 High-1: actor entry point.
// Validates inputs, pauses GC, builds the provider + spooling sink, and
// spawns the worker thread that runs the actual BoC parse OFF the
// CellDbIn actor's message loop. The worker writes only a private spool;
// every CellDb KeyValue write is later performed by CellDbIn in bounded
// actor-side batches.
//
// Lifecycle:
//   1. Reject zero-size or empty-path requests up front.
//   2. Create an import spool in the same temp directory as the source.
//   3. Build a LiveCellDbReaderProvider seeded with the current
//      pre-commit reader. Lazy ExtCells produced during parse bind
//      to this provider; after commit the actor publishes a fresh
//      post-commit reader on the same provider.
//   4. Construct a SpoolingImportSink wrapping (provider, spool fd);
//      the sink serializes cells into the spool and returns ExtCells.
//   5. Allocate a StreamingImportJob and spawn a `td::thread` worker
//      that runs `run_streaming_import_worker(job, sink)`. The worker
//      drives parse + verify + spool sealing off-actor.
//   6. The worker's last action is `send_closure(self, &continue_import_after_worker)`
//      which queues a single message into the actor's mailbox.
//   7. `continue_import_after_worker` runs on the actor's loop, joins
//      the worker thread, and starts `commit_streaming_import_spool_batch`.
//   8. Actor-side spool draining writes bounded CellDb batches, publishes
//      the post-commit snapshot, and resolves the original promise.
//
// Failures BEFORE worker spawn (input validation, spool creation)
// resolve the promise and resume GC immediately. Failures during the
// worker's parse are surfaced via `job->worker_status` and resolved
// in the continuation; the GC pause is released through the same
// abort-or-lease handshake the in-actor version used.
void CellDbIn::import_persistent_state_streaming(PersistentStateImportRequest request,
                                                 td::Promise<PersistentStateImportResult> promise) {
  // Defer to the action queue if a snapshot/store/gc operation is
  // currently using the DB; this preserves CellDbIn's existing
  // serialization contract for the validation prologue. The worker will
  // not touch KeyValue, and the later actor-side spool drain checks
  // db_busy_ before every bounded batch.
  if (db_busy_) {
    action_queue_.push_back([self = this, request = std::move(request),
                             promise = std::move(promise)](td::Result<td::Unit> R) mutable {
      if (R.is_error()) {
        promise.set_error(R.move_as_error_prefix(
            "CellDbIn::import_persistent_state_streaming: queued CellDb action failed: "));
        return;
      }
      self->import_persistent_state_streaming(std::move(request), std::move(promise));
    });
    return;
  }
  if (!streaming_rollback_jobs_.empty()) {
    action_queue_.push_back([self = this, request = std::move(request),
                             promise = std::move(promise)](td::Result<td::Unit> R) mutable {
      if (R.is_error()) {
        promise.set_error(R.move_as_error_prefix(
            "CellDbIn::import_persistent_state_streaming: queued rollback action failed: "));
        return;
      }
      self->import_persistent_state_streaming(std::move(request), std::move(promise));
    });
    drain_streaming_import_rollback_batch();
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
  // tos27/tos29: kMaxConcurrentStreamingImports = 1 is structurally
  // enforced by this actor-owned job slot. A second import never gets a
  // worker thread and never receives a KeyValue handle.
  if (streaming_job_ != nullptr) {
    promise.set_error(td::Status::Error(
        "CellDbIn::import_persistent_state_streaming: another streaming import is already in flight on this CellDbIn"));
    return;
  }

  auto r_spool_reservation_bytes = streaming_import_spool_reservation_bytes(request.file_size);
  if (r_spool_reservation_bytes.is_error()) {
    promise.set_error(r_spool_reservation_bytes.move_as_error());
    return;
  }
  auto spool_reservation_bytes = r_spool_reservation_bytes.move_as_ok();
  if (!fullnode::try_reserve_persistent_state_spool_disk(spool_reservation_bytes)) {
    auto cfg = fullnode::persistent_state_budget_config();
    promise.set_error(td::Status::Error(
        PSTRING() << "CellDbIn::import_persistent_state_streaming: streaming import spool budget exhausted: "
                  << "reservation=" << spool_reservation_bytes
                  << " max_total_spool_bytes=" << cfg.max_total_spool_bytes));
    return;
  }
  auto spool_reservation = std::make_shared<fullnode::PersistentStateSpoolReservation>(spool_reservation_bytes);

  auto r_spool = create_streaming_import_spool_file(request.tempfile_path);
  if (r_spool.is_error()) {
    promise.set_error(r_spool.move_as_error());
    return;
  }
  auto spool_pair = r_spool.move_as_ok();
  auto spool = std::make_shared<StreamingImportSpool>();
  spool->path = std::move(spool_pair.second);

  auto r_rollback = create_streaming_import_rollback_file(request.tempfile_path);
  if (r_rollback.is_error()) {
    promise.set_error(r_rollback.move_as_error());
    return;
  }
  auto rollback_pair = r_rollback.move_as_ok();
  auto rollback_spool = std::make_shared<StreamingImportSpool>();
  rollback_spool->path = std::move(rollback_pair.second);

  // tos26 P1-5: pause GC for the duration of this import. The matching
  // resume runs on every exit path: success delays the resume long
  // enough for the downloader's follow-up set_block_state to commit a
  // desc-list entry that references the imported cells (via the GC
  // lease), while every failure path resumes immediately in the
  // continuation (no cells durable on a failed import).
  pause_gc_for_import();
  cell_db_statistics_.streaming_import_started_++;

  // Build a LiveCellDbReaderProvider seeded with the current reader.
  // The lazy ExtCells emitted during parse capture this provider; we
  // republish a fresh post-commit reader on the same provider after
  // commit so they observe the just-flushed cells.
  auto initial_reader = boc_->get_cell_db_reader();
  auto provider = std::make_shared<LiveCellDbReaderProvider>(initial_reader);

  // Construct the worker sink. It can create ExtCell replacements from
  // hash/depth metadata, but it never writes CellDb; it only appends
  // serialized cells to `spool_pair.first`.
  auto sink = std::make_unique<SpoolingImportSink>(
      std::shared_ptr<vm::CellDbReaderProvider>(provider), spool, std::move(spool_pair.first),
      spool_reservation_bytes);

  // Spawn the worker thread. The job owns the request, promise,
  // provider, and worker thread; we hand the sink over via raw
  // pointer because the sink's lifetime is tied to the job (we move
  // it into a shared_ptr inside the lambda for clean teardown).
  streaming_job_ = std::make_unique<StreamingImportJob>();
  streaming_job_->request = std::move(request);
  streaming_job_->promise = std::move(promise);
  streaming_job_->provider = std::move(provider);
  streaming_job_->spool = std::move(spool);
  streaming_job_->rollback_spool = std::move(rollback_spool);
  streaming_job_->spool_reservation = std::move(spool_reservation);
  streaming_job_->spool_budget_bytes = spool_reservation_bytes;
  streaming_job_->rollback_writer = std::move(rollback_pair.first);
  streaming_job_->expected_hash = vm::Cell::Hash{};  // populated post-parse

  // Park the sink in a shared_ptr held by both the job and the worker
  // lambda. The shared_ptr keeps the spool fd alive across the worker ->
  // actor handoff and lets failure teardown invalidate the provider.
  auto shared_sink = std::shared_ptr<SpoolingImportSink>(std::move(sink));
  streaming_job_->sink_keepalive = std::static_pointer_cast<vm::StreamingCellSink>(shared_sink);

  // Spawn the off-actor worker. The CellDbIn actor's message loop is
  // free to interleave any other operation while the worker runs.
  auto* job_ptr = streaming_job_.get();
  auto self_actor = actor_id(this);
  streaming_job_->worker = td::thread([job_ptr, sink_keepalive = std::move(shared_sink), self_actor]() mutable {
    // The worker drives begin / parse / verify / spool-seal against
    // `sink_keepalive`. On any error path the worker calls sink->abort()
    // before stashing worker_status; the continuation handles
    // resume_gc + promise.set_* on the actor.
    run_streaming_import_worker(job_ptr, sink_keepalive.get());
    // Post a single completion message back to the actor. The
    // continuation will join this thread and tear down the job.
    td::actor::send_closure(self_actor, &CellDbIn::continue_import_after_worker);
  });
}

// tos27/tos29: completion message posted by the worker thread.
// Runs on the CellDbIn actor's serialized loop; joins the worker and
// starts the actor-side CellDb write stage. The promise is resolved only
// by finish_streaming_import_after_actor_commit / fail_streaming_import.
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

  // Join the worker thread. The worker's final action was
  // send_closure to this method, so the thread is done with all its
  // observable side-effects and we can join without blocking on
  // useful work. td::thread::join() is safe to call on an
  // already-joined / uninitialized thread (no-ops).
  streaming_job_->worker.join();
  streaming_job_->worker_joined = true;

  // Failure path: worker reported an error. The sink has already been
  // aborted by the worker (run_streaming_import_worker calls abort()
  // on every error path before stashing the status). Resume GC and
  // surface the error; no cells are durable.
  if (streaming_job_->worker_status.is_error()) {
    fail_streaming_import(streaming_job_->worker_status.move_as_error());
    return;
  }

  if (streaming_job_->spool == nullptr || streaming_job_->spool->path.empty()) {
    fail_streaming_import(td::Status::Error("CellDbIn::continue_import_after_worker: missing verified spool"));
    return;
  }

  commit_streaming_import_spool_batch();
}

void CellDbIn::commit_streaming_import_spool_batch() {
  if (streaming_job_ == nullptr) {
    LOG(ERROR) << "CellDbIn::commit_streaming_import_spool_batch: no streaming job in flight";
    return;
  }
  if (db_busy_) {
    action_queue_.push_back([self = this](td::Result<td::Unit> R) mutable {
      if (R.is_error()) {
        self->fail_streaming_import(R.move_as_error_prefix(
            "CellDbIn::commit_streaming_import_spool_batch: queued CellDb action failed: "));
        return;
      }
      self->commit_streaming_import_spool_batch();
    });
    return;
  }

  auto* job = streaming_job_.get();
  if (job->spool == nullptr || job->spool->path.empty()) {
    fail_streaming_import(td::Status::Error("CellDbIn::commit_streaming_import_spool_batch: missing spool path"));
    return;
  }
  if (cell_db_ == nullptr || boc_ == nullptr) {
    fail_streaming_import(td::Status::Error("CellDbIn::commit_streaming_import_spool_batch: cell_db not initialized"));
    return;
  }

  if (job->spool_cells_committed >= job->spool->cells) {
    finish_streaming_import_after_actor_commit();
    return;
  }

  if (job->spool_reader.empty()) {
    auto r_fd = td::FileFd::open(job->spool->path, td::FileFd::Flags::Read);
    if (r_fd.is_error()) {
      fail_streaming_import(r_fd.move_as_error_prefix("CellDbIn::commit_streaming_import_spool_batch: open spool: "));
      return;
    }
    job->spool_reader = r_fd.move_as_ok();
  }

  auto status = [&]() -> td::Status {
    auto begin_status = cell_db_->begin_write_batch();
    if (begin_status.is_error()) {
      return begin_status;
    }
    bool batch_open = true;
    auto abort_batch = [&]() {
      if (batch_open) {
        auto abort_status = cell_db_->abort_write_batch();
        LOG_IF(ERROR, abort_status.is_error())
            << "CellDbIn::commit_streaming_import_spool_batch: abort_write_batch failed: " << abort_status;
        batch_open = false;
      }
    };
    SCOPE_EXIT {
      abort_batch();
    };

    td::uint32 batch_cells = 0;
    td::uint64 batch_bytes = 0;
    td::uint32 batch_new_cells = 0;
    while (job->spool_cells_committed < job->spool->cells &&
           batch_cells < kMaxImportActorBatchCells &&
           batch_bytes < kMaxImportActorBatchBytes) {
      TRY_RESULT(record, read_spooled_cell_record(job->spool_reader));
      auto& hash = record.first;
      auto& value = record.second;
      td::Slice hash_slice(hash.data(), hash.size());
      td::Slice value_slice(value.data(), value.size());

      // tos30 fail-closed rollback: discover whether this import is
      // creating a new cell before appending the write. Only newly
      // created cells are recorded in the rollback manifest; pre-existing
      // idempotent cells must not be erased if the import later fails.
      std::string existing;
      TRY_RESULT(get_status, cell_db_->get(hash_slice, existing));
      if (get_status == td::KeyValue::GetStatus::Ok) {
        if (td::Slice(existing) != value_slice) {
          abort_batch();
          return td::Status::Error(PSLICE() << "cell hash collision during actor streaming import: "
                                            << td::base64_encode(hash_slice)
                                            << " already stored with different bytes (existing="
                                            << existing.size() << "B, new=" << value.size() << "B)");
        }
      } else {
        if (job->rollback_writer.empty() || job->rollback_spool == nullptr ||
            job->rollback_spool->path.empty()) {
          abort_batch();
          return td::Status::Error(
              "CellDb streaming import actor batch: missing rollback manifest writer for new cell");
        }
        const auto record_bytes = kStreamingImportSpoolRecordHeaderBytes + value.size();
        const auto import_spool_bytes = job->spool != nullptr ? job->spool->bytes : 0;
        if (job->spool_budget_bytes != 0 &&
            (import_spool_bytes > job->spool_budget_bytes ||
             job->rollback_spool->bytes > job->spool_budget_bytes - import_spool_bytes ||
             record_bytes > job->spool_budget_bytes - import_spool_bytes - job->rollback_spool->bytes)) {
          abort_batch();
          return td::Status::Error(PSTRING() << "CellDb streaming import actor batch: rollback spool budget exceeded: "
                                             << "import_spool=" << import_spool_bytes
                                             << " rollback_spool=" << job->rollback_spool->bytes
                                             << " next_record=" << record_bytes
                                             << " budget=" << job->spool_budget_bytes);
        }
        TRY_STATUS(write_spooled_cell_record(job->rollback_writer, hash_slice, value_slice));
        ++job->rollback_spool->cells;
        job->rollback_spool->bytes += record_bytes;
        ++job->rollback_cells_recorded;
        job->rollback_bytes_recorded += record_bytes;
        ++batch_new_cells;
        TRY_STATUS(cell_db_->set(hash_slice, value_slice));
      }
      ++job->spool_cells_committed;
      ++batch_cells;
      batch_bytes += kStreamingImportSpoolRecordHeaderBytes + value.size();
      job->spool_bytes_committed += kStreamingImportSpoolRecordHeaderBytes + value.size();
    }

    // Make the rollback manifest durable before the corresponding cell
    // batch becomes durable. This is primarily a fail-closed runtime
    // guarantee; crash recovery can later reuse the same manifest shape.
    if (batch_new_cells > 0) {
      TRY_STATUS(job->rollback_writer.sync());
    }

    auto commit_status = cell_db_->commit_write_batch();
    batch_open = false;
    if (commit_status.is_error()) {
      return commit_status;
    }
    ++job->actor_write_batches;
    return td::Status::OK();
  }();

  if (status.is_error()) {
    fail_streaming_import(status.move_as_error_prefix("CellDb streaming import actor batch: "));
    return;
  }

  if (job->spool_cells_committed < job->spool->cells) {
    td::actor::send_closure(actor_id(this), &CellDbIn::commit_streaming_import_spool_batch);
    return;
  }

  finish_streaming_import_after_actor_commit();
}

void CellDbIn::finish_streaming_import_after_actor_commit() {
  if (streaming_job_ == nullptr) {
    LOG(ERROR) << "CellDbIn::finish_streaming_import_after_actor_commit: no streaming job in flight";
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
    auto refresh_status = refresh_loader_after_celldb_mutation("finish_streaming_import_after_actor_commit");
    if (refresh_status.is_error()) {
      fail_streaming_import(refresh_status.move_as_error());
      return;
    }
  }

  auto job = std::move(streaming_job_);
  streaming_job_.reset();

  auto post_commit_reader = boc_->get_cell_db_reader();
  if (post_commit_reader != nullptr) {
    job->provider->publish(post_commit_reader);
  }
  if (!job->rollback_writer.empty()) {
    auto sync_status = job->rollback_writer.sync();
    LOG_IF(ERROR, sync_status.is_error())
        << "CellDbIn::finish_streaming_import_after_actor_commit: rollback manifest sync failed after commit: "
        << sync_status;
    job->rollback_writer.close();
  }

  PersistentStateImportResult result;
  result.hash_only_root = std::move(job->hash_only_root);
  result.cells_persisted = job->cells_persisted;
  result.parsed_root_hash = job->parsed_hash;
  cell_db_statistics_.streaming_import_committed_++;
  cell_db_statistics_.streaming_import_cells_committed_ += job->spool_cells_committed;
  cell_db_statistics_.streaming_import_actor_batches_ += job->actor_write_batches;
  LOG(INFO) << "CellDbIn::import_persistent_state_streaming: committed " << result.cells_persisted
            << " cell(s); root=" << job->request.expected_root_hash.to_hex()
            << " (lazy ExtCell-backed; child DAG durable in CellDb"
            << "; actor_batches=" << job->actor_write_batches
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
  std::string rollback_manifest_path;
  td::uint64 rollback_cells = job->rollback_cells_recorded;
  td::uint64 rollback_bytes = job->rollback_bytes_recorded;
  if (job->rollback_spool != nullptr && !job->rollback_spool->path.empty()) {
    if (rollback_cells > 0) {
      rollback_manifest_path = std::move(job->rollback_spool->path);
      job->rollback_spool->path.clear();
    } else {
      auto status = td::unlink(job->rollback_spool->path);
      LOG_IF(WARNING, status.is_error())
          << "failed to unlink empty streaming-import rollback manifest " << job->rollback_spool->path
          << ": " << status;
      job->rollback_spool->path.clear();
    }
  }
  result.gc_lease = std::make_unique<CellDbGcPauseLease>(actor_id(this), std::move(rollback_manifest_path),
                                                         rollback_cells, rollback_bytes);

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
  // Job (incl. sink_keepalive + spool) torn down at scope exit. The
  // spool destructor unlinks the verified import spool after the actor
  // has committed every record.
}

void CellDbIn::fail_streaming_import(td::Status error) {
  if (streaming_job_ == nullptr) {
    LOG(ERROR) << "CellDbIn::fail_streaming_import: no streaming job in flight; error=" << error;
    resume_gc_for_import();
    return;
  }
  auto job = std::move(streaming_job_);
  streaming_job_.reset();
  cell_db_statistics_.streaming_import_failed_++;
  if (job->provider != nullptr) {
    job->provider->invalidate();
  }
  if (!job->rollback_writer.empty()) {
    auto sync_status = job->rollback_writer.sync();
    LOG_IF(ERROR, sync_status.is_error())
        << "CellDbIn::fail_streaming_import: rollback manifest sync failed before failure rollback: "
        << sync_status;
    job->rollback_writer.close();
  }
  if (job->rollback_spool != nullptr && !job->rollback_spool->path.empty() &&
      job->rollback_spool->cells > 0) {
    auto rollback = std::make_unique<StreamingImportRollbackJob>();
    rollback->path = std::move(job->rollback_spool->path);
    job->rollback_spool->path.clear();
    rollback->reason = "streaming import failed after actor-side CellDb writes";
    rollback->cells = job->rollback_spool->cells;
    rollback->bytes = job->rollback_spool->bytes;
    rollback->resume_gc_after = true;
    rollback->resolve_import_promise = true;
    rollback->promise = std::move(job->promise);
    rollback->promise_error = std::move(error);
    cell_db_statistics_.streaming_import_rollback_jobs_started_++;
    streaming_rollback_jobs_.push_back(std::move(rollback));
    drain_streaming_import_rollback_batch();
    return;
  }
  if (job->rollback_spool != nullptr && !job->rollback_spool->path.empty()) {
    auto status = td::unlink(job->rollback_spool->path);
    LOG_IF(WARNING, status.is_error())
        << "failed to unlink empty streaming-import rollback manifest " << job->rollback_spool->path
        << ": " << status;
    job->rollback_spool->path.clear();
  }
  resume_gc_for_import();
  job->promise.set_error(std::move(error));
}

void CellDbIn::rollback_streaming_import_manifest(std::string rollback_manifest_path, td::uint64 rollback_cells,
                                                  td::uint64 rollback_bytes, std::string reason,
                                                  bool resume_gc_after) {
  if (rollback_manifest_path.empty() || rollback_cells == 0) {
    if (!rollback_manifest_path.empty()) {
      auto status = td::unlink(rollback_manifest_path);
      LOG_IF(WARNING, status.is_error())
          << "failed to unlink empty streaming-import rollback manifest " << rollback_manifest_path
          << ": " << status;
    }
    if (resume_gc_after) {
      resume_gc_for_import();
    }
    return;
  }

  auto rollback = std::make_unique<StreamingImportRollbackJob>();
  rollback->path = std::move(rollback_manifest_path);
  rollback->reason = std::move(reason);
  rollback->cells = rollback_cells;
  rollback->bytes = rollback_bytes;
  rollback->resume_gc_after = resume_gc_after;
  cell_db_statistics_.streaming_import_rollback_jobs_started_++;
  streaming_rollback_jobs_.push_back(std::move(rollback));
  drain_streaming_import_rollback_batch();
}

void CellDbIn::release_streaming_import_after_root_store_committed(std::string rollback_manifest_path,
                                                                   td::uint64 rollback_cells,
                                                                   td::uint64 rollback_bytes) {
  if (rollback_manifest_path.empty() || rollback_cells == 0) {
    if (!rollback_manifest_path.empty()) {
      auto status = td::unlink(rollback_manifest_path);
      LOG_IF(WARNING, status.is_error())
          << "failed to unlink empty committed streaming-import rollback manifest "
          << rollback_manifest_path << ": " << status;
    }
    resume_gc_for_import();
    return;
  }

  auto marker_status = write_streaming_import_adopted_marker(
      rollback_manifest_path, rollback_cells, rollback_bytes);
  if (marker_status.is_error()) {
    auto committed_path = streaming_import_committed_manifest_path(rollback_manifest_path);
    auto rename_status = td::rename(rollback_manifest_path, committed_path);
    if (rename_status.is_ok()) {
      auto unlink_committed = td::unlink(committed_path);
      LOG_IF(WARNING, unlink_committed.is_error())
          << "failed to unlink committed streaming-import rollback manifest "
          << committed_path << ": " << unlink_committed;
    } else {
      LOG(ERROR) << "failed to mark streaming-import rollback manifest adopted after root-store commit: marker="
                 << marker_status << " rename=" << rename_status
                 << "; manifest=" << rollback_manifest_path
                 << " may be replayed on startup unless the operator removes it after validating root-store";
    }
    resume_gc_for_import();
    return;
  }

  auto unlink_manifest = td::unlink(rollback_manifest_path);
  if (unlink_manifest.is_error()) {
    LOG(WARNING) << "failed to unlink adopted streaming-import rollback manifest "
                 << rollback_manifest_path << ": " << unlink_manifest
                 << "; adopted marker retained so startup recovery will not rollback it";
    resume_gc_for_import();
    return;
  }

  auto marker_path = streaming_import_adopted_marker_path(rollback_manifest_path);
  auto unlink_marker = td::unlink(marker_path);
  LOG_IF(WARNING, unlink_marker.is_error())
      << "failed to unlink streaming-import adopted marker " << marker_path
      << ": " << unlink_marker;
  resume_gc_for_import();
}

void CellDbIn::fail_streaming_import_rollback(td::Status error) {
  if (streaming_rollback_jobs_.empty()) {
    LOG(ERROR) << "CellDbIn::fail_streaming_import_rollback with empty rollback queue: " << error;
    release_db();
    return;
  }
  auto finished = std::move(streaming_rollback_jobs_.front());
  streaming_rollback_jobs_.pop_front();
  if (!finished->reader.empty()) {
    finished->reader.close();
  }
  LOG(ERROR) << "CellDbIn rollback failed for manifest " << finished->path
             << " reason=\"" << finished->reason << "\": " << error;
  if (finished->resume_gc_after) {
    resume_gc_for_import();
  }
  if (finished->resolve_import_promise) {
    finished->promise.set_error(
        td::Status::Error(PSTRING() << "streaming import failed and rollback failed: import error="
                                    << finished->promise_error << "; rollback error=" << error));
  }
  if (!streaming_rollback_jobs_.empty()) {
    td::actor::send_closure(actor_id(this), &CellDbIn::drain_streaming_import_rollback_batch);
  } else {
    release_db();
  }
}

void CellDbIn::drain_streaming_import_rollback_batch() {
  if (streaming_rollback_jobs_.empty()) {
    return;
  }
  if (db_busy_) {
    action_queue_.push_front([self = this](td::Result<td::Unit> R) mutable {
      if (R.is_error()) {
        self->fail_streaming_import_rollback(R.move_as_error_prefix(
            "CellDbIn::drain_streaming_import_rollback_batch: queued CellDb action failed: "));
        return;
      }
      self->drain_streaming_import_rollback_batch();
    });
    return;
  }
  if (cell_db_ == nullptr || boc_ == nullptr) {
    auto job = std::move(streaming_rollback_jobs_.front());
    streaming_rollback_jobs_.pop_front();
    auto rollback_error =
        td::Status::Error("CellDbIn::drain_streaming_import_rollback_batch: cell_db not initialized");
    LOG(ERROR) << rollback_error << "; manifest=" << job->path << " reason=" << job->reason;
    if (job->resume_gc_after) {
      resume_gc_for_import();
    }
    if (job->resolve_import_promise) {
      job->promise.set_error(
          td::Status::Error(PSTRING() << "streaming import failed and rollback could not run: import error="
                                      << job->promise_error << "; rollback error=" << rollback_error));
    }
    if (streaming_rollback_jobs_.empty()) {
      release_db();
    } else {
      td::actor::send_closure(actor_id(this), &CellDbIn::drain_streaming_import_rollback_batch);
    }
    return;
  }

  auto* job = streaming_rollback_jobs_.front().get();
  if (job->reader.empty()) {
    auto r_fd = td::FileFd::open(job->path, td::FileFd::Flags::Read);
    if (r_fd.is_error()) {
      auto error = r_fd.move_as_error_prefix("open streaming-import rollback manifest: ");
      LOG(ERROR) << "CellDbIn rollback failed before reading manifest " << job->path << ": " << error;
      auto finished = std::move(streaming_rollback_jobs_.front());
      streaming_rollback_jobs_.pop_front();
      if (finished->resume_gc_after) {
        resume_gc_for_import();
      }
      if (finished->resolve_import_promise) {
        finished->promise.set_error(
            td::Status::Error(PSTRING() << "streaming import failed and rollback manifest could not be opened: "
                                        << "import error=" << finished->promise_error
                                        << "; rollback error=" << error));
      }
      if (!streaming_rollback_jobs_.empty()) {
        td::actor::send_closure(actor_id(this), &CellDbIn::drain_streaming_import_rollback_batch);
      } else {
        release_db();
      }
      return;
    }
    job->reader = r_fd.move_as_ok();
  }

  auto status = [&]() -> td::Status {
    auto begin_status = cell_db_->begin_write_batch();
    if (begin_status.is_error()) {
      return begin_status;
    }
    bool batch_open = true;
    auto abort_batch = [&]() {
      if (batch_open) {
        auto abort_status = cell_db_->abort_write_batch();
        LOG_IF(ERROR, abort_status.is_error())
            << "CellDbIn::drain_streaming_import_rollback_batch: abort_write_batch failed: "
            << abort_status;
        batch_open = false;
      }
    };
    SCOPE_EXIT {
      abort_batch();
    };

    td::uint32 batch_cells = 0;
    td::uint64 batch_bytes = 0;
    while (job->cells_processed < job->cells &&
           batch_cells < kMaxImportActorBatchCells &&
           batch_bytes < kMaxImportActorBatchBytes) {
      TRY_RESULT(record, read_spooled_cell_record(job->reader));
      auto& hash = record.first;
      auto& value = record.second;
      td::Slice hash_slice(hash.data(), hash.size());
      td::Slice value_slice(value.data(), value.size());

      std::string current;
      TRY_RESULT(get_status, cell_db_->get(hash_slice, current));
      if (get_status == td::KeyValue::GetStatus::Ok && td::Slice(current) == value_slice) {
        TRY_STATUS(cell_db_->erase(hash_slice));
        ++job->cells_erased;
      }
      ++job->cells_processed;
      ++batch_cells;
      batch_bytes += kStreamingImportSpoolRecordHeaderBytes + value.size();
      job->bytes_processed += kStreamingImportSpoolRecordHeaderBytes + value.size();
    }

    auto commit_status = cell_db_->commit_write_batch();
    batch_open = false;
    if (commit_status.is_error()) {
      return commit_status;
    }
    ++job->batches;
    return td::Status::OK();
  }();

  if (status.is_error()) {
    auto rollback_error = status.move_as_error_prefix("streaming-import rollback batch: ");
    LOG(ERROR) << "CellDbIn rollback failed for manifest " << job->path
               << " after processed=" << job->cells_processed << "/" << job->cells
               << " erased=" << job->cells_erased << ": " << rollback_error;
    auto finished = std::move(streaming_rollback_jobs_.front());
    streaming_rollback_jobs_.pop_front();
    if (finished->resume_gc_after) {
      resume_gc_for_import();
    }
    if (finished->resolve_import_promise) {
      finished->promise.set_error(
          td::Status::Error(PSTRING() << "streaming import failed and rollback failed: import error="
                                      << finished->promise_error << "; rollback error=" << rollback_error));
    }
    if (!streaming_rollback_jobs_.empty()) {
      td::actor::send_closure(actor_id(this), &CellDbIn::drain_streaming_import_rollback_batch);
    } else {
      release_db();
    }
    return;
  }

  if (job->cells_processed < job->cells) {
    td::actor::send_closure(actor_id(this), &CellDbIn::drain_streaming_import_rollback_batch);
    return;
  }

  auto finished = std::move(streaming_rollback_jobs_.front());
  streaming_rollback_jobs_.pop_front();
  finished->reader.close();
  auto unlink_status = td::unlink(finished->path);
  LOG_IF(WARNING, unlink_status.is_error())
      << "failed to unlink streaming-import rollback manifest " << finished->path << ": " << unlink_status;
  cell_db_statistics_.streaming_import_rollback_jobs_finished_++;
  cell_db_statistics_.streaming_import_rollback_cells_processed_ += finished->cells_processed;
  cell_db_statistics_.streaming_import_rollback_cells_erased_ += finished->cells_erased;
  LOG(WARNING) << "CellDbIn rolled back streaming import manifest " << finished->path
               << " reason=\"" << finished->reason << "\""
               << " processed=" << finished->cells_processed << "/" << finished->cells
               << " erased=" << finished->cells_erased
               << " batches=" << finished->batches
               << " bytes=" << finished->bytes_processed << "/" << finished->bytes;
  if (!opts_->get_celldb_in_memory()) {
    auto refresh_status = refresh_loader_after_celldb_mutation("drain_streaming_import_rollback_batch");
    if (refresh_status.is_error()) {
      auto refresh_error = refresh_status.move_as_error().to_string();
      LOG(ERROR) << "CellDbIn::drain_streaming_import_rollback_batch: " << refresh_error;
      if (finished->resolve_import_promise) {
        finished->promise_error = td::Status::Error(PSTRING()
                                                    << finished->promise_error
                                                    << "; rollback completed but CellDb loader refresh failed: "
                                                    << refresh_error);
      }
    }
  }
  if (finished->resume_gc_after) {
    resume_gc_for_import();
  }
  if (finished->resolve_import_promise) {
    finished->promise.set_error(std::move(finished->promise_error));
  }
  if (!streaming_rollback_jobs_.empty()) {
    td::actor::send_closure(actor_id(this), &CellDbIn::drain_streaming_import_rollback_batch);
  } else {
    release_db();
  }
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
