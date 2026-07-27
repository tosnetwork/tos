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

// FIXME: Remove once RocksDB stops triggering this warning.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-int-float-conversion"
#include "rocksdb/db.h"
#pragma GCC diagnostic pop

#include "rocksdb/filter_policy.h"
#include "rocksdb/statistics.h"
#include "rocksdb/table.h"
#include "rocksdb/utilities/optimistic_transaction_db.h"
#include "rocksdb/utilities/transaction.h"
#include "rocksdb/write_batch.h"
#include "rocksdb/write_buffer_manager.h"
#include "td/db/RocksDb.h"
#include "td/utils/memory-tracker.h"
#include "td/utils/misc.h"

#include <cstdlib>

namespace td {
struct RocksDb::MemoryDiagnosticsState {
  std::atomic<td::uint64> next_log_at{0};
};

namespace {
struct ProcessRocksDbMemoryOptions {
  td::optional<size_t> write_buffer_size;
  td::optional<td::int64> transaction_history_size;
  std::shared_ptr<rocksdb::WriteBufferManager> write_buffer_manager;
};

td::optional<size_t> positive_size_from_env(const char *name) {
  const char *value = std::getenv(name);
  if (value == nullptr) {
    return {};
  }
  auto parsed = td::to_integer_safe<size_t>(td::Slice(value));
  if (parsed.is_error() || parsed.ok() == 0) {
    LOG(WARNING) << "Ignoring invalid " << name << "=" << value << "; expected a positive byte count";
    return {};
  }
  return parsed.move_as_ok();
}

bool bool_from_env(const char *name, bool default_value) {
  const char *value = std::getenv(name);
  if (value == nullptr) {
    return default_value;
  }
  auto parsed = td::to_integer_safe<int>(td::Slice(value));
  if (parsed.is_error() || (parsed.ok() != 0 && parsed.ok() != 1)) {
    LOG(WARNING) << "Ignoring invalid " << name << "=" << value << "; expected 0 or 1";
    return default_value;
  }
  return parsed.ok() == 1;
}

const ProcessRocksDbMemoryOptions &process_memory_options() {
  static const ProcessRocksDbMemoryOptions options = [] {
    ProcessRocksDbMemoryOptions result;
    result.write_buffer_size = positive_size_from_env("TOS_ROCKSDB_WRITE_BUFFER_SIZE");
    auto transaction_history_size = positive_size_from_env("TOS_ROCKSDB_TRANSACTION_HISTORY_SIZE");
    if (transaction_history_size) {
      result.transaction_history_size = static_cast<td::int64>(transaction_history_size.value());
    }
    auto global_write_buffer_size = positive_size_from_env("TOS_ROCKSDB_GLOBAL_WRITE_BUFFER_SIZE");
    if (global_write_buffer_size) {
      auto allow_stall = bool_from_env("TOS_ROCKSDB_GLOBAL_WRITE_BUFFER_ALLOW_STALL", true);
      result.write_buffer_manager = std::make_shared<rocksdb::WriteBufferManager>(
          global_write_buffer_size.value(), std::shared_ptr<rocksdb::Cache>(), allow_stall);
      LOG(WARNING) << "Enabled process-wide RocksDB write-buffer budget: limit="
                   << global_write_buffer_size.value() << " allow_stall=" << allow_stall;
    }
    if (result.write_buffer_size || result.transaction_history_size) {
      LOG(WARNING) << "Enabled RocksDB memory overrides: write_buffer_size="
                   << (result.write_buffer_size ? result.write_buffer_size.value() : 0)
                   << " transaction_history_size="
                   << (result.transaction_history_size ? result.transaction_history_size.value() : 0);
    }
    return result;
  }();
  return options;
}

static Status from_rocksdb(const rocksdb::Status &status) {
  if (status.ok()) {
    return Status::OK();
  }
  return Status::Error(status.ToString());
}
static Slice from_rocksdb(rocksdb::Slice slice) {
  return Slice(slice.data(), slice.size());
}
static rocksdb::Slice to_rocksdb(Slice slice) {
  return rocksdb::Slice(slice.data(), slice.size());
}
}  // namespace

Status RocksDb::destroy(Slice path) {
  return from_rocksdb(rocksdb::DestroyDB(path.str(), {}));
}

RocksDb::RocksDb(RocksDb &&) = default;
RocksDb &RocksDb::operator=(RocksDb &&) = default;

RocksDb::~RocksDb() {
  if (!db_) {
    return;
  }
  end_snapshot().ensure();
}

RocksDb RocksDb::clone() const {
  return transaction_db_ ? RocksDb{transaction_db_, options_, memory_diagnostics_}
                         : RocksDb{db_, options_, memory_diagnostics_};
}

Result<RocksDb> RocksDb::open(std::string path, RocksDbOptions options) {
  rocksdb::Options db_options;
  db_options.merge_operator = options.merge_operator;
  db_options.compaction_filter = options.compaction_filter;

  const auto &process_options = process_memory_options();
  if (!options.write_buffer_size && process_options.write_buffer_size) {
    options.write_buffer_size = process_options.write_buffer_size;
  }
  if (!options.no_transactions && !options.max_write_buffer_size_to_maintain &&
      process_options.transaction_history_size) {
    options.max_write_buffer_size_to_maintain = process_options.transaction_history_size;
  }
  if (!options.write_buffer_manager && process_options.write_buffer_manager) {
    options.write_buffer_manager = process_options.write_buffer_manager;
  }
  if (options.write_buffer_size) {
    db_options.write_buffer_size = options.write_buffer_size.value();
  }
  if (options.max_write_buffer_size_to_maintain) {
    if (!options.no_transactions && options.max_write_buffer_size_to_maintain.value() <= 0) {
      return Status::Error("OptimisticTransactionDB requires a positive max_write_buffer_size_to_maintain; "
                           "use no_transactions=true to disable transaction history");
    }
    db_options.max_write_buffer_size_to_maintain = options.max_write_buffer_size_to_maintain.value();
  }
  db_options.write_buffer_manager = options.write_buffer_manager;

  static auto default_cache = rocksdb::NewLRUCache(1 << 30);
  if (!options.no_block_cache && options.block_cache == nullptr) {
    options.block_cache = default_cache;
  }

  rocksdb::BlockBasedTableOptions table_options;
  if (options.no_block_cache) {
    table_options.no_block_cache = true;
  } else {
    table_options.block_cache = options.block_cache;
  }
  if (options.enable_bloom_filter) {
    table_options.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10, false));
    if (options.two_level_index_and_filter) {
      table_options.index_type = rocksdb::BlockBasedTableOptions::IndexType::kTwoLevelIndexSearch;
      table_options.partition_filters = true;
      table_options.cache_index_and_filter_blocks = true;
      table_options.pin_l0_filter_and_index_blocks_in_cache = true;
    }
  }
  db_options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_options));

  // table_options.block_align = true;
  if (options.no_reads) {
    db_options.memtable_factory.reset(new rocksdb::VectorRepFactory());
    db_options.allow_concurrent_memtable_write = false;
  }

  db_options.wal_recovery_mode = rocksdb::WALRecoveryMode::kTolerateCorruptedTailRecords;
  db_options.use_direct_reads = options.use_direct_reads;
  db_options.manual_wal_flush = true;
  db_options.create_if_missing = true;
  db_options.max_background_compactions = 4;
  db_options.max_background_flushes = 2;
  db_options.bytes_per_sync = 1 << 20;
  db_options.writable_file_max_buffer_size = 2 << 14;
  db_options.statistics = options.statistics;
  db_options.max_log_file_size = 100 << 20;
  db_options.keep_log_file_num = 1;

  if (options.experimental) {
    // Place your experimental options here
  }

  if (options.no_transactions) {
    rocksdb::DB *db{nullptr};
    TRY_STATUS(from_rocksdb(rocksdb::DB::Open(db_options, std::move(path), &db)));
    return RocksDb(std::shared_ptr<rocksdb::DB>(db), std::move(options));
  } else {
    rocksdb::OptimisticTransactionDB *db{nullptr};
    rocksdb::ColumnFamilyOptions cf_options(db_options);
    std::vector<rocksdb::ColumnFamilyDescriptor> column_families;
    column_families.push_back(rocksdb::ColumnFamilyDescriptor(rocksdb::kDefaultColumnFamilyName, cf_options));
    std::vector<rocksdb::ColumnFamilyHandle *> handles;
    rocksdb::OptimisticTransactionDBOptions occ_options;
    occ_options.validate_policy = rocksdb::OccValidationPolicy::kValidateSerial;
    TRY_STATUS(from_rocksdb(rocksdb::OptimisticTransactionDB::Open(db_options, occ_options, std::move(path),
                                                                   column_families, &handles, &db)));
    CHECK(handles.size() == 1);
    // i can delete the handle since DBImpl is always holding a reference to
    // default column family
    delete handles[0];
    return RocksDb(std::shared_ptr<rocksdb::OptimisticTransactionDB>(db), std::move(options));
  }
}

std::shared_ptr<rocksdb::Statistics> RocksDb::create_statistics() {
  return rocksdb::CreateDBStatistics();
}

std::string RocksDb::statistics_to_string(const std::shared_ptr<rocksdb::Statistics> &statistics) {
  return statistics->ToString();
}

void RocksDb::reset_statistics(const std::shared_ptr<rocksdb::Statistics> &statistics) {
  statistics->Reset();
}

std::shared_ptr<rocksdb::Cache> RocksDb::create_cache(size_t capacity) {
  return rocksdb::NewLRUCache(capacity);
}

std::shared_ptr<rocksdb::WriteBufferManager> RocksDb::create_write_buffer_manager(size_t capacity,
                                                                                  bool allow_stall) {
  return std::make_shared<rocksdb::WriteBufferManager>(capacity, nullptr, allow_stall);
}

std::unique_ptr<KeyValueReader> RocksDb::snapshot() {
  auto res = std::make_unique<RocksDb>(clone());
  res->begin_snapshot().ensure();
  return std::move(res);
}

std::string RocksDb::stats() const {
  std::string out;
  db_->GetProperty("rocksdb.stats", &out);
  //db_->GetProperty("rocksdb.cur-size-all-mem-tables", &out);
  return out;
}

std::string RocksDb::memory_stats() const {
  if (!db_) {
    return "";
  }
  struct Property {
    const char *name;
    const char *label;
  };
  static constexpr Property properties[] = {
      {"rocksdb.cur-size-active-mem-table", "active_memtable_bytes"},
      {"rocksdb.cur-size-all-mem-tables", "all_memtable_bytes"},
      {"rocksdb.size-all-mem-tables", "all_memtable_reserved_bytes"},
      {"rocksdb.num-immutable-mem-table", "immutable_memtables"},
      {"rocksdb.estimate-table-readers-mem", "table_readers_bytes"},
      {"rocksdb.block-cache-usage", "block_cache_bytes"},
      {"rocksdb.block-cache-pinned-usage", "block_cache_pinned_bytes"},
  };
  td::StringBuilder builder;
  builder << "db=" << db_->GetName();
  for (const auto &property : properties) {
    td::uint64 value = 0;
    if (db_->GetIntProperty(property.name, &value)) {
      builder << " " << property.label << "=" << value;
    }
  }
  if (options_.write_buffer_manager && options_.write_buffer_manager->enabled()) {
    builder << " write_buffer_manager_bytes=" << options_.write_buffer_manager->memory_usage()
            << " write_buffer_manager_mutable_bytes="
            << options_.write_buffer_manager->mutable_memtable_memory_usage()
            << " write_buffer_manager_limit_bytes=" << options_.write_buffer_manager->buffer_size();
  }
  return builder.as_cslice().str();
}

void RocksDb::maybe_log_memory_stats() const {
  if (!memory_tracker_enabled() || !memory_diagnostics_) {
    return;
  }
  auto now = static_cast<td::uint64>(td::Time::now());
  auto next = memory_diagnostics_->next_log_at.load(std::memory_order_relaxed);
  if (now < next ||
      !memory_diagnostics_->next_log_at.compare_exchange_strong(next, now + 60, std::memory_order_relaxed)) {
    return;
  }
  auto current = memory_stats();
  if (!current.empty()) {
    LOG(WARNING) << "MEMORY_DIAGNOSTICS rocksdb " << current;
  }
}

Result<RocksDb::GetStatus> RocksDb::get(Slice key, std::string &value) {
  if (options_.no_reads) {
    return td::Status::Error("trying to read from write-only database");
  }
  rocksdb::Status status;
  if (snapshot_) {
    rocksdb::ReadOptions options;
    options.snapshot = snapshot_.get();
    status = db_->Get(options, to_rocksdb(key), &value);
  } else if (transaction_) {
    status = transaction_->Get({}, to_rocksdb(key), &value);
  } else {
    status = db_->Get({}, to_rocksdb(key), &value);
  }
  if (status.ok()) {
    return GetStatus::Ok;
  }
  if (status.code() == rocksdb::Status::kNotFound) {
    return GetStatus::NotFound;
  }
  return from_rocksdb(status);
}

Result<std::vector<RocksDb::GetStatus>> RocksDb::get_multi(td::Span<Slice> keys, std::vector<std::string> *values) {
  std::vector<rocksdb::Status> statuses(keys.size());
  std::vector<rocksdb::Slice> keys_rocksdb;
  keys_rocksdb.reserve(keys.size());
  for (auto &key : keys) {
    keys_rocksdb.push_back(to_rocksdb(key));
  }
  std::vector<rocksdb::PinnableSlice> values_rocksdb(keys.size());
  rocksdb::ReadOptions options;
  if (snapshot_) {
    options.snapshot = snapshot_.get();
    db_->MultiGet(options, db_->DefaultColumnFamily(), keys_rocksdb.size(), keys_rocksdb.data(), values_rocksdb.data(),
                  statuses.data());
  } else if (transaction_) {
    transaction_->MultiGet(options, db_->DefaultColumnFamily(), keys_rocksdb.size(), keys_rocksdb.data(),
                           values_rocksdb.data(), statuses.data());
  } else {
    db_->MultiGet(options, db_->DefaultColumnFamily(), keys_rocksdb.size(), keys_rocksdb.data(), values_rocksdb.data(),
                  statuses.data());
  }
  std::vector<GetStatus> res(statuses.size());
  values->resize(statuses.size());
  for (size_t i = 0; i < statuses.size(); i++) {
    auto &status = statuses[i];
    if (status.ok()) {
      res[i] = GetStatus::Ok;
      values->at(i) = values_rocksdb[i].ToString();
    } else if (status.code() == rocksdb::Status::kNotFound) {
      res[i] = GetStatus::NotFound;
      values->at(i) = "";
    } else {
      return from_rocksdb(status);
    }
  }
  return res;
}

Status RocksDb::set(Slice key, Slice value) {
  maybe_log_memory_stats();
  if (write_batch_) {
    return from_rocksdb(write_batch_->Put(to_rocksdb(key), to_rocksdb(value)));
  }
  if (transaction_) {
    return from_rocksdb(transaction_->Put(to_rocksdb(key), to_rocksdb(value)));
  }
  return from_rocksdb(db_->Put({}, to_rocksdb(key), to_rocksdb(value)));
}
Status RocksDb::merge(Slice key, Slice value) {
  maybe_log_memory_stats();
  if (write_batch_) {
    return from_rocksdb(write_batch_->Merge(to_rocksdb(key), to_rocksdb(value)));
  }
  if (transaction_) {
    return from_rocksdb(transaction_->Merge(to_rocksdb(key), to_rocksdb(value)));
  }
  return from_rocksdb(db_->Merge({}, to_rocksdb(key), to_rocksdb(value)));
}
Status RocksDb::run_gc() {
  return from_rocksdb(db_->CompactRange({}, nullptr, nullptr));
}

Status RocksDb::erase(Slice key) {
  maybe_log_memory_stats();
  if (write_batch_) {
    return from_rocksdb(write_batch_->Delete(to_rocksdb(key)));
  }
  if (transaction_) {
    return from_rocksdb(transaction_->Delete(to_rocksdb(key)));
  }
  return from_rocksdb(db_->Delete({}, to_rocksdb(key)));
}

Result<size_t> RocksDb::count(Slice prefix) {
  if (options_.no_reads) {
    return td::Status::Error("trying to read from write-only database");
  }
  rocksdb::ReadOptions options;
  options.auto_prefix_mode = true;
  options.snapshot = snapshot_.get();
  std::unique_ptr<rocksdb::Iterator> iterator;
  if (snapshot_ || !transaction_) {
    iterator.reset(db_->NewIterator(options));
  } else {
    iterator.reset(transaction_->GetIterator(options));
  }

  size_t res = 0;
  for (iterator->Seek(to_rocksdb(prefix)); iterator->Valid(); iterator->Next()) {
    if (from_rocksdb(iterator->key()).truncate(prefix.size()) != prefix) {
      break;
    }
    res++;
  }
  if (!iterator->status().ok()) {
    return from_rocksdb(iterator->status());
  }
  return res;
}

Status RocksDb::for_each(std::function<Status(Slice, Slice)> f) {
  if (options_.no_reads) {
    return td::Status::Error("trying to read from write-only database");
  }
  rocksdb::ReadOptions options;
  options.auto_prefix_mode = true;
  options.snapshot = snapshot_.get();
  std::unique_ptr<rocksdb::Iterator> iterator;
  if (snapshot_ || !transaction_) {
    iterator.reset(db_->NewIterator(options));
  } else {
    iterator.reset(transaction_->GetIterator(options));
  }

  iterator->SeekToFirst();
  for (; iterator->Valid(); iterator->Next()) {
    auto key = from_rocksdb(iterator->key());
    auto value = from_rocksdb(iterator->value());
    TRY_STATUS(f(key, value));
  }
  if (!iterator->status().ok()) {
    return from_rocksdb(iterator->status());
  }
  return Status::OK();
}

Status RocksDb::for_each_in_range(Slice begin, Slice end, std::function<Status(Slice, Slice)> f) {
  if (options_.no_reads) {
    return td::Status::Error("trying to read from write-only database");
  }
  rocksdb::ReadOptions options;
  options.auto_prefix_mode = true;
  options.snapshot = snapshot_.get();
  std::unique_ptr<rocksdb::Iterator> iterator;
  if (snapshot_ || !transaction_) {
    iterator.reset(db_->NewIterator(options));
  } else {
    iterator.reset(transaction_->GetIterator(options));
  }

  auto comparator = rocksdb::BytewiseComparator();
  iterator->Seek(to_rocksdb(begin));
  for (; iterator->Valid(); iterator->Next()) {
    auto key = from_rocksdb(iterator->key());
    if (comparator->Compare(to_rocksdb(key), to_rocksdb(end)) >= 0) {
      break;
    }
    auto value = from_rocksdb(iterator->value());
    TRY_STATUS(f(key, value));
  }
  if (!iterator->status().ok()) {
    return from_rocksdb(iterator->status());
  }
  return td::Status::OK();
}

Status RocksDb::begin_write_batch() {
  CHECK(!transaction_);
  write_batch_ = std::make_unique<rocksdb::WriteBatch>();
  return Status::OK();
}

Status RocksDb::begin_transaction() {
  CHECK(!write_batch_);
  CHECK(transaction_db_);
  rocksdb::WriteOptions options;
  options.sync = true;
  transaction_.reset(transaction_db_->BeginTransaction(options, {}));
  return Status::OK();
}

Status RocksDb::commit_write_batch() {
  maybe_log_memory_stats();
  CHECK(write_batch_);
  auto write_batch = std::move(write_batch_);
  rocksdb::WriteOptions options;
  options.sync = true;
  return from_rocksdb(db_->Write(options, write_batch.get()));
}

Status RocksDb::commit_transaction() {
  maybe_log_memory_stats();
  CHECK(transaction_);
  auto transaction = std::move(transaction_);
  return from_rocksdb(transaction->Commit());
}

Status RocksDb::abort_write_batch() {
  CHECK(write_batch_);
  write_batch_.reset();
  return Status::OK();
}

Status RocksDb::abort_transaction() {
  CHECK(transaction_);
  transaction_.reset();
  return Status::OK();
}

Status RocksDb::flush() {
  return from_rocksdb(db_->Flush({}));
}

Status RocksDb::flush_wal(bool sync) {
  return from_rocksdb(db_->FlushWAL(sync));
}

Status RocksDb::begin_snapshot() {
  snapshot_.reset(db_->GetSnapshot());
  if (options_.snapshot_statistics) {
    options_.snapshot_statistics->begin_snapshot(snapshot_.get());
  }
  return td::Status::OK();
}

Status RocksDb::end_snapshot() {
  if (snapshot_) {
    if (options_.snapshot_statistics) {
      options_.snapshot_statistics->end_snapshot(snapshot_.get());
    }
    db_->ReleaseSnapshot(snapshot_.release());
  }
  return td::Status::OK();
}

RocksDb::RocksDb(std::shared_ptr<rocksdb::OptimisticTransactionDB> db, RocksDbOptions options,
                 std::shared_ptr<MemoryDiagnosticsState> memory_diagnostics)
    : transaction_db_{db}
    , db_(std::move(db))
    , options_(std::move(options))
    , memory_diagnostics_(memory_diagnostics ? std::move(memory_diagnostics)
                                            : std::make_shared<MemoryDiagnosticsState>()) {
}

RocksDb::RocksDb(std::shared_ptr<rocksdb::DB> db, RocksDbOptions options,
                 std::shared_ptr<MemoryDiagnosticsState> memory_diagnostics)
    : db_(std::move(db))
    , options_(std::move(options))
    , memory_diagnostics_(memory_diagnostics ? std::move(memory_diagnostics)
                                            : std::make_shared<MemoryDiagnosticsState>()) {
}

void RocksDbSnapshotStatistics::begin_snapshot(const rocksdb::Snapshot *snapshot) {
  auto lock = std::unique_lock<std::mutex>(mutex_);
  auto id = reinterpret_cast<std::uintptr_t>(snapshot);
  auto ts = td::Timestamp::now().at();
  CHECK(id_to_ts_.emplace(id, ts).second);
  CHECK(by_ts_.emplace(ts, id).second);
}

void RocksDbSnapshotStatistics::end_snapshot(const rocksdb::Snapshot *snapshot) {
  auto lock = std::unique_lock<std::mutex>(mutex_);
  auto id = reinterpret_cast<std::uintptr_t>(snapshot);
  auto it = id_to_ts_.find(id);
  CHECK(it != id_to_ts_.end());
  auto ts = it->second;
  CHECK(by_ts_.erase(std::make_pair(ts, id)) == 1u);
  CHECK(id_to_ts_.erase(id) == 1u);
}

td::Timestamp RocksDbSnapshotStatistics::oldest_snapshot_timestamp() const {
  auto lock = std::unique_lock<std::mutex>(mutex_);
  if (by_ts_.empty()) {
    return {};
  }
  return td::Timestamp::at(by_ts_.begin()->first);
}

std::string RocksDbSnapshotStatistics::to_string() const {
  td::Timestamp oldest_snapshot = oldest_snapshot_timestamp();
  double value;
  if (oldest_snapshot) {
    value = td::Timestamp::now().at() - oldest_snapshot.at();
  } else {
    value = -1;
  }
  return PSTRING() << "td.rocksdb.snapshot.oldest_snapshot_ago.seconds : " << value << "\n";
}

}  // namespace td
