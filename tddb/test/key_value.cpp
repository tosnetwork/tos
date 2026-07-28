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
#include <cstdlib>

#include "td/db/KeyValue.h"
#include "td/db/KeyValueAsync.h"
#include "td/db/RocksDb.h"
#include "td/utils/UInt.h"
#include "td/utils/benchmark.h"
#include "td/utils/buffer.h"
#include "td/utils/optional.h"
#include "td/utils/tests.h"

namespace {

td::uint64 rocksdb_memory_stat(const std::string &stats, td::Slice name) {
  auto prefix = name.str() + "=";
  auto begin = stats.find(prefix);
  CHECK(begin != std::string::npos);
  begin += prefix.size();
  auto end = stats.find(' ', begin);
  auto value = stats.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
  return td::to_integer_safe<td::uint64>(value).move_as_ok();
}

void write_batches(td::RocksDb &db, size_t batches, size_t entries_per_batch, size_t value_size) {
  std::string value(value_size, 'x');
  for (size_t batch = 0; batch < batches; ++batch) {
    db.begin_write_batch().ensure();
    for (size_t entry = 0; entry < entries_per_batch; ++entry) {
      db.set(PSLICE() << batch << ":" << entry, value).ensure();
    }
    db.commit_write_batch().ensure();
  }
}

}  // namespace

namespace {
// Fake reader used to verify PrefixedKeyValueReader::get_multi forwards
// each key with the correct, distinct prefix. The old implementation stored
// Slices pointing into PSLICE() temporaries reused from a stack allocator
// arena, so by the time get_multi ran, every entry silently aliased the last
// key's bytes instead of its own.
class FakeKeyValueReader : public td::KeyValueReader {
 public:
  td::Result<GetStatus> get(td::Slice key, std::string &value) override {
    value = key.str();
    return GetStatus::Ok;
  }
  td::Result<std::vector<GetStatus>> get_multi(td::Span<td::Slice> keys, std::vector<std::string> *values) override {
    last_keys_.clear();
    values->clear();
    std::vector<GetStatus> statuses;
    for (auto &key : keys) {
      last_keys_.push_back(key.str());
      values->push_back(key.str());
      statuses.push_back(GetStatus::Ok);
    }
    return statuses;
  }
  td::Result<size_t> count(td::Slice prefix) override {
    return 0;
  }

  std::vector<std::string> last_keys_;
};
}  // namespace

TEST(KeyValue, PrefixedGetMulti) {
  auto fake = std::make_shared<FakeKeyValueReader>();
  td::PrefixedKeyValueReader reader(fake, "pfx:");

  std::vector<std::string> key_storage = {"aaa", "bbb", "ccc", "ddd"};
  std::vector<td::Slice> keys;
  for (auto &k : key_storage) {
    keys.push_back(k);
  }

  std::vector<std::string> values;
  auto r_statuses = reader.get_multi(keys, &values);
  r_statuses.ensure();
  auto statuses = r_statuses.move_as_ok();

  ASSERT_EQ(key_storage.size(), fake->last_keys_.size());
  ASSERT_EQ(key_storage.size(), values.size());
  ASSERT_EQ(key_storage.size(), statuses.size());
  for (size_t i = 0; i < key_storage.size(); i++) {
    std::string expected = "pfx:" + key_storage[i];
    ASSERT_EQ(expected, fake->last_keys_[i]);
    ASSERT_EQ(expected, values[i]);
    ASSERT_EQ(td::int32(td::KeyValueReader::GetStatus::Ok), td::int32(statuses[i]));
  }
}

TEST(KeyValue, simple) {
  td::Slice db_name = "testdb";
  td::RocksDb::destroy(db_name).ignore();

  std::unique_ptr<td::KeyValue> kv = std::make_unique<td::RocksDb>(td::RocksDb::open(db_name.str()).move_as_ok());
  auto set_value = [&](td::Slice key, td::Slice value) {
    kv->begin_transaction();
    kv->set(key, value);
    kv->commit_transaction();
  };
  auto ensure_value = [&](td::Slice key, td::Slice value) {
    std::string kv_value;
    auto status = kv->get(key, kv_value).move_as_ok();
    ASSERT_EQ(td::int32(status), td::int32(td::KeyValue::GetStatus::Ok));
    ASSERT_EQ(kv_value, value);
  };
  auto ensure_no_value = [&](td::Slice key) {
    std::string kv_value;
    auto status = kv->get(key, kv_value).move_as_ok();
    ASSERT_EQ(td::int32(status), td::int32(td::KeyValue::GetStatus::NotFound));
  };

  ensure_no_value("A");
  set_value("A", "HELLO");
  ensure_value("A", "HELLO");

  td::UInt128 x;
  std::fill(td::as_mutable_slice(x).begin(), td::as_mutable_slice(x).end(), '1');
  x.raw[5] = 0;
  set_value(as_slice(x), as_slice(x));
  ensure_value(as_slice(x), as_slice(x));

  kv.reset();
  td::RocksDbOptions options;
  options.snapshot_statistics = std::make_shared<td::RocksDbSnapshotStatistics>();
  kv = std::make_unique<td::RocksDb>(td::RocksDb::open(db_name.str(), options).move_as_ok());
  ensure_value("A", "HELLO");
  ensure_value(as_slice(x), as_slice(x));

  CHECK(!options.snapshot_statistics->oldest_snapshot_timestamp());
  auto snapshot = kv->snapshot();
  CHECK(options.snapshot_statistics->oldest_snapshot_timestamp());
  auto snapshot2 = kv->snapshot();
  snapshot.reset();
  CHECK(options.snapshot_statistics->oldest_snapshot_timestamp());
  snapshot2.reset();
  CHECK(!options.snapshot_statistics->oldest_snapshot_timestamp());
};

TEST(KeyValue, async_simple) {
  td::Slice db_name = "testdb";
  td::RocksDb::destroy(db_name).ignore();

  td::actor::Scheduler scheduler({6});
  auto watcher = td::create_shared_destructor([] { td::actor::SchedulerContext::get().stop(); });

  class Worker : public td::actor::Actor {
   public:
    Worker(std::shared_ptr<td::Destructor> watcher, std::string db_name)
        : watcher_(std::move(watcher)), db_name_(std::move(db_name)) {
    }
    void start_up() override {
      loop();
    }
    void tear_down() override {
    }
    void loop() override {
      if (!kv_) {
        kv_ = td::KeyValueAsync<td::UInt128, td::BufferSlice>(
            std::make_unique<td::RocksDb>(td::RocksDb::open(db_name_).move_as_ok()));
        set_start_at_ = td::Timestamp::now();
      }
      if (next_set_ && next_set_.is_in_past()) {
        for (size_t i = 0; i < 10 && left_cnt_ > 0; i++, left_cnt_--) {
          do_set();
        }
        if (left_cnt_ > 0) {
          next_set_ = td::Timestamp::in(0.001);
          alarm_timestamp() = next_set_;
        } else {
          next_set_ = td::Timestamp::never();
          set_finish_at_ = td::Timestamp::now();
        }
      }
    }

   private:
    std::shared_ptr<td::Destructor> watcher_;
    td::optional<td::KeyValueAsync<td::UInt128, td::BufferSlice>> kv_;
    std::string db_name_;
    int left_cnt_ = 10000;
    int pending_cnt_ = left_cnt_;
    td::Timestamp next_set_ = td::Timestamp::now();
    td::Timestamp set_start_at_;
    td::Timestamp set_finish_at_;

    void do_set() {
      td::UInt128 key;
      td::Random::secure_bytes(td::as_mutable_slice(key));
      td::BufferSlice data(1024);
      td::Random::secure_bytes(as_slice(data));
      kv_.value().set(key, std::move(data), [actor_id = actor_id(this)](td::Result<td::Unit> res) {
        res.ensure();
        send_closure(actor_id, &Worker::on_stored);
      });
    }

    void on_stored() {
      pending_cnt_--;
      if (pending_cnt_ == 0) {
        auto now = td::Timestamp::now();
        LOG(ERROR) << (now.at() - set_finish_at_.at());
        LOG(ERROR) << (set_finish_at_.at() - set_start_at_.at());
        stop();
      }
    }
  };

  scheduler.run_in_context([watcher = std::move(watcher), &db_name]() mutable {
    td::actor::create_actor<Worker>("Worker", watcher, db_name.str()).release();
    watcher.reset();
  });

  scheduler.run();
};

class KeyValueBenchmark : public td::Benchmark {
 public:
  std::string get_description() const override {
    return "kv transation benchmark";
  }

  void start_up() override {
    td::RocksDb::destroy("ttt");
    db_ = td::RocksDb::open("ttt").move_as_ok();
  }
  void tear_down() override {
    db_ = {};
  }
  void run(int n) override {
    for (int i = 0; i < n; i++) {
      db_.value().begin_transaction();
      db_.value().set(PSLICE() << i, PSLICE() << i);
      db_.value().commit_transaction();
    }
  }

 private:
  td::optional<td::RocksDb> db_;
};

TEST(KeyValue, RocksDbMemoryBounds) {
  constexpr size_t write_buffer_size = 64 << 10;
  constexpr size_t global_write_buffer_size = 512 << 10;

  td::RocksDb::destroy("testdb-memory-nontx").ignore();
  td::RocksDb::destroy("testdb-memory-tx").ignore();
  auto write_buffer_manager = td::RocksDb::create_write_buffer_manager(global_write_buffer_size, true);
  td::RocksDbOptions no_transaction_options;
  no_transaction_options.no_transactions = true;
  no_transaction_options.write_buffer_size = write_buffer_size;
  no_transaction_options.write_buffer_manager = write_buffer_manager;
  {
    auto no_transaction_db = td::RocksDb::open("testdb-memory-nontx", std::move(no_transaction_options)).move_as_ok();

    write_batches(no_transaction_db, 32, 16, 1024);
    no_transaction_db.flush().ensure();
    auto no_transaction_stats = no_transaction_db.memory_stats();
    ASSERT_TRUE(rocksdb_memory_stat(no_transaction_stats, "all_memtable_reserved_bytes") < (512 << 10));
    ASSERT_TRUE(rocksdb_memory_stat(no_transaction_stats, "write_buffer_manager_bytes") <
                (2 * global_write_buffer_size));
    ASSERT_EQ(rocksdb_memory_stat(no_transaction_stats, "write_buffer_manager_limit_bytes"), global_write_buffer_size);

    td::RocksDbOptions transaction_options;
    transaction_options.write_buffer_size = write_buffer_size;
    transaction_options.max_write_buffer_size_to_maintain = static_cast<td::int64>(write_buffer_size);
    transaction_options.write_buffer_manager = write_buffer_manager;
    auto transaction_db = td::RocksDb::open("testdb-memory-tx", std::move(transaction_options)).move_as_ok();

    std::string value(1024, 'y');
    for (size_t batch = 0; batch < 32; ++batch) {
      transaction_db.begin_transaction().ensure();
      for (size_t entry = 0; entry < 16; ++entry) {
        transaction_db.set(PSLICE() << batch << ":" << entry, value).ensure();
      }
      transaction_db.commit_transaction().ensure();
    }
    transaction_db.flush().ensure();
    auto transaction_stats = transaction_db.memory_stats();
    ASSERT_TRUE(rocksdb_memory_stat(transaction_stats, "all_memtable_reserved_bytes") < (1024 << 10));
    ASSERT_EQ(rocksdb_memory_stat(transaction_stats, "write_buffer_manager_limit_bytes"), global_write_buffer_size);
    ASSERT_TRUE(rocksdb_memory_stat(transaction_stats, "write_buffer_manager_bytes") < (2 * global_write_buffer_size));
  }

  td::RocksDb::destroy("testdb-memory-nontx").ensure();
  td::RocksDb::destroy("testdb-memory-tx").ensure();
}

TEST(KeyValue, RocksDbCriticalMemoryDomain) {
  const char *configured_limit = std::getenv("TOS_ROCKSDB_CRITICAL_WRITE_BUFFER_SIZE");
  if (configured_limit == nullptr) {
    return;
  }
  const auto expected_limit = td::to_integer_safe<td::uint64>(td::Slice(configured_limit)).move_as_ok();
  const char *configured_global_limit = std::getenv("TOS_ROCKSDB_GLOBAL_WRITE_BUFFER_SIZE");

  td::RocksDb::destroy("testdb-memory-critical").ignore();
  td::RocksDb::destroy("testdb-memory-background").ignore();

  {
    td::RocksDbOptions critical_options;
    critical_options.no_transactions = true;
    critical_options.critical_write_path = true;
    auto critical_db = td::RocksDb::open("testdb-memory-critical", std::move(critical_options)).move_as_ok();
    const auto critical_stats = critical_db.memory_stats();
    ASSERT_TRUE(critical_stats.find("write_buffer_manager_domain=critical") != std::string::npos);
    ASSERT_EQ(rocksdb_memory_stat(critical_stats, "write_buffer_manager_limit_bytes"), expected_limit);

    td::RocksDbOptions background_options;
    background_options.no_transactions = true;
    auto background_db = td::RocksDb::open("testdb-memory-background", std::move(background_options)).move_as_ok();
    const auto background_stats = background_db.memory_stats();
    ASSERT_TRUE(background_stats.find("write_buffer_manager_domain=critical") == std::string::npos);
    if (configured_global_limit != nullptr) {
      const auto expected_global_limit =
          td::to_integer_safe<td::uint64>(td::Slice(configured_global_limit)).move_as_ok();
      ASSERT_TRUE(background_stats.find("write_buffer_manager_domain=global") != std::string::npos);
      ASSERT_EQ(rocksdb_memory_stat(background_stats, "write_buffer_manager_limit_bytes"), expected_global_limit);
    }
  }
  td::RocksDb::destroy("testdb-memory-critical").ensure();
  td::RocksDb::destroy("testdb-memory-background").ensure();
}

TEST(KeyValue, Bench) {
  td::bench(KeyValueBenchmark());
}

TEST(KeyValue, Stress) {
  return;
  td::Slice db_name = "testdb";
  size_t N = 20;
  auto db_name_i = [&](size_t i) { return PSTRING() << db_name << i; };
  for (size_t i = 0; i < N; i++) {
    td::RocksDb::destroy(db_name_i(i)).ignore();
  }

  td::actor::Scheduler scheduler({6});
  auto watcher = td::create_shared_destructor([] { td::actor::SchedulerContext::get().stop(); });

  class Worker : public td::actor::Actor {
   public:
    Worker(std::shared_ptr<td::Destructor> watcher, std::string db_name)
        : watcher_(std::move(watcher)), db_name_(std::move(db_name)) {
    }
    void start_up() override {
      loop();
    }
    void tear_down() override {
    }
    void loop() override {
      if (stat_at_.is_in_past()) {
        stat_at_ = td::Timestamp::in(10);
        LOG(ERROR) << db_->stats();
      }
      if (!kv_) {
        db_ = std::make_shared<td::RocksDb>(td::RocksDb::open(db_name_).move_as_ok());
        kv_ = td::KeyValueAsync<td::UInt128, td::BufferSlice>(db_);
        set_start_at_ = td::Timestamp::now();
      }
      if (next_set_ && next_set_.is_in_past()) {
        for (size_t i = 0; i < 10 && left_cnt_ > 0; i++, left_cnt_--) {
          do_set();
        }
        if (left_cnt_ > 0) {
          next_set_ = td::Timestamp::in(0.01);
          alarm_timestamp() = next_set_;
        } else {
          next_set_ = td::Timestamp::never();
          set_finish_at_ = td::Timestamp::now();
        }
      }
    }

   private:
    std::shared_ptr<td::Destructor> watcher_;
    std::shared_ptr<td::RocksDb> db_;
    td::optional<td::KeyValueAsync<td::UInt128, td::BufferSlice>> kv_;
    std::string db_name_;
    int left_cnt_ = 1000000000;
    int pending_cnt_ = left_cnt_;
    td::Timestamp next_set_ = td::Timestamp::now();
    td::Timestamp set_start_at_;
    td::Timestamp set_finish_at_;
    td::Timestamp stat_at_ = td::Timestamp::in(10);

    void do_set() {
      td::UInt128 key = td::UInt128::zero();
      td::Random::secure_bytes(td::as_mutable_slice(key).substr(0, 1));
      td::BufferSlice data(1024);
      td::Random::secure_bytes(as_slice(data));
      kv_.value().set(key, std::move(data), [actor_id = actor_id(this)](td::Result<td::Unit> res) {
        res.ensure();
        send_closure(actor_id, &Worker::on_stored);
      });
    }

    void on_stored() {
      pending_cnt_--;
      if (pending_cnt_ == 0) {
        auto now = td::Timestamp::now();
        LOG(ERROR) << (now.at() - set_finish_at_.at());
        LOG(ERROR) << (set_finish_at_.at() - set_start_at_.at());
        stop();
      }
    }
  };
  scheduler.run_in_context([watcher = std::move(watcher), &db_name_i, &N]() mutable {
    for (size_t i = 0; i < N; i++) {
      td::actor::create_actor<Worker>("Worker", watcher, db_name_i(i)).release();
    }
    watcher.reset();
  });

  scheduler.run();
}
