/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Actor/restart regression coverage for CellDb streaming-import rollback
// manifests. These tests intentionally use the real CellDb actor wrapper
// and RocksDB-backed storage, then restart the actor against the same DB
// path so startup recovery runs through CellDbIn::start_up().

#include "validator/db/celldb.hpp"
#include "validator/state-download-buffer.h"
#include "validator/validator.h"

#include "td/actor/actor.h"
#include "td/utils/Status.h"
#include "td/utils/Time.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"

#include "vm/cells/CellBuilder.h"
#include "vm/cells/DataCell.h"
#include "vm/db/CellStorage.h"
#include "vm/db/DynamicBagOfCellsDb.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace {

#define EXPECT_TRUE(cond)                                                                              \
  do {                                                                                                 \
    if (!(cond)) {                                                                                     \
      std::fprintf(stderr, "FAIL %s:%d  expected true: %s\n", __FILE__, __LINE__, #cond);              \
      std::exit(1);                                                                                    \
    }                                                                                                  \
  } while (0)

#define EXPECT_FALSE(cond)                                                                             \
  do {                                                                                                 \
    if (cond) {                                                                                        \
      std::fprintf(stderr, "FAIL %s:%d  expected false: %s\n", __FILE__, __LINE__, #cond);             \
      std::exit(1);                                                                                    \
    }                                                                                                  \
  } while (0)

void expect_status_ok(td::Status status, const char* what) {
  if (status.is_error()) {
    std::fprintf(stderr, "FAIL %s: %s\n", what, status.to_string().c_str());
    std::exit(1);
  }
}

template <class T>
T expect_result_ok(td::Result<T> result, const char* what) {
  if (result.is_error()) {
    auto error = result.move_as_error();
    std::fprintf(stderr, "FAIL %s: %s\n", what, error.to_string().c_str());
    std::exit(1);
  }
  return result.move_as_ok();
}

std::string unique_tmp_root(td::Slice suffix) {
#if !defined(_WIN32)
  auto pid = static_cast<long long>(::getpid());
#else
  auto pid = 0;
#endif
  return std::string("/tmp/tos-test-celldb-actor-restart-") + std::to_string(pid) + "-" + suffix.str();
}

td::Ref<tos::validator::ValidatorManagerOptions> make_options() {
  auto opts = tos::validator::ValidatorManagerOptions::create(
      tos::BlockIdExt{}, tos::BlockIdExt{},
      /*allow_blockchain_init=*/false,
      /*sync_blocks_before=*/0.0,
      /*block_ttl=*/0.0,
      /*state_ttl=*/0.0,
      /*archive_ttl=*/0.0,
      /*key_proof_ttl=*/0.0,
      /*max_mempool_num=*/0,
      /*initial_sync_disabled=*/true);
  auto& writable = opts.write();
  writable.set_disable_rocksdb_stats(true);
  writable.set_celldb_compress_depth(0);
  writable.set_celldb_in_memory(false);
  writable.set_celldb_v2(false);
  writable.set_celldb_disable_bloom_filter(true);
  writable.set_permanent_celldb(false);
  writable.set_catchain_broadcast_speed_multiplier(1.0);
  return opts;
}

td::Ref<vm::DataCell> make_test_cell() {
  vm::CellBuilder cb;
  const char payload[] = "cell-db-actor-restart-rollback-regression";
  cb.store_bytes(payload, sizeof(payload) - 1);
  auto cell = cb.finalize();
  auto data_cell = td::Ref<vm::DataCell>{cell};
  EXPECT_TRUE(data_cell.not_null());
  return data_cell;
}

std::string serialize_imported_cell_value(const td::Ref<vm::DataCell>& cell) {
  EXPECT_TRUE(cell.not_null());
  return vm::CellStorer::serialize_value(/*refcnt=*/1, cell, /*as_boc=*/false);
}

bool path_exists(const std::string& path) {
  return td::stat(path).is_ok();
}

std::string write_rollback_manifest(const std::string& persistent_state_dir,
                                    const vm::Cell::Hash& hash,
                                    td::Slice serialized_value,
                                    td::Slice name) {
  expect_status_ok(td::mkpath(persistent_state_dir + "/", 0700), "mk persistent-state dir");
  auto path = persistent_state_dir + "/" + name.str() + ".celldb-rollback.test.partial";
  auto fd = expect_result_ok(td::FileFd::open(path,
                                             td::FileFd::Flags::Write |
                                                 td::FileFd::Flags::Create |
                                                 td::FileFd::Flags::Truncate),
                             "open rollback manifest");

  constexpr td::uint32 header_size = static_cast<td::uint32>(vm::Cell::hash_bytes + sizeof(td::uint32));
  std::array<char, header_size> header{};
  std::memcpy(header.data(), hash.as_slice().data(), vm::Cell::hash_bytes);
  auto len = static_cast<td::uint32>(serialized_value.size());
  std::memcpy(header.data() + vm::Cell::hash_bytes, &len, sizeof(len));
  expect_status_ok(fd.write_all(td::Slice(header.data(), header.size())), "write rollback manifest header");
  expect_status_ok(fd.write_all(serialized_value), "write rollback manifest cell value");
  expect_status_ok(fd.sync(), "sync rollback manifest");
  fd.close();
  return path;
}

void write_adopted_marker(const std::string& manifest_path, td::uint64 cells, td::uint64 bytes) {
  auto marker_path = manifest_path + ".adopted";
  auto fd = expect_result_ok(td::FileFd::open(marker_path,
                                             td::FileFd::Flags::Write |
                                                 td::FileFd::Flags::Create |
                                                 td::FileFd::Flags::Truncate),
                             "open adopted marker");
  auto payload = std::string("adopted\ncells=") + std::to_string(cells) +
                 "\nbytes=" + std::to_string(bytes) + "\n";
  expect_status_ok(fd.write_all(td::Slice(payload.data(), payload.size())), "write adopted marker");
  expect_status_ok(fd.sync(), "sync adopted marker");
  fd.close();
}

class CellDbActorSession {
 public:
  CellDbActorSession(std::string db_path, td::Ref<tos::validator::ValidatorManagerOptions> opts)
      : db_path_(std::move(db_path)), opts_(std::move(opts)), scheduler_({1}) {
    scheduler_.run_in_context([&] {
      cell_db_ = td::actor::create_actor<tos::validator::CellDb>(
          "test-celldb", td::actor::ActorId<tos::validator::RootDb>{}, db_path_, opts_);
      cell_db_id_ = cell_db_.get();
    });
  }

  CellDbActorSession(const CellDbActorSession&) = delete;
  CellDbActorSession& operator=(const CellDbActorSession&) = delete;

  ~CellDbActorSession() {
    stop();
  }

  td::Result<std::unique_ptr<tos::validator::CellDbStreamingWriter>> create_writer() {
    return ask<std::unique_ptr<tos::validator::CellDbStreamingWriter>>(
        [&](td::Promise<std::unique_ptr<tos::validator::CellDbStreamingWriter>> promise) {
          td::actor::send_closure(cell_db_id_,
                                  &tos::validator::CellDb::create_celldb_streaming_writer_unsafe_for_tests_only,
                                  std::move(promise));
        });
  }

  td::Result<std::shared_ptr<vm::CellDbReader>> get_reader() {
    return ask<std::shared_ptr<vm::CellDbReader>>(
        [&](td::Promise<std::shared_ptr<vm::CellDbReader>> promise) {
          td::actor::send_closure(cell_db_id_, &tos::validator::CellDb::get_cell_db_reader, std::move(promise));
        });
  }

  void stop() {
    if (stopped_) {
      return;
    }
    stopped_ = true;
    scheduler_.run_in_context([&] {
      cell_db_.reset();
      td::actor::SchedulerContext::get().stop();
    });
    scheduler_.run();
  }

 private:
  template <class T, class Send>
  td::Result<T> ask(Send send) {
    std::optional<td::Result<T>> result;
    scheduler_.run_in_context([&] {
      auto promise = td::PromiseCreator::lambda([&](td::Result<T> r) mutable {
        result.emplace(std::move(r));
      });
      send(std::move(promise));
    });
    run_until([&] { return result.has_value(); }, "CellDb actor promise");
    return std::move(*result);
  }

  void run_until(const std::function<bool()>& done, const char* what) {
    auto deadline = td::Timestamp::in(30.0);
    while (!done()) {
      if (deadline.is_in_past()) {
        std::fprintf(stderr, "FAIL timeout waiting for %s\n", what);
        std::exit(1);
      }
      if (!scheduler_.run(1) && !done()) {
        std::fprintf(stderr, "FAIL scheduler stopped before %s\n", what);
        std::exit(1);
      }
    }
  }

  std::string db_path_;
  td::Ref<tos::validator::ValidatorManagerOptions> opts_;
  td::actor::Scheduler scheduler_;
  td::actor::ActorOwn<tos::validator::CellDb> cell_db_;
  td::actor::ActorId<tos::validator::CellDb> cell_db_id_;
  bool stopped_ = false;
};

void store_cell_through_actor_writer(const std::string& db_path,
                                     const td::Ref<tos::validator::ValidatorManagerOptions>& opts,
                                     const td::Ref<vm::DataCell>& cell) {
  CellDbActorSession session(db_path, opts);
  auto writer = expect_result_ok(session.create_writer(), "create test CellDb streaming writer");
  expect_status_ok(writer->begin_batch(), "begin CellDb writer batch");
  expect_status_ok(writer->store_cell(cell), "store CellDb test cell");
  expect_status_ok(writer->commit_batch(), "commit CellDb writer batch");
  writer.reset();
  session.stop();
}

bool load_cell_after_actor_restart(const std::string& db_path,
                                   const td::Ref<tos::validator::ValidatorManagerOptions>& opts,
                                   const vm::Cell::Hash& hash) {
  CellDbActorSession session(db_path, opts);
  auto reader = expect_result_ok(session.get_reader(), "get CellDb reader after restart");
  auto loaded = reader->load_cell(hash.as_slice());
  session.stop();
  return loaded.is_ok() && loaded.ok().not_null() && loaded.ok()->get_hash() == hash;
}

void prepare_temp_roots(const std::string& root, std::string& db_path, std::string& persistent_state_dir) {
  td::rmrf(root).ignore();
  db_path = root + "/celldb/";
  auto tempfile_root = root + "/tmp";
  persistent_state_dir = tempfile_root + "/persistent-state";
  expect_status_ok(td::mkpath(db_path, 0700), "mk CellDb path");
  expect_status_ok(td::mkpath(persistent_state_dir + "/", 0700), "mk persistent-state path");
  tos::validator::fullnode::set_persistent_state_tempfile_dir(tempfile_root);
}

void test_restart_replays_unadopted_manifest() {
  std::printf("=== test_restart_replays_unadopted_manifest ===\n");
  std::string db_path;
  std::string persistent_state_dir;
  auto root = unique_tmp_root("unadopted");
  prepare_temp_roots(root, db_path, persistent_state_dir);

  auto opts = make_options();
  auto cell = make_test_cell();
  auto value = serialize_imported_cell_value(cell);
  store_cell_through_actor_writer(db_path, opts, cell);

  auto manifest = write_rollback_manifest(persistent_state_dir, cell->get_hash(), td::Slice(value), "state");
  EXPECT_TRUE(path_exists(manifest));

  EXPECT_FALSE(load_cell_after_actor_restart(db_path, opts, cell->get_hash()));
  EXPECT_FALSE(path_exists(manifest));

  td::rmrf(root).ignore();
}

void test_restart_skips_adopted_manifest() {
  std::printf("=== test_restart_skips_adopted_manifest ===\n");
  std::string db_path;
  std::string persistent_state_dir;
  auto root = unique_tmp_root("adopted");
  prepare_temp_roots(root, db_path, persistent_state_dir);

  auto opts = make_options();
  auto cell = make_test_cell();
  auto value = serialize_imported_cell_value(cell);
  store_cell_through_actor_writer(db_path, opts, cell);

  auto manifest = write_rollback_manifest(persistent_state_dir, cell->get_hash(), td::Slice(value), "state");
  auto marker = manifest + ".adopted";
  write_adopted_marker(manifest, /*cells=*/1, /*bytes=*/value.size());
  EXPECT_TRUE(path_exists(manifest));
  EXPECT_TRUE(path_exists(marker));

  EXPECT_TRUE(load_cell_after_actor_restart(db_path, opts, cell->get_hash()));
  EXPECT_FALSE(path_exists(manifest));
  EXPECT_FALSE(path_exists(marker));

  td::rmrf(root).ignore();
}

}  // namespace

int main() {
  std::printf("test-celldb-actor-restart: CellDb rollback manifest actor/restart regressions\n");
  test_restart_replays_unadopted_manifest();
  test_restart_skips_adopted_manifest();
  std::printf("All CellDb actor/restart rollback tests passed.\n");
  return 0;
}
