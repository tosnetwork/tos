/*
    This file is part of TOS Blockchain.
    Copyright 2025-2026 TOS Blockchain Teams
    SPDX-License-Identifier: LGPL-2.0-or-later
*/
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <dlfcn.h>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <string>

#include "td/actor/actor.h"
#include "td/db/RocksDb.h"
#include "td/db/RocksDbReadOnly.h"
#include "td/utils/Time.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "validator/block-handle.hpp"
#include "validator/db/archive-manager.hpp"
#include "validator/db/archive-slice.hpp"
#include "validator/impl/shard.hpp"
#include "validator/validator.h"
#include "vm/cells.h"

namespace tos::validator {

// Access is serialized on each production actor; no alternate manager/slice
// implementation, skipped alarm or process-exit shortcut is used.
struct ArchivePruneTestAccess {
  static void create_package(td::actor::ActorId<ArchiveManager> manager, PackageId id,
                             td::Promise<td::actor::ActorId<ArchiveSlice>> promise) {
    td::actor::send_lambda(manager, [manager, id, promise = std::move(promise)]() mutable {
      auto &self = manager.get_actor_unsafe();
      auto desc = self.get_file_desc(ShardIdFull{masterchainId}, id, id.id + 1, id.id + 1, id.id + 1, true);
      promise.set_value(desc.move_as_ok()->file_actor_id());
    });
  }

  static void prune_package(td::actor::ActorId<ArchiveManager> manager, PackageId id, bool retain_source_files,
                            td::Promise<td::Unit> promise) {
    td::actor::send_lambda(manager, [manager, id, retain_source_files, promise = std::move(promise)]() mutable {
      auto &self = manager.get_actor_unsafe();
      if (retain_source_files) {
        // Negative control: publish the real deletion metadata but keep the
        // source package on disk. A secondary must stop, never destroy it.
        auto it = self.get_file_map(id).find(id);
        CHECK(it != self.get_file_map(id).end());
        it->second.deleted = true;
        self.deleted_package(id, std::move(promise));
      } else {
        self.delete_package(id, std::move(promise));
      }
    });
  }

  static void get_slice(td::actor::ActorId<ArchiveManager> manager, PackageId id,
                        td::Promise<td::actor::ActorId<ArchiveSlice>> promise) {
    td::actor::send_lambda(manager, [manager, id, promise = std::move(promise)]() mutable {
      auto &self = manager.get_actor_unsafe();
      auto &files = self.get_file_map(id);
      auto it = files.find(id);
      CHECK(it != files.end());
      promise.set_value(it->second.file_actor_id());
    });
  }

  static void snapshot(td::actor::ActorId<ArchiveSlice> slice,
                       td::Promise<std::unique_ptr<td::KeyValueReader>> promise) {
    td::actor::send_lambda(slice, [slice, promise = std::move(promise)]() mutable {
      auto &self = slice.get_actor_unsafe();
      TRY_STATUS_PROMISE(promise, self.before_query());
      promise.set_value(self.kv_->snapshot());
    });
  }

  static void released_own_index(td::actor::ActorId<ArchiveSlice> slice, td::Promise<bool> promise) {
    td::actor::send_lambda(slice, [slice, promise = std::move(promise)]() mutable {
      auto &self = slice.get_actor_unsafe();
      promise.set_value(self.destroyed_ && self.kv_ == nullptr);
    });
  }

  static void index_closed(td::actor::ActorId<ArchiveSlice> slice, td::Promise<bool> promise) {
    td::actor::send_lambda(slice, [slice, promise = std::move(promise)]() mutable {
      auto &self = slice.get_actor_unsafe();
      promise.set_value(self.status_ == ArchiveSlice::st_closed && !self.kv_ && self.packages_.empty() &&
                        self.id_to_package_.empty() && self.active_queries_ == 0);
    });
  }

  static void make_catch_up_due(td::actor::ActorId<ArchiveSlice> slice, td::Promise<td::Unit> promise) {
    td::actor::send_lambda(slice, [slice, promise = std::move(promise)]() mutable {
      slice.get_actor_unsafe().last_catch_up_ = {};
      promise.set_value(td::Unit());
    });
  }

  static void manager_index_closed(td::actor::ActorId<ArchiveManager> manager, td::Promise<bool> promise) {
    td::actor::send_lambda(manager, [manager, promise = std::move(promise)]() mutable {
      auto &self = manager.get_actor_unsafe();
      promise.set_value(!self.index_ && self.files_.empty() && self.key_files_.empty() && self.temp_files_.empty());
    });
  }

  // (packages open, packages with a writer)
  static void package_writers(td::actor::ActorId<ArchiveSlice> slice, td::Promise<std::pair<size_t, size_t>> promise) {
    td::actor::send_lambda(slice, [slice, promise = std::move(promise)]() mutable {
      auto &self = slice.get_actor_unsafe();
      size_t with_writer = 0;
      for (const auto &package : self.packages_) {
        if (!package->writer.empty()) {
          ++with_writer;
        }
      }
      promise.set_value(std::make_pair(self.packages_.size(), with_writer));
    });
  }

  static void deletion_completed(td::actor::ActorId<ArchiveManager> manager, PackageId id, td::Promise<bool> promise) {
    td::actor::send_lambda(manager, [manager, id, promise = std::move(promise)]() mutable {
      auto &files = manager.get_actor_unsafe().get_file_map(id);
      auto it = files.find(id);
      CHECK(it != files.end());
      promise.set_value(it->second.deleted && it->second.file.empty());
    });
  }

  // Whether the manager has a live, undeleted package `id` in its map.
  static void package_live(td::actor::ActorId<ArchiveManager> manager, PackageId id, td::Promise<bool> promise) {
    td::actor::send_lambda(manager, [manager, id, promise = std::move(promise)]() mutable {
      auto &files = manager.get_actor_unsafe().get_file_map(id);
      auto it = files.find(id);
      promise.set_value(it != files.end() && !it->second.deleted && !it->second.file.empty());
    });
  }

  // Package timing samples the manager holds that no alarm has drained yet,
  // and whether its periodic alarm is armed.
  static void package_samples(td::actor::ActorId<ArchiveManager> manager,
                              td::Promise<std::pair<size_t, bool>> promise) {
    td::actor::send_lambda(manager, [manager, promise = std::move(promise)]() mutable {
      auto &self = manager.get_actor_unsafe();
      promise.set_value({self.statistics_.pending_package_samples(), static_cast<bool>(self.alarm_timestamp())});
    });
  }

  // Runs the manager's periodic statistics alarm now.
  static void run_alarm(td::actor::ActorId<ArchiveManager> manager, td::Promise<td::Unit> promise) {
    td::actor::send_lambda(manager, [manager, promise = std::move(promise)]() mutable {
      manager.get_actor_unsafe().alarm();
      promise.set_value(td::Unit());
    });
  }
};

}  // namespace tos::validator

namespace {

using namespace tos::validator;

void check(bool condition, const char *message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << std::endl;
    std::abort();
  }
}

template <class Predicate>
void pump_until(td::actor::Scheduler &scheduler, Predicate condition, const char *message) {
  const auto deadline = td::Timestamp::in(10.0);
  while (!condition() && !deadline.is_in_past()) {
    scheduler.run(0.001);
  }
  check(condition(), message);
}

template <class T, class Dispatch>
td::Result<T> request(td::actor::Scheduler &scheduler, Dispatch dispatch) {
  std::atomic<bool> done{false};
  td::Result<T> result = td::Status::Error("request has not completed");
  scheduler.run_in_context([&] {
    dispatch(td::Promise<T>([&](td::Result<T> value) {
      result = std::move(value);
      done.store(true, std::memory_order_release);
    }));
  });
  pump_until(scheduler, [&] { return done.load(std::memory_order_acquire); }, "actor request deadline");
  return result;
}

void retained_reader_control(const std::string &root) {
  const auto path = root + "/reader-control.index";
  std::unique_ptr<td::KeyValueReader> reader;
  {
    auto db = td::RocksDb::open(path).move_as_ok();
    db.set("control", "retained").ensure();
    reader = db.snapshot();
  }
  auto blocked = td::RocksDb::destroy(path);
  check(blocked.is_error(), "retained snapshot must prevent destruction");
  std::string value;
  check(reader->get("control", value).move_as_ok() == td::KeyValue::GetStatus::Ok && value == "retained",
        "negative control must retain a working reader");
  reader.reset();
  td::RocksDb::destroy(path).ensure();
  check(!std::filesystem::exists(path), "released control index must disappear");
  std::cout << "PASS: retained reader blocks destruction; release removes index" << std::endl;
}

void slice_prune(const std::string &root, bool key, bool temp, bool close_first) {
  const PackageId id{17, key, temp};
  std::filesystem::create_directories(root + id.path());
  const auto prefix = root + id.path() + id.name();
  {
    td::actor::Scheduler scheduler({2});
    td::actor::ActorOwn<ArchiveSlice> slice;
    scheduler.run_in_context([&] {
      slice = td::actor::create_actor<ArchiveSlice>("prune-test", id.id, key, temp, false, 0, root,
                                                    td::actor::ActorId<ArchiveLru>{});
      td::actor::send_closure(slice, &ArchiveSlice::open_files);
      if (close_first) {
        td::actor::send_closure(slice, &ArchiveSlice::close_files);
      }
    });
    request<td::Unit>(scheduler, [&](td::Promise<td::Unit> promise) {
      td::actor::send_closure(slice, &ArchiveSlice::destroy, std::move(promise));
    }).ensure();
    check(!std::filesystem::exists(prefix + ".pack"), "package must disappear before acknowledgement");
    check(!std::filesystem::exists(prefix + ".index"), "index must disappear before acknowledgement");
    scheduler.run_in_context([&] { slice.reset(); });
  }
  std::cout << "PASS: " << id.name() << " close_first=" << close_first << " clean scheduler teardown" << std::endl;
}

tos::BlockIdExt block_id(tos::BlockSeqno seqno) {
  return {tos::masterchainId, tos::shardIdAll, seqno, tos::RootHash::zero(), tos::FileHash::zero()};
}

// run_gc only consumes the masterchain height and timestamp in this fixture.
// No temp package is old enough to enter its shard-topology fallback.
class GcState final : public MasterchainStateQ {
 public:
  GcState() : MasterchainStateQ(block_id(60000), vm::CellBuilder{}.finalize_novm()) {
  }
  tos::UnixTime get_unix_time() const override {
    return 100004;
  }
};

void manager_prune(const std::string &root, bool async_mode) {
  auto opts = ValidatorManagerOptions::create(block_id(0), block_id(0));
  const PackageId oldest{0, false, false};
  const PackageId middle{20000, false, false};
  const PackageId newest{40000, false, false};
  const auto prefix = [&](PackageId id) { return root + id.path() + id.name(); };
  {
    td::actor::Scheduler scheduler({2});
    td::actor::ActorOwn<ArchiveManager> manager;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<ArchiveManager>("manager-prune", td::actor::ActorId<RootDb>{}, root, opts);
    });
    request<td::Unit>(scheduler, [&](td::Promise<td::Unit> promise) {
      td::actor::send_closure(manager, &ArchiveManager::set_async_mode, async_mode, std::move(promise));
    }).ensure();
    for (tos::BlockSeqno seqno : {1U, 20001U, 40001U}) {
      auto handle = BlockHandleImpl::create_empty(block_id(seqno));
      handle->set_logical_time(100000 + seqno);
      handle->set_unix_time(100000 + seqno / 20000);
      handle->set_is_key_block(false);
      // Keep the ordinary temporary copy too: get_handle succeeding after GC
      // is explicitly not accepted as proof that an archive still exists.
      request<td::Unit>(scheduler, [&](td::Promise<td::Unit> promise) {
        td::actor::send_closure(manager, &ArchiveManager::update_handle, handle, std::move(promise));
      }).ensure();
      request<td::Unit>(scheduler, [&](td::Promise<td::Unit> promise) {
        td::actor::send_closure(manager, &ArchiveManager::add_handle, handle, std::move(promise));
      }).ensure();
    }
    for (auto id : {oldest, middle, newest}) {
      check(std::filesystem::exists(prefix(id) + ".pack"), "seed package exists");
      check(std::filesystem::exists(prefix(id) + ".index"), "seed index exists");
    }
    scheduler.run_in_context([&] {
      td::actor::send_closure(manager, &ArchiveManager::run_gc, td::Ref<MasterchainState>{td::make_ref<GcState>()},
                              100004U, 1.0);
    });
    pump_until(
        scheduler,
        [&] {
          for (auto id : {oldest, middle}) {
            if (std::filesystem::exists(prefix(id) + ".pack") || std::filesystem::exists(prefix(id) + ".index")) {
              return false;
            }
          }
          return true;
        },
        "real manager TTL must remove both package and index in-process");
    check(std::filesystem::exists(prefix(newest) + ".pack"), "newest package retained");
    check(std::filesystem::exists(prefix(newest) + ".index"), "newest index retained");
    auto missing = request<td::uint64>(scheduler, [&](td::Promise<td::uint64> promise) {
      td::actor::send_closure(manager, &ArchiveManager::get_archive_id, 1U, tos::ShardIdFull{tos::masterchainId},
                              std::move(promise));
    });
    check(missing.is_error(), "pruned archive lookup must fail");
    auto temp_copy = request<BlockHandle>(scheduler, [&](td::Promise<BlockHandle> promise) {
      td::actor::send_closure(manager, &ArchiveManager::get_handle, block_id(1), std::move(promise));
    });
    check(temp_copy.is_ok(), "temporary handle copy survives archive pruning");
    scheduler.run_in_context([&] { manager.reset(); });
  }
  // A real destructor above, not a leaked scheduler or _Exit. Reopen in this
  // process: every original database owner must have released its lock.
  {
    td::actor::Scheduler scheduler({2});
    td::actor::ActorOwn<ArchiveManager> manager;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<ArchiveManager>("manager-reopen", td::actor::ActorId<RootDb>{}, root, opts);
    });
    request<td::uint64>(scheduler, [&](td::Promise<td::uint64> promise) {
      td::actor::send_closure(manager, &ArchiveManager::get_archive_id, 40001U, tos::ShardIdFull{tos::masterchainId},
                              std::move(promise));
    }).ensure();
    for (auto id : {oldest, middle}) {
      check(!std::filesystem::exists(prefix(id) + ".index"), "restart must not recreate pruned index");
    }
    scheduler.run_in_context([&] { manager.reset(); });
  }
  std::cout << "PASS: manager TTL, temp-copy control, clean teardown and same-process reopen; async=" << async_mode
            << std::endl;
}

void manager_held_reader(const std::string &root, bool shutdown_while_held) {
  const PackageId oldest{0, false, false};
  const auto prefix = root + oldest.path() + oldest.name();
  auto opts = ValidatorManagerOptions::create(block_id(0), block_id(0));
  std::unique_ptr<td::KeyValueReader> reader;
  {
    td::actor::Scheduler scheduler({2});
    td::actor::ActorOwn<ArchiveManager> manager;
    scheduler.run_in_context([&] {
      manager =
          td::actor::create_actor<ArchiveManager>("held-reader-manager", td::actor::ActorId<RootDb>{}, root, opts);
    });
    for (tos::BlockSeqno seqno : {1U, 20001U}) {
      auto handle = BlockHandleImpl::create_empty(block_id(seqno));
      handle->set_logical_time(100000 + seqno);
      handle->set_unix_time(100000 + seqno / 20000);
      handle->set_is_key_block(false);
      request<td::Unit>(scheduler, [&](td::Promise<td::Unit> promise) {
        td::actor::send_closure(manager, &ArchiveManager::add_handle, handle, std::move(promise));
      }).ensure();
    }
    auto slice = request<td::actor::ActorId<ArchiveSlice>>(scheduler, [&](td::Promise<td::actor::ActorId<ArchiveSlice>>
                                                                              promise) {
                   ArchivePruneTestAccess::get_slice(manager.get(), oldest, std::move(promise));
                 }).move_as_ok();
    reader =
        request<std::unique_ptr<td::KeyValueReader>>(scheduler,
                                                     [&](td::Promise<std::unique_ptr<td::KeyValueReader>> promise) {
                                                       ArchivePruneTestAccess::snapshot(slice, std::move(promise));
                                                     })
            .move_as_ok();
    scheduler.run_in_context([&] {
      td::actor::send_closure(manager, &ArchiveManager::run_gc, td::Ref<MasterchainState>{td::make_ref<GcState>()},
                              100004U, 1.0);
    });
    pump_until(
        scheduler, [&] { return !std::filesystem::exists(prefix + ".pack"); },
        "held-reader package must enter deletion");
    auto released = request<bool>(scheduler, [&](td::Promise<bool> promise) {
                      ArchivePruneTestAccess::released_own_index(slice, std::move(promise));
                    }).move_as_ok();
    check(released, "slice must have released its own index before the teardown barrier");
    check(std::filesystem::exists(prefix + ".index"), "retained reader must keep the index alive");
    std::string value;
    check(reader->get("status", value).move_as_ok() == td::KeyValue::GetStatus::Ok,
          "retained reader must still be usable");
    auto completed = request<bool>(scheduler, [&](td::Promise<bool> promise) {
                       ArchivePruneTestAccess::deletion_completed(manager.get(), oldest, std::move(promise));
                     }).move_as_ok();
    check(!completed, "held reader must prevent a successful deletion acknowledgement");
    if (!shutdown_while_held) {
      reader.reset();
      pump_until(
          scheduler, [&] { return !std::filesystem::exists(prefix + ".index"); },
          "releasing the actual slice reader must let GC finish");
      pump_until(
          scheduler,
          [&] {
            return request<bool>(scheduler,
                                 [&](td::Promise<bool> promise) {
                                   ArchivePruneTestAccess::deletion_completed(manager.get(), oldest,
                                                                              std::move(promise));
                                 })
                .move_as_ok();
          },
          "manager must acknowledge completed deletion");
    }
    std::cout << "BARRIER: actual slice owner released; external reader held=" << shutdown_while_held << std::endl;
    scheduler.run_in_context([&] { manager.reset(); });
  }
  if (shutdown_while_held) {
    // This is negative-control cleanup, not a claim that GC can remove a live
    // reader. Shutdown must cancel rather than falsely acknowledge deletion.
    check(std::filesystem::exists(prefix + ".index"), "shutdown must not delete a still-retained index");
    reader.reset();
    td::RocksDb::destroy(prefix + ".index").ensure();
  }
  check(!std::filesystem::exists(prefix + ".index"), "released fixture index removed");
  std::cout << "PASS: actual slice retained-reader control; shutdown_while_held=" << shutdown_while_held << std::endl;
}

void secondary_prune_lifetime(const std::string &root, bool retain_source_files) {
  auto opts = ValidatorManagerOptions::create(block_id(0), block_id(0));
  opts.write().set_disable_rocksdb_stats(true);
  opts.write().set_max_open_archive_files(128);
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<ArchiveManager> primary, secondary;
  scheduler.run_in_context([&] {
    primary = td::actor::create_actor<ArchiveManager>("primary-lifetime", td::actor::ActorId<RootDb>{}, root, opts);
  });
  std::vector<td::actor::ActorId<ArchiveSlice>> retired;
  for (unsigned round = 1; round <= 12; ++round) {
    // Exercise all three package maps without waiting for real-hour rotation.
    PackageId id{round * 20000, round % 3 == 1, round % 3 == 2};
    auto source = request<td::actor::ActorId<ArchiveSlice>>(scheduler, [&](auto promise) {
                    ArchivePruneTestAccess::create_package(primary.get(), id, std::move(promise));
                  }).move_as_ok();
    {
      auto snapshot = request<std::unique_ptr<td::KeyValueReader>>(scheduler, [&](auto promise) {
                        ArchivePruneTestAccess::snapshot(source, std::move(promise));
                      }).move_as_ok();
      std::string value;
      check(snapshot->get("status", value).move_as_ok() == td::KeyValue::GetStatus::Ok, "source index opened");
    }
    if (secondary.empty()) {
      scheduler.run_in_context([&] {
        secondary = td::actor::create_actor<ArchiveManager>("secondary-lifetime", td::actor::ActorId<RootDb>{}, root,
                                                            opts, td::DbOpenMode::db_secondary);
      });
    }
    auto catch_up = [&] {
      request<td::Unit>(scheduler, [&](auto promise) {
        td::actor::send_closure(secondary, &ArchiveManager::try_catch_up_with_primary, CatchUpMode::Force,
                                std::move(promise));
      }).ensure();
    };
    catch_up();
    auto reader = request<td::actor::ActorId<ArchiveSlice>>(scheduler, [&](auto promise) {
                    ArchivePruneTestAccess::get_slice(secondary.get(), id, std::move(promise));
                  }).move_as_ok();
    {
      auto snapshot = request<std::unique_ptr<td::KeyValueReader>>(scheduler, [&](auto promise) {
                        ArchivePruneTestAccess::snapshot(reader, std::move(promise));
                      }).move_as_ok();
      std::string value;
      check(snapshot->get("status", value).move_as_ok() == td::KeyValue::GetStatus::Ok, "secondary index opened");
    }
    check(reader.is_alive(), "secondary actor must be alive before deletion");
    const auto prefix = root + id.path() + id.name();
    auto package_before = td::read_file(prefix + ".pack").move_as_ok();
    request<td::Unit>(scheduler, [&](auto promise) {
      ArchivePruneTestAccess::prune_package(primary.get(), id, retain_source_files, std::move(promise));
    }).ensure();
    catch_up();
    retired.push_back(reader);
    pump_until(scheduler, [&] { return !reader.is_alive(); }, "deleted secondary archive actor must terminate");
    for (const auto &old : retired)
      check(!old.is_alive(), "no retired archive actors may accumulate across catch-up rounds");
    if (retain_source_files) {
      check(std::filesystem::exists(prefix + ".index"), "secondary teardown must not destroy source index");
      check(td::read_file(prefix + ".pack").move_as_ok().as_slice() == package_before.as_slice(),
            "secondary teardown must preserve source package bytes");
    } else {
      check(!std::filesystem::exists(prefix + ".pack"), "primary deletion must remove the package");
      check(!std::filesystem::exists(prefix + ".index"), "primary deletion must remove the index");
    }
    catch_up();  // Repeated tombstones must be harmless.
  }
  scheduler.run_in_context([&] {
    secondary.reset();
    primary.reset();
  });
  std::cout << "PASS: 12 secondary deletion/catch-up rounds; retired actors=0; retain_source_files="
            << retain_source_files << std::endl;
}

}  // namespace

// A reader (secondary or read-only) must never sync, or write to, the package
// files of the node it reads; the primary keeps syncing what it appends. The
// fsync counts come from test/validator/fsync-count-shim.c (LD_PRELOAD), scoped
// to the slice's package directory and reset per phase. Each phase runs on its
// own scheduler, which is destroyed, with every actor torn down, before the
// count is read.
namespace reader_sync {

using CountFn = long (*)();
using ResetFn = void (*)();

struct Shim {
  CountFn count = nullptr;
  ResetFn reset = nullptr;
};

Shim load_shim() {
  Shim shim;
  shim.count = reinterpret_cast<CountFn>(dlsym(RTLD_DEFAULT, "tos_fsync_count_for_testing"));
  shim.reset = reinterpret_cast<ResetFn>(dlsym(RTLD_DEFAULT, "tos_fsync_reset_for_testing"));
  check(shim.count != nullptr && shim.reset != nullptr, "the fsync counting shim must be preloaded");
  return shim;
}

// Handles the slices were given. A handle may not be destroyed with changes
// it was never told are stored; the slice stores them in its own index, so
// they are marked stored once the scheduler that used them is gone.
std::vector<BlockHandle> &handles() {
  static std::vector<BlockHandle> kept;
  return kept;
}

void release_handles() {
  for (auto &kept : handles()) {
    kept->flushed_upto(kept->version());
  }
  handles().clear();
}

BlockHandle handle(tos::BlockSeqno seqno) {
  auto result = BlockHandleImpl::create_empty(block_id(seqno));
  result->set_logical_time(100000 + seqno);
  result->set_unix_time(100000 + seqno);
  result->set_is_key_block(false);
  handles().push_back(result);
  return result;
}

FileReference ref(tos::BlockSeqno seqno) {
  return FileReference(fileref::Block{block_id(seqno)});
}

std::string payload(tos::BlockSeqno seqno) {
  return PSTRING() << "block-" << seqno << "-" << std::string(512, static_cast<char>('a' + seqno % 26));
}

td::actor::ActorOwn<ArchiveSlice> open_slice(td::actor::Scheduler &scheduler, const std::string &root, PackageId id,
                                             td::DbOpenMode mode) {
  td::actor::ActorOwn<ArchiveSlice> slice;
  scheduler.run_in_context([&] {
    slice = td::actor::create_actor<ArchiveSlice>("reader-sync", id.id, id.key, id.temp, false, 0, root,
                                                  td::actor::ActorId<ArchiveLru>{}, DbStatistics{}, mode);
  });
  return slice;
}

td::Status add_file(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> slice, tos::BlockSeqno seqno) {
  return request<td::Unit>(scheduler,
                           [&](td::Promise<td::Unit> promise) {
                             td::actor::send_closure(slice, &ArchiveSlice::add_file, handle(seqno), ref(seqno),
                                                     td::BufferSlice(payload(seqno)), std::move(promise));
                           })
      .move_as_status();
}

td::Status add_block(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> slice, tos::BlockSeqno seqno) {
  return request<td::Unit>(scheduler,
                           [&](td::Promise<td::Unit> promise) {
                             std::vector<std::pair<FileReference, td::BufferSlice>> files;
                             files.emplace_back(ref(seqno), td::BufferSlice(payload(seqno)));
                             files.emplace_back(ref(seqno + 1), td::BufferSlice(payload(seqno + 1)));
                             td::connect(std::move(promise), td::actor::ask(slice, &ArchiveSlice::add_block,
                                                                            handle(seqno), std::move(files)));
                           })
      .move_as_status();
}

td::Status set_async(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> slice, bool mode) {
  return request<td::Unit>(scheduler,
                           [&](td::Promise<td::Unit> promise) {
                             td::actor::send_closure(slice, &ArchiveSlice::set_async_mode, mode, std::move(promise));
                           })
      .move_as_status();
}

td::Result<std::string> get_file(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> slice,
                                 tos::BlockSeqno seqno) {
  auto result = request<td::BufferSlice>(scheduler, [&](td::Promise<td::BufferSlice> promise) {
    td::actor::send_closure(slice, &ArchiveSlice::get_file, handle(seqno), ref(seqno), std::move(promise));
  });
  if (result.is_error()) {
    return result.move_as_error();
  }
  return result.ok().as_slice().str();
}

void close_slice(td::actor::Scheduler &scheduler, td::actor::ActorOwn<ArchiveSlice> &slice) {
  scheduler.run_in_context([&] { slice.reset(); });
}

// Every file under the slice's directory, with its bytes.
std::map<std::string, std::string> snapshot(const std::string &directory) {
  std::map<std::string, std::string> files;
  for (const auto &entry : std::filesystem::recursive_directory_iterator(directory)) {
    if (entry.is_regular_file()) {
      files[entry.path().string()] = td::read_file_str(entry.path().string()).move_as_ok();
    }
  }
  return files;
}

const char *mode_name(td::DbOpenMode mode) {
  return mode == td::DbOpenMode::db_secondary ? "secondary" : "read-only";
}

}  // namespace reader_sync

void reader_package_sync(const std::string &root) {
  using namespace reader_sync;
  auto shim = load_shim();
  const PackageId id{100, false, false};
  const auto directory = root + id.path();
  std::filesystem::create_directories(directory);
  check(setenv("TOS_FSYNC_COUNT_PREFIX", directory.c_str(), 1) == 0, "scope the fsync count");
  const tos::BlockSeqno written[] = {101, 102, 103, 105};

  // Primary: append, multi-append and an async-mode append, each synced.
  shim.reset();
  {
    td::actor::Scheduler scheduler({2});
    auto slice = open_slice(scheduler, root, id, td::DbOpenMode::db_primary);
    check(add_file(scheduler, slice.get(), 101).is_ok(), "primary append");
    check(add_block(scheduler, slice.get(), 102).is_ok(), "primary multi-append");
    check(set_async(scheduler, slice.get(), true).is_ok(), "primary enters async mode");
    check(add_file(scheduler, slice.get(), 105).is_ok(), "primary async append");
    check(set_async(scheduler, slice.get(), false).is_ok(), "primary leaves async mode and flushes");
    close_slice(scheduler, slice);
  }
  release_handles();
  const auto primary_syncs = shim.count();
  std::cout << "primary package syncs: " << primary_syncs << std::endl;
  check(primary_syncs > 0, "the primary syncs the packages it appends to");

  // Primary reopen: everything written survives.
  {
    td::actor::Scheduler scheduler({2});
    auto slice = open_slice(scheduler, root, id, td::DbOpenMode::db_primary);
    for (auto seqno : written) {
      auto read = get_file(scheduler, slice.get(), seqno);
      check(read.is_ok() && read.ok() == payload(seqno), "written data survives a primary reopen");
    }
    close_slice(scheduler, slice);
  }
  release_handles();
  const auto before = snapshot(directory);

  for (auto mode : {td::DbOpenMode::db_secondary, td::DbOpenMode::db_readonly}) {
    shim.reset();
    {
      td::actor::Scheduler scheduler({2});
      auto slice = open_slice(scheduler, root, id, mode);
      auto read = get_file(scheduler, slice.get(), 101);
      check(read.is_ok() && read.ok() == payload(101), "a reader reads the packages");
      auto writers = request<std::pair<size_t, size_t>>(scheduler, [&](auto promise) {
                       ArchivePruneTestAccess::package_writers(slice.get(), std::move(promise));
                     }).move_as_ok();
      check(writers.first > 0 && writers.second == 0, "a reader keeps its packages open without writers");
      check(set_async(scheduler, slice.get(), true).is_ok(), "a reader accepts async mode");
      check(set_async(scheduler, slice.get(), false).is_ok(), "a reader leaves async mode");
      auto file = add_file(scheduler, slice.get(), 110);
      check(file.is_error() && file.message() == td::Slice(kArchiveSliceReadOnly),
            "a reader refuses add_file as read-only");
      auto block = add_block(scheduler, slice.get(), 111);
      check(block.is_error() && block.message() == td::Slice(kArchiveSliceReadOnly),
            "a reader refuses add_block as read-only");
      // A stored, flushed handle takes the update shortcut; a reader refuses
      // it before that shortcut too.
      auto flushed = handle(112);
      flushed->set_handle_moved_to_archive();
      flushed->flushed_upto(flushed->version());
      auto update = request<td::Unit>(scheduler, [&](td::Promise<td::Unit> promise) {
                      td::actor::send_closure(slice.get(), &ArchiveSlice::update_handle, flushed, std::move(promise));
                    }).move_as_status();
      check(update.is_error() && update.message() == td::Slice(kArchiveSliceReadOnly),
            "a reader refuses update_handle as read-only");
      auto added = request<td::Unit>(scheduler, [&](td::Promise<td::Unit> promise) {
                     td::actor::send_closure(slice.get(), &ArchiveSlice::add_handle, handle(113), std::move(promise));
                   }).move_as_status();
      check(added.is_error() && added.message() == td::Slice(kArchiveSliceReadOnly),
            "a reader refuses add_handle as read-only");
      close_slice(scheduler, slice);
    }
    release_handles();
    const auto reader_syncs = shim.count();
    std::cout << mode_name(mode) << " reader package syncs: " << reader_syncs << std::endl;
    check(reader_syncs == 0, "a reader never syncs the packages it reads");
    check(snapshot(directory) == before, "a reader leaves the package bytes and index unchanged");
  }
  check(unsetenv("TOS_FSYNC_COUNT_PREFIX") == 0, "unscope the fsync count");
  std::cout << "PASS: readers never sync or write packages; the primary still syncs and its data survives a reopen"
            << std::endl;
}

// A package whose legacy (`0:shard`) and current (`0_shard`) file names both
// exist needs a repair that merges or deletes files. Only the primary may run
// it. A reader (secondary or read-only) refuses that package, changes no file,
// and keeps serving the packages before and after it at their own indices. It
// checks the files again only when the slice is reopened.
namespace reader_repair {

using namespace reader_sync;

const PackageId kId{200, false, false};
constexpr tos::BlockSeqno kFirstMc = 201;       // package 0: masterchain, seqnos 200..299
constexpr tos::BlockSeqno kLaterMc = 301;       // package 2: masterchain, seqnos 300..399
const tos::BlockSeqno kShardBlocks[] = {1, 2};  // package 1: workchain 0, referring to kFirstMc

td::uint64 archive_id_of(td::uint32 package_index) {
  return (static_cast<td::uint64>(package_index) << 32) + kId.id;
}

tos::BlockIdExt shard_block_id(tos::BlockSeqno seqno) {
  return {tos::basechainId, tos::shardIdAll, seqno, tos::RootHash::zero(), tos::FileHash::zero()};
}

BlockHandle shard_handle(tos::BlockSeqno seqno) {
  auto result = BlockHandleImpl::create_empty(shard_block_id(seqno));
  result->set_logical_time(200000 + seqno);
  result->set_unix_time(200000 + seqno);
  result->set_masterchain_ref_block(kFirstMc);
  handles().push_back(result);
  return result;
}

FileReference shard_ref(tos::BlockSeqno seqno) {
  return FileReference(fileref::Block{shard_block_id(seqno)});
}

std::string shard_payload(tos::BlockSeqno seqno) {
  return PSTRING() << "shard-block-" << seqno << "-" << std::string(700, static_cast<char>('A' + seqno % 26));
}

td::actor::ActorOwn<ArchiveSlice> open_slice_with(td::actor::Scheduler &scheduler, const std::string &root,
                                                  td::DbOpenMode mode, DbStatistics statistics) {
  td::actor::ActorOwn<ArchiveSlice> slice;
  scheduler.run_in_context([&] {
    slice = td::actor::create_actor<ArchiveSlice>("reader-repair", kId.id, kId.key, kId.temp, false, 0, root,
                                                  td::actor::ActorId<ArchiveLru>{}, statistics, mode);
  });
  return slice;
}

td::Status add_shard_file(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> slice,
                          tos::BlockSeqno seqno) {
  return request<td::Unit>(scheduler,
                           [&](td::Promise<td::Unit> promise) {
                             td::actor::send_closure(slice, &ArchiveSlice::add_file, shard_handle(seqno),
                                                     shard_ref(seqno), td::BufferSlice(shard_payload(seqno)),
                                                     std::move(promise));
                           })
      .move_as_status();
}

td::Result<std::string> get_shard_file(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> slice,
                                       tos::BlockSeqno seqno) {
  auto result = request<td::BufferSlice>(scheduler, [&](td::Promise<td::BufferSlice> promise) {
    td::actor::send_closure(slice, &ArchiveSlice::get_file, shard_handle(seqno), shard_ref(seqno), std::move(promise));
  });
  if (result.is_error()) {
    return result.move_as_error();
  }
  return result.ok().as_slice().str();
}

td::Result<std::string> get_slice_bytes(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> slice,
                                        td::uint64 archive_id, td::uint32 limit) {
  auto result = request<td::BufferSlice>(scheduler, [&](td::Promise<td::BufferSlice> promise) {
    td::actor::send_closure(slice, &ArchiveSlice::get_slice, archive_id, 0, limit, std::move(promise));
  });
  if (result.is_error()) {
    return result.move_as_error();
  }
  return result.ok().as_slice().str();
}

td::Result<td::uint64> get_archive_id(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> slice,
                                      tos::BlockSeqno masterchain_seqno, tos::ShardIdFull shard) {
  return request<td::uint64>(scheduler, [&](td::Promise<td::uint64> promise) {
    td::actor::send_closure(slice, &ArchiveSlice::get_archive_id, masterchain_seqno, shard, std::move(promise));
  });
}

td::Status catch_up(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> slice) {
  return request<td::Unit>(scheduler,
                           [&](td::Promise<td::Unit> promise) {
                             td::actor::send_closure(slice, &ArchiveSlice::try_catch_up_with_primary,
                                                     CatchUpMode::Force, std::move(promise));
                           })
      .move_as_status();
}

// Closes the slice's files; the slice reopens them on its next query.
void close_files(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> slice) {
  scheduler.run_in_context([&] { td::actor::send_closure(slice, &ArchiveSlice::close_files); });
  request<td::Unit>(scheduler, [&](td::Promise<td::Unit> promise) {
    td::actor::send_lambda(slice, [promise = std::move(promise)]() mutable { promise.set_value(td::Unit()); });
  }).ensure();
}

td::uint64 counter(const std::string &stats, const std::string &name) {
  auto key = name + " COUNT : ";
  auto at = stats.find(key);
  check(at != std::string::npos, "statistics report the package counter");
  return std::stoull(stats.substr(at + key.size()));
}

template <class T>
void require_refusal(const td::Result<T> &result, const char *message) {
  check(result.is_error() && result.error().message() == td::Slice(kArchivePackageNeedsRepair), message);
}

enum class Conflict { Merge, NoData };

const char *conflict_name(Conflict conflict) {
  return conflict == Conflict::Merge ? "merge" : "no-data";
}

struct Fixture {
  std::string root;
  std::string directory;
  std::string path_new;
  std::string path_legacy;
  std::string path_later;
  std::string new_bytes;
};

// The primary writes package 0 (masterchain), package 1 (workchain 0) and
// package 2 (masterchain, a later range) in that order. Then the legacy name
// of package 1 is created the way a node that rolled back across the file
// name change leaves it: the package header, zeros up to where it resumed
// appending, and data after that.
Fixture make_fixture(const std::string &root, Conflict conflict) {
  Fixture fixture;
  fixture.root = root;
  fixture.directory = root + kId.path();
  std::filesystem::create_directories(fixture.directory);
  {
    td::actor::Scheduler scheduler({2});
    auto slice = open_slice(scheduler, root, kId, td::DbOpenMode::db_primary);
    check(add_file(scheduler, slice.get(), kFirstMc).is_ok(), "fixture: first masterchain package");
    for (auto seqno : kShardBlocks) {
      check(add_shard_file(scheduler, slice.get(), seqno).is_ok(), "fixture: workchain package");
    }
    check(add_file(scheduler, slice.get(), kLaterMc).is_ok(), "fixture: later masterchain package");
    auto later = get_archive_id(scheduler, slice.get(), kLaterMc, tos::ShardIdFull{tos::masterchainId});
    check(later.is_ok() && later.ok() == archive_id_of(2), "fixture: the later package is package 2");
    close_slice(scheduler, slice);
  }
  release_handles();
  const std::string shard_name = kId.name() + ".0_" + tos::shard_to_str(tos::shardIdAll) + ".pack";
  const std::string legacy_name = kId.name() + ".0:" + tos::shard_to_str(tos::shardIdAll) + ".pack";
  fixture.path_new = fixture.directory + shard_name;
  fixture.path_legacy = fixture.directory + legacy_name;
  const PackageId later_id{300, false, false};
  fixture.path_later = root + later_id.path() + later_id.name() + ".pack";
  check(std::filesystem::exists(fixture.path_new), "fixture: the workchain package uses the current name");
  check(std::filesystem::exists(fixture.path_later), "fixture: the later package has its own file");
  check(!std::filesystem::exists(fixture.path_legacy), "fixture: no legacy name before the conflict is made");
  fixture.new_bytes = td::read_file_str(fixture.path_new).move_as_ok();

  // The first entry: 4-byte package header, 8-byte entry header, name, data.
  const size_t first_entry_end = tos::Package::header_size() + 8 + shard_ref(kShardBlocks[0]).filename().size() +
                                 shard_payload(kShardBlocks[0]).size();
  check(first_entry_end < fixture.new_bytes.size(), "fixture: the package holds two entries");
  std::string legacy = fixture.new_bytes;
  const size_t zero_end = conflict == Conflict::Merge ? first_entry_end : legacy.size();
  std::fill(legacy.begin() + tos::Package::header_size(), legacy.begin() + static_cast<std::ptrdiff_t>(zero_end), '\0');
  td::write_file(fixture.path_legacy, legacy).ensure();
  return fixture;
}

// What the primary's repair leaves, and the primary still reads every entry.
void primary_repairs(const Fixture &fixture, Conflict conflict, const char *stage) {
  {
    td::actor::Scheduler scheduler({2});
    auto slice = open_slice(scheduler, fixture.root, kId, td::DbOpenMode::db_primary);
    for (auto seqno : kShardBlocks) {
      auto read = get_shard_file(scheduler, slice.get(), seqno);
      check(read.is_ok() && read.ok() == shard_payload(seqno), "the primary reads the repaired package");
    }
    close_slice(scheduler, slice);
  }
  release_handles();
  if (conflict == Conflict::Merge) {
    check(!std::filesystem::exists(fixture.path_new), "the primary's merge removes the current name");
    auto merged = td::read_file_str(fixture.path_legacy);
    check(merged.is_ok() && merged.ok() == fixture.new_bytes, "the primary merges the data into the legacy name");
  } else {
    check(!std::filesystem::exists(fixture.path_legacy), "the primary removes a legacy file without data");
    auto kept = td::read_file_str(fixture.path_new);
    check(kept.is_ok() && kept.ok() == fixture.new_bytes, "the primary keeps the current file unchanged");
  }
  std::cout << "PASS: primary repairs the " << conflict_name(conflict) << " conflict (" << stage << ")" << std::endl;
}

// A reader refuses the conflicted package on every selection path, still
// serves the packages before and after it at their own indices, and leaves
// every file present and byte-identical without a single fsync.
void reader_refuses(const Fixture &fixture, Conflict conflict, td::DbOpenMode mode, const Shim &shim) {
  const auto before = snapshot(fixture.directory);
  DbStatistics statistics;
  statistics.init();
  shim.reset();
  {
    td::actor::Scheduler scheduler({2});
    auto slice = open_slice_with(scheduler, fixture.root, mode, statistics);
    // The first query opens every package of the slice; the files must be
    // untouched right after that open.
    auto first = get_file(scheduler, slice.get(), kFirstMc);
    check(first.is_ok() && first.ok() == payload(kFirstMc), "a reader reads the package before the refused one");
    check(std::filesystem::exists(fixture.path_new) && std::filesystem::exists(fixture.path_legacy),
          "opening a reader leaves both package names in place");
    check(snapshot(fixture.directory) == before, "opening a reader leaves every package file byte-identical");
    // The packages around the refused one keep their own indices.
    auto first_id = get_archive_id(scheduler, slice.get(), kFirstMc, tos::ShardIdFull{tos::masterchainId});
    check(first_id.is_ok() && first_id.ok() == archive_id_of(0), "the package before keeps archive id 0");

    auto later = get_file(scheduler, slice.get(), kLaterMc);
    check(later.is_ok() && later.ok() == payload(kLaterMc), "a reader reads the package after the refused one");
    auto later_id = get_archive_id(scheduler, slice.get(), kLaterMc, tos::ShardIdFull{tos::masterchainId});
    check(later_id.is_ok() && later_id.ok() == archive_id_of(2), "the package after keeps archive id 2");
    auto later_bytes = get_slice_bytes(scheduler, slice.get(), archive_id_of(2), 1 << 16);
    check(later_bytes.is_ok() && later_bytes.ok() == td::read_file_str(fixture.path_later).move_as_ok(),
          "get_slice for the package after returns that package's bytes");

    for (auto seqno : kShardBlocks) {
      require_refusal(get_shard_file(scheduler, slice.get(), seqno),
                      "a reader refuses get_file from a package that needs repair");
    }
    require_refusal(get_archive_id(scheduler, slice.get(), kFirstMc, tos::ShardIdFull{tos::basechainId}),
                    "a reader refuses get_archive_id for a package that needs repair");
    require_refusal(get_slice_bytes(scheduler, slice.get(), archive_id_of(1), 1 << 12),
                    "a reader refuses get_slice for a package that needs repair");

    close_files(scheduler, slice.get());
    auto stats = statistics.to_string_and_reset();
    check(counter(stats, "tos.pack.open") == 2, "a reader opens only the two readable packages");
    check(counter(stats, "tos.pack.close") == 2, "a reader closes as many packages as it opened");
    close_slice(scheduler, slice);
  }
  release_handles();
  check(shim.count() == 0, "a reader never syncs a package that needs repair");
  check(std::filesystem::exists(fixture.path_new) && std::filesystem::exists(fixture.path_legacy),
        "a reader leaves both package names in place");
  check(snapshot(fixture.directory) == before, "a reader leaves every package file byte-identical");
  std::cout << "PASS: " << mode_name(mode) << " reader refuses the " << conflict_name(conflict)
            << " conflict and changes nothing" << std::endl;
}

// The placeholder is not refreshed while the slice stays open, not even by a
// forced catch-up; the same reader reads the repaired package once the slice
// is closed and reopened.
void reader_rechecks_on_reopen(const Fixture &fixture) {
  {
    td::actor::Scheduler scheduler({2});
    auto slice = open_slice(scheduler, fixture.root, kId, td::DbOpenMode::db_secondary);
    require_refusal(get_shard_file(scheduler, slice.get(), kShardBlocks[0]),
                    "the reader refuses the package before it is repaired");

    // The file outcome of the primary's merge (checked by primary_repairs):
    // the merged data under the legacy name, and no current name.
    td::write_file(fixture.path_legacy + ".repaired", fixture.new_bytes).ensure();
    std::filesystem::rename(fixture.path_legacy + ".repaired", fixture.path_legacy);
    std::filesystem::remove(fixture.path_new);

    check(catch_up(scheduler, slice.get()).is_ok(), "the reader catches up with the primary");
    require_refusal(get_shard_file(scheduler, slice.get(), kShardBlocks[0]),
                    "an open reader keeps refusing after the files are repaired");

    close_files(scheduler, slice.get());
    for (auto seqno : kShardBlocks) {
      auto read = get_shard_file(scheduler, slice.get(), seqno);
      check(read.is_ok() && read.ok() == shard_payload(seqno), "the reopened reader reads the repaired package");
    }
    auto id = get_archive_id(scheduler, slice.get(), kFirstMc, tos::ShardIdFull{tos::basechainId});
    check(id.is_ok() && id.ok() == archive_id_of(1), "the repaired package keeps archive id 1");
    close_slice(scheduler, slice);
  }
  release_handles();
  std::cout << "PASS: a reader re-checks a refused package only when the slice is reopened" << std::endl;
}

}  // namespace reader_repair

void reader_package_repair(const std::string &root) {
  using namespace reader_repair;
  auto shim = load_shim();
  for (auto conflict : {Conflict::Merge, Conflict::NoData}) {
    // Primary control on its own fixture first: the primary's repair is the
    // same with and without the reader refusal.
    auto control = make_fixture(PSTRING() << root << "/" << conflict_name(conflict) << "-primary", conflict);
    primary_repairs(control, conflict, "no reader first");

    auto fixture = make_fixture(PSTRING() << root << "/" << conflict_name(conflict) << "-readers", conflict);
    check(setenv("TOS_FSYNC_COUNT_PREFIX", fixture.directory.c_str(), 1) == 0, "scope the fsync count");
    for (auto mode : {td::DbOpenMode::db_secondary, td::DbOpenMode::db_readonly}) {
      reader_refuses(fixture, conflict, mode, shim);
    }
    check(unsetenv("TOS_FSYNC_COUNT_PREFIX") == 0, "unscope the fsync count");
    primary_repairs(fixture, conflict, "after the readers");
  }
  reader_rechecks_on_reopen(make_fixture(root + "/reopen", Conflict::Merge));
  std::cout << "PASS: readers refuse packages that need repair and change no file; the primary still repairs"
            << std::endl;
}

// A reader (secondary or read-only) writes nothing into the node's tree: not
// the initial layout of a slice index, not the archive directories, not the
// statistics file, and nothing through the archive manager's writes.
namespace reader_guards {

using namespace reader_sync;

const PackageId kSliced{400, false, false};
const PackageId kTemp{3600, false, true};
constexpr td::uint32 kSplitDepth = 2;  // not the default, so a stale layout picks the wrong package
constexpr tos::BlockSeqno kMc = 401;
constexpr tos::BlockSeqno kShard = 7;

template <class ActorT>
void barrier(td::actor::Scheduler &scheduler, td::actor::ActorId<ActorT> actor) {
  request<td::Unit>(scheduler, [&](td::Promise<td::Unit> promise) {
    td::actor::send_lambda(actor, [promise = std::move(promise)]() mutable { promise.set_value(td::Unit()); });
  }).ensure();
}

void require_read_only(const td::Status &status, const char *message) {
  check(status.is_error() && status.message() == td::Slice(kArchiveReadOnly), message);
}

template <class T>
void require_not_ready(const td::Result<T> &result, const char *message) {
  check(result.is_error() && result.error().code() == tos::ErrorCode::notready, message);
}

std::string index_path(const std::string &root, PackageId id) {
  return root + id.path() + id.name() + ".index";
}

// An index that exists but has no keys yet: what a primary leaves when it
// stops between opening a new slice index and committing its layout.
void make_empty_index(const std::string &root, PackageId id) {
  std::filesystem::create_directories(root + id.path());
  auto db = td::RocksDb::open(index_path(root, id)).move_as_ok();
}

bool index_has_status(const std::string &root, PackageId id) {
  auto db = td::RocksDbReadOnly::open(index_path(root, id)).move_as_ok();
  std::string value;
  return db.get("status", value).move_as_ok() == td::KeyValue::GetStatus::Ok;
}

td::actor::ActorOwn<ArchiveSlice> open_slice_at(td::actor::Scheduler &scheduler, const std::string &root, PackageId id,
                                                td::DbOpenMode mode, td::uint32 split_depth,
                                                DbStatistics statistics = {}) {
  td::actor::ActorOwn<ArchiveSlice> slice;
  scheduler.run_in_context([&] {
    slice = td::actor::create_actor<ArchiveSlice>("reader-guards", id.id, id.key, id.temp, false, split_depth, root,
                                                  td::actor::ActorId<ArchiveLru>{}, statistics, mode);
  });
  return slice;
}

BlockHandle mc_handle(tos::BlockSeqno seqno) {
  return reader_sync::handle(seqno);
}

BlockHandle shard_handle(tos::BlockSeqno seqno) {
  auto result = BlockHandleImpl::create_empty(reader_repair::shard_block_id(seqno));
  result->set_logical_time(300000 + seqno);
  result->set_unix_time(300000 + seqno);
  result->set_masterchain_ref_block(kMc);
  handles().push_back(result);
  return result;
}

FileReference shard_ref(tos::BlockSeqno seqno) {
  return FileReference(fileref::Block{reader_repair::shard_block_id(seqno)});
}

td::Status put(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> slice, BlockHandle block,
               FileReference file, std::string data) {
  return request<td::Unit>(scheduler,
                           [&](td::Promise<td::Unit> promise) {
                             td::actor::send_closure(slice, &ArchiveSlice::add_file, std::move(block), std::move(file),
                                                     td::BufferSlice(data), std::move(promise));
                           })
      .move_as_status();
}

td::Result<std::string> fetch(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> slice,
                              ConstBlockHandle block, FileReference file) {
  auto result = request<td::BufferSlice>(scheduler, [&](td::Promise<td::BufferSlice> promise) {
    td::actor::send_closure(slice, &ArchiveSlice::get_file, std::move(block), std::move(file), std::move(promise));
  });
  if (result.is_error()) {
    return result.move_as_error();
  }
  return result.ok().as_slice().str();
}

td::Result<std::map<tos::ShardIdFull, tos::BlockSeqno>> temp_max_seqnos(td::actor::Scheduler &scheduler,
                                                                        td::actor::ActorId<ArchiveSlice> slice) {
  return request<std::map<tos::ShardIdFull, tos::BlockSeqno>>(scheduler, [&](auto promise) {
    td::actor::send_closure(slice, &ArchiveSlice::get_temp_max_seqnos, std::move(promise));
  });
}

td::uint64 sliced_archive_id(td::uint32 package_index) {
  return (static_cast<td::uint64>(package_index) << 32) + kSliced.id;
}

// The primary's writes into a slice whose index it finds empty: it lays out
// a shard-separated index with kSplitDepth, then a masterchain package and a
// workchain package.
void primary_fills_sliced(td::actor::Scheduler &scheduler, const std::string &root) {
  auto primary = open_slice_at(scheduler, root, kSliced, td::DbOpenMode::db_primary, kSplitDepth);
  check(put(scheduler, primary.get(), mc_handle(kMc), ref(kMc), payload(kMc)).is_ok(), "primary: masterchain file");
  check(put(scheduler, primary.get(), shard_handle(kShard), shard_ref(kShard), payload(kShard)).is_ok(),
        "primary: workchain file");
  close_slice(scheduler, primary);
}

// A sliced reader that read the primary's layout reads both packages, with the
// workchain one at its own shard-separated archive id.
void reads_sliced_layout(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> reader, const char *who) {
  auto mc = fetch(scheduler, reader, mc_handle(kMc), ref(kMc));
  check(mc.is_ok() && mc.ok() == payload(kMc), who);
  auto shard = fetch(scheduler, reader, shard_handle(kShard), shard_ref(kShard));
  check(shard.is_ok() && shard.ok() == payload(kShard), who);
  auto id = reader_repair::get_archive_id(scheduler, reader, kMc, tos::ShardIdFull{tos::basechainId});
  check(id.is_ok() && id.ok() == sliced_archive_id(1), "the workchain package has shard-separated archive id 1");
  auto writers = request<std::pair<size_t, size_t>>(scheduler, [&](auto promise) {
                   ArchivePruneTestAccess::package_writers(reader, std::move(promise));
                 }).move_as_ok();
  check(writers.first == 2 && writers.second == 0, "the reader holds the two packages once, without writers");
}

// Every query on a slice whose index has no layout answers not ready.
void not_ready(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> reader) {
  require_not_ready(fetch(scheduler, reader, mc_handle(kMc), ref(kMc)), "get_file is not ready without a layout");
  require_not_ready(reader_repair::get_archive_id(scheduler, reader, kMc, tos::ShardIdFull{tos::masterchainId}),
                    "get_archive_id is not ready without a layout");
  require_not_ready(reader_repair::get_slice_bytes(scheduler, reader, sliced_archive_id(0), 1 << 12),
                    "get_slice is not ready without a layout");
  require_not_ready(reader_repair::get_slice_bytes(scheduler, reader, kSliced.id, 1 << 12),
                    "get_slice of package 0 is not ready without a layout");
}

void secondary_missing_layout(const std::string &root) {
  make_empty_index(root, kSliced);
  const auto directory = root + kSliced.path();
  const auto before = snapshot(directory);
  DbStatistics statistics;
  statistics.init();
  {
    td::actor::Scheduler scheduler({2});
    auto reader = open_slice_at(scheduler, root, kSliced, td::DbOpenMode::db_secondary, 0, statistics);
    not_ready(scheduler, reader.get());
    check(!index_has_status(root, kSliced), "a secondary does not write the layout of an empty index");
    check(snapshot(directory) == before, "a secondary leaves an empty index unchanged");
    check(reader_repair::catch_up(scheduler, reader.get()).is_ok(), "catch-up with no layout yet");
    not_ready(scheduler, reader.get());

    primary_fills_sliced(scheduler, root);
    for (int round = 0; round < 3; ++round) {
      check(reader_repair::catch_up(scheduler, reader.get()).is_ok(), "the secondary catches up with the primary");
      reads_sliced_layout(scheduler, reader.get(), "the secondary reads the layout after it catches up");
    }
    reader_repair::close_files(scheduler, reader.get());
    auto stats = statistics.to_string_and_reset();
    check(reader_repair::counter(stats, "tos.pack.open") == 2, "repeated catch-up opens each package once");
    check(reader_repair::counter(stats, "tos.pack.close") == 2, "the reader closes as many packages as it opened");
    close_slice(scheduler, reader);
  }
  release_handles();
  std::cout << "PASS: secondary reads nothing and writes nothing until the layout exists, then reads it" << std::endl;
}

void secondary_missing_layout_temp(const std::string &root) {
  make_empty_index(root, kTemp);
  const auto directory = root + kTemp.path();
  const auto before = snapshot(directory);
  {
    td::actor::Scheduler scheduler({2});
    auto reader = open_slice_at(scheduler, root, kTemp, td::DbOpenMode::db_secondary, 0);
    require_not_ready(fetch(scheduler, reader.get(), nullptr, ref(kMc)), "a temporary get_file is not ready");
    require_not_ready(reader_repair::get_archive_id(scheduler, reader.get(), kMc, tos::ShardIdFull{tos::masterchainId}),
                      "a temporary get_archive_id is not ready");
    auto empty_max = temp_max_seqnos(scheduler, reader.get());
    check(empty_max.is_ok() && empty_max.ok().empty(), "a temporary reader without a layout knows no blocks");
    check(!index_has_status(root, kTemp), "a secondary does not write the layout of an empty temporary index");
    check(snapshot(directory) == before, "a secondary leaves an empty temporary index unchanged");

    auto primary = open_slice_at(scheduler, root, kTemp, td::DbOpenMode::db_primary, 0);
    check(put(scheduler, primary.get(), nullptr, ref(kMc), payload(kMc)).is_ok(), "primary: temporary file");
    close_slice(scheduler, primary);
    for (int round = 0; round < 3; ++round) {
      check(reader_repair::catch_up(scheduler, reader.get()).is_ok(), "the secondary catches up with the primary");
      auto read = fetch(scheduler, reader.get(), nullptr, ref(kMc));
      check(read.is_ok() && read.ok() == payload(kMc), "the secondary reads the unsliced layout after catch-up");
      auto writers = request<std::pair<size_t, size_t>>(scheduler, [&](auto promise) {
                       ArchivePruneTestAccess::package_writers(reader.get(), std::move(promise));
                     }).move_as_ok();
      check(writers.first == 1, "the temporary reader holds its one package once");
      auto max = temp_max_seqnos(scheduler, reader.get());
      check(max.is_ok() && max.ok().size() == 1 && max.ok().begin()->second == kMc,
            "the temporary reader's block heights come from the layout read after catch-up");
    }
    close_slice(scheduler, reader);
  }
  release_handles();
  std::cout << "PASS: secondary reads an unsliced layout once it exists" << std::endl;
}

void readonly_missing_layout(const std::string &root) {
  make_empty_index(root, kSliced);
  const auto directory = root + kSliced.path();
  const auto before = snapshot(directory);
  {
    td::actor::Scheduler scheduler({2});
    auto reader = open_slice_at(scheduler, root, kSliced, td::DbOpenMode::db_readonly, 0);
    not_ready(scheduler, reader.get());
    check(!index_has_status(root, kSliced), "a read-only reader does not write the layout of an empty index");
    check(snapshot(directory) == before, "a read-only reader leaves an empty index unchanged");

    primary_fills_sliced(scheduler, root);
    reader_repair::close_files(scheduler, reader.get());
    reads_sliced_layout(scheduler, reader.get(), "the read-only reader reads the layout after it reopens");
    close_slice(scheduler, reader);
  }
  release_handles();
  std::cout << "PASS: read-only reader reads nothing and writes nothing until it reopens on a layout" << std::endl;
}

td::Ref<ValidatorManagerOptions> manager_options(bool stats) {
  auto opts = ValidatorManagerOptions::create(block_id(0), block_id(0));
  opts.write().set_disable_rocksdb_stats(!stats);
  return opts;
}

// Starts a manager on `root`, waits for its start-up, runs `body`, then tears
// it down with its scheduler.
template <class Body>
void with_manager(const std::string &root, td::Ref<ValidatorManagerOptions> opts, td::DbOpenMode mode, Body body) {
  {
    td::actor::Scheduler scheduler({2});
    td::actor::ActorOwn<ArchiveManager> manager;
    scheduler.run_in_context([&] {
      manager =
          td::actor::create_actor<ArchiveManager>("reader-guards", td::actor::ActorId<RootDb>{}, root, opts, mode);
    });
    barrier(scheduler, manager.get());
    body(scheduler, manager.get());
    scheduler.run_in_context([&] { manager.reset(); });
  }
  release_handles();
}

void reader_creates_no_directories(const std::string &root) {
  auto opts = manager_options(false);
  with_manager(root, opts, td::DbOpenMode::db_primary, [](auto &, auto) {});
  for (const char *empty : {"/archive/tmp/", "/files/packages/"}) {
    check(std::filesystem::remove(root + empty), "the primary created the directory");
  }
  const auto before = snapshot(root);
  for (auto mode : {td::DbOpenMode::db_secondary, td::DbOpenMode::db_readonly}) {
    with_manager(root, opts, mode, [](auto &, auto) {});
    check(!std::filesystem::exists(root + "/archive/tmp/"), "a reader does not create archive/tmp");
    check(!std::filesystem::exists(root + "/files/packages/"), "a reader does not create files/packages");
    check(snapshot(root) == before, "a reader leaves the tree unchanged");
  }
  std::cout << "PASS: a reader manager creates no directories" << std::endl;
}

void reader_statistics_file(const std::string &root) {
  const auto working = root + "-secondary-work";
  std::filesystem::create_directories(working);
  auto opts = manager_options(true);
  opts.write().set_secondary_working_dir(td::optional<std::string>(working));
  const auto node_stats = root + "/db_stats.txt";
  const auto alarm = [](auto &scheduler, auto manager) {
    request<td::Unit>(scheduler, [&](td::Promise<td::Unit> promise) {
      ArchivePruneTestAccess::run_alarm(manager, std::move(promise));
    }).ensure();
  };
  // The primary stores one file, so that a reader has a package to read.
  with_manager(root, opts, td::DbOpenMode::db_primary, [](auto &scheduler, auto manager) {
    check(call(scheduler,
               [&](auto promise) {
                 td::actor::send_closure(manager, &ArchiveManager::add_file, mc_handle(1), ref(1),
                                         td::BufferSlice("statistics"), std::move(promise));
               })
              .is_ok(),
          "primary: a file to read");
  });
  check(!std::filesystem::exists(node_stats), "no statistics file before an alarm");
  // A read-only reader writes no statistics file, but its alarm still drains
  // the samples its package reads record; otherwise they grow without bound.
  with_manager(root, opts, td::DbOpenMode::db_readonly, [&](auto &scheduler, auto manager) {
    auto read = request<td::BufferSlice>(scheduler, [&](td::Promise<td::BufferSlice> promise) {
      td::actor::send_closure(manager, &ArchiveManager::get_file, mc_handle(1), ref(1), std::move(promise));
    });
    check(read.is_ok() && read.ok().as_slice() == "statistics", "the read-only reader reads the primary's file");
    const auto samples = [&] {
      return request<std::pair<size_t, bool>>(
                 scheduler, [&](auto promise) { ArchivePruneTestAccess::package_samples(manager, std::move(promise)); })
          .move_as_ok();
    };
    check(samples().first > 0, "the read recorded a timing sample");
    alarm(scheduler, manager);
    auto after = samples();
    check(after.first == 0, "a read-only reader's alarm drains the timing samples");
    check(after.second, "a read-only reader's alarm stays armed");
  });
  check(!std::filesystem::exists(node_stats), "a read-only reader writes no statistics into the node's tree");
  with_manager(root, opts, td::DbOpenMode::db_secondary, alarm);
  check(std::filesystem::exists(working + "/db_stats.txt"), "a secondary writes statistics into its working dir");
  check(!std::filesystem::exists(node_stats), "a secondary writes no statistics into the node's tree");
  with_manager(root, opts, td::DbOpenMode::db_primary, alarm);
  check(std::filesystem::exists(node_stats), "the primary writes its statistics into its tree");
  std::cout << "PASS: only the primary writes statistics into the node's tree" << std::endl;
}

template <class Dispatch>
td::Status call(td::actor::Scheduler &scheduler, Dispatch dispatch) {
  return request<td::Unit>(scheduler, dispatch).move_as_status();
}

void reader_manager_refuses_writes(const std::string &root) {
  auto opts = manager_options(false);
  const PackageId archived{0, false, false};
  // The primary stores block 1 in package 0 and its temporary copy.
  with_manager(root, opts, td::DbOpenMode::db_primary, [](auto &scheduler, auto manager) {
    auto block = mc_handle(1);
    check(call(scheduler,
               [&](auto promise) {
                 td::actor::send_closure(manager, &ArchiveManager::update_handle, block, std::move(promise));
               })
              .is_ok(),
          "primary: temporary handle");
    check(call(scheduler,
               [&](auto promise) {
                 td::actor::send_closure(manager, &ArchiveManager::add_handle, block, std::move(promise));
               })
              .is_ok(),
          "primary: archived handle");
  });
  const auto before = snapshot(root);
  const auto noop_writer = [](td::FileFd &) { return td::Status::OK(); };
  const PersistentStateType unsplit{UnsplitStateType{}};
  for (auto mode : {td::DbOpenMode::db_secondary, td::DbOpenMode::db_readonly}) {
    with_manager(root, opts, mode, [&](auto &scheduler, auto manager) {
      auto live = request<bool>(scheduler, [&](auto promise) {
                    ArchivePruneTestAccess::package_live(manager, archived, std::move(promise));
                  }).move_as_ok();
      check(live, "the reader loaded the primary's package");

      require_read_only(call(scheduler,
                             [&](auto promise) {
                               td::actor::send_closure(manager, &ArchiveManager::add_zero_state, block_id(0),
                                                       td::BufferSlice("zero"), std::move(promise));
                             }),
                        "a reader refuses add_zero_state");
      require_read_only(call(scheduler,
                             [&](auto promise) {
                               td::actor::send_closure(manager, &ArchiveManager::add_zero_state_gen, block_id(0),
                                                       noop_writer, std::move(promise));
                             }),
                        "a reader refuses add_zero_state_gen");
      require_read_only(call(scheduler,
                             [&](auto promise) {
                               td::actor::send_closure(manager, &ArchiveManager::add_persistent_state, block_id(1),
                                                       block_id(1), unsplit, td::BufferSlice("state"),
                                                       std::move(promise));
                             }),
                        "a reader refuses add_persistent_state");
      require_read_only(call(scheduler,
                             [&](auto promise) {
                               td::actor::send_closure(manager, &ArchiveManager::add_persistent_state_gen, block_id(1),
                                                       block_id(1), unsplit, noop_writer, std::move(promise));
                             }),
                        "a reader refuses add_persistent_state_gen");

      // add_handle into the existing package 0, then into a package that
      // does not exist yet.
      for (tos::BlockSeqno seqno : {2U, 40001U}) {
        require_read_only(call(scheduler,
                               [&](auto promise) {
                                 td::actor::send_closure(manager, &ArchiveManager::add_handle, mc_handle(seqno),
                                                         std::move(promise));
                               }),
                          "a reader refuses add_handle");
      }
      // update_handle of an archived handle that needs a flush, then of a
      // temporary one.
      auto moved = mc_handle(3);
      moved->set_handle_moved_to_archive();
      require_read_only(call(scheduler,
                             [&](auto promise) {
                               td::actor::send_closure(manager, &ArchiveManager::update_handle, moved,
                                                       std::move(promise));
                             }),
                        "a reader refuses update_handle of an archived handle");
      require_read_only(call(scheduler,
                             [&](auto promise) {
                               td::actor::send_closure(manager, &ArchiveManager::update_handle, mc_handle(4),
                                                       std::move(promise));
                             }),
                        "a reader refuses update_handle of a temporary handle");

      // add_file on the temporary path, then on the archived path into the
      // existing package 0 and into a package that does not exist yet.
      require_read_only(call(scheduler,
                             [&](auto promise) {
                               td::actor::send_closure(manager, &ArchiveManager::add_file, mc_handle(5), ref(5),
                                                       td::BufferSlice(payload(5)), std::move(promise));
                             }),
                        "a reader refuses add_file on the temporary path");
      for (tos::BlockSeqno seqno : {6U, 40002U}) {
        auto archived_block = mc_handle(seqno);
        archived_block->set_handle_moved_to_archive();
        require_read_only(call(scheduler,
                               [&](auto promise) {
                                 td::actor::send_closure(manager, &ArchiveManager::add_file, archived_block, ref(seqno),
                                                         td::BufferSlice(payload(seqno)), std::move(promise));
                               }),
                          "a reader refuses add_file on the archived path");
      }
      require_read_only(call(scheduler,
                             [&](auto promise) {
                               td::actor::send_closure(manager, &ArchiveManager::add_key_block_proof, 1U, 1U, 1U,
                                                       FileReference(fileref::Proof{block_id(1)}),
                                                       td::BufferSlice("proof"), std::move(promise));
                             }),
                        "a reader refuses add_key_block_proof");
      require_read_only(call(scheduler,
                             [&](auto promise) {
                               td::actor::send_closure(manager, &ArchiveManager::add_temp_file_short, ref(7),
                                                       td::BufferSlice(payload(7)), std::move(promise));
                             }),
                        "a reader refuses add_temp_file_short");
      require_read_only(call(scheduler,
                             [&](auto promise) {
                               std::vector<std::pair<FileReference, td::BufferSlice>> files;
                               files.emplace_back(ref(8), td::BufferSlice(payload(8)));
                               td::connect(std::move(promise),
                                           td::actor::ask(manager, &ArchiveManager::move_block_to_archive,
                                                          mc_handle(40008), std::move(files)));
                             }),
                        "a reader refuses move_block_to_archive");

      // Package deletion, then the deletion record on its own (last: it
      // marks the package deleted in this reader's map).
      require_read_only(call(scheduler,
                             [&](auto promise) {
                               ArchivePruneTestAccess::prune_package(manager, archived, false, std::move(promise));
                             }),
                        "a reader refuses delete_package");
      live = request<bool>(scheduler, [&](auto promise) {
               ArchivePruneTestAccess::package_live(manager, archived, std::move(promise));
             }).move_as_ok();
      check(live, "a refused delete_package leaves the package live");
      require_read_only(call(scheduler,
                             [&](auto promise) {
                               ArchivePruneTestAccess::prune_package(manager, archived, true, std::move(promise));
                             }),
                        "a reader refuses deleted_package");
    });
    check(snapshot(root) == before, "a reader leaves the states, temporary files and index unchanged");
    std::cout << "PASS: " << mode_name(mode) << " manager refuses every write" << std::endl;
  }
  // Primary control: the same zero-state write lands in the node's tree.
  const auto zero_state = root + "/archive/states/" + FileReference{fileref::ZeroState{block_id(0)}}.filename_short();
  check(!std::filesystem::exists(zero_state), "no zero state before the primary control");
  with_manager(root, opts, td::DbOpenMode::db_primary, [](auto &scheduler, auto manager) {
    check(call(scheduler,
               [&](auto promise) {
                 td::actor::send_closure(manager, &ArchiveManager::add_zero_state, block_id(0), td::BufferSlice("zero"),
                                         std::move(promise));
               })
              .is_ok(),
          "the primary stores a zero state");
  });
  check(std::filesystem::exists(zero_state), "the primary's zero state is in its tree");
  std::cout << "PASS: the primary still stores states" << std::endl;
}

}  // namespace reader_guards

void reader_write_guards(const std::string &root) {
  using namespace reader_guards;
  secondary_missing_layout(root + "/secondary-layout");
  secondary_missing_layout_temp(root + "/secondary-layout-temp");
  readonly_missing_layout(root + "/readonly-layout");
  reader_creates_no_directories(root + "/directories");
  reader_statistics_file(root + "/statistics");
  reader_manager_refuses_writes(root + "/manager-writes");
  std::cout << "PASS: readers write nothing into the node's tree" << std::endl;
}

namespace reader_open {

using namespace reader_sync;

template <class T>
void require_index_not_ready(const td::Result<T> &result, const char *prefix) {
  check(result.is_error(), "an unavailable reader index must refuse the query");
  check(result.error().code() == tos::ErrorCode::notready, "the refusal must be notready");
  check(result.error().message().str().find(prefix) == 0, "the refusal must identify the failed index open");
}

void check_closed(td::actor::Scheduler &scheduler, td::actor::ActorId<ArchiveSlice> reader) {
  check(
      request<bool>(scheduler, [&](auto promise) { ArchivePruneTestAccess::index_closed(reader, std::move(promise)); })
          .move_as_ok(),
      "failed opens leave a closed slice with no index, packages or active queries");
}

// The secondary learns a package from the global index, but has not opened
// its index when the primary removes it. All ordering uses actor replies;
// the package is deliberately older than the one preloaded at startup.
void lazy_prune(const std::string &root, td::DbOpenMode mode, PackageId id) {
  std::filesystem::create_directories(std::filesystem::path(root).parent_path());
  auto opts = ValidatorManagerOptions::create(block_id(0), block_id(0));
  opts.write().set_disable_rocksdb_stats(true);
  opts.write().set_archive_preload_period(0);
  opts.write().set_max_open_archive_files(128);
  const PackageId newest{80000, false, false};
  const auto prefix = root + id.path() + id.name();
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<ArchiveManager> primary, secondary;
  scheduler.run_in_context([&] {
    primary = td::actor::create_actor<ArchiveManager>("primary-lazy-prune", td::actor::ActorId<RootDb>{}, root, opts);
  });
  for (auto package_id : {id, newest}) {
    auto source = request<td::actor::ActorId<ArchiveSlice>>(scheduler, [&](auto promise) {
                    ArchivePruneTestAccess::create_package(primary.get(), package_id, std::move(promise));
                  }).move_as_ok();
    auto archive_id = request<td::uint64>(scheduler, [&](auto promise) {
      td::actor::send_closure(source, &ArchiveSlice::get_archive_id, package_id.id,
                              tos::ShardIdFull{tos::masterchainId}, std::move(promise));
    });
    check(archive_id.is_ok() && archive_id.ok() == package_id.id, "primary package exists and is queryable");
  }
  scheduler.run_in_context([&] {
    secondary =
        td::actor::create_actor<ArchiveManager>("reader-lazy-prune", td::actor::ActorId<RootDb>{}, root, opts, mode);
  });
  auto reader = request<td::actor::ActorId<ArchiveSlice>>(scheduler, [&](auto promise) {
                  ArchivePruneTestAccess::get_slice(secondary.get(), id, std::move(promise));
                }).move_as_ok();
  auto preloaded = request<td::actor::ActorId<ArchiveSlice>>(scheduler, [&](auto promise) {
                     ArchivePruneTestAccess::get_slice(secondary.get(), newest, std::move(promise));
                   }).move_as_ok();
  request<td::uint64>(scheduler, [&](auto promise) {
    td::actor::send_closure(preloaded, &ArchiveSlice::get_archive_id, newest.id, tos::ShardIdFull{tos::masterchainId},
                            std::move(promise));
  }).ensure();
  check_closed(scheduler, reader);
  request<td::Unit>(scheduler, [&](auto promise) {
    ArchivePruneTestAccess::prune_package(primary.get(), id, false, std::move(promise));
  }).ensure();
  check(!std::filesystem::exists(prefix + ".pack") && !std::filesystem::exists(prefix + ".index"),
        "primary deletion finishes before the first reader query");
  check(reader.is_alive(), "reader has not observed the deletion record yet");
  const auto opens_before = archive_slice_opens();
  const char *reason = "archive slice index is not ready:";
  for (unsigned attempt = 0; attempt < 32; ++attempt) {
    require_index_not_ready(request<td::uint64>(scheduler,
                                                [&](auto promise) {
                                                  td::actor::send_closure(reader, &ArchiveSlice::get_archive_id, id.id,
                                                                          tos::ShardIdFull{tos::masterchainId},
                                                                          std::move(promise));
                                                }),
                            reason);
    check_closed(scheduler, reader);
  }
  require_index_not_ready(request<td::BufferSlice>(scheduler,
                                                   [&](auto promise) {
                                                     td::actor::send_closure(reader, &ArchiveSlice::get_file, nullptr,
                                                                             ref(id.id + 1), std::move(promise));
                                                   }),
                          reason);
  require_index_not_ready(request<td::BufferSlice>(scheduler,
                                                   [&](auto promise) {
                                                     td::actor::send_closure(reader, &ArchiveSlice::get_slice, id.id, 0,
                                                                             64, std::move(promise));
                                                   }),
                          reason);
  require_index_not_ready(request<td::Unit>(scheduler,
                                            [&](auto promise) {
                                              td::actor::send_closure(reader, &ArchiveSlice::try_catch_up_with_primary,
                                                                      CatchUpMode::Force, std::move(promise));
                                            }),
                          reason);
  if (!id.key) {
    require_index_not_ready(request<BlockHandle>(scheduler,
                                                 [&](auto promise) {
                                                   td::actor::send_closure(reader, &ArchiveSlice::get_handle,
                                                                           block_id(id.id + 1), std::move(promise));
                                                 }),
                            reason);
    require_index_not_ready(request<ConstBlockHandle>(scheduler,
                                                      [&](auto promise) {
                                                        td::actor::send_closure(reader, &ArchiveSlice::get_temp_handle,
                                                                                block_id(id.id + 1),
                                                                                std::move(promise));
                                                      }),
                            reason);
    require_index_not_ready(request<ConstBlockHandle>(
                                scheduler,
                                [&](auto promise) {
                                  td::actor::send_closure(reader, &ArchiveSlice::get_block_by_seqno,
                                                          tos::AccountIdPrefixFull(tos::masterchainId, tos::shardIdAll),
                                                          id.id + 1, std::move(promise));
                                }),
                            reason);
    require_index_not_ready(request<tos::BlockSeqno>(scheduler,
                                                     [&](auto promise) {
                                                       td::actor::send_closure(reader,
                                                                               &ArchiveSlice::get_max_masterchain_seqno,
                                                                               std::move(promise));
                                                     }),
                            reason);
    require_index_not_ready(request<tos::BlockSeqno>(scheduler,
                                                     [&](auto promise) {
                                                       td::actor::send_closure(reader,
                                                                               &ArchiveSlice::get_min_masterchain_seqno,
                                                                               std::move(promise));
                                                     }),
                            reason);
  }
  if (id.temp) {
    require_index_not_ready(request<std::map<tos::ShardIdFull, tos::BlockSeqno>>(
                                scheduler,
                                [&](auto promise) {
                                  td::actor::send_closure(reader, &ArchiveSlice::get_temp_max_seqnos,
                                                          std::move(promise));
                                }),
                            reason);
  }
  scheduler.run_in_context([&] { td::actor::send_closure(reader, &ArchiveSlice::open_files); });
  check_closed(scheduler, reader);
  check(archive_slice_opens() == opens_before, "failed attempts are not counted as successful opens");
  check(!std::filesystem::exists(prefix + ".index"), "a reader never recreates a removed index");
  if (mode == td::DbOpenMode::db_secondary) {
    request<td::Unit>(scheduler, [&](auto promise) {
      td::actor::send_closure(secondary, &ArchiveManager::try_catch_up_with_primary, CatchUpMode::Force,
                              std::move(promise));
    }).ensure();
    pump_until(scheduler, [&] { return !reader.is_alive(); }, "catch-up retires the unavailable slice");
    check(!request<bool>(
               scheduler,
               [&](auto promise) { ArchivePruneTestAccess::package_live(secondary.get(), id, std::move(promise)); })
               .move_as_ok(),
          "the deletion record retires the stale package description");
  }
  scheduler.run_in_context([&] {
    secondary.reset();
    primary.reset();
  });
  std::cout << "PASS: " << mode_name(mode) << " discovery -> prune -> lazy open; " << id.name() << std::endl;
}

void slice_recovers(const std::string &root, td::DbOpenMode mode, bool corrupt_index) {
  const PackageId id{20000, false, false};
  const auto directory = root + id.path();
  const auto current = directory + id.name() + ".index/CURRENT";
  std::filesystem::create_directories(directory);
  auto seed = [&](td::actor::Scheduler &scheduler) {
    auto primary = open_slice(scheduler, root, id, td::DbOpenMode::db_primary);
    add_file(scheduler, primary.get(), id.id + 1).ensure();
    close_slice(scheduler, primary);
  };
  std::string saved_current;
  if (corrupt_index) {
    {
      td::actor::Scheduler scheduler({2});
      seed(scheduler);
    }
    release_handles();
    saved_current = td::read_file_str(current).move_as_ok();
    td::write_file(current, "invalid manifest\n").ensure();
  }
  {
    td::actor::Scheduler scheduler({2});
    auto reader = open_slice(scheduler, root, id, mode);
    require_index_not_ready(get_file(scheduler, reader.get(), id.id + 1), "archive slice index is not ready:");
    check_closed(scheduler, reader.get());
    if (corrupt_index) {
      td::write_file(current, saved_current).ensure();
    } else {
      seed(scheduler);
    }
    auto data = get_file(scheduler, reader.get(), id.id + 1);
    check(data.is_ok() && data.ok() == payload(id.id + 1), "the same reader recovers after the index is available");
    close_slice(scheduler, reader);
  }
  release_handles();
  std::cout << "PASS: " << mode_name(mode) << " slice retries " << (corrupt_index ? "corrupt" : "missing")
            << " index and reads the source bytes" << std::endl;
}

void missing_package_recovers(const std::string &root, td::DbOpenMode mode) {
  const PackageId id{20000, false, false};
  const auto directory = root + id.path();
  const PackageId second{id.id + 100, false, false};
  const auto package = directory + second.name() + ".pack";
  std::filesystem::create_directories(directory);
  {
    td::actor::Scheduler scheduler({2});
    auto primary = open_slice(scheduler, root, id, td::DbOpenMode::db_primary);
    add_file(scheduler, primary.get(), id.id + 1).ensure();
    add_file(scheduler, primary.get(), second.id + 1).ensure();
    close_slice(scheduler, primary);
  }
  release_handles();
  std::filesystem::rename(package, package + ".held");
  {
    td::actor::Scheduler scheduler({2});
    auto reader = open_slice(scheduler, root, id, mode);
    auto missing = get_file(scheduler, reader.get(), second.id + 1);
    check(missing.is_error() && missing.error().code() == tos::ErrorCode::notready &&
              missing.error().message() == "archive package is not open yet",
          "a missing package after a successful index open is notready");
    check_closed(scheduler, reader.get());
    std::filesystem::rename(package + ".held", package);
    auto recovered = get_file(scheduler, reader.get(), second.id + 1);
    check(recovered.is_ok() && recovered.ok() == payload(second.id + 1),
          "a reader discards the partial layout and reads a restored package");
    close_slice(scheduler, reader);
  }
  release_handles();
  std::cout << "PASS: " << mode_name(mode) << " missing package leaves no partial open and recovers" << std::endl;
}

void catch_up_recovers(const std::string &root) {
  const PackageId id{20000, false, false};
  const auto directory = root + id.path();
  const auto current = directory + id.name() + ".index/CURRENT";
  std::filesystem::create_directories(directory);
  {
    td::actor::Scheduler scheduler({2});
    auto primary = open_slice(scheduler, root, id, td::DbOpenMode::db_primary);
    add_file(scheduler, primary.get(), id.id + 1).ensure();
    close_slice(scheduler, primary);
  }
  release_handles();
  {
    td::actor::Scheduler scheduler({2});
    auto reader = open_slice(scheduler, root, id, td::DbOpenMode::db_secondary);
    get_file(scheduler, reader.get(), id.id + 1).ensure();
    const auto opens_before = archive_slice_opens();
    std::filesystem::rename(current, current + ".held");
    request<td::Unit>(scheduler, [&](auto promise) {
      ArchivePruneTestAccess::make_catch_up_due(reader.get(), std::move(promise));
    }).ensure();
    const char *reason = "archive slice index catch-up is not ready:";
    require_index_not_ready(get_file(scheduler, reader.get(), id.id + 1), reason);
    require_index_not_ready(request<td::Unit>(scheduler,
                                              [&](auto promise) {
                                                td::actor::send_closure(reader,
                                                                        &ArchiveSlice::try_catch_up_with_primary,
                                                                        CatchUpMode::Force, std::move(promise));
                                              }),
                            reason);
    std::filesystem::rename(current + ".held", current);
    auto recovered = get_file(scheduler, reader.get(), id.id + 1);
    check(recovered.is_ok() && recovered.ok() == payload(id.id + 1),
          "an open secondary recovers from catch-up failure without restarting");
    check(archive_slice_opens() == opens_before, "catch-up recovery reuses the existing index");
    close_slice(scheduler, reader);
  }
  release_handles();
  std::cout << "PASS: an open secondary reports catch-up failures and recovers" << std::endl;
}

void manager_recovers(const std::string &root, td::DbOpenMode mode, bool corrupt_index) {
  std::filesystem::create_directories(std::filesystem::path(root).parent_path());
  auto opts = ValidatorManagerOptions::create(block_id(0), block_id(0));
  opts.write().set_disable_rocksdb_stats(true);
  const PackageId id{20000, false, false};
  const auto current = root + "/files/globalindex/CURRENT";
  auto seed = [&](td::actor::Scheduler &scheduler) {
    td::actor::ActorOwn<ArchiveManager> primary;
    scheduler.run_in_context([&] {
      primary =
          td::actor::create_actor<ArchiveManager>("primary-index-recovery", td::actor::ActorId<RootDb>{}, root, opts);
    });
    auto slice = request<td::actor::ActorId<ArchiveSlice>>(scheduler, [&](auto promise) {
                   ArchivePruneTestAccess::create_package(primary.get(), id, std::move(promise));
                 }).move_as_ok();
    request<td::uint64>(scheduler, [&](auto promise) {
      td::actor::send_closure(slice, &ArchiveSlice::get_archive_id, id.id, tos::ShardIdFull{tos::masterchainId},
                              std::move(promise));
    }).ensure();
    scheduler.run_in_context([&] { primary.reset(); });
  };
  std::string saved_current;
  if (corrupt_index) {
    {
      td::actor::Scheduler scheduler({2});
      seed(scheduler);
    }
    saved_current = td::read_file_str(current).move_as_ok();
    td::write_file(current, "invalid manifest\n").ensure();
  }
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<ArchiveManager> reader;
  scheduler.run_in_context([&] {
    reader = td::actor::create_actor<ArchiveManager>("reader-index-recovery", td::actor::ActorId<RootDb>{}, root, opts,
                                                     mode);
  });
  for (unsigned attempt = 0; attempt < 16; ++attempt) {
    require_index_not_ready(request<tos::BlockSeqno>(scheduler,
                                                     [&](auto promise) {
                                                       td::actor::send_closure(
                                                           reader, &ArchiveManager::get_max_masterchain_seqno, true,
                                                           std::move(promise));
                                                     }),
                            "archive index is not ready:");
    check(request<bool>(
              scheduler,
              [&](auto promise) { ArchivePruneTestAccess::manager_index_closed(reader.get(), std::move(promise)); })
              .move_as_ok(),
          "failed global opens leave no index or package actors");
  }
  require_index_not_ready(request<tos::BlockSeqno>(scheduler,
                                                   [&](auto promise) {
                                                     td::actor::send_closure(reader,
                                                                             &ArchiveManager::get_min_masterchain_seqno,
                                                                             std::move(promise));
                                                   }),
                          "archive index is not ready:");
  require_index_not_ready(request<td::Unit>(scheduler,
                                            [&](auto promise) {
                                              td::actor::send_closure(reader,
                                                                      &ArchiveManager::try_catch_up_with_primary,
                                                                      CatchUpMode::Force, std::move(promise));
                                            }),
                          "archive index is not ready:");
  if (corrupt_index) {
    td::write_file(current, saved_current).ensure();
  } else {
    check(!std::filesystem::exists(root), "failed reader startup does not create the source tree");
    seed(scheduler);
  }
  auto archive_id = request<td::uint64>(scheduler, [&](auto promise) {
    td::actor::send_closure(reader, &ArchiveManager::get_archive_id, id.id + 1, tos::ShardIdFull{tos::masterchainId},
                            std::move(promise));
  });
  check(archive_id.is_ok() && archive_id.ok() == id.id, "the same manager loads the recovered global index");
  scheduler.run_in_context([&] { reader.reset(); });
  std::cout << "PASS: " << mode_name(mode) << " manager retries " << (corrupt_index ? "corrupt" : "missing")
            << " global index without restarting" << std::endl;
}

void empty_global_index(const std::string &root, td::DbOpenMode mode) {
  std::filesystem::create_directories(root);
  auto opts = ValidatorManagerOptions::create(block_id(0), block_id(0));
  opts.write().set_disable_rocksdb_stats(true);
  reader_guards::with_manager(root, opts, td::DbOpenMode::db_primary, [](auto &, auto) {});
  reader_guards::with_manager(root, opts, mode, [&](auto &scheduler, auto reader) {
    const char *reason = "archive has no masterchain blocks";
    require_index_not_ready(request<tos::BlockSeqno>(scheduler,
                                                     [&](auto promise) {
                                                       td::actor::send_closure(
                                                           reader, &ArchiveManager::get_max_masterchain_seqno, true,
                                                           std::move(promise));
                                                     }),
                            reason);
    require_index_not_ready(request<tos::BlockSeqno>(scheduler,
                                                     [&](auto promise) {
                                                       td::actor::send_closure(
                                                           reader, &ArchiveManager::get_min_masterchain_seqno,
                                                           std::move(promise));
                                                     }),
                            reason);
    if (mode == td::DbOpenMode::db_secondary) {
      require_index_not_ready(request<td::Unit>(scheduler,
                                                [&](auto promise) {
                                                  td::actor::send_closure(reader,
                                                                          &ArchiveManager::try_catch_up_with_primary,
                                                                          CatchUpMode::Force, std::move(promise));
                                                }),
                              "archive has no packages yet");
    }
  });
  std::cout << "PASS: " << mode_name(mode) << " empty global index reports notready" << std::endl;
}

}  // namespace reader_open

void reader_open_failures(const std::string &root) {
  for (auto mode : {td::DbOpenMode::db_secondary, td::DbOpenMode::db_readonly}) {
    const auto directory = root + "/" + reader_sync::mode_name(mode);
    for (auto id : {PackageId{20000, false, false}, PackageId{20000, true, false}, PackageId{20000, false, true}}) {
      reader_open::lazy_prune(directory + "/" + id.name(), mode, id);
    }
    reader_open::missing_package_recovers(directory + "/missing-package", mode);
    reader_open::empty_global_index(directory + "/empty-index", mode);
    for (bool corrupt_index : {false, true}) {
      const auto suffix = corrupt_index ? "/corrupt" : "/missing";
      reader_open::slice_recovers(directory + "/slice" + suffix, mode, corrupt_index);
      reader_open::manager_recovers(directory + "/manager" + suffix, mode, corrupt_index);
    }
  }
  reader_open::catch_up_recovers(root + "/catch-up");
  std::cout << "PASS: unavailable reader indexes fail without aborting and recover without restart" << std::endl;
}

int main(int argc, char **argv) {
  auto root = td::mkdtemp("", "archive-prune-").move_as_ok();
  if (argc == 2 && std::string(argv[1]) == "--held-reader-shutdown") {
    manager_held_reader(root + "/held-shutdown", true);
    td::rmrf(root).ensure();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--secondary-lifetime") {
    secondary_prune_lifetime(root + "/secondary-delete", false);
    secondary_prune_lifetime(root + "/secondary-preserve", true);
    td::rmrf(root).ensure();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--reader-package-sync") {
    reader_package_sync(root + "/reader-package-sync");
    td::rmrf(root).ensure();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--reader-package-repair") {
    reader_package_repair(root + "/reader-package-repair");
    td::rmrf(root).ensure();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--reader-write-guards") {
    reader_write_guards(root + "/reader-write-guards");
    td::rmrf(root).ensure();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--reader-open-failures") {
    reader_open_failures(root + "/reader-open-failures");
    td::rmrf(root).ensure();
    return 0;
  }
  check(argc == 1, "unknown test argument");
  retained_reader_control(root);
  for (bool close_first : {false, true}) {
    slice_prune(root, false, false, close_first);
    slice_prune(root, true, false, close_first);
    slice_prune(root, false, true, close_first);
  }
  manager_prune(root + "/manager-sync", false);
  manager_prune(root + "/manager-async", true);
  manager_held_reader(root + "/held-release", false);
  secondary_prune_lifetime(root + "/secondary-delete", false);
  secondary_prune_lifetime(root + "/secondary-preserve", true);
  td::rmrf(root).ensure();
  std::cout << "PASS: archive prune baseline" << std::endl;
}
