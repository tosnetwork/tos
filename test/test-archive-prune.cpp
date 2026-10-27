/*
    This file is part of TOS Blockchain.
    Copyright 2025-2026 TOS Blockchain Teams
    SPDX-License-Identifier: LGPL-2.0-or-later
*/
#include <atomic>
#include <cstdlib>
#include <dlfcn.h>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <sys/resource.h>

#include "td/actor/actor.h"
#include "td/db/RocksDb.h"
#include "td/db/RocksDbSecondary.h"
#include "td/utils/Time.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "validator/block-handle.hpp"
#include "validator/db/archive-lru-policy.h"
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
      self.before_query();
      promise.set_value(self.kv_->snapshot());
    });
  }

  static void released_own_index(td::actor::ActorId<ArchiveSlice> slice, td::Promise<bool> promise) {
    td::actor::send_lambda(slice, [slice, promise = std::move(promise)]() mutable {
      auto &self = slice.get_actor_unsafe();
      promise.set_value(self.destroyed_ && self.kv_ == nullptr);
    });
  }

  // Completes once the manager's archive LRU has handled everything sent to
  // it before.
  static void lru_barrier(td::actor::ActorId<ArchiveManager> manager, td::Promise<td::Unit> promise) {
    td::actor::send_lambda(manager, [manager, promise = std::move(promise)]() mutable {
      auto lru = manager.get_actor_unsafe().archive_lru_.get();
      if (lru.empty()) {
        promise.set_value(td::Unit());
        return;
      }
      td::actor::send_lambda(lru, [promise = std::move(promise)]() mutable { promise.set_value(td::Unit()); });
    });
  }

  template <class ActorT>
  static void actor_barrier(td::actor::ActorId<ActorT> actor, td::Promise<td::Unit> promise) {
    td::actor::send_lambda(actor, [promise = std::move(promise)]() mutable { promise.set_value(td::Unit()); });
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

// A secondary reader with a descriptor budget over three slices written by a
// real primary (packages 0, 20000 and 40000; the last is the newest). Before a
// test samples process-wide descriptor counts, every asynchronous step the
// reader started is finished: the manager's start-up work, the newest slice's
// preload and the LRU decisions it caused, and any close those requested.
struct GateFixture {
  const PackageId kMiddle{20000, false, false};
  const PackageId kNewest{40000, false, false};

  explicit GateFixture(const std::string &root) : root_(root) {
    auto opts = ValidatorManagerOptions::create(block_id(0), block_id(0));
    opts.write().set_disable_rocksdb_stats(true);
    opts.write().set_max_open_archive_files(128);
    {
      td::actor::Scheduler primary_scheduler({2});
      td::actor::ActorOwn<ArchiveManager> primary;
      primary_scheduler.run_in_context([&] {
        primary = td::actor::create_actor<ArchiveManager>("gate-primary", td::actor::ActorId<RootDb>{}, root, opts);
      });
      for (tos::BlockSeqno seqno : {1U, 20001U, 40001U}) {
        auto handle = BlockHandleImpl::create_empty(block_id(seqno));
        handle->set_logical_time(100000 + seqno);
        handle->set_unix_time(100000 + seqno / 20000);
        handle->set_is_key_block(false);
        request<td::Unit>(primary_scheduler, [&](td::Promise<td::Unit> promise) {
          td::actor::send_closure(primary, &ArchiveManager::add_handle, handle, std::move(promise));
        }).ensure();
      }
      primary_scheduler.run_in_context([&] { primary.reset(); });
    }
    auto reader_opts = opts;
    reader_opts.write().set_archive_lru_keep_most_recent(2);
    reader_opts.write().set_archive_descriptor_budget(1u << 20);
    scheduler.run_in_context([&] {
      secondary = td::actor::create_actor<ArchiveManager>("gate-secondary", td::actor::ActorId<RootDb>{}, root,
                                                          reader_opts, td::DbOpenMode::db_secondary);
    });
    middle = slice_of(kMiddle);
    newest = slice_of(kNewest);
    // The newest slice is opened by the manager's preload; open it here too,
    // so that nothing about it is left pending.
    check(query(newest).is_ok(), "the newest slice opens");
    settle();
  }
  ~GateFixture() {
    scheduler.run_in_context([&] { secondary.reset(); });
  }

  td::actor::ActorId<ArchiveSlice> slice_of(PackageId id) {
    return request<td::actor::ActorId<ArchiveSlice>>(
               scheduler,
               [&](auto promise) { ArchivePruneTestAccess::get_slice(secondary.get(), id, std::move(promise)); })
        .move_as_ok();
  }
  td::Result<tos::BlockSeqno> query(td::actor::ActorId<ArchiveSlice> slice) {
    return request<tos::BlockSeqno>(scheduler, [&](td::Promise<tos::BlockSeqno> promise) {
      td::actor::send_closure(slice, &ArchiveSlice::get_max_masterchain_seqno, std::move(promise));
    });
  }
  // Each actor handles its mailbox in order, so a round trip through it
  // finishes everything sent to it before. Two rounds cover slice -> LRU ->
  // slice (an open reported to the LRU, and a close it requested).
  void settle() {
    for (int round = 0; round < 2; ++round) {
      request<td::Unit>(scheduler, [&](auto promise) {
        ArchivePruneTestAccess::lru_barrier(secondary.get(), std::move(promise));
      }).ensure();
      for (auto slice : {middle, newest}) {
        request<td::Unit>(scheduler, [&](auto promise) {
          ArchivePruneTestAccess::actor_barrier(slice, std::move(promise));
        }).ensure();
      }
    }
  }
  size_t middle_index_files() const {
    return count_directory_files(root_ + kMiddle.path() + kMiddle.name() + ".index");
  }

  std::string root_;
  td::actor::Scheduler scheduler{{2}};
  td::actor::ActorOwn<ArchiveManager> secondary;
  td::actor::ActorId<ArchiveSlice> middle, newest;
};

// A budgeted reader must refuse a slice open it has no descriptors for, and
// fail the query instead of the process: here the descriptor limit leaves
// room for two more files, fewer than any slice index needs. Without the
// admission, the secondary's RocksDB open fails with "Too many open files"
// and the archive aborts. Restoring the limit lets the same slice open.
void descriptor_gate(const std::string &root) {
  GateFixture fixture(root);
  const auto index_files = fixture.middle_index_files();
  check(index_files >= 3, "the slice index exists");
  struct rlimit original{};
  check(getrlimit(RLIMIT_NOFILE, &original) == 0, "read the descriptor limit");
  auto refusals_before = archive_descriptor_refusals();
  {
    auto held = count_process_open_fds();
    check(held > 0, "descriptors can be counted");
    struct rlimit tight = original;
    tight.rlim_cur = static_cast<rlim_t>(held) + 2;
    check(setrlimit(RLIMIT_NOFILE, &tight) == 0, "lower the descriptor limit");
    set_archive_descriptor_budget(static_cast<size_t>(tight.rlim_cur));
    auto refused = fixture.query(fixture.middle);
    check(setrlimit(RLIMIT_NOFILE, &original) == 0, "restore the descriptor limit");
    check(refused.is_error(), "an open the budget cannot hold must fail the query");
    check(refused.error().message().str().find("descriptors") != std::string::npos,
          "the refusal names the descriptor shortage");
  }
  auto refusals_after = archive_descriptor_refusals();
  check(refusals_after.shortages == refusals_before.shortages + 1 && refusals_after.last_was_shortage,
        "with nothing closable the refusal is a shortage");
  set_archive_descriptor_budget(1u << 20);
  check(fixture.query(fixture.middle).is_ok(), "the same slice opens once descriptors are available");
  set_archive_descriptor_budget(0);
  std::cout << "PASS: descriptor gate refuses an open it cannot hold, then opens; index files=" << index_files
            << std::endl;
}

// A secondary open that fails after the instance was opened must close it:
// the reader retries, and every failed attempt would otherwise keep the
// database and its files open.
void secondary_open_retry(const std::string &root) {
  GateFixture fixture(root);
  const auto baseline = count_process_open_fds();
  check(baseline > 0, "descriptors can be counted");
  td::RocksDbSecondary::fail_next_open_catch_ups_for_testing(5);
  for (int attempt = 0; attempt < 5; ++attempt) {
    auto failed = fixture.query(fixture.middle);
    check(failed.is_error(), "an open whose catch-up fails must fail the query");
    fixture.settle();
  }
  const auto after_failures = count_process_open_fds();
  std::cout << "descriptors before " << baseline << ", after five failed opens " << after_failures << std::endl;
  check(after_failures == baseline, "failed opens must release every descriptor they took");
  check(fixture.query(fixture.middle).is_ok(), "the retry after the failures opens the slice");
  std::cout << "PASS: failed secondary opens release their descriptors, then the slice opens" << std::endl;
}

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

int main(int argc, char **argv) {
  auto root = td::mkdtemp("", "archive-prune-").move_as_ok();
  if (argc == 2 && std::string(argv[1]) == "--held-reader-shutdown") {
    manager_held_reader(root + "/held-shutdown", true);
    td::rmrf(root).ensure();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--secondary-open-retry") {
    secondary_open_retry(root + "/secondary-open-retry");
    td::rmrf(root).ensure();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--descriptor-gate") {
    descriptor_gate(root + "/descriptor-gate");
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
