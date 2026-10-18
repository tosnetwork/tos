/*
    This file is part of TOS Blockchain.
    Copyright 2025-2026 TOS Blockchain Teams
    SPDX-License-Identifier: LGPL-2.0-or-later
*/
#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

#include "td/actor/actor.h"
#include "td/db/RocksDb.h"
#include "td/utils/Time.h"
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

// The package serving a block's archived files, and when retention starts
// aging it, come from the real package map: a basechain block is filed under
// its own masterchain reference, which can be an older package than the one
// a later masterchain anchor lives in.
void manager_package_start(const std::string &root) {
  auto opts = ValidatorManagerOptions::create(block_id(0), block_id(0));
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<ArchiveManager> manager;
  scheduler.run_in_context([&] {
    manager = td::actor::create_actor<ArchiveManager>("package-start", td::actor::ActorId<RootDb>{}, root, opts);
  });
  auto add = [&](BlockHandle handle) {
    request<td::Unit>(scheduler, [&](td::Promise<td::Unit> promise) {
      td::actor::send_closure(manager, &ArchiveManager::add_handle, handle, std::move(promise));
    }).ensure();
  };
  auto masterchain = [&](tos::BlockSeqno seqno, tos::UnixTime ts, bool key_block = false) {
    auto handle = BlockHandleImpl::create_empty(block_id(seqno));
    handle->set_logical_time(1000 + seqno);
    handle->set_unix_time(ts);
    handle->set_is_key_block(key_block);
    add(handle);
    return handle;
  };
  auto first = masterchain(1, 100000);
  auto anchor = masterchain(20001, 200000, true);
  auto shard = BlockHandleImpl::create_empty(
      tos::BlockIdExt{tos::basechainId, tos::shardIdAll, 7, tos::RootHash::zero(), tos::FileHash::zero()});
  shard->set_logical_time(1500);
  shard->set_unix_time(150000);
  shard->set_is_key_block(false);
  shard->set_masterchain_ref_block(5);
  add(shard);
  auto start = [&](BlockHandle handle) {
    return request<tos::UnixTime>(scheduler, [&](td::Promise<tos::UnixTime> promise) {
      td::actor::send_closure(manager, &ArchiveManager::get_archive_package_start, handle, std::move(promise));
    });
  };
  check(start(shard).is_error(), "files not yet moved to the archive are not governed by archive retention");
  for (auto &handle : {first, anchor, shard}) {
    handle->set_moved_to_archive();
    add(handle);
  }
  auto shard_start = start(shard);
  check(shard_start.is_ok() && shard_start.ok() == 100000,
        "a block referencing masterchain 5 is served from package 0, aged from its first block");
  auto anchor_start = start(anchor);
  check(anchor_start.is_ok() && anchor_start.ok() == 200000, "the anchor's package is aged from masterchain 20001");
  check(shard_start.ok() < anchor_start.ok(), "the older shard proof's package expires before the anchor's");

  scheduler.run_in_context([&] {
    td::actor::send_closure(manager, &ArchiveManager::run_gc, td::Ref<MasterchainState>{td::make_ref<GcState>()},
                            200002U, 1.0);
  });
  pump_until(scheduler, [&] { return start(shard).is_error(); }, "deleted package must not report a start time");
  check(start(anchor).is_ok(), "the newest package is retained");
  scheduler.run_in_context([&] { manager.reset(); });
  std::cout << "PASS: archive package start follows the package that serves each block" << std::endl;
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

}  // namespace

int main(int argc, char **argv) {
  auto root = td::mkdtemp("", "archive-prune-").move_as_ok();
  if (argc == 2 && std::string(argv[1]) == "--held-reader-shutdown") {
    manager_held_reader(root + "/held-shutdown", true);
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
  manager_package_start(root + "/package-start");
  td::rmrf(root).ensure();
  std::cout << "PASS: archive prune baseline" << std::endl;
}
