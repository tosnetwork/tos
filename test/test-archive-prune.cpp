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
    pump_until(scheduler, [&] {
      for (auto id : {oldest, middle}) {
        if (std::filesystem::exists(prefix(id) + ".pack") || std::filesystem::exists(prefix(id) + ".index")) {
          return false;
        }
      }
      return true;
    }, "real manager TTL must remove both package and index in-process");
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
      td::actor::send_closure(manager, &ArchiveManager::get_archive_id, 40001U,
                              tos::ShardIdFull{tos::masterchainId}, std::move(promise));
    }).ensure();
    for (auto id : {oldest, middle}) {
      check(!std::filesystem::exists(prefix(id) + ".index"), "restart must not recreate pruned index");
    }
    scheduler.run_in_context([&] { manager.reset(); });
  }
  std::cout << "PASS: manager TTL, temp-copy control, clean teardown and same-process reopen; async=" << async_mode
            << std::endl;
}

}  // namespace

int main() {
  auto root = td::mkdtemp("", "archive-prune-").move_as_ok();
  retained_reader_control(root);
  for (bool close_first : {false, true}) {
    slice_prune(root, false, false, close_first);
    slice_prune(root, true, false, close_first);
    slice_prune(root, false, true, close_first);
  }
  manager_prune(root + "/manager-sync", false);
  manager_prune(root + "/manager-async", true);
  td::rmrf(root).ensure();
  std::cout << "PASS: archive prune baseline" << std::endl;
}
