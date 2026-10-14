/*
    This file is part of TOS Blockchain.
    Copyright 2025-2026 TOS Blockchain Teams
    SPDX-License-Identifier: LGPL-2.0-or-later
*/
#include <atomic>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

#include "td/actor/actor.h"
#include "td/db/RocksDb.h"
#include "td/utils/Time.h"
#include "td/utils/port/path.h"
#include "validator/db/archive-slice.hpp"

namespace {

using namespace tos::validator;

void check(bool condition, const char *message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << std::endl;
    std::abort();
  }
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
  std::atomic<bool> done{false};
  bool ok = false;
  std::string error;
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
      td::actor::send_closure(slice, &ArchiveSlice::destroy, [&](td::Result<td::Unit> result) {
        ok = result.is_ok();
        if (result.is_error()) {
          error = result.error().to_string();
        }
        done.store(true, std::memory_order_release);
      });
    });
    const auto deadline = td::Timestamp::in(8.0);
    while (!done.load(std::memory_order_acquire) && !deadline.is_in_past()) {
      scheduler.run(0.001);
    }
    if (!done.load(std::memory_order_acquire) || !ok) {
      std::cerr << "destroy incomplete: " << prefix << " error=" << error << std::endl;
    }
    check(done.load(std::memory_order_acquire) && ok, "slice destroy must acknowledge within deadline");
    check(!std::filesystem::exists(prefix + ".pack"), "package must disappear before acknowledgement");
    check(!std::filesystem::exists(prefix + ".index"), "index must disappear before acknowledgement");
    scheduler.run_in_context([&] { slice.reset(); });
  }
  std::cout << "PASS: " << id.name() << " close_first=" << close_first << " clean scheduler teardown" << std::endl;
}

}  // namespace

int main() {
  auto root = td::mkdtemp().move_as_ok();
  retained_reader_control(root);
  for (bool close_first : {false, true}) {
    slice_prune(root, false, false, close_first);
    slice_prune(root, true, false, close_first);
    slice_prune(root, false, true, close_first);
  }
  td::rmrf(root).ensure();
  std::cout << "PASS: archive prune baseline" << std::endl;
}
