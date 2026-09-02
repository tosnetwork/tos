/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "keyring/keyring.h"

#include "td/actor/actor.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/port/Stat.h"
#include "td/utils/Time.h"

#include <atomic>

namespace {

void wait_flag(td::actor::Scheduler &scheduler, std::atomic<bool> &flag, const char *what) {
  auto deadline = td::Timestamp::in(10.0);
  while (!flag.load(std::memory_order_acquire)) {
    scheduler.run(0.1);
    LOG_CHECK(!deadline.is_in_past()) << "timed out: " << what;
  }
}

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(verbosity_INFO);

  std::string db_root = "tmp-dir-test-keyring";
  td::rmrf(db_root).ignore();
  td::mkdir(db_root).ensure();

  td::actor::ActorOwn<tos::keyring::Keyring> keyring;
  td::actor::ActorOwn<tos::keyring::Keyring> keyring2;
  td::actor::Scheduler scheduler({1});

  // Phase 1: a key persisted to disk, then re-added as temporary in a fresh
  // keyring (fresh map, same directory). Deleting it must still wipe the
  // persisted file — otherwise the "deleted" key resurrects from disk.
  auto persisted = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  auto persisted_id = persisted.compute_short_id();
  auto persisted_file = db_root + "/" + persisted_id.bits256_value().to_hex();
  std::atomic<bool> stored{false};
  scheduler.run_in_context([&] {
    keyring = tos::keyring::Keyring::create(db_root);
    td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, persisted, false,
                            [&](td::Result<td::Unit> R) {
                              R.ensure();
                              stored.store(true, std::memory_order_release);
                            });
  });
  wait_flag(scheduler, stored, "persisting the key");
  LOG_CHECK(td::stat(persisted_file).is_ok()) << "persistent key file was not written";

  std::atomic<bool> shadow_deleted{false};
  scheduler.run_in_context([&] {
    keyring2 = tos::keyring::Keyring::create(db_root);
    td::actor::send_closure(keyring2, &tos::keyring::Keyring::add_key, persisted, true, [](td::Result<td::Unit>) {});
    td::actor::send_closure(keyring2, &tos::keyring::Keyring::del_key, persisted_id,
                            [&](td::Result<td::Unit> R) {
                              R.ensure();
                              shadow_deleted.store(true, std::memory_order_release);
                            });
  });
  wait_flag(scheduler, shadow_deleted, "deleting the shadowed key");
  if (td::stat(persisted_file).is_ok()) {
    LOG(FATAL) << "deleting a key re-added as temporary left its persisted file behind";
  }
  std::atomic<bool> shadow_checked{false};
  scheduler.run_in_context([&] {
    td::actor::send_closure(keyring2, &tos::keyring::Keyring::check_key, persisted_id,
                            [&](td::Result<td::Unit> R) {
                              LOG_CHECK(R.is_error()) << "a deleted shadowed key still resolves";
                              shadow_checked.store(true, std::memory_order_release);
                            });
  });
  wait_flag(scheduler, shadow_checked, "re-checking the shadowed key");

  // Phase 2: a purely temporary key with the key directory gone entirely.
  // Deletion must not touch the filesystem: this would abort on the missing
  // directory if it tried to wipe a key file.
  auto temp_key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  auto temp_id = temp_key.compute_short_id();
  std::atomic<bool> added{false};
  scheduler.run_in_context([&] {
    td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, std::move(temp_key), true,
                            [&](td::Result<td::Unit> R) {
                              R.ensure();
                              added.store(true, std::memory_order_release);
                            });
  });
  wait_flag(scheduler, added, "adding the temporary key");

  td::rmrf(db_root).ensure();

  std::atomic<bool> deleted{false};
  scheduler.run_in_context([&] {
    td::actor::send_closure(keyring, &tos::keyring::Keyring::del_key, temp_id,
                            [&](td::Result<td::Unit> R) {
                              R.ensure();
                              deleted.store(true, std::memory_order_release);
                            });
  });
  wait_flag(scheduler, deleted, "deleting the temporary key");
  if (td::stat(db_root).is_ok()) {
    LOG(FATAL) << "deleting a temporary key recreated the key directory path";
  }

  // Deletion must actually remove the key, and deleting it again must be a
  // harmless no-op rather than a filesystem wipe of a nonexistent file.
  std::atomic<bool> checked{false};
  std::atomic<bool> deleted_again{false};
  scheduler.run_in_context([&] {
    td::actor::send_closure(keyring, &tos::keyring::Keyring::check_key, temp_id,
                            [&](td::Result<td::Unit> R) {
                              LOG_CHECK(R.is_error()) << "a deleted temporary key still resolves";
                              checked.store(true, std::memory_order_release);
                            });
    td::actor::send_closure(keyring, &tos::keyring::Keyring::del_key, temp_id,
                            [&](td::Result<td::Unit> R) {
                              R.ensure();
                              deleted_again.store(true, std::memory_order_release);
                            });
  });
  wait_flag(scheduler, checked, "re-checking the deleted key");
  wait_flag(scheduler, deleted_again, "re-deleting the deleted key");
  if (td::stat(db_root).is_ok()) {
    LOG(FATAL) << "repeated deletion recreated the key directory path";
  }

  scheduler.run_in_context([&] {
    keyring.reset();
    keyring2.reset();
    td::actor::SchedulerContext::get().stop();
  });
  while (scheduler.run(1)) {
  }
  return 0;
}
