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
#include "td/utils/Time.h"

#include <atomic>

int main() {
  SET_VERBOSITY_LEVEL(verbosity_INFO);

  std::string db_root = "tmp-dir-test-keyring";
  td::rmrf(db_root).ignore();
  td::mkdir(db_root).ensure();

  td::actor::ActorOwn<tos::keyring::Keyring> keyring;
  std::atomic<bool> added{false};
  std::atomic<bool> deleted{false};
  tos::PublicKeyHash key_id;

  td::actor::Scheduler scheduler({1});
  scheduler.run_in_context([&] {
    keyring = tos::keyring::Keyring::create(db_root);
    auto pk = tos::PrivateKey{tos::privkeys::Ed25519::random()};
    key_id = pk.compute_short_id();
    td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, std::move(pk), true,
                            [&](td::Result<td::Unit> R) {
                              R.ensure();
                              added.store(true, std::memory_order_release);
                            });
  });

  auto deadline = td::Timestamp::in(10.0);
  while (!added.load(std::memory_order_acquire)) {
    scheduler.run(0.1);
    LOG_CHECK(!deadline.is_in_past()) << "timed out adding the temporary key";
  }

  // A temporary key never touches the key directory; deleting it must not
  // either. Removing the directory makes any file operation fail loudly, so
  // this would abort if deletion tried to wipe a key file.
  td::rmrf(db_root).ensure();

  scheduler.run_in_context([&] {
    td::actor::send_closure(keyring, &tos::keyring::Keyring::del_key, key_id,
                            [&](td::Result<td::Unit> R) {
                              R.ensure();
                              deleted.store(true, std::memory_order_release);
                            });
  });

  deadline = td::Timestamp::in(10.0);
  while (!deleted.load(std::memory_order_acquire)) {
    scheduler.run(0.1);
    LOG_CHECK(!deadline.is_in_past()) << "timed out deleting the temporary key";
  }

  if (td::stat(db_root).is_ok()) {
    LOG(FATAL) << "deleting a temporary key recreated the key directory path";
  }

  // Deletion must actually remove the key, and deleting it again must be a
  // harmless no-op rather than a filesystem wipe of a nonexistent file.
  std::atomic<bool> checked{false};
  std::atomic<bool> deleted_again{false};
  scheduler.run_in_context([&] {
    td::actor::send_closure(keyring, &tos::keyring::Keyring::check_key, key_id,
                            [&](td::Result<td::Unit> R) {
                              LOG_CHECK(R.is_error()) << "a deleted temporary key still resolves";
                              checked.store(true, std::memory_order_release);
                            });
    td::actor::send_closure(keyring, &tos::keyring::Keyring::del_key, key_id,
                            [&](td::Result<td::Unit> R) {
                              R.ensure();
                              deleted_again.store(true, std::memory_order_release);
                            });
  });

  deadline = td::Timestamp::in(10.0);
  while (!checked.load(std::memory_order_acquire) || !deleted_again.load(std::memory_order_acquire)) {
    scheduler.run(0.1);
    LOG_CHECK(!deadline.is_in_past()) << "timed out re-checking the deleted key";
  }
  if (td::stat(db_root).is_ok()) {
    LOG(FATAL) << "repeated deletion recreated the key directory path";
  }

  scheduler.run_in_context([&] {
    keyring.reset();
    td::actor::SchedulerContext::get().stop();
  });
  while (scheduler.run(1)) {
  }
  return 0;
}
