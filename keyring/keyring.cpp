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
#include "common/errorcode.h"
#include "common/io.hpp"
#include "td/utils/PathView.h"
#include "td/utils/Random.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/port/Stat.h"

#include "keyring.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace tos {

namespace keyring {

KeyringImpl::PrivateKeyDescr::PrivateKeyDescr(PrivateKey private_key, bool is_temp)
    : public_key(private_key.compute_public_key()), private_key(private_key), is_temp(is_temp) {
  auto D = private_key.create_decryptor_async();
  D.ensure();
  decryptor_sign = D.move_as_ok();
  D = private_key.create_decryptor_async();
  D.ensure();
  decryptor_decrypt = D.move_as_ok();
}

void KeyringImpl::start_up() {
  if (db_root_.size() > 0) {
    td::mkdir(db_root_).ensure();
  }
}

td::Result<KeyringImpl::PrivateKeyDescr*> KeyringImpl::load_key(PublicKeyHash key_hash) {
  auto it = map_.find(key_hash);
  if (it != map_.end()) {
    return it->second.get();
  }

  if (db_root_.size() == 0) {
    return td::Status::Error(ErrorCode::notready, "key not in db");
  }

  auto name = db_root_ + "/" + key_hash.bits256_value().to_hex();

  // Warn if a private key file is
  // group/world-readable. Keys are stored unencrypted; permissive mode bits
  // turn host/backup compromise into key compromise. Don't refuse to load
  // (operators with intentionally-relaxed perms exist and we don't want to
  // brick a running validator), but make the misconfiguration loud.
  struct stat st;
  if (::stat(name.c_str(), &st) == 0 && (st.st_mode & 0077) != 0) {
    LOG(ERROR) << "keyring: key file " << name << " has insecure permissions "
               << std::oct << (st.st_mode & 0777) << std::dec
               << " (expected 0600). Run: chmod 0600 " << name;
  }

  auto R = td::read_file_secure(td::CSlice{name});
  if (R.is_error()) {
    return R.move_as_error_prefix("key not in db: ");
  }
  auto data = R.move_as_ok();
  auto R2 = PrivateKey::import(data);
  R2.ensure();

  auto key = R2.move_as_ok();
  auto desc = std::make_unique<PrivateKeyDescr>(key, false);
  auto short_id = desc->public_key.compute_short_id();
  CHECK(short_id == key_hash);
  return map_.emplace(short_id, std::move(desc)).first->second.get();
}

void KeyringImpl::add_key(PrivateKey key, bool is_temp, td::Promise<td::Unit> promise) {
  auto pub = key.compute_public_key();
  auto short_id = pub.compute_short_id();

  if (map_.count(short_id)) {
    LOG(WARNING) << "duplicate key " << short_id;
    promise.set_value(td::Unit());
    return;
  }
  if (db_root_.size() == 0) {
    CHECK(is_temp);
  }
  map_.emplace(short_id, std::make_unique<PrivateKeyDescr>(key, is_temp));

  if (!is_temp && key.exportable()) {
    auto S = key.export_as_slice();
    auto name = db_root_ + "/" + short_id.bits256_value().to_hex();
    auto tmp_name = name + ".tmp";

    // Write the temp file with mode 0600
    // FROM CREATION so the umask-honoring `td::atomic_write_file` cannot
    // leave the key material readable by other users for the brief window
    // between write and rename. O_EXCL refuses any pre-existing tmp file
    // (would mean another concurrent writer or a stale crash artifact);
    // we unlink + retry once to recover from the latter without silently
    // overwriting a possibly-attacker-controlled symlink.
    auto write_tmp = [&]() -> int {
      return ::open(tmp_name.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                    0600);
    };
    int fd = write_tmp();
    if (fd < 0 && errno == EEXIST) {
      LOG(WARNING) << "keyring: removing stale " << tmp_name
                   << " (likely from a previous crashed write)";
      ::unlink(tmp_name.c_str());
      fd = write_tmp();
    }
    if (fd < 0) {
      LOG(FATAL) << "keyring: cannot open " << tmp_name << " for write: "
                 << td::Status::PosixError(errno, "open");
    }
    auto data = S.as_slice();
    size_t off = 0;
    while (off < data.size()) {
      ssize_t n = ::write(fd, data.data() + off, data.size() - off);
      if (n < 0) {
        if (errno == EINTR) continue;
        ::close(fd);
        ::unlink(tmp_name.c_str());
        LOG(FATAL) << "keyring: write " << tmp_name << " failed: "
                   << td::Status::PosixError(errno, "write");
      }
      off += static_cast<size_t>(n);
    }
    if (::fsync(fd) != 0) {
      ::close(fd);
      ::unlink(tmp_name.c_str());
      LOG(FATAL) << "keyring: fsync " << tmp_name << " failed: "
                 << td::Status::PosixError(errno, "fsync");
    }
    ::close(fd);
    if (::rename(tmp_name.c_str(), name.c_str()) != 0) {
      ::unlink(tmp_name.c_str());
      LOG(FATAL) << "keyring: rename " << tmp_name << " -> " << name
                 << " failed: " << td::Status::PosixError(errno, "rename");
    }
    // Belt-and-suspenders: rename preserves source mode bits, but call
    // chmod(0600) again in case the source mode was somehow widened
    // between open() and rename() (e.g. a hostile mode change on the tmp
    // path before rename). Failure here is not fatal — the file already
    // has restrictive bits from O_EXCL+0600 above.
    if (::chmod(name.c_str(), 0600) != 0) {
      LOG(ERROR) << "keyring: failed to chmod " << name
                 << " to 0600: " << td::Status::PosixError(errno, "chmod");
    }
  }
  promise.set_value(td::Unit());
}

void KeyringImpl::check_key(PublicKeyHash key_hash, td::Promise<td::Unit> promise) {
  auto S = load_key(key_hash);

  if (S.is_error()) {
    promise.set_error(S.move_as_error());
  } else {
    promise.set_value(td::Unit());
  }
}

void KeyringImpl::add_key_short(PublicKeyHash key_hash, td::Promise<PublicKey> promise) {
  auto S = load_key(key_hash);

  if (S.is_error()) {
    promise.set_error(S.move_as_error());
  } else {
    promise.set_result(map_[key_hash]->public_key);
  }
}

void KeyringImpl::del_key(PublicKeyHash key_hash, td::Promise<td::Unit> promise) {
  map_.erase(key_hash);
  if (db_root_.size() == 0) {
    return promise.set_value(td::Unit());
  }
  auto name = db_root_ + "/" + key_hash.bits256_value().to_hex();
  // The disk is the authority on what needs wiping: a temporary key, an
  // already-deleted key, or a key that was never stored has no file, and
  // wiping one anyway would create and destroy it — and turn a read-only key
  // directory into an abort. Only genuine absence counts: any other stat
  // failure falls through to the wipe, whose own failure stops the process
  // rather than reporting a deletion that left the file behind. This also
  // wipes the persisted file of a key later re-added as temporary.
  auto stat_result = td::stat(name);
  if (stat_result.is_error() &&
      (stat_result.error().code() == ENOENT || stat_result.error().code() == ENOTDIR)) {
    return promise.set_value(td::Unit());
  }
  td::BufferSlice d{256};
  td::Random::secure_bytes(d.as_slice());
  td::write_file(name, d.as_slice()).ensure();
  td::unlink(name).ensure();
  promise.set_value(td::Unit());
}

void KeyringImpl::export_private_key(PublicKeyHash key_hash, td::Promise<PrivateKey> promise) {
  auto S = load_key(key_hash);

  if (S.is_error()) {
    promise.set_error(S.move_as_error());
  } else {
    promise.set_result(map_[key_hash]->private_key);
  }
}

void KeyringImpl::get_public_key(PublicKeyHash key_hash, td::Promise<PublicKey> promise) {
  auto S = load_key(key_hash);

  if (S.is_error()) {
    promise.set_error(S.move_as_error());
  } else {
    promise.set_result(map_[key_hash]->public_key);
  }
}

void KeyringImpl::sign_message(PublicKeyHash key_hash, td::BufferSlice data, td::Promise<td::BufferSlice> promise) {
  auto S = load_key(key_hash);

  if (S.is_error()) {
    promise.set_error(S.move_as_error());
  } else {
    td::actor::send_closure(S.move_as_ok()->decryptor_sign, &DecryptorAsync::sign, std::move(data), std::move(promise));
  }
}

void KeyringImpl::sign_add_get_public_key(PublicKeyHash key_hash, td::BufferSlice data,
                                          td::Promise<std::pair<td::BufferSlice, PublicKey>> promise) {
  auto S = load_key(key_hash);

  if (S.is_error()) {
    promise.set_error(S.move_as_error());
    return;
  }

  auto D = S.move_as_ok();
  auto P = td::PromiseCreator::lambda(
      [promise = std::move(promise), id = D->public_key](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_error(R.move_as_error());
          return;
        }
        promise.set_value(std::pair<td::BufferSlice, PublicKey>{R.move_as_ok(), id});
      });
  td::actor::send_closure(D->decryptor_sign, &DecryptorAsync::sign, std::move(data), std::move(P));
}

void KeyringImpl::sign_messages(PublicKeyHash key_hash, std::vector<td::BufferSlice> data,
                                td::Promise<std::vector<td::Result<td::BufferSlice>>> promise) {
  auto S = load_key(key_hash);

  if (S.is_error()) {
    promise.set_error(S.move_as_error());
  } else {
    td::actor::send_closure(S.move_as_ok()->decryptor_sign, &DecryptorAsync::sign_batch, std::move(data),
                            std::move(promise));
  }
}

void KeyringImpl::decrypt_message(PublicKeyHash key_hash, td::BufferSlice data, td::Promise<td::BufferSlice> promise) {
  auto S = load_key(key_hash);

  if (S.is_error()) {
    promise.set_error(S.move_as_error());
  } else {
    td::actor::send_closure(S.move_as_ok()->decryptor_decrypt, &DecryptorAsync::decrypt, std::move(data),
                            std::move(promise));
  }
}

void KeyringImpl::export_all_private_keys(td::Promise<std::vector<PrivateKey>> promise) {
  load_all_keys();
  std::vector<PrivateKey> keys;
  for (auto& [_, descr] : map_) {
    if (!descr->is_temp && descr->private_key.exportable()) {
      keys.push_back(descr->private_key);
    }
  }
  promise.set_value(std::move(keys));
}

void KeyringImpl::load_all_keys() {
  if (loaded_all_keys_) {
    return;
  }
  loaded_all_keys_ = true;
  LOG(DEBUG) << "Loading all keys from " << db_root_;
  bool first = true;
  auto status = td::WalkPath::run(db_root_, [&](td::Slice path, td::WalkPath::Type type) {
    if (type == td::WalkPath::Type::EnterDir) {
      if (!first) {
        return td::WalkPath::Action::SkipDir;
      }
      first = false;
    } else if (type == td::WalkPath::Type::RegularFile) {
      td::Slice name = td::PathView{path}.file_name();
      td::Bits256 hash;
      if (hash.from_hex(name) != 256) {
        LOG(WARNING) << "Unexpected file in keyring directory: " << name;
        return td::WalkPath::Action::Continue;
      }
      auto result = load_key(PublicKeyHash{hash});
      if (result.is_error()) {
        LOG(WARNING) << "Failed to load key " << name << ": " << result.move_as_error();
      } else {
        LOG(DEBUG) << "Loaded key " << name;
      }
    }
    return td::WalkPath::Action::Continue;
  });
  if (status.is_error()) {
    LOG(WARNING) << "Failed to load all keys: " << status;
  }
}

td::actor::ActorOwn<Keyring> Keyring::create(std::string db_root) {
  return td::actor::create_actor<KeyringImpl>("keyring", db_root);
}

}  // namespace keyring

}  // namespace tos
