/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>
#include <utility>

#include "consensus-key-file.h"
#include "consensus-key-lock.h"

namespace tos::pq {

namespace {

// One open file description holding the exclusive flock. Closing it is what releases the
// lock, so it is closed exactly once, when the last signer that depends on it is gone.
class KeyFileLock {
 public:
  KeyFileLock(int fd, dev_t dev, ino_t ino) noexcept : fd_(fd), dev_(dev), ino_(ino) {
  }
  ~KeyFileLock() {
    ::close(fd_);
  }
  KeyFileLock(const KeyFileLock&) = delete;
  KeyFileLock& operator=(const KeyFileLock&) = delete;

  dev_t dev() const noexcept {
    return dev_;
  }
  ino_t ino() const noexcept {
    return ino_;
  }

 private:
  int fd_;
  dev_t dev_;
  ino_t ino_;
};

// The locks this process holds, by file identity. flock(2) locks belong to an open file
// description, so a second open of a file this process already holds would conflict with
// itself; every load of one file shares the lock instead. Entries whose lock is gone are
// pruned on every acquisition, so the map holds at most the files of live signers.
std::mutex registry_mutex;
std::map<std::pair<dev_t, ino_t>, std::weak_ptr<KeyFileLock>> registry;

// A signer and the lock it depends on, freed together.
struct LockedStore {
  std::shared_ptr<KeyFileLock> lock;
  ValidatorPQKeyStore store;
};

std::string errno_text(int error) {
  return std::string(std::strerror(error));
}

std::variant<std::shared_ptr<KeyFileLock>, std::string> acquire(const std::string& path) {
  // Not following a symlink, as the key file rules do not; the file locked is the file
  // configured.
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    return "cannot open the consensus key file to lock it: " + errno_text(errno);
  }
  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    const int error = errno;
    ::close(fd);
    return "cannot inspect the consensus key file to lock it: " + errno_text(error);
  }
  if (!S_ISREG(st.st_mode)) {
    ::close(fd);
    return "the consensus key file is not a regular file";
  }
  struct statfs fs{};
  if (::fstatfs(fd, &fs) != 0) {
    const int error = errno;
    ::close(fd);
    return "cannot inspect the filesystem of the consensus key file: " + errno_text(error);
  }
  const auto f_type = static_cast<std::uint64_t>(static_cast<unsigned long>(fs.f_type));
  if (!consensus_key_lock_supported_filesystem(f_type)) {
    ::close(fd);
    char hex[32];
    std::snprintf(hex, sizeof(hex), "0x%llx", static_cast<unsigned long long>(f_type));
    return std::string("the consensus key file is on a filesystem (type ") + hex +
           ") where the engine cannot enforce that only one process signs with it; keep the key on a local "
           "filesystem (ext4, xfs, btrfs, tmpfs or the overlay over one of them)";
  }

  std::scoped_lock guard(registry_mutex);
  for (auto it = registry.begin(); it != registry.end();) {
    if (it->second.expired()) {
      it = registry.erase(it);
    } else {
      ++it;
    }
  }
  const auto identity = std::make_pair(st.st_dev, st.st_ino);
  if (auto it = registry.find(identity); it != registry.end()) {
    if (auto held = it->second.lock()) {
      ::close(fd);
      return held;
    }
  }
  if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
    const int error = errno;
    ::close(fd);
    if (error == EWOULDBLOCK) {
      return std::string(
          "another process holds this consensus key file: an engine already signs with it; stop it before "
          "starting another");
    }
    return "cannot lock the consensus key file: " + errno_text(error);
  }
  auto lock = std::make_shared<KeyFileLock>(fd, st.st_dev, st.st_ino);
  registry[identity] = lock;
  return lock;
}

}  // namespace

bool consensus_key_lock_supported_filesystem(std::uint64_t f_type) noexcept {
  // Local filesystems, from <linux/magic.h>. Everything else is refused: network and
  // cluster filesystems (NFS, SMB/CIFS, 9p, Ceph, GFS2, OCFS2) do not give every host
  // one lock table, and FUSE filesystems decide locking in user space.
  switch (f_type) {
    case 0xEF53:      // ext2, ext3, ext4
    case 0x58465342:  // xfs
    case 0x9123683E:  // btrfs
    case 0x01021994:  // tmpfs
    case 0x858458F6:  // ramfs
    case 0x794C7630:  // overlayfs
    case 0xF2F52010:  // f2fs
      return true;
    default:
      return false;
  }
}

std::variant<std::shared_ptr<const ValidatorPQKeyStore>, std::string> load_locked_consensus_key(
    std::string_view path, std::uint32_t expire_at) {
  const std::string name(path);
  // Locked before it is read, so the key this process signs with is never one another
  // engine is signing with at the same moment.
  auto acquired = acquire(name);
  if (std::holds_alternative<std::string>(acquired)) {
    return std::get<std::string>(std::move(acquired));
  }
  auto lock = std::get<std::shared_ptr<KeyFileLock>>(std::move(acquired));

  auto loaded = load_consensus_key(name);
  if (std::holds_alternative<ConsensusKeyFileError>(loaded)) {
    return std::string(describe(std::get<ConsensusKeyFileError>(loaded)));
  }
  // The file read must be the file locked: one replaced in between would leave this
  // process signing with a key whose file nothing holds.
  struct stat st{};
  if (::lstat(name.c_str(), &st) != 0 || st.st_dev != lock->dev() || st.st_ino != lock->ino()) {
    return std::string("the consensus key file was replaced while it was being loaded");
  }

  auto holder =
      std::make_shared<LockedStore>(LockedStore{std::move(lock), std::move(std::get<ValidatorPQKeyStore>(loaded))});
  holder->store.set_expire_at(expire_at);
  // Every copy of this pointer shares the holder, and with it the lock.
  return std::shared_ptr<const ValidatorPQKeyStore>(holder, &holder->store);
}

}  // namespace tos::pq
