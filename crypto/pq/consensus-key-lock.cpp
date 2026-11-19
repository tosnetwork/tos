/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cerrno>
#include <cstring>
#include <map>
#include <mutex>
#include <utility>

#include "consensus-key-file.h"
#include "consensus-key-lock.h"

#if TOS_SEED_FILES_SUPPORTED
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#if defined(__APPLE__)
#include <sys/mount.h>
#include <sys/param.h>
#else
#include <sys/statfs.h>
#endif
#include <unistd.h>
#endif

namespace tos::pq {

#if TOS_SEED_FILES_SUPPORTED
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

// Locks the file open at `fd`, which this function takes over: it ends up owned by the new
// lock, or closed when the file's lock is already held in this process. The caller must
// not use `fd` afterwards except through what is returned.
std::variant<std::shared_ptr<KeyFileLock>, std::string> acquire(int fd) {
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
#if defined(__APPLE__)
  const std::string_view type_name(fs.f_fstypename, ::strnlen(fs.f_fstypename, sizeof(fs.f_fstypename)));
  if (!consensus_key_lock_supported_darwin_filesystem(type_name, (fs.f_flags & MNT_LOCAL) != 0)) {
    ::close(fd);
    return "the consensus key file is on a filesystem (" + std::string(type_name) +
           ") where the engine cannot enforce that only one process signs with it; keep the key on a local "
           "filesystem (apfs or hfs)";
  }
#else
  const auto f_type = static_cast<std::uint64_t>(static_cast<unsigned long>(fs.f_type));
  if (!consensus_key_lock_supported_filesystem(f_type)) {
    ::close(fd);
    char hex[32];
    std::snprintf(hex, sizeof(hex), "0x%llx", static_cast<unsigned long long>(f_type));
    return std::string("the consensus key file is on a filesystem (type ") + hex +
           ") where the engine cannot enforce that only one process signs with it; keep the key on a local "
           "filesystem (ext4, xfs, btrfs, tmpfs or the overlay over one of them)";
  }
#endif

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
#endif

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

bool consensus_key_lock_supported_darwin_filesystem(std::string_view type_name, bool local) noexcept {
  // Only local Apple filesystems, where every process shares the kernel's lock table.
  // Network mounts (smbfs, nfs, afpfs, webdav) lack MNT_LOCAL; FUSE mounts (macfuse,
  // which decides locking in user space) are refused by name, whatever their flags.
  if (!local) {
    return false;
  }
  return type_name == "apfs" || type_name == "hfs";
}

std::variant<std::shared_ptr<const ValidatorPQKeyStore>, std::string> load_locked_consensus_key(
    std::string_view path, std::uint32_t expire_at) {
#if !TOS_SEED_FILES_SUPPORTED
  // The key file itself is refused on this platform, so there is nothing to lock.
  static_cast<void>(path);
  static_cast<void>(expire_at);
  return std::string(describe(ConsensusKeyFileError::unsupported_platform));
#else
  // Opened once, as the key file rules open it: no symlink followed, and without blocking,
  // so a FIFO is refused instead of waited on. Everything after this happens through this
  // one descriptor: the file locked is the file judged and read, whatever the path names
  // meanwhile. Reopening the path would let a file swapped in between be read while the
  // locked one is not.
  const int opened = detail::open_seed_file(path);
  if (opened < 0) {
    return "cannot open the consensus key file to lock it: " + errno_text(errno);
  }
  // A second descriptor of the same open file description, kept for reading: the first
  // is given to the lock, which may close it when this process already holds the file.
  // dup() shares the description, so it refers to the inode just opened.
  detail::Descriptor reader(::fcntl(opened, F_DUPFD_CLOEXEC, 0));
  if (!reader.valid()) {
    const int error = errno;
    ::close(opened);
    return "cannot open the consensus key file to lock it: " + errno_text(error);
  }
  // Locked before it is read, so the key this process signs with is never one another
  // engine is signing with at the same moment.
  auto acquired = acquire(opened);
  if (std::holds_alternative<std::string>(acquired)) {
    return std::get<std::string>(std::move(acquired));
  }
  auto lock = std::get<std::shared_ptr<KeyFileLock>>(std::move(acquired));
  // When the lock was already held here, it was taken on another descriptor; it covers
  // this file only if this descriptor refers to the same inode, which the registry lookup
  // established by fstat of this very description.
  auto loaded = load_consensus_key_from(reader.get(), path);
  if (std::holds_alternative<ConsensusKeyFileError>(loaded)) {
    return std::string(describe(std::get<ConsensusKeyFileError>(loaded)));
  }

  auto holder =
      std::make_shared<LockedStore>(LockedStore{std::move(lock), std::move(std::get<ValidatorPQKeyStore>(loaded))});
  holder->store.set_expire_at(expire_at);
  // Every copy of this pointer shares the holder, and with it the lock.
  return std::shared_ptr<const ValidatorPQKeyStore>(holder, &holder->store);
#endif
}

}  // namespace tos::pq
