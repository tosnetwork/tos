#include <cerrno>
#include <fcntl.h>
#include <sodium.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "durable-log.h"
namespace tos::auth {
namespace {
constexpr std::size_t max_record = 4194304;
bool read_all(int fd, std::span<std::uint8_t> data) {
  while (!data.empty()) {
    auto n = ::read(fd, data.data(), data.size());
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return false;
    data = data.subspan(static_cast<std::size_t>(n));
  }
  return true;
}
bool write_all(int fd, std::span<const std::uint8_t> data) {
  while (!data.empty()) {
    auto n = ::write(fd, data.data(), data.size());
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return false;
    data = data.subspan(static_cast<std::size_t>(n));
  }
  return true;
}
bool sync_file(int fd) {
  if (::fsync(fd) != 0)
    return false;
#if defined(__APPLE__)
  if (::fcntl(fd, F_FULLFSYNC) != 0)
    return false;
#endif
  return true;
}
}  // namespace
DurableLog::~DurableLog() {
  if (fd_ >= 0)
    ::close(fd_);
}
bool DurableLog::linked_at(const std::string& path) const {
  struct stat held{}, named{};
  return !stopped_ && ::fstat(fd_, &held) == 0 && ::lstat(path.c_str(), &named) == 0 && S_ISREG(named.st_mode) &&
         named.st_uid == ::geteuid() && (named.st_mode & 0777) == 0600 && named.st_nlink == 1 &&
         held.st_dev == named.st_dev && held.st_ino == named.st_ino && held.st_size >= 0 &&
         static_cast<std::uint64_t>(held.st_size) == size_;
}
Result<LogFrontier> DurableLog::next(const LogFrontier& previous, std::span<const std::uint8_t> raw) {
  if (raw.empty() || raw.size() > max_record)
    return Error{"journal-record-bound"};
  if (previous.sequence == std::numeric_limits<std::uint64_t>::max())
    return Error{"journal-exhausted"};
  Writer w;
  w.bytes(previous.hash);
  w.integer(previous.sequence + 1);
  w.length(raw.size(), 4);
  w.bytes(raw);
  if (!w.ok())
    return Error{w.error};
  auto h = digest("local-journal-record", w.data);
  sodium_memzero(w.data.data(), w.data.size());
  if (!h.ok())
    return h.error();
  return LogFrontier{previous.sequence + 1, h.value()};
}
Result<std::unique_ptr<DurableLog>> DurableLog::open(const std::string& path, bool create, const Replay& replay,
                                                     std::uint64_t limit) {
  int fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW | (create ? O_CREAT | O_EXCL : 0), 0600);
  if (fd < 0)
    return Error{"storage-unavailable"};
  auto log = std::unique_ptr<DurableLog>(new DurableLog(fd, limit));
  struct stat info{};
  if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || (info.st_mode & 0777) != 0600 ||
      info.st_uid != ::geteuid() || info.st_nlink != 1 || info.st_size < 0)
    return Error{"journal-file-security"};
  if (::flock(fd, LOCK_EX | LOCK_NB) != 0)
    return Error{"journal-writer-conflict"};
  log->size_ = static_cast<std::uint64_t>(info.st_size);
  if (log->size_ > limit)
    return Error{"journal-storage-limit"};
  if (create) {
    if (!sync_file(fd))
      return Error{"storage-unavailable"};
    auto split = path.find_last_of('/');
    auto parent = split == std::string::npos ? "." : (split == 0 ? "/" : path.substr(0, split));
    int dir = ::open(parent.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (dir < 0)
      return Error{"storage-unavailable"};
    bool synced = ::fsync(dir) == 0;
    ::close(dir);
    if (!synced)
      return Error{"storage-unavailable"};
  }
  std::uint64_t remaining = log->size_;
  while (remaining) {
    // Length is admitted against both the per-record cap and actual file size
    // before allocation. Missing bytes never become an ABSENT request.
    std::array<std::uint8_t, 4> prefix{};
    if (remaining < 4 || !read_all(fd, prefix))
      return Error{"journal-corrupt"};
    std::uint32_t length = 0;
    for (auto b : prefix)
      length = (length << 8) | b;
    if (length == 0 || length > max_record || remaining - 4 < std::uint64_t(length) + 32)
      return Error{"journal-corrupt"};
    Bytes raw(length);
    Hash recorded{};
    if (!read_all(fd, raw) || !read_all(fd, recorded))
      return Error{"journal-corrupt"};
    auto next = DurableLog::next(log->frontier_, raw);
    if (!next.ok())
      return next.error();
    if (next.value().hash != recorded)
      return Error{"journal-hash"};
    auto applied = replay(next.value(), raw);
    sodium_memzero(raw.data(), raw.size());
    if (!applied.ok())
      return applied.error();
    if (!applied.value())
      return Error{"journal-replay"};
    log->frontier_ = next.value();
    remaining -= 4 + std::uint64_t(length) + 32;
  }
  return log;
}
Result<LogFrontier> DurableLog::append(std::span<const std::uint8_t> raw) {
  if (stopped_)
    return Error{"storage-unavailable"};
  auto next = DurableLog::next(frontier_, raw);
  if (!next.ok())
    return next.error();
  const auto bytes = std::uint64_t(raw.size()) + 36;
  if (size_ > limit_ || bytes > limit_ - size_)
    return Error{"journal-storage-limit"};
  Writer w;
  w.length(raw.size(), 4);
  w.bytes(raw);
  w.bytes(next.value().hash);
  if (!w.ok())
    return Error{w.error};
  // A failed write/sync may have reached storage. Do not retry on this instance.
  stopped_ = true;
  bool synced = write_all(fd_, w.data) && sync_file(fd_);
  sodium_memzero(w.data.data(), w.data.size());
  if (!synced)
    return Error{"storage-unavailable"};
  size_ += bytes;
  frontier_ = next.value();
  stopped_ = false;
  return frontier_;
}
}  // namespace tos::auth
