#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "key-isolation.h"
namespace tos::auth {
namespace {
constexpr std::size_t max_designations = 1048576;
constexpr std::uint64_t max_log = 134217728;
constexpr std::array<std::uint8_t, 4> tag{'P', '0', 'K', 1};
}  // namespace
KeyIsolation::~KeyIsolation() {
  if (directory_fd_ >= 0)
    ::close(directory_fd_);
}
bool KeyIsolation::secure_parent() const {
  struct stat parent{};
  return ::fstat(directory_fd_, &parent) == 0 && parent.st_uid == ::geteuid() && (parent.st_mode & 0022) == 0;
}
Result<bool> KeyIsolation::replay(std::span<const std::uint8_t> raw) {
  if (raw.size() != 36 || !std::equal(tag.begin(), tag.end(), raw.begin()))
    return Error{"keyring-isolation-record"};
  Hash key{};
  std::copy(raw.begin() + 4, raw.end(), key.begin());
  if (denied_.size() >= max_designations || !denied_.insert(key).second)
    return Error{"keyring-isolation-record"};
  return true;
}
Result<bool> KeyIsolation::refresh() {
  if (stopped_)
    return Error{"keyring-isolation-unavailable"};
  if (root_.empty())
    return true;
  if (directory_fd_ < 0) {
    directory_fd_ = ::open(root_.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd_ < 0 || ::flock(directory_fd_, LOCK_SH | LOCK_NB) != 0) {
      stopped_ = true;
      return Error{"keyring-isolation-unavailable"};
    }
  }
  auto directory = root_ + "/validator-auth-guard";
  struct stat st{};
  if (::lstat(directory.c_str(), &st) != 0) {
    // Legacy keyrings have no guard directory. Once seen, its disappearance
    // cannot silently turn a running keyring back into a legacy keyring.
    if (errno == ENOENT && !log_)
      return true;
    stopped_ = true;
    return Error{"keyring-isolation-unavailable"};
  }
  if (!S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 0777) != 0700) {
    stopped_ = true;
    return Error{"keyring-isolation-unavailable"};
  }
  auto path = directory + "/keys";
  if (!secure_parent()) {
    stopped_ = true;
    return Error{"keyring-isolation-unavailable"};
  }
  if (!log_) {
    auto opened =
        DurableLog::open(path, false, [this](const LogFrontier&, auto bytes) { return replay(bytes); }, max_log);
    if (!opened.ok()) {
      stopped_ = true;
      return Error{"keyring-isolation-unavailable"};
    }
    log_ = std::move(opened.value());
  }
  if (!log_->linked_at(path)) {
    stopped_ = true;
    return Error{"keyring-isolation-unavailable"};
  }
  return true;
}
Result<bool> KeyIsolation::admit(const Hash& key) {
  auto ready = refresh();
  if (!ready.ok())
    return ready.error();
  if (denied_.contains(key))
    return Error{"keyring-validator-auth-key"};
  return true;
}
Result<bool> KeyIsolation::admit_export_all() {
  auto ready = refresh();
  if (!ready.ok())
    return ready.error();
  // A bulk export never claims completeness while silently omitting a protected
  // key. Export unrelated network keys individually instead.
  if (!denied_.empty())
    return Error{"keyring-validator-auth-key"};
  return true;
}
Result<bool> KeyIsolation::protect(const Hash& key) {
  auto ready = refresh();
  if (!ready.ok())
    return ready.error();
  if (root_.empty())
    return Error{"keyring-isolation-persistence-required"};
  if (!secure_parent()) {
    stopped_ = true;
    return Error{"keyring-isolation-unavailable"};
  }
  if (!exclusive_) {
    // Legacy instances share the directory lock. No P0 designation can be
    // acknowledged while another instance still admits raw operations. A
    // failed nonblocking upgrade stops this already-drained instance, since
    // flock conversion may release its previous shared lock.
    if (::flock(directory_fd_, LOCK_EX | LOCK_NB) != 0) {
      stopped_ = true;
      return Error{"keyring-isolation-writer-conflict"};
    }
    exclusive_ = true;
  }
  if (denied_.contains(key))
    return true;
  if (denied_.size() >= max_designations)
    return Error{"keyring-isolation-capacity"};
  if (!log_) {
    // The directory is the durable initialization marker. A crash after its
    // creation and before the ledger exists requires explicit recovery.
    stopped_ = true;
    auto directory = root_ + "/validator-auth-guard";
    if (::mkdir(directory.c_str(), 0700) != 0)
      return Error{"keyring-isolation-unavailable"};
    int parent = ::open(root_.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0)
      return Error{"keyring-isolation-unavailable"};
    bool synced = ::fsync(parent) == 0;
    ::close(parent);
    if (!synced)
      return Error{"keyring-isolation-unavailable"};
    auto opened = DurableLog::open(directory + "/keys", true, [](const LogFrontier&, auto) { return true; }, max_log);
    if (!opened.ok())
      return Error{"keyring-isolation-unavailable"};
    log_ = std::move(opened.value());
    stopped_ = false;
  }
  Bytes record(tag.begin(), tag.end());
  record.insert(record.end(), key.begin(), key.end());
  stopped_ = true;
  auto written = log_->append(record);
  if (!written.ok())
    return Error{"keyring-isolation-unavailable"};
  denied_.insert(key);
  stopped_ = false;
  return true;
}
}  // namespace tos::auth
