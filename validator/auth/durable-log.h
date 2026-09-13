#pragma once
#include <functional>
#include <memory>

#include "crypto.h"
namespace tos::auth {
struct LogFrontier {
  std::uint64_t sequence = 0;
  Hash hash{};
  bool operator==(const LogFrontier&) const = default;
};
// Local storage format, deliberately separate from the frozen network schema.
// The log owns an exclusive OS lock. It never repairs, truncates or ignores a
// damaged tail: after any ambiguous append the instance is permanently stopped.
class DurableLog {
  int fd_ = -1;
  std::uint64_t size_ = 0, limit_;
  LogFrontier frontier_;
  bool stopped_ = false;
  DurableLog(int fd, std::uint64_t limit) : fd_(fd), limit_(limit) {
  }

 public:
  using Replay = std::function<Result<bool>(const LogFrontier&, std::span<const std::uint8_t>)>;
  ~DurableLog();
  DurableLog(const DurableLog&) = delete;
  DurableLog& operator=(const DurableLog&) = delete;
  // Creation is explicit and exclusive; a missing safety ledger is never
  // silently recreated. Exhaustion stops admission without deleting history.
  static Result<std::unique_ptr<DurableLog>> open(const std::string& path, bool create, const Replay&,
                                                  std::uint64_t limit = 1073741824);
  Result<LogFrontier> append(std::span<const std::uint8_t>);
  bool linked_at(const std::string& path) const;
  const LogFrontier& frontier() const {
    return frontier_;
  }
  static Result<LogFrontier> next(const LogFrontier&, std::span<const std::uint8_t>);
};
}  // namespace tos::auth
