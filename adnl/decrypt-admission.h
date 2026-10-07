#pragma once

#include <map>
#include <mutex>

#include "td/utils/port/IPAddress.h"

#include "utils.hpp"

namespace tos::adnl {

// Shared across actor threads for the process budget; local budgets use the
// same admission semantics. Completion releases concurrency, never rate debt.
class DecryptBudget {
 public:
  DecryptBudget(td::uint32 burst, double period, size_t in_flight_limit)
      : work_(burst, period), limit_(in_flight_limit) {
  }
  bool acquire() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (in_flight_ >= limit_ || !work_.take()) {
      return false;
    }
    ++in_flight_;
    return true;
  }
  void release() {
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK(in_flight_ > 0);
    --in_flight_;
  }

 private:
  std::mutex mutex_;
  RateLimiter work_;
  size_t limit_;
  size_t in_flight_ = 0;
};

inline td::IPAddress preauth_source(td::IPAddress addr) {
  addr.set_port(0);
  if (addr.is_ipv6()) {
    auto bytes = addr.get_ipv6();
    std::fill(bytes.begin() + 8, bytes.end(), 0);
    addr.init_ipv6_port(td::IPAddress::ipv6_to_str(bytes), 1).ensure();
    addr.set_port(0);
  }
  return addr;
}

template <class Key, class Value>
Value *bounded_source(std::map<Key, Value> &table, const Key &key, size_t limit) {
  auto it = table.find(key);
  if (it != table.end()) {
    return &it->second;
  }
  if (table.size() >= limit) {
    return nullptr;
  }
  return &table.try_emplace(key).first->second;
}

}  // namespace tos::adnl
