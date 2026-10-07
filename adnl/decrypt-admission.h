#pragma once

#include <list>
#include <map>
#include <mutex>

#include "td/utils/Status.h"
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

// Admission of a packet to pre-authentication decryption.
//
// A source (an IPv4 address or an IPv6 /64) is charged first: it must have a
// table entry and a token from its own rate limiter. Only then are the shared
// process and local budgets charged, so one source cannot spend more of them
// than its own rate allows. Rate tokens are never refunded.
//
// The table is bounded. When it is full, a new source replaces the least
// recently used idle entry (no decryption in flight); an entry is never
// replaced while a ticket for it is alive.
//
// Per-source state is reachable only through a ticket, so a caller cannot use
// it without having been admitted.
template <class Extra>
class PreauthGate {
  struct Node;

 public:
  struct Source {
    Source(td::uint32 burst, double period) : rate_limiter(burst, period) {
    }
    RateLimiter rate_limiter;
    td::uint64 in_flight = 0;
    Extra extra{};
  };

  class Ticket {
   public:
    Ticket(Ticket &&other) noexcept
        : gate_(other.gate_), node_(other.node_), process_(other.process_), local_(other.local_) {
      other.gate_ = nullptr;
    }
    Ticket &operator=(Ticket &&) = delete;
    Ticket(const Ticket &) = delete;
    Ticket &operator=(const Ticket &) = delete;
    ~Ticket() {
      if (gate_) {
        gate_->release(*node_, *process_, *local_);
      }
    }
    Source &source() const {
      return node_->source;
    }

   private:
    friend class PreauthGate;
    Ticket(PreauthGate *gate, Node *node, DecryptBudget *process, DecryptBudget *local)
        : gate_(gate), node_(node), process_(process), local_(local) {
    }
    PreauthGate *gate_;
    Node *node_;
    DecryptBudget *process_;
    DecryptBudget *local_;
  };

  PreauthGate(size_t max_sources, td::uint32 burst, double period)
      : max_sources_(max_sources), burst_(burst), period_(period) {
    CHECK(max_sources_ > 0);
  }
  PreauthGate(const PreauthGate &) = delete;
  PreauthGate &operator=(const PreauthGate &) = delete;

  td::Result<Ticket> admit(const td::IPAddress &addr, DecryptBudget &process, DecryptBudget &local) {
    auto key = preauth_source(addr);
    auto it = table_.find(key);
    if (it == table_.end()) {
      if (table_.size() >= max_sources_) {
        if (idle_.empty()) {
          return td::Status::Error("pre-authentication source limit exceeded");
        }
        table_.erase(idle_.front());
        idle_.pop_front();
      }
      it = table_.try_emplace(key, key, burst_, period_).first;
      it->second.idle_pos = idle_.insert(idle_.end(), key);
    } else if (it->second.source.in_flight == 0) {
      idle_.splice(idle_.end(), idle_, it->second.idle_pos);
    }
    auto &node = it->second;
    if (!node.source.rate_limiter.take()) {
      return td::Status::Error("rate limit exceeded");
    }
    if (!process.acquire()) {
      return td::Status::Error("process decrypt budget exceeded");
    }
    if (!local.acquire()) {
      process.release();
      return td::Status::Error("local decrypt budget exceeded");
    }
    if (node.source.in_flight++ == 0) {
      idle_.erase(node.idle_pos);
    }
    return Ticket(this, &node, &process, &local);
  }

  // Removes idle entries for which pred(source) holds.
  template <class F>
  void erase_idle_if(F &&pred) {
    for (auto it = idle_.begin(); it != idle_.end();) {
      auto node = table_.find(*it);
      CHECK(node != table_.end());
      if (pred(node->second.source)) {
        table_.erase(node);
        it = idle_.erase(it);
      } else {
        ++it;
      }
    }
  }

  template <class F>
  void for_each(F &&f) {
    for (auto &[key, node] : table_) {
      f(key, node.source);
    }
  }

  bool empty() const {
    return table_.empty();
  }
  size_t size() const {
    return table_.size();
  }
  bool contains(const td::IPAddress &addr) const {
    return table_.count(preauth_source(addr)) != 0;
  }

 private:
  struct Node {
    Node(const td::IPAddress &key, td::uint32 burst, double period) : key(key), source(burst, period) {
    }
    td::IPAddress key;
    Source source;
    // Position in idle_ while source.in_flight == 0.
    std::list<td::IPAddress>::iterator idle_pos;
  };

  void release(Node &node, DecryptBudget &process, DecryptBudget &local) {
    local.release();
    process.release();
    CHECK(node.source.in_flight > 0);
    if (--node.source.in_flight == 0) {
      node.idle_pos = idle_.insert(idle_.end(), node.key);
    }
  }

  size_t max_sources_;
  td::uint32 burst_;
  double period_;
  std::map<td::IPAddress, Node> table_;
  // Keys of idle entries, least recently used first.
  std::list<td::IPAddress> idle_;
};

}  // namespace tos::adnl
