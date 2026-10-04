/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

#include "td/utils/port/IPAddress.h"

namespace tos::adnl {

// A shared network budget is divided so that no single source address may hold
// more than this fraction of it. One ordinary source can then exhaust only its
// own share, never the whole budget, and never needs another source's
// connection or stream to be evicted to make room.
//
// This is source isolation, not a Sybil-resistant availability guarantee: a
// party controlling many addresses (or many IPv6 /64 prefixes) still holds one
// share per address and can together exhaust the global budget. The budgets
// these shares divide bound pending or attributable bytes; they are not bounds
// on total process memory.
//
// For operators: a share belongs to an address, not to a peer. Everything that
// reaches a node from one address shares one allowance: nodes colocated on one
// host or behind one address, and every user behind one NAT or carrier-grade
// NAT gateway. Loopback is not exempt, so a testnet whose nodes all run on one
// host gives all of them together one eighth of each budget. The one-eighth
// default has not been validated against live load; run a load test of the
// intended deployment before claiming the defaults suit it. Any future
// per-deployment override of a share must keep the global ceiling it divides.
inline constexpr std::size_t kSourceShareDivisor = 8;

// One eighth of `global_limit`, but never nothing while the limit is not
// nothing: a budget too small to divide still admits one source's first unit.
inline constexpr std::size_t default_source_share(std::size_t global_limit) {
  auto share = global_limit / kSourceShareDivisor;
  return share == 0 && global_limit > 0 ? 1 : share;
}

// The key a source's share is charged under.
//
// IPv4: the address. IPv6: its /64 prefix. A single host or subscriber is
// often assigned a whole /64 and may send from any address in it, so a
// per-address key would give one host 2^64 shares. /64 is a chosen aggregation
// boundary, not a fact about ownership: a /64 may be shared by unrelated users
// (who then share one allowance), and one party may hold many /64s (and then
// many allowances). IPv4-mapped IPv6 addresses
// (a dual-stack socket receiving IPv4) are keyed as the IPv4 address they
// carry, so the same peer is one source whichever socket it reached.
inline std::string network_source_key(const td::IPAddress &address) {
  if (!address.is_valid()) {
    return "unknown";
  }
  if (address.is_ipv4()) {
    return "v4:" + td::IPAddress::ipv4_to_str(address.get_ipv4());
  }
  if (!address.is_ipv6()) {
    return "unknown";
  }
  auto raw = address.get_ipv6();
  if (raw.size() != 16) {
    return "unknown";
  }
  bool mapped = true;
  for (std::size_t i = 0; i < 10; i++) {
    mapped = mapped && raw[i] == '\0';
  }
  mapped = mapped && static_cast<unsigned char>(raw[10]) == 0xff && static_cast<unsigned char>(raw[11]) == 0xff;
  if (mapped) {
    return "v4:" + std::to_string(static_cast<unsigned char>(raw[12])) + "." +
           std::to_string(static_cast<unsigned char>(raw[13])) + "." +
           std::to_string(static_cast<unsigned char>(raw[14])) + "." +
           std::to_string(static_cast<unsigned char>(raw[15]));
  }
  for (std::size_t i = 8; i < 16; i++) {
    raw[i] = '\0';
  }
  return "v6:" + td::IPAddress::ipv6_to_str(raw) + "/64";
}

// How much of one shared resource each source holds, with every source limited
// to `per_source_limit`. A source's entry exists only while it holds something:
// it is created by a reservation and erased when its usage returns to zero, so
// the table never holds more entries than there are outstanding reservations,
// however many addresses have come and gone.
//
// The ledger is charged alongside the global budget it divides, never instead of
// it: a caller reserves the source's share first, then the global budget, and
// gives back the source share if the global budget refused.
class SourceShareLedger {
 public:
  explicit SourceShareLedger(std::size_t per_source_limit) : per_source_limit_(per_source_limit) {
  }
  SourceShareLedger(const SourceShareLedger &) = delete;
  SourceShareLedger &operator=(const SourceShareLedger &) = delete;

  // Take `amount` for `source` if it fits in the source's share; all or nothing.
  bool try_reserve(const std::string &source, std::size_t amount) {
    if (amount == 0) {
      return true;
    }
    std::lock_guard lock(mutex_);
    auto it = used_.find(source);
    std::size_t used = it == used_.end() ? 0 : it->second;
    if (used > per_source_limit_ || amount > per_source_limit_ - used) {
      return false;
    }
    used_[source] = used + amount;
    return true;
  }

  // Take as much of `amount` as fits in the source's share; returns what was
  // taken, which is zero when the share is spent.
  std::size_t try_reserve_up_to(const std::string &source, std::size_t amount) {
    if (amount == 0) {
      return 0;
    }
    std::lock_guard lock(mutex_);
    auto it = used_.find(source);
    std::size_t used = it == used_.end() ? 0 : it->second;
    if (used >= per_source_limit_) {
      return 0;
    }
    std::size_t room = per_source_limit_ - used;
    std::size_t taken = amount < room ? amount : room;
    used_[source] = used + taken;
    return taken;
  }

  // Give back `amount` the source holds. False if the source holds less, which
  // is an accounting error; nothing is then released.
  bool release(const std::string &source, std::size_t amount) {
    if (amount == 0) {
      return true;
    }
    std::lock_guard lock(mutex_);
    auto it = used_.find(source);
    if (it == used_.end() || it->second < amount) {
      return false;
    }
    it->second -= amount;
    if (it->second == 0) {
      used_.erase(it);
    }
    return true;
  }

  std::size_t used(const std::string &source) const {
    std::lock_guard lock(mutex_);
    auto it = used_.find(source);
    return it == used_.end() ? 0 : it->second;
  }
  // Sources currently holding anything.
  std::size_t sources() const {
    std::lock_guard lock(mutex_);
    return used_.size();
  }
  std::size_t per_source_limit() const {
    return per_source_limit_;
  }

 private:
  const std::size_t per_source_limit_;
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::size_t> used_;
};

}  // namespace tos::adnl
