/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "td/utils/int_types.h"

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace tos {
namespace dns {

// 366-day lease measured from the last balance top-up (nft-item one_year)
constexpr td::int64 DNS_LEASE_SECONDS = 31622400;

struct DnsCacheEntry {
  std::string address_;
  double created_at_ = 0;
  // hard expiry: min(created + base ttl, renewal deadline)
  double expires_at_ = 0;
};

// Identity of the exact chain state against which a DNS answer was proved.
// Both hashes are part of the identity: seqno alone is insufficient across a
// reorganization, while hashes alone make diagnostics and tests less useful.
struct DnsCheckpoint {
  td::int32 workchain = 0;
  td::int64 shard = 0;
  td::int32 seqno = 0;
  std::string root_hash;
  std::string file_hash;
};

inline bool operator==(const DnsCheckpoint& lhs, const DnsCheckpoint& rhs) {
  return lhs.workchain == rhs.workchain && lhs.shard == rhs.shard && lhs.seqno == rhs.seqno &&
         lhs.root_hash == rhs.root_hash && lhs.file_hash == rhs.file_hash;
}

inline bool operator!=(const DnsCheckpoint& lhs, const DnsCheckpoint& rhs) {
  return !(lhs == rhs);
}

// A copyable cleanup token for asynchronous callback chains. The cleanup runs
// exactly once when the last copy is destroyed, including on every early-error
// return. This is used to pair every successful smc.load with smc.forget.
class SharedCleanup {
 public:
  explicit SharedCleanup(std::function<void()> cleanup) : state_(std::make_shared<State>(std::move(cleanup))) {}

 private:
  struct State {
    explicit State(std::function<void()> cleanup) : cleanup_(std::move(cleanup)) {}
    ~State() {
      if (cleanup_) {
        cleanup_();
      }
    }
    std::function<void()> cleanup_;
  };
  std::shared_ptr<State> state_;
};

struct DomainItemPath {
  std::string collection;
  std::string item;
  std::string label;
};

// The canonical .tos path is Root -> Collection -> Domain Item, followed by
// zero or more owner-controlled delegated resolvers. Never use path.back():
// for a delegated subdomain it identifies the delegate, not the Domain Item.
inline td::Result<DomainItemPath> select_tos_domain_item(td::Slice host,
                                                         const std::vector<std::string>& resolver_path) {
  while (!host.empty() && host.back() == '.') {
    host.remove_suffix(1);
  }
  auto dot = host.rfind('.');
  if (dot == td::Slice::npos || dot == 0 || host.substr(dot + 1) != "tos") {
    return td::Status::Error("lifecycle verification requires a canonical second-level .tos name");
  }
  if (resolver_path.size() < 3 || resolver_path[1].empty() || resolver_path[2].empty()) {
    return td::Status::Error("resolver path does not contain the .tos Collection and Domain Item");
  }
  auto label_start = host.substr(0, dot).rfind('.');
  label_start = label_start == td::Slice::npos ? 0 : label_start + 1;
  auto label = host.substr(label_start, dot - label_start);
  if (label.empty()) {
    return td::Status::Error(".tos Domain Item label is empty");
  }
  return DomainItemPath{resolver_path[1], resolver_path[2], label.str()};
}

// Fail-closed lifecycle gate: a domain item retains its records while it is
// under auction (including ended-but-unfinalized) or past its renewal
// deadline, so a security-sensitive consumer must refuse them. Returns the
// renewal deadline (unix seconds) when the record may be served.
inline td::Result<td::int64> check_domain_lifecycle(td::int64 auction_end_time, td::int64 last_fill_up_time,
                                                    td::int64 now) {
  if (auction_end_time != 0) {
    return td::Status::Error(
        "domain is under auction (or its auction is unfinalized); records belong to a previous "
        "lease");
  }
  if (last_fill_up_time <= 0) {
    return td::Status::Error("domain has no renewal clock; refusing its records");
  }
  if (last_fill_up_time > std::numeric_limits<td::int64>::max() - DNS_LEASE_SECONDS) {
    return td::Status::Error("domain renewal deadline overflows int64");
  }
  td::int64 deadline = last_fill_up_time + DNS_LEASE_SECONDS;
  if (now > deadline) {
    return td::Status::Error("domain is overdue; anyone may release and re-auction it");
  }
  return deadline;
}

// Cache expiry for a positive answer: the base ttl, but never beyond the
// derived renewal deadline (a record must not outlive the lease it belongs
// to). `now` and `now_unix` describe the same instant on the two clocks.
inline double bounded_cache_expiry(double now, double base_ttl, td::int64 renewal_deadline_unix, td::int64 now_unix) {
  // Convert before subtraction so extreme int64 values cannot overflow. Any
  // precision loss at those magnitudes is irrelevant after clamping to TTL.
  double until_deadline = static_cast<double>(renewal_deadline_unix) - static_cast<double>(now_unix);
  return now + std::max(0.0, std::min(base_ttl, until_deadline));
}

// Bounded-cache insertion policy: evict expired entries first, then the
// stalest live entry, so the map never exceeds max_entries.
inline void evict_for_insert(std::map<std::string, DnsCacheEntry>& cache, const std::string& key, double now,
                             size_t max_entries) {
  if (cache.size() < max_entries || cache.find(key) != cache.end()) {
    return;
  }
  auto oldest = cache.end();
  for (auto it = cache.begin(); it != cache.end();) {
    if (now >= it->second.expires_at_) {
      it = cache.erase(it);
      continue;
    }
    if (oldest == cache.end() || it->second.created_at_ < oldest->second.created_at_) {
      oldest = it;
    }
    ++it;
  }
  if (cache.size() >= max_entries && oldest != cache.end()) {
    cache.erase(oldest);
  }
}

}  // namespace dns
}  // namespace tos
