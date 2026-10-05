/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <utility>

#include "td/utils/Status.h"
#include "td/utils/int_types.h"

namespace tos::validator::fullnode {

// Outcome of admitting one request to the full-node master service.
enum class MasterAdmission {
  // The source is a configured slave and its own bucket held a request.
  Admitted,
  // The source is not a configured slave. Nothing was charged and no state
  // was created for it.
  NotListed,
  // The source is a configured slave whose own bucket is empty.
  RateLimited,
};

// Admission for the full-node master service, shared by every master the
// engine runs, so the ceiling holds across all listening ports together.
//
// The service is allowlist-only. Only the configured slave identities are
// served; every other source, including any connection that did not
// authenticate, is refused before it reaches any bucket. A configured identity
// is an authenticated ADNL id: a slave signs in to the master's external port
// with its full-node key. An external connection that did not sign in is
// attributed an id derived from its address, which is never a configured key
// id, so it is refused like any other unlisted source.
//
// The aggregate ceiling is a token bucket of kBurst requests of burst and
// kPerSecond requests per second. It is divided into equal, independent
// buckets, one per configured identity, and nothing else draws on it: no
// identity's traffic, and no unlisted traffic, can take a request from
// another identity's bucket, whatever order requests arrive in.
//
// Token amounts are integers in units of 1/kUnit of a request. kUnit is a
// multiple of every allowlist size up to kMaxTrusted and of 1000, so the equal
// shares of the burst and of the per-millisecond refill are exact and add up
// to the aggregate ceiling with nothing lost to rounding.
template <typename SourceID>
class MasterIngressLimiter {
 public:
  // Monotonic milliseconds.
  using Clock = std::function<td::uint64()>;

  static constexpr td::uint64 kBurst = 16;
  static constexpr td::uint64 kPerSecond = 4;
  static constexpr size_t kMaxTrusted = 8;
  static constexpr td::uint64 kUnit = 840 * 1000;

  static_assert(kUnit % 1000 == 0, "the per-millisecond refill must be exact");
  static_assert(kUnit % 840 == 0, "840 is the least common multiple of 1..8");
  static_assert(kMaxTrusted <= 8, "kUnit only divides evenly for allowlists of up to 8 identities");
  static_assert(kPerSecond * (kUnit / 1000) % 840 == 0, "every share of the refill must be exact");

  // Refuses an empty allowlist: a master with nobody to serve is a
  // configuration error, not an open service.
  static td::Result<std::unique_ptr<MasterIngressLimiter>> create(std::set<SourceID> trusted, Clock clock) {
    TRY_STATUS(check_trusted(trusted));
    if (!clock) {
      return td::Status::Error("full-node master limiter needs a clock");
    }
    return std::unique_ptr<MasterIngressLimiter>(new MasterIngressLimiter(std::move(trusted), std::move(clock)));
  }

  static td::Status check_trusted(const std::set<SourceID> &trusted) {
    if (trusted.empty()) {
      return td::Status::Error(
          "the full-node master service is allowlist-only and has no trusted slave ids: configure at least one "
          "--full-node-master-trusted id, or remove the full-node master from the configuration");
    }
    if (trusted.size() > kMaxTrusted) {
      return td::Status::Error(PSLICE() << "at most " << kMaxTrusted
                                        << " trusted full-node slave ids are supported, so that each share holds "
                                           "at least one whole request; got "
                                        << trusted.size());
    }
    return td::Status::OK();
  }

  MasterIngressLimiter(const MasterIngressLimiter &) = delete;
  MasterIngressLimiter &operator=(const MasterIngressLimiter &) = delete;

  MasterAdmission try_acquire(const SourceID &source) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = trusted_.find(source);
    if (it == trusted_.end()) {
      return MasterAdmission::NotListed;
    }
    return it->second.try_take(clock_()) ? MasterAdmission::Admitted : MasterAdmission::RateLimited;
  }

  size_t trusted_count() {
    std::lock_guard<std::mutex> lock(mutex_);
    return trusted_.size();
  }

  // One identity's share, in requests, as a fraction: burst is
  // share_burst_units() / kUnit requests, and the refill is
  // share_per_ms_units() / kUnit requests per millisecond.
  td::uint64 share_burst_units() const {
    return share_.capacity;
  }
  td::uint64 share_per_ms_units() const {
    return share_.per_ms;
  }

 private:
  struct Shape {
    td::uint64 capacity;
    td::uint64 per_ms;
  };

  struct Bucket {
    Shape shape;
    td::uint64 level;
    td::uint64 last_ms;

    void refill(td::uint64 now) {
      if (now <= last_ms) {
        return;
      }
      td::uint64 elapsed = now - last_ms;
      last_ms = now;
      if (level >= shape.capacity) {
        level = shape.capacity;
        return;
      }
      td::uint64 missing = shape.capacity - level;
      // elapsed * per_ms >= missing, computed without overflow.
      if (shape.per_ms != 0 && elapsed >= (missing + shape.per_ms - 1) / shape.per_ms) {
        level = shape.capacity;
      } else {
        level += elapsed * shape.per_ms;
      }
    }

    bool try_take(td::uint64 now) {
      refill(now);
      if (level < kUnit) {
        return false;
      }
      level -= kUnit;
      return true;
    }
  };

  MasterIngressLimiter(std::set<SourceID> trusted, Clock clock)
      : clock_(std::move(clock)), share_(equal_share(trusted.size())) {
    td::uint64 now = clock_();
    for (const SourceID &id : trusted) {
      trusted_.emplace(id, Bucket{share_, share_.capacity, now});
    }
  }

  // Requests per second expressed as kUnit-scaled tokens per millisecond.
  static constexpr td::uint64 per_ms(td::uint64 per_second) {
    return per_second * (kUnit / 1000);
  }

  // Only called with 1..kMaxTrusted identities, which check_trusted enforces.
  static Shape equal_share(size_t trusted_count) {
    return Shape{kBurst * kUnit / trusted_count, per_ms(kPerSecond) / trusted_count};
  }

  Clock clock_;
  Shape share_;
  std::mutex mutex_;
  std::map<SourceID, Bucket> trusted_;
};

}  // namespace tos::validator::fullnode
