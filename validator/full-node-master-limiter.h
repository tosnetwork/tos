/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <utility>

#include "td/utils/Status.h"
#include "td/utils/int_types.h"

namespace tos::validator::fullnode {

// Admission for the full-node master endpoint, shared by every master the
// engine runs.
//
// The aggregate ceiling is a token bucket of 16 requests of burst and 4
// requests per second. When the operator configures trusted slave identities,
// half of that burst and rate is reserved for them and divided equally, so
// each trusted identity owns its own bucket that neither public identities nor
// other trusted identities can drain. The other half serves everybody else
// through a shared public bucket plus a small bucket per source, with bounded
// per-source state.
//
// A trusted identity is an authenticated ADNL id: a slave signs in to the
// master's external port with its full-node key. With no trusted identity
// configured, public sources share the whole ceiling, and nothing prevents
// enough distinct identities from consuming it: there is then no
// Sybil-resistant availability guarantee.
//
// Token amounts are integers in units of 1/kUnit of a request. kUnit is a
// multiple of every trusted-set size up to kMaxTrusted and of 1000, so equal
// shares of the reserved burst and of the per-millisecond refill are exact.
template <typename SourceID>
class MasterIngressLimiter {
 public:
  // Monotonic milliseconds.
  using Clock = std::function<td::uint64()>;

  static constexpr td::uint64 kBurst = 16;
  static constexpr td::uint64 kPerSecond = 4;
  static constexpr size_t kMaxTrusted = 8;
  static constexpr td::uint64 kPerSourceBurst = 1;
  static constexpr td::uint64 kPerSourcePerSecond = 1;
  static constexpr size_t kMaxTrackedSources = 1000;
  static constexpr td::uint64 kPerSourceIdleMs = 300 * 1000;
  static constexpr td::uint64 kUnit = 840 * 1000;

  static td::Result<std::unique_ptr<MasterIngressLimiter>> create(std::set<SourceID> trusted, Clock clock) {
    TRY_STATUS(check_trusted(trusted));
    if (!clock) {
      return td::Status::Error("full-node master limiter needs a clock");
    }
    return std::unique_ptr<MasterIngressLimiter>(new MasterIngressLimiter(std::move(trusted), std::move(clock)));
  }

  MasterIngressLimiter(const MasterIngressLimiter &) = delete;
  MasterIngressLimiter &operator=(const MasterIngressLimiter &) = delete;

  // Replace the trusted set. A change never raises the tokens any bucket
  // holds: surviving buckets keep their current level clamped to their new
  // capacity, and identities that join the set start with an empty bucket.
  td::Status set_trusted(std::set<SourceID> trusted) {
    TRY_STATUS(check_trusted(trusted));
    std::lock_guard<std::mutex> lock(mutex_);
    td::uint64 now = clock_();
    public_.refill(now);
    for (auto &[id, bucket] : trusted_) {
      bucket.refill(now);
    }
    std::map<SourceID, Bucket> next;
    Shape share = trusted_share(trusted.size());
    for (const SourceID &id : trusted) {
      auto it = trusted_.find(id);
      td::uint64 level = it == trusted_.end() ? 0 : it->second.level;
      next.emplace(id, Bucket{share, std::min(level, share.capacity), now});
    }
    trusted_ = std::move(next);
    public_.reshape(public_shape(trusted_.size()));
    return td::Status::OK();
  }

  bool has_trusted() {
    std::lock_guard<std::mutex> lock(mutex_);
    return !trusted_.empty();
  }

  bool try_acquire(const SourceID &source) {
    std::lock_guard<std::mutex> lock(mutex_);
    td::uint64 now = clock_();
    auto trusted_it = trusted_.find(source);
    if (trusted_it != trusted_.end() && trusted_it->second.try_take(now)) {
      return true;
    }
    return try_acquire_public(source, now);
  }

  size_t tracked_sources() {
    std::lock_guard<std::mutex> lock(mutex_);
    return per_source_.size();
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

    bool has_token(td::uint64 now) {
      refill(now);
      return level >= kUnit;
    }

    bool try_take(td::uint64 now) {
      if (!has_token(now)) {
        return false;
      }
      level -= kUnit;
      return true;
    }

    void reshape(Shape next) {
      shape = next;
      level = std::min(level, shape.capacity);
    }
  };

  struct SourceEntry {
    Bucket bucket;
    td::uint64 last_use_ms;
  };

  MasterIngressLimiter(std::set<SourceID> trusted, Clock clock) : clock_(std::move(clock)) {
    td::uint64 now = clock_();
    Shape share = trusted_share(trusted.size());
    for (const SourceID &id : trusted) {
      trusted_.emplace(id, Bucket{share, share.capacity, now});
    }
    Shape shape = public_shape(trusted_.size());
    public_ = Bucket{shape, shape.capacity, now};
  }

  static td::Status check_trusted(const std::set<SourceID> &trusted) {
    if (trusted.size() > kMaxTrusted) {
      return td::Status::Error(PSLICE() << "at most " << kMaxTrusted
                                        << " trusted full-node slave ids are supported, so that each reserved share "
                                           "holds at least one whole request; got "
                                        << trusted.size());
    }
    return td::Status::OK();
  }

  // Requests per second expressed as kUnit-scaled tokens per millisecond.
  static constexpr td::uint64 per_ms(td::uint64 per_second) {
    return per_second * (kUnit / 1000);
  }

  static Shape trusted_share(size_t trusted_count) {
    if (trusted_count == 0) {
      return Shape{0, 0};
    }
    return Shape{kBurst / 2 * kUnit / trusted_count, per_ms(kPerSecond / 2) / trusted_count};
  }

  static Shape public_shape(size_t trusted_count) {
    if (trusted_count == 0) {
      return Shape{kBurst * kUnit, per_ms(kPerSecond)};
    }
    return Shape{(kBurst - kBurst / 2) * kUnit, per_ms(kPerSecond - kPerSecond / 2)};
  }

  bool try_acquire_public(const SourceID &source, td::uint64 now) {
    if (!public_.has_token(now)) {
      return false;
    }
    auto it = per_source_.find(source);
    if (it == per_source_.end()) {
      if (per_source_.size() >= kMaxTrackedSources && !evict_idle(now)) {
        return false;
      }
      Shape shape{kPerSourceBurst * kUnit, per_ms(kPerSourcePerSecond)};
      it = per_source_.emplace(source, SourceEntry{Bucket{shape, shape.capacity, now}, now}).first;
    }
    it->second.last_use_ms = now;
    if (!it->second.bucket.try_take(now)) {
      return false;
    }
    public_.level -= kUnit;
    return true;
  }

  // Evict the longest-idle source, but only one that has been idle long
  // enough; a full table of active sources rejects newcomers instead.
  bool evict_idle(td::uint64 now) {
    auto victim = per_source_.end();
    for (auto it = per_source_.begin(); it != per_source_.end(); ++it) {
      if (victim == per_source_.end() || it->second.last_use_ms < victim->second.last_use_ms) {
        victim = it;
      }
    }
    if (victim == per_source_.end() || now < victim->second.last_use_ms ||
        now - victim->second.last_use_ms < kPerSourceIdleMs) {
      return false;
    }
    per_source_.erase(victim);
    return true;
  }

  Clock clock_;
  std::mutex mutex_;
  Bucket public_{};
  std::map<SourceID, Bucket> trusted_;
  std::map<SourceID, SourceEntry> per_source_;
};

}  // namespace tos::validator::fullnode
