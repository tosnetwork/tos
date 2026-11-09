/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <array>
#include <atomic>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <vector>

#include "consensus/types.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "validator/candidate-data-cache.h"

namespace tos::validator::consensus::simplex {

inline td::uint64 saturating_add(td::uint64 a, td::uint64 b) {
  return a > std::numeric_limits<td::uint64>::max() - b ? std::numeric_limits<td::uint64>::max() : a + b;
}

inline td::uint64 saturating_sub(td::uint64 a, td::uint64 b) {
  return a >= b ? a - b : 0;
}

constexpr td::uint64 DEFAULT_CANDIDATE_CACHE_BYTES = td::uint64{512} << 20;

// The bytes of finalized candidate payloads all candidate resolvers of this process may keep
// cached together. Every session reads the same environment, so this is one allowance for the
// whole node. Zero is valid and means that no finalized payload is cached: every later reader
// loads it from the database.
inline td::uint64 candidate_cache_bytes_from_env() {
  const char* value = std::getenv("TOS_SIMPLEX_CANDIDATE_CACHE_BYTES");
  if (value == nullptr) {
    return DEFAULT_CANDIDATE_CACHE_BYTES;
  }
  auto parsed = td::to_integer_safe<td::uint64>(td::Slice(value));
  if (parsed.is_error()) {
    LOG(WARNING) << "Simplex candidate-resolver: ignoring invalid TOS_SIMPLEX_CANDIDATE_CACHE_BYTES=" << value;
    return DEFAULT_CANDIDATE_CACHE_BYTES;
  }
  return parsed.ok();
}

// The allocations behind one cached payload: its block data, collated data and signature,
// each a compact copy the resolver made, and the bytes they are charged together.
struct CachedPayloadAllocations {
  std::array<const td::BufferRaw*, 3> raws{};
  td::uint64 charge = 0;
};

// The node-wide allowance for cached finalized payloads, shared by every candidate resolver
// of the process. Resolvers run as actors on any scheduler thread, so the charge is one
// atomic counter, and a reservation either fits under the limit or is refused as a whole:
// however many resolvers reserve at once, the charged bytes never exceed the limit.
//
// A charge covers the allocations a resolver made for a payload, not the resolver's
// reference to it. A payload the resolver stops caching while something else still holds it
// (a coroutine that resolved it, a block being applied, a clone of its data) is retired: it
// stays charged here until the last holder is gone, which sweep() notices. Retired payloads
// belong to this object, not to the session that cached them, so they stay charged after
// that session ends and are never charged twice or released twice.
class CandidatePayloadBudget {
 public:
  struct Snapshot {
    td::uint64 limit = 0;
    td::uint64 charged_bytes = 0;
    td::uint64 charged_peak = 0;
    td::uint64 retired_bytes = 0;
    size_t retired_payloads = 0;
    td::uint64 refused_reservations = 0;
    td::uint64 accounting_errors = 0;
  };

  explicit CandidatePayloadBudget(td::uint64 limit) : limit_(limit) {
  }
  CandidatePayloadBudget(const CandidatePayloadBudget&) = delete;
  CandidatePayloadBudget& operator=(const CandidatePayloadBudget&) = delete;

  td::uint64 limit() const {
    return limit_;
  }

  // Charges `charge` bytes if they fit under the limit together with everything already
  // charged. A refusal changes nothing.
  bool try_reserve(td::uint64 charge) {
    auto current = charged_.load(std::memory_order_acquire);
    do {
      if (charge > limit_ || current > limit_ - charge) {
        refused_.fetch_add(1, std::memory_order_relaxed);
        return false;
      }
    } while (!charged_.compare_exchange_weak(current, current + charge, std::memory_order_acq_rel,
                                             std::memory_order_acquire));
    auto charged = current + charge;
    auto peak = charged_peak_.load(std::memory_order_relaxed);
    while (peak < charged && !charged_peak_.compare_exchange_weak(peak, charged, std::memory_order_relaxed)) {
    }
    return true;
  }

  // Returns a charge reserved earlier. Returning more than is charged is an accounting
  // error: it is counted and logged, and the counter stops at zero instead of wrapping.
  void release(td::uint64 charge) {
    auto current = charged_.load(std::memory_order_acquire);
    td::uint64 next = 0;
    do {
      next = current >= charge ? current - charge : 0;
    } while (!charged_.compare_exchange_weak(current, next, std::memory_order_acq_rel, std::memory_order_acquire));
    if (current < charge) {
      accounting_errors_.fetch_add(1, std::memory_order_relaxed);
      LOG(ERROR) << "Simplex candidate-resolver: payload cache released " << charge << " bytes with only " << current
                 << " charged";
    }
  }

  // Takes over a payload the caller stops caching, with the charge of its allocations.
  // `payload` must be the caller's last reference. The charge is returned now if nothing
  // else holds the payload or its allocations, otherwise once sweep() finds them released.
  void retire(CandidateRef payload, const CachedPayloadAllocations& allocations) {
    Retired entry{std::move(payload), allocations};
    if (!is_held_elsewhere(entry)) {
      release(entry.allocations.charge);
      return;
    }
    std::scoped_lock lock(mutex_);
    retired_bytes_ = saturating_add(retired_bytes_, entry.allocations.charge);
    retired_.push_back(std::move(entry));
  }

  // Returns the charge of every retired payload nothing holds any more. The payloads
  // themselves are freed after the lock is released.
  void sweep() {
    std::vector<Retired> released;
    {
      std::scoped_lock lock(mutex_);
      for (size_t i = 0; i < retired_.size();) {
        if (is_held_elsewhere(retired_[i])) {
          ++i;
          continue;
        }
        auto charge = retired_[i].allocations.charge;
        retired_bytes_ = saturating_sub(retired_bytes_, charge);
        released.push_back(std::move(retired_[i]));
        retired_[i] = std::move(retired_.back());
        retired_.pop_back();
      }
    }
    for (const auto& entry : released) {
      release(entry.allocations.charge);
    }
  }

  Snapshot snapshot() const {
    Snapshot result;
    result.limit = limit_;
    result.charged_bytes = charged_.load(std::memory_order_acquire);
    result.charged_peak = charged_peak_.load(std::memory_order_relaxed);
    result.refused_reservations = refused_.load(std::memory_order_relaxed);
    result.accounting_errors = accounting_errors_.load(std::memory_order_relaxed);
    std::scoped_lock lock(mutex_);
    result.retired_bytes = retired_bytes_;
    result.retired_payloads = retired_.size();
    return result;
  }

 private:
  struct Retired {
    CandidateRef payload;
    CachedPayloadAllocations allocations;
  };

  static bool is_held_elsewhere(const Retired& entry) {
    if (entry.payload.not_null() && entry.payload->get_refcnt() > 1) {
      return true;
    }
    for (const auto* raw : entry.allocations.raws) {
      if (compact_buffer_is_shared(raw)) {
        return true;
      }
    }
    return false;
  }

  const td::uint64 limit_;
  std::atomic<td::uint64> charged_{0};
  std::atomic<td::uint64> charged_peak_{0};
  std::atomic<td::uint64> refused_{0};
  std::atomic<td::uint64> accounting_errors_{0};
  mutable std::mutex mutex_;
  std::vector<Retired> retired_;
  td::uint64 retired_bytes_ = 0;
};

// The allowance of this process, created on first use from the environment.
inline CandidatePayloadBudget& node_candidate_payload_budget() {
  static CandidatePayloadBudget budget{candidate_cache_bytes_from_env()};
  return budget;
}

// A compact copy of a candidate for the cache, and the allocations it is charged for. The
// block data, collated data and signature get allocations of their own: the originals can
// be views into larger buffers (a network message, a decompression buffer) that holding
// them would keep alive uncounted. The locally collected queue-proof broadcasts are left
// out, as they are from the database record a later reader would load instead.
inline td::uint64 compact_candidate_charge(const Candidate& candidate) {
  td::uint64 charge = 0;
  auto add = [&](const td::BufferSlice& slice) {
    if (!slice.empty()) {
      charge = saturating_add(charge, compact_buffer_charge(slice.size()));
    }
  };
  add(candidate.signature);
  if (const auto* block = std::get_if<BlockCandidate>(&candidate.block)) {
    add(block->data);
    add(block->collated_data);
  }
  return charge;
}

inline CandidateRef make_compact_candidate(const Candidate& candidate, CachedPayloadAllocations& allocations) {
  size_t next = 0;
  auto copy = [&](const td::BufferSlice& slice) {
    if (slice.empty()) {
      return td::BufferSlice();
    }
    auto compact = make_compact_buffer(slice.as_slice());
    allocations.raws[next++] = compact.raw;
    return std::move(compact.data);
  };
  allocations.charge = compact_candidate_charge(candidate);
  auto signature = copy(candidate.signature);
  if (const auto* original = std::get_if<BlockCandidate>(&candidate.block)) {
    BlockCandidate block{original->producer, original->id, original->collated_file_hash, copy(original->data),
                         copy(original->collated_data)};
    return td::make_ref<Candidate>(candidate.id, candidate.parent_id, candidate.leader, std::move(block),
                                   std::move(signature));
  }
  return td::make_ref<Candidate>(candidate.id, candidate.parent_id, candidate.leader,
                                 std::get<BlockIdExt>(candidate.block), std::move(signature));
}

}  // namespace tos::validator::consensus::simplex
