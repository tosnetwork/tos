/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <mutex>
#include <utility>
#include <vector>

namespace tos {
namespace validator {

// Archive packages and the blocks in them. ArchiveManager files a basechain
// block under its handle's masterchain reference seqno: the package is the one
// with the largest id not above that seqno (ArchiveManager::get_package_id,
// used by add_handle and move_block_to_archive). So a package with id `id`,
// followed in the archive by a package with id `next_id`, holds exactly the
// blocks whose reference lies in [id, next_id). Retention is expressed in
// those reference seqnos, which makes the package boundary exact.

// Nothing to keep beyond the archive TTL.
constexpr uint32_t kNoArchiveGcFloor = std::numeric_limits<uint32_t>::max();

// What archive pruning must keep, and what it has given up. Everything here
// changes only under `mutex`, which is held for a few comparisons and a map
// insertion, never across I/O or a wait:
//  - an applying block holds a lease on its reference seqno from before it is
//    filed until its reader has taken over (archive_lease_acquire/release);
//  - a reader keeps blocks from a reference seqno on (archive_retain, and
//    archive_set_floor for its recomputation);
//  - pruning admits each deletion against all of these (archive_admit_deletion)
//    and records, before the deletion's I/O, that references below the next
//    package's id may be gone.
struct ArchiveRetention {
  std::mutex mutex;
  uint32_t floor = kNoArchiveGcFloor;
  std::map<uint32_t, uint32_t> leases;  // reference seqno -> holders
  uint32_t deleted_below = 0;
};
inline ArchiveRetention g_archive_retention;

// Keep the package of a block with reference seqno `mc_seqno` while it is
// being applied. False when that package may already be given up.
inline bool archive_lease_acquire(uint32_t mc_seqno) {
  std::lock_guard<std::mutex> guard(g_archive_retention.mutex);
  if (mc_seqno < g_archive_retention.deleted_below) {
    return false;
  }
  g_archive_retention.leases[mc_seqno]++;
  return true;
}

inline void archive_lease_release(uint32_t mc_seqno) {
  std::lock_guard<std::mutex> guard(g_archive_retention.mutex);
  auto it = g_archive_retention.leases.find(mc_seqno);
  if (it != g_archive_retention.leases.end() && --it->second == 0) {
    g_archive_retention.leases.erase(it);
  }
}

// A reader keeps every package holding blocks with reference `mc_seqno` or
// later. False when such a package may already be given up.
inline bool archive_retain(uint32_t mc_seqno) {
  std::lock_guard<std::mutex> guard(g_archive_retention.mutex);
  if (mc_seqno < g_archive_retention.deleted_below) {
    return false;
  }
  g_archive_retention.floor = std::min(g_archive_retention.floor, mc_seqno);
  return true;
}

// The reader's recomputation from everything it still needs.
inline void archive_set_floor(uint32_t floor) {
  std::lock_guard<std::mutex> guard(g_archive_retention.mutex);
  g_archive_retention.floor = floor;
}

inline uint32_t archive_floor() {
  std::lock_guard<std::mutex> guard(g_archive_retention.mutex);
  return g_archive_retention.floor;
}

// Admit the deletion of a package followed by a package with id `next_id`:
// only when no reader, lease or block not yet applied may need a reference
// below `next_id`. Blocks are applied with references at or after the shard
// client's masterchain seqno (`shard_client_seqno`), so those are covered by
// it. Constant work under the lock.
inline bool archive_admit_deletion(uint32_t next_id, uint32_t shard_client_seqno) {
  std::lock_guard<std::mutex> guard(g_archive_retention.mutex);
  uint32_t limit = std::min(shard_client_seqno, g_archive_retention.floor);
  if (!g_archive_retention.leases.empty()) {
    limit = std::min(limit, g_archive_retention.leases.begin()->first);
  }
  if (next_id > limit) {
    return false;
  }
  g_archive_retention.deleted_below = std::max(g_archive_retention.deleted_below, next_id);
  return true;
}

// Which packages the archive TTL lets pruning consider. `first_ts` gives, in
// package order, the generation time of each candidate package's first
// masterchain block. A package qualifies when that time is before the TTL
// cutoff; the newest qualifying package is kept anyway.
inline std::vector<size_t> archive_packages_by_ttl(const std::vector<double>& first_ts, double gc_ts,
                                                   double archive_ttl) {
  double cutoff = gc_ts - archive_ttl;
  std::vector<size_t> out;
  for (size_t i = 0; i < first_ts.size(); ++i) {
    if (first_ts[i] < cutoff) {
      out.push_back(i);
    }
  }
  if (out.size() > 1) {
    out.pop_back();
  } else {
    out.clear();
  }
  return out;
}

// A package pruning may consider: when its first masterchain block was
// generated, and the id of the package after it in the archive.
struct ArchivePackage {
  double first_ts;
  uint32_t next_id;
};

// Delete what the TTL allows and admission confirms, one package at a time.
// Everything about the packages is computed before; each admission is
// constant work under the retention lock; the deletion (`remove`, which does
// the I/O) runs after the lock is released. `before_admit` is a test hook.
// Returns how many packages were deleted.
template <class Remove, class BeforeAdmit>
size_t prune_archive_packages(const std::vector<ArchivePackage>& packages, double gc_ts, double archive_ttl,
                              uint32_t shard_client_seqno, Remove&& remove, BeforeAdmit&& before_admit) {
  std::vector<double> first_ts;
  first_ts.reserve(packages.size());
  for (const auto& package : packages) {
    first_ts.push_back(package.first_ts);
  }
  size_t removed = 0;
  for (auto index : archive_packages_by_ttl(first_ts, gc_ts, archive_ttl)) {
    before_admit(index);
    if (archive_admit_deletion(packages[index].next_id, shard_client_seqno)) {
      remove(index);
      ++removed;
    }
  }
  return removed;
}

template <class Remove>
size_t prune_archive_packages(const std::vector<ArchivePackage>& packages, double gc_ts, double archive_ttl,
                              uint32_t shard_client_seqno, Remove&& remove) {
  return prune_archive_packages(packages, gc_ts, archive_ttl, shard_client_seqno, std::forward<Remove>(remove),
                                [](size_t) {});
}

// Tests only: forget leases, the floor and what pruning gave up.
inline void reset_archive_retention_for_testing() {
  std::lock_guard<std::mutex> guard(g_archive_retention.mutex);
  g_archive_retention.floor = kNoArchiveGcFloor;
  g_archive_retention.leases.clear();
  g_archive_retention.deleted_below = 0;
}

}  // namespace validator
}  // namespace tos
