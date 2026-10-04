/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <cstddef>
#include <list>
#include <map>
#include <utility>

#include "td/utils/buffer.h"
#include "td/utils/check.h"

namespace tos::validator {

struct CandidateDataCacheLimits {
  std::size_t max_entries;
  // Bytes of backing allocations the cache keeps alive, all entries together.
  std::size_t max_bytes;
  // Largest payload one entry may hold.
  std::size_t max_entry_size;
};

// Least-recently-used block data keyed by block id, bounded both by entry count
// and by the bytes of the allocations its entries keep alive.
//
// A stored payload is copied into an allocation of its own. A BufferSlice can
// be a view into a larger buffer, such as the network message it arrived in,
// or share a slab with unrelated small slices; retaining that view would keep
// the whole backing buffer alive while the cache counted only the view. The
// copy makes what an entry retains exactly its own allocation, which is what
// the entry is charged. Slices handed out by get() are clones of that
// allocation and share it; they do not hold a second payload.
//
// Owned by one actor; not thread-safe. Every removal (eviction, erase, clear,
// destruction) releases the entry's charge.
template <class Key>
class CandidateDataCache {
 public:
  enum class PutResult { Stored, AlreadyPresent, TooLarge };

  explicit CandidateDataCache(CandidateDataCacheLimits limits) : limits_(limits) {
    CHECK(limits_.max_entries > 0);
    CHECK(limits_.max_entry_size > 0);
    CHECK(charge_for(limits_.max_entry_size) <= limits_.max_bytes);
  }
  CandidateDataCache(const CandidateDataCache &) = delete;
  CandidateDataCache &operator=(const CandidateDataCache &) = delete;

  // Bytes an entry holding `size` payload bytes is charged: the allocation
  // header and the payload, rounded and padded as the allocator does.
  static std::size_t charge_for(std::size_t size) {
    std::size_t payload = size < kMinAllocation ? kMinAllocation : size;
    payload = (payload + 7) & ~static_cast<std::size_t>(7);
    return sizeof(td::BufferRaw) + payload;
  }

  // Stores a compact copy of `data` unless the key is present or the payload
  // exceeds the per-entry limit, then evicts least-recently-used entries until
  // both bounds hold. An existing entry is left as it is.
  PutResult put(const Key &key, const td::BufferSlice &data) {
    if (entries_.contains(key)) {
      return PutResult::AlreadyPresent;
    }
    if (data.size() > limits_.max_entry_size) {
      return PutResult::TooLarge;
    }
    std::size_t charge = charge_for(data.size());
    // Evict before allocating, so the copy never coexists with entries that
    // the bound already excludes.
    while (!order_.empty() && (entries_.size() >= limits_.max_entries || bytes_ > limits_.max_bytes - charge)) {
      erase(order_.front());
    }
    order_.push_back(key);
    Entry entry{copy_exclusive(data.as_slice()), charge, std::prev(order_.end())};
    entries_.emplace(key, std::move(entry));
    bytes_ += charge;
    return PutResult::Stored;
  }

  // The cached payload, or nullptr. With `touch`, the entry becomes the most
  // recently used.
  const td::BufferSlice *get(const Key &key, bool touch = true) {
    auto it = entries_.find(key);
    if (it == entries_.end()) {
      return nullptr;
    }
    if (touch) {
      order_.splice(order_.end(), order_, it->second.position);
    }
    return &it->second.data;
  }

  bool contains(const Key &key) const {
    return entries_.contains(key);
  }

  void erase(const Key &key) {
    auto it = entries_.find(key);
    if (it == entries_.end()) {
      return;
    }
    CHECK(bytes_ >= it->second.charge);
    bytes_ -= it->second.charge;
    order_.erase(it->second.position);
    entries_.erase(it);
  }

  void clear() {
    entries_.clear();
    order_.clear();
    bytes_ = 0;
  }

  std::size_t size() const {
    return entries_.size();
  }
  std::size_t bytes() const {
    return bytes_;
  }
  const CandidateDataCacheLimits &limits() const {
    return limits_;
  }

 private:
  // The allocator never hands out an exclusive buffer smaller than this.
  static constexpr std::size_t kMinAllocation = 512;

  struct Entry {
    td::BufferSlice data;
    std::size_t charge;
    typename std::list<Key>::iterator position;
  };

  static td::BufferSlice copy_exclusive(td::Slice data) {
    auto writer = td::BufferAllocator::create_writer(data.size());
    writer->end_.fetch_add((data.size() + 7) & ~static_cast<std::size_t>(7), std::memory_order_relaxed);
    std::size_t begin = writer->begin_;
    td::BufferSlice result(td::BufferAllocator::create_reader(writer), begin, begin + data.size());
    result.as_slice().copy_from(data);
    return result;
  }

  CandidateDataCacheLimits limits_;
  std::map<Key, Entry> entries_;
  std::list<Key> order_;
  std::size_t bytes_ = 0;
};

}  // namespace tos::validator
