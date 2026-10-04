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

// Least-recently-used block data keyed by block id, bounded by entry count and
// by the bytes of the allocations it created that are still alive.
//
// A stored payload is copied into an allocation of its own. A BufferSlice can
// be a view into a larger buffer, such as the network message it arrived in,
// or share a slab with unrelated small slices; retaining that view would keep
// the whole backing buffer alive while the cache counted only the view. The
// copy makes what an entry retains exactly its own allocation, which is what
// the entry is charged.
//
// get() hands out the cached slice, and callers clone it into asynchronous
// work (signature verification, block processing) that can outlive the entry.
// Such a clone shares the allocation, so evicting the entry would not free it.
// An evicted entry whose allocation is still shared is therefore retired, not
// released: it stays charged until every clone is gone, which sweep() notices.
// When retired allocations alone leave no room, put() refuses the payload
// (Full); a caller then finds no cached data and fetches the block the normal
// way. The bound on bytes alive covers every holder of an allocation this
// cache made, however long its asynchronous owner keeps it.
//
// Owned by one actor; not thread-safe, except that clones handed out may be
// dropped on any thread.
template <class Key>
class CandidateDataCache {
 public:
  enum class PutResult { Stored, AlreadyPresent, TooLarge, Full };

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

  // Stores a compact copy of `data` unless the key is present, the payload
  // exceeds the per-entry limit, or allocations still held by earlier callers
  // leave no room. Least-recently-used entries are evicted first until both
  // bounds hold. An existing entry is left as it is.
  PutResult put(const Key &key, const td::BufferSlice &data) {
    if (entries_.contains(key)) {
      return PutResult::AlreadyPresent;
    }
    if (data.size() > limits_.max_entry_size) {
      return PutResult::TooLarge;
    }
    std::size_t charge = charge_for(data.size());
    sweep();
    // Evict before allocating, so the copy never coexists with entries that
    // the bound already excludes.
    while (!order_.empty() && (entries_.size() >= limits_.max_entries || bytes_ > limits_.max_bytes - charge)) {
      erase(order_.front());
    }
    if (bytes_ > limits_.max_bytes - charge) {
      return PutResult::Full;
    }
    order_.push_back(key);
    Entry entry = make_entry(data.as_slice(), charge);
    entry.position = std::prev(order_.end());
    entries_.emplace(key, std::move(entry));
    bytes_ += charge;
    return PutResult::Stored;
  }

  // The cached payload, or nullptr. With `touch`, the entry becomes the most
  // recently used. A clone of it shares the cache's allocation and keeps it
  // charged until the clone is dropped.
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

  // Removes the entry. Its charge is released once no clone of it remains.
  void erase(const Key &key) {
    auto it = entries_.find(key);
    if (it == entries_.end()) {
      return;
    }
    order_.erase(it->second.position);
    retire(std::move(it->second));
    entries_.erase(it);
  }

  void clear() {
    for (auto &[key, entry] : entries_) {
      retire(std::move(entry));
    }
    entries_.clear();
    order_.clear();
  }

  // Releases the charge of retired allocations no clone holds any more.
  void sweep() {
    for (auto it = retired_.begin(); it != retired_.end();) {
      if (is_shared(*it)) {
        ++it;
        continue;
      }
      release(it->charge);
      it = retired_.erase(it);
    }
  }

  std::size_t size() const {
    return entries_.size();
  }
  // Bytes of the allocations this cache made that may still be alive: cached
  // entries and retired ones some caller still holds.
  std::size_t bytes() const {
    return bytes_;
  }
  std::size_t retired() const {
    return retired_.size();
  }
  const CandidateDataCacheLimits &limits() const {
    return limits_;
  }

 private:
  // The allocator never hands out an exclusive buffer smaller than this.
  static constexpr std::size_t kMinAllocation = 512;

  struct Entry {
    td::BufferSlice data;
    // The allocation behind `data`, kept alive by `data` itself; used only to
    // read how many slices share it.
    const td::BufferRaw *raw = nullptr;
    std::size_t charge = 0;
    typename std::list<Key>::iterator position;
  };

  static bool is_shared(const Entry &entry) {
    return entry.raw->ref_cnt_.load(std::memory_order_acquire) > 1;
  }

  void retire(Entry entry) {
    if (is_shared(entry)) {
      retired_.push_back(std::move(entry));
      return;
    }
    release(entry.charge);
  }

  void release(std::size_t charge) {
    CHECK(bytes_ >= charge);
    bytes_ -= charge;
  }

  static Entry make_entry(td::Slice data, std::size_t charge) {
    auto writer = td::BufferAllocator::create_writer(data.size());
    writer->end_.fetch_add((data.size() + 7) & ~static_cast<std::size_t>(7), std::memory_order_relaxed);
    std::size_t begin = writer->begin_;
    Entry entry;
    entry.raw = writer.get();
    entry.data = td::BufferSlice(td::BufferAllocator::create_reader(writer), begin, begin + data.size());
    entry.data.as_slice().copy_from(data);
    entry.charge = charge;
    return entry;
  }

  CandidateDataCacheLimits limits_;
  std::map<Key, Entry> entries_;
  std::list<Key> order_;
  std::list<Entry> retired_;
  std::size_t bytes_ = 0;
};

}  // namespace tos::validator
