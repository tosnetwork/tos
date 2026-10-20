/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <map>
#include <memory>
#include <string>

#include "interfaces/liteserver.h"
#include "td/utils/LRUCache.h"
#include "td/utils/List.h"
#include "td/utils/Time.h"
#include "td/utils/buffer.h"

namespace tos::validator {

// Bounded store of lite-server query answers.
//
// A cache is a memory budget, so every bound here is on memory the store itself
// owns:
//  - each entry keeps a private copy of the answer in a plain string, sized by
//    the answer rather than by whoever produced it. An answer arrives as a view into the buffer the serializer or the
//    network wrote, and a shared view keeps that whole buffer alive; small
//    answers carved from pooled slabs pinned the slab long after everything
//    else in it was gone. A hit hands out a fresh buffer copied from the
//    string, so no caller can pin anything the store owns;
//  - the logical charge counts the string's capacity plus a fixed per-entry
//    overhead for the map node and the entry, so the byte bound tracks heap
//    use rather than the answer's nominal length;
//  - the entry count is bounded as well, so per-entry overhead cannot dominate
//    the byte bound when every answer is tiny;
//  - an entry idle longer than MAX_ENTRY_IDLE is dropped by the periodic sweep
//    and refused by lookup. A cached answer for a pinned block stays correct
//    forever, but once the head has moved on it is never asked for again.
// The class is plain so the bounds can be exercised without an actor scheduler;
// the actor below owns one and feeds it the monotonic clock.
class LiteServerQueryCache {
 public:
  // Logical charge bound: answer bytes plus ENTRY_OVERHEAD per entry.
  static constexpr size_t MAX_CACHE_SIZE = 64 << 20;
  // Entry bound: with every answer tiny, the overhead alone stays near 16 MiB.
  static constexpr size_t MAX_CACHE_ENTRIES = 1 << 16;
  // Charged per entry on top of the answer's storage: the map node and the
  // entry with its list links and string header. The unit test checks that the
  // structures this charge stands for fit in it.
  static constexpr size_t ENTRY_OVERHEAD = 256;
  // An entry neither looked up nor refreshed for this long is dropped.
  static constexpr double MAX_ENTRY_IDLE = 600.0;
  // Answers larger than this are served but not cached: caching one would
  // evict everything else for a result nobody is likely to ask for twice.
  static constexpr size_t MAX_ENTRY_VALUE_SIZE = MAX_CACHE_SIZE / 16;

  struct CacheEntry : public td::ListNode {
    CacheEntry(td::Bits256 key, std::string value, double now)
        : key_(key), value_(std::move(value)), last_access_(now) {
    }
    td::Bits256 key_;
    // Owned storage, sized by private_copy; the charge counts its capacity.
    std::string value_;
    double last_access_;

    size_t charge() const {
      return LiteServerQueryCache::charge(value_.capacity());
    }
  };

  static size_t charge(size_t storage_size) {
    return storage_size + ENTRY_OVERHEAD;
  }

  // Whether an answer of this size may be cached at all.
  static bool admissible(size_t value_size) {
    return value_size <= MAX_ENTRY_VALUE_SIZE;
  }

  // A private copy sized to the answer: a fresh string, never a slice of a
  // pooled slab, so the copy pins nothing but itself. A replacement gets a new
  // string rather than reusing the old one's capacity, so a small answer never
  // keeps a large predecessor's storage.
  static std::string private_copy(td::Slice value) {
    std::string copy(value.data(), value.size());
    copy.shrink_to_fit();
    return copy;
  }

  // The cached answer for `key`, or an error when there is none or it has gone
  // idle. A hit refreshes the entry's recency and idle clock.
  td::Result<td::BufferSlice> lookup(td::Bits256 key, double now) {
    auto it = cache_.find(key);
    if (it == cache_.end()) {
      return td::Status::Error("not found");
    }
    CacheEntry *entry = it->second.get();
    if (is_idle(*entry, now)) {
      erase(entry);
      return td::Status::Error("not found");
    }
    touch(entry, now);
    return td::BufferSlice(td::Slice(entry->value_));
  }

  // Stores a private copy of `value` under `key`, replacing any earlier answer,
  // and evicts least recently used entries until both bounds hold. Returns
  // false when the answer is too large to cache; nothing is evicted then.
  bool update(td::Bits256 key, td::Slice value, double now) {
    if (!admissible(value.size())) {
      ++rejected_oversized_;
      return false;
    }
    std::string copy = private_copy(value);
    std::unique_ptr<CacheEntry> &slot = cache_[key];
    if (slot == nullptr) {
      slot = std::make_unique<CacheEntry>(key, std::move(copy), now);
    } else {
      total_size_ -= slot->charge();
      // Swap rather than assign: assignment may keep the old buffer when the new
      // answer fits in it, and the charge would then count storage the small
      // answer does not need.
      slot->value_.swap(copy);
      slot->remove();
    }
    total_size_ += slot->charge();
    touch(slot.get(), now);
    enforce_bounds();
    return true;
  }

  // Drops entries idle longer than MAX_ENTRY_IDLE, oldest first, and returns
  // how many were dropped. Recency order equals access-time order because
  // every lookup and update moves its entry to the head, so the walk stops at
  // the first entry still young. The cost is bounded by the number dropped.
  size_t expire_idle(double now) {
    size_t expired = 0;
    while (!lru_.empty()) {
      // Peek: `get()` would unlink the entry, and a young entry must stay in
      // the list or no later sweep or eviction could ever reach it.
      auto *oldest = static_cast<CacheEntry *>(oldest_node());
      if (!is_idle(*oldest, now)) {
        break;
      }
      erase(oldest);
      ++expired;
    }
    return expired;
  }

  size_t entries() const {
    return cache_.size();
  }
  size_t total_size() const {
    return total_size_;
  }
  size_t rejected_oversized() const {
    return rejected_oversized_;
  }

 private:
  static bool is_idle(const CacheEntry &entry, double now) {
    return now - entry.last_access_ > MAX_ENTRY_IDLE;
  }

  // Moves `entry` to the most recently used position.
  void touch(CacheEntry *entry, double now) {
    entry->last_access_ = now;
    entry->remove();
    lru_.put(entry);
  }

  void erase(CacheEntry *entry) {
    total_size_ -= entry->charge();
    entry->remove();
    cache_.erase(entry->key_);
  }

  void enforce_bounds() {
    while (total_size_ > MAX_CACHE_SIZE || cache_.size() > MAX_CACHE_ENTRIES) {
      CHECK(!lru_.empty());
      erase(static_cast<CacheEntry *>(oldest_node()));
    }
  }

  // The least recently used entry, still linked: `put` inserts at the front
  // and `get` takes from the back, so the oldest is the head's `prev`.
  td::ListNode *oldest_node() {
    return lru_.get_prev();
  }

  std::map<td::Bits256, std::unique_ptr<CacheEntry>> cache_;
  // Least recently used at the tail (`get()`), most recently used at the head.
  td::ListNode lru_;
  size_t total_size_ = 0;
  size_t rejected_oversized_ = 0;
};

class LiteServerCacheImpl : public LiteServerCache {
 public:
  void start_up() override {
    alarm();
  }

  void alarm() override {
    alarm_timestamp() = td::Timestamp::in(60.0);
    // The idle sweep runs whether or not anything was asked in the last minute:
    // an idle node is exactly when retained answers stop earning their memory.
    size_t expired = cache_.expire_idle(td::Time::now());
    if (queries_cnt_ > 0 || expired > 0 || !send_message_cache_.empty()) {
      LOG(WARNING) << "LS Cache stats: " << queries_cnt_ << " queries, " << queries_hit_cnt_ << " hits; "
                   << cache_.entries() << "/" << LiteServerQueryCache::MAX_CACHE_ENTRIES
                   << " entries, size=" << cache_.total_size() << "/" << LiteServerQueryCache::MAX_CACHE_SIZE << ", "
                   << expired << " expired, " << cache_.rejected_oversized() << " oversized;   "
                   << send_message_cache_.size() << " different sendMessage queries, " << send_message_error_cnt_
                   << " duplicates";
      queries_cnt_ = 0;
      queries_hit_cnt_ = 0;
      send_message_cache_.clear();
      send_message_error_cnt_ = 0;
    }
  }

  void lookup(td::Bits256 key, td::Promise<td::BufferSlice> promise) override {
    ++queries_cnt_;
    auto result = cache_.lookup(key, td::Time::now());
    if (result.is_error()) {
      promise.set_error(result.move_as_error());
      return;
    }
    ++queries_hit_cnt_;
    promise.set_value(result.move_as_ok());
  }

  void update(td::Bits256 key, td::BufferSlice value) override {
    cache_.update(key, value.as_slice(), td::Time::now());
  }

  void process_send_message(td::Bits256 key, td::Promise<td::Unit> promise) override {
    if (send_message_cache_.contains(key)) {
      ++send_message_error_cnt_;
      promise.set_error(td::Status::Error("duplicate message"));
      return;
    }
    send_message_cache_.put(key, td::Unit{});
    promise.set_result(td::Unit());
  }

  void drop_send_message_from_cache(td::Bits256 key) override {
    send_message_cache_.erase(key);
  }

 private:
  static constexpr size_t MAX_MSG_CACHE_SIZE = 1 << 17;

  LiteServerQueryCache cache_;

  size_t queries_cnt_ = 0, queries_hit_cnt_ = 0;

  td::LRUCache<td::Bits256, td::Unit> send_message_cache_{MAX_MSG_CACHE_SIZE};
  size_t send_message_error_cnt_ = 0;
};

}  // namespace tos::validator
