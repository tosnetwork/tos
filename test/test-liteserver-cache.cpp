/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
// The lite-server query cache bounds the memory it owns, not a proxy for it.
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "td/utils/buffer.h"
#include "td/utils/memory-tracker.h"
#include "td/utils/port/thread_local.h"
#include "td/utils/tests.h"
#include "validator/impl/liteserver-cache.hpp"

using tos::validator::LiteServerQueryCache;

namespace {

td::Bits256 key_of(size_t i) {
  td::Bits256 key = td::Bits256::zero();
  std::memcpy(key.as_slice().begin(), &i, sizeof(i));
  return key;
}

std::string value_of(size_t i, size_t size) {
  std::string value(size, static_cast<char>('a' + i % 26));
  if (size >= sizeof(i)) {
    std::memcpy(value.data(), &i, sizeof(i));
  }
  return value;
}

constexpr double kNow = 1'000'000.0;

}  // namespace

// Registered first so the memory diagnostics switch is read before any buffer
// of this process is allocated; the counters are off otherwise.
TEST(LiteServerCache, private_copies_do_not_pin_pooled_slabs) {
  setenv("TOS_MEMORY_DIAGNOSTICS", "1", 1);
  ASSERT_TRUE(td::memory_tracker_enabled());

  // Answers of the size the small-buffer pool serves (under 512 bytes), each
  // interleaved with a transient buffer that leaves the slab again: the sparse
  // slab case from the field. Every allocation happens on a worker thread that
  // releases its thread-local current slab and exits before measuring, so the
  // only thing that can keep a slab alive is what the two stores hold.
  constexpr size_t kAnswers = 20'000;
  constexpr size_t kAnswerSize = 100;
  LiteServerQueryCache cache;
  std::vector<td::BufferSlice> pinned_like_before;  // what the old cache stored: clones of the arrivals

  auto baseline = td::BufferAllocator::get_memory_stats();
  size_t slabs_seen_while_allocating = 0;
  {
    std::thread worker([&] {
      for (size_t i = 0; i < kAnswers; i++) {
        td::BufferSlice arrival(kAnswerSize);  // carved from the thread's current slab
        std::memcpy(arrival.as_slice().begin(), value_of(i, kAnswerSize).data(), kAnswerSize);
        td::BufferSlice transient(kAnswerSize * 3);  // leaves the slab as soon as this iteration ends
        pinned_like_before.push_back(arrival.clone());
        ASSERT_TRUE(cache.update(key_of(i), arrival.as_slice(), kNow));
      }
      slabs_seen_while_allocating = td::BufferAllocator::get_memory_stats().live_small_slabs;
      td::clear_thread_locals();  // drop the worker's current slab reference
    });
    worker.join();
  }
  ASSERT_TRUE(slabs_seen_while_allocating > baseline.live_small_slabs);  // the instrument saw the slabs
  ASSERT_EQ(kAnswers, cache.entries());

  // Positive control of the measurement: the clones the old cache kept hold
  // every slab alive even though the arrivals and the transients are gone.
  auto with_clones = td::BufferAllocator::get_memory_stats();
  ASSERT_TRUE(with_clones.live_small_slab_bytes > baseline.live_small_slab_bytes);

  // The fix: once the clones are gone, the slabs are gone, while the cache is
  // still full and still answers correctly from its private copies.
  pinned_like_before.clear();
  auto with_cache_only = td::BufferAllocator::get_memory_stats();
  ASSERT_EQ(baseline.live_small_slab_bytes, with_cache_only.live_small_slab_bytes);
  ASSERT_EQ(kAnswers, cache.entries());
  auto hit = cache.lookup(key_of(kAnswers / 2), kNow);
  ASSERT_TRUE(hit.is_ok());
  ASSERT_EQ(value_of(kAnswers / 2, kAnswerSize), hit.ok().as_slice().str());
}

TEST(LiteServerCache, overhead_charge_covers_the_structures_it_stands_for) {
  // Map node: three pointers and a colour plus the key and the owning pointer.
  constexpr size_t kMapNodeEstimate = 4 * sizeof(void *) + sizeof(td::Bits256) + sizeof(void *);
  size_t structures = sizeof(LiteServerQueryCache::CacheEntry) + kMapNodeEstimate;
  ASSERT_TRUE(structures <= LiteServerQueryCache::ENTRY_OVERHEAD);
  ASSERT_EQ(LiteServerQueryCache::ENTRY_OVERHEAD + 10, LiteServerQueryCache::charge(10));
  // The charge follows the storage actually held, not the nominal length.
  LiteServerQueryCache cache;
  std::string answer(1000, 'z');
  ASSERT_TRUE(cache.update(key_of(1), answer, kNow));
  ASSERT_TRUE(cache.total_size() >= LiteServerQueryCache::charge(answer.size()));
  ASSERT_TRUE(cache.total_size() <= LiteServerQueryCache::charge(answer.size() + 64));
}

TEST(LiteServerCache, entry_count_is_bounded_and_evicts_the_least_recently_used) {
  LiteServerQueryCache cache;
  constexpr size_t kExtra = 1000;
  constexpr size_t kTotal = LiteServerQueryCache::MAX_CACHE_ENTRIES + kExtra;
  for (size_t i = 0; i < kTotal; i++) {
    ASSERT_TRUE(cache.update(key_of(i), value_of(i, 16), kNow + static_cast<double>(i) * 1e-6));
  }
  ASSERT_EQ(LiteServerQueryCache::MAX_CACHE_ENTRIES, cache.entries());
  ASSERT_TRUE(cache.total_size() <= LiteServerQueryCache::MAX_CACHE_SIZE);
  // Tiny answers never reach the byte bound; without the entry bound all of
  // them would have stayed.
  ASSERT_TRUE(cache.total_size() < LiteServerQueryCache::MAX_CACHE_SIZE / 2);
  for (size_t i = 0; i < kExtra; i++) {
    ASSERT_TRUE(cache.lookup(key_of(i), kNow + 1).is_error());
  }
  for (size_t i = kExtra; i < kTotal; i += 997) {
    ASSERT_TRUE(cache.lookup(key_of(i), kNow + 1).is_ok());
  }
}

TEST(LiteServerCache, byte_bound_holds_for_large_answers) {
  // Also true of the previous cache; kept so the byte bound cannot regress
  // while the entry bound is added.
  LiteServerQueryCache cache;
  constexpr size_t kAnswerSize = 1 << 20;
  size_t inserted = 0;
  while (inserted * LiteServerQueryCache::charge(kAnswerSize) < 2 * LiteServerQueryCache::MAX_CACHE_SIZE) {
    ASSERT_TRUE(cache.update(key_of(inserted), value_of(inserted, kAnswerSize), kNow));
    ++inserted;
    ASSERT_TRUE(cache.total_size() <= LiteServerQueryCache::MAX_CACHE_SIZE);
  }
  ASSERT_TRUE(cache.entries() < inserted);
  ASSERT_TRUE(cache.total_size() >= cache.entries() * LiteServerQueryCache::charge(kAnswerSize));
}

TEST(LiteServerCache, an_oversized_answer_is_not_cached_and_evicts_nothing) {
  LiteServerQueryCache cache;
  for (size_t i = 0; i < 100; i++) {
    ASSERT_TRUE(cache.update(key_of(i), value_of(i, 64), kNow));
  }
  size_t size_before = cache.total_size();
  std::string oversized(LiteServerQueryCache::MAX_ENTRY_VALUE_SIZE + 1, 'x');
  ASSERT_TRUE(!cache.update(key_of(1000), oversized, kNow));
  ASSERT_EQ(100u, cache.entries());
  ASSERT_EQ(size_before, cache.total_size());
  ASSERT_EQ(1u, cache.rejected_oversized());
  ASSERT_TRUE(cache.lookup(key_of(1000), kNow).is_error());
  // The largest admissible answer is cached.
  std::string largest(LiteServerQueryCache::MAX_ENTRY_VALUE_SIZE, 'y');
  ASSERT_TRUE(cache.update(key_of(1001), largest, kNow));
  ASSERT_TRUE(cache.lookup(key_of(1001), kNow).is_ok());
}

TEST(LiteServerCache, replacing_an_answer_reaccounts_it_in_both_directions) {
  LiteServerQueryCache cache;
  std::string large(10'000, 'L');
  std::string small(10, 'S');
  std::string with_nul("a\0b\0c", 5);
  // Capacities, not lengths, are charged; a short string may carry a small
  // in-object capacity, so the checks allow that slack and no more.
  auto within = [](size_t charged, size_t length) {
    return charged >= LiteServerQueryCache::charge(length) && charged <= LiteServerQueryCache::charge(length + 64);
  };
  ASSERT_TRUE(cache.update(key_of(1), large, kNow));
  ASSERT_TRUE(within(cache.total_size(), large.size()));
  ASSERT_TRUE(cache.update(key_of(1), small, kNow));
  ASSERT_EQ(1u, cache.entries());
  ASSERT_TRUE(within(cache.total_size(), small.size()));  // the large storage is gone
  ASSERT_TRUE(cache.update(key_of(1), large, kNow));
  ASSERT_TRUE(within(cache.total_size(), large.size()));
  ASSERT_EQ(large, cache.lookup(key_of(1), kNow).ok().as_slice().str());

  ASSERT_TRUE(cache.update(key_of(2), td::Slice(), kNow));
  ASSERT_EQ(0u, cache.lookup(key_of(2), kNow).ok().size());
  ASSERT_TRUE(cache.update(key_of(3), with_nul, kNow));
  ASSERT_EQ(with_nul, cache.lookup(key_of(3), kNow).ok().as_slice().str());
  ASSERT_EQ(3u, cache.entries());
  size_t least = LiteServerQueryCache::charge(large.size()) + LiteServerQueryCache::charge(0) +
                 LiteServerQueryCache::charge(with_nul.size());
  ASSERT_TRUE(cache.total_size() >= least);
  ASSERT_TRUE(cache.total_size() <= least + 3 * 64);
}

TEST(LiteServerCache, lookup_and_update_refresh_recency) {
  LiteServerQueryCache cache;
  for (size_t i = 0; i < LiteServerQueryCache::MAX_CACHE_ENTRIES; i++) {
    ASSERT_TRUE(cache.update(key_of(i), value_of(i, 8), kNow));
  }
  // The oldest two are refreshed: one by a hit, one by a rewrite.
  ASSERT_TRUE(cache.lookup(key_of(0), kNow + 1).is_ok());
  ASSERT_TRUE(cache.update(key_of(1), value_of(1, 8), kNow + 1));
  // Two insertions evict two entries: the next oldest, not the refreshed ones.
  ASSERT_TRUE(cache.update(key_of(1'000'000), value_of(0, 8), kNow + 2));
  ASSERT_TRUE(cache.update(key_of(1'000'001), value_of(0, 8), kNow + 2));
  ASSERT_TRUE(cache.lookup(key_of(0), kNow + 3).is_ok());
  ASSERT_TRUE(cache.lookup(key_of(1), kNow + 3).is_ok());
  ASSERT_TRUE(cache.lookup(key_of(2), kNow + 3).is_error());
  ASSERT_TRUE(cache.lookup(key_of(3), kNow + 3).is_error());
  ASSERT_TRUE(cache.lookup(key_of(4), kNow + 3).is_ok());
}

TEST(LiteServerCache, idle_entries_expire_from_the_tail_and_are_refused_by_lookup) {
  LiteServerQueryCache cache;
  for (size_t i = 0; i < 10; i++) {
    ASSERT_TRUE(cache.update(key_of(i), value_of(i, 8), kNow + static_cast<double>(i)));
  }
  // Exactly at the window's edge nothing is idle yet: the sweep drops nothing.
  double edge = kNow + LiteServerQueryCache::MAX_ENTRY_IDLE;
  ASSERT_EQ(0u, cache.expire_idle(edge));
  ASSERT_EQ(10u, cache.entries());
  // A hit at the edge keeps entry 0 alive past its original window.
  ASSERT_TRUE(cache.lookup(key_of(0), edge).is_ok());
  // Entries 1..4 are idle at this instant, 5..9 and the refreshed 0 are not;
  // the sweep stops at the first young entry.
  double sweep_at = kNow + 4 + LiteServerQueryCache::MAX_ENTRY_IDLE + 0.5;
  ASSERT_EQ(4u, cache.expire_idle(sweep_at));
  ASSERT_EQ(6u, cache.entries());
  ASSERT_TRUE(cache.lookup(key_of(1), sweep_at).is_error());
  ASSERT_TRUE(cache.lookup(key_of(5), sweep_at).is_ok());
  // An idle entry the sweep has not reached yet is refused by lookup and gone.
  double late = kNow + 9 + 2 * LiteServerQueryCache::MAX_ENTRY_IDLE;
  ASSERT_TRUE(cache.lookup(key_of(6), late).is_error());
  ASSERT_EQ(5u, cache.entries());
  // Everything idle: the sweep clears the store and the charge returns to zero.
  ASSERT_EQ(5u, cache.expire_idle(late));
  ASSERT_EQ(0u, cache.entries());
  ASSERT_EQ(0u, cache.total_size());
}

TEST(LiteServerCache, a_returned_answer_outlives_eviction_and_expiry) {
  LiteServerQueryCache cache;
  std::string answer = value_of(7, 300);
  ASSERT_TRUE(cache.update(key_of(7), answer, kNow));
  td::BufferSlice held = cache.lookup(key_of(7), kNow).move_as_ok();
  ASSERT_EQ(1u, cache.expire_idle(kNow + 2 * LiteServerQueryCache::MAX_ENTRY_IDLE));
  ASSERT_EQ(0u, cache.entries());
  ASSERT_EQ(answer, held.as_slice().str());
  for (size_t i = 0; i <= LiteServerQueryCache::MAX_CACHE_ENTRIES; i++) {
    ASSERT_TRUE(cache.update(key_of(i), value_of(i, 8), kNow));
  }
  ASSERT_EQ(answer, held.as_slice().str());
}
