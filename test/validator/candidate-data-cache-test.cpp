/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Drives the cache that holds block data received before validation. It is
// bounded by entries and by the bytes it keeps allocated, and what it is
// charged must be what it actually keeps alive: the allocator's own count of
// live buffer memory is the instrument, so a cache that kept a large backing
// buffer alive through a small view would show up here.
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "td/utils/buffer.h"
#include "validator/candidate-data-cache.h"

namespace {

using tos::validator::CandidateDataCache;
using tos::validator::CandidateDataCacheLimits;
using Cache = CandidateDataCache<int>;

[[noreturn]] void fail(const std::string &message) {
  std::cerr << "CANDIDATE_DATA_CACHE_FAILURE: " << message << '\n';
  std::exit(1);
}

void require(bool condition, const std::string &message) {
  if (!condition) {
    fail(message);
  }
}

// An exclusive allocation of `size` bytes filled with `fill`.
td::BufferSlice buffer(std::size_t size, char fill) {
  td::BufferSlice result(size < 512 ? 512 : size);
  result.truncate(size);
  std::memset(result.as_slice().begin(), fill, size);
  return result;
}

// A `size`-byte view into the middle of `backing`, sharing its allocation.
td::BufferSlice view(const td::BufferSlice &backing, std::size_t offset, std::size_t size) {
  td::BufferSlice result = backing.clone();
  result.confirm_read(offset);
  result.truncate(size);
  return result;
}

std::size_t live() {
  return td::BufferAllocator::get_buffer_mem();
}

}  // namespace

int main() {
  // What the cache is charged is what it keeps allocated. A small view into a
  // large received buffer must not keep that buffer alive once the caller
  // drops it.
  {
    Cache cache({.max_entries = 8, .max_bytes = std::size_t{64} << 20, .max_entry_size = std::size_t{4} << 20});
    const std::size_t before = live();
    {
      td::BufferSlice received = buffer(std::size_t{1} << 20, 'r');
      auto candidate = view(received, 4096, 3000);
      require(cache.put(1, candidate) == Cache::PutResult::Stored, "a view is stored");
      require(cache.get(1, false)->as_slice() == candidate.as_slice(), "the stored payload is the view's bytes");
    }
    const std::size_t retained = live() - before;
    require(retained > 0, "the cache keeps its entry allocated");
    require(retained <= cache.bytes(), "the cache keeps no more allocated than it is charged (retained " +
                                           std::to_string(retained) + ", charged " + std::to_string(cache.bytes()) +
                                           ")");
    require(cache.bytes() - retained < 64, "the charge is the entry's own allocation, not an estimate");
    cache.erase(1);
    require(cache.bytes() == 0 && cache.size() == 0, "erasing releases the charge");
    require(live() == before, "erasing releases the allocation");
  }

  // Byte budget: entries are evicted, oldest first, until the bytes the cache
  // keeps allocated fit, even with entry slots to spare.
  {
    const std::size_t entry = 3000;
    const std::size_t budget = Cache::charge_for(entry) * 3;
    Cache cache({.max_entries = 100, .max_bytes = budget, .max_entry_size = 4000});
    const std::size_t before = live();
    for (int key = 0; key < 5; ++key) {
      require(cache.put(key, buffer(entry, static_cast<char>('a' + key))) == Cache::PutResult::Stored,
              "an entry within the per-entry limit is stored");
      require(cache.bytes() <= budget, "the byte budget holds after every insertion");
    }
    require(cache.size() == 3, "the byte budget, not the entry limit, bounded the cache");
    require(!cache.contains(0) && !cache.contains(1), "the oldest entries were evicted");
    require(cache.contains(2) && cache.contains(3) && cache.contains(4), "the newest entries remain");
    require(live() - before <= budget, "evicted entries released their allocations");
  }

  // Entry limit, and recency: a touched entry outlives an untouched older one.
  {
    Cache cache({.max_entries = 2, .max_bytes = std::size_t{64} << 20, .max_entry_size = 4000});
    cache.put(1, buffer(100, 'a'));
    cache.put(2, buffer(100, 'b'));
    require(cache.get(1) != nullptr, "a present entry is found");
    cache.put(3, buffer(100, 'c'));
    require(cache.size() == 2, "the entry limit holds");
    require(cache.contains(1) && !cache.contains(2) && cache.contains(3), "the least recently used entry went");
  }

  // A payload over the per-entry limit is refused and charges nothing; a key
  // already present keeps its first payload.
  {
    Cache cache({.max_entries = 8, .max_bytes = std::size_t{64} << 20, .max_entry_size = 4000});
    require(cache.put(1, buffer(4001, 'x')) == Cache::PutResult::TooLarge, "an oversized payload is refused");
    require(cache.size() == 0 && cache.bytes() == 0, "a refused payload charges nothing");
    require(cache.put(1, buffer(4000, 'y')) == Cache::PutResult::Stored, "a payload at the limit is stored");
    const std::size_t charged = cache.bytes();
    require(cache.put(1, buffer(10, 'z')) == Cache::PutResult::AlreadyPresent, "a second payload is not stored");
    require(cache.bytes() == charged && cache.get(1, false)->size() == 4000, "the first payload is kept");
  }

  // Clearing and destruction release everything.
  {
    const std::size_t before = live();
    {
      Cache cache({.max_entries = 8, .max_bytes = std::size_t{64} << 20, .max_entry_size = 1 << 20});
      cache.put(1, buffer(100000, 'a'));
      cache.put(2, buffer(200000, 'b'));
      cache.clear();
      require(cache.bytes() == 0 && live() == before, "clearing releases the allocations");
      cache.put(3, buffer(300000, 'c'));
    }
    require(live() == before, "destruction releases the allocations");
  }

  std::cout << "CANDIDATE_DATA_CACHE_OK\n";
  return 0;
}
