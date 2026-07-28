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

    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "td/utils/LRUCache.h"
#include "td/utils/tests.h"

TEST(LRUCache, new_entry_value_initialized) {
  // Regression test: LRUCache::get(key) used to construct new Entry objects
  // via the key/weight-only constructor without initializing `value`, so a
  // freshly-inserted entry held indeterminate memory instead of a
  // value-initialized (i.e. zeroed, for scalar types) value.
  td::LRUCache<int, int> cache(100);
  for (int key = 0; key < 100; key++) {
    int &value = cache.get(key);
    ASSERT_EQ(0, value);
    value = key + 1;
  }
  for (int key = 0; key < 100; key++) {
    int &value = cache.get(key);
    ASSERT_EQ(key + 1, value);
  }
}

TEST(LRUCache, put_get_erase) {
  td::LRUCache<int, std::string> cache(10);
  CHECK(cache.get_if_exists(1) == nullptr);
  cache.put(1, "one");
  cache.put(2, "two");
  ASSERT_EQ(std::string("one"), *cache.get_if_exists(1));
  ASSERT_EQ(std::string("two"), *cache.get_if_exists(2));
  cache.erase(1);
  CHECK(cache.get_if_exists(1) == nullptr);
  ASSERT_EQ(std::string("two"), *cache.get_if_exists(2));
}

TEST(LRUCache, eviction_bounds_total_weight) {
  td::LRUCache<int, int> cache(10);
  for (int key = 0; key < 100; key++) {
    cache.put(key, key);
  }
  CHECK(cache.size() <= 10);
  // The most recently inserted key must still be present.
  CHECK(cache.get_if_exists(99) != nullptr);
}
