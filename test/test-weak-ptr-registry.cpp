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

    Copyright 2025-2026 TOS Blockchain Teams
*/

#include <memory>
#include <vector>

#include "td/utils/tests.h"
#include "validator/weak-ptr-registry.hpp"

namespace {

struct Value {
  explicit Value(int value) : value(value) {
  }
  int value;
};

struct AllocationStats {
  std::size_t allocations{0};
  std::size_t deallocations{0};
};

template <class T>
struct CountingAllocator {
  using value_type = T;

  explicit CountingAllocator(std::shared_ptr<AllocationStats> stats) : stats(std::move(stats)) {
  }

  template <class U>
  CountingAllocator(const CountingAllocator<U> &other) : stats(other.stats) {
  }

  T *allocate(std::size_t count) {
    ++stats->allocations;
    return std::allocator<T>{}.allocate(count);
  }

  void deallocate(T *ptr, std::size_t count) {
    ++stats->deallocations;
    std::allocator<T>{}.deallocate(ptr, count);
  }

  template <class U>
  bool operator==(const CountingAllocator<U> &other) const {
    return stats == other.stats;
  }

  template <class>
  friend struct CountingAllocator;

  std::shared_ptr<AllocationStats> stats;
};

using Registry = tos::validator::WeakPtrRegistry<int, Value>;

TEST(WeakPtrRegistry, PreservesLiveEntriesAndRemovesExpiredEntries) {
  Registry registry;
  auto live = std::make_shared<Value>(1);
  auto expired = std::make_shared<Value>(2);

  ASSERT_TRUE(registry.insert_or_get(1, live).inserted);
  ASSERT_TRUE(registry.insert_or_get(2, expired).inserted);
  ASSERT_TRUE(!registry.insert_or_get(1, live).inserted);
  ASSERT_EQ(registry.get(1), live);

  expired.reset();
  registry.sweep_expired(2);

  ASSERT_EQ(registry.size(), 1u);
  ASSERT_EQ(registry.get(1), live);
  auto stats = registry.stats();
  ASSERT_EQ(stats.sweep_scanned, 2u);
  ASSERT_EQ(stats.sweep_removed, 1u);
}

TEST(WeakPtrRegistry, KeyCursorSurvivesLookupErasingLastInspectedEntry) {
  Registry registry;
  std::vector<std::shared_ptr<Value>> values;
  for (int key = 1; key <= 4; ++key) {
    values.push_back(std::make_shared<Value>(key));
    ASSERT_TRUE(registry.insert_or_get(key, values.back()).inserted);
  }

  registry.sweep_expired(2);  // The key cursor now points at key 2.
  values[1].reset();
  ASSERT_TRUE(!registry.get(2));  // Erases the key stored by the cursor.

  for (auto &value : values) {
    value.reset();
  }
  for (int i = 0; i < 4; ++i) {
    registry.sweep_expired(2);
  }

  ASSERT_EQ(registry.size(), 0u);
  ASSERT_EQ(registry.stats().lookup_removed, 1u);
}

TEST(WeakPtrRegistry, WrapFindsKeysInsertedOnBothSidesOfCursor) {
  Registry registry;
  std::vector<std::shared_ptr<Value>> values;
  for (int key : {10, 20, 30}) {
    values.push_back(std::make_shared<Value>(key));
    ASSERT_TRUE(registry.insert_or_get(key, values.back()).inserted);
  }

  registry.sweep_expired(1);  // The key cursor now points at key 10.
  auto before = std::make_shared<Value>(5);
  auto after = std::make_shared<Value>(40);
  ASSERT_TRUE(registry.insert_or_get(5, before).inserted);
  ASSERT_TRUE(registry.insert_or_get(40, after).inserted);

  for (auto &value : values) {
    value.reset();
  }
  before.reset();
  after.reset();
  for (int i = 0; i < 8; ++i) {
    registry.sweep_expired(1);
  }

  ASSERT_EQ(registry.size(), 0u);
  ASSERT_TRUE(registry.stats().sweep_passes >= 1u);
}

TEST(WeakPtrRegistry, InsertionProportionalSweepBoundsExpiredBacklog) {
  Registry registry;
  for (int key = 0; key < 10000; ++key) {
    auto value = std::make_shared<Value>(key);
    ASSERT_TRUE(registry.insert_or_get(key, value).inserted);
    value.reset();
    registry.sweep_expired(4);
  }

  ASSERT_TRUE(registry.size() <= 1u);
  ASSERT_TRUE(registry.stats().sweep_removed >= 9999u);
}

TEST(WeakPtrRegistry, SweepReleasesSharedAllocationRetainedByWeakReference) {
  Registry registry;
  auto allocation_stats = std::make_shared<AllocationStats>();
  auto value = std::allocate_shared<Value>(CountingAllocator<Value>{allocation_stats}, 1);
  ASSERT_EQ(allocation_stats->allocations, 1u);
  ASSERT_TRUE(registry.insert_or_get(1, value).inserted);

  value.reset();
  ASSERT_EQ(allocation_stats->deallocations, 0u);

  registry.sweep_expired(1);
  ASSERT_EQ(registry.size(), 0u);
  ASSERT_EQ(allocation_stats->deallocations, 1u);
}

TEST(WeakPtrRegistry, InsertOrGetKeepsLiveCanonicalValue) {
  Registry registry;
  auto canonical = std::make_shared<Value>(1);
  auto duplicate = std::make_shared<Value>(2);

  auto first = registry.insert_or_get(1, canonical);
  auto second = registry.insert_or_get(1, duplicate);

  ASSERT_TRUE(first.inserted);
  ASSERT_EQ(first.value, canonical);
  ASSERT_TRUE(!second.inserted);
  ASSERT_EQ(second.value, canonical);
  ASSERT_EQ(registry.size(), 1u);
}

TEST(WeakPtrRegistry, InsertOrGetReplacesExpiredValue) {
  Registry registry;
  auto expired = std::make_shared<Value>(1);
  ASSERT_TRUE(registry.insert_or_get(1, expired).inserted);
  expired.reset();

  auto replacement = std::make_shared<Value>(2);
  auto result = registry.insert_or_get(1, replacement);

  ASSERT_TRUE(result.inserted);
  ASSERT_EQ(result.value, replacement);
  ASSERT_EQ(registry.get(1), replacement);
  ASSERT_EQ(registry.size(), 1u);
  ASSERT_EQ(registry.stats().lookup_removed, 1u);
}

}  // namespace
