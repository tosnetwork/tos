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

TEST(LRUCache, independent_lru_pair_desync_and_resync) {
  // Models the bug class fixed in rldp-http-proxy.cpp's
  // ask_peer_capabilities(): RldpHttpProxy::peer_capabilities_ and
  // RldpDispatcher::supports_rldp2_ are two independently-bounded
  // td::LRUCache instances driven by different access patterns --
  // peer_capabilities_ is touched roughly once per request (via
  // ask_peer_capabilities), while supports_rldp2_ is touched on every
  // dispatch() call, i.e. far more often per active peer, since a single
  // request can send many packets. A peer's entry can therefore be evicted
  // from one cache (falling back to RLDP1) while still resident in the
  // other with `received=true`, and if nothing re-asserts the known value
  // into the evicted cache, that peer silently and permanently stays on
  // the fallback. The two real proxy caches can't be unit-tested directly
  // (RldpHttpProxy/RldpDispatcher are actor-heavy local classes in
  // rldp-http-proxy.cpp with hardcoded capacity 10000), so this reproduces
  // the desync at the td::LRUCache level with a small capacity, then
  // verifies the fix's mechanism: re-asserting a known value into the
  // evicted cache whenever the (would-be) caller asks about that peer.
  struct Capability {
    bool received = false;
    bool supports_rldp2 = false;
  };
  const td::uint64 capacity = 3;
  td::LRUCache<int, Capability> capabilities(capacity);
  td::LRUCache<int, bool> dispatch(capacity);

  const int target_peer = 0;
  capabilities.put(target_peer, Capability{/* received = */ true, /* supports_rldp2 = */ true});
  dispatch.put(target_peer, true);
  CHECK(dispatch.get_if_exists(target_peer) != nullptr);

  // Simulate `dispatch` being touched for `capacity` other peers (as
  // dispatch() is called per packet) without those peers' capabilities
  // being re-queried (as ask_peer_capabilities() is called far less often)
  // -- this evicts target_peer from `dispatch` only.
  for (int other = 1; other <= static_cast<int>(capacity); other++) {
    dispatch.put(other, true);
  }
  CHECK(dispatch.get_if_exists(target_peer) == nullptr);

  // `capabilities` is unaffected: still remembers target_peer as received.
  auto *cap = capabilities.get_if_exists(target_peer);
  CHECK(cap != nullptr);
  CHECK(cap->received);
  CHECK(cap->supports_rldp2);

  // Without the fix, an ask_peer_capabilities() that only re-queries when
  // `!received` would never repopulate `dispatch`, so target_peer would be
  // silently and permanently downgraded to RLDP1. The fix re-asserts the
  // already-known value into `dispatch` on every ask, self-healing exactly
  // this kind of eviction.
  cap = &capabilities.get(target_peer);
  if (cap->received) {
    dispatch.put(target_peer, cap->supports_rldp2);
  }
  auto *resynced = dispatch.get_if_exists(target_peer);
  CHECK(resynced != nullptr);
  CHECK(*resynced == true);
}
