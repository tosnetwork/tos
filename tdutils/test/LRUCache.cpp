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
  // silently and permanently downgraded to RLDP1. The fix unconditionally
  // re-asserts `received && supports_rldp2` into `dispatch` on every ask,
  // self-healing exactly this kind of eviction.
  cap = &capabilities.get(target_peer);
  dispatch.put(target_peer, cap->received && cap->supports_rldp2);
  auto *resynced = dispatch.get_if_exists(target_peer);
  CHECK(resynced != nullptr);
  CHECK(*resynced == true);
}

TEST(LRUCache, independent_lru_pair_reverse_desync_and_resync) {
  // Mirror image of independent_lru_pair_desync_and_resync above: this time
  // `capabilities` (peer_capabilities_) evicts target_peer first, while
  // `dispatch` (supports_rldp2_) still holds a stale `true` from before the
  // eviction. An earlier version of the ask_peer_capabilities() fix only
  // handled the `received=true` case (re-asserting a known value), so on
  // the *next* ask -- where `capabilities.get(target_peer)` returns a fresh
  // received=false entry -- it took no action at all, leaving the stale
  // `true` in `dispatch` in place indefinitely (worse: if the resulting
  // fresh capability probe then fails or the peer is offline, `received`
  // never becomes true again, so the stale `true` in `dispatch` would
  // persist forever). The fix must positively write `false` into `dispatch`
  // whenever `capabilities` doesn't (yet, or anymore) have a received
  // value, not merely skip touching `dispatch`.
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

  // Simulate `capabilities` being evicted by `capacity` other peers' probe
  // responses landing (touches `capabilities` only) without target_peer
  // being dispatched to in between (touches `dispatch` only) -- this evicts
  // target_peer from `capabilities` but leaves `dispatch` untouched, still
  // holding the stale `true`.
  for (int other = 1; other <= static_cast<int>(capacity); other++) {
    capabilities.put(other, Capability{/* received = */ true, /* supports_rldp2 = */ false});
  }
  CHECK(capabilities.get_if_exists(target_peer) == nullptr);
  auto *stale = dispatch.get_if_exists(target_peer, /* update = */ false);
  CHECK(stale != nullptr);
  CHECK(*stale == true);

  // The next ask_peer_capabilities(target_peer) call: `capabilities.get()`
  // creates a fresh, default (received=false) entry, since it was evicted.
  auto &cap = capabilities.get(target_peer);
  CHECK(!cap.received);

  // The fix must unconditionally resync, writing `false` here because
  // `received` is false -- not skip the write and leave the stale `true`.
  dispatch.put(target_peer, cap.received && cap.supports_rldp2);
  auto *resynced = dispatch.get_if_exists(target_peer);
  CHECK(resynced != nullptr);
  CHECK(*resynced == false);
}
