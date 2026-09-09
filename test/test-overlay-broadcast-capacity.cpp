/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The FEC and two-step broadcast receivers each hold an in-flight table of
// partially assembled broadcasts. Two properties keep that table from being a
// memory-growth or liveness hazard, and both are white-box tested here because
// standing up real FEC decoding plus signatures to drive the public path is
// disproportionate:
//
//  1. Admission: once the table is full, a NEW broadcast is refused rather than
//     an in-flight one evicted, so the table stays bounded between gc passes.
//  2. gc keeps fresh, still-assembling broadcasts. gc evicts only by the
//     assembly-window deadline; it must NOT evict by count, because a count
//     eviction would drop a fresh broadcast and (like the deadline path) mark
//     it delivered, permanently suppressing its remaining parts.
//
// The tests reach the real admission predicate and the real gc() through narrow
// friend accessors, and inject fresh decoder-less entries through a test-only
// hook, so a regression in either property fails the build's tests.

#include "adnl/adnl-node-id.hpp"
#include "overlay/broadcast-fec.hpp"
#include "overlay/broadcast-twostep.hpp"
#include "overlay/overlay.hpp"
#include "td/utils/tests.h"

#include <cstring>
#include <vector>

namespace tos::overlay {

class OverlayImplBroadcastCapacityTest {
 public:
  static BroadcastsFec &fec(OverlayImpl &overlay) {
    return overlay.broadcasts_fec_;
  }
  static BroadcastsTwostep &twostep(OverlayImpl &overlay) {
    return overlay.broadcasts_twostep_;
  }
};

class BroadcastsFecTestAccess {
 public:
  static void inject_fresh(BroadcastsFec &b, Overlay::BroadcastHash hash) {
    b.inject_fresh_in_flight_for_test(hash);
  }
  static size_t count(const BroadcastsFec &b) {
    return b.in_flight_count_for_test();
  }
  static size_t capacity(const BroadcastsFec &b) {
    return b.capacity_for_test();
  }
  static td::Status admit(const BroadcastsFec &b, bool is_ours) {
    return b.check_in_flight_capacity(is_ours);
  }
};

class BroadcastsTwostepTestAccess {
 public:
  static void inject_fresh(BroadcastsTwostep &b, Overlay::BroadcastHash broadcast_id) {
    b.inject_fresh_in_flight_for_test(broadcast_id);
  }
  static size_t count(const BroadcastsTwostep &b) {
    return b.in_flight_count_for_test();
  }
  static size_t capacity(const BroadcastsTwostep &b) {
    return b.capacity_for_test();
  }
  static td::Status admit(const BroadcastsTwostep &b) {
    return b.check_in_flight_capacity();
  }
};

}  // namespace tos::overlay

namespace {

// A distinct broadcast hash per index (first 8 bytes carry the index).
td::Bits256 hash_from_index(size_t i) {
  td::Bits256 h = td::Bits256::zero();
  std::memcpy(h.as_slice().data(), &i, sizeof(i));
  return h;
}

// Builds a bare OverlayImpl sufficient for white-box table access. No scheduler
// or network is needed: the admission predicate, gc(), and is_delivered() touch
// only in-process state. Mirrors test-overlay-peer-cleanup.
template <class F>
void with_overlay(F &&f) {
  td::Bits256 local_bits;
  local_bits.as_slice().fill('l');
  auto local_id = tos::adnl::AdnlNodeIdShort{local_bits};

  tos::overlay::OverlayOptions options;
  options.max_neighbours_ = 0;
  options.enable_plumtree_broadcast_ = false;
  tos::overlay::OverlayImpl overlay(
      {}, {}, {}, {}, local_id, tos::overlay::OverlayIdFull{td::BufferSlice{"bcast-capacity-test"}},
      tos::overlay::OverlayType::Public, {}, {}, {}, std::make_unique<tos::overlay::Overlays::Callback>(),
      tos::overlay::OverlayPrivacyRules{}, "bcast-capacity-test", std::move(options));
  f(overlay);
}

}  // namespace

TEST(OverlayBroadcastCapacity, FecRefusesNewBroadcastWhenFull) {
  using Access = tos::overlay::BroadcastsFecTestAccess;
  with_overlay([](tos::overlay::OverlayImpl &overlay) {
    auto &fec = tos::overlay::OverlayImplBroadcastCapacityTest::fec(overlay);
    const size_t cap = Access::capacity(fec);

    // One short of capacity: a new inbound broadcast is still admitted.
    for (size_t i = 0; i + 1 < cap; i++) {
      Access::inject_fresh(fec, hash_from_index(i));
    }
    ASSERT_TRUE(Access::admit(fec, /*is_ours=*/false).is_ok());

    // At capacity: a new inbound broadcast is refused (it is not evicted in,
    // and not recorded as delivered -- it may arrive again later).
    Access::inject_fresh(fec, hash_from_index(cap - 1));
    ASSERT_EQ(Access::count(fec), cap);
    ASSERT_TRUE(Access::admit(fec, /*is_ours=*/false).is_error());

    // Our own broadcasts are locally paced and exempt from the ceiling.
    ASSERT_TRUE(Access::admit(fec, /*is_ours=*/true).is_ok());
  });
}

TEST(OverlayBroadcastCapacity, FecGcKeepsFreshInFlightBroadcasts) {
  using Access = tos::overlay::BroadcastsFecTestAccess;
  with_overlay([](tos::overlay::OverlayImpl &overlay) {
    auto &fec = tos::overlay::OverlayImplBroadcastCapacityTest::fec(overlay);
    const size_t cap = Access::capacity(fec);

    std::vector<td::Bits256> hashes;
    hashes.reserve(cap + 1);
    for (size_t i = 0; i <= cap; i++) {  // one past the ceiling, all fresh
      auto h = hash_from_index(i);
      hashes.push_back(h);
      Access::inject_fresh(fec, h);
    }
    ASSERT_EQ(Access::count(fec), cap + 1);

    fec.gc(&overlay);

    // Every fresh entry survives (gc evicts only past the assembly window), and
    // none was registered delivered. A count eviction here -- the removed
    // regression -- would drop at least one fresh broadcast and mark it
    // delivered, failing both checks.
    ASSERT_EQ(Access::count(fec), cap + 1);
    for (const auto &h : hashes) {
      ASSERT_TRUE(!overlay.is_delivered(h));
    }
  });
}

TEST(OverlayBroadcastCapacity, TwostepRefusesNewBroadcastWhenFull) {
  using Access = tos::overlay::BroadcastsTwostepTestAccess;
  with_overlay([](tos::overlay::OverlayImpl &overlay) {
    auto &twostep = tos::overlay::OverlayImplBroadcastCapacityTest::twostep(overlay);
    const size_t cap = Access::capacity(twostep);

    for (size_t i = 0; i + 1 < cap; i++) {
      Access::inject_fresh(twostep, hash_from_index(i));
    }
    ASSERT_TRUE(Access::admit(twostep).is_ok());

    Access::inject_fresh(twostep, hash_from_index(cap - 1));
    ASSERT_EQ(Access::count(twostep), cap);
    ASSERT_TRUE(Access::admit(twostep).is_error());
  });
}

TEST(OverlayBroadcastCapacity, TwostepGcKeepsFreshInFlightBroadcasts) {
  using Access = tos::overlay::BroadcastsTwostepTestAccess;
  with_overlay([](tos::overlay::OverlayImpl &overlay) {
    auto &twostep = tos::overlay::OverlayImplBroadcastCapacityTest::twostep(overlay);
    const size_t cap = Access::capacity(twostep);

    std::vector<td::Bits256> ids;
    ids.reserve(cap + 1);
    for (size_t i = 0; i <= cap; i++) {
      auto id = hash_from_index(i);
      ids.push_back(id);
      Access::inject_fresh(twostep, id);
    }
    ASSERT_EQ(Access::count(twostep), cap + 1);

    twostep.gc(&overlay);

    ASSERT_EQ(Access::count(twostep), cap + 1);
    for (const auto &id : ids) {
      ASSERT_TRUE(!overlay.is_delivered(id));
    }
  });
}
