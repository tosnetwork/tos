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
// partially assembled broadcasts. These white-box tests pin the properties that
// keep that table from being a memory-growth or liveness hazard; standing up
// real FEC decoding plus signatures to drive every public path is
// disproportionate, so the tests reach the real gc(), the real admission gate,
// and (for FEC) the real process() through narrow friend accessors and a
// date-parameterized inject hook.
//
//  1. Admission bounds the inbound table: once full, a NEW broadcast is refused
//     rather than an in-flight one evicted.
//  2. Admission first reclaims entries past the assembly window, so a table full
//     only of already-expired slots does not block a new broadcast -- important
//     on fixed-member overlays whose periodic gc can lag the assembly window.
//  3. gc keeps fresh, still-assembling broadcasts and marks none delivered: it
//     evicts only by the assembly-window deadline, never by count (a count
//     eviction would drop a fresh broadcast and suppress its remaining parts).
//  4. The FEC production path (process()) actually consults the admission gate,
//     not just the predicate in isolation.

#include "adnl/adnl-node-id.hpp"
#include "common/errorcode.h"
#include "overlay/broadcast-fec.hpp"
#include "overlay/broadcast-twostep.hpp"
#include "overlay/overlay.hpp"
#include "td/utils/port/Clocks.h"
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
  static void inject(BroadcastsFec &b, Overlay::BroadcastHash hash, td::uint32 date) {
    b.inject_in_flight_for_test(hash, date);
  }
  static size_t count(const BroadcastsFec &b) {
    return b.in_flight_count_for_test();
  }
  static size_t capacity(const BroadcastsFec &b) {
    return b.capacity_for_test();
  }
  static td::Status admit(BroadcastsFec &b, OverlayImpl &overlay, bool is_ours) {
    return b.ensure_in_flight_capacity(&overlay, is_ours);
  }
  static td::Status try_process_fresh(BroadcastsFec &b, OverlayImpl &overlay, Overlay::BroadcastHash hash,
                                      bool is_ours) {
    return b.try_process_fresh_for_test(&overlay, hash, is_ours);
  }
};

class BroadcastsTwostepTestAccess {
 public:
  static void inject(BroadcastsTwostep &b, Overlay::BroadcastHash id, td::uint32 date) {
    b.inject_in_flight_for_test(id, date);
  }
  static size_t count(const BroadcastsTwostep &b) {
    return b.in_flight_count_for_test();
  }
  static size_t capacity(const BroadcastsTwostep &b) {
    return b.capacity_for_test();
  }
  static td::Status admit(BroadcastsTwostep &b, OverlayImpl &overlay) {
    return b.ensure_in_flight_capacity(&overlay);
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

td::uint32 now_sec() {
  return static_cast<td::uint32>(td::Clocks::system());
}

// A date comfortably past both the FEC (60 s) and two-step (25 s) assembly
// windows, so gc treats the entry as expired.
td::uint32 expired_sec() {
  return now_sec() - 120;
}

// Builds a bare OverlayImpl sufficient for white-box table access. No scheduler
// or network is needed: the admission gate, gc(), process()'s early admission
// branch, and is_delivered() touch only in-process state. Mirrors
// test-overlay-peer-cleanup.
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

    // One short of capacity, all fresh: a new inbound broadcast is still
    // admitted.
    for (size_t i = 0; i + 1 < cap; i++) {
      Access::inject(fec, hash_from_index(i), now_sec());
    }
    ASSERT_TRUE(Access::admit(fec, overlay, /*is_ours=*/false).is_ok());

    // At capacity with every entry fresh: reclaiming finds nothing, so a new
    // inbound broadcast is refused (not evicted in, not marked delivered).
    Access::inject(fec, hash_from_index(cap - 1), now_sec());
    ASSERT_EQ(Access::count(fec), cap);
    ASSERT_TRUE(Access::admit(fec, overlay, /*is_ours=*/false).is_error());

    // Our own broadcasts are locally paced and exempt from the ceiling.
    ASSERT_TRUE(Access::admit(fec, overlay, /*is_ours=*/true).is_ok());
  });
}

TEST(OverlayBroadcastCapacity, FecReclaimsExpiredBeforeRejecting) {
  using Access = tos::overlay::BroadcastsFecTestAccess;
  with_overlay([](tos::overlay::OverlayImpl &overlay) {
    auto &fec = tos::overlay::OverlayImplBroadcastCapacityTest::fec(overlay);
    const size_t cap = Access::capacity(fec);

    // A full table whose entries are all past the assembly window.
    for (size_t i = 0; i < cap; i++) {
      Access::inject(fec, hash_from_index(i), expired_sec());
    }
    ASSERT_EQ(Access::count(fec), cap);

    // Admission reclaims the expired slots first, so a new broadcast is not
    // blocked behind them. Without that reclaim this would report "full".
    ASSERT_TRUE(Access::admit(fec, overlay, /*is_ours=*/false).is_ok());
    ASSERT_EQ(Access::count(fec), 0u);
  });
}

TEST(OverlayBroadcastCapacity, FecReclaimsExpiredBehindFreshOldestInsertion) {
  using Access = tos::overlay::BroadcastsFecTestAccess;
  with_overlay([](tos::overlay::OverlayImpl &overlay) {
    auto &fec = tos::overlay::OverlayImplBroadcastCapacityTest::fec(overlay);
    const size_t cap = Access::capacity(fec);

    // A fresh entry inserted FIRST, with expired entries inserted after it. The
    // accepted date can lag arrival, so an entry inserted later can already be
    // expired. An insertion-ordered scan stops at this first-inserted fresh
    // entry and reclaims nothing; ordering reclamation by date drops the expired
    // entries regardless of insertion order.
    Access::inject(fec, hash_from_index(0), now_sec());
    for (size_t i = 1; i < cap; i++) {
      Access::inject(fec, hash_from_index(i), expired_sec());
    }
    ASSERT_EQ(Access::count(fec), cap);

    ASSERT_TRUE(Access::admit(fec, overlay, /*is_ours=*/false).is_ok());
    ASSERT_EQ(Access::count(fec), 1u);  // only the fresh entry survives
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
      Access::inject(fec, h, now_sec());
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

TEST(OverlayBroadcastCapacity, FecProcessConsultsAdmissionGate) {
  using Access = tos::overlay::BroadcastsFecTestAccess;
  with_overlay([](tos::overlay::OverlayImpl &overlay) {
    auto &fec = tos::overlay::OverlayImplBroadcastCapacityTest::fec(overlay);
    const size_t cap = Access::capacity(fec);

    for (size_t i = 0; i < cap; i++) {  // fill to capacity with fresh entries
      Access::inject(fec, hash_from_index(i), now_sec());
    }
    ASSERT_EQ(Access::count(fec), cap);

    // Drive the real process() with a minimal part whose hash is new. It must
    // be refused with notready at the admission gate, before any new entry is
    // created -- proving the production insertion path consults the gate, not
    // just that the predicate works in isolation. Removing the gate's call from
    // process() makes this fail (a different error, or an inserted entry).
    auto status = Access::try_process_fresh(fec, overlay, hash_from_index(cap), /*is_ours=*/false);
    ASSERT_TRUE(status.is_error());
    ASSERT_EQ(status.error().code(), static_cast<int>(tos::ErrorCode::notready));
    ASSERT_EQ(Access::count(fec), cap);
  });
}

TEST(OverlayBroadcastCapacity, TwostepRefusesNewBroadcastWhenFull) {
  using Access = tos::overlay::BroadcastsTwostepTestAccess;
  with_overlay([](tos::overlay::OverlayImpl &overlay) {
    auto &twostep = tos::overlay::OverlayImplBroadcastCapacityTest::twostep(overlay);
    const size_t cap = Access::capacity(twostep);

    for (size_t i = 0; i + 1 < cap; i++) {
      Access::inject(twostep, hash_from_index(i), now_sec());
    }
    ASSERT_TRUE(Access::admit(twostep, overlay).is_ok());

    Access::inject(twostep, hash_from_index(cap - 1), now_sec());
    ASSERT_EQ(Access::count(twostep), cap);
    ASSERT_TRUE(Access::admit(twostep, overlay).is_error());
  });
}

TEST(OverlayBroadcastCapacity, TwostepReclaimsExpiredBeforeRejecting) {
  using Access = tos::overlay::BroadcastsTwostepTestAccess;
  with_overlay([](tos::overlay::OverlayImpl &overlay) {
    auto &twostep = tos::overlay::OverlayImplBroadcastCapacityTest::twostep(overlay);
    const size_t cap = Access::capacity(twostep);

    for (size_t i = 0; i < cap; i++) {
      Access::inject(twostep, hash_from_index(i), expired_sec());
    }
    ASSERT_EQ(Access::count(twostep), cap);

    ASSERT_TRUE(Access::admit(twostep, overlay).is_ok());
    ASSERT_EQ(Access::count(twostep), 0u);
  });
}

TEST(OverlayBroadcastCapacity, TwostepReclaimsExpiredBehindFreshOldestInsertion) {
  using Access = tos::overlay::BroadcastsTwostepTestAccess;
  with_overlay([](tos::overlay::OverlayImpl &overlay) {
    auto &twostep = tos::overlay::OverlayImplBroadcastCapacityTest::twostep(overlay);
    const size_t cap = Access::capacity(twostep);

    // A fresh entry inserted first, expired entries after it: reclamation must
    // follow date order, not insertion order, or the expired slots stay full.
    Access::inject(twostep, hash_from_index(0), now_sec());
    for (size_t i = 1; i < cap; i++) {
      Access::inject(twostep, hash_from_index(i), expired_sec());
    }
    ASSERT_EQ(Access::count(twostep), cap);

    ASSERT_TRUE(Access::admit(twostep, overlay).is_ok());
    ASSERT_EQ(Access::count(twostep), 1u);
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
      Access::inject(twostep, id, now_sec());
    }
    ASSERT_EQ(Access::count(twostep), cap + 1);

    twostep.gc(&overlay);

    ASSERT_EQ(Access::count(twostep), cap + 1);
    for (const auto &id : ids) {
      ASSERT_TRUE(!overlay.is_delivered(id));
    }
  });
}
