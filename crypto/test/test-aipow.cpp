/*
    Copyright (C) 2025-2026  TOS Network.

    Licensed under the GNU General Public License v3.0.
*/
#include "block/aipow.h"
#include "td/utils/tests.h"

namespace {

using td::make_refint;
using td::RefInt256;

block::AipowConfig make_cfg(td::uint32 k_num, td::uint32 k_den, long long schedule_cap,
                            long long cold_start_floor) {
  block::AipowConfig c;
  c.k_num = k_num;
  c.k_den = k_den;
  c.schedule_cap = make_refint(schedule_cap);
  c.cold_start_floor = make_refint(cold_start_floor);
  c.challenge_mult_num = 1;
  c.challenge_mult_den = 1;
  return c;
}

block::AipowLimits make_limits(long long total_cap) {
  block::AipowLimits l;
  l.total_cap = make_refint(total_cap);
  return l;
}

block::aipow::SettlementCursor make_cursor(td::uint32 next_epoch, long long minted_total,
                                           td::uint32 epoch_seconds, td::uint32 register_grace) {
  block::aipow::SettlementCursor c;
  c.next_epoch = next_epoch;
  c.minted_total = make_refint(minted_total);
  c.epoch_seconds = epoch_seconds;
  c.register_grace = register_grace;
  return c;
}

// pool value equals `expected`.
bool pool_is(const RefInt256& pool, long long expected) {
  return pool.not_null() && td::cmp(pool, expected) == 0;
}

}  // namespace

TEST(Aipow, epoch_pool_basic_and_floor_rounding) {
  // floor(organic * 1/2) = 500.
  CHECK(pool_is(block::aipow::compute_epoch_pool(make_cfg(1, 2, 1000000, 0), make_refint(1000)), 500));
  // floor(1000 * 1/3) = 333 (0.333 truncated), not 334.
  CHECK(pool_is(block::aipow::compute_epoch_pool(make_cfg(1, 3, 1000000, 0), make_refint(1000)), 333));
  // floor(7 * 3/2) = floor(10.5) = 10.
  CHECK(pool_is(block::aipow::compute_epoch_pool(make_cfg(3, 2, 1000000, 0), make_refint(7)), 10));
}

TEST(Aipow, epoch_pool_cap_and_floor_clamps) {
  // Raw 1e9 exceeds the schedule cap -> clamped to the cap.
  CHECK(pool_is(block::aipow::compute_epoch_pool(make_cfg(1, 1, 1000, 0), make_refint(1000000000LL)), 1000));
  // Raw 0 (floor of 0.001) is lifted to the cold-start floor.
  CHECK(pool_is(block::aipow::compute_epoch_pool(make_cfg(1, 1000000, 1000000, 50), make_refint(1000)), 50));
  // The cap wins over the floor: min(cap=700, max(floor=800, raw=500)) = 700.
  CHECK(pool_is(block::aipow::compute_epoch_pool(make_cfg(1, 2, 700, 800), make_refint(1000)), 700));
}

TEST(Aipow, epoch_pool_boundaries) {
  // Zero organic with a zero floor is a zero pool.
  CHECK(pool_is(block::aipow::compute_epoch_pool(make_cfg(1, 2, 1000, 0), make_refint(0)), 0));
  // Zero organic with a floor emits the floor.
  CHECK(pool_is(block::aipow::compute_epoch_pool(make_cfg(1, 2, 1000, 50), make_refint(0)), 50));
  // A zero denominator is a broken config -> null (no defined pool).
  CHECK(block::aipow::compute_epoch_pool(make_cfg(1, 0, 1000, 0), make_refint(1000)).is_null());
  // A very large organic clamps to the schedule cap without overflow.
  CHECK(pool_is(block::aipow::compute_epoch_pool(make_cfg(1000000, 1, 4500000000000000000LL, 0),
                                                 make_refint(9000000000000LL)),
                4500000000000000000LL));
}

TEST(Aipow, epoch_pool_overflow_yields_null_not_a_clamped_value) {
  // A 257-bit-overflowing quotient makes muldiv return an INVALID bigint (not
  // null). compute_epoch_pool must reject it as "no defined pool" (null), NOT
  // silently clamp it to the cold-start floor. organic 2^250 * 2^30 / 1 = 2^280
  // overflows the 257-bit range.
  RefInt256 huge_organic = make_refint(1) << 250;
  auto cfg = make_cfg(1u << 30, 1, 4500000000000000000LL, 100);
  auto pool = block::aipow::compute_epoch_pool(cfg, huge_organic);
  // The contract is fail-closed to null (not merely a non-null NaN), so a future
  // regression that returned an invalid-but-non-null ref would be caught here.
  CHECK(pool.is_null());
  // And the full derivation mints nothing on such an input.
  auto r = block::aipow::compute_epoch_mint(cfg, make_limits(4500000000000000000LL),
                                            make_cursor(5, 0, 65536, 3600), true, huge_organic, 0);
  CHECK(r.is_none());
}

TEST(Aipow, k_num_zero_yields_the_cold_start_floor) {
  // A zero numerator makes the per-organic term 0, so the pool is exactly the
  // cold-start floor (deterministic, not undefined).
  CHECK(pool_is(block::aipow::compute_epoch_pool(make_cfg(0, 7, 1000, 250), make_refint(1000000)), 250));
  CHECK(pool_is(block::aipow::compute_epoch_pool(make_cfg(0, 7, 1000, 0), make_refint(1000000)), 0));
}

TEST(Aipow, skip_deadline_does_not_overflow_at_the_max_epoch) {
  // epoch == UINT32_MAX must NOT wrap (epoch + 1 -> 0 in uint32 would collapse
  // the deadline to register_grace and diverge from the FunC 257-bit check).
  // With the correct 64-bit promotion, skippable_at = 2^32 * 65536 + 3600, far
  // beyond any uint32 gen_utime, so the epoch is never skippable.
  auto cfg = make_cfg(1, 2, 1000000, 0);
  auto limits = make_limits(4500000000000000000LL);
  auto cursor = make_cursor(0xFFFFFFFFu, 0, 65536, 3600);
  // A gen_utime that WOULD skip under the wrap bug (>= register_grace):
  auto r = block::aipow::compute_epoch_mint(cfg, limits, cursor, false, make_refint(0), 1000000000u);
  CHECK(r.is_none());  // not skippable: the deadline did not overflow to 3600
  // The maximum uint32 time is still below the (2^32 * 65536) deadline.
  auto r2 = block::aipow::compute_epoch_mint(cfg, limits, cursor, false, make_refint(0), 0xFFFFFFFFu);
  CHECK(r2.is_none());
}

TEST(Aipow, broken_config_fails_closed_to_no_mint) {
  // The derivation is fail-closed: a missing (null) config field yields no mint
  // rather than a null-deref or a partial clamp. These pin the is_usable guards
  // so a regression that drops one is caught even though valid consensus config
  // never hits them.
  auto organic = make_refint(1000);
  // Null schedule_cap.
  auto no_cap = make_cfg(1, 2, 1000, 0);
  no_cap.schedule_cap = {};
  CHECK(block::aipow::compute_epoch_pool(no_cap, organic).is_null());
  // Null cold_start_floor.
  auto no_floor = make_cfg(1, 2, 1000, 0);
  no_floor.cold_start_floor = {};
  CHECK(block::aipow::compute_epoch_pool(no_floor, organic).is_null());
  // Null organic.
  CHECK(block::aipow::compute_epoch_pool(make_cfg(1, 2, 1000, 0), RefInt256{}).is_null());

  // Null total_cap / minted_total in the full decision -> NoSettlement.
  auto cfg = make_cfg(1, 2, 1000000000LL, 0);
  auto cursor = make_cursor(5, 0, 65536, 3600);
  auto no_total = make_limits(1000);
  no_total.total_cap = {};
  CHECK(block::aipow::compute_epoch_mint(cfg, no_total, cursor, true, organic, 0).is_none());
  auto null_minted = make_cursor(5, 0, 65536, 3600);
  null_minted.minted_total = {};
  CHECK(block::aipow::compute_epoch_mint(cfg, make_limits(1000000000LL), null_minted, true, organic, 0).is_none());
}

TEST(Aipow, mint_happy_path_and_epoch) {
  auto cfg = make_cfg(1, 2, 1000000000LL, 0);  // pool = organic/2
  auto limits = make_limits(4500000000000000000LL);
  auto cursor = make_cursor(27260, 0, 65536, 3600);
  auto r = block::aipow::compute_epoch_mint(cfg, limits, cursor, true, make_refint(1000), 0);
  CHECK(r.is_mint());
  CHECK(r.epoch == 27260);
  CHECK(td::cmp(r.amount, 500) == 0);
}

TEST(Aipow, mint_clamps_to_the_remaining_supply_cap) {
  auto cfg = make_cfg(1, 1, 1000000000LL, 0);  // pool = organic
  auto limits = make_limits(600);
  // 300 already minted, so only 300 of the 500 pool remains.
  auto cursor = make_cursor(5, 300, 65536, 3600);
  auto r = block::aipow::compute_epoch_mint(cfg, limits, cursor, true, make_refint(500), 0);
  CHECK(r.is_mint());
  CHECK(td::cmp(r.amount, 300) == 0);
}

TEST(Aipow, mint_stops_when_the_cap_is_exhausted) {
  auto cfg = make_cfg(1, 1, 1000000000LL, 0);
  auto limits = make_limits(600);
  // Exactly at the cap: nothing remains.
  auto exhausted = block::aipow::compute_epoch_mint(cfg, limits, make_cursor(5, 600, 65536, 3600), true,
                                                    make_refint(500), 0);
  CHECK(exhausted.is_none());
  // Past the cap (should never happen, but the derivation is total): still none.
  auto over = block::aipow::compute_epoch_mint(cfg, limits, make_cursor(5, 700, 65536, 3600), true,
                                               make_refint(500), 0);
  CHECK(over.is_none());
}

TEST(Aipow, a_zero_pool_mints_nothing) {
  // Valid commitment but organic 0 and no floor -> zero pool -> nothing to mint.
  auto cfg = make_cfg(1, 2, 1000, 0);
  auto r = block::aipow::compute_epoch_mint(cfg, make_limits(1000000), make_cursor(5, 0, 65536, 3600), true,
                                            make_refint(0), 0);
  CHECK(r.is_none());
}

TEST(Aipow, unregistered_epoch_skips_only_past_the_grace_deadline) {
  auto cfg = make_cfg(1, 2, 1000000, 0);
  auto limits = make_limits(4500000000000000000LL);
  auto cursor = make_cursor(10, 0, 100, 50);
  // skippable_at = (10 + 1) * 100 + 50 = 1150.
  auto before = block::aipow::compute_epoch_mint(cfg, limits, cursor, false, make_refint(0), 1149);
  CHECK(before.is_none());
  auto at = block::aipow::compute_epoch_mint(cfg, limits, cursor, false, make_refint(0), 1150);
  CHECK(at.is_skip());
  CHECK(at.epoch == 10);
  auto after = block::aipow::compute_epoch_mint(cfg, limits, cursor, false, make_refint(0), 5000);
  CHECK(after.is_skip());
}

TEST(Aipow, derivation_is_a_pure_deterministic_function) {
  // A deterministic sweep (no RNG, no time): the same inputs must always give
  // the same tagged result and byte-identical amount, and every Mint must honor
  // the invariants (positive, <= schedule cap, <= remaining cap). The sweep
  // rotates through configs and input regimes so it exercises the clamp, skip,
  // zero-pool, k_num==0, max-epoch and 257-bit-overflow branches, not just the
  // easy interior.
  block::AipowConfig cfgs[] = {
      make_cfg(3, 7, 1000000000LL, 100),         // ordinary
      make_cfg(0, 7, 1000000000LL, 50),          // k_num == 0 -> floor
      make_cfg(1, 1, 1000, 0),                   // tiny cap (frequent clamp)
      make_cfg(1u << 30, 1, 4500000000000000000LL, 100),  // can overflow on a huge organic
  };
  auto limits = make_limits(5000000000LL);
  td::uint64 seed = 0x9E3779B97F4A7C15ull;
  for (int i = 0; i < 6000; i++) {
    // A simple LCG drives the sweep deterministically.
    seed = seed * 6364136223846793005ull + 1442695040888963407ull;
    const auto& cfg = cfgs[(seed >> 45) % 4u];
    // Organic is usually a moderate value, but ~1/8 of the time a near-2^257
    // value that overflows the widest config's quotient.
    RefInt256 organic;
    if (((seed >> 43) & 7u) == 0u) {
      organic = make_refint(1) << (200 + (int)((seed >> 5) % 56u));
    } else {
      organic = make_refint((long long)((seed >> 11) % 3000000000ull));
    }
    long long minted = (long long)((seed >> 29) % 6000000000ull);
    // Epochs span the whole uint32 range, including values near UINT32_MAX.
    td::uint32 epoch = (((seed >> 40) & 3u) == 0u) ? (td::uint32)(0xFFFFFFFFu - ((seed >> 7) % 5u))
                                                   : (td::uint32)((seed >> 3) % 100000u);
    bool has_commit = ((seed >> 41) & 1u) != 0;
    td::uint32 gen_utime = (td::uint32)((seed >> 17) % 4000000000u);
    auto cursor = make_cursor(epoch, minted, 65536, 3600);

    auto a = block::aipow::compute_epoch_mint(cfg, limits, cursor, has_commit, organic, gen_utime);
    auto b = block::aipow::compute_epoch_mint(cfg, limits, cursor, has_commit, organic, gen_utime);

    // Same input => same output (kind, epoch, amount).
    CHECK(a.kind == b.kind);
    CHECK(a.epoch == b.epoch);
    CHECK(a.amount.is_null() == b.amount.is_null());
    if (a.amount.not_null()) {
      CHECK(a.amount->is_valid());
      CHECK(td::cmp(a.amount, b.amount) == 0);
    }

    if (a.is_mint()) {
      CHECK(td::sgn(a.amount) > 0);
      CHECK(a.amount <= cfg.schedule_cap);
      auto remaining = limits.total_cap - cursor.minted_total;
      CHECK(a.amount <= remaining);
    }
    if (a.is_skip()) {
      // Skip only past the (non-overflowing) grace deadline.
      td::uint64 skippable_at = ((td::uint64)epoch + 1) * 65536ull + 3600ull;
      CHECK((td::uint64)gen_utime >= skippable_at);
    }
  }
}
