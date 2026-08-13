/*
    Copyright (C) 2025-2026  TOS Network.

    Licensed under the GNU General Public License v3.0.
*/
#include <vector>
#include "block/aipow.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"
#include "td/utils/tests.h"

namespace {

using td::make_refint;
using td::RefInt256;

// A distinct, reproducible 256-bit value (seed in the low 64 bits, big-endian).
td::Bits256 mk_bits(unsigned long long seed) {
  td::Bits256 b;
  b.set_zero();
  unsigned char* d = b.data();
  for (int i = 0; i < 8; i++) {
    d[31 - i] = (unsigned char)(seed >> (8 * i));
  }
  return b;
}

td::Ref<vm::Cell> dummy_ref() {
  vm::CellBuilder cb;
  cb.store_long_bool(0xD1, 8);
  return cb.finalize();
}

// Build a commitment "economic tuple" ref: score_root methodology total_score organic.
td::Ref<vm::Cell> build_econ_tuple(td::Bits256 score_root, long long total_score, long long organic) {
  vm::CellBuilder cb;
  cb.store_bits_bool(score_root);
  cb.store_bits_bool(mk_bits(0x44));  // methodology_hash
  cb.store_int256_bool(make_refint(total_score), 128, false);
  cb.store_int256_bool(make_refint(organic), 128, false);
  return cb.finalize();
}

// A window_deadline comfortably past the provenance floor for a candidate
// registered near t=0 (kAipowChallengeWindow = 7 days = 604800s).
constexpr long long kDefaultWindowDeadline = 700000;

// Build a commitment account data cell (W4.2 layout) with the fields the parser reads.
td::Ref<vm::Cell> build_commitment(td::uint16 version, td::uint8 status, td::uint64 epoch,
                                   td::Bits256 score_root, long long total_score, long long organic,
                                   long long window_deadline = kDefaultWindowDeadline) {
  vm::CellBuilder cb;
  cb.store_long_bool(version, 16);
  block::tlb::t_MsgAddressInt.store_std_address(cb, -1, mk_bits(0x11));  // committer
  block::tlb::t_MsgAddressInt.store_std_address(cb, -1, mk_bits(0x22));  // reviewer
  cb.store_long_bool(status, 8);
  cb.store_long_bool((long long)epoch, 64);
  cb.store_long_bool(window_deadline, 64);
  cb.store_long_bool(0, 64);     // review_deadline
  block::tlb::t_Tomis.store_integer_value(cb, *make_refint(5000000000LL));  // commit_bond
  block::tlb::t_Tomis.store_integer_value(cb, *make_refint(0));             // challenge_bond
  cb.store_ref(build_econ_tuple(score_root, total_score, organic));        // ^economic tuple
  vm::CellBuilder chal;
  block::tlb::t_MsgAddressInt.store_std_address(chal, -1, mk_bits(0));  // challenger (dummy std)
  chal.store_int256_bool(make_refint(0), 256, false);
  cb.store_ref(chal.finalize());   // ^[challenger evidence]
  vm::CellBuilder stl;
  block::tlb::t_MsgAddressInt.store_std_address(stl, -1, mk_bits(0x99));
  cb.store_ref(stl.finalize());    // ^[settlement]
  return cb.finalize();
}

// A single candidate for build_registrations: (account_id, workchain, score_root,
// total_score, organic, registered_at).
struct Cand {
  td::Bits256 id;
  td::int32 wc;
  td::Bits256 score_root;
  long long total_score;
  long long organic;
  td::uint32 registered_at;
};

// Build the record body (inline dict value): workchain:int8 score_root:256
// total_score:128 organic:128 registered_at:32.
td::Ref<vm::Cell> build_candidate_record(const Cand& c) {
  vm::CellBuilder cb;
  cb.store_long_bool(c.wc, 8);
  cb.store_bits_bool(c.score_root);
  cb.store_int256_bool(make_refint(c.total_score), 128, false);
  cb.store_int256_bool(make_refint(c.organic), 128, false);
  cb.store_long_bool(c.registered_at, 32);
  return cb.finalize();
}

// Build a registrations root (udict 32 -> ^[count:16 candidates:HashmapE 256]),
// with the given candidates recorded for `epoch`.
td::Ref<vm::Cell> build_registrations(td::uint32 epoch, const std::vector<Cand>& cands) {
  vm::Dictionary candidates{256};
  for (const auto& c : cands) {
    candidates.set(c.id, vm::load_cell_slice_ref(build_candidate_record(c)));
  }
  vm::CellBuilder ecell;
  ecell.store_long_bool((long long)cands.size(), 16);
  ecell.store_maybe_ref(candidates.get_root_cell());
  vm::Dictionary regs{32};
  regs.set_ref(td::BitArray<32>{(long long)epoch}, ecell.finalize());
  return regs.get_root_cell();
}

// Build a settlement account data cell (W4.1 layout) with an optional registrations dict.
td::Ref<vm::Cell> build_settlement(td::uint32 next_epoch, long long minted_total, long long total_cap,
                                   td::Ref<vm::Cell> registrations_root, td::uint16 version = 1) {
  vm::CellBuilder cb;
  cb.store_long_bool(version, 16);      // version
  cb.store_long_bool(next_epoch, 32);
  cb.store_long_bool(65536, 32);        // epoch_seconds
  cb.store_long_bool(3600, 32);         // register_grace
  cb.store_long_bool(block::aipow::kAipowChallengeWindow, 32);  // challenge_window (the value the tests use)
  cb.store_long_bool(-1, 8);            // earner_workchain (int8)
  cb.store_long_bool(2500, 16);         // immediate_bps
  cb.store_long_bool(8, 16);            // stream_epochs
  cb.store_long_bool(65536, 32);        // mat_epoch_seconds
  block::tlb::t_Tomis.store_integer_value(cb, *make_refint(minted_total));
  block::tlb::t_Tomis.store_integer_value(cb, *make_refint(total_cap));
  cb.store_ref(dummy_ref());            // ^distributor_code
  cb.store_maybe_ref(registrations_root);  // registrations HashmapE
  return cb.finalize();
}

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

TEST(Aipow, parse_settlement_ledger_roundtrips) {
  auto data = build_settlement(27260, 1000, 4500000000000000000LL, {});
  block::aipow::SettlementLedger led;
  CHECK(block::aipow::parse_settlement_ledger(data, led));
  CHECK(led.version == 1);
  CHECK(led.next_epoch == 27260);
  CHECK(led.epoch_seconds == 65536);
  CHECK(led.register_grace == 3600);
  CHECK(led.challenge_window == block::aipow::kAipowChallengeWindow);
  CHECK(led.earner_workchain == -1);
  CHECK(led.immediate_bps == 2500);
  CHECK(led.stream_epochs == 8);
  CHECK(led.mat_epoch_seconds == 65536);
  CHECK(td::cmp(led.minted_total, 1000) == 0);
  CHECK(td::cmp(led.total_cap, 4500000000000000000LL) == 0);
  CHECK(led.distributor_code.not_null());
  CHECK(led.registrations.is_null());  // empty dict
  // A short cell fails to parse.
  block::aipow::SettlementLedger bad;
  CHECK(!block::aipow::parse_settlement_ledger(dummy_ref(), bad));
}

TEST(Aipow, list_epoch_candidates_enumerates_in_ascending_address_order) {
  auto score = mk_bits(0x5C);
  // Two candidates for epoch 27263, inserted out of address order.
  auto root = build_registrations(
      27263, {Cand{mk_bits(0xC0), -1, score, 4000000, 9000000000LL, 12345},
              Cand{mk_bits(0x30), 0, mk_bits(0x77), 2000000, 5, 7}});
  auto cands = block::aipow::list_epoch_candidates(root, 27263);
  CHECK(cands.size() == 2u);
  // Ascending account-id order: 0x30 before 0xC0.
  CHECK(cands[0].account_id == mk_bits(0x30));
  CHECK(cands[0].workchain == 0);
  CHECK(cands[1].account_id == mk_bits(0xC0));
  CHECK(cands[1].workchain == -1);
  CHECK(cands[1].score_root == score);
  CHECK(td::cmp(cands[1].total_score, 4000000) == 0);
  CHECK(td::cmp(cands[1].organic_settled_value, 9000000000LL) == 0);
  CHECK(cands[1].registered_at == 12345);

  // A different epoch and an empty dict yield no candidates.
  CHECK(block::aipow::list_epoch_candidates(root, 27264).empty());
  CHECK(block::aipow::list_epoch_candidates(td::Ref<vm::Cell>{}, 27263).empty());
}

TEST(Aipow, parse_commitment_state_roundtrips) {
  auto score = mk_bits(0x5C);
  auto data = build_commitment(1, block::aipow::kCommitmentStatusFinal, 27263, score, 4000000, 9000000000LL);
  block::aipow::CommitmentState c;
  CHECK(block::aipow::parse_commitment_state(data, c));
  CHECK(c.version == 1);
  CHECK(c.status == block::aipow::kCommitmentStatusFinal);
  CHECK(c.epoch == 27263);
  CHECK(c.score_root == score);
  CHECK(td::cmp(c.total_score, 4000000) == 0);
  CHECK(td::cmp(c.organic_settled_value, 9000000000LL) == 0);
}

TEST(Aipow, commitment_authorizes_only_a_matching_final_commitment) {
  auto score = mk_bits(0x5C);
  block::aipow::EpochCandidate cand;
  cand.account_id = mk_bits(0xC0);
  cand.workchain = -1;
  cand.score_root = score;
  cand.total_score = make_refint(4000000);
  cand.organic_settled_value = make_refint(9000000000LL);
  cand.registered_at = 1;

  auto good = [&](td::uint16 ver, td::uint8 status, td::uint64 epoch, td::Bits256 root, long long ts,
                  long long org) {
    block::aipow::CommitmentState c;
    CHECK(block::aipow::parse_commitment_state(build_commitment(ver, status, epoch, root, ts, org), c));
    return block::aipow::commitment_authorizes(cand, c, 1, 27263, block::aipow::kAipowChallengeWindow);
  };

  // Exact match, status final -> authorized.
  CHECK(good(1, block::aipow::kCommitmentStatusFinal, 27263, score, 4000000, 9000000000LL));
  // Not final -> not authorized.
  CHECK(!good(1, 0, 27263, score, 4000000, 9000000000LL));
  CHECK(!good(1, 3 /*rejected*/, 27263, score, 4000000, 9000000000LL));
  // Wrong version -> not authorized.
  CHECK(!good(2, block::aipow::kCommitmentStatusFinal, 27263, score, 4000000, 9000000000LL));
  // Epoch mismatch (commitment epoch != registration key) -> not authorized.
  CHECK(!good(1, block::aipow::kCommitmentStatusFinal, 27264, score, 4000000, 9000000000LL));
  // Root / total_score / organic mismatch -> not authorized.
  CHECK(!good(1, block::aipow::kCommitmentStatusFinal, 27263, mk_bits(0x77), 4000000, 9000000000LL));
  CHECK(!good(1, block::aipow::kCommitmentStatusFinal, 27263, score, 4000001, 9000000000LL));
  CHECK(!good(1, block::aipow::kCommitmentStatusFinal, 27263, score, 4000000, 9000000001LL));

  // Provenance floor: window_deadline must cover registered_at(1) + the challenge
  // window. A commitment whose window closed a second too early is unauthorized
  // even though every economic field matches (it could not have held a full
  // dispute window open).
  auto with_window = [&](long long window_deadline) {
    block::aipow::CommitmentState c;
    CHECK(block::aipow::parse_commitment_state(
        build_commitment(1, block::aipow::kCommitmentStatusFinal, 27263, score, 4000000, 9000000000LL,
                         window_deadline),
        c));
    return block::aipow::commitment_authorizes(cand, c, 1, 27263, block::aipow::kAipowChallengeWindow);
  };
  CHECK(with_window(1 + block::aipow::kAipowChallengeWindow));       // exactly enough -> authorized
  CHECK(!with_window(1 + block::aipow::kAipowChallengeWindow - 1));  // one second short -> rejected
  CHECK(!with_window(0));                                            // a past/zero window -> rejected
}

TEST(Aipow, end_to_end_registered_final_commitment_mints_the_pool) {
  // Wire the parsers to compute_epoch_mint: a settlement at the cursor epoch with
  // a registration and a matching final commitment mints the derived pool.
  auto score = mk_bits(0x5C);
  auto addr = mk_bits(0xC0);
  long long organic = 1000;
  auto root = build_registrations(27260, {Cand{addr, -1, score, 4000000, organic, 1}});
  auto settlement = build_settlement(27260, 0, 4500000000000000000LL, root);

  block::aipow::SettlementLedger led;
  CHECK(block::aipow::parse_settlement_ledger(settlement, led));
  auto cands = block::aipow::list_epoch_candidates(led.registrations, led.next_epoch);
  CHECK(cands.size() == 1u);
  block::aipow::CommitmentState c;
  CHECK(block::aipow::parse_commitment_state(
      build_commitment(1, block::aipow::kCommitmentStatusFinal, led.next_epoch, score, 4000000, organic), c));
  bool authorized = block::aipow::commitment_authorizes(cands[0], c, 1, led.next_epoch, led.challenge_window);
  CHECK(authorized);

  auto cfg = make_cfg(1, 2, 1000000000LL, 0);  // pool = organic / 2 = 500
  block::aipow::SettlementCursor cursor;
  cursor.next_epoch = led.next_epoch;
  cursor.minted_total = led.minted_total;
  cursor.epoch_seconds = led.epoch_seconds;
  cursor.register_grace = led.register_grace;
  auto r = block::aipow::compute_epoch_mint(cfg, make_limits(4500000000000000000LL), cursor, authorized,
                                            cands[0].organic_settled_value, 0);
  CHECK(r.is_mint());
  CHECK(r.epoch == 27260);
  CHECK(td::cmp(r.amount, 500) == 0);
}

TEST(Aipow, derive_masterchain_end_to_end_mints_for_a_registered_final_commitment) {
  auto score = mk_bits(0x5C);
  auto commitment_addr = mk_bits(0xC0);
  auto settlement_addr = mk_bits(0x99);
  auto commit_code_hash = mk_bits(0xCC);
  long long organic = 1000;

  auto root = build_registrations(27260, {Cand{commitment_addr, -1, score, 4000000, organic, 1}});
  auto settlement_data = build_settlement(27260, 0, 4500000000000000000LL, root);
  auto commitment_data =
      build_commitment(1, block::aipow::kCommitmentStatusFinal, 27260, score, 4000000, organic);

  auto resolver = [&](td::int32 wc, const td::Bits256& addr) -> block::aipow::ResolvedAccount {
    block::aipow::ResolvedAccount a;
    if (wc == -1 && addr == settlement_addr) {
      a.exists = true;
      a.data = settlement_data;
      a.code_hash = mk_bits(0x5E);
    } else if (wc == -1 && addr == commitment_addr) {
      a.exists = true;
      a.data = commitment_data;
      a.code_hash = commit_code_hash;
    }
    return a;
  };

  block::aipow::MasterchainMintContext ctx;
  ctx.config = make_cfg(1, 2, 1000000000LL, 0);  // pool = organic / 2 = 500
  ctx.settlement_addr = settlement_addr;
  ctx.commitment_code_hash = commit_code_hash;
  ctx.expected_commitment_version = 1;
  ctx.reviewer_addr = mk_bits(0x22);
  ctx.gen_utime = 700000;  // past registered_at(1) + kAipowChallengeWindow(604800)

  auto r = block::aipow::derive_masterchain_epoch_mint(ctx, resolver);
  CHECK(r.is_mint());
  CHECK(r.epoch == 27260);
  CHECK(td::cmp(r.amount, 500) == 0);

  // A wrong commitment code hash makes the only candidate invalid. With no valid
  // candidate the epoch is now Skip-eligible past its grace deadline (skip no
  // longer refuses a registered epoch -- the griefing fix), so far past grace the
  // result is Skip.
  {
    auto bad = ctx;
    bad.commitment_code_hash = mk_bits(0xBAD);
    bad.gen_utime = 4000000000u;
    CHECK(block::aipow::derive_masterchain_epoch_mint(bad, resolver).is_skip());
  }
  // A non-final commitment is likewise unauthorized.
  {
    auto committed = build_commitment(1, 0 /*committed*/, 27260, score, 4000000, organic);
    auto res2 = [&](td::int32 wc, const td::Bits256& addr) -> block::aipow::ResolvedAccount {
      auto a = resolver(wc, addr);
      if (wc == -1 && addr == commitment_addr) {
        a.data = committed;
      }
      return a;
    };
    CHECK(block::aipow::derive_masterchain_epoch_mint(ctx, res2).is_none());
  }
  // A missing settlement account -> NoSettlement.
  {
    auto empty = [](td::int32, const td::Bits256&) { return block::aipow::ResolvedAccount{}; };
    CHECK(block::aipow::derive_masterchain_epoch_mint(ctx, empty).is_none());
  }
}

TEST(Aipow, derive_masterchain_skips_an_unregistered_epoch_only_past_grace) {
  auto settlement_addr = mk_bits(0x99);
  auto settlement_data = build_settlement(10, 0, 4500000000000000000LL, {});  // empty registrations
  auto resolver = [&](td::int32 wc, const td::Bits256& addr) -> block::aipow::ResolvedAccount {
    block::aipow::ResolvedAccount a;
    if (wc == -1 && addr == settlement_addr) {
      a.exists = true;
      a.data = settlement_data;
    }
    return a;
  };
  block::aipow::MasterchainMintContext ctx;
  ctx.config = make_cfg(1, 2, 1000000000LL, 0);
  ctx.settlement_addr = settlement_addr;
  ctx.commitment_code_hash = mk_bits(0xCC);
  ctx.expected_commitment_version = 1;
  ctx.reviewer_addr = mk_bits(0x22);
  // build_settlement uses epoch_seconds=65536, register_grace=3600.
  td::uint64 skippable_at = (10ull + 1) * 65536ull + 3600ull;
  ctx.gen_utime = (td::uint32)(skippable_at - 1);
  CHECK(block::aipow::derive_masterchain_epoch_mint(ctx, resolver).is_none());
  ctx.gen_utime = (td::uint32)skippable_at;
  auto r = block::aipow::derive_masterchain_epoch_mint(ctx, resolver);
  CHECK(r.is_skip());
  CHECK(r.epoch == 10);
}

TEST(Aipow, config_registry_carries_the_commitment_code_hash) {
  // Build a ConfigParam 93 (AipowRegistry) cell to the block.tlb schema and
  // confirm the commitment_code_hash (in the anonymous ref) round-trips -- this
  // is the audited hash the native settle path pins a commitment's code to.
  vm::CellBuilder cb;
  cb.store_bits_bool(mk_bits(0x01));  // settlement_addr
  cb.store_bits_bool(mk_bits(0x02));  // methodology_hash
  cb.store_bits_bool(mk_bits(0x03));  // rate_card_hash
  vm::CellBuilder ref;
  ref.store_bits_bool(mk_bits(0xCC));  // ^[ commitment_code_hash
  ref.store_bits_bool(mk_bits(0xDD));  //    reviewer_addr ]
  cb.store_ref(ref.finalize());
  cb.store_long_bool(0, 1);  // distributor_code_hashes: empty HashmapE
  auto cell = cb.finalize();

  block::gen::AipowRegistry::Record rec;
  CHECK(tlb::unpack_cell(cell, rec));
  CHECK(rec.settlement_addr == mk_bits(0x01));
  CHECK(rec.r1.commitment_code_hash == mk_bits(0xCC));
  CHECK(rec.r1.reviewer_addr == mk_bits(0xDD));
}

TEST(Aipow, parse_settlement_ledger_reports_the_version_and_derive_fails_closed_on_a_future_version) {
  // A future settlement layout version must not be reinterpreted under v1: the
  // parser reports it, and the masterchain decision fails closed (D9).
  auto settlement_addr = mk_bits(0x99);
  auto v2 = build_settlement(10, 0, 4500000000000000000LL, {}, /*version=*/2);
  block::aipow::SettlementLedger led;
  CHECK(block::aipow::parse_settlement_ledger(v2, led));
  CHECK(led.version == 2);
  auto resolver = [&](td::int32 wc, const td::Bits256& addr) -> block::aipow::ResolvedAccount {
    block::aipow::ResolvedAccount a;
    if (wc == -1 && addr == settlement_addr) {
      a.exists = true;
      a.data = v2;
    }
    return a;
  };
  block::aipow::MasterchainMintContext ctx;
  ctx.config = make_cfg(1, 2, 1000000000LL, 0);
  ctx.settlement_addr = settlement_addr;
  ctx.commitment_code_hash = mk_bits(0xCC);
  ctx.expected_commitment_version = 1;
  ctx.reviewer_addr = mk_bits(0x22);
  ctx.gen_utime = 4000000000u;  // far past any grace deadline
  CHECK(block::aipow::derive_masterchain_epoch_mint(ctx, resolver).is_none());
}

TEST(Aipow, parsers_fail_closed_on_malformed_input_instead_of_throwing) {
  // A garbage cell as the registrations root must not throw (the dict ops would
  // otherwise raise a vm exception in consensus code); it yields no candidates.
  auto garbage = dummy_ref();  // an 8-bit cell, not a valid dictionary node
  CHECK(block::aipow::list_epoch_candidates(garbage, 27260).empty());
  // A garbage cell is not a valid settlement ledger or commitment (returns
  // false, no throw).
  block::aipow::SettlementLedger led;
  CHECK(!block::aipow::parse_settlement_ledger(garbage, led));
  block::aipow::CommitmentState c;
  CHECK(!block::aipow::parse_commitment_state(garbage, c));
}

TEST(Aipow, config_cap_binds_even_below_the_settlements_stored_cap) {
  // ConfigParam 92 is an enforced hard limit: derive clamps the pool to
  // min(config cap, stored cap) - minted, so a settlement deployed with a larger
  // stored cap cannot mint past the declared config cap.
  auto score = mk_bits(0x5C);
  auto commitment_addr = mk_bits(0xC0);
  auto settlement_addr = mk_bits(0x99);
  auto commit_code_hash = mk_bits(0xCC);
  long long organic = 1000;  // pool = organic / 1 = 1000 (k = 1/1)

  auto root = build_registrations(27260, {Cand{commitment_addr, -1, score, 4000000, organic, 1}});
  auto settlement_data = build_settlement(27260, 0, 4500000000000000000LL, root);
  auto commitment_data =
      build_commitment(1, block::aipow::kCommitmentStatusFinal, 27260, score, 4000000, organic);
  auto resolver = [&](td::int32 wc, const td::Bits256& addr) -> block::aipow::ResolvedAccount {
    block::aipow::ResolvedAccount a;
    if (wc == -1 && addr == settlement_addr) {
      a.exists = true;
      a.data = settlement_data;
    } else if (wc == -1 && addr == commitment_addr) {
      a.exists = true;
      a.data = commitment_data;
      a.code_hash = commit_code_hash;
    }
    return a;
  };
  block::aipow::MasterchainMintContext ctx;
  ctx.config = make_cfg(1, 1, 1000000000LL, 0);
  ctx.limits = make_limits(400);  // config cap 400 < pool 1000 and << stored 4.5e18
  ctx.settlement_addr = settlement_addr;
  ctx.commitment_code_hash = commit_code_hash;
  ctx.expected_commitment_version = 1;
  ctx.reviewer_addr = mk_bits(0x22);
  ctx.gen_utime = 700000;  // past registered_at(1) + kAipowChallengeWindow(604800)
  auto r = block::aipow::derive_masterchain_epoch_mint(ctx, resolver);
  CHECK(r.is_mint());
  CHECK(td::cmp(r.amount, 400) == 0);  // clamped to the config cap, not 1000
}

TEST(Aipow, a_malformed_registration_entry_yields_no_candidate_and_skips_past_grace) {
  // A registrations entry EXISTS for the cursor epoch but its cell is garbage
  // (not [count, candidates]). list_epoch_candidates must not throw and yields no
  // candidates, so derive skips the epoch past the grace deadline (the candidate
  // model + the no-freeze skip mean a corrupt entry can never freeze the cursor).
  vm::Dictionary dict{32};
  td::BitArray<32> key;
  key.store_ulong(10);
  dict.set_ref(key, dummy_ref());  // an 8-bit garbage entry, not [count, candidates]
  CHECK(block::aipow::list_epoch_candidates(dict.get_root_cell(), 10).empty());

  auto settlement_addr = mk_bits(0x99);
  auto settlement_data = build_settlement(10, 0, 4500000000000000000LL, dict.get_root_cell());
  auto resolver = [&](td::int32 wc, const td::Bits256& addr) -> block::aipow::ResolvedAccount {
    block::aipow::ResolvedAccount a;
    if (wc == -1 && addr == settlement_addr) {
      a.exists = true;
      a.data = settlement_data;
    }
    return a;
  };
  block::aipow::MasterchainMintContext ctx;
  ctx.config = make_cfg(1, 2, 1000000000LL, 0);
  ctx.limits = make_limits(4500000000000000000LL);
  ctx.settlement_addr = settlement_addr;
  ctx.commitment_code_hash = mk_bits(0xCC);
  ctx.expected_commitment_version = 1;
  ctx.reviewer_addr = mk_bits(0x22);
  ctx.gen_utime = 4000000000u;  // far past any grace deadline
  CHECK(block::aipow::derive_masterchain_epoch_mint(ctx, resolver).is_skip());
}

TEST(Aipow, derive_selects_the_min_address_valid_candidate_skipping_a_bogus_smaller_one) {
  // Two candidates for the cursor epoch: a SMALLER-address bogus one (wrong code
  // hash) and a LARGER-address genuine one. The bogus candidate cannot exclude
  // the genuine one; derive skips the invalid smaller candidate and mints for the
  // min-address VALID candidate, naming it as the winner.
  auto score = mk_bits(0x5C);
  auto settlement_addr = mk_bits(0x99);
  auto commit_code_hash = mk_bits(0xCC);
  long long organic = 1000;

  auto bogus_id = mk_bits(0x10);    // smaller address, bogus
  auto genuine_id = mk_bits(0x40);  // larger address, genuine
  auto root = build_registrations(
      27260, {Cand{bogus_id, -1, mk_bits(0xBB), 4000000, organic, 1},
              Cand{genuine_id, -1, score, 4000000, organic, 2}});
  auto settlement_data = build_settlement(27260, 0, 4500000000000000000LL, root);
  auto genuine_commitment =
      build_commitment(1, block::aipow::kCommitmentStatusFinal, 27260, score, 4000000, organic);

  auto resolver = [&](td::int32 wc, const td::Bits256& addr) -> block::aipow::ResolvedAccount {
    block::aipow::ResolvedAccount a;
    if (wc == -1 && addr == settlement_addr) {
      a.exists = true;
      a.data = settlement_data;
    } else if (wc == -1 && addr == bogus_id) {
      // The bogus candidate resolves to an account with the WRONG code hash.
      a.exists = true;
      a.data = build_commitment(1, block::aipow::kCommitmentStatusFinal, 27260, mk_bits(0xBB), 4000000, organic);
      a.code_hash = mk_bits(0xBAD);
    } else if (wc == -1 && addr == genuine_id) {
      a.exists = true;
      a.data = genuine_commitment;
      a.code_hash = commit_code_hash;
    }
    return a;
  };
  block::aipow::MasterchainMintContext ctx;
  ctx.config = make_cfg(1, 2, 1000000000LL, 0);  // pool = organic / 2 = 500
  ctx.limits = make_limits(4500000000000000000LL);
  ctx.settlement_addr = settlement_addr;
  ctx.commitment_code_hash = commit_code_hash;
  ctx.expected_commitment_version = 1;
  ctx.reviewer_addr = mk_bits(0x22);
  ctx.gen_utime = 700000;  // past registered_at(1) + kAipowChallengeWindow(604800)

  auto r = block::aipow::derive_masterchain_epoch_mint(ctx, resolver);
  CHECK(r.is_mint());
  CHECK(r.epoch == 27260);
  CHECK(td::cmp(r.amount, 500) == 0);
  CHECK(r.winner_id == genuine_id);       // the genuine (larger-address) candidate wins
  CHECK(r.winner_workchain == -1);
}

TEST(Aipow, derive_enforces_the_challenge_window_provenance_floor) {
  // A genuine, final commitment whose economic tuple matches, but the block clock
  // has NOT yet passed registered_at + kAipowChallengeWindow: the mint must wait
  // (NoSettlement), so a fabricated commitment cannot be minted before a real,
  // observable dispute window has elapsed on the settlement's trusted clock.
  auto score = mk_bits(0x5C);
  auto commitment_addr = mk_bits(0xC0);
  auto settlement_addr = mk_bits(0x99);
  auto commit_code_hash = mk_bits(0xCC);
  long long organic = 1000;
  td::uint32 reg_at = 1000000;  // settlement-recorded nomination time
  long long good_window = (long long)reg_at + block::aipow::kAipowChallengeWindow;

  auto make_ctx = [&](long long window_deadline, td::uint32 gen_utime) {
    auto root = build_registrations(27260, {Cand{commitment_addr, -1, score, 4000000, organic, reg_at}});
    auto settlement_data = build_settlement(27260, 0, 4500000000000000000LL, root);
    auto commitment_data =
        build_commitment(1, block::aipow::kCommitmentStatusFinal, 27260, score, 4000000, organic,
                         window_deadline);
    auto resolver = [=](td::int32 wc, const td::Bits256& addr) -> block::aipow::ResolvedAccount {
      block::aipow::ResolvedAccount a;
      if (wc == -1 && addr == settlement_addr) {
        a.exists = true;
        a.data = settlement_data;
      } else if (wc == -1 && addr == commitment_addr) {
        a.exists = true;
        a.data = commitment_data;
        a.code_hash = commit_code_hash;
      }
      return a;
    };
    block::aipow::MasterchainMintContext ctx;
    ctx.config = make_cfg(1, 2, 1000000000LL, 0);  // pool = 500
    ctx.settlement_addr = settlement_addr;
    ctx.commitment_code_hash = commit_code_hash;
    ctx.expected_commitment_version = 1;
  ctx.reviewer_addr = mk_bits(0x22);
    ctx.gen_utime = gen_utime;
    return block::aipow::derive_masterchain_epoch_mint(ctx, resolver);
  };

  // Window open long enough, but one second before it elapses -> no mint yet, and
  // (grace not reached) not a skip either: the cursor holds.
  CHECK(make_ctx(good_window, (td::uint32)(good_window - 1)).is_none());
  // The instant the window elapses -> mint.
  {
    auto r = make_ctx(good_window, (td::uint32)good_window);
    CHECK(r.is_mint());
    CHECK(r.epoch == 27260);
    CHECK(r.winner_id == commitment_addr);
    CHECK(td::cmp(r.amount, 500) == 0);
  }
  // A window that closed one second too early is never mintable, even well past
  // registered_at + the window: the commitment could not have held a full dispute
  // window, so it is rejected (NoSettlement, not a forged mint).
  CHECK(make_ctx(good_window - 1, (td::uint32)(good_window + 1000)).is_none());
}

TEST(Aipow, derive_requires_the_commitments_reviewer_to_be_the_registry_reviewer) {
  // Gate 3: a genuine, final commitment mints only if its reviewer is the
  // governance-approved reviewer named in the registry (ConfigParam 93). A
  // committer that names a reviewer it controls (to dismiss challenges) must not be
  // able to mint, even with an otherwise-valid commitment.
  auto score = mk_bits(0x5C);
  auto commitment_addr = mk_bits(0xC0);
  auto settlement_addr = mk_bits(0x99);
  auto commit_code_hash = mk_bits(0xCC);
  long long organic = 1000;
  auto root = build_registrations(27260, {Cand{commitment_addr, -1, score, 4000000, organic, 1}});
  auto settlement_data = build_settlement(27260, 0, 4500000000000000000LL, root);
  // build_commitment fixes the reviewer at mk_bits(0x22) on the masterchain.
  auto commitment_data =
      build_commitment(1, block::aipow::kCommitmentStatusFinal, 27260, score, 4000000, organic);
  auto resolver = [&](td::int32 wc, const td::Bits256& addr) -> block::aipow::ResolvedAccount {
    block::aipow::ResolvedAccount a;
    if (wc == -1 && addr == settlement_addr) {
      a.exists = true;
      a.data = settlement_data;
    } else if (wc == -1 && addr == commitment_addr) {
      a.exists = true;
      a.data = commitment_data;
      a.code_hash = commit_code_hash;
    }
    return a;
  };
  auto ctx_for = [&](td::Bits256 reviewer) {
    block::aipow::MasterchainMintContext ctx;
    ctx.config = make_cfg(1, 2, 1000000000LL, 0);
    ctx.settlement_addr = settlement_addr;
    ctx.commitment_code_hash = commit_code_hash;
    ctx.reviewer_addr = reviewer;
    ctx.expected_commitment_version = 1;
    ctx.gen_utime = 700000;
    return ctx;
  };

  // The registry reviewer matches the commitment's reviewer -> mint.
  CHECK(block::aipow::derive_masterchain_epoch_mint(ctx_for(mk_bits(0x22)), resolver).is_mint());
  // A different registry reviewer -> the commitment is not authorized; since the
  // epoch is not skippable yet (gen_utime before grace) the cursor holds.
  CHECK(block::aipow::derive_masterchain_epoch_mint(ctx_for(mk_bits(0x77)), resolver).is_none());
}
