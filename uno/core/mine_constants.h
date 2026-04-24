/*
    Uno Workchain — MineUno halving table and mining constants (§UNO Mining).

    Bitcoin-clone distribution mathematics: 21 M UNO cap, 50 UNO initial reward,
    halving every 210,000 solves (~4 years per era), 600-second target interval,
    Poseidon2-over-Goldilocks CPU-only PoW.

    Source of truth: doc/Mining-Design.md §"UNO Mining (wc=2 STARK / Privacy)"
    and §"Initial Difficulty Calibration / UNO".

    Mirror: tosctl/uno/src/mine_constants.rs — field names and types are
    kept byte-identical.  Any divergence must be documented at the mirror site.

    AIR constraint spec: doc/uno-mine-air-constraints.md (Phase 1 document).
    Phase 2 implementation: uno/plonky3-ffi/src/mine_uno_air.rs (not yet created).
*/
#pragma once

#include <cstdint>

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Bitcoin-clone halving parameters
// ---------------------------------------------------------------------------

/// Number of successful solves per halving era. Matches Bitcoin's 210,000-
/// block interval. Era 0 spans epochs [0, 210000), era 1 spans [210000, 420000),
/// etc. Epoch tracks cumulative accepted MineUno solves.
constexpr uint64_t kEraSize = 210'000;

/// Initial mining reward in nano-UNO (era 0). 50 UNO × 10^9 nano/UNO.
/// Mirrors Bitcoin's 50 BTC initial subsidy. Halves once per era.
constexpr uint64_t kInitMineReward = 50ULL * 1'000'000'000ULL;

/// Total UNO supply reserved for mining (nano-UNO).
/// Equals kGenesisTotalSupplyNano from genesis.h: 21,000,000 UNO × 10^9.
/// This is 21 M × 10^9 = 2.1 × 10^16 nano-UNO.
/// Note: genesis.h already defines kGenesisTotalSupplyNano — this constant
/// is provided here as a self-contained reference for mine-specific code
/// without requiring a dependency on genesis.h.
constexpr uint64_t kMineSupplyNano = 21'000'000ULL * 1'000'000'000ULL;

/// Target PoW solve interval in seconds. Matches Bitcoin's 10-minute block time.
constexpr uint64_t kTargetSolveSeconds = 600;

/// Retargeting factor bounds for UNO (more aggressive than TOS/eTOS due to
/// volatile CPU hashrate: a single EPYC server can double network rate).
/// Minimum retarget multiplier numerator / denominator: factor = 3/4.
/// Maximum retarget multiplier: factor = 4/3.
/// Stored as numerator pairs for integer arithmetic.
constexpr uint32_t kRetargetMinNum = 3;
constexpr uint32_t kRetargetMinDen = 4;
constexpr uint32_t kRetargetMaxNum = 4;
constexpr uint32_t kRetargetMaxDen = 3;

/// Domain-separation tag for the PoW hash.
/// `Poseidon2("uno-mine-v1" ‖ epoch ‖ nonce ‖ output_cm)`.
/// Must match the MineUno AIR constraint 1 (doc/uno-mine-air-constraints.md).
/// This tag is CONSENSUS-CRITICAL — changing it is a hard fork.
constexpr const char kMineHashTag[] = "uno-mine-v1";

/// Initial PoW target for genesis, derived from calibration assuming
/// 5-10 CPU miners at launch (~150 Mops/s total Poseidon2).
///
/// Calculation (doc/Mining-Design.md §Initial Difficulty Calibration / UNO):
///   hashes/solve = 150M/s × 600s = 9 × 10^10
///   log2(9e10) ≈ 36.4 → init_target = 2^(256 − 37) = 2^219
///
/// The target is a 256-bit big-endian threshold: a PoW hash is accepted when
/// Poseidon2(tag ‖ epoch ‖ nonce ‖ cm) < target (numerically, as 4 Goldilocks
/// field elements compared lexicographically in little-endian limb order).
///
/// Stored as a 32-byte big-endian array matching the MineUnoPublicInputs wire.
///
/// Derivation: 2^219 = 0x08 << 216, so in big-endian the only non-zero byte
/// is byte[4] = 0x08 (because `(31 - 219/8) = 31 - 27 = 4`, and the bit within
/// that byte is `219 % 8 = 3`, i.e., value `1 << 3 = 0x08`).
///
/// Byte layout:
///   bytes [0..3]  = 0x00
///   byte  [4]     = 0x08   ← the single set bit is here
///   bytes [5..31] = 0x00
///
/// Mirror: `INIT_MINE_TARGET_BE` in tosctl/uno/src/mine_constants.rs (byte-identical).
constexpr uint8_t kInitMineTargetBE[32] = {
    // bytes 0..3: zero (bits 255..220 must be zero for threshold 2^219)
    0x00, 0x00, 0x00, 0x00,
    // byte 4: 2^219 → big-endian byte 4 = (1 << 3) = 0x08
    0x08,
    // bytes 5..31: zero (threshold is exactly 2^219 with lower bits zero)
    0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00
};

// ---------------------------------------------------------------------------
// Computed constants (verifiable at compile time)
// ---------------------------------------------------------------------------

/// Maximum number of non-zero halving eras before reward reaches zero.
/// kInitMineReward = 50 UNO × 10^9 = 5 × 10^10 ≈ 2^35.5.
/// After 36 right-shifts the value falls below 1 (nano-UNO) and truncates
/// to 0. Eras 36 and beyond produce zero reward, matching Bitcoin's behaviour
/// (Bitcoin's integer subsidy also reaches 0 after enough halvings).
///
/// Exact first-zero era: mine_reward_for_era(36) = 5e10 >> 36 = 0.
/// mine_reward_for_era(35) = 5e10 >> 35 = 1 (last non-zero era).
constexpr uint32_t kMaxNonZeroEra = 35;

// ---------------------------------------------------------------------------
// Constexpr helpers
// ---------------------------------------------------------------------------

/// Returns the mining reward in nano-UNO for a given halving era.
/// Era 0: 50 UNO; era 1: 25 UNO; era k: 50 UNO / 2^k.
/// For era >= 64, returns 0 (no further reward — integer shift saturates).
///
/// This function is the off-circuit reference used by:
///   - Chain state validation in the MineUno apply step (Phase 2).
///   - Rust mirror: `mine_constants::mine_reward_for_era()`.
///   - AIR constraint 3 (doc/uno-mine-air-constraints.md): the in-circuit
///     halving table is derived from the same formula baked into the AIR.
constexpr uint64_t mine_reward_for_era(uint32_t era) noexcept {
    if (era >= 64) { return 0; }
    return kInitMineReward >> era;
}

/// Compute the halving era from the cumulative solve epoch.
/// Era = epoch / kEraSize (integer division).
///
/// Epoch 0 → era 0 (50 UNO/solve).
/// Epoch 209999 → era 0 (still 50 UNO/solve).
/// Epoch 210000 → era 1 (25 UNO/solve).
///
/// Mirrors: `mine_constants::era_from_epoch()` in Rust.
constexpr uint32_t era_from_epoch(uint32_t epoch) noexcept {
    return static_cast<uint32_t>(epoch / kEraSize);
}

/// Convenience: reward for the era corresponding to a given epoch.
constexpr uint64_t mine_reward_for_epoch(uint32_t epoch) noexcept {
    return mine_reward_for_era(era_from_epoch(epoch));
}

// ---------------------------------------------------------------------------
// Static assertions (compile-time sanity)
// ---------------------------------------------------------------------------

// Era-0 reward must equal the spec constant.
static_assert(mine_reward_for_era(0) == kInitMineReward,
              "era-0 reward must be kInitMineReward");
// Era-1 reward must be exactly half.
static_assert(mine_reward_for_era(1) == kInitMineReward / 2,
              "era-1 reward must be half of era-0");
// kMaxNonZeroEra reward must be non-zero (last era with a reward).
// kInitMineReward = 50 * 10^9 ≈ 2^35.5; era 35 gives >> 35 = 1.
static_assert(mine_reward_for_era(kMaxNonZeroEra) > 0,
              "era kMaxNonZeroEra must be non-zero");
// Era kMaxNonZeroEra+1 must be zero (integer truncation).
static_assert(mine_reward_for_era(kMaxNonZeroEra + 1) == 0,
              "era kMaxNonZeroEra+1 must be zero due to integer truncation");
// era_from_epoch boundary: epoch 210000 → era 1.
static_assert(era_from_epoch(210'000) == 1,
              "epoch 210000 must be in era 1");
// era_from_epoch boundary: epoch 209999 → era 0.
static_assert(era_from_epoch(209'999) == 0,
              "epoch 209999 must be in era 0");
// Supply cap: 21M UNO = kMineSupplyNano.
static_assert(kMineSupplyNano == 21'000'000ULL * 1'000'000'000ULL,
              "kMineSupplyNano must be 21M UNO in nano-UNO");
// kEraSize matches Bitcoin.
static_assert(kEraSize == 210'000, "kEraSize must be Bitcoin-clone 210000");

}  // namespace uno_workchain
