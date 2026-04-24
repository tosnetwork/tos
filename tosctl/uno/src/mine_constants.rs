//! MineUno halving table and mining constants — Rust mirror of
//! `uno/core/mine_constants.h`.
//!
//! Bitcoin-clone distribution mathematics: 21 M UNO cap, 50 UNO initial reward,
//! halving every 210,000 solves (~4 years per era), 600-second target interval,
//! Poseidon2-over-Goldilocks CPU-only PoW.
//!
//! Source of truth: `doc/Mining-Design.md` §"UNO Mining (wc=2 STARK / Privacy)"
//! and §"Initial Difficulty Calibration / UNO".
//!
//! **C++ mirror**: `uno/core/mine_constants.h`. Field names and semantics must
//! match exactly. Any divergence is a consensus fault.
//!
//! **AIR constraint spec**: `doc/uno-mine-air-constraints.md`.
//! **Phase 2 implementation**: `uno/plonky3-ffi/src/mine_uno_air.rs` (not yet created).

// ---------------------------------------------------------------------------
// Bitcoin-clone halving parameters
// ---------------------------------------------------------------------------

/// Number of successful solves per halving era. Matches Bitcoin's 210,000-
/// block interval. Era 0 spans epochs [0, 210_000), era 1 [210_000, 420_000), …
pub const ERA_SIZE: u64 = 210_000;

/// Initial mining reward in nano-UNO (era 0). 50 UNO × 10^9 nano/UNO.
/// Mirrors Bitcoin's 50 BTC initial subsidy. Halves once per era.
pub const INIT_MINE_REWARD: u64 = 50 * 1_000_000_000;

/// Total UNO supply reserved for mining in nano-UNO.
/// 21,000,000 UNO × 10^9 = 2.1 × 10^16 nano-UNO.
pub const MINE_SUPPLY_NANO: u64 = 21_000_000 * 1_000_000_000;

/// Target PoW solve interval in seconds. Matches Bitcoin's 10-minute block time.
pub const TARGET_SOLVE_SECONDS: u64 = 600;

/// Retargeting lower bound: factor = 3/4.
pub const RETARGET_MIN_NUM: u32 = 3;
pub const RETARGET_MIN_DEN: u32 = 4;

/// Retargeting upper bound: factor = 4/3.
pub const RETARGET_MAX_NUM: u32 = 4;
pub const RETARGET_MAX_DEN: u32 = 3;

/// Domain-separation tag for the PoW hash (consensus-critical).
/// `Poseidon2("uno-mine-v1" ‖ epoch ‖ nonce ‖ output_cm)`.
pub const MINE_HASH_TAG: &[u8] = b"uno-mine-v1";

/// Initial PoW target for genesis: 2^219 (32-byte big-endian).
///
/// Derived from calibration (5-10 CPU miners, ~150 Mops/s):
///   hashes/solve = 150M × 600s = 9 × 10^10; log2(9e10) ≈ 36.4
///   init_target = 2^(256 − 37) = 2^219
///
/// Byte layout: byte[4] (from MSB) = 0x08, all others 0.
/// (Big-endian index of bit 219: 31 − 219/8 = 31 − 27 = 4; bit 219%8 = 3 → 0x08.)
pub const INIT_MINE_TARGET_BE: [u8; 32] = {
    let mut t = [0u8; 32];
    // bit 219 from LSB → byte 4 from MSB, bit 3 within byte → 0x08
    t[4] = 0x08;
    t
};

/// Last era with a non-zero reward.
/// INIT_MINE_REWARD = 50 × 10^9 ≈ 2^35.5; era 35 gives >> 35 = 1 nano-UNO.
/// Era 36 gives 0 (integer truncation). Matches C++ kMaxNonZeroEra = 35.
pub const MAX_NON_ZERO_ERA: u32 = 35;

// ---------------------------------------------------------------------------
// Computed helpers
// ---------------------------------------------------------------------------

/// Returns the mining reward in nano-UNO for a given halving era.
///
/// Era 0: 50 UNO (= [`INIT_MINE_REWARD`]); era k: 50 UNO / 2^k.
/// For `era >= 64`, returns 0 (Rust's checked_shr would saturate to 0).
///
/// C++ mirror: `mine_reward_for_era()` in `mine_constants.h`.
#[inline]
pub const fn mine_reward_for_era(era: u32) -> u64 {
    if era >= 64 {
        return 0;
    }
    INIT_MINE_REWARD >> era
}

/// Compute the halving era from the cumulative solve epoch.
/// `era = epoch / ERA_SIZE` (integer division).
///
/// C++ mirror: `era_from_epoch()` in `mine_constants.h`.
#[inline]
pub const fn era_from_epoch(epoch: u32) -> u32 {
    (epoch as u64 / ERA_SIZE) as u32
}

/// Convenience: reward for the era corresponding to a given epoch.
///
/// C++ mirror: `mine_reward_for_epoch()` in `mine_constants.h`.
#[inline]
pub const fn mine_reward_for_epoch(epoch: u32) -> u64 {
    mine_reward_for_era(era_from_epoch(epoch))
}

// ---------------------------------------------------------------------------
// Compile-time verification
// ---------------------------------------------------------------------------

const _: () = {
    assert!(mine_reward_for_era(0) == INIT_MINE_REWARD, "era-0 reward");
    assert!(mine_reward_for_era(1) == INIT_MINE_REWARD / 2, "era-1 reward");
    assert!(mine_reward_for_era(MAX_NON_ZERO_ERA) > 0, "kMaxNonZeroEra non-zero");
    assert!(mine_reward_for_era(MAX_NON_ZERO_ERA + 1) == 0, "kMaxNonZeroEra+1 zero");
    assert!(era_from_epoch(210_000) == 1, "epoch 210000 → era 1");
    assert!(era_from_epoch(209_999) == 0, "epoch 209999 → era 0");
    assert!(MINE_SUPPLY_NANO == 21_000_000 * 1_000_000_000, "supply");
    assert!(ERA_SIZE == 210_000, "era size");
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn era_0_reward_is_50_uno() {
        assert_eq!(mine_reward_for_era(0), 50 * 1_000_000_000);
    }

    #[test]
    fn era_1_reward_is_25_uno() {
        assert_eq!(mine_reward_for_era(1), 25 * 1_000_000_000);
    }

    #[test]
    fn era_35_reward_is_nonzero() {
        assert!(mine_reward_for_era(35) > 0);
    }

    #[test]
    fn era_36_reward_is_zero() {
        assert_eq!(mine_reward_for_era(36), 0);
    }

    #[test]
    fn era_from_epoch_boundary() {
        assert_eq!(era_from_epoch(0), 0);
        assert_eq!(era_from_epoch(209_999), 0);
        assert_eq!(era_from_epoch(210_000), 1);
        assert_eq!(era_from_epoch(419_999), 1);
        assert_eq!(era_from_epoch(420_000), 2);
    }

    #[test]
    fn mine_reward_for_epoch_matches_era() {
        let epoch = 210_000u32;
        assert_eq!(mine_reward_for_epoch(epoch), mine_reward_for_era(1));
        let epoch0 = 0u32;
        assert_eq!(mine_reward_for_epoch(epoch0), mine_reward_for_era(0));
    }

    #[test]
    fn init_target_bit_219() {
        // 2^219 in big-endian 32 bytes:
        // bit 219 from LSB → byte index from MSB = 31 - 219/8 = 31 - 27 = 4
        // bit within byte = 219 % 8 = 3 → 0x08
        let t = INIT_MINE_TARGET_BE;
        assert_eq!(t[4], 0x08, "byte 4 must be 0x08 (bit 219 set)");
        for i in 0..32 {
            if i != 4 {
                assert_eq!(t[i], 0x00, "byte {i} must be 0 in init target");
            }
        }
    }

    #[test]
    fn mine_supply_is_21m_uno() {
        assert_eq!(MINE_SUPPLY_NANO, 21_000_000u64 * 1_000_000_000u64);
    }

    #[test]
    fn mine_hash_tag_matches_cpp() {
        assert_eq!(MINE_HASH_TAG, b"uno-mine-v1");
    }
}
