//! FRI fold-chain AIR — trace layout + pure-Rust constraint checker
//! (Phase A2-3c-iv-d-4).
//!
//! Encodes the Lagrange-at-β fold of `fri_arith::fold_row_ref` as an
//! AIR for the **binary FRI** case (`log_arity = 1`). A full FRI
//! verification for one query runs `num_commit_phase_rounds` folds
//! (= 6 for our MvpConfig at degree_bits = 6). We represent one fold
//! round per trace row; the chain's `CURRENT` is threaded across rows
//! exactly as in `merkle_path_air::MerklePathAirV1`.
//!
//! # The binary fold formula (derived from Lagrange interpolation)
//!
//! For `arity = 2`, `fold_row_ref` interpolates at β over xs = [s, −s]
//! where `s = g^{reverse_bits(idx, log_height)}` is the coset start.
//! The closed-form collapses to:
//!
//! ```text
//!   folded = (y0 + y1) / 2  +  β · (y0 − y1) / (2 · s)
//!
//! which rearranges to the polynomial identity we encode as AIR:
//!
//!   folded · (2s) == s · (y0 + y1) + β · (y0 − y1)          (I)
//! ```
//!
//! (I) is degree-2 per limb; handling the β·(y0−y1) extension product
//! adds one more factor per term. Using the BinomialExtendable pin
//! `W = 7` for Goldilocks's D=2 extension:
//!
//! ```text
//!   folded_0 · 2s == s · (y0_0 + y1_0) + β_0 · d_0 + 7 · β_1 · d_1
//!   folded_1 · 2s == s · (y0_1 + y1_1) + β_0 · d_1 +     β_1 · d_0
//!
//! where d_i = PAIR_LEFT_i − PAIR_RIGHT_i and y0, y1 are after
//! INDEX_BIT-driven orientation (PAIR_LEFT / PAIR_RIGHT).
//! ```
//!
//! Max constraint degree 2 for the fold identity itself; we gate by
//! `is_fold` which adds one more degree → degree 3 overall.
//!
//! # Column layout per row (framing; no Poseidon2 block needed)
//!
//! ```text
//! -------- Selectors (one-hot over {FOLD, IDLE}) -----------------
//!   IS_FOLD                : 1 col
//!   IS_IDLE                : 1 col
//!
//! -------- Per-row extension values (Challenge = (lo, hi)) -------
//!   CURRENT[0..2]          : 2 cols — running folded eval from the
//!                                     previous round (equals
//!                                     INITIAL_FOLDED on row 0)
//!   SIBLING[0..2]          : 2 cols — this round's sibling opening
//!   PAIR_LEFT[0..2]        : 2 cols — PAIR_LEFT  = (1-bit)·CURRENT
//!                                                  + bit·SIBLING
//!   PAIR_RIGHT[0..2]       : 2 cols — PAIR_RIGHT = bit·CURRENT
//!                                                  + (1-bit)·SIBLING
//!   BETA[0..2]             : 2 cols — this round's β challenge
//!   FOLDED[0..2]           : 2 cols — output of this round's fold
//!
//! -------- Base-field per-row -----------------------------------
//!   INDEX_BIT              : 1 col  — boolean; picks y0/y1 orientation
//!   S                      : 1 col  — coset start g^{reverse_bits(idx)}
//!   INV_2S                 : 1 col  — witness: 2·S·INV_2S == 1
//!
//! -------- Threaded / public-input proxies -----------------------
//!   INITIAL_FOLDED[0..2]   : 2 cols — ro_value from open_input (d-4 only:
//!                                     duplicated per row; d-6 integration
//!                                     will bind this to α-reduction output)
//!   FINAL_FOLDED[0..2]     : 2 cols — expected final folded_eval, equal
//!                                     to eval_final_poly(final_eval_x).
//!                                     Same public-input-proxy treatment
//!                                     as Merkle's ROOT.
//! ```
//!
//! Total framing width: 2 + 2 + 2 + 2 + 2 + 2 + 2 + 1 + 1 + 1 + 2 + 2
//!                    = **21 cols**.
//!
//! # Transition rules (encoded by `check_all_transitions`)
//!
//! 1. One-hot: `IS_FOLD + IS_IDLE = 1`.
//! 2. FOLD row:
//!    - INDEX_BIT boolean.
//!    - PAIR_LEFT  = (1 − INDEX_BIT)·CURRENT + INDEX_BIT·SIBLING.
//!    - PAIR_RIGHT = INDEX_BIT·CURRENT + (1 − INDEX_BIT)·SIBLING.
//!    - INV_2S witness: 2·S·INV_2S = 1 (ensures S ≠ 0).
//!    - Fold identity (I) per limb.
//! 3. Transition: `next.IS_FOLD = 1 ⇒ next.CURRENT = local.FOLDED` (threading).
//! 4. IDLE preserves every data column (KIND flags may change).
//! 5. Row 0's CURRENT = INITIAL_FOLDED.
//! 6. Last non-IDLE row's FOLDED = FINAL_FOLDED.
//!
//! # Out of scope for d-4 (future sub-phases)
//!
//! - **S binding**: no AIR constraint links S to
//!   `g^{reverse_bits(query_idx)}`. A future sub-phase adds a
//!   bit-decomposition + exponent reconstruction (or precomputes
//!   per-round S via a public-input vector).
//! - **β binding**: β comes from Fiat-Shamir (ChallengerAir).
//!   Integration binds it via `num_public_values`.
//! - **Air<AB> port**: lands in d-4-2 (mirrors d-1 → d-2 for Merkle).
//! - **Final-poly evaluation**: the Horner eval that produces
//!   FINAL_FOLDED gets its own sub-phase.

use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_util::reverse_bits_len;

use crate::fri_arith::fold_row_ref;
use crate::prover::Challenge;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Extension field DIMENSION — Goldilocks's BinomialExtensionField<_, 2>.
pub const CHALLENGE_DIM: usize = 2;
/// Binomial extension norm constant for Goldilocks D=2. Must match
/// `<Goldilocks as BinomiallyExtendable<2>>::W`.
pub const EXT_W: u64 = 7;

// ---------------------------------------------------------------------------
// Op-kind selectors
// ---------------------------------------------------------------------------

pub const OP_KIND_FOLD: u8 = 0;
pub const OP_KIND_IDLE: u8 = 1;
pub const NUM_OP_KINDS: usize = 2;

// ---------------------------------------------------------------------------
// Column offsets
// ---------------------------------------------------------------------------

pub mod col {
    use super::*;

    pub const KIND0: usize = 0;
    pub const KIND_END: usize = KIND0 + NUM_OP_KINDS;

    pub const CURRENT0: usize = KIND_END;
    pub const CURRENT_END: usize = CURRENT0 + CHALLENGE_DIM;

    pub const SIBLING0: usize = CURRENT_END;
    pub const SIBLING_END: usize = SIBLING0 + CHALLENGE_DIM;

    pub const PAIR_LEFT0: usize = SIBLING_END;
    pub const PAIR_LEFT_END: usize = PAIR_LEFT0 + CHALLENGE_DIM;

    pub const PAIR_RIGHT0: usize = PAIR_LEFT_END;
    pub const PAIR_RIGHT_END: usize = PAIR_RIGHT0 + CHALLENGE_DIM;

    pub const BETA0: usize = PAIR_RIGHT_END;
    pub const BETA_END: usize = BETA0 + CHALLENGE_DIM;

    pub const FOLDED0: usize = BETA_END;
    pub const FOLDED_END: usize = FOLDED0 + CHALLENGE_DIM;

    pub const INDEX_BIT: usize = FOLDED_END;
    pub const S: usize = INDEX_BIT + 1;
    pub const INV_2S: usize = S + 1;

    pub const INITIAL_FOLDED0: usize = INV_2S + 1;
    pub const INITIAL_FOLDED_END: usize = INITIAL_FOLDED0 + CHALLENGE_DIM;

    pub const FINAL_FOLDED0: usize = INITIAL_FOLDED_END;
    pub const FINAL_FOLDED_END: usize = FINAL_FOLDED0 + CHALLENGE_DIM;

    pub const WIDTH: usize = FINAL_FOLDED_END;
}

/// Canonical framing width. 21 cols.
pub const FOLD_AIR_FRAMING_WIDTH: usize = col::WIDTH;

// ---------------------------------------------------------------------------
// Round description — caller-supplied per-fold-round data
// ---------------------------------------------------------------------------

/// One round of the fold chain.
#[derive(Clone, Debug)]
pub struct FoldRound {
    /// Sibling value at this round (the other half of the arity-2 group).
    pub sibling: Challenge,
    /// FRI fold challenge β_r.
    pub beta: Challenge,
    /// Domain index at the START of this round — drives orientation
    /// (low bit → INDEX_BIT) and the coset start S.
    ///
    /// After the round, the index is right-shifted by 1 in the caller
    /// (matches upstream `*start_index >>= log_arity`).
    pub domain_index: usize,
    /// Log-height of this round's FRI codeword BEFORE the fold. Drives
    /// `S = two_adic_generator(log_height + 1)^{reverse_bits(idx, log_height)}`.
    ///
    /// After the fold, the codeword halves: `log_height - 1`.
    pub log_height: usize,
}

// ---------------------------------------------------------------------------
// Trace builder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TraceBuildError {
    TraceHeightNotPow2 { got: usize },
    TraceHeightTooSmall { physical_rows: usize, trace_height: usize },
    SZero { round: usize },
}

/// Build a row-major trace for the fold chain.
///
/// `rounds.len()` is the number of fold steps (= num_commit_phase_rounds
/// from the proof). `initial_folded` is the RO value from `open_input`.
/// `final_folded` is `eval_final_poly_horner(final_poly, final_eval_x)`
/// — the fold chain must land exactly on this value.
pub fn build_trace(
    initial_folded: Challenge,
    rounds: &[FoldRound],
    final_folded: Challenge,
    trace_height: usize,
) -> Result<Vec<Goldilocks>, TraceBuildError> {
    if !trace_height.is_power_of_two() {
        return Err(TraceBuildError::TraceHeightNotPow2 { got: trace_height });
    }
    let physical_rows = rounds.len();
    if physical_rows > trace_height {
        return Err(TraceBuildError::TraceHeightTooSmall {
            physical_rows,
            trace_height,
        });
    }

    use p3_field::TwoAdicField;

    let width = col::WIDTH;
    let mut flat = vec![Goldilocks::default(); trace_height * width];
    let zero = Goldilocks::default();

    let write_ext = |out: &mut [Goldilocks], base: usize, v: Challenge| {
        use p3_field::BasedVectorSpace;
        let limbs = <Challenge as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&v);
        for i in 0..CHALLENGE_DIM {
            out[base + i] = limbs[i];
        }
    };
    let write_kind = |out: &mut [Goldilocks], kind: u8| {
        for k in 0..NUM_OP_KINDS {
            out[col::KIND0 + k] =
                if k as u8 == kind { Goldilocks::new(1) } else { zero };
        }
    };

    // Run the fold chain so we can populate FOLDED + CURRENT per row.
    let mut current = initial_folded;
    for (r, round) in rounds.iter().enumerate() {
        let base = r * width;
        let row = &mut flat[base..base + width];
        write_kind(row, OP_KIND_FOLD);

        // INDEX_BIT = low bit of domain_index for this round.
        let bit = (round.domain_index & 1) as u64;
        // S = fold_row_ref's `subgroup_start`. Upstream passes
        // (parent_idx, child_log_h) to fold_row, so S is derived from
        // the CHILD level:
        //   g_outer        = two_adic_generator(child_log_h + log_arity)
        //                 = two_adic_generator(round.log_height)
        //   subgroup_start = g_outer^{reverse_bits(parent_idx, child_log_h)}
        // where parent_idx = round.domain_index >> 1 and
        //       child_log_h = round.log_height - 1.
        let child_log_h = round.log_height - 1;
        let parent_idx = round.domain_index >> 1;
        let g_outer = Goldilocks::two_adic_generator(child_log_h + 1);
        let rev = reverse_bits_len(parent_idx, child_log_h);
        let s = g_outer.exp_u64(rev as u64);
        if s == zero {
            return Err(TraceBuildError::SZero { round: r });
        }
        let two_s = s * Goldilocks::new(2);
        let inv_2s = two_s
            .try_inverse()
            .expect("2s ≠ 0 ⇒ invertible in Goldilocks");

        // PAIR_LEFT / PAIR_RIGHT from INDEX_BIT orientation.
        let (pair_left, pair_right) = if bit == 0 {
            (current, round.sibling)
        } else {
            (round.sibling, current)
        };

        // Compute FOLDED via the reference (Lagrange-at-β) — same
        // parent_idx / child_log_h as the S formula above.
        let folded = fold_row_ref(
            parent_idx,
            child_log_h,
            1, // log_arity = 1 (binary FRI)
            round.beta,
            &[pair_left, pair_right],
        );

        // Write columns.
        write_ext(row, col::CURRENT0, current);
        write_ext(row, col::SIBLING0, round.sibling);
        write_ext(row, col::PAIR_LEFT0, pair_left);
        write_ext(row, col::PAIR_RIGHT0, pair_right);
        write_ext(row, col::BETA0, round.beta);
        write_ext(row, col::FOLDED0, folded);
        row[col::INDEX_BIT] = Goldilocks::new(bit);
        row[col::S] = s;
        row[col::INV_2S] = inv_2s;
        write_ext(row, col::INITIAL_FOLDED0, initial_folded);
        write_ext(row, col::FINAL_FOLDED0, final_folded);

        current = folded;
    }

    // Pad remaining rows with IDLE — clone the previous row's data
    // columns so the IDLE-persistence transition holds.
    for row_idx in physical_rows..trace_height {
        let prev_base = (row_idx - 1) * width;
        let prev_row = flat[prev_base..prev_base + width].to_vec();
        let base = row_idx * width;
        let row = &mut flat[base..base + width];
        for c in col::KIND_END..col::WIDTH {
            row[c] = prev_row[c];
        }
        write_kind(row, OP_KIND_IDLE);
    }

    Ok(flat)
}

// ---------------------------------------------------------------------------
// Pure-Rust constraint checker
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CheckError {
    TraceLengthMismatch { expected: usize, got: usize },
    KindFlagNotBoolean { row: usize, kind: usize },
    KindNotOneHot { row: usize },
    IndexBitNotBoolean { row: usize },
    PairLeftMismatch { row: usize, limb: usize },
    PairRightMismatch { row: usize, limb: usize },
    InvTwoSWitnessInvalid { row: usize },
    FoldIdentityLimb0 { row: usize },
    FoldIdentityLimb1 { row: usize },
    CurrentThreadingMismatch { row: usize, limb: usize },
    IdlePersistenceMismatch { row: usize, col: usize },
    InitialFoldedMismatchOnFirstRow { limb: usize },
    FinalFoldedMismatchOnLastRow { limb: usize },
    InitialFoldedDrift { row: usize, limb: usize },
    FinalFoldedDrift { row: usize, limb: usize },
}

pub fn check_all_transitions(
    trace: &[Goldilocks],
    trace_height: usize,
) -> Result<(), CheckError> {
    let width = col::WIDTH;
    if trace.len() != trace_height * width {
        return Err(CheckError::TraceLengthMismatch {
            expected: trace_height * width,
            got: trace.len(),
        });
    }
    let row = |r: usize| &trace[r * width..(r + 1) * width];
    let zero = Goldilocks::default();
    let one = Goldilocks::new(1);
    let two = Goldilocks::new(2);
    let w_const = Goldilocks::new(EXT_W);

    let mut last_non_idle_folded: Option<(Goldilocks, Goldilocks)> = None;

    for r in 0..trace_height {
        let local = row(r);

        // One-hot.
        let mut sum = zero;
        for k in 0..NUM_OP_KINDS {
            let v = local[col::KIND0 + k];
            if v != zero && v != one {
                return Err(CheckError::KindFlagNotBoolean { row: r, kind: k });
            }
            sum += v;
        }
        if sum != one {
            return Err(CheckError::KindNotOneHot { row: r });
        }

        let is_fold = local[col::KIND0 + OP_KIND_FOLD as usize] == one;
        let is_idle = local[col::KIND0 + OP_KIND_IDLE as usize] == one;

        // Per-row FOLD constraints.
        if is_fold {
            let bit = local[col::INDEX_BIT];
            if bit != zero && bit != one {
                return Err(CheckError::IndexBitNotBoolean { row: r });
            }

            // PAIR_LEFT / PAIR_RIGHT from orientation.
            for i in 0..CHALLENGE_DIM {
                let cur = local[col::CURRENT0 + i];
                let sib = local[col::SIBLING0 + i];
                let expected_left = (one - bit) * cur + bit * sib;
                let expected_right = bit * cur + (one - bit) * sib;
                if local[col::PAIR_LEFT0 + i] != expected_left {
                    return Err(CheckError::PairLeftMismatch { row: r, limb: i });
                }
                if local[col::PAIR_RIGHT0 + i] != expected_right {
                    return Err(CheckError::PairRightMismatch { row: r, limb: i });
                }
            }

            // INV_2S witness: 2·S·INV_2S = 1.
            let s = local[col::S];
            let inv_2s = local[col::INV_2S];
            if two * s * inv_2s != one {
                return Err(CheckError::InvTwoSWitnessInvalid { row: r });
            }

            // Fold identity (I) per limb.
            let pl0 = local[col::PAIR_LEFT0];
            let pl1 = local[col::PAIR_LEFT0 + 1];
            let pr0 = local[col::PAIR_RIGHT0];
            let pr1 = local[col::PAIR_RIGHT0 + 1];
            let b0 = local[col::BETA0];
            let b1 = local[col::BETA0 + 1];
            let f0 = local[col::FOLDED0];
            let f1 = local[col::FOLDED0 + 1];

            let two_s = two * s;
            let d0 = pl0 - pr0;
            let d1 = pl1 - pr1;

            // Limb 0: folded_0 · 2s == s·(pl0 + pr0) + β_0·d_0 + 7·β_1·d_1
            let lhs0 = f0 * two_s;
            let rhs0 = s * (pl0 + pr0) + b0 * d0 + w_const * b1 * d1;
            if lhs0 != rhs0 {
                return Err(CheckError::FoldIdentityLimb0 { row: r });
            }
            // Limb 1: folded_1 · 2s == s·(pl1 + pr1) + β_0·d_1 + β_1·d_0
            let lhs1 = f1 * two_s;
            let rhs1 = s * (pl1 + pr1) + b0 * d1 + b1 * d0;
            if lhs1 != rhs1 {
                return Err(CheckError::FoldIdentityLimb1 { row: r });
            }
        }

        // CURRENT threading from previous row's FOLDED (on FOLD rows r ≥ 1).
        if is_fold && r > 0 {
            let prev = row(r - 1);
            for i in 0..CHALLENGE_DIM {
                if local[col::CURRENT0 + i] != prev[col::FOLDED0 + i] {
                    return Err(CheckError::CurrentThreadingMismatch { row: r, limb: i });
                }
            }
        }

        // INITIAL_FOLDED / FINAL_FOLDED persistence across rows.
        if r > 0 {
            let prev = row(r - 1);
            for i in 0..CHALLENGE_DIM {
                if local[col::INITIAL_FOLDED0 + i] != prev[col::INITIAL_FOLDED0 + i] {
                    return Err(CheckError::InitialFoldedDrift { row: r, limb: i });
                }
                if local[col::FINAL_FOLDED0 + i] != prev[col::FINAL_FOLDED0 + i] {
                    return Err(CheckError::FinalFoldedDrift { row: r, limb: i });
                }
            }
        }

        // IDLE persistence: all non-KIND cols equal the previous row's.
        if is_idle && r > 0 {
            let prev = row(r - 1);
            for c in col::KIND_END..col::WIDTH {
                if local[c] != prev[c] {
                    return Err(CheckError::IdlePersistenceMismatch { row: r, col: c });
                }
            }
        }

        if !is_idle {
            last_non_idle_folded = Some((local[col::FOLDED0], local[col::FOLDED0 + 1]));
        }
    }

    // Row 0's CURRENT must equal INITIAL_FOLDED.
    {
        let row0 = row(0);
        for i in 0..CHALLENGE_DIM {
            if row0[col::CURRENT0 + i] != row0[col::INITIAL_FOLDED0 + i] {
                return Err(CheckError::InitialFoldedMismatchOnFirstRow { limb: i });
            }
        }
    }

    // Last non-IDLE row's FOLDED must equal FINAL_FOLDED.
    if let Some((f0, f1)) = last_non_idle_folded {
        let last = row(trace_height - 1);
        let expected0 = last[col::FINAL_FOLDED0];
        let expected1 = last[col::FINAL_FOLDED0 + 1];
        if f0 != expected0 {
            return Err(CheckError::FinalFoldedMismatchOnLastRow { limb: 0 });
        }
        if f1 != expected1 {
            return Err(CheckError::FinalFoldedMismatchOnLastRow { limb: 1 });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::BasedVectorSpace;

    fn gl(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    fn ext(a: u64, b: u64) -> Challenge {
        Challenge::from_basis_coefficients_fn(|i| if i == 0 { gl(a) } else { gl(b) })
    }

    /// Build a handmade 3-round chain and return (initial, rounds, final).
    fn handmade_3_round_chain(
        initial: Challenge,
    ) -> (Challenge, Vec<FoldRound>, Challenge) {
        // Rounds are synthetic — the actual S/INDEX_BIT come from the
        // index schedule. Let's start at log_height=6 (64 rows) and
        // fold down via log_arity=1 each round.
        let rounds = vec![
            FoldRound {
                sibling: ext(11, 22),
                beta: ext(3, 5),
                domain_index: 0b101011,
                log_height: 6,
            },
            FoldRound {
                sibling: ext(33, 44),
                beta: ext(7, 11),
                domain_index: 0b10101, // after >>1
                log_height: 5,
            },
            FoldRound {
                sibling: ext(55, 66),
                beta: ext(13, 17),
                domain_index: 0b1010,
                log_height: 4,
            },
        ];

        // Simulate the fold chain to compute the expected FINAL.
        let mut current = initial;
        for round in &rounds {
            let bit = round.domain_index & 1;
            let (pl, pr) = if bit == 0 {
                (current, round.sibling)
            } else {
                (round.sibling, current)
            };
            let parent_idx = round.domain_index >> 1;
            let child_log_h = round.log_height - 1;
            current = fold_row_ref(parent_idx, child_log_h, 1, round.beta, &[pl, pr]);
        }
        let final_folded = current;
        (initial, rounds, final_folded)
    }

    // ---- builder positive ----

    #[test]
    fn build_and_check_accept_handmade_chain() {
        let (initial, rounds, final_folded) = handmade_3_round_chain(ext(100, 200));
        let trace = build_trace(initial, &rounds, final_folded, 8).unwrap();
        assert_eq!(trace.len(), 8 * col::WIDTH);
        check_all_transitions(&trace, 8).expect("valid fold chain must check");
    }

    #[test]
    fn build_rejects_non_pow2_height() {
        let (initial, rounds, final_folded) = handmade_3_round_chain(ext(1, 2));
        let err = build_trace(initial, &rounds, final_folded, 7).unwrap_err();
        assert_eq!(err, TraceBuildError::TraceHeightNotPow2 { got: 7 });
    }

    #[test]
    fn build_rejects_insufficient_height() {
        let (initial, rounds, final_folded) = handmade_3_round_chain(ext(1, 2));
        let err = build_trace(initial, &rounds, final_folded, 2).unwrap_err();
        assert_eq!(
            err,
            TraceBuildError::TraceHeightTooSmall {
                physical_rows: 3,
                trace_height: 2
            }
        );
    }

    // ---- checker negatives ----

    #[test]
    fn checker_rejects_tampered_sibling() {
        let (initial, rounds, final_folded) = handmade_3_round_chain(ext(100, 200));
        let mut trace = build_trace(initial, &rounds, final_folded, 8).unwrap();
        // Tamper row 0 SIBLING[0].
        trace[col::SIBLING0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_flipped_index_bit() {
        let (initial, rounds, final_folded) = handmade_3_round_chain(ext(100, 200));
        let mut trace = build_trace(initial, &rounds, final_folded, 8).unwrap();
        // Row 0: bit was 1 (domain_index=0b101011). Flip to 0.
        trace[col::INDEX_BIT] = gl(0);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_bad_inv_2s_witness() {
        let (initial, rounds, final_folded) = handmade_3_round_chain(ext(100, 200));
        let mut trace = build_trace(initial, &rounds, final_folded, 8).unwrap();
        // Row 0: corrupt INV_2S → 2·S·INV_2S ≠ 1.
        trace[col::INV_2S] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_tampered_folded_limb0() {
        let (initial, rounds, final_folded) = handmade_3_round_chain(ext(100, 200));
        let mut trace = build_trace(initial, &rounds, final_folded, 8).unwrap();
        // Row 0 FOLDED[0] tampered; limb-0 fold identity fires.
        trace[col::FOLDED0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_tampered_folded_limb1() {
        let (initial, rounds, final_folded) = handmade_3_round_chain(ext(100, 200));
        let mut trace = build_trace(initial, &rounds, final_folded, 8).unwrap();
        // Row 0 FOLDED[1] tampered; limb-1 fold identity fires.
        trace[col::FOLDED0 + 1] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_broken_current_threading() {
        let (initial, rounds, final_folded) = handmade_3_round_chain(ext(100, 200));
        let mut trace = build_trace(initial, &rounds, final_folded, 8).unwrap();
        // Row 1 CURRENT[0] should equal row 0 FOLDED[0]. Break it.
        let row1 = col::WIDTH;
        trace[row1 + col::CURRENT0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_initial_folded_mismatch_row0() {
        let (initial, rounds, final_folded) = handmade_3_round_chain(ext(100, 200));
        let mut trace = build_trace(initial, &rounds, final_folded, 8).unwrap();
        // Tamper row 0 INITIAL_FOLDED[0]: CURRENT should equal it → mismatch.
        trace[col::INITIAL_FOLDED0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_wrong_final_folded() {
        let (initial, rounds, _) = handmade_3_round_chain(ext(100, 200));
        let mut wrong_final = ext(0, 0);
        // Any non-matching extension element works.
        wrong_final += ext(1, 0);
        let trace = build_trace(initial, &rounds, wrong_final, 8).unwrap();
        // The last non-IDLE row's FOLDED matches the REAL chain output,
        // but FINAL_FOLDED says the chain should produce `wrong_final`.
        // So the last-row check fires.
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_initial_folded_drift() {
        let (initial, rounds, final_folded) = handmade_3_round_chain(ext(100, 200));
        let mut trace = build_trace(initial, &rounds, final_folded, 8).unwrap();
        // Flip row 2's INITIAL_FOLDED[0] → persistence transition fails.
        let row2 = 2 * col::WIDTH;
        trace[row2 + col::INITIAL_FOLDED0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_idle_mutation() {
        let (initial, rounds, final_folded) = handmade_3_round_chain(ext(100, 200));
        let mut trace = build_trace(initial, &rounds, final_folded, 8).unwrap();
        // Row 5 is IDLE (3 FOLD rows + 5 IDLE pad). Tamper a data col.
        let row5 = 5 * col::WIDTH;
        trace[row5 + col::SIBLING0] += gl(1);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    // ---- column layout regression ----

    #[test]
    fn column_layout_constants() {
        // If anyone shifts offsets, lock-step update required.
        assert_eq!(col::KIND0, 0);
        assert_eq!(col::KIND_END, 2);
        assert_eq!(col::WIDTH, 21);
        assert_eq!(FOLD_AIR_FRAMING_WIDTH, col::WIDTH);
    }

    // ---- end-to-end: drive the chain from a real FRI proof ----

    /// Reconstruct the fold chain used by query 0 of a real 2/2
    /// Transfer proof and validate our AIR trace against it.
    ///
    /// Reconstructing the initial folded_eval requires the full
    /// α-reduction (A2-3c-iv-b → `compute_reduced_openings_for_query`),
    /// so we run that, then feed it into our fold-chain builder and
    /// check each round produces the value the upstream verifier
    /// would compute — confirmed by comparing the chain's final
    /// folded_eval to `eval_final_poly_horner(final_poly, final_eval_x)`.
    #[test]
    fn fold_chain_matches_fri_verify_on_real_proof() {
        use crate::fiat_shamir::derive_full_challenges;
        use crate::fri_arith::{eval_final_poly_horner, final_eval_x};
        use crate::open_input::compute_reduced_openings_for_query;
        use crate::prover::{MvpConfig, MvpProver};
        use crate::transfer_air::MvpWitness;
        use p3_field::TwoAdicField;
        use p3_uni_stark::Proof;

        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(2, 2, 0xFD4E_0001);
        let (bytes, _) = prover.prove(&w.encode()).unwrap();
        let proof: Proof<MvpConfig> = postcard::from_bytes(&bytes).unwrap();
        let pis = w.public_inputs();
        let ch = derive_full_challenges(&proof, &pis);

        // Query 0's fold chain.
        let q_pos = 0;
        let domain_index = ch.query_indices[q_pos];
        let zeta_next =
            ch.zeta * Goldilocks::two_adic_generator(proof.degree_bits);
        let ro = compute_reduced_openings_for_query(
            &proof,
            ch.zeta,
            zeta_next,
            ch.fri_alpha,
            ch.log_global_max_height,
            q_pos,
            domain_index,
        )
        .expect("ro");
        let initial_folded = ro.value;

        // Build rounds from commit_phase_openings + betas.
        let query = &proof.opening_proof.query_proofs[q_pos];
        let num_rounds = query.commit_phase_openings.len();
        let mut rounds = Vec::with_capacity(num_rounds);
        let mut idx = domain_index;
        let mut log_h = ch.log_global_max_height;
        for (r, step) in query.commit_phase_openings.iter().enumerate() {
            let log_arity = step.log_arity as usize;
            assert_eq!(log_arity, 1);
            assert_eq!(step.sibling_values.len(), 1);
            rounds.push(FoldRound {
                sibling: step.sibling_values[0],
                beta: ch.betas[r],
                domain_index: idx,
                log_height: log_h,
            });
            idx >>= log_arity;
            log_h -= log_arity;
        }

        // Expected final: eval_final_poly at final_eval_x of the
        // residual index.
        let x_final = final_eval_x(idx, ch.log_global_max_height);
        let final_folded = eval_final_poly_horner(&proof.opening_proof.final_poly, x_final);

        let trace_height = (num_rounds + 4).next_power_of_two();
        let trace = build_trace(initial_folded, &rounds, final_folded, trace_height)
            .expect("build fold-chain trace");

        check_all_transitions(&trace, trace_height)
            .expect("real fold chain must check out-of-circuit");
    }
}
