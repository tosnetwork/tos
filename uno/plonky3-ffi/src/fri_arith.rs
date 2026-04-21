//! FRI verifier — pure-arithmetic primitives (no Merkle).
//!
//! Phase A2-3c-ii of the aggregation roadmap (`doc/uno-aggregation-design.md`).
//! Provides the three stand-alone arithmetic operations the FRI verifier
//! executes per query, *without* the MMCS path-verification work (that
//! lands in Phase A2-3c-iii). Each function is implemented from scratch
//! — independent of upstream's `fri::verifier` code path — and paired
//! with a byte-parity test against the same algorithm as called through
//! upstream's public trait methods.
//!
//! # The three primitives
//!
//! 1. **`fold_row_ref(index, log_height, log_arity, beta, evals)`** —
//!    Given a full arity-sized sibling group `evals` at a domain of
//!    size `2^(log_height + log_arity)`, fold it down to a single
//!    parent evaluation at domain size `2^log_height`. The fold is a
//!    Lagrange interpolation at the out-of-coset point `beta`. Matches
//!    `p3_fri::TwoAdicFriFolding::fold_row`.
//!
//! 2. **`eval_final_poly_horner(final_poly, x)`** — Horner-method
//!    evaluation of the final FRI polynomial at `x`. Matches the
//!    inline reverse-iteration loop in upstream
//!    `fri::verifier.rs:314-317`.
//!
//! 3. **`final_eval_x(domain_index, log_global_max_height)`** — Computes
//!    the Goldilocks point `x = g^k` at which `final_poly` is evaluated,
//!    where `k = reverse_bits_len(domain_index, log_global_max_height)`
//!    and `g` is the 2-adic generator of order `2^log_global_max_height`.
//!    Matches upstream `fri::verifier.rs:307-308`.
//!
//! # Why reimplement?
//!
//! The in-circuit FRI-AIR (Phase A2-3c-iv) encodes **exactly these
//! three primitives** as constraint banks:
//!   * fold_row → per-round Lagrange-at-beta over a 2-element coset
//!     (our `log_arity` is always 1 — binary FRI).
//!   * eval_final_poly → a degree-`log_final_poly_len` Horner chain.
//!   * final_eval_x → a bit-reversed power lookup.
//!
//! Having a **self-contained, line-numbered reference** makes the
//! AIR encoding auditable: each circuit constraint maps back to a
//! line of the reference, each reference line maps to a spec bullet.
//! The parity tests prove our reference is byte-faithful to the
//! upstream implementation.
//!
//! # Out of scope (for A2-3c-ii)
//!
//! The FRI query loop also involves:
//!   * Merkle path verification for each commit-phase opening
//!     (Phase A2-3c-iii — reuses the Poseidon2-w8 row-loop pattern
//!     from `transfer_air`).
//!   * `reduced_openings` construction in `open_input` (Lagrange
//!     combinations with the STARK `alpha`, batch-inversed
//!     denominators) — still under design for A2-3c-iv.
//!   * Rolling in reduced openings at intermediate heights during
//!     the fold chain.
//!
//! Those are tracked separately.

use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_util::reverse_bits_len;

use crate::prover::Challenge;

// ---------------------------------------------------------------------------
// Primitive 1: fold_row — Lagrange interpolation at beta over a coset
// ---------------------------------------------------------------------------

/// Fold `arity = 2^log_arity` sibling evaluations at the current
/// domain's child nodes into a single parent evaluation at the folded
/// domain. Matches `p3_fri::TwoAdicFriFolding::fold_row` byte-for-byte
/// (see `third-party/plonky3-uno/fri/src/two_adic_pcs.rs:110-133`).
///
/// Algorithm:
///   1. Locate the coset: the arity-sized group of children sits at
///      `subgroup_start · ω^k` for `k in 0..arity`, where
///      `subgroup_start = g^{reverse_bits(index, log_height)}` and
///      `g = two_adic_generator(log_height + log_arity)`, `ω =
///      two_adic_generator(log_arity)`.
///   2. Bit-reverse the x-coordinate vector so indexing matches the
///      natural evaluation order of the children.
///   3. Lagrange-interpolate `evals` at the extension-field point
///      `beta`. The result is the folded parent's evaluation at
///      `beta^arity` (which lives in the same domain as the next
///      round's codeword).
///
/// # Arguments
///
/// - `index`: the fold-chain's current query index at the PARENT level
///   (i.e. after the `>>= log_arity` shift — same convention upstream
///   uses).
/// - `log_height`: log2 of the parent-domain size.
/// - `log_arity`: the fold factor (1 for binary FRI).
/// - `beta`: the per-round FRI challenge (extension element).
/// - `evals`: the `arity`-sized vector of children evaluations.
pub fn fold_row_ref(
    index: usize,
    log_height: usize,
    log_arity: usize,
    beta: Challenge,
    evals: &[Challenge],
) -> Challenge {
    let arity = 1usize << log_arity;
    assert_eq!(
        evals.len(),
        arity,
        "fold_row_ref: expected {} evaluations, got {}",
        arity,
        evals.len()
    );

    // Coset start: g^{reverse_bits(index, log_height)} where g is the
    // 2-adic generator of order 2^{log_height + log_arity}.
    let g_outer = Goldilocks::two_adic_generator(log_height + log_arity);
    let subgroup_start = g_outer.exp_u64(reverse_bits_len(index, log_height) as u64);

    // x-coordinates of the arity children: subgroup_start · ω^k for
    // k in 0..arity, bit-reversed.
    let omega = Goldilocks::two_adic_generator(log_arity);
    let mut xs: Vec<Goldilocks> = Vec::with_capacity(arity);
    let mut acc = subgroup_start;
    for _ in 0..arity {
        xs.push(acc);
        acc *= omega;
    }
    reverse_slice_index_bits(&mut xs);

    // Lagrange interpolate `evals` at `beta`.
    lagrange_interpolate_at_ref(&xs, evals, beta)
}

/// Reverse the first `log2(len)` bits of each index in the slice,
/// swapping `slice[i]` with `slice[reverse_bits(i, log2(len))]`. Matches
/// `p3_util::reverse_slice_index_bits`.
fn reverse_slice_index_bits<T: Copy>(slice: &mut [T]) {
    let n = slice.len();
    if n <= 1 {
        return;
    }
    let log_n = n.trailing_zeros() as usize;
    assert_eq!(
        1usize << log_n,
        n,
        "reverse_slice_index_bits: length must be a power of two, got {n}"
    );
    for i in 0..n {
        let j = reverse_bits_len(i, log_n);
        if i < j {
            slice.swap(i, j);
        }
    }
}

/// Barycentric Lagrange interpolation at `z`. `xs` are the interpolation
/// points in the base field (a coset of the `arity`-th roots of unity),
/// `ys` are the values (in the extension), `z` is the evaluation point
/// (extension). Returns `L(z)` where `L` is the unique polynomial of
/// degree `< n` with `L(xs[i]) = ys[i]`.
///
/// Line-matches `third-party/plonky3-uno/fri/src/two_adic_pcs.rs:221-261`.
fn lagrange_interpolate_at_ref(
    xs: &[Goldilocks],
    ys: &[Challenge],
    z: Challenge,
) -> Challenge {
    assert_eq!(xs.len(), ys.len());
    let n = xs.len();
    if n == 0 {
        return Challenge::ZERO;
    }

    // Early return if z happens to coincide with an interpolation point.
    for i in 0..n {
        if (z - xs[i]).is_zero() {
            return ys[i];
        }
    }

    let log_n = n.trailing_zeros() as usize;
    assert_eq!(
        1usize << log_n,
        n,
        "lagrange: len must be a power of 2, got {n}"
    );

    // All xs lie in a coset of the 2^log_n roots of unity; the coset
    // scalar factor is xs[0]^{2^log_n}. The barycentric weight scale is
    // 1 / (n · coset_power).
    let coset_power = xs[0].exp_power_of_2(log_n);
    let weight_scale = (Goldilocks::from_usize(n) * coset_power)
        .try_inverse()
        .expect("n * coset_power must be invertible in Goldilocks");

    // (z - xs[i])^{-1} — batch-invert would be more efficient but this
    // is reference code; each inverse is O(log p) and n is tiny (≤ 2
    // for binary FRI).
    let diffs: Vec<Challenge> = xs.iter().map(|&x| z - x).collect();
    let diff_invs: Vec<Challenge> = diffs
        .iter()
        .map(|d| d.try_inverse().expect("already early-returned on zero diff"))
        .collect();

    // L(z) = prod_i (z - xs[i])
    let mut l_z = Challenge::ONE;
    for d in &diffs {
        l_z *= *d;
    }

    // Barycentric: sum_i (w_i · ys[i] / (z - xs[i])) where
    //   w_i = 1 / prod_{j != i} (xs[i] - xs[j]) = xs[i] · weight_scale
    let mut result = Challenge::ZERO;
    for ((&x, &y), &dinv) in xs.iter().zip(ys).zip(diff_invs.iter()) {
        let weight: Goldilocks = x * weight_scale;
        result += y * dinv * weight;
    }

    result * l_z
}

// ---------------------------------------------------------------------------
// Primitive 2: eval_final_poly_horner — Horner eval of the final FRI poly
// ---------------------------------------------------------------------------

/// Evaluate the final FRI polynomial (given as a coefficient vector) at
/// the base-field point `x`. Uses Horner's method. Matches the inline
/// loop at `third-party/plonky3-uno/fri/src/verifier.rs:314-317`.
///
/// The `final_poly` vector is in **coefficient order**: `final_poly[0]`
/// is the constant term, `final_poly[n-1]` is the highest-degree
/// coefficient. The Horner loop iterates from highest to lowest,
/// accumulating `eval = eval * x + coeff`.
pub fn eval_final_poly_horner(final_poly: &[Challenge], x: Goldilocks) -> Challenge {
    let mut eval = Challenge::ZERO;
    for &coeff in final_poly.iter().rev() {
        eval = eval * x + coeff;
    }
    eval
}

// ---------------------------------------------------------------------------
// Primitive 3: final_eval_x — the base-field point at which final_poly
//              is evaluated for a given query
// ---------------------------------------------------------------------------

/// Compute `x = g^{reverse_bits(domain_index, log_global_max_height)}`
/// where `g` is the 2-adic generator of order `2^log_global_max_height`.
/// This is the base-field point at which the final FRI polynomial is
/// evaluated to check consistency with the folded value. Matches
/// `third-party/plonky3-uno/fri/src/verifier.rs:307-308`.
///
/// Note: `domain_index` here is the RESIDUAL query index after all
/// `log_arity` right-shifts across the commit-phase loop. It is *not*
/// the original sampled query index.
pub fn final_eval_x(domain_index: usize, log_global_max_height: usize) -> Goldilocks {
    let g = Goldilocks::two_adic_generator(log_global_max_height);
    g.exp_u64(reverse_bits_len(domain_index, log_global_max_height) as u64)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};

    fn ch(a: u64, b: u64) -> Challenge {
        use p3_field::BasedVectorSpace;
        Challenge::from_basis_coefficients_fn(|i| if i == 0 { Goldilocks::new(a) } else { Goldilocks::new(b) })
    }

    /// Upstream reference folder used for parity tests. The `InputProof`
    /// and `InputError` generics are irrelevant for `fold_row` (it only
    /// touches the arithmetic), so we plug `()` for both.
    fn upstream_folder() -> TwoAdicFriFolding<(), ()> {
        TwoAdicFriFolding(core::marker::PhantomData)
    }

    /// Thin wrapper that fixes the generic parameters `F = Goldilocks,
    /// EF = Challenge` so callers don't need the fully-qualified syntax
    /// at every test site. Forwards directly to upstream.
    fn upstream_fold_row(
        index: usize,
        log_height: usize,
        log_arity: usize,
        beta: Challenge,
        evals: &[Challenge],
    ) -> Challenge {
        <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<Goldilocks, Challenge>>::fold_row(
            &upstream_folder(),
            index,
            log_height,
            log_arity,
            beta,
            evals.iter().copied(),
        )
    }

    // ---- fold_row parity tests ----

    #[test]
    fn fold_row_matches_upstream_arity_2_basic() {
        let beta = ch(0x1111_2222_3333_4444, 0x5555_6666_7777_8888);
        let evals = vec![ch(7, 11), ch(13, 17)];
        let index = 3;
        let log_height = 5;
        let log_arity = 1;

        let ours = fold_row_ref(index, log_height, log_arity, beta, &evals);
        let theirs = upstream_fold_row(index, log_height, log_arity, beta, &evals);
        assert_eq!(ours, theirs, "fold_row disagreement at arity-2");
    }

    #[test]
    fn fold_row_matches_upstream_multiple_indices() {
        // Sweep indices at a few (log_height, beta) combinations.
        let log_arity = 1;
        for log_height in [3usize, 7, 12, 15] {
            let beta = ch(0xDEAD_BEEF + log_height as u64, 0xCAFE_BABE);
            let evals = vec![
                ch(0xAAAA_0001 + log_height as u64, 0xBBBB_0002),
                ch(0xCCCC_0003, 0xDDDD_0004 + log_height as u64),
            ];
            for &index in &[0usize, 1, (1 << log_height) - 1, 1 << (log_height - 1)] {
                let ours = fold_row_ref(index, log_height, log_arity, beta, &evals);
                let theirs = upstream_fold_row(index, log_height, log_arity, beta, &evals);
                assert_eq!(
                    ours, theirs,
                    "fold_row disagreement at log_height={log_height}, index={index}",
                );
            }
        }
    }

    #[test]
    fn fold_row_matches_upstream_randomized() {
        // 64 pseudo-random (index, evals, beta) triples at log_height=10
        // — enough to catch any off-by-one bit-reversal bug.
        let log_height = 10;
        let log_arity = 1;
        let mut state: u64 = 0xC0DE_C0DE_0000_0001;
        let mut rand_u64 = || {
            // xorshift64*; deterministic, reproducible.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..64 {
            let index = (rand_u64() as usize) & ((1 << log_height) - 1);
            let beta = ch(rand_u64(), rand_u64());
            let evals = vec![ch(rand_u64(), rand_u64()), ch(rand_u64(), rand_u64())];
            let ours = fold_row_ref(index, log_height, log_arity, beta, &evals);
            let theirs = upstream_fold_row(index, log_height, log_arity, beta, &evals);
            assert_eq!(ours, theirs, "random fold_row disagreement at index={index}");
        }
    }

    #[test]
    fn fold_row_arity_4_matches_upstream() {
        // While our production config uses binary FRI (log_arity=1),
        // fold_row_ref must remain correct for higher arities in case
        // we ever raise `max_log_arity`. Matches upstream exactly here
        // too — any bit-reversal bug would surface.
        let log_arity = 2;
        let log_height = 6;
        let beta = ch(0xA1, 0xB2);
        let evals = vec![ch(1, 2), ch(3, 4), ch(5, 6), ch(7, 8)];
        for index in 0..(1 << log_height) {
            let ours = fold_row_ref(index, log_height, log_arity, beta, &evals);
            let theirs = upstream_fold_row(index, log_height, log_arity, beta, &evals);
            assert_eq!(ours, theirs, "arity-4 disagreement at index={index}");
        }
    }

    // ---- eval_final_poly_horner tests ----

    #[test]
    fn eval_final_poly_matches_direct_sum_small() {
        // f(x) = 5 + 7x + 11x^2 + 13x^3
        let coeffs = vec![ch(5, 0), ch(7, 0), ch(11, 0), ch(13, 0)];
        let x = Goldilocks::new(42);

        let ours = eval_final_poly_horner(&coeffs, x);

        // Direct sum: Σ c_i · x^i
        use p3_field::PrimeCharacteristicRing as _;
        let mut expected = Challenge::ZERO;
        let mut xp = Goldilocks::ONE;
        for c in &coeffs {
            expected += *c * xp;
            xp *= x;
        }
        assert_eq!(ours, expected);
    }

    #[test]
    fn eval_final_poly_matches_upstream_inline() {
        // Reproduce the inline loop from upstream verifier.rs:314-317
        // and compare to our function.
        let coeffs = vec![ch(3, 5), ch(7, 11), ch(13, 17), ch(19, 23)];
        let x = Goldilocks::new(0xABCDE);
        let ours = eval_final_poly_horner(&coeffs, x);

        let mut theirs = Challenge::ZERO;
        for &c in coeffs.iter().rev() {
            theirs = theirs * x + c;
        }
        assert_eq!(ours, theirs);
    }

    #[test]
    fn eval_final_poly_empty_is_zero() {
        let x = Goldilocks::new(7);
        assert_eq!(eval_final_poly_horner(&[], x), Challenge::ZERO);
    }

    #[test]
    fn eval_final_poly_single_coef_is_constant() {
        // Horner over a 1-element poly must return that element regardless of x.
        let coeffs = vec![ch(123, 456)];
        for x in [Goldilocks::new(1), Goldilocks::new(2), Goldilocks::new(999_999)] {
            assert_eq!(eval_final_poly_horner(&coeffs, x), coeffs[0]);
        }
    }

    // ---- final_eval_x tests ----

    #[test]
    fn final_eval_x_matches_upstream_formula() {
        // Compute x both via our helper and via the raw upstream formula
        // (verifier.rs:307-308). Must match on many (index, log_size)
        // combinations.
        for log_global in [3usize, 5, 10, 16] {
            let g = Goldilocks::two_adic_generator(log_global);
            for index in [0usize, 1, 2, 7, (1 << log_global) - 1, 1 << (log_global - 1)] {
                let ours = final_eval_x(index, log_global);
                let theirs = g.exp_u64(reverse_bits_len(index, log_global) as u64);
                assert_eq!(
                    ours, theirs,
                    "final_eval_x disagrees at log_global={log_global}, index={index}",
                );
            }
        }
    }

    #[test]
    fn final_eval_x_zero_index_is_one() {
        // reverse_bits(0, *) == 0 ⇒ g^0 == 1 in any 2-adic subgroup.
        for log_global in [1usize, 4, 10, 20] {
            assert_eq!(final_eval_x(0, log_global), Goldilocks::ONE);
        }
    }

    // ---- structural regression ----

    #[test]
    fn reverse_slice_index_bits_matches_p3_util() {
        use p3_util::reverse_slice_index_bits as upstream_reverse;
        for log_n in [0usize, 1, 2, 3, 5, 8] {
            let n = 1usize << log_n;
            let mut ours: Vec<u32> = (0..n as u32).collect();
            let mut theirs = ours.clone();
            reverse_slice_index_bits(&mut ours);
            upstream_reverse(&mut theirs);
            assert_eq!(ours, theirs, "reverse_slice_index_bits disagrees at n={n}");
        }
    }
}
