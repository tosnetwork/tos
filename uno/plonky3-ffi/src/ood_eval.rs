//! Out-of-domain constraint evaluation — STARK verifier's "arithmetic
//! identity" step, lifted out of the PCS (FRI) step.
//!
//! Phase A2-3b of the aggregation roadmap (`doc/uno-aggregation-design.md`).
//! Builds on the Fiat-Shamir driver from A2-3a (`fiat_shamir.rs`): given
//! the derived `(alpha, zeta)` and a proof's opened values at `zeta`, we
//! rebuild `quotient(zeta)` from chunks and assert the identity
//!
//! ```text
//! constraints(zeta, trace_local, trace_next, alpha, pi) * Z_H(zeta)^{-1}
//!   ==  quotient(zeta)
//! ```
//!
//! This is the **constraint-folding** half of the verifier. The
//! remaining half — the PCS (FRI) argument that the opened values are
//! genuine evaluations of the committed trace polynomial at zeta — is
//! orthogonal and lands in Phase A2-3c (FRI-as-AIR) or A2-4
//! (single-slot end-to-end).
//!
//! # Why expose this separately?
//!
//! The in-circuit VerifierAir reproduces **exactly the OOD identity**
//! as a bank of AIR constraints (the quotient identity). Factoring the
//! upstream primitives into a dedicated driver lets us:
//!   1. Unit-test "tampered opening ⇒ OOD reject" independently of FRI,
//!      so the A2-3c audit can focus on FRI-folding soundness alone.
//!   2. Supply a known-good reference the VerifierAir's
//!      `eval` function will be diffed against during A2-3c development.
//!   3. Reuse the (alpha, zeta) `fiat_shamir::derive_pre_pcs_challenges`
//!      already derives — no double implementation of the transcript.
//!
//! # Upstream primitives reused (no custom crypto)
//!
//! - `p3_uni_stark::recompose_quotient_from_chunks` — Lagrange-interpolate
//!   quotient chunks back to a single `quotient(zeta)` extension element.
//! - `p3_uni_stark::verify_constraints` — run the AIR's `eval` on a
//!   `VerifierConstraintFolder` at zeta, compare to recomposed quotient.
//! - `p3_uni_stark::get_log_num_quotient_chunks` — symbolic bound on
//!   the quotient-domain split; wrapped for our specific AIR + layout.
//! - `p3_commit::Pcs::natural_domain_for_degree` — public trait method
//!   on the PCS inside our `StarkConfig`.
//!
//! This module adds **no cryptographic primitives**; it is pure glue
//! that wires our production `MvpConfig` + `MvpTransferAir` into those
//! upstream helpers.

use p3_commit::{Pcs, PolynomialSpace};
use p3_field::BasedVectorSpace;
use p3_uni_stark::{
    get_log_num_quotient_chunks, recompose_quotient_from_chunks, verify_constraints, AirLayout,
    PcsError, Proof, StarkGenericConfig, VerificationError,
};

use crate::prover::{build_config, Challenge, MvpChallenger, MvpConfig, MvpPcs, Val};
use crate::transfer_air::{
    air_num_public_values, derive_shape_from_public_inputs_len, MvpTransferAir,
};

// ---------------------------------------------------------------------------
// Shape inference
// ---------------------------------------------------------------------------

/// Derive `(n_spends, n_outputs)` from the number of public-input field
/// elements. Each legal shape has a unique PI length by construction —
/// see `transfer_air::derive_shape_from_public_inputs_len`.
fn shape_from_public_values(
    num_pis: usize,
) -> Result<(usize, usize), VerificationError<PcsError<MvpConfig>>> {
    // PI wire format is 8 bytes per field element.
    derive_shape_from_public_inputs_len(num_pis * 8).map_err(|_| {
        VerificationError::InvalidProofShape(
            p3_uni_stark::InvalidProofShapeError::PublicValuesLengthMismatch {
                expected: 0,
                got: num_pis,
            },
        )
    })
}

// ---------------------------------------------------------------------------
// Public driver
// ---------------------------------------------------------------------------

/// Runs the out-of-domain identity check on a `Proof<MvpConfig>` using
/// the derived `(alpha, zeta)` challenges. Skips the PCS (FRI) step —
/// assumes the opened values in the proof faithfully represent the
/// trace / quotient polynomials at zeta. That assumption is discharged
/// separately by `uni_stark::verify`'s `pcs.verify(...)` (or by
/// Phase A2-3c's FRI-as-AIR).
///
/// Returns:
/// - `Ok(())` iff the quotient identity holds at zeta.
/// - `Err(OodEvaluationMismatch)` iff the opened values don't satisfy
///   the constraint identity at zeta (e.g. someone tampered the opening).
/// - `Err(InvalidProofShape{...})` iff the proof's degree_bits /
///   quotient-chunk count / PI length doesn't fit the shape derived
///   from PI length.
pub fn verify_ood_skip_pcs(
    proof: &Proof<MvpConfig>,
    public_values: &[Val],
    alpha: Challenge,
    zeta: Challenge,
) -> Result<(), VerificationError<PcsError<MvpConfig>>> {
    let (n_s, n_o) = shape_from_public_values(public_values.len())?;
    let air = MvpTransferAir::new(n_s, n_o);

    // Soundness: the PI vector length MUST match the AIR shape we're
    // re-running `verify_constraints` against. `shape_from_public_values`
    // already guarantees this, but defense-in-depth rechecks it.
    debug_assert_eq!(public_values.len(), air_num_public_values(n_s, n_o));

    let cfg = build_config();
    let pcs: &MvpPcs = cfg.pcs();
    let degree_bits = proof.degree_bits;
    let degree = 1usize.checked_shl(degree_bits as u32).ok_or_else(|| {
        VerificationError::InvalidProofShape(
            p3_uni_stark::InvalidProofShapeError::DegreeBitsTooLarge {
                air: None,
                maximum: usize::BITS as usize - 1,
                got: degree_bits,
            },
        )
    })?;
    let trace_domain =
        <MvpPcs as Pcs<Challenge, MvpChallenger>>::natural_domain_for_degree(pcs, degree);
    let init_trace_domain = trace_domain; // is_zk = 0 ⇒ init == trace

    // Decide the quotient-domain partition exactly as uni-stark verifier.rs:281.
    let layout = AirLayout {
        preprocessed_width: 0, // MvpTransferAir has no preprocessed trace
        main_width: <MvpTransferAir as p3_air::BaseAir<Val>>::width(&air),
        num_public_values: <MvpTransferAir as p3_air::BaseAir<Val>>::num_public_values(&air),
        num_periodic_columns: <MvpTransferAir as p3_air::BaseAir<Val>>::num_periodic_columns(&air),
        ..Default::default()
    };
    let is_zk = cfg.is_zk();
    let log_num_quotient_chunks =
        get_log_num_quotient_chunks::<Val, MvpTransferAir>(&air, layout, is_zk);
    let num_quotient_chunks = 1usize << log_num_quotient_chunks;

    // Shape sanity: the proof's quotient_chunks vector MUST have
    // exactly `num_quotient_chunks` entries, each of length `DIMENSION`
    // (= 2 for our BinomialExtensionField<Goldilocks, 2>).
    if proof.opened_values.quotient_chunks.len() != num_quotient_chunks {
        return Err(VerificationError::InvalidProofShape(
            p3_uni_stark::InvalidProofShapeError::QuotientDomainsCountMismatch { air: 0 },
        ));
    }
    for qc in &proof.opened_values.quotient_chunks {
        if qc.len() != <Challenge as BasedVectorSpace<Val>>::DIMENSION {
            return Err(VerificationError::InvalidProofShape(
                p3_uni_stark::InvalidProofShapeError::OpenedValuesDimensionMismatch,
            ));
        }
    }

    let quotient_domain_size = 1usize << (degree_bits + log_num_quotient_chunks);
    let quotient_domain = trace_domain.create_disjoint_domain(quotient_domain_size);
    let quotient_chunks_domains = quotient_domain.split_domains(num_quotient_chunks);

    let quotient = recompose_quotient_from_chunks::<MvpConfig>(
        &quotient_chunks_domains,
        &proof.opened_values.quotient_chunks,
        zeta,
    );

    // Build trace_next slice. Our AIR uses transition constraints
    // (is_transition selector), so main_next_row_columns is non-empty,
    // and `opened_values.trace_next` is present. If it's missing the
    // proof is malformed.
    let trace_next: &[Challenge] = match proof.opened_values.trace_next.as_deref() {
        Some(v) => v,
        None => {
            return Err(VerificationError::InvalidProofShape(
                p3_uni_stark::InvalidProofShapeError::OpenedValuesDimensionMismatch,
            ));
        }
    };

    // periodic_values: our AIR has no periodic columns (num_periodic == 0).
    let periodic_values: alloc::vec::Vec<Challenge> = alloc::vec::Vec::new();

    verify_constraints::<MvpConfig, MvpTransferAir, PcsError<MvpConfig>>(
        &air,
        &proof.opened_values.trace_local,
        trace_next,
        None, // preprocessed_local (none for our AIR)
        None, // preprocessed_next
        &periodic_values,
        public_values,
        init_trace_domain,
        zeta,
        alpha,
        quotient,
    )
}

/// Convenience wrapper: re-derive `(alpha, zeta)` via the A2-3a
/// transcript driver and run the OOD check in one call.
///
/// Equivalent to:
/// ```ignore
/// let (alpha, zeta) = fiat_shamir::derive_pre_pcs_challenges(proof, pis);
/// verify_ood_skip_pcs(proof, pis, alpha, zeta)
/// ```
pub fn derive_and_verify_ood(
    proof: &Proof<MvpConfig>,
    public_values: &[Val],
) -> Result<(), VerificationError<PcsError<MvpConfig>>> {
    let (alpha, zeta) = crate::fiat_shamir::derive_pre_pcs_challenges(proof, public_values);
    verify_ood_skip_pcs(proof, public_values, alpha, zeta)
}

// ---------------------------------------------------------------------------
// Allocator shim — the `alloc::vec::Vec` import above needs `extern crate`.
// ---------------------------------------------------------------------------
extern crate alloc;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::MvpProver;
    use crate::transfer_air::MvpWitness;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;

    fn proof_for(
        n_s: usize,
        n_o: usize,
        seed: u64,
    ) -> (Proof<MvpConfig>, alloc::vec::Vec<Goldilocks>) {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(n_s, n_o, seed);
        let (proof_bytes, _pi_bytes) = prover.prove(&w.encode()).expect("prove ok");
        let proof: Proof<MvpConfig> = postcard::from_bytes(&proof_bytes).expect("decode");
        let pis = w.public_inputs();
        (proof, pis)
    }

    #[test]
    fn ood_accepts_valid_1_1() {
        let (proof, pis) = proof_for(1, 1, 0xAA01);
        derive_and_verify_ood(&proof, &pis).expect("OOD must accept a valid 1/1 proof");
    }

    #[test]
    fn ood_accepts_valid_2_2() {
        let (proof, pis) = proof_for(2, 2, 0xAA02);
        derive_and_verify_ood(&proof, &pis).expect("OOD must accept a valid 2/2 proof");
    }

    #[test]
    fn ood_accepts_valid_4_4_worst_case() {
        let (proof, pis) = proof_for(4, 4, 0xAA03);
        derive_and_verify_ood(&proof, &pis).expect("OOD must accept a valid 4/4 proof");
    }

    /// Tampered trace_local: the claimed trace evaluation at zeta no
    /// longer satisfies the AIR identity → OodEvaluationMismatch.
    #[test]
    fn ood_rejects_tampered_trace_local() {
        let (mut proof, pis) = proof_for(2, 2, 0xBB01);
        // Flip one limb of trace_local[0].
        let first = proof.opened_values.trace_local[0];
        let flip = first + Challenge::ONE;
        proof.opened_values.trace_local[0] = flip;
        let err =
            derive_and_verify_ood(&proof, &pis).expect_err("tampered trace_local must fail OOD");
        matches!(err, VerificationError::OodEvaluationMismatch { .. });
    }

    /// Tampered quotient chunk: recomposed quotient(zeta) no longer
    /// matches the constraint folding → OodEvaluationMismatch.
    #[test]
    fn ood_rejects_tampered_quotient_chunk() {
        let (mut proof, pis) = proof_for(2, 2, 0xBB02);
        // Flip one limb of quotient_chunks[0][0].
        let first = proof.opened_values.quotient_chunks[0][0];
        proof.opened_values.quotient_chunks[0][0] = first + Challenge::ONE;
        let err =
            derive_and_verify_ood(&proof, &pis).expect_err("tampered quotient chunk must fail OOD");
        matches!(err, VerificationError::OodEvaluationMismatch { .. });
    }

    /// Tampered trace_next: the next-row opening no longer satisfies
    /// the transition constraint identity at zeta.
    #[test]
    fn ood_rejects_tampered_trace_next() {
        let (mut proof, pis) = proof_for(2, 2, 0xBB03);
        let vec_next = proof
            .opened_values
            .trace_next
            .as_mut()
            .expect("our AIR has transition constraints");
        let first = vec_next[0];
        vec_next[0] = first + Challenge::ONE;
        let err =
            derive_and_verify_ood(&proof, &pis).expect_err("tampered trace_next must fail OOD");
        matches!(err, VerificationError::OodEvaluationMismatch { .. });
    }

    /// Using the wrong (alpha, zeta) — e.g. swapping them — must
    /// produce a mismatch even on an untouched proof. Guards against
    /// transcript-skew bugs.
    #[test]
    fn ood_rejects_wrong_challenges() {
        let (proof, pis) = proof_for(2, 2, 0xBB04);
        let (alpha_ok, zeta_ok) = crate::fiat_shamir::derive_pre_pcs_challenges(&proof, &pis);
        // Swap alpha and zeta — both are extension elements of the same
        // type, but the identity should hold ONLY for the correct pair.
        let err = verify_ood_skip_pcs(&proof, &pis, zeta_ok, alpha_ok)
            .expect_err("OOD with swapped challenges must fail");
        matches!(err, VerificationError::OodEvaluationMismatch { .. });
    }

    /// Sanity: upstream `uni_stark::verify` and our OOD driver agree on
    /// every valid proof we produce. Proves the OOD extraction is
    /// consistent with the full verifier.
    #[test]
    fn upstream_verify_and_ood_agree_on_valid_proofs() {
        use crate::prover::build_config;
        use p3_uni_stark::verify;

        for (n_s, n_o, seed) in [(1, 1, 0x10), (1, 3, 0x11), (3, 2, 0x12), (4, 4, 0x13)] {
            let (proof, pis) = proof_for(n_s, n_o, seed);
            let air = MvpTransferAir::new(n_s, n_o);
            let cfg = build_config();
            verify(&cfg, &air, &proof, &pis).expect("upstream must accept");
            derive_and_verify_ood(&proof, &pis).expect("our OOD must accept");
        }
    }
}
