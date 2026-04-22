//! Reference prover for the Uno Transfer AIR (P.2 scale-to-envelope).
//!
//! Uses the production, consensus-binding FRI parameters pinned in §2.1
//! of doc/uno-workchain.md (`log_blowup=2, num_queries=128, pow_bits=16`).
//! Both the prover and the validator verifier build their `StarkConfig`
//! via `build_config()` below, so they stay byte-identical by
//! construction; diverging FRI params on either side would cause every
//! validator to reject every proof.
//!
//! Consumed by:
//! - the `uno_plonky3_prove` FFI entry point;
//! - Rust-side integration tests.
//!
//! NOT consumed by:
//! - the validator compute phase (which only ever calls the verifier);
//! - any consensus-critical path.

use std::sync::Arc;

use p3_batch_stark::{prove_batch, ProverData, StarkInstance};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, StarkConfig};

use crate::transfer_air::{MvpTransferAir, MvpWitness};
use crate::Plonky3Status;

// ---------------------------------------------------------------------------
// Type aliases pinning our concrete config.
// ---------------------------------------------------------------------------

pub(crate) type Val = Goldilocks;
pub(crate) type Challenge = BinomialExtensionField<Val, 2>;

pub(crate) type Perm8 = Poseidon2Goldilocks<8>;

pub(crate) type MvpHash = PaddingFreeSponge<Perm8, 8, 4, 4>;
pub(crate) type MvpCompress = TruncatedPermutation<Perm8, 2, 4, 8>;

pub(crate) type MvpValMmcs = MerkleTreeMmcs<
    <Val as p3_field::Field>::Packing,
    <Val as p3_field::Field>::Packing,
    MvpHash,
    MvpCompress,
    2,
    4,
>;

pub(crate) type MvpChallengeMmcs = ExtensionMmcs<Val, Challenge, MvpValMmcs>;
pub(crate) type MvpChallenger = DuplexChallenger<Val, Perm8, 8, 4>;
pub(crate) type MvpDft = Radix2DitParallel<Val>;
pub(crate) type MvpPcs = TwoAdicFriPcs<Val, MvpDft, MvpValMmcs, MvpChallengeMmcs>;
pub(crate) type MvpConfig = StarkConfig<MvpPcs, Challenge, MvpChallenger>;

// ---------------------------------------------------------------------------
// Config builder
// ---------------------------------------------------------------------------

/// Build the canonical Transfer `StarkConfig`.
///
/// FRI parameters are the §2.1 (doc/uno-workchain.md) consensus-binding
/// production triple ("Option B", pinned 2026-04-20 per the
/// K-fri-analysis parameter sweep at `doc/uno-fri-param-analysis.md`):
///
/// ```text
/// log_blowup               = 3     // trace domain = 8× trace length
/// num_queries              = 52    // FRI verifier query rounds
/// query_proof_of_work_bits = 24    // Fiat-Shamir grinding bits per query
/// commit_proof_of_work_bits= 0     // not used; commit grinding disabled
/// ```
///
/// Target: **180-bit conjectured / 102-bit proven classical** soundness
/// (ethSTARK model). Design bar is 128-bit conjectured classical; the
/// pin sits 40 % above that. Quantum: 90 / 51 bits (Grover).
///
/// Amendment history: the original v1 pin was (2, 128, 16) giving
/// 272 conjectured / 144 proven bits — more than 2× the design goal,
/// wasting ~57 % proof bytes on no realistic-adversary security gain.
/// Option B is the same soundness tier (180 bits, still >40 % above
/// the 128-bit design target) at the best proof-size / verify-time
/// point on the frontier. See §16 decision #33 (amended) for the full
/// rationale + rejected alternatives.
///
/// Expected measured impact vs the original pin (from K-fri-analysis on
/// 4/4 worst case):
///   proof: 2,290,134 B → 984,019 B  (−57 %)
///   verify: 55.7 ms     → 24.7 ms   (−56 %)
///   prove:  124 ms      → 354 ms    (+185 %, acceptable — client-side)
///
/// Field-name mapping from §2.1 to the Plonky3 `FriParameters` struct
/// (third-party/plonky3-uno/fri/src/config.rs): the spec's `pow_bits`
/// binds to `query_proof_of_work_bits` (the grinding phase before query
/// sampling, counted in `conjectured_soundness_bits = log_blowup·num_queries
/// + query_proof_of_work_bits = 3·52 + 24 = 180`).
/// `commit_proof_of_work_bits` is an orthogonal per-batching-challenge
/// grind that the Plonky3 `new_benchmark*` presets leave at 0; we match.
/// `log_final_poly_len = 0` and `max_log_arity = 1` also match the
/// benchmark presets (final polynomial of size 1, binary FRI folding).
///
/// The validator verifier builds `StarkConfig` via this same function
/// (see verifier.rs::MvpVerifier::new), so prover and verifier cannot
/// drift on FRI params.
pub(crate) fn build_config() -> MvpConfig {
    let perm: Perm8 = default_goldilocks_poseidon2_8();
    let hash = MvpHash::new(perm.clone());
    let compress = MvpCompress::new(perm.clone());
    let val_mmcs = MvpValMmcs::new(hash, compress, 0);
    let challenge_mmcs = MvpChallengeMmcs::new(val_mmcs.clone());
    let dft = MvpDft::default();
    let fri_params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 52,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 24,
        mmcs: challenge_mmcs,
    };
    let pcs = MvpPcs::new(dft, val_mmcs, fri_params);
    let challenger = MvpChallenger::new(perm);
    MvpConfig::new(pcs, challenger)
}

// ---------------------------------------------------------------------------
// Prover handle
// ---------------------------------------------------------------------------

/// Reference prover. The AIR shape is selected per-prove-call from the
/// decoded witness, so a single prover handle serves all 16 legal shapes.
pub struct MvpProver {
    config: MvpConfig,
}

impl Default for MvpProver {
    fn default() -> Self {
        Self::new()
    }
}

impl MvpProver {
    /// Build a prover with the canonical config.
    pub fn new() -> Self {
        Self {
            config: build_config(),
        }
    }

    /// Prove a witness. Returns `(proof_bytes, public_inputs_bytes)`.
    pub fn prove(&self, witness_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Plonky3Status> {
        let witness = MvpWitness::decode(witness_bytes)?;
        self.pre_check_witness(&witness)?;

        let (n_s, n_o) = witness.shape();
        let air = MvpTransferAir::new(n_s, n_o);
        let trace = witness.generate_trace();
        let public_inputs = witness.public_inputs();

        let proof = prove(&self.config, &air, trace, &public_inputs);
        let proof_bytes =
            postcard::to_allocvec(&proof).map_err(|_| Plonky3Status::InternalError)?;
        let pi_bytes = witness.public_inputs_bytes();
        Ok((proof_bytes, pi_bytes))
    }

    /// Cheap sanity checks mirroring the hardest AIR constraints. Short-
    /// circuits adversarial witnesses with `WitnessInvalid` before Plonky3
    /// sees them, keeping the FFI error code stable across debug/release
    /// profiles and preventing debug-build `DebugConstraintBuilder` panics
    /// on malformed witnesses.
    ///
    /// The witness is inconsistent iff any of the following is true:
    ///   (a) `fee` or any proxy is non-canonical mod Goldilocks.
    ///   (b) Claim 8 balance: `Σ spend.value ≠ Σ output.value + fee`.
    ///   (c) Claim 2 leaf derivation: for any spend,
    ///       `leaf_i ≠ Poseidon2("uno-cm-v1", d_i, pk_d_i, ivk_commitment_i,
    ///                            value_i, rcm_i)`.
    ///   (d) Claim 1 anchor consistency: for any spend,
    ///       `Poseidon2(leaf_i, sibling_i) ≠ anchor_proxy`.
    fn pre_check_witness(&self, w: &MvpWitness) -> Result<(), Plonky3Status> {
        pre_check_transfer_witness(w)
    }
}

/// Batch-STARK feasibility prover for Path (iii).
///
/// This uses the same Transfer AIR, same witness format, same public-input
/// schema, and same §2.1 Option B FRI config as [`MvpProver`], but proves it
/// through `p3_batch_stark::prove_batch` as a single-instance batch with no
/// LogUp lookups yet. It intentionally runs beside the shipped uni-stark
/// prover until the wider proof-format migration is ready.
pub struct MvpBatchProver {
    config: MvpConfig,
}

impl Default for MvpBatchProver {
    fn default() -> Self {
        Self::new()
    }
}

impl MvpBatchProver {
    /// Build a batch-stark prover with the canonical Option B config.
    pub fn new() -> Self {
        Self {
            config: build_config(),
        }
    }

    /// Prove a witness through `p3_batch_stark`.
    ///
    /// Returns `(batch_proof_bytes, public_inputs_bytes)`. The proof bytes
    /// are postcard-encoded `p3_batch_stark::BatchProof<MvpConfig>`.
    pub fn prove(&self, witness_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Plonky3Status> {
        let witness = MvpWitness::decode(witness_bytes)?;
        pre_check_transfer_witness(&witness)?;

        let (n_s, n_o) = witness.shape();
        let air = MvpTransferAir::new(n_s, n_o);
        let trace = witness.generate_trace();
        let public_inputs = witness.public_inputs();
        let instances = [StarkInstance {
            air: &air,
            trace: &trace,
            public_values: public_inputs,
            lookups: Vec::new(),
        }];
        let prover_data = ProverData::empty(instances.len());

        let proof = prove_batch(&self.config, &instances, &prover_data);
        let proof_bytes =
            postcard::to_allocvec(&proof).map_err(|_| Plonky3Status::InternalError)?;
        let pi_bytes = witness.public_inputs_bytes();
        Ok((proof_bytes, pi_bytes))
    }
}

fn pre_check_transfer_witness(w: &MvpWitness) -> Result<(), Plonky3Status> {
    use crate::transfer_air::{witness_claim1_anchor_consistent, witness_claim2_leaf_consistent};

    if w.fee >= crate::transfer_air::GOLDILOCKS_P {
        return Err(Plonky3Status::WitnessInvalid);
    }
    if !w.balance_holds() {
        return Err(Plonky3Status::WitnessInvalid);
    }
    if !witness_claim2_leaf_consistent(w) {
        return Err(Plonky3Status::WitnessInvalid);
    }
    if !witness_claim1_anchor_consistent(w) {
        return Err(Plonky3Status::WitnessInvalid);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Thread-safety marker
// ---------------------------------------------------------------------------
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MvpProver>();
    assert_send_sync::<MvpBatchProver>();
    assert_send_sync::<Arc<MvpProver>>();
    assert_send_sync::<Arc<MvpBatchProver>>();
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer_air::{air_public_inputs_wire_len, MvpWitness};

    #[test]
    fn prove_succeeds_on_valid_1_1() {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(1, 1, 0x4242_4242_4242_4242);
        let (proof, pis) = prover.prove(&w.encode()).expect("prove 1/1");
        assert!(!proof.is_empty());
        assert_eq!(pis.len(), air_public_inputs_wire_len(1, 1));
    }

    #[test]
    fn prove_succeeds_on_valid_1_2() {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(1, 2, 0xAAAA_0001);
        let (proof, pis) = prover.prove(&w.encode()).expect("prove 1/2");
        assert!(!proof.is_empty());
        assert_eq!(pis.len(), air_public_inputs_wire_len(1, 2));
    }

    /// M-P2 Phase 3 scaffolding: confirm `p3-lookup` is linkable and the
    /// `Lookup<F>` / `Kind` / `Direction` surface can be constructed against
    /// our field (`Goldilocks`). This test does NOT yet register a real
    /// range-check lookup on the Transfer AIR — that's Phase 3b (which
    /// replaces the per-value bit-decomposition columns with a shared
    /// 16-bit preprocessed range table + u16-limb trace columns).
    ///
    /// Purpose: pin the `p3-lookup` dep into the build graph so subsequent
    /// commits can focus on AIR-layout changes without re-discovering the
    /// correct types / trait bounds. If this test stops compiling, the
    /// vendored `third-party/plonky3-uno/lookup` API drifted and Phase 3b
    /// has to re-align.
    #[test]
    fn lookup_types_linkable_for_phase3b() {
        use p3_field::PrimeCharacteristicRing;
        use p3_lookup::{Direction, Kind, Lookup};

        // Shape of an eventual 64-bit range lookup: element tuple = (limb,),
        // multiplicity = 1, direction = Receive (consume from the shared
        // 16-bit table). Actual tuple construction happens during AIR
        // `register_lookup` when we have `SymbolicExpression` handles on
        // the u16-limb trace columns.
        let _direction = Direction::Receive;
        let _kind_local: Kind = Kind::Local;

        // An empty `Lookup<Goldilocks>` can be round-tripped through
        // `Lookup::new` — proves the const constructor is visible.
        let empty: Lookup<Goldilocks> = Lookup::new(Kind::Local, vec![], vec![], vec![]);
        assert_eq!(empty.element_exprs.len(), 0);
        assert_eq!(empty.multiplicities_exprs.len(), 0);
        assert_eq!(empty.columns.len(), 0);

        // Sanity: batch-stark's `StarkInstance` accepts an empty
        // `Vec<Lookup<Val<SC>>>` today (Phase 0 / 1 already exercised
        // this). This assertion simply documents the type equivalence
        // so Phase 3b can extend from a known-good baseline.
        let _mult_one = Goldilocks::ONE;
    }

    #[test]
    fn batch_prove_succeeds_on_valid_1_2() {
        let prover = MvpBatchProver::new();
        let w = MvpWitness::deterministic_valid(1, 2, 0xBABA_0001);
        let (proof, pis) = prover.prove(&w.encode()).expect("batch prove 1/2");
        assert!(!proof.is_empty());
        assert_eq!(pis.len(), air_public_inputs_wire_len(1, 2));
    }

    /// M-P2 Phase 1: sweep the full 1..4 × 1..4 envelope through the
    /// batch-stark prover + verifier round-trip.
    ///
    /// The batch path uses the SAME AIR / witness / public-input schema
    /// as the uni-stark path, so every shape that the uni-stark prover
    /// accepts must also succeed through batch-stark. Public-input byte
    /// lengths are also asserted — they come from the same
    /// `MvpWitness::public_inputs_bytes()` function for both provers and
    /// must be shape-identical (`air_public_inputs_wire_len(n_s, n_o)`).
    ///
    /// This is the Phase 1 feasibility gate: if any shape fails here,
    /// subsequent phases (Poseidon2Air swap, LogUp lookups, real 4-limb
    /// field material) are blocked.
    #[test]
    fn batch_prove_verify_round_trip_all_shapes() {
        use crate::verifier::MvpBatchVerifier;

        let prover = MvpBatchProver::new();
        let verifier = MvpBatchVerifier::new();

        for n_s in 1..=4 {
            for n_o in 1..=4 {
                let seed = 0xBA7C_0000_u64 | ((n_s as u64) << 4) | (n_o as u64);
                let w = MvpWitness::deterministic_valid(n_s, n_o, seed);
                let (proof, pis) = prover
                    .prove(&w.encode())
                    .unwrap_or_else(|e| panic!("batch prove {n_s}/{n_o} failed: {e:?}"));
                assert!(!proof.is_empty(), "{n_s}/{n_o}: empty proof");
                assert_eq!(
                    pis.len(),
                    air_public_inputs_wire_len(n_s, n_o),
                    "{n_s}/{n_o}: PI byte length mismatch"
                );

                // Round-trip through the batch verifier.
                let status = verifier.verify(&proof, &pis);
                assert_eq!(
                    status,
                    Plonky3Status::Ok,
                    "{n_s}/{n_o}: batch verify did not return Ok: {status:?}"
                );
            }
        }
    }

    /// M-P2 Phase 1: per-shape public-input byte-length parity between
    /// the uni-stark prover path and the batch-stark prover path.
    ///
    /// PI bytes are derived from the witness via the same
    /// `public_inputs_bytes()` function regardless of prover choice, so
    /// the two paths must agree slot-for-slot on length. (Proof bytes
    /// differ by format; we do NOT assert proof-byte equality — the
    /// uni-stark `Proof` struct and the batch-stark `BatchProof` struct
    /// have different postcard schemas by design.)
    #[test]
    fn batch_and_uni_stark_pi_shape_parity() {
        let uni_prover = MvpProver::new();
        let batch_prover = MvpBatchProver::new();

        for n_s in 1..=4 {
            for n_o in 1..=4 {
                let seed = 0xBA22_0000_u64 | ((n_s as u64) << 4) | (n_o as u64);
                let w = MvpWitness::deterministic_valid(n_s, n_o, seed);
                let wire = w.encode();

                let (_uni_proof, uni_pis) = uni_prover
                    .prove(&wire)
                    .unwrap_or_else(|e| panic!("uni prove {n_s}/{n_o}: {e:?}"));
                let (_batch_proof, batch_pis) = batch_prover
                    .prove(&wire)
                    .unwrap_or_else(|e| panic!("batch prove {n_s}/{n_o}: {e:?}"));

                assert_eq!(
                    uni_pis, batch_pis,
                    "{n_s}/{n_o}: uni-stark PI bytes and batch-stark PI bytes diverged — the \
                     shared `MvpWitness::public_inputs_bytes()` source was somehow reached \
                     through different code paths"
                );
            }
        }
    }

    #[test]
    fn prove_succeeds_on_valid_2_2() {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(2, 2, 0xBBBB_0002);
        let (proof, pis) = prover.prove(&w.encode()).expect("prove 2/2");
        assert!(!proof.is_empty());
        assert_eq!(pis.len(), air_public_inputs_wire_len(2, 2));
    }

    #[test]
    fn prove_succeeds_on_valid_4_4_worst_case() {
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(4, 4, 0xCCCC_0004);
        let (proof, pis) = prover.prove(&w.encode()).expect("prove 4/4");
        assert!(!proof.is_empty());
        assert_eq!(pis.len(), air_public_inputs_wire_len(4, 4));
    }

    #[test]
    fn prove_rejects_malformed_witness() {
        let prover = MvpProver::new();
        let short = vec![0u8; 5];
        let err = prover.prove(&short).unwrap_err();
        assert_eq!(err, Plonky3Status::WitnessInvalid);
    }

    /// Inflation attempt: bump an output value so `output_sum > spend_sum + fee`.
    /// Must reject with `WitnessInvalid` (balance pre-check).
    #[test]
    fn prove_rejects_inflation_attempt() {
        let prover = MvpProver::new();
        let mut w = MvpWitness::deterministic_valid(2, 2, 0x1234);
        w.outputs[0].value = w.outputs[0].value.saturating_add(1);
        let err = prover.prove(&w.encode()).unwrap_err();
        assert_eq!(err, Plonky3Status::WitnessInvalid);
    }

    /// Under-claim output: also breaks balance. Must reject.
    #[test]
    fn prove_rejects_under_claim() {
        let prover = MvpProver::new();
        let mut w = MvpWitness::deterministic_valid(2, 2, 0x2345);
        w.outputs[0].value = w.outputs[0].value.saturating_sub(1);
        let err = prover.prove(&w.encode()).unwrap_err();
        assert_eq!(err, Plonky3Status::WitnessInvalid);
    }

    /// Record proof / witness / public-input byte sizes at (4, 4).
    /// Not a consensus-binding assertion — just a visible regression floor.
    #[test]
    fn sizes_at_4_4_worst_case_recorded() {
        use crate::transfer_air::MERKLE_DEPTH;
        let prover = MvpProver::new();
        let w = MvpWitness::deterministic_valid(4, 4, 0x1111_2222_3333_4444);
        let witness_wire = w.encode();
        let (proof, pi) = prover.prove(&witness_wire).expect("prove 4/4");
        println!(
            "[sizes 4/4] witness={}B proof={}B public_inputs={}B air_cols={}",
            witness_wire.len(),
            proof.len(),
            pi.len(),
            crate::transfer_air::air_width(4, 4),
        );
        // V1-3c-round-8 档1 extended wire layout:
        //   HEAD(10) + PER_SPEND(64 + 8·MERKLE_DEPTH + 32)·n_s
        //           + PER_OUTPUT(40 + 32 + 32 + 2)·n_o
        //           + TAIL(8 + 32 + 1 + 4 + 8)
        let per_spend = 64 + 8 * MERKLE_DEPTH + 32;
        let per_output = 40 + 32 + 32 + 2;
        let head = 10;
        let tail = 8 + 32 + 1 + 4 + 8;
        assert_eq!(
            witness_wire.len(),
            head + per_spend * 4 + per_output * 4 + tail
        );
        assert_eq!(pi.len(), 608);
    }
}
