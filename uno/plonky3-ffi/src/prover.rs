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

use crate::range16_air::{Range16Air, RANGE_TABLE_HEIGHT};
use crate::transfer_air::{MvpTransferAir, MvpWitness, TRACE_HEIGHT, VALUE_LIMBS_U16};
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

// ---------------------------------------------------------------------------
// Heterogeneous AIR dispatch (M-P2 Phase 3b-step3)
// ---------------------------------------------------------------------------
//
// `MvpAirUnion` is the enum wrapper that lets us put both `MvpTransferAir`
// and `Range16Air` into the same `[A]` slice for
// `p3_batch_stark::ProverData::from_airs_and_degrees` + `prove_batch`.
// Matches the vendored `DemoAirWithLookups` pattern in
// `third-party/plonky3-uno/batch-stark/tests/simple.rs`.

use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_lookup::lookup_traits::Lookup;
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

#[derive(Debug, Clone, Copy)]
pub(crate) enum MvpAirUnion {
    Transfer(MvpTransferAir),
    Range16(Range16Air),
}

impl<F: p3_field::PrimeCharacteristicRing + Send + Sync> BaseAir<F> for MvpAirUnion {
    fn width(&self) -> usize {
        match self {
            Self::Transfer(a) => <MvpTransferAir as BaseAir<F>>::width(a),
            Self::Range16(a) => <Range16Air as BaseAir<F>>::width(a),
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::Transfer(a) => <MvpTransferAir as BaseAir<F>>::num_public_values(a),
            Self::Range16(a) => <Range16Air as BaseAir<F>>::num_public_values(a),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Transfer(a) => <MvpTransferAir as BaseAir<F>>::preprocessed_trace(a),
            Self::Range16(a) => <Range16Air as BaseAir<F>>::preprocessed_trace(a),
        }
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Transfer(a) => <MvpTransferAir as BaseAir<F>>::main_next_row_columns(a),
            Self::Range16(a) => <Range16Air as BaseAir<F>>::main_next_row_columns(a),
        }
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Self::Transfer(a) => <MvpTransferAir as BaseAir<F>>::max_constraint_degree(a),
            Self::Range16(a) => <Range16Air as BaseAir<F>>::max_constraint_degree(a),
        }
    }
}

impl<AB> Air<AB> for MvpAirUnion
where
    AB: p3_air::AirBuilder<F = Goldilocks>,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Transfer(a) => <MvpTransferAir as Air<AB>>::eval(a, builder),
            Self::Range16(a) => <Range16Air as Air<AB>>::eval(a, builder),
        }
    }
}

impl<F: Field> LookupAir<F> for MvpAirUnion {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Transfer(a) => LookupAir::<F>::add_lookup_columns(a),
            Self::Range16(a) => LookupAir::<F>::add_lookup_columns(a),
        }
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        match self {
            Self::Transfer(a) => LookupAir::<F>::get_lookups(a),
            Self::Range16(a) => LookupAir::<F>::get_lookups(a),
        }
    }
}

/// Collect all u16 limb values from a witness, each repeated
/// `TRACE_HEIGHT` times (the "proxies are constant across rows"
/// §4.2 invariant means every MvpTransferAir trace row fires the
/// same tuple receive, so the matching Send-side multiplicity must
/// scale by TRACE_HEIGHT for the cross-AIR global sum to cancel).
///
/// Per-row layout (ordered to match the receive-side in
/// `MvpTransferAir::get_lookups`):
///
///   * Phase 3b-step2: 4 u16 limbs per spend `value`
///     + 4 u16 limbs per output `value`
///       (total: 4·(n_s + n_o))
///   * Phase 4b-step3-step1.3-fields: 56 u16 limbs per output
///     (14 fe-limbs × 4 u16) for the d/pk_d/ivk_cm/rcm fe-limb
///     cols — each fe-limb is the canonical u64 of an 8-byte LE
///     chunk of the corresponding 32-byte witness field, split
///     into 4 × u16 LE.
fn collect_u16_reads_for_range16(w: &MvpWitness) -> Vec<u16> {
    use crate::transfer_air::reduce_to_goldilocks;

    let (n_s, n_o) = w.shape();
    let per_row = VALUE_LIMBS_U16 * (n_s + n_o) + 56 * n_o;
    let mut reads: Vec<u16> = Vec::with_capacity(per_row * TRACE_HEIGHT);

    // Helper: push 4 u16 limbs (LE, low→high) of a canonical u64
    // into the per-row buffer.
    fn push_u16_limbs(buf: &mut Vec<u16>, u: u64) {
        for k in 0..4 {
            buf.push(((u >> (16 * k)) & 0xffff) as u16);
        }
    }

    let mut per_row_limbs: Vec<u16> = Vec::with_capacity(per_row);
    for s in w.spends.iter() {
        let v = reduce_to_goldilocks(s.value);
        for k in 0..VALUE_LIMBS_U16 {
            per_row_limbs.push(((v >> (16 * k)) & 0xffff) as u16);
        }
    }
    for o in w.outputs.iter() {
        let v = reduce_to_goldilocks(o.value);
        for k in 0..VALUE_LIMBS_U16 {
            per_row_limbs.push(((v >> (16 * k)) & 0xffff) as u16);
        }
    }
    // Phase 4b-step3-step1.3-fields: 56 u16 limbs per output for
    // the 14 fe-limb proxy cols. Extract each u16 directly from
    // the real 32-byte witness bytes via 8-byte LE chunks reduced
    // to Goldilocks canonical form — identical to what trace-gen
    // pushes into the new `O_{D,PK_D,IVK_COMMITMENT,RCM}_LIMB0..`
    // cols, and identical to what `pack_*_as_*fe(...)` emits.
    for o in w.outputs.iter() {
        // d: 2 fe-limbs (bytes[0..8], bytes[8..16])
        for i in 0..2 {
            let u = reduce_to_goldilocks(u64::from_le_bytes(
                o.d[i * 8..(i + 1) * 8].try_into().unwrap(),
            ));
            push_u16_limbs(&mut per_row_limbs, u);
        }
        // pk_d: 4 fe-limbs
        for i in 0..4 {
            let u = reduce_to_goldilocks(u64::from_le_bytes(
                o.pk_d[i * 8..(i + 1) * 8].try_into().unwrap(),
            ));
            push_u16_limbs(&mut per_row_limbs, u);
        }
        // ivk_commitment: 4 fe-limbs
        for i in 0..4 {
            let u = reduce_to_goldilocks(u64::from_le_bytes(
                o.ivk_commitment[i * 8..(i + 1) * 8].try_into().unwrap(),
            ));
            push_u16_limbs(&mut per_row_limbs, u);
        }
        // rcm: 4 fe-limbs
        for i in 0..4 {
            let u = reduce_to_goldilocks(u64::from_le_bytes(
                o.rcm[i * 8..(i + 1) * 8].try_into().unwrap(),
            ));
            push_u16_limbs(&mut per_row_limbs, u);
        }
    }
    debug_assert_eq!(per_row_limbs.len(), per_row);

    for _ in 0..TRACE_HEIGHT {
        reads.extend_from_slice(&per_row_limbs);
    }
    reads
}

impl MvpBatchProver {
    /// Prove a witness with the cross-AIR u16 range-check LogUp wired
    /// (M-P2 Phase 3b-step3). Uses `MvpTransferAir` (trace height 64)
    /// + `Range16Air` (trace height 2^16 = 65 536) as two instances of
    /// the same `prove_batch`, tied by `Kind::Global("u16_range")`.
    ///
    /// Returns `(batch_proof_bytes, public_inputs_bytes)`. The public
    /// inputs are from the Transfer AIR only — `Range16Air` has zero
    /// public values (it's a fixed range table).
    pub fn prove_with_range_check(
        &self,
        witness_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Plonky3Status> {
        let witness = MvpWitness::decode(witness_bytes)?;
        pre_check_transfer_witness(&witness)?;

        let (n_s, n_o) = witness.shape();
        let transfer_trace = witness.generate_trace();
        let transfer_public_inputs = witness.public_inputs();

        // Range16 trace: multiplicity column counts how many times each
        // u16 entry 0..=65535 is received by MvpTransferAir across its
        // full 64-row trace (= TRACE_HEIGHT × per-row-tuple count).
        let reads = collect_u16_reads_for_range16(&witness);
        let range16_trace = Range16Air::build_main_trace(&reads);

        // Two-instance heterogeneous-height batch.
        let airs = [
            MvpAirUnion::Transfer(MvpTransferAir::new(n_s, n_o)),
            MvpAirUnion::Range16(Range16Air::new()),
        ];
        let traces = [&transfer_trace, &range16_trace];
        let pvs = [transfer_public_inputs.clone(), Vec::new()];

        // Sanity: the two traces' degree_bits are what we think they
        // are. `prove_batch` takes per-instance heights implicitly via
        // `trace.height()`, but asserting here locks the §4.1 TRACE_HEIGHT
        // + RANGE_TABLE_HEIGHT invariants into the prover contract so
        // a future edit that e.g. bumps trace height trips here first.
        debug_assert_eq!(transfer_trace.values.len() % transfer_trace.width, 0);
        debug_assert_eq!(
            transfer_trace.values.len() / transfer_trace.width,
            TRACE_HEIGHT
        );
        debug_assert_eq!(
            range16_trace.values.len() / range16_trace.width,
            RANGE_TABLE_HEIGHT
        );

        // Use from_airs_and_degrees so p3_lookup collects get_lookups
        // from both AIRs into common.lookups, including the matching
        // Kind::Global("u16_range") Receive + Send pair.
        let mut airs_mut = airs;
        // `from_airs_and_degrees` wants EXT degree bits (base + is_zk),
        // not base degree bits. Our PCS (TwoAdicFriPcs) is non-ZK, so
        // is_zk==0 and ext==base — but call the config to stay robust
        // across any future PCS swap.
        let zk = p3_uni_stark::StarkGenericConfig::is_zk(&self.config);
        let log_ext_degrees = [
            crate::transfer_air::LOG_TRACE_HEIGHT + zk,
            crate::range16_air::LOG_RANGE_TABLE_HEIGHT + zk,
        ];
        let prover_data: ProverData<MvpConfig> =
            ProverData::from_airs_and_degrees(&self.config, &mut airs_mut, &log_ext_degrees);
        let common = &prover_data.common;

        // Now build StarkInstances against the AIRs with lookups plumbed
        // in via common_data (the `new_multiple` helper auto-fills
        // `instance.lookups` from `common.lookups`).
        let instances = StarkInstance::new_multiple(&airs, &traces, &pvs, common);

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
    // NOTE: `witness_cm_bytes_consistent` and
    // `witness_anchor_bytes_consistent` exist in transfer_air.rs as
    // Phase 4b-step1 helpers but are NOT wired here yet. They enforce
    // `cm_bytes[0..8] as u64 == poseidon2_cm_fe(proxies)` /
    // `anchor_bytes[0..8] == anchor_proxy`, which is currently FALSE
    // for real tosctl-built witnesses: `cm_bytes` is the 32-byte
    // consensus commitment over real address material, while
    // `poseidon2_cm_fe` runs Poseidon2 over u64 digest-reductions of
    // that material. They fundamentally differ on limb 0.
    //
    // True limb-0 byte-parity with the C++ validator requires the
    // real Phase 4b (AIR upgrade to compute cm / anchor from
    // 32-byte inputs rather than u64 proxies). Step1 here only binds
    // limbs 1..3 and leaves limb-0 on its existing proxy footing.
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

    /// M-P2 Phase 3b-step3: end-to-end cross-AIR u16 range-check LogUp
    /// prove-side smoke. See `verifier::tests` for the corresponding
    /// verify-side round-trip that actually validates the global
    /// cumulative-sum check.
    #[test]
    fn batch_prove_with_range_check_smoke_1_1() {
        let prover = MvpBatchProver::new();
        let w = MvpWitness::deterministic_valid(1, 1, 0xB16B_0001);
        let (proof, pis) = prover
            .prove_with_range_check(&w.encode())
            .expect("batch prove_with_range_check 1/1");
        assert!(!proof.is_empty(), "empty proof bytes");
        assert_eq!(pis.len(), air_public_inputs_wire_len(1, 1));

        use p3_batch_stark::BatchProof;
        let _: BatchProof<MvpConfig> =
            postcard::from_bytes(&proof).expect("BatchProof postcard decode");
    }

    /// M-P2 Phase 3b-step3: full prove + verify round-trip for the
    /// cross-AIR u16 range-check LogUp at shape 1/1. Exercises
    /// `prove_with_range_check` + `verify_with_range_check` through
    /// independent `ProverData::from_airs_and_degrees` reconstruction
    /// on the verifier side. Green here confirms the
    /// Kind::Global("u16_range") cumulative sum balances across
    /// {MvpTransferAir receive, Range16Air send} and the AIR+lookup
    /// combined constraint accumulator agrees between prover and
    /// verifier at the OOD point.
    #[test]
    fn batch_range_check_round_trip_1_1() {
        use crate::verifier::MvpBatchVerifier;

        let prover = MvpBatchProver::new();
        let verifier = MvpBatchVerifier::new();

        let w = MvpWitness::deterministic_valid(1, 1, 0xB16B_0002);
        let (proof, pis) = prover
            .prove_with_range_check(&w.encode())
            .expect("prove_with_range_check 1/1");
        let status = verifier.verify_with_range_check(&proof, &pis);
        assert_eq!(
            status,
            Plonky3Status::Ok,
            "verify_with_range_check did not return Ok: {status:?}"
        );
    }

    /// M-P2 Phase 3b-step3: cross-AIR LogUp round-trip at the §4.1
    /// worst-case envelope shape 4/4. Exercises 4·(4+4) = 32 per-row
    /// u16 limb receives against the 65 536-entry Range16Air send.
    /// This is the consensus-binding worst case that the real
    /// validator path will hit.
    #[test]
    fn batch_range_check_round_trip_4_4_worst_case() {
        use crate::verifier::MvpBatchVerifier;

        let prover = MvpBatchProver::new();
        let verifier = MvpBatchVerifier::new();

        let w = MvpWitness::deterministic_valid(4, 4, 0xB16B_4004);
        let (proof, pis) = prover
            .prove_with_range_check(&w.encode())
            .expect("prove_with_range_check 4/4");
        let status = verifier.verify_with_range_check(&proof, &pis);
        assert_eq!(
            status,
            Plonky3Status::Ok,
            "verify_with_range_check did not return Ok at 4/4: {status:?}"
        );
    }

    /// Regression test mirroring the passing plonky3-uno simple.rs
    /// cross-AIR pattern — prove + verify using a SHARED
    /// `prover_data.common` passed to both sides (vs.
    /// `batch_range_check_round_trip_1_1` which reconstructs on the
    /// verifier side via `MvpBatchVerifier::verify_with_range_check`).
    /// Both tests now pass together, confirming that
    /// `ProverData::from_airs_and_degrees` is deterministic across
    /// fresh reconstructions with identical inputs.
    #[test]
    fn batch_range_check_round_trip_1_1_shared_common() {
        use crate::range16_air::{Range16Air, LOG_RANGE_TABLE_HEIGHT};
        use crate::transfer_air::{MvpTransferAir, LOG_TRACE_HEIGHT};
        use p3_batch_stark::{prove_batch, verify_batch, ProverData, StarkInstance};

        let config = build_config();
        let w = MvpWitness::deterministic_valid(1, 1, 0xB16B_0003);

        let (n_s, n_o) = w.shape();
        let transfer_trace = w.generate_trace();
        let transfer_public_inputs = w.public_inputs();
        let reads = collect_u16_reads_for_range16(&w);
        let range16_trace = Range16Air::build_main_trace(&reads);

        let mut airs = [
            MvpAirUnion::Transfer(MvpTransferAir::new(n_s, n_o)),
            MvpAirUnion::Range16(Range16Air::new()),
        ];
        let zk = p3_uni_stark::StarkGenericConfig::is_zk(&config);
        let log_ext_degrees = [LOG_TRACE_HEIGHT + zk, LOG_RANGE_TABLE_HEIGHT + zk];

        // ONE `from_airs_and_degrees` call — shared between prove + verify,
        // matching the passing plonky3-uno tests
        // (`test_batch_stark_global_lookups_only` et al).
        let prover_data: ProverData<MvpConfig> =
            ProverData::from_airs_and_degrees(&config, &mut airs, &log_ext_degrees);
        let common = &prover_data.common;

        let traces = [&transfer_trace, &range16_trace];
        let pvs = [transfer_public_inputs.clone(), Vec::new()];
        let instances = StarkInstance::new_multiple(&airs, &traces, &pvs, common);

        let proof = prove_batch(&config, &instances, &prover_data);

        // Verify with the SAME common_data that the prover used —
        // avoids any potential drift from independent reconstruction.
        let result = verify_batch(&config, &airs, &proof, &pvs, common);
        assert!(result.is_ok(), "shared-common verify failed: {:?}", result.err());
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
        // M-P2 Phase 4b-step3-step0 widened wire layout:
        //   HEAD(10)
        //   + PER_SPEND(32 + 4·32 + 8·MERKLE_DEPTH + 32)·n_s     (448 each at depth 32)
        //   + PER_OUTPUT(4·32 + 8 + 32 + 32 + 2)·n_o             (202 each)
        //   + TAIL(8 + 32 + 1 + 4 + 8)                           (53)
        let per_spend = 32 + 4 * 32 + 8 * MERKLE_DEPTH + 32;
        let per_output = 4 * 32 + 8 + 32 + 32 + 2;
        let head = 10;
        let tail = 8 + 32 + 1 + 4 + 8;
        assert_eq!(
            witness_wire.len(),
            head + per_spend * 4 + per_output * 4 + tail
        );
        assert_eq!(pi.len(), 608);
    }
}
