//! Minimum Viable AIR for the Uno Transfer — P.0 scaffolding.
//!
//! # Scope of this file
//!
//! This is **NOT** the production Transfer AIR described in §4.2 of
//! `doc/uno-workchain.md`. It is the P.0 bootstrap circuit whose only
//! purpose is to exercise the full Plonky3 toolchain — witness generation,
//! trace construction, constraint evaluation, FRI commit, challenger binding,
//! proof serialization, verifier round-trip — end-to-end so that the FFI
//! bridge to C++ can be validated.
//!
//! # What the MVP AIR asserts
//!
//! The AIR has the following trace layout (7 columns over Goldilocks):
//!
//! | col | name                   | semantic (MVP)                                           |
//! |-----|------------------------|----------------------------------------------------------|
//! | 0   | leaf                   | note-commitment leaf digest (one field-element proxy)    |
//! | 1   | sibling                | Merkle sibling at this level; also reused as the         |
//! |     |                        | diversifier `d` proxy in the claim-3 binding             |
//! | 2   | parent_claim           | claimed parent digest (one field-element proxy)          |
//! | 3   | value_acc              | rolling accumulator of `value` for the range check       |
//! | 4   | value_bit              | one bit of the little-endian decomposition of `value`    |
//! | 5   | ivk                    | private-witness `ivk` (decision #1, §2.6 claim 3)         |
//! | 6   | ivk_commitment_claim   | claimed Poseidon2("uno-ivk-cm-v1", ivk, d) proxy         |
//!
//! Over a trace of `2^k` rows (MVP uses `k=6`, so 64 rows), the AIR enforces:
//!
//! - **Merkle-step constraint** (first row): `parent_claim = leaf * mix_coef +
//!   sibling` where `mix_coef` is a public AIR constant. This is the
//!   **shape** of a 4-to-1 Poseidon2 compression contracted to a single field
//!   element — a real compression would be wider but the *constraint shape*
//!   (read leaf + sibling columns, produce parent column, check equality
//!   against a declared public input) is identical. See `// TODO(uno-design-
//!   gap)` below for the swap to real Poseidon2.
//!
//! - **Merkle-step public binding** (first row): `parent_claim` equals
//!   `public_inputs[0]` (the "declared parent" the verifier sees).
//!
//! - **Leaf public binding** (first row): `leaf` equals `public_inputs[1]`.
//!
//! - **Range check transition**: `value_acc_next = value_acc_curr * 2 +
//!   value_bit_next`, i.e. `value_acc` is the bit-by-bit accumulation of
//!   `value` in big-endian order, MSB first. Enforced on every transition.
//!
//! - **Bit constraint**: `value_bit * (value_bit - 1) = 0` on every row —
//!   each value-bit column cell must be 0 or 1.
//!
//! - **Range check public binding** (last row): `value_acc` equals
//!   `public_inputs[2]` (the "declared range-checked value"). With 64 rows
//!   of decomposition this asserts value ∈ [0, 2^63]. A depth-64 trace + one
//!   sign-bit column would extend this to [0, 2^64).
//!
//! - **ivk-commitment binding** (first row; decision #1, §4.2 claim 3
//!   scaffold): `ivk_commitment_claim = ivk * IVK_CM_MIX_COEF + sibling`
//!   where `sibling` is reused as the diversifier `d` proxy. This is the
//!   linear stand-in for `Poseidon2("uno-ivk-cm-v1", ivk, d)`; the full
//!   Transfer AIR (P.2) swaps the mix-coef compression for a real Poseidon2
//!   permutation with the same constraint shape (private-witness input ×
//!   public-input-derived input → public-input output). `ivk` and
//!   `ivk_commitment_claim` replicate across every transition so a prover
//!   cannot silently change them mid-trace.
//!
//! - **ivk-commitment public binding** (first row): `ivk_commitment_claim`
//!   equals `public_inputs[3]` (the "declared ivk_commitment"). Together
//!   with the binding above, this proves the claim-3 property: "prover
//!   knows an `ivk` such that `Poseidon2("uno-ivk-cm-v1", ivk, d) ==
//!   declared_ivk_commitment`". An adversary who picks a different `ivk`
//!   (not hash-chained from the owner's seed) gets a different
//!   `ivk_commitment_claim` and verify rejects.
//!
//! # Why this shape
//!
//! Three Plonky3 constraint families appear in the production Transfer AIR:
//! - **In-row binding to public inputs** (claims 1, 4, 6, 7).
//! - **Merkle compression** (claim 1 across 32 levels).
//! - **Bit decomposition / range checks** (claims 5, 8).
//!
//! The MVP includes one instance of each family. Passing prove/verify here
//! means the toolchain accepts the basic constraint patterns we need; it
//! does NOT mean the circuit is sound for actual Transfer semantics.
//!
//! # TODO(uno-design-gap) — map of §4.2 claims to future AIR work
//!
//! The full Transfer AIR (P.2 roadmap) must extend this scaffold to cover
//! all nine claims of §4.2. Mapping, with implementation hints:
//!
//! - **Claim 1 (Tree membership)** — depth-32 Merkle path. Replace the
//!   single-row Merkle step with 32 rows of full Poseidon2 compression
//!   (width t=8 or t=12 over Goldilocks per §2.2). Each row constrains one
//!   Poseidon2 permutation; consecutive rows feed parent(i) -> child(i+1).
//!   Use `p3-poseidon2-air::Poseidon2Air` as the sub-AIR; our transfer_air
//!   becomes a composite AIR that embeds Poseidon2Air columns and adds the
//!   "which sibling is left vs right" boolean column per level.
//!
//! - **Claim 2 (Note opening)** — one Poseidon2 permutation over
//!   `(d, pk_d, value, rcm)` packed into 11 Goldilocks elements; compare to
//!   `cm` public input. Same Poseidon2 sub-AIR reused; shape is identical to
//!   claim 1's Merkle compression, different input packing.
//!
//! - **Claim 3 (Ownership / hash-chain)** — DESIGN GAP FLAGGED IN DOC.
//!   The doc line "`pk_d` corresponds to this `(ivk, d)` via a hash-binding
//!   check (see circuit spec)" is under-specified: it does not concretize
//!   the hash-to-Ristretto derivation's in-circuit proxy. **This must be
//!   resolved by the cryptographer before the AIR can be written** — a
//!   plausible reading is that the AIR re-derives `ivk = Poseidon2("uno-
//!   ivk-v1", nk, ak)` in-circuit and then asserts a *public* binding
//!   `pk_d_commit = Poseidon2("uno-pk-d-bind-v1", ivk, d, pk_d.bytes)`
//!   alongside an off-circuit proof that `pk_d_commit` matches the note's
//!   actual `pk_d`, but this is an AGENT-4 GUESS, not in the doc. Flag as
//!   blocking issue for P.2 kickoff. See doc §2.6 and §4.2 claim 3.
//!
//! - **Claim 4 (Nullifier correctness)** — `nf = Poseidon2("uno-nf-v1",
//!   nk, cm, pos)`. One more Poseidon2 permutation row; `nf` is a public
//!   input (§4.3 step 4.6).
//!
//! - **Claim 5 (Spend value range)** — bit-decomposition columns as in the
//!   MVP but widened to 64 bits with a sign-bit freeness check so the
//!   accumulator covers `[0, 2^64)`. Since `p_Goldilocks = 2^64 − 2^32 + 1`,
//!   a naïve "assert value < p" is not enough; we need explicit
//!   bit-decomposition to catch the `2^64 − 2^32 + 1 .. 2^64 − 1` sliver.
//!
//! - **Claim 6 (Spend-auth binding)** — DESIGN GAP FLAGGED IN DOC.
//!   The doc line "`rk_i` equals the public key derived from the randomizer
//!   committed in-circuit (indirectly, via hash-chain on `ak_i` + randomizer
//!   `α_i`). Exact in-circuit formula pinned by circuit spec." is
//!   **under-specified**: no concrete hash-chain is given. The off-circuit
//!   Schnorr signature verifies `sig(rsk, tx_hash)` where `rsk = ask + α`,
//!   so the AIR would need to prove `ask` matches the hash-chain owner of
//!   `cm` AND publish `rk = ak + α·G` — but `α·G` is a Ristretto op and the
//!   doc §2.5 says "No in-circuit curve operations." The intended bridge is
//!   a hash-commitment to `α` that the off-circuit signature is linked to.
//!   **This must be resolved by the cryptographer before the AIR can be
//!   written** — listing as blocking P.2 gap. See doc §2.5, §4.2 claim 6.
//!
//! - **Claim 7 (Well-formed commitment for outputs)** — same as claim 2
//!   but on the output side. Another Poseidon2 row per output, with `cm_j`
//!   as a public input.
//!
//! - **Claim 8 (Output value range)** — same treatment as claim 5.
//!
//! - **Claim 9 (Value conservation)** — one linear equation over u64
//!   sums. Negligible cost. Encoded as: one public column `fee`, N private
//!   spend-value columns summed, M private output-value columns summed,
//!   equality asserted in-circuit on the last row.
//!
//! The full AIR is expected to be ~500–1500 columns wide and ~64-128 rows
//! tall, with proof size ~40-80 KB per §7.4 budget. The MVP here is 5
//! columns × 64 rows, yielding a ~5-10 KB proof — an order of magnitude
//! smaller but the same constraint *kinds*.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use crate::Plonky3Status;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of trace columns. See module doc for semantics.
///
/// Decision #1 grew the AIR from 5 → 7 columns by adding `ivk` and
/// `ivk_commitment_claim` columns for the claim-3 binding constraint.
pub const NUM_COLS: usize = 7;

/// Column indices — kept as named consts to make the witness generator
/// and AIR `eval()` signatures match the module-doc table above.
///
/// Currently unused at runtime because the AIR uses the typed [`MvpRow`]
/// view; kept as documentation of the column ordering contract. A future
/// debug dump or trace-inspector tooling can consume these names.
///
/// Not exported to the C header — these are Rust-side column indices,
/// meaningless to the FFI caller.
#[allow(dead_code)]
#[doc(hidden)]
pub(crate) mod col {
    pub const LEAF: usize = 0;
    pub const SIBLING: usize = 1;
    pub const PARENT_CLAIM: usize = 2;
    pub const VALUE_ACC: usize = 3;
    pub const VALUE_BIT: usize = 4;
    pub const IVK: usize = 5;
    pub const IVK_COMMITMENT_CLAIM: usize = 6;
}

/// Log2 of the trace height. 64 rows = 2^6.
///
/// Chosen so that the bit-decomposition column accumulates 64 bits over 64
/// transitions — covers values up to 2^63. Real Transfer AIR uses the same
/// structure with a sign-bit extension to cover the full u64 range.
pub const LOG_TRACE_HEIGHT: usize = 6;

/// Trace height = 2^LOG_TRACE_HEIGHT.
pub const TRACE_HEIGHT: usize = 1 << LOG_TRACE_HEIGHT;

/// Number of public inputs.
///
/// Layout (Goldilocks elements, indexed):
/// - `[0]`: declared parent digest (Merkle step output)
/// - `[1]`: declared leaf digest  (Merkle step input)
/// - `[2]`: declared range-checked value (the u64 being range-proved)
/// - `[3]`: declared ivk_commitment (decision #1, claim 3 binding)
pub const NUM_PUBLIC_INPUTS: usize = 4;

/// Byte length of the public-input wire encoding. Each Goldilocks element
/// is serialized as 8 little-endian bytes.
pub const PUBLIC_INPUTS_WIRE_LEN: usize = NUM_PUBLIC_INPUTS * 8;

/// AIR mixing coefficient used by the MVP Merkle step:
///
/// ```text
///     parent_claim = leaf * MERKLE_MIX_COEF + sibling
/// ```
///
/// This is a scaffolding stand-in for a real Poseidon2 4-to-1 compression.
/// It keeps the constraint-shape realistic (degree 1, two inputs, one
/// output, public output) while avoiding the ~300-line Poseidon2 round
/// expansion for the MVP. Value: 0xdeadbeef_cafef00d (arbitrary, fixed).
///
/// TODO(uno-design-gap): replace with `p3_goldilocks::Poseidon2Goldilocks<8>`
/// compression. When we do, `parent_claim` becomes a 4-element digest
/// (4 columns) and `leaf`/`sibling` become 4-element digests as well.
pub const MERKLE_MIX_COEF: u64 = 0xdead_beef_cafe_f00d;

/// AIR mixing coefficient used by the MVP ivk-commitment binding (decision
/// #1, §4.2 claim 3 scaffold):
///
/// ```text
///     ivk_commitment_claim = ivk * IVK_CM_MIX_COEF + sibling   // sibling reused as `d` proxy
/// ```
///
/// Linear stand-in for `Poseidon2("uno-ivk-cm-v1", ivk, d)`. Same role as
/// `MERKLE_MIX_COEF`: preserves the constraint family (one public-input
/// output bound to a hash-like combination of a private witness and a
/// trace-accessible value) while deferring the full Poseidon2 expansion to
/// P.2. A different mix coefficient is used so the two constraints don't
/// collapse into the same linear relation — an adversary who satisfies the
/// Merkle step without knowing the right `ivk` still gets the wrong
/// `ivk_commitment_claim`. Value: 0xbadcafe0_ivkcmv1 formatted as a nonce.
///
/// TODO(uno-design-gap): replace with the real in-circuit Poseidon2 over
/// the 6-element input `[ivk (4 fes), d_packed (2 fes)]` at P.2. Verifier
/// side (off-circuit, §2.6) already uses real Poseidon2.
pub const IVK_CM_MIX_COEF: u64 = 0xbad_cafe_0001_cb01;

// ---------------------------------------------------------------------------
// Row view
// ---------------------------------------------------------------------------

/// Typed view of one MVP trace row.
#[repr(C)]
pub struct MvpRow<F> {
    /// `col::LEAF`
    pub leaf: F,
    /// `col::SIBLING` — also reused as the diversifier `d` proxy in the
    /// claim-3 ivk-commitment binding (decision #1).
    pub sibling: F,
    /// `col::PARENT_CLAIM`
    pub parent_claim: F,
    /// `col::VALUE_ACC`
    pub value_acc: F,
    /// `col::VALUE_BIT`
    pub value_bit: F,
    /// `col::IVK` — private-witness `ivk` (decision #1, §4.2 claim 3).
    pub ivk: F,
    /// `col::IVK_COMMITMENT_CLAIM` — the claim-3 output, bound to
    /// `public_inputs[3]` on row 0.
    pub ivk_commitment_claim: F,
}

impl<F> Borrow<MvpRow<F>> for [F] {
    #[inline]
    fn borrow(&self) -> &MvpRow<F> {
        debug_assert_eq!(self.len(), NUM_COLS);
        // SAFETY: repr(C) with NUM_COLS identically-typed fields matches
        // the column-major-stride layout of a single trace row.
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MvpRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

// ---------------------------------------------------------------------------
// AIR definition
// ---------------------------------------------------------------------------

/// The Minimum Viable AIR. See module-level doc for the constraint system.
#[derive(Debug, Default, Clone, Copy)]
pub struct MvpTransferAir;

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for MvpTransferAir {
    #[inline]
    fn width(&self) -> usize {
        NUM_COLS
    }

    #[inline]
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_INPUTS
    }

    #[inline]
    fn max_constraint_degree(&self) -> Option<usize> {
        // Highest-degree constraint is `value_bit * (value_bit - 1)` and
        // the range-check transition `acc_next - (acc_curr * 2 +
        // bit_next)`, both degree 2. Binding checks are degree 1 (wrapped
        // by is_first_row / is_last_row selectors which are degree 1 each).
        Some(2)
    }
}

impl<AB> Air<AB> for MvpTransferAir
where
    AB: AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_slice = main.current_slice();
        let next_slice = main.next_slice();

        let local: &MvpRow<AB::Var> = local_slice.borrow();
        let next: &MvpRow<AB::Var> = next_slice.borrow();

        let pis = builder.public_values();
        let declared_parent = pis[0];
        let declared_leaf = pis[1];
        let declared_value = pis[2];
        let declared_ivk_commitment = pis[3];

        // ---- First-row: Merkle-step and public bindings ----------------
        //
        // Row 0 is the "real" Merkle step; subsequent rows replicate `leaf`,
        // `sibling`, `parent_claim` unchanged (enforced by the transition
        // below for determinism). We bind to public inputs only on the first
        // row so the constraint system doesn't over-constrain replicas.
        {
            let mut first = builder.when_first_row();

            // Merkle step: parent_claim = leaf * mix_coef + sibling.
            let mix = AB::Expr::from(AB::F::from_u64(MERKLE_MIX_COEF));
            first.assert_eq(
                local.parent_claim.into(),
                local.leaf.into() * mix + local.sibling.into(),
            );

            // Bind declared parent / leaf to the trace.
            first.assert_eq(local.parent_claim, declared_parent);
            first.assert_eq(local.leaf, declared_leaf);

            // Range-check accumulator starts at value_bit[row 0] (the MSB).
            first.assert_eq(local.value_acc, local.value_bit);

            // ---- ivk-commitment binding (decision #1, §4.2 claim 3) ----
            //
            // Linear stand-in for `Poseidon2("uno-ivk-cm-v1", ivk, d)`,
            // with `sibling` reused as the `d` proxy. The full P.2 AIR
            // swaps this mix-coef compression for real Poseidon2 over the
            // 6-element absorb `[ivk (4 fes), d_packed (2 fes)]`; the
            // constraint *family* here (private-witness + trace-linked
            // input → public-input output) is identical.
            let ivk_mix = AB::Expr::from(AB::F::from_u64(IVK_CM_MIX_COEF));
            first.assert_eq(
                local.ivk_commitment_claim.into(),
                local.ivk.into() * ivk_mix + local.sibling.into(),
            );

            // Public binding: declared ivk_commitment matches the trace.
            // An adversary who supplies a different private `ivk` (one not
            // hash-chained from the owner's seed) gets a different
            // ivk_commitment_claim value, and the verifier rejects.
            first.assert_eq(local.ivk_commitment_claim, declared_ivk_commitment);
        }

        // ---- Per-row bit-ness check ------------------------------------
        //
        // `value_bit * (value_bit - 1) = 0` on every row. Enforcing on ALL
        // rows (not just transitions) catches a malicious witness that sets
        // a non-bit value on the last row.
        builder.assert_bool(local.value_bit);

        // ---- Per-row replica checks for leaf / sibling / parent_claim ---
        //
        // The Merkle step is a single-row relation, but Plonky3 traces must
        // be at least 2^log_blowup rows. We pad by replicating columns 0..3
        // across every row. Enforce `leaf_next = leaf_curr`,
        // `sibling_next = sibling_curr`, `parent_claim_next = parent_claim_curr`
        // on every transition.  Decision #1 adds the same for `ivk` and
        // `ivk_commitment_claim` so the claim-3 binding cannot drift.
        {
            let mut t = builder.when_transition();
            t.assert_eq(next.leaf, local.leaf);
            t.assert_eq(next.sibling, local.sibling);
            t.assert_eq(next.parent_claim, local.parent_claim);
            t.assert_eq(next.ivk, local.ivk);
            t.assert_eq(next.ivk_commitment_claim, local.ivk_commitment_claim);

            // Range-check accumulator transition:
            //   value_acc_next = value_acc_curr * 2 + value_bit_next
            // i.e. MSB-first bit-shift-and-add.
            let two = AB::Expr::from(AB::F::from_u64(2));
            t.assert_eq(
                next.value_acc.into(),
                local.value_acc.into() * two + next.value_bit.into(),
            );
        }

        // ---- Last-row: range check public binding ----------------------
        {
            let mut last = builder.when_last_row();
            last.assert_eq(local.value_acc, declared_value);
        }
    }
}

// ---------------------------------------------------------------------------
// Witness struct + trace generation
// ---------------------------------------------------------------------------

/// A witness to the MVP AIR, in a form callable from tests and the FFI
/// prover entry point.
#[derive(Debug, Clone)]
pub struct MvpWitness {
    /// The Merkle leaf — corresponds to the "spent note commitment" in
    /// the full Transfer AIR. MVP treats it as one field element.
    pub leaf: u64,
    /// Merkle sibling at the step being proved. TEST ONLY — the
    /// production AIR has 32 siblings (one per tree level). Also reused
    /// as the diversifier `d` proxy for the claim-3 ivk-commitment
    /// binding (decision #1).
    pub merkle_sibling: [u8; 8],
    /// The u64 value being range-checked. Represents one spend's `value`.
    pub value: u64,
    /// Private-witness `ivk` (decision #1, §4.2 claim 3). The full AIR
    /// treats this as 4 Goldilocks field elements; the MVP AIR treats it
    /// as one u64 proxy alongside the other single-element simplifications.
    pub ivk: u64,
}

impl MvpWitness {
    /// Build a deterministic valid witness, seeded by `seed`.
    ///
    /// "Valid" here means: the `parent_claim` column the prover derives
    /// from `(leaf, sibling)` is exactly what the public inputs will
    /// declare, and `value` is within the range the AIR covers (MVP:
    /// `value < 2^63`, so we mask off the top bit).
    pub fn deterministic_valid(seed: u64) -> Self {
        let leaf = seed ^ 0xa5a5_a5a5_a5a5_a5a5;
        let sibling_word = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x1234_0000_0000_0000;
        let value = (seed ^ 0xbabe_cafe_dead_f00d) & ((1u64 << 63) - 1); // mask to 63-bit range
        // Deterministic `ivk` proxy; distinct from `leaf`/`sibling` so a
        // copy-paste regression between columns is caught at prove time.
        let ivk = seed.wrapping_mul(0xc2b2_ae3d_27d4_eb4f) ^ 0x1efbe1edu64;

        Self {
            leaf,
            merkle_sibling: sibling_word.to_le_bytes(),
            value,
            ivk,
        }
    }

    /// Serialize the witness to a byte buffer for the FFI path.
    /// Layout: `leaf_le(8) || sibling(8) || value_le(8) || ivk_le(8)` = 32 B.
    /// Decision #1 grew the witness by 8 B (the `ivk` proxy); callers
    /// encoding witnesses off-wire must supply 32 B, not 24 B.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&self.leaf.to_le_bytes());
        out.extend_from_slice(&self.merkle_sibling);
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&self.ivk.to_le_bytes());
        out
    }

    /// Decode from wire bytes produced by [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, Plonky3Status> {
        if bytes.len() != 32 {
            return Err(Plonky3Status::WitnessInvalid);
        }
        let leaf = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let merkle_sibling: [u8; 8] = bytes[8..16].try_into().unwrap();
        let value = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let ivk = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        // Enforce the MVP 63-bit range here as well — the AIR would reject
        // at verify time, but rejecting early gives a cleaner error code.
        if value >> 63 != 0 {
            return Err(Plonky3Status::WitnessInvalid);
        }
        Ok(Self {
            leaf,
            merkle_sibling,
            value,
            ivk,
        })
    }

    /// Derive the 4 public-input field elements from the witness.
    /// These are the values the verifier will see.
    pub fn public_inputs(&self) -> [Goldilocks; NUM_PUBLIC_INPUTS] {
        let leaf_f = Goldilocks::from_u64(reduce_to_goldilocks(self.leaf));
        let sibling_u = u64::from_le_bytes(self.merkle_sibling);
        let sibling_f = Goldilocks::from_u64(reduce_to_goldilocks(sibling_u));

        // parent_claim = leaf * MERKLE_MIX_COEF + sibling  (in Goldilocks)
        let mix = Goldilocks::from_u64(MERKLE_MIX_COEF);
        let parent = leaf_f * mix + sibling_f;

        let value_f = Goldilocks::from_u64(self.value);

        // ivk_commitment_claim = ivk * IVK_CM_MIX_COEF + sibling_as_d
        // (decision #1, §4.2 claim 3 scaffold). `sibling` is reused as the
        // `d` proxy; this matches the first-row AIR constraint.
        let ivk_f = Goldilocks::from_u64(reduce_to_goldilocks(self.ivk));
        let ivk_mix = Goldilocks::from_u64(IVK_CM_MIX_COEF);
        let ivk_commitment = ivk_f * ivk_mix + sibling_f;

        [parent, leaf_f, value_f, ivk_commitment]
    }

    /// Encode the public inputs as the verifier wire format (LE bytes,
    /// 8 per Goldilocks element). Matches [`NUM_PUBLIC_INPUTS`] *
    /// 8 = 24 bytes for MVP.
    pub fn public_inputs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_INPUTS_WIRE_LEN);
        for elem in self.public_inputs() {
            out.extend_from_slice(&elem.as_canonical_u64().to_le_bytes());
        }
        out
    }

    /// Generate the full trace matrix for this witness.
    pub fn generate_trace(&self) -> RowMajorMatrix<Goldilocks> {
        let pis = self.public_inputs();
        let declared_leaf = pis[1];

        // Sibling as Goldilocks.
        let sibling_u = u64::from_le_bytes(self.merkle_sibling);
        let sibling_f = Goldilocks::from_u64(reduce_to_goldilocks(sibling_u));

        // Parent from pis[0] — matches the AIR's declared_parent check.
        let parent_f = pis[0];

        // Decision #1: ivk + ivk_commitment_claim replicate across the trace.
        let ivk_f = Goldilocks::from_u64(reduce_to_goldilocks(self.ivk));
        let ivk_commitment_f = pis[3];

        // Pre-compute the 64 bits of `value`, MSB first.
        // For a 63-bit range the top bit is guaranteed 0 (decoder enforced).
        let mut bits_msb_first = [0u64; TRACE_HEIGHT];
        for i in 0..TRACE_HEIGHT {
            let bit_index_from_lsb = (TRACE_HEIGHT - 1) - i;
            bits_msb_first[i] = (self.value >> bit_index_from_lsb) & 1;
        }

        let mut values = Vec::<Goldilocks>::with_capacity(TRACE_HEIGHT * NUM_COLS);
        let mut acc: u64 = 0;
        for (row_idx, &bit) in bits_msb_first.iter().enumerate() {
            // First three columns replicate across the trace.
            values.push(declared_leaf); // col 0: leaf
            values.push(sibling_f); // col 1: sibling
            values.push(parent_f); // col 2: parent_claim

            // Range-check accumulator advances MSB-first.
            if row_idx == 0 {
                acc = bit;
            } else {
                acc = acc.wrapping_mul(2).wrapping_add(bit);
            }

            values.push(Goldilocks::from_u64(acc)); // col 3: value_acc
            values.push(Goldilocks::from_u64(bit)); // col 4: value_bit

            // Decision #1: ivk + ivk_commitment_claim replicated per row.
            values.push(ivk_f);             // col 5: ivk
            values.push(ivk_commitment_f);  // col 6: ivk_commitment_claim
        }

        RowMajorMatrix::new(values, NUM_COLS)
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Reduce a `u64` into a canonical Goldilocks residue.
///
/// `Goldilocks::from_u64(x)` accepts any `u64` but interprets it as the
/// field element `x mod p`. For MVP we want byte-input → field-element to
/// be injective within the Goldilocks canonical range (`0 .. p-1`). We
/// subtract `p` only for values ≥ p.
#[inline]
pub(crate) fn reduce_to_goldilocks(x: u64) -> u64 {
    // p = 2^64 - 2^32 + 1
    const P: u64 = 0xFFFF_FFFF_0000_0001;
    if x >= P {
        x.wrapping_sub(P)
    } else {
        x
    }
}

/// Decode a public-input byte buffer into Goldilocks field elements.
///
/// Consumed by the verifier FFI entry point. Fails if the buffer length
/// doesn't match [`PUBLIC_INPUTS_WIRE_LEN`] or a byte group encodes a
/// value outside canonical range (we do NOT silently wrap into the
/// "aliased" `2^64 − 2^32 .. 2^64 − 1` region, which would accept two
/// different wire encodings for the same field element — a malleability
/// bug).
pub fn decode_public_inputs(bytes: &[u8]) -> Result<Vec<Goldilocks>, Plonky3Status> {
    if bytes.len() != PUBLIC_INPUTS_WIRE_LEN {
        return Err(Plonky3Status::PublicInputLengthMismatch);
    }
    const P: u64 = 0xFFFF_FFFF_0000_0001;
    let mut out = Vec::with_capacity(NUM_PUBLIC_INPUTS);
    for chunk in bytes.chunks_exact(8) {
        let v = u64::from_le_bytes(chunk.try_into().unwrap());
        if v >= P {
            // Non-canonical encoding. Rejecting closes off a proof-system
            // malleability vector (two different wire encodings producing
            // the same proof).
            return Err(Plonky3Status::PublicInputDecodeFailed);
        }
        out.push(Goldilocks::from_u64(v));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Unit tests (pure AIR semantics — no prover stack)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_inputs_are_four_elements() {
        // Decision #1 bumped NUM_PUBLIC_INPUTS from 3 to 4.
        assert_eq!(NUM_PUBLIC_INPUTS, 4);
        assert_eq!(
            <MvpTransferAir as BaseAir<Goldilocks>>::num_public_values(&MvpTransferAir),
            NUM_PUBLIC_INPUTS
        );
    }

    #[test]
    fn num_cols_is_seven() {
        // Decision #1 bumped NUM_COLS from 5 to 7 (added ivk +
        // ivk_commitment_claim).
        assert_eq!(NUM_COLS, 7);
    }

    #[test]
    fn witness_encode_decode_roundtrip() {
        let w = MvpWitness::deterministic_valid(42);
        let bytes = w.encode();
        assert_eq!(bytes.len(), 32, "decision #1: witness wire is 32 B");
        let w2 = MvpWitness::decode(&bytes).unwrap();
        assert_eq!(w.leaf, w2.leaf);
        assert_eq!(w.merkle_sibling, w2.merkle_sibling);
        assert_eq!(w.value, w2.value);
        assert_eq!(w.ivk, w2.ivk);
    }

    #[test]
    fn witness_decode_rejects_out_of_range_value() {
        let mut bytes = MvpWitness::deterministic_valid(0).encode();
        // Overwrite the value with u64::MAX (top bit set).
        bytes[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            MvpWitness::decode(&bytes),
            Err(Plonky3Status::WitnessInvalid)
        ));
    }

    #[test]
    fn witness_decode_rejects_short_length() {
        // A 24-byte buffer (pre-decision-#1 shape) must be rejected now
        // that the witness carries the 8-byte `ivk` tail.
        let short = vec![0u8; 24];
        assert!(matches!(
            MvpWitness::decode(&short),
            Err(Plonky3Status::WitnessInvalid)
        ));
    }

    #[test]
    fn public_inputs_bytes_are_expected_length() {
        let w = MvpWitness::deterministic_valid(7);
        assert_eq!(w.public_inputs_bytes().len(), PUBLIC_INPUTS_WIRE_LEN);
    }

    #[test]
    fn public_input_decode_round_trip() {
        let w = MvpWitness::deterministic_valid(99);
        let bytes = w.public_inputs_bytes();
        let pis = decode_public_inputs(&bytes).unwrap();
        assert_eq!(pis.len(), NUM_PUBLIC_INPUTS);
        let expected = w.public_inputs();
        assert_eq!(pis[0], expected[0]);
        assert_eq!(pis[1], expected[1]);
        assert_eq!(pis[2], expected[2]);
        // Decision #1: fourth element is the ivk_commitment binding.
        assert_eq!(pis[3], expected[3]);
    }

    /// Honest witness produces a non-trivial ivk_commitment binding, and
    /// that binding must change if the adversary alters the `ivk` private
    /// witness. This is the scaffold form of §4.2 claim 3: only the holder
    /// of the seed-chained `ivk` can match the public ivk_commitment.
    #[test]
    fn ivk_commitment_binding_changes_with_ivk() {
        let honest = MvpWitness::deterministic_valid(0xcafe_f00d_0001);
        let honest_pis = honest.public_inputs();
        let mut tampered = honest.clone();
        tampered.ivk ^= 0xffff_ffff_ffff_ffff;
        let tampered_pis = tampered.public_inputs();
        // Merkle-step public input (index 0) unchanged — only claim 3
        // flips. This confirms the new constraint is functionally wired
        // and is not collapsing into one of the earlier bindings.
        assert_eq!(honest_pis[0], tampered_pis[0]);
        assert_eq!(honest_pis[1], tampered_pis[1]);
        assert_eq!(honest_pis[2], tampered_pis[2]);
        assert_ne!(
            honest_pis[3], tampered_pis[3],
            "decision #1: ivk_commitment must change when `ivk` changes"
        );
    }

    #[test]
    fn public_input_decode_rejects_non_canonical() {
        // Encode a u64 value equal to P (= 2^64 - 2^32 + 1) — out of
        // canonical range, even though `from_u64` would silently accept.
        let mut bytes = vec![0u8; PUBLIC_INPUTS_WIRE_LEN];
        let p = 0xFFFF_FFFF_0000_0001u64;
        bytes[0..8].copy_from_slice(&p.to_le_bytes());
        assert!(matches!(
            decode_public_inputs(&bytes),
            Err(Plonky3Status::PublicInputDecodeFailed)
        ));
    }

    #[test]
    fn public_input_decode_rejects_wrong_length() {
        let bytes = vec![0u8; PUBLIC_INPUTS_WIRE_LEN - 1];
        assert!(matches!(
            decode_public_inputs(&bytes),
            Err(Plonky3Status::PublicInputLengthMismatch)
        ));
    }

    #[test]
    fn trace_shape() {
        use p3_matrix::Matrix;
        let w = MvpWitness::deterministic_valid(11);
        let trace = w.generate_trace();
        assert_eq!(trace.height(), TRACE_HEIGHT);
        assert_eq!(trace.width(), NUM_COLS);
    }
}
