//! Witness types and trace-generation for the Transfer AIR.
//!
//! Contains `SpendWitness`, `OutputWitness`, `MvpWitness`, `impl MvpWitness`
//! (encode/decode/trace-gen), and the prover-side pre-check helpers
//! (`witness_claim*`). Extracted from `transfer_air.rs`; re-exported from
//! there via `pub use crate::transfer_witness::*`.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
    default_goldilocks_poseidon2_16, default_goldilocks_poseidon2_8,
    GenericPoseidon2LinearLayersGoldilocks, Goldilocks,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::RoundConstants;
use p3_symmetric::Permutation;

use crate::transfer_columns::*;
use crate::transfer_preimage::*;
use crate::transfer_sponge::*;
use crate::Plonky3Status;

// ---------------------------------------------------------------------------
// Witness + trace generation
// ---------------------------------------------------------------------------

/// Single-spend witness.
#[derive(Debug, Clone)]
pub struct SpendWitness {
    /// Raw 32-byte spent-note commitment `cm` (= Merkle leaf). Phase 4b-
    /// step3-step2a widened from `u64` single-fe proxy so tosctl can
    /// thread the real 32-byte note commitment through. The AIR in its
    /// current (pre-step2b) shape still derives a u64 proxy internally
    /// via `first_u64_proxy(&s.leaf)` — narrow-nf claim 4 and the
    /// per-spend Merkle walk both still use the low 8 bytes only.
    /// Step 2b will add 4-fe leaf decomposition cols + widen the nf
    /// derivation to consume them in-circuit.
    pub leaf: [u8; 32],
    /// Raw diversifier `d_i` in 32-byte representation. The real
    /// diversifier is 11 bytes; tosctl pads `bytes[0..11]` with the
    /// real material and leaves `bytes[11..32]` zero. Phase 4b-step3-
    /// step5a-wire widened from `[u8; 8]` so tosctl can pass real
    /// per-note diversifier material through to the spend-side cm
    /// sponge (step 5c). The AIR (pre-step5c) still derives a u64
    /// proxy internally via `first_u64_proxy(&s.d)` — low 8 bytes; the
    /// real 32-byte material is only absorbed once step 5c lands.
    /// Bytes `d[11..32]` must be canonical zero (decoder enforces);
    /// mirrors the same rejection on `OutputWitness.d`.
    pub d: [u8; 32],
    /// Value being spent. Must be `< p_Goldilocks`.
    pub value: u64,
    /// Raw 32-byte `ivk_commitment_i` (spender's address commitment,
    /// §2.6). Phase 4b-step3-step5a-wire added so the spend-side cm
    /// sponge (step 5c) can absorb it as 4 fes at `fes[6..10]` of the
    /// 15-fe input, matching the output-side layout. Derived off-chain
    /// by tosctl as `Poseidon2("uno-ivk-cm-v1", ivk, d)` — byte-
    /// identical to the output-side `OutputWitness.ivk_commitment`.
    /// The AIR (pre-step5c) consumes only `first_u64_proxy(&s.ivk_commitment)`
    /// (low 8 bytes) via the legacy single-perm path.
    pub ivk_commitment: [u8; 32],
    /// Raw 32-byte `ivk` (Ristretto255 scalar). Phase 4b-step3-step0
    /// widened from `u64` proxy so tosctl can pass the real viewing
    /// key through. The AIR in its current (pre-step3) shape still
    /// derives a u64 proxy internally via
    /// `u64::from_le_bytes(ivk[0..8].try_into().unwrap())` — claim 2 /
    /// 3 semantics are unchanged until step 1+ lifts cm / nf to
    /// 4-fe output.
    pub ivk: [u8; 32],
    /// Raw 32-byte `pk_d` (Ristretto255 compressed point). See `ivk`
    /// doc for the same step0 widening note.
    pub pk_d: [u8; 32],
    /// Raw 32-byte note randomness `rcm`. Per-note value, not the
    /// whole address.
    pub rcm: [u8; 32],
    /// Raw 32-byte nullifier key `nk` (from the spender's FVK).
    pub nk: [u8; 32],
    /// Leaf position within the depth-32 commitment tree. Low bit is the
    /// level-0 path bit (§2.3, matching `commitment-tree.{h,cpp}`). Must
    /// satisfy `pos < 2^MERKLE_DEPTH` (upper bits in `pos` are discarded
    /// when the witness is encoded because only 32 path bits are stored).
    pub pos: u64,
    /// 32-level Merkle path: each entry is the raw 32-byte sibling hash
    /// at level `k`. Level 0 is the first layer above the leaf. Phase
    /// 4b-step3-step3c widened from `u64` single-fe proxy (per-entry)
    /// to `[u8; 32]` so tosctl can thread the real 32-byte sibling
    /// digests through. The AIR in its current (pre-step3a) shape
    /// still derives a single-fe proxy via
    /// `first_u64_proxy(&s.merkle_path[k])` (low 8 bytes) for the
    /// legacy single-fe Merkle walk — no AIR logic changes here.
    /// Step 3a will lift the Merkle walk to a 4-fe state by
    /// decomposing each sibling via `pack_32b_as_4fe` for the
    /// `(left[4] ‖ right[4]) → out[4]` compression.
    pub merkle_path: [[u8; 32]; MERKLE_DEPTH],
    /// Raw 32-byte `rk` (compressed Ristretto255 spend-auth pubkey, §4.1).
    /// Consensus-binding: C++ `build_plonky3_public_inputs` encodes this
    /// via `encode_256` → 4 Goldilocks limbs. V1-3c-round-8 (tier-1) added
    /// this field so Rust-side PI bytes match the C++ build byte-for-byte
    /// (previously the 4 rk slots were all-zero, breaking STARK verify
    /// on a real validator). The AIR proxy claims do not bind these
    /// slots; the constraint is satisfied solely by consensus-level
    /// preimage equality via §4.1 tx_hash.
    pub rk_bytes: [u8; 32],
}

/// Single-output witness.
#[derive(Debug, Clone)]
pub struct OutputWitness {
    /// Raw diversifier `d_j` in 32-byte representation. The real
    /// diversifier is 11 bytes; tosctl pads `bytes[0..11]` with the
    /// real material and leaves `bytes[11..32]` zero. Phase 4b-step3-
    /// step0 widened from `u64` proxy so tosctl can pass real
    /// material through. The AIR (pre-step3) still derives a u64
    /// proxy internally via the first 8 bytes.
    pub d: [u8; 32],
    /// Raw 32-byte recipient `pk_d_j`.
    pub pk_d: [u8; 32],
    /// Raw 32-byte recipient `ivk_commitment_j`.
    pub ivk_commitment: [u8; 32],
    /// Output value (u64, Goldilocks-fits).
    pub value: u64,
    /// Raw 32-byte per-output randomness `rcm_j`.
    pub rcm: [u8; 32],
    /// Raw 32-byte `cm_j` (note commitment, §4.1). Used to populate all
    /// 4 PI limbs via `encode_256`; the current proxy AIR binds only the
    /// low-limb equality (`pi_cm[j] == cm_fe_computed_from_witness`).
    /// V1-3c-round-8 (tier-1) — see `rk_bytes` note on SpendWitness.
    pub cm_bytes: [u8; 32],
    /// Raw 32-byte `epk_j` (compressed Ristretto255 ephemeral pubkey, §4.1).
    pub epk_bytes: [u8; 32],
    /// 16-bit compact filter tag (§2.8). Becomes 1 PI element.
    pub filter_tag: u16,
}

/// Full Transfer witness for 1..4 spends × 1..4 outputs + fee.
#[derive(Debug, Clone)]
pub struct MvpWitness {
    /// `scheme_id` (§4.1, v1 = 0x01). Goes into PI position 0.
    pub scheme_id: u8,
    /// `chain_id` (§4.1, mainnet 0x554E4F4D "UNOM" / testnet 0x554E4F54
    /// "UNOT"). Goes into PI position 1.
    pub chain_id: u32,
    /// `expiry_block` (§4.1, §4.3 step 1.3). Goes into PI position 2.
    pub expiry_block: u64,
    /// Transaction fee, public input.
    pub fee: u64,
    /// Spend descriptions (len ∈ [1, 4]).
    pub spends: Vec<SpendWitness>,
    /// Output descriptions (len ∈ [1, 4]).
    pub outputs: Vec<OutputWitness>,
    /// Legacy single-u64 anchor proxy (pre-step-3a Merkle-walk output).
    /// Raw 32-byte anchor (§4.1). PI slots 4..7 are the 4 `encode_256`
    /// limbs of these bytes. Post Phase 4b-step3-step3a the AIR derives
    /// all 4 limbs from the 4-fe Merkle walk and binds them directly
    /// to `PI[PI_ANCHOR + 0..4]`; callers arrange `anchor_bytes` to
    /// equal the Merkle root of the tree they're proving against.
    /// V1-3c-round-8 (tier-1) — see `rk_bytes` note on SpendWitness.
    pub anchor_bytes: [u8; 32],
}

impl MvpWitness {
    /// `(n_spends, n_outputs)` for this witness.
    #[inline]
    pub fn shape(&self) -> (usize, usize) {
        (self.spends.len(), self.outputs.len())
    }

    /// Build a deterministic valid witness of the given shape.
    ///
    /// All spends share `(leaf, sibling, value, ivk, pk_d, rcm)` so the
    /// per-spend Merkle step produces the same anchor by construction
    /// (single-step Merkle can only produce anchor-equivalence if all
    /// `(leaf, sibling)` pairs are equal). Only `(nk, pos)` differ
    /// per-spend to produce distinct nullifiers. This is a test-fixture
    /// construction — real wallets produce distinct leaves per spend
    /// over a 32-level Merkle chain. The 32-level depth walk landed in
    /// M-P2 K-AIR; the 4-fe per-level state (real 32-byte siblings,
    /// 256-bit anchor binding) landed in Phase 4b-step3-step3a (`a0ff246ae`).
    ///
    /// Balance construction: `value_i = v` constant per spend; total in
    /// is `n_s · v`; `fee` is chosen small; output values split
    /// `n_s·v - fee` evenly across `n_o` outputs (last output absorbs
    /// the remainder).
    pub fn deterministic_valid(n_spends: usize, n_outputs: usize, seed: u64) -> Self {
        assert!(n_spends >= MIN_SPENDS && n_spends <= MAX_SPENDS);
        assert!(n_outputs >= MIN_OUTPUTS && n_outputs <= MAX_OUTPUTS);

        let perm = default_goldilocks_poseidon2_8();
        let perm16 = default_goldilocks_poseidon2_16();

        // Derive shared spend witness fields.
        let d_word = seed
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(0x1234_0000_0000_0000)
            & ((1u64 << 62) - 1);
        let shared_ivk = seed.wrapping_mul(0xc2b2_ae3d_27d4_eb4f) ^ 0x1efb_e1ed;
        let shared_pk_d = seed.wrapping_mul(0x1656_67b1_9e37_79f9) ^ 0xdeca_d0de;
        let shared_rcm = seed.wrapping_mul(0xd6e8_feb8_6659_fd93) ^ 0xfade_cafe;

        // Shared per-spend value (small u32-ish so n_s·v never overflows u64).
        let v_per_spend: u64 = 0x0001_0000 + (seed & 0xFF_FFFF);
        let fee: u64 = 0x100 + (seed & 0xFFF);

        // Derived shared leaf. Computed below from the 15-fe iterated
        // sponge once `shared_*_bytes` are built, so the AIR's step-5c
        // `shared_cm_out[0..4] == (S_LEAF, S_LEAF_FE1..3)` binding
        // holds. Pre-step-5c this was a single-perm `poseidon2_cm(...)`
        // over u64 proxies; that value DID NOT match the sponge output
        // and would trip the claim-2 closure today.
        let ivkcm = poseidon2_ivk_commitment(&perm, shared_ivk, d_word);

        // Shared 32-level Merkle path: siblings fixed per seed; position
        // fixed per seed. All spends share `(leaf, path, pos)` so that the
        // resulting anchor is the same by construction (the AIR only
        // enforces anchor equality, not distinct leaves — test-fixture
        // convention, see struct-doc).
        let shared_pos: u64 = (seed & ((1u64 << MERKLE_DEPTH) - 1)) as u64;
        let mut shared_path = [0u64; MERKLE_DEPTH];
        for k in 0..MERKLE_DEPTH {
            // Distinct per-level siblings, bounded to 62 bits to stay
            // canonical after Goldilocks reduction.
            let mix = seed
                .wrapping_mul(0xBF58_476D_1CE4_E5B9)
                .wrapping_add((k as u64).wrapping_mul(0x94D0_49BB_1331_11EB));
            shared_path[k] = mix & ((1u64 << 62) - 1);
        }
        // Phase 4b-step3-step3c: widen siblings from `[u64; 32]` to
        // `[[u8; 32]; 32]`. Fixture projects each legacy u64 proxy into
        // bytes[0..8] with zero pad (same 8-byte-low-limb convention
        // as leaf / d / nk above); real tosctl witnesses now carry
        // full 32-byte sibling digests.
        let mut shared_path_bytes = [[0u8; 32]; MERKLE_DEPTH];
        for k in 0..MERKLE_DEPTH {
            shared_path_bytes[k][0..8].copy_from_slice(&shared_path[k].to_le_bytes());
        }

        // Phase 4b-step3-step5a-wire: widened `d` from `[u8; 8]` to
        // `[u8; 32]`, populate bytes[0..8] from `shared_d_word.to_le_bytes()`
        // with the remainder zero-padded — matches the "u64 proxy in low
        // 8 bytes" convention used by every other widened field in this
        // fixture. Bytes [11..32] must be zero (decoder rejects non-zero
        // padding; d[8..11] may hold high bits of the proxy u64 but
        // tosctl honest witnesses keep those zero as well).
        let mut shared_d_bytes = [0u8; 32];
        shared_d_bytes[0..8].copy_from_slice(&d_word.to_le_bytes());
        // Force d[8..32] = 0 so the decoder's canonical-padding check
        // holds even if d_word were to set bits 56..64 (62-bit mask
        // above keeps bit 62+ zero so d_bytes[7] can only have bits
        // 0..5 set; bits 56..63 stay zero which is fine).
        debug_assert!(shared_d_bytes[11..].iter().all(|b| *b == 0));

        // Phase 4b-step3-step5a-wire: compute `shared_ivk_commitment`
        // from the 32-byte FVK-mirror `shared_ivk` + 11-byte diversifier
        // prefix via the existing helper. For the fixture all spends
        // share (ivk, d), so all spends share ivk_commitment too. The
        // AIR still reads `first_u64_proxy(&s.ivk_commitment)` for the
        // legacy single-perm claim until step 5c.
        let mut shared_ivk_commitment_bytes = [0u8; 32];
        shared_ivk_commitment_bytes[0..8]
            .copy_from_slice(&ivkcm.as_canonical_u64().to_le_bytes());

        // Build spends; all share the path so the anchor is identical per
        // spend. Only `nk` differs for distinct nullifiers.
        let mut spends = Vec::with_capacity(n_spends);
        for i in 0..n_spends {
            let s = seed
                .wrapping_mul(0x517c_c1b7_2722_0a95)
                .wrapping_add((i as u64) * 0xC0FF_EE00);
            let nk = s.wrapping_mul(0xcbf2_9ce4_8422_2325) ^ 0xba11_00ba;
            // Phase 4b-step3-step0: widened fields take `[u8; 32]`.
            // For this deterministic_valid test fixture, project the
            // legacy u64 proxy into `bytes[0..8]` with zero padding;
            // the AIR reads `first_u64_proxy(&field)` internally, so
            // the derived u64 is identical to pre-step0 behaviour.
            let mut ivk_bytes = [0u8; 32];
            ivk_bytes[0..8].copy_from_slice(&shared_ivk.to_le_bytes());
            let mut pk_d_bytes = [0u8; 32];
            pk_d_bytes[0..8].copy_from_slice(&shared_pk_d.to_le_bytes());
            let mut rcm_bytes = [0u8; 32];
            rcm_bytes[0..8].copy_from_slice(&shared_rcm.to_le_bytes());
            let mut nk_bytes = [0u8; 32];
            nk_bytes[0..8].copy_from_slice(&nk.to_le_bytes());
            // Phase 4b-step3-step5c-sponge: spend leaf now matches the
            // 15-fe iterated Poseidon2-w=16 sponge output (4 fes → 32 B
            // via LE u64 packing). Pre-step-5c this was the low 8 bytes
            // of the legacy single-perm `poseidon2_cm(...)` — that
            // digest does NOT equal the sponge output, so the AIR's
            // bank-2 closure `shared_cm_out[0..4] == S_LEAF_FE[0..4]`
            // would trip. The sponge output IS `compute_note_commitment`
            // byte-for-byte.
            let sponge_leaf_fes = poseidon2_cm_full_sponge(
                &perm16,
                &shared_d_bytes,
                &pk_d_bytes,
                &shared_ivk_commitment_bytes,
                v_per_spend,
                &rcm_bytes,
            );
            let mut leaf_bytes = [0u8; 32];
            for k in 0..4 {
                leaf_bytes[k * 8..(k + 1) * 8]
                    .copy_from_slice(&sponge_leaf_fes[k].as_canonical_u64().to_le_bytes());
            }
            spends.push(SpendWitness {
                leaf: leaf_bytes,
                d: shared_d_bytes,
                value: v_per_spend,
                ivk: ivk_bytes,
                pk_d: pk_d_bytes,
                ivk_commitment: shared_ivk_commitment_bytes,
                rcm: rcm_bytes,
                nk: nk_bytes,
                pos: shared_pos,
                merkle_path: shared_path_bytes,
                rk_bytes: [0u8; 32],
            });
        }

        // Balance: Σ spends = n_s · v_per_spend; distribute across outputs.
        let total_in: u128 = (n_spends as u128) * (v_per_spend as u128);
        assert!(total_in > fee as u128, "test seed produced unpayable fee");
        let total_out: u128 = total_in - (fee as u128);
        let v_per_out_base: u64 = (total_out / (n_outputs as u128)) as u64;
        let remainder: u64 = (total_out - (v_per_out_base as u128) * (n_outputs as u128)) as u64;

        let mut outputs = Vec::with_capacity(n_outputs);
        for j in 0..n_outputs {
            let s = seed
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add((j as u64) * 0xDEAD_BEEF);
            let d = s.wrapping_mul(0xc2b2_ae3d_27d4_eb4f) ^ 0x1efb_e1ed;
            let pk_d = s.wrapping_mul(0x1656_67b1_9e37_79f9) ^ 0xdeca_d0de;
            let rcm = s.wrapping_mul(0xd6e8_feb8_6659_fd93) ^ 0xfade_cafe;
            let ivk_commitment = s.wrapping_mul(0xcbf2_9ce4_8422_2325) ^ 0xba11_00ba;
            let value = if j + 1 == n_outputs {
                v_per_out_base + remainder
            } else {
                v_per_out_base
            };
            // Phase 4b-step3-step0: widen u64 proxies to [u8; 32] with
            // 8-byte low-limb projection + 24-byte zero padding (test
            // fixture convention; real tosctl witnesses carry full
            // 32-byte material).
            let mut d_bytes = [0u8; 32];
            d_bytes[0..8].copy_from_slice(&d.to_le_bytes());
            let mut pk_d_bytes = [0u8; 32];
            pk_d_bytes[0..8].copy_from_slice(&pk_d.to_le_bytes());
            let mut ivk_commitment_bytes = [0u8; 32];
            ivk_commitment_bytes[0..8].copy_from_slice(&ivk_commitment.to_le_bytes());
            let mut rcm_bytes = [0u8; 32];
            rcm_bytes[0..8].copy_from_slice(&rcm.to_le_bytes());
            // Phase 4b-step3-step1.3-pi: synthesize cm_bytes from the
            // 15-fe iterated-sponge output so the AIR's new PI binding
            // (`O_CM_SPONGE_OUT[0..4] == PI[pi_cm(j) + 0..4]`) holds.
            // Pre-step-1.3 this fixture projected only `poseidon2_cm_fe`
            // (the OLD single-perm 6-input u64-proxy Poseidon2) into
            // cm_bytes[0..8], which diverges from the sponge output and
            // would break the round-trip here.
            let sponge_out = poseidon2_cm_full_sponge(
                &perm16,
                &d_bytes,
                &pk_d_bytes,
                &ivk_commitment_bytes,
                value,
                &rcm_bytes,
            );
            let mut cm_bytes = [0u8; 32];
            for k in 0..4 {
                cm_bytes[k * 8..(k + 1) * 8]
                    .copy_from_slice(&sponge_out[k].as_canonical_u64().to_le_bytes());
            }
            outputs.push(OutputWitness {
                d: d_bytes,
                pk_d: pk_d_bytes,
                ivk_commitment: ivk_commitment_bytes,
                value,
                rcm: rcm_bytes,
                cm_bytes,
                epk_bytes: [0u8; 32],
                filter_tag: 0,
            });
        }

        // Phase 4b-step3-step3a: compute `anchor_bytes` as the output
        // of the 4-fe Merkle walk (matching the AIR's post-step-3a
        // last-row binding `S_CURRENT_FE[0..4] == PI[PI_ANCHOR+0..4]`
        // where `PI[PI_ANCHOR+k] = encode_256(anchor_bytes)[k]`).
        // The low 8 bytes are no longer `shared_anchor.to_le_bytes()`
        // — that was the legacy single-u64-proxy walk, which is a
        // different digest; only the 4-fe walk matches the in-circuit
        // computation.
        //
        // We still pick a representative `s` from `spends` to thread
        // (leaf, pos, merkle_path) — all spends share the same path
        // per this fixture's convention.
        let leaf0_bytes = &spends[0].leaf;
        let path0 = &spends[0].merkle_path;
        let anchor_bytes = poseidon2_merkle_path_root_4fe_bytes(
            &perm,
            leaf0_bytes,
            shared_pos,
            path0,
        );

        Self {
            scheme_id: 0x01,
            chain_id: CHAIN_ID_TEST,
            expiry_block: EXPIRY_BLOCK_TEST,
            fee,
            spends,
            outputs,
            anchor_bytes,
        }
    }

    /// Wire-encode for FFI.
    ///
    /// Legacy layout (pre-tier-1):
    ///   `u8 n_s || u8 n_o || u64 fee ||`
    ///   `(u64 leaf || [8 B] d || u64 value || u64 ivk || u64 pk_d || u64 rcm
    ///    || u64 nk || u64 pos || u64 path[0..32]) × n_s ||`
    ///   `(u64 d || u64 pk_d || u64 ivk_commitment || u64 value || u64 rcm) × n_o ||`
    ///   `u64 anchor_proxy`.
    ///
    /// V1-3c-round-8 (tier-1) extended layout (this function):
    ///   `[32 B] anchor_bytes || u8 scheme_id || u32 chain_id || u64 expiry_block`  (trailer)
    ///   Each spend: `[32 B] rk_bytes` appended (stride +32).
    ///   Each output: `[32 B] cm_bytes || [32 B] epk_bytes || u16 filter_tag` appended (stride +66).
    ///
    /// M-P2 Phase 4b-step3-step0 widening (this revision): four spend
    /// fields (`ivk`, `pk_d`, `rcm`, `nk`) and four output fields (`d`,
    /// `pk_d`, `ivk_commitment`, `rcm`) move from `u64` (8 bytes each)
    /// to `[u8; 32]` (32 bytes each) so tosctl can pass real address
    /// material through instead of digest-reduced proxies. The AIR
    /// itself is unchanged in this commit — trace-gen extracts a u64
    /// proxy from `field[0..8]` (little-endian) at every existing
    /// Poseidon2 / Merkle call site.
    ///
    /// Per-spend bytes: `leaf(8) + d(8) + value(8) + pos(8) +
    ///   4·32 (ivk,pk_d,rcm,nk) + 8·MERKLE_DEPTH + 32 (rk_bytes) =
    ///   32 + 128 + 256 + 32 = 448 bytes` (was 352 pre-step0).
    /// Per-output bytes: `4·32 (d,pk_d,ivk_cm,rcm) + value(8) + cm(32)
    ///   + epk(32) + filter_tag(2) = 128 + 8 + 64 + 2 = 202 bytes`
    ///   (was 106 pre-step0).
    /// Trailer: `8 (anchor_proxy) + 32 (anchor_bytes) + 1 + 4 + 8 = 53 bytes`.
    /// Byte length: `10 (n_s+n_o+fee) + 448·n_s + 202·n_o + 53`.
    ///
    /// The extended layout is backwards-incompatible with the pre-step0
    /// callers; callers inside this crate and `tosctl/uno` are updated
    /// atomically. `decode()` enforces the new length. Wire blob is
    /// transient tosctl → Rust-prover FFI only (no C++ consumer;
    /// confirmed by the pre-commit Explore agent audit).
    pub fn encode(&self) -> Vec<u8> {
        // Per-spend: leaf(32) + d(32) + value(8) + ivk_commitment(32)
        //          + ivk(32) + pk_d(32) + rcm(32) + nk(32) + pos(8)
        //          + path(32*MERKLE_DEPTH) + rk_bytes(32)
        //          = 32 + 32 + 8 + 32 + 4·32 + 8 + 32·32 + 32 = 1296.
        // Phase 4b-step3-step2a widened leaf from u64 (8 B) to [u8;32]
        // (448 -> 472, +24 B/spend).
        // Phase 4b-step3-step3c widened per-level Merkle sibling from
        // u64 (8 B) to [u8;32] so tosctl can thread real 32-byte
        // sibling digests through. Net wire bump per spend:
        // (32-8)·MERKLE_DEPTH = 24·32 = +768 B (472 -> 1240).
        // Phase 4b-step3-step5a-wire widened `d` from `[u8; 8]` to
        // `[u8; 32]` (+24 B/spend) and added `ivk_commitment: [u8; 32]`
        // (+32 B/spend) so the spend-side cm sponge (step 5c) can
        // absorb the full 15-fe input (d_fes(2) + pk_d_fes(4) +
        // ivk_commitment_fes(4) + value(1) + rcm_fes(4)). Net bump
        // 1240 -> 1296 (+56 B/spend).
        const PER_SPEND: usize = 32 + 32 + 8 + 32 + 4 * 32 + 8 + 32 * MERKLE_DEPTH + 32;
        // Per-output: d(32) + pk_d(32) + ivk_cm(32) + value(8) + rcm(32)
        //           + cm(32) + epk(32) + filter_tag(2) = 202.
        const PER_OUTPUT: usize = 4 * 32 + 8 + 32 + 32 + 2;
        const HEAD: usize = 10;
        // Phase 4b-step3-step4: anchor_proxy (8 B) removed — PI anchor
        // limbs now come from the AIR's 4-fe Merkle walk via
        // S_CURRENT_FE[0..4]. TAIL: 53 → 45 B.
        const TAIL: usize = 32 + 1 + 4 + 8;
        let mut out = Vec::with_capacity(
            HEAD + PER_SPEND * self.spends.len() + PER_OUTPUT * self.outputs.len() + TAIL,
        );
        out.push(self.spends.len() as u8);
        out.push(self.outputs.len() as u8);
        out.extend_from_slice(&self.fee.to_le_bytes());
        for s in &self.spends {
            out.extend_from_slice(&s.leaf);
            out.extend_from_slice(&s.d);
            out.extend_from_slice(&s.value.to_le_bytes());
            out.extend_from_slice(&s.ivk);
            out.extend_from_slice(&s.pk_d);
            out.extend_from_slice(&s.ivk_commitment);
            out.extend_from_slice(&s.rcm);
            out.extend_from_slice(&s.nk);
            out.extend_from_slice(&s.pos.to_le_bytes());
            for sib in &s.merkle_path {
                out.extend_from_slice(sib);
            }
            out.extend_from_slice(&s.rk_bytes);
        }
        for o in &self.outputs {
            out.extend_from_slice(&o.d);
            out.extend_from_slice(&o.pk_d);
            out.extend_from_slice(&o.ivk_commitment);
            out.extend_from_slice(&o.value.to_le_bytes());
            out.extend_from_slice(&o.rcm);
            out.extend_from_slice(&o.cm_bytes);
            out.extend_from_slice(&o.epk_bytes);
            out.extend_from_slice(&o.filter_tag.to_le_bytes());
        }
        out.extend_from_slice(&self.anchor_bytes);
        out.push(self.scheme_id);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.expiry_block.to_le_bytes());
        out
    }

    /// Decode a witness from the wire format (tier-1 extended layout —
    /// see `encode()` doc for the field order).
    pub fn decode(bytes: &[u8]) -> Result<Self, Plonky3Status> {
        const HEAD: usize = 10;
        const TAIL: usize = 32 + 1 + 4 + 8; // anchor_bytes + scheme + chain + expiry
        // Must match `encode()` — see step5a-wire widening doc there.
        const PER_SPEND: usize = 32 + 32 + 8 + 32 + 4 * 32 + 8 + 32 * MERKLE_DEPTH + 32;
        const PER_OUTPUT: usize = 4 * 32 + 8 + 32 + 32 + 2;
        if bytes.len() < HEAD + TAIL {
            return Err(Plonky3Status::WitnessInvalid);
        }
        let n_s = bytes[0] as usize;
        let n_o = bytes[1] as usize;
        if n_s < MIN_SPENDS || n_s > MAX_SPENDS || n_o < MIN_OUTPUTS || n_o > MAX_OUTPUTS {
            return Err(Plonky3Status::WitnessInvalid);
        }
        let want = HEAD + PER_SPEND * n_s + PER_OUTPUT * n_o + TAIL;
        if bytes.len() != want {
            return Err(Plonky3Status::WitnessInvalid);
        }
        let fee = u64::from_le_bytes(bytes[2..10].try_into().unwrap());
        if fee >= GOLDILOCKS_P {
            return Err(Plonky3Status::WitnessInvalid);
        }

        let mut off = 10;
        let mut spends = Vec::with_capacity(n_s);
        for _ in 0..n_s {
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut d = [0u8; 32];
            d.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            // Phase 4b-step3-step5a-wire: reject non-canonical
            // diversifier, mirroring the output-side rejection added in
            // step 4c. The spend-side cm sponge (step 5c) consumes
            // `d[0..16]` via `pack_diversifier_as_2fe`; bytes
            // `d[11..32]` must be zero so the wire has a single
            // canonical representation and no claim can be forged for
            // a diversifier that has no 11-byte spec preimage.
            if d[11..].iter().any(|b| *b != 0) {
                return Err(Plonky3Status::WitnessInvalid);
            }
            let value = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            if value >= GOLDILOCKS_P {
                return Err(Plonky3Status::WitnessInvalid);
            }
            let mut ivk = [0u8; 32];
            ivk.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut pk_d = [0u8; 32];
            pk_d.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut ivk_commitment = [0u8; 32];
            ivk_commitment.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut rcm = [0u8; 32];
            rcm.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut nk = [0u8; 32];
            nk.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let pos = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            // `pos` must fit in MERKLE_DEPTH bits for the AIR's bit
            // decomposition to hold.
            if pos >= (1u64 << MERKLE_DEPTH) {
                return Err(Plonky3Status::WitnessInvalid);
            }
            let mut merkle_path = [[0u8; 32]; MERKLE_DEPTH];
            for sib in merkle_path.iter_mut() {
                sib.copy_from_slice(&bytes[off..off + 32]);
                off += 32;
            }
            let mut rk_bytes = [0u8; 32];
            rk_bytes.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            spends.push(SpendWitness {
                leaf,
                d,
                value,
                ivk,
                pk_d,
                ivk_commitment,
                rcm,
                nk,
                pos,
                merkle_path,
                rk_bytes,
            });
        }
        let mut outputs = Vec::with_capacity(n_o);
        for _ in 0..n_o {
            let mut d = [0u8; 32];
            d.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            // Phase 4b-step3-step4c: reject non-canonical diversifier.
            // C++ `compute_note_commitment` consumes an 11-byte diversifier
            // zero-padded to 16 B; `pack_diversifier_as_2fe` on this side
            // absorbs `d[0..16]` directly. Without this check a caller
            // could set `d[11..16]` to non-zero and produce a `cm` proof
            // for a diversifier that has no valid 11-B preimage — spec-
            // domain mismatch (Codex audit finding 2, doc/uno-phase4b-
            // step3-codex-audit.md). Bytes [16..32] are never absorbed
            // but we reject them too so the wire form has a single
            // canonical representation.
            if d[11..].iter().any(|b| *b != 0) {
                return Err(Plonky3Status::WitnessInvalid);
            }
            let mut pk_d = [0u8; 32];
            pk_d.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut ivk_commitment = [0u8; 32];
            ivk_commitment.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let value = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            if value >= GOLDILOCKS_P {
                return Err(Plonky3Status::WitnessInvalid);
            }
            let mut rcm = [0u8; 32];
            rcm.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut cm_bytes = [0u8; 32];
            cm_bytes.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut epk_bytes = [0u8; 32];
            epk_bytes.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let filter_tag = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
            off += 2;
            outputs.push(OutputWitness {
                d,
                pk_d,
                ivk_commitment,
                value,
                rcm,
                cm_bytes,
                epk_bytes,
                filter_tag,
            });
        }
        let mut anchor_bytes = [0u8; 32];
        anchor_bytes.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let scheme_id = bytes[off];
        off += 1;
        let chain_id = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        let expiry_block = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        debug_assert_eq!(off, bytes.len());

        Ok(Self {
            scheme_id,
            chain_id,
            expiry_block,
            fee,
            spends,
            outputs,
            anchor_bytes,
        })
    }

    /// Balance pre-check. Runs in u128 to dodge u64 overflow on sums of
    /// up to 4 u64 summands.
    pub fn balance_holds(&self) -> bool {
        let sin: u128 = self.spends.iter().map(|s| s.value as u128).sum();
        let sout: u128 = self.outputs.iter().map(|o| o.value as u128).sum();
        sin == sout + (self.fee as u128)
    }

    /// Derive public inputs per §4.3 step 4.
    ///
    /// Layout (per-element 8 B LE Goldilocks):
    /// ```text
    ///   [scheme_id, chain_id, expiry_block, fee]          (4 header scalars)
    ///   [anchor as 4 limbs — limb 0 = anchor_proxy]       (4 anchor limbs)
    ///   for each spend i:
    ///     [nf_i via 4-limb Poseidon2 nullifier]           (4 nf limbs)
    ///     [rk_i as 4 limbs — all zero in proxy AIR]       (4 rk limbs)
    ///   for each output j:
    ///     [cm_j via 1-limb proxy + 3 zeros]               (4 cm limbs)
    ///     [epk_j as 4 limbs — all zero in proxy AIR]      (4 epk limbs)
    ///     [filter_tag_j as u16 → 1 limb — zero in proxy]  (1 filter_tag)
    /// ```
    ///
    /// **V1-3c-round-8 (tier-1, 2026-04-22)**: this is a partial fix. The
    /// header scalars `scheme_id` / `chain_id` / `expiry_block` are now
    /// threaded from the witness (no more hardcoded `CHAIN_ID_TEST` /
    /// `EXPIRY_BLOCK_TEST`), which is the subset of PI slots that the
    /// proxy AIR does not constrain and therefore can be safely pinned
    /// to real values. The 256-bit slots (anchor, nf, cm, rk, epk,
    /// filter_tag) remain proxy-derived:
    ///
    /// * `anchor[0]` is bound by the AIR to `anchor_proxy` (derived via
    ///   the depth-32 Merkle walk over the witness). Setting it to
    ///   `encode_256(real_anchor)[0]` would break the AIR constraint
    ///   (real anchor ≠ proxy anchor under the current u64-proxy AIR).
    /// * Same for `cm[0]` (AIR-bound to `poseidon2_cm_fe(witness)`) and
    ///   `nf[0..4]` (AIR-bound to `poseidon2_nf_full(witness)`).
    /// * `rk`, `epk`, `filter_tag` are not AIR-bound but stay at zero
    ///   in this pass to keep wallet↔validator PI alignment self-
    ///   consistent with the proxy anchor/cm/nf; C++ validator produces
    ///   real values at those slots, so full byte parity is still a
    ///   **M-P2** responsibility (real 32-byte field-material AIR).
    ///
    /// **Tier-1 net effect for v1 launch**: closes the hardcoded-constant
    /// hazard for `scheme_id` / `chain_id` / `expiry_block`. Full
    /// Rust-prover ↔ C++ validator STARK verify parity still requires
    /// M-P2 (see `doc/uno-workchain.md §4.1` proxy-AIR notes).
    pub fn public_inputs(&self) -> Vec<Goldilocks> {
        let n_s = self.spends.len();
        let n_o = self.outputs.len();
        let mut out = Vec::with_capacity(air_num_public_values(n_s, n_o));

        out.push(Goldilocks::from_u64(self.scheme_id as u64));
        out.push(Goldilocks::from_u64(self.chain_id as u64));
        out.push(Goldilocks::from_u64(reduce_to_goldilocks(
            self.expiry_block,
        )));
        out.push(Goldilocks::from_u64(reduce_to_goldilocks(self.fee)));

        // anchor: Phase 4b-step2b — all 4 limbs now come from
        // witness.anchor_bytes[k*8..(k+1)*8] as u64 (mod p). The
        // Merkle-walk constraint (`last_row: S_CURRENT ==
        // G_ANCHOR_PROXY` per spend) still proves the walk lands on
        // `anchor_proxy` internally, but `PI[PI_ANCHOR + k]` is now
        // bound via row-0 copy-constraint to
        // `G_ANCHOR_LIMB{0_REAL,1,2,3}`. Matches C++'s
        // `pack_bits256_as_4_limbs(anchor)` / `encode_256` byte-for-
        // byte. See the module-level Phase 4b-step2 comments for the
        // documented soundness trade-off (Merkle consistency is now a
        // trace-only claim; the AIR no longer reveals the derived
        // anchor proxy on the PI wire).
        for k in 0..4 {
            let limb = u64::from_le_bytes(
                self.anchor_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
            );
            out.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
        }

        let perm16 = default_goldilocks_poseidon2_16();

        for s in &self.spends {
            // nf_i: 4-limb Poseidon2 nullifier (AIR-bound).
            // Phase 4b-step3-step2b-AIR: nf now derived from the real
            // 32-byte `nk` + 32-byte `leaf` (cm) + `pos` via a single
            // Poseidon2-w=16 permutation on shared-wide row 16+i, per
            // the AIR constraint block. Matches the C++ validator's
            // `derive_nullifier` which consumes the same 10-fe input.
            let nf_limbs = poseidon2_nf_full_wide(&perm16, &s.nk, &s.leaf, s.pos);
            for limb in nf_limbs {
                out.push(limb);
            }
            // rk_i: 4 u64 limbs of rk_bytes (LE), reduced mod Goldilocks.
            // Phase 4a AIR-bound to spend's S_RK_LIMB0..S_RK_LIMB0+4
            // proxy cols. Matches C++ validator `encode_256`.
            for k in 0..RK_EPK_LIMBS {
                let limb = u64::from_le_bytes(
                    s.rk_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
                );
                out.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
            }
        }

        for o in &self.outputs {
            // cm_j: Phase 4b-step2a — all 4 limbs now come from
            // witness.cm_bytes[k*8..(k+1)*8] as u64 (mod p). The
            // Poseidon2-w=16 proxy-derivation (poseidon2_cm_fe) still
            // constrains the `O_CM_CLAIM` trace column via the shared
            // wide block, but no longer drives PI. Matches C++'s
            // `pack_bits256_as_4_limbs(o.cm)` / `encode_256` output
            // byte-for-byte.
            for k in 0..4 {
                let limb = u64::from_le_bytes(
                    o.cm_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
                );
                out.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
            }
            // epk_j: 4 u64 limbs of epk_bytes (LE), reduced mod
            // Goldilocks. Phase 4a AIR-bound to output's
            // O_EPK_LIMB0..O_EPK_LIMB0+4 proxy cols.
            for k in 0..RK_EPK_LIMBS {
                let limb = u64::from_le_bytes(
                    o.epk_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
                );
                out.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
            }
            // filter_tag_j: 1 u16-wide field element. Phase 4a AIR-
            // bound to output's O_FILTER_TAG proxy col.
            out.push(Goldilocks::from_u64(o.filter_tag as u64));
        }

        debug_assert_eq!(out.len(), air_num_public_values(n_s, n_o));
        out
    }

    /// Serialize `public_inputs()` to the wire-byte format (8 B LE per FE).
    pub fn public_inputs_bytes(&self) -> Vec<u8> {
        let pis = self.public_inputs();
        let mut out = Vec::with_capacity(pis.len() * 8);
        for fe in pis {
            out.extend_from_slice(&fe.as_canonical_u64().to_le_bytes());
        }
        out
    }

    /// Generate the full trace matrix.
    pub fn generate_trace(&self) -> RowMajorMatrix<Goldilocks> {
        let n_s = self.spends.len();
        let n_o = self.outputs.len();
        let width = air_width(n_s, n_o);

        let perm = default_goldilocks_poseidon2_8();
        let perm16 = default_goldilocks_poseidon2_16();
        let constants_8 = RoundConstants::new(
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
        );
        let constants_16 = RoundConstants::new(
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_INITIAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_INTERNAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_FINAL,
        );
        let gen_p2_row = |input: [Goldilocks; POSEIDON2_WIDTH]| -> Vec<Goldilocks> {
            use p3_poseidon2_air::generate_trace_rows;
            let mat = generate_trace_rows::<
                Goldilocks,
                GenericPoseidon2LinearLayersGoldilocks,
                POSEIDON2_WIDTH,
                POSEIDON2_SBOX_DEGREE,
                POSEIDON2_SBOX_REGISTERS,
                POSEIDON2_HALF_FULL_ROUNDS,
                POSEIDON2_PARTIAL_ROUNDS,
            >(vec![input], &constants_8, 0);
            debug_assert_eq!(mat.values.len(), POSEIDON2_COLS_PER_INSTANCE);
            mat.values
        };
        let gen_p2_row_16 = |input: [Goldilocks; POSEIDON2_WIDTH_16]| -> Vec<Goldilocks> {
            use p3_poseidon2_air::generate_trace_rows;
            let mat = generate_trace_rows::<
                Goldilocks,
                GenericPoseidon2LinearLayersGoldilocks,
                POSEIDON2_WIDTH_16,
                POSEIDON2_SBOX_DEGREE,
                POSEIDON2_SBOX_REGISTERS,
                POSEIDON2_HALF_FULL_ROUNDS,
                POSEIDON2_PARTIAL_ROUNDS_16,
            >(vec![input], &constants_16, 0);
            debug_assert_eq!(mat.values.len(), POSEIDON2_COLS_PER_INSTANCE_16);
            mat.values
        };
        let padding_p2 = gen_p2_row([Goldilocks::ZERO; POSEIDON2_WIDTH]);
        let padding_p2_16 = gen_p2_row_16([Goldilocks::ZERO; POSEIDON2_WIDTH_16]);

        // K-air-col-share step 1: the 32 Merkle levels now share one
        // Poseidon2 column block per spend, placed on rows 0..31. We
        // pre-compute:
        //   - `merkle_rows[i][k]` (k ∈ 0..32): the permutation witness for
        //     spend `i`'s level-k compression (placed at trace row `k`).
        //   - `s_current_vals[i][row]` (row ∈ 0..TRACE_HEIGHT): the per-row
        //     running Merkle digest (row 0 = leaf; row k+1 = permutation
        //     output of level k; rows 32..63 latch the final value = anchor).
        //   - `row0_spend_ivkcm / _cm / _nf`: the single-row permutation
        //     witnesses for claims 3/2/4 (placed on trace row 0 only).
        let mut merkle_rows: Vec<Vec<Vec<Goldilocks>>> = Vec::with_capacity(n_s);
        // Phase 4b-step3-step3a: running Merkle digest is now 4-fe per
        // row. Previously `Vec<Vec<Goldilocks>>` (single-fe).
        let mut s_current_vals_fes: Vec<Vec<[Goldilocks; 4]>> = Vec::with_capacity(n_s);
        let mut row0_spend_ivkcm = Vec::with_capacity(n_s);
        for s in &self.spends {
            // Phase 4b-step3-step5a-wire: widened `d` from `[u8; 8]` to
            // `[u8; 32]`. Legacy `d_word` / `d_f` only feed the narrow
            // claim-3 IvkCm block below (w=8); the spend-side cm claim
            // now runs through the 15-fe iterated sponge (bank-1 on
            // row i, bank-2 on row 24+i — see step5c-sponge section
            // below).
            let d_word = first_u64_proxy(&s.d);
            let d_f = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
            // Phase 4b-step3-step0: widened fields → u64 proxy via
            // first_u64_proxy for the narrow claim-3 IvkCm block only.
            let ivk_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.ivk)));
            let _ = poseidon2_ivk_commitment(&perm, first_u64_proxy(&s.ivk), d_word);

            // Phase 4b-step3-step3a: 4-fe Merkle walk. Level k goes on
            // trace row k. Each level performs a Poseidon2-w=8
            // `(left[4] ‖ right[4]) → out[4]` compression with `left` /
            // `right` selected by path bit `(pos >> k) & 1`. State is
            // decomposed as `pack_32b_as_4fe` throughout.
            let leaf_fes: [Goldilocks; 4] = pack_32b_as_4fe(&s.leaf);
            let mut cur_state: [Goldilocks; 4] = leaf_fes;
            let mut per_spend_merkle = Vec::with_capacity(TRACE_HEIGHT);
            let mut per_spend_current_fes: Vec<[Goldilocks; 4]> =
                Vec::with_capacity(TRACE_HEIGHT);
            per_spend_current_fes.push(cur_state);
            for k in 0..MERKLE_DEPTH {
                let bit = (s.pos >> k) & 1;
                let sib_fes: [Goldilocks; 4] = pack_32b_as_4fe(&s.merkle_path[k]);
                let (left, right) = if bit == 0 {
                    (cur_state, sib_fes)
                } else {
                    (sib_fes, cur_state)
                };
                let mut input = [Goldilocks::ZERO; POSEIDON2_WIDTH];
                for m in 0..4 {
                    input[m] = left[m];
                }
                for m in 0..4 {
                    input[4 + m] = right[m];
                }
                let mut state = input;
                perm.permute_mut(&mut state);
                per_spend_merkle.push(gen_p2_row(input));
                cur_state = [state[0], state[1], state[2], state[3]];
                per_spend_current_fes.push(cur_state);
            }
            // Latch rows 32..63: pad P2 with zero-input permutation, and
            // hold the 4-fe running digest at the final anchor value.
            while per_spend_merkle.len() < TRACE_HEIGHT {
                per_spend_merkle.push(padding_p2.clone());
            }
            while per_spend_current_fes.len() < TRACE_HEIGHT {
                per_spend_current_fes.push(cur_state);
            }
            debug_assert_eq!(per_spend_merkle.len(), TRACE_HEIGHT);
            debug_assert_eq!(per_spend_current_fes.len(), TRACE_HEIGHT);
            merkle_rows.push(per_spend_merkle);
            s_current_vals_fes.push(per_spend_current_fes);

            let mut ivkcm_in = [Goldilocks::ZERO; POSEIDON2_WIDTH];
            ivkcm_in[0] = Goldilocks::from_u64(TAG_IVK_CM);
            ivkcm_in[1] = ivk_f;
            ivkcm_in[2] = d_f;
            row0_spend_ivkcm.push(gen_p2_row(ivkcm_in));
        }

        // Phase 4b-step3-step5c-sponge: spend cm iterated-sponge witness
        // per spend. Bank-1 lives on shared_cm row i, bank-2 on row
        // 24+i. Mirror of the output cm sponge (step 1.2a) and nf
        // sponge (step 2b-AIR-v2), with the 15-fe input per §3.2:
        //
        //   fes[0..1]   = d   (pack_diversifier_as_2fe)
        //   fes[2..5]   = pk_d            (pack_32b_as_4fe)
        //   fes[6..9]   = ivk_commitment  (pack_32b_as_4fe)
        //   fes[10]     = value
        //   fes[11..14] = rcm             (pack_32b_as_4fe)
        //
        //   Bank 1: state[0..8]  = fes[0..8]
        //           state[8..16] = uno_cm_v1_tag_block()
        //   Bank 2: state[0..7]  = bank1_out[0..7] + fes[8..14]
        //           state[7]     = bank1_out[7] + 1   (10* padding)
        //           state[8..16] = bank1_out[8..16]
        //
        // Output bank2[0..4] → S_LEAF / S_LEAF_FE1..3 (AIR-ratified in
        // step 5c-sponge closure). Byte-identical to
        // `poseidon2_cm_full_sponge(&perm16, &s.d, &s.pk_d, &s.ivk_commitment, s.value, &s.rcm)`.
        //
        // Bank-1 output rate + capacity captured for the per-spend
        // `S_CM_CARRY_{CAP,RATE}[0..8]` proxy cols; AIR constraints
        // then bind bank-2 inputs to those carried values + 10*
        // padding at slot 7 + fes[8..=14] absorb.
        let cm_tag_block_trace = uno_cm_v1_tag_block();
        let mut spend_cm_bank1: Vec<Vec<Goldilocks>> = Vec::with_capacity(n_s);
        let mut spend_cm_bank2: Vec<Vec<Goldilocks>> = Vec::with_capacity(n_s);
        let mut spend_cm_out_cap: Vec<[Goldilocks; 8]> = Vec::with_capacity(n_s);
        let mut spend_cm_out_rate: Vec<[Goldilocks; 8]> = Vec::with_capacity(n_s);
        for s in &self.spends {
            // Assemble the 15-fe input per §3.2.
            let d_fes = pack_diversifier_as_2fe(&s.d);
            let pk_d_fes = pack_32b_as_4fe(&s.pk_d);
            let ivk_cm_fes = pack_32b_as_4fe(&s.ivk_commitment);
            let value_fe = Goldilocks::from_u64(reduce_to_goldilocks(s.value));
            let rcm_fes = pack_32b_as_4fe(&s.rcm);
            let mut fes = [Goldilocks::ZERO; 15];
            fes[0] = d_fes[0];
            fes[1] = d_fes[1];
            fes[2..6].copy_from_slice(&pk_d_fes);
            fes[6..10].copy_from_slice(&ivk_cm_fes);
            fes[10] = value_fe;
            fes[11..15].copy_from_slice(&rcm_fes);

            // Bank 1 input: state[0..8] = fes[0..8], state[8..16] = tag_block.
            let mut bank1_in = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
            bank1_in[0..8].copy_from_slice(&fes[0..8]);
            bank1_in[8..16].copy_from_slice(&cm_tag_block_trace);
            spend_cm_bank1.push(gen_p2_row_16(bank1_in));

            // Post-perm-1 state (off-circuit; matches the Poseidon2-w=16
            // sub-AIR on row i).
            let mut state_after_perm1 = bank1_in;
            perm16.permute_mut(&mut state_after_perm1);

            // Save bank-1 output capacity for S_CM_CARRY_CAP[0..8].
            let mut out_cap = [Goldilocks::ZERO; 8];
            out_cap.copy_from_slice(&state_after_perm1[8..16]);
            spend_cm_out_cap.push(out_cap);
            // Save bank-1 output rate for S_CM_CARRY_RATE[0..8].
            let mut out_rate = [Goldilocks::ZERO; 8];
            out_rate.copy_from_slice(&state_after_perm1[0..8]);
            spend_cm_out_rate.push(out_rate);

            // Bank 2 input: bank1_output[0..7] += fes[8..14];
            //               bank1_output[7] += ONE (padding bit, rem=7);
            //               bank1_output[8..16] unchanged.
            let mut bank2_in = state_after_perm1;
            for j in 0..7 {
                bank2_in[j] = bank2_in[j] + fes[8 + j];
            }
            bank2_in[7] = bank2_in[7] + Goldilocks::from_u64(1);
            spend_cm_bank2.push(gen_p2_row_16(bank2_in));
        }

        // Phase 4b-step3-step2b-AIR-v2: nf iterated-sponge witness per
        // spend. Bank-1 lives on shared_cm row 16+i, bank-2 on row
        // 20+i. Mirror of the cm sponge (step 1.2a) with 9-fe input
        // instead of 15-fe:
        //
        //   Bank 1: state[0..8]  = (nk_fes[0..4], cm_fes[0..4])
        //           state[8..16] = pack_tag_block("uno-nf-v1")
        //   Bank 2: state[0]     = bank1_out[0] + pos
        //           state[1]     = bank1_out[1] + 1 (10* padding)
        //           state[2..8]  = bank1_out[2..8]
        //           state[8..16] = bank1_out[8..16]
        //
        // Output bank2[0..4] → PI[pi_nf(i) + 0..4]. Byte-identical to
        // `uno/crypto/poseidon2.cpp::derive_nullifier` and the codec-
        // parity helper `hash_tagged(b"uno-nf-v1", 9 fes)`.
        //
        // Bank-1 output rate + capacity captured for the per-spend
        // `S_NF_CARRY_{CAP,RATE}[0..8]` proxy cols; AIR constraints
        // then bind bank-2 inputs to those carried values + 10*
        // padding + pos absorb.
        let nf_tag_block = uno_nf_v1_tag_block();
        let mut spend_nf_bank1: Vec<Vec<Goldilocks>> = Vec::with_capacity(n_s);
        let mut spend_nf_bank2: Vec<Vec<Goldilocks>> = Vec::with_capacity(n_s);
        let mut spend_nf_out_cap: Vec<[Goldilocks; 8]> = Vec::with_capacity(n_s);
        let mut spend_nf_out_rate: Vec<[Goldilocks; 8]> = Vec::with_capacity(n_s);
        for s in &self.spends {
            let nk_fes = pack_32b_as_4fe(&s.nk);
            let leaf_fes = pack_32b_as_4fe(&s.leaf);
            // Bank 1 input: (nk_fes, leaf_fes) into rate slots; tag
            // block into capacity slots.
            let mut bank1_in = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
            bank1_in[0..4].copy_from_slice(&nk_fes);
            bank1_in[4..8].copy_from_slice(&leaf_fes);
            bank1_in[8..16].copy_from_slice(&nf_tag_block);
            spend_nf_bank1.push(gen_p2_row_16(bank1_in));

            // Bank-1 post-permutation state (off-circuit; matches what
            // the Poseidon2-w=16 sub-AIR emits on row 16+i).
            let mut state_after_perm1 = bank1_in;
            perm16.permute_mut(&mut state_after_perm1);

            let mut out_cap = [Goldilocks::ZERO; 8];
            out_cap.copy_from_slice(&state_after_perm1[8..16]);
            spend_nf_out_cap.push(out_cap);
            let mut out_rate = [Goldilocks::ZERO; 8];
            out_rate.copy_from_slice(&state_after_perm1[0..8]);
            spend_nf_out_rate.push(out_rate);

            // Bank 2 input: absorb pos at slot 0, ONE padding at slot 1,
            // rest of rate carried from bank1, capacity carried from
            // bank1.
            let mut bank2_in = state_after_perm1;
            bank2_in[0] = bank2_in[0] + Goldilocks::from_u64(reduce_to_goldilocks(s.pos));
            bank2_in[1] = bank2_in[1] + Goldilocks::ONE;
            spend_nf_bank2.push(gen_p2_row_16(bank2_in));
        }

        let mut row0_out_cm = Vec::with_capacity(n_o);
        for o in &self.outputs {
            // Phase 4b-step3-step0: widened output fields → u64 proxy.
            let d_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&o.d)));
            let pk_d_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&o.pk_d)));
            let ivk_cm_f =
                Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&o.ivk_commitment)));
            let rcm_f = Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&o.rcm)));
            let value_f = Goldilocks::from_u64(reduce_to_goldilocks(o.value));
            let mut cm_in = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
            cm_in[0] = Goldilocks::from_u64(TAG_CM);
            cm_in[1] = d_f;
            cm_in[2] = pk_d_f;
            cm_in[3] = ivk_cm_f;
            cm_in[4] = value_f;
            cm_in[5] = rcm_f;
            row0_out_cm.push(gen_p2_row_16(cm_in));
        }

        // Phase 4b-step3-step1.2a: pre-compute the Poseidon2-w=16
        // permutation witnesses for the 15-fe iterated sponge, one
        // per output. Each output j produces two permutations:
        //
        //   sponge_bank1_cm[j] — perm-1: state[0..7] = fes[0..8],
        //                        state[8..15] = tag_block. Placed on
        //                        trace row 8+j.
        //   sponge_bank2_cm[j] — perm-2: bank1.output with fes[8..14]
        //                        absorbed into slots 0..6 + ONE padding
        //                        at slot 7; state[8..15] unchanged from
        //                        bank1. Placed on trace row 12+j.
        //
        // These reuse the existing G_CM_SHARED_P2_16 column block (rows
        // 8..15 and 12..15 were `padding_p2_16` before this commit), so
        // no new global cols are added. The Poseidon2-w=16 AIR
        // constraints (`eval_poseidon2_16` on every row) apply uniformly
        // — any valid round-by-round witness satisfies them. Step
        // 1.2b+ will add row-gated constraints that bind bank1 inputs
        // to the 15-fe absorption layout and bank2 output to
        // `O_CM_SPONGE_OUT[0..4]`; today this commit just fills the
        // trace cells.
        let tag_block = uno_cm_v1_tag_block();
        let mut sponge_bank1_cm: Vec<Vec<Goldilocks>> = Vec::with_capacity(n_o);
        let mut sponge_bank2_cm: Vec<Vec<Goldilocks>> = Vec::with_capacity(n_o);
        // Phase 4b-step3-step1.2d: save bank-1 output capacity
        // (state[8..16] after perm-1) per output so the output proxy
        // block can carry it via `O_SPONGE_CARRY_CAP[0..8]`.
        let mut sponge_bank1_out_cap: Vec<[Goldilocks; 8]> = Vec::with_capacity(n_o);
        // Phase 4b-step3-step1.2f: save bank-1 output rate slots
        // (state[0..8] after perm-1) per output so the output proxy
        // block can carry them via `O_SPONGE_CARRY_RATE[0..8]`.
        let mut sponge_bank1_out_rate: Vec<[Goldilocks; 8]> = Vec::with_capacity(n_o);
        for o in &self.outputs {
            // Assemble the 15-fe input per §3.2.
            let d_fes = pack_diversifier_as_2fe(&o.d);
            let pk_d_fes = pack_32b_as_4fe(&o.pk_d);
            let ivk_cm_fes = pack_32b_as_4fe(&o.ivk_commitment);
            let value_fe = Goldilocks::from_u64(reduce_to_goldilocks(o.value));
            let rcm_fes = pack_32b_as_4fe(&o.rcm);
            let mut fes = [Goldilocks::ZERO; 15];
            fes[0] = d_fes[0];
            fes[1] = d_fes[1];
            fes[2..6].copy_from_slice(&pk_d_fes);
            fes[6..10].copy_from_slice(&ivk_cm_fes);
            fes[10] = value_fe;
            fes[11..15].copy_from_slice(&rcm_fes);

            // Bank 1 input: state[0..7] = fes[0..8], state[8..15] = tag_block.
            let mut bank1_in = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
            bank1_in[0..8].copy_from_slice(&fes[0..8]);
            bank1_in[8..16].copy_from_slice(&tag_block);
            sponge_bank1_cm.push(gen_p2_row_16(bank1_in));

            // Post-perm-1 state (off-circuit, matches the Poseidon2Cols
            // `ending_full_rounds[last].post` field in trace).
            let mut state_after_perm1 = bank1_in;
            perm16.permute_mut(&mut state_after_perm1);

            // Save bank-1 output capacity for carry-col population.
            let mut out_cap = [Goldilocks::ZERO; 8];
            out_cap.copy_from_slice(&state_after_perm1[8..16]);
            sponge_bank1_out_cap.push(out_cap);
            // Save bank-1 output rate slots for carry-col population
            // (step 1.2f).
            let mut out_rate = [Goldilocks::ZERO; 8];
            out_rate.copy_from_slice(&state_after_perm1[0..8]);
            sponge_bank1_out_rate.push(out_rate);

            // Bank 2 input: bank1_output[0..6] += fes[8..14];
            //               bank1_output[7] += ONE (padding, rem=7);
            //               bank1_output[8..15] unchanged.
            let mut bank2_in = state_after_perm1;
            for j in 0..7 {
                bank2_in[j] = bank2_in[j] + fes[8 + j];
            }
            bank2_in[7] = bank2_in[7] + Goldilocks::from_u64(1);
            sponge_bank2_cm.push(gen_p2_row_16(bank2_in));
        }

        // Per-spend proxy vector: [leaf, d, value, ivk, ivk_cm_claim, pk_d,
        // rcm, nk, pos, path_bits[0..32], siblings[0..32],
        // value_bits[0..64]].
        let spend_proxies: Vec<Vec<Goldilocks>> = self
            .spends
            .iter()
            .enumerate()
            .map(|(i, s)| {
                // Phase 4b-step3-step5a-wire: widened `d` → [u8; 32].
                // Low 8 bytes via `first_u64_proxy` remain the legacy
                // AIR input until step 5c.
                let d_word = first_u64_proxy(&s.d);
                let d_f = Goldilocks::from_u64(reduce_to_goldilocks(d_word));
                let ivkcm_fe = poseidon2_ivk_commitment(&perm, first_u64_proxy(&s.ivk), d_word);
                let mut v = Vec::with_capacity(SPEND_PROXY_COLS);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.leaf))));
                v.push(d_f);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.value)));
                // Phase 4b-step3-step0: widened u64 proxy extraction
                // from witness byte arrays.
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.ivk))));
                v.push(ivkcm_fe);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.pk_d))));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.rcm))));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(first_u64_proxy(&s.nk))));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(s.pos)));
                for k in 0..MERKLE_DEPTH {
                    let bit = (s.pos >> k) & 1;
                    v.push(Goldilocks::from_u64(bit));
                }
                // Phase 4b-step3-step3a: 4 fes per level via
                // `pack_32b_as_4fe(&s.merkle_path[k])`. Was 1 u64-proxy
                // per level pre-step-3a. Total sibling cols:
                // `MERKLE_DEPTH · SIBLING_FES_PER_LEVEL = 32 · 4 = 128`.
                for k in 0..MERKLE_DEPTH {
                    let sib_fes = pack_32b_as_4fe(&s.merkle_path[k]);
                    for m in 0..SIBLING_FES_PER_LEVEL {
                        v.push(sib_fes[m]);
                    }
                }
                // Decompose value into VALUE_LIMBS_U16 = 4 u16 limbs
                // (low-to-high). Phase 3b-step2: was 64 bit columns.
                let value_canon = reduce_to_goldilocks(s.value);
                for k in 0..VALUE_LIMBS_U16 {
                    let limb = (value_canon >> (16 * k)) & 0xffff;
                    v.push(Goldilocks::from_u64(limb));
                }
                // Phase 4a: 4 u64 limbs from rk_bytes (LE), each reduced
                // mod Goldilocks. Matches C++ `encode_256` — consensus-
                // binding byte-for-byte with validator PI.
                for k in 0..RK_EPK_LIMBS {
                    let limb = u64::from_le_bytes(
                        s.rk_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
                    );
                    v.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
                }
                // Phase 4b-step3-step2b-decomp: 6 upper-fe proxy cols
                // (3 each for nk + leaf) + 32 u16 limb cols (4 fes ×
                // 4 u16 × 2 fields). Spend-side mirror of the output-
                // side step 1.3-fields block. Low fes (`S_NK`, `S_LEAF`)
                // are already pushed above at `S_NK` / `S_LEAF`
                // positions; only the upper 3 fes per field are pushed
                // here. The u16 limb blocks decompose ALL 4 fes per
                // field (so the AIR can bind the existing low-fe proxy
                // col to its limbs too).
                let nk_fes = pack_32b_as_4fe(&s.nk);
                let leaf_fes = pack_32b_as_4fe(&s.leaf);
                // S_NK_FE1..3 (upper 3 fes of nk).
                v.push(nk_fes[1]);
                v.push(nk_fes[2]);
                v.push(nk_fes[3]);
                // S_LEAF_FE1..3 (upper 3 fes of leaf).
                v.push(leaf_fes[1]);
                v.push(leaf_fes[2]);
                v.push(leaf_fes[3]);
                // S_NK_LIMB0..15: 4 fes × 4 u16 (LE, low→high).
                let push_u16_limbs = |v: &mut Vec<Goldilocks>, fe: Goldilocks| {
                    let u = fe.as_canonical_u64();
                    for k in 0..4 {
                        let limb = (u >> (16 * k)) & 0xffff;
                        v.push(Goldilocks::from_u64(limb));
                    }
                };
                for k in 0..4 {
                    push_u16_limbs(&mut v, nk_fes[k]);
                }
                // S_LEAF_LIMB0..15: 4 fes × 4 u16 (LE, low→high).
                for k in 0..4 {
                    push_u16_limbs(&mut v, leaf_fes[k]);
                }
                // Phase 4b-step3-step2b-AIR-v2: S_NF_CARRY_CAP[0..8] —
                // bank-1 Poseidon2-w=16 output capacity slots. AIR
                // constraint on row 16+i pins these to bank-1.post[8+k];
                // row 20+i pins bank-2.inputs[8+k] to them. Carries the
                // capacity across the 4-row gap between bank-1 (row
                // 16+i) and bank-2 (row 20+i).
                for fe in spend_nf_out_cap[i].iter() {
                    v.push(*fe);
                }
                // Phase 4b-step3-step2b-AIR-v2: S_NF_CARRY_RATE[0..8] —
                // bank-1 post-permutation rate slots, carried so bank-2
                // inputs[0..8] can be constrained as
                //   bank-2.inputs[k] = carry_rate[k] + absorb_term_k
                // where absorb_term is (pos, ONE, 0*6).
                for fe in spend_nf_out_rate[i].iter() {
                    v.push(*fe);
                }
                // Phase 4b-step3-step5b-decomp: 11 new fe-limb cols
                // for the spend cm sponge input (d×2 + pk_d×4 +
                // ivk_cm×4 + rcm×4 = 14 fe-limbs; `S_D` / `S_PK_D` /
                // `S_RCM` already hold the low fe of d / pk_d / rcm,
                // so only 3 × 3 = 9 upper fes + 2 d/ivkcm new cols
                // are pushed here. `S_IVK_COMMITMENT_FE0..3` are all
                // new — the legacy `S_IVK_COMMITMENT_CLAIM` col is
                // the narrow-claim-3 output, a different field).
                // Mirror of the output-side step 1.2c/f fe-limb pushes.
                let d_fes = pack_diversifier_as_2fe(&s.d);
                let pk_d_fes = pack_32b_as_4fe(&s.pk_d);
                let ivk_cm_fes = pack_32b_as_4fe(&s.ivk_commitment);
                let rcm_fes = pack_32b_as_4fe(&s.rcm);
                // S_D_FE1 (d fe[1]).
                v.push(d_fes[1]);
                // S_PK_D_FE1..3 (pk_d fes[1..4]).
                v.push(pk_d_fes[1]);
                v.push(pk_d_fes[2]);
                v.push(pk_d_fes[3]);
                // S_IVK_COMMITMENT_FE0..3 (all 4 fes of ivk_commitment).
                v.push(ivk_cm_fes[0]);
                v.push(ivk_cm_fes[1]);
                v.push(ivk_cm_fes[2]);
                v.push(ivk_cm_fes[3]);
                // S_RCM_FE1..3 (rcm fes[1..4]).
                v.push(rcm_fes[1]);
                v.push(rcm_fes[2]);
                v.push(rcm_fes[3]);
                // Phase 4b-step3-step5b-decomp: 56 u16 limb cols
                // (d×8 + pk_d×16 + ivk_cm×16 + rcm×16). Same
                // `push_u16_limbs` helper as the nk/leaf block above.
                // d: 2 fe-limbs × 4 u16 = 8 cols (S_D_LIMB0..7).
                push_u16_limbs(&mut v, d_fes[0]);
                push_u16_limbs(&mut v, d_fes[1]);
                // pk_d: 4 fe-limbs × 4 u16 = 16 cols.
                for k in 0..4 {
                    push_u16_limbs(&mut v, pk_d_fes[k]);
                }
                // ivk_commitment: 4 fe-limbs × 4 u16 = 16 cols.
                for k in 0..4 {
                    push_u16_limbs(&mut v, ivk_cm_fes[k]);
                }
                // rcm: 4 fe-limbs × 4 u16 = 16 cols.
                for k in 0..4 {
                    push_u16_limbs(&mut v, rcm_fes[k]);
                }
                // Phase 4b-step3-step5c-sponge: S_CM_CARRY_CAP[0..8] —
                // bank-1 Poseidon2-w=16 output capacity slots. AIR
                // constraint on row i pins these to bank-1.post[8+k];
                // row 24+i pins bank-2.inputs[8+k] to them. Carries the
                // capacity across the 24-row gap via the proxies-are-
                // constant invariant.
                for fe in spend_cm_out_cap[i].iter() {
                    v.push(*fe);
                }
                // Phase 4b-step3-step5c-sponge: S_CM_CARRY_RATE[0..8] —
                // bank-1 post-permutation rate slots. Row i pins these
                // to bank-1.post[0..8]; row 24+i uses them as the
                // "bank-1 out term" in bank-2's input-absorb addition
                // `bank-2.inputs[k] = carry_rate[k] + absorb_term_k`.
                for fe in spend_cm_out_rate[i].iter() {
                    v.push(*fe);
                }
                debug_assert_eq!(v.len(), SPEND_PROXY_COLS);
                v
            })
            .collect();

        let output_proxies: Vec<Vec<Goldilocks>> = self
            .outputs
            .iter()
            .enumerate()
            .map(|(j, o)| {
                // Phase 4b-step3-step0: widened output fields → u64
                // proxy for Poseidon2 input; cm derivation shape
                // unchanged.
                let d_p = first_u64_proxy(&o.d);
                let pk_d_p = first_u64_proxy(&o.pk_d);
                let ivkcm_p = first_u64_proxy(&o.ivk_commitment);
                let rcm_p = first_u64_proxy(&o.rcm);
                let cm_fe =
                    poseidon2_cm_fe(&perm16, d_p, pk_d_p, ivkcm_p, o.value, rcm_p);
                let mut v = Vec::with_capacity(OUTPUT_PROXY_COLS);
                v.push(cm_fe);
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(d_p)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(pk_d_p)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(ivkcm_p)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(o.value)));
                v.push(Goldilocks::from_u64(reduce_to_goldilocks(rcm_p)));
                // Phase 3b-step2: 4 u16 limbs (was 64 bit columns).
                let value_canon = reduce_to_goldilocks(o.value);
                for k in 0..VALUE_LIMBS_U16 {
                    let limb = (value_canon >> (16 * k)) & 0xffff;
                    v.push(Goldilocks::from_u64(limb));
                }
                // Phase 4a: 4 u64 limbs of epk_bytes (LE), + 1 filter_tag
                // column. All reduced mod Goldilocks; matches C++
                // `encode_256` + the u16 `filter_tag` PI encoding.
                for k in 0..RK_EPK_LIMBS {
                    let limb = u64::from_le_bytes(
                        o.epk_bytes[k * 8..(k + 1) * 8].try_into().unwrap(),
                    );
                    v.push(Goldilocks::from_u64(reduce_to_goldilocks(limb)));
                }
                v.push(Goldilocks::from_u64(o.filter_tag as u64));
                // Phase 4b-step3-step1.1: O_CM_SPONGE_OUT[0..4] — the
                // 4-fe digest produced by the 15-fe iterated Poseidon2
                // sponge over the widened witness fields. AIR-bound
                // by step1.2e to bank-2 output on row 12+j.
                let sponge_out =
                    poseidon2_cm_full_sponge(&perm16, &o.d, &o.pk_d, &o.ivk_commitment, o.value, &o.rcm);
                for fe in &sponge_out {
                    v.push(*fe);
                }
                // Phase 4b-step3-step1.2d: O_SPONGE_CARRY_CAP[0..8] —
                // bank-1 Poseidon2-w=16 output capacity (state[8..16]
                // after perm-1). AIR constraint on row 8+j pins this
                // col to bank-1.post[8+k]; row 12+j pins bank-2.inputs
                // [8+k] to this col. Together with the output-proxy
                // "constant across rows" transition invariant, this
                // carries the capacity across the 4-row gap between
                // the two sponge permutations without cross-row AIR
                // access.
                for fe in sponge_bank1_out_cap[j].iter() {
                    v.push(*fe);
                }
                // Phase 4b-step3-step1.2c: upper fe limbs of d, pk_d,
                // and ivk_commitment that bank-1 absorbs into its rate
                // slots 1, 3, 4, 5, 7 on row 8+j. These 5 cols
                // complement the existing single-fe proxies
                // (`O_D`, `O_PK_D`, `O_IVK_COMMITMENT`) so that the
                // full 8-fe bank-1 input matches the iterated-sponge
                // layout per §4.1:
                //   inputs[0..=1] = d_fes[0..=1]
                //   inputs[2..=5] = pk_d_fes[0..=3]
                //   inputs[6..=7] = ivk_cm_fes[0..=1]
                // Trace-gen uses the same `pack_*_as_*fe` helpers as
                // `poseidon2_cm_full_sponge`, so the column values are
                // byte-identical to what bank-1 absorbs on row 8+j.
                let d_fes = pack_diversifier_as_2fe(&o.d);
                let pk_d_fes = pack_32b_as_4fe(&o.pk_d);
                let ivk_cm_fes = pack_32b_as_4fe(&o.ivk_commitment);
                let rcm_fes = pack_32b_as_4fe(&o.rcm);
                v.push(d_fes[1]);
                v.push(pk_d_fes[1]);
                v.push(pk_d_fes[2]);
                v.push(pk_d_fes[3]);
                v.push(ivk_cm_fes[1]);
                // Phase 4b-step3-step1.2f: upper fe limbs of
                // ivk_commitment and rcm that bank-2 absorbs into its
                // rate slots on row 12+j. Combined with `O_VALUE` and
                // `O_RCM` (== rcm_fes[0]), these complete the
                // bank-2 absorb layout fes[8..=14].
                v.push(ivk_cm_fes[2]);
                v.push(ivk_cm_fes[3]);
                v.push(rcm_fes[1]);
                v.push(rcm_fes[2]);
                v.push(rcm_fes[3]);
                // Phase 4b-step3-step1.2f: bank-1 output rate slots
                // (state[0..8] after perm-1) carried forward to row
                // 12+j as the "bank-1 output term" in bank-2's input
                // absorb addition.
                for fe in sponge_bank1_out_rate[j].iter() {
                    v.push(*fe);
                }
                // Phase 4b-step3-step1.3-fields: decompose each of the
                // 14 output fe-limb proxy cols (d[0..2], pk_d[0..4],
                // ivk_cm[0..4], rcm[0..4]) into 4 u16 limbs (LE,
                // low-to-high). The AIR eval binds each fe-limb col to
                // `Σ_k limb_k · 2^{16k}` and the cross-AIR `u16_range`
                // LogUp bounds each limb to `0..=0xffff`, closing the
                // step 1.2c/f decoupling gap: the prover can no longer
                // pick non-canonical Goldilocks values for the sponge
                // rate slots — each fe-limb must be the canonical
                // u64 of the corresponding 8-byte LE chunk.
                //
                // Note `O_VALUE` already has its own 4-limb
                // decomposition at `O_VALUE_LIMB0..3` (Phase 3b-step2),
                // so fes[10] (== `O_VALUE`) is NOT duplicated here.
                let push_u16_limbs = |v: &mut Vec<Goldilocks>, fe: Goldilocks| {
                    let u = fe.as_canonical_u64();
                    for k in 0..4 {
                        let limb = (u >> (16 * k)) & 0xffff;
                        v.push(Goldilocks::from_u64(limb));
                    }
                };
                // d_fes[0..2]  (2 fe-limbs × 4 u16 = 8 cols)
                push_u16_limbs(&mut v, d_fes[0]);
                push_u16_limbs(&mut v, d_fes[1]);
                // pk_d_fes[0..4]  (4 fe-limbs × 4 u16 = 16 cols)
                for k in 0..4 {
                    push_u16_limbs(&mut v, pk_d_fes[k]);
                }
                // ivk_cm_fes[0..4]  (4 fe-limbs × 4 u16 = 16 cols)
                for k in 0..4 {
                    push_u16_limbs(&mut v, ivk_cm_fes[k]);
                }
                // rcm_fes[0..4]  (4 fe-limbs × 4 u16 = 16 cols)
                for k in 0..4 {
                    push_u16_limbs(&mut v, rcm_fes[k]);
                }
                debug_assert_eq!(v.len(), OUTPUT_PROXY_COLS);
                v
            })
            .collect();

        let fee_f = Goldilocks::from_u64(self.fee);

        let mut values = Vec::<Goldilocks>::with_capacity(TRACE_HEIGHT * width);
        for row_idx in 0..TRACE_HEIGHT {
            // Global cols: fee + 32 one-hot Merkle row selectors.
            values.push(fee_f);
            for k in 0..MERKLE_DEPTH {
                let bit = if row_idx < MERKLE_DEPTH && row_idx == k {
                    1
                } else {
                    0
                };
                values.push(Goldilocks::from_u64(bit));
            }

            // Globally-shared Cm/OutCm (w=16) block:
            //   row i (i ∈ 0..n_s): spend i's cm sponge bank-1 (step 5c)
            //   row 4+j (j ∈ 0..n_o): output j's claim-6 witness
            //   row 8+j (j ∈ 0..n_o): output j's sponge perm-1 (step 1.2a)
            //   row 12+j (j ∈ 0..n_o): output j's sponge perm-2 (step 1.2a)
            //   row 16+i (i ∈ 0..n_s): spend i's nf sponge bank-1 (step 2b-AIR-v2)
            //   row 20+i (i ∈ 0..n_s): spend i's nf sponge bank-2 (step 2b-AIR-v2)
            //   row 24+i (i ∈ 0..n_s): spend i's cm sponge bank-2 (step 5c)
            //   else: zero-input permutation
            if row_idx < n_s {
                values.extend_from_slice(&spend_cm_bank1[row_idx]);
            } else if (4..4 + n_o).contains(&row_idx) {
                values.extend_from_slice(&row0_out_cm[row_idx - 4]);
            } else if (8..8 + n_o).contains(&row_idx) {
                values.extend_from_slice(&sponge_bank1_cm[row_idx - 8]);
            } else if (12..12 + n_o).contains(&row_idx) {
                values.extend_from_slice(&sponge_bank2_cm[row_idx - 12]);
            } else if (16..16 + n_s).contains(&row_idx) {
                values.extend_from_slice(&spend_nf_bank1[row_idx - 16]);
            } else if (20..20 + n_s).contains(&row_idx) {
                values.extend_from_slice(&spend_nf_bank2[row_idx - 20]);
            } else if (24..24 + n_s).contains(&row_idx) {
                values.extend_from_slice(&spend_cm_bank2[row_idx - 24]);
            } else {
                values.extend_from_slice(&padding_p2_16);
            }

            // Globally-shared IvkCm/Nf (w=8) block:
            //   row i (i ∈ 0..n_s): spend i's claim-3 (IvkCm) witness
            //   else: zero-input permutation (padding_p2)
            //
            // Phase 4b-step3-step2b-AIR: rows 4..(4+n_s-1) used to host
            // the narrow-nf (claim 4) witness; that derivation moved to
            // the wide-w=16 block on rows 16..(15+n_s) with real 4-fe
            // nk + 4-fe cm + pos inputs. Narrow rows 4+i now just carry
            // a zero-input Poseidon2 permutation witness which satisfies
            // the narrow sub-AIR trivially — the old constraint block
            // is deleted and `row0_spend_nf` (narrow) is no longer built.
            if row_idx < n_s {
                values.extend_from_slice(&row0_spend_ivkcm[row_idx]);
            } else {
                values.extend_from_slice(&padding_p2);
            }

            // Phase 4b-step3-step3a cleanup: Phase 4b-step1 / step2b
            // anchor-limb global cols (`G_ANCHOR_LIMB1..3`,
            // `G_ANCHOR_PROXY`, `G_ANCHOR_LIMB0_REAL`) retired. All 4
            // anchor-limb PI slots are now last-row-bound from the
            // 4-fe Merkle-walk digest `S_CURRENT_FE[0..4]`.

            // Per-spend block: proxies + S_CURRENT_FE[0..4] +
            // per-spend shared Merkle P2 row-loop.
            for i in 0..n_s {
                values.extend_from_slice(&spend_proxies[i]);
                let cur_fes = s_current_vals_fes[i][row_idx];
                for m in 0..4 {
                    values.push(cur_fes[m]);
                }
                values.extend_from_slice(&merkle_rows[i][row_idx]);
            }
            // Per-output block: proxies only (Cm moved to global block).
            for j in 0..n_o {
                values.extend_from_slice(&output_proxies[j]);
            }
        }

        debug_assert_eq!(values.len(), TRACE_HEIGHT * width);
        RowMajorMatrix::new(values, width)
    }
}

// ---------------------------------------------------------------------------
// Pre-check helpers (prover-side)
// ---------------------------------------------------------------------------
//
// Plonky3's `DebugConstraintBuilder` panics on inconsistent traces in
// debug builds. These helpers run the hard claim checks in plain Rust so
// the prover can reject with a structured `WitnessInvalid` status before
// ever invoking Plonky3. Identical checks as the AIR row-0 bindings —
// drift here silently accepts constraint-violating witnesses at debug
// build time, but release builds catch them at verify.

/// True iff for every spend, `pack_32b_as_4fe(&s.leaf) ==
/// poseidon2_cm_full_sponge(&s.d, &s.pk_d, &s.ivk_commitment, s.value,
/// &s.rcm)` — the 15-fe iterated sponge per §3.2 of `doc/uno-workchain.md`
/// and `compute_note_commitment` on the tosctl / C++ side.
///
/// Phase 4b-step3-step5c-sponge (2026-04-23): switched from the legacy
/// single-perm u64-proxy `poseidon2_cm(...)` check to the full 4-fe
/// sponge digest comparison, mirroring the AIR's new bank-1/bank-2
/// sponge closure on spend rows i / 24+i. Closes Codex audit finding
/// 1: the pre-check and the AIR constraint now agree on what leaf
/// means.
pub fn witness_claim2_leaf_consistent(w: &MvpWitness) -> bool {
    let perm16 = default_goldilocks_poseidon2_16();
    for s in &w.spends {
        let derived: [Goldilocks; 4] = poseidon2_cm_full_sponge(
            &perm16,
            &s.d,
            &s.pk_d,
            &s.ivk_commitment,
            s.value,
            &s.rcm,
        );
        let want: [Goldilocks; 4] = pack_32b_as_4fe(&s.leaf);
        if derived != want {
            return false;
        }
    }
    true
}

/// True iff for every spend, folding the 32-level Merkle path with a
/// 4-fe Poseidon2-w=8 walk reproduces the 4-fe decomposition of
/// `witness.anchor_bytes`.
///
/// Phase 4b-step3-step3a rewrote the reference from the legacy single-
/// u64-proxy walk (`anchor_proxy`) to the full 4-fe walk: both the
/// leaf and every sibling feed in as `pack_32b_as_4fe(&field)`, and
/// the target is `pack_32b_as_4fe(&w.anchor_bytes)`. This matches the
/// AIR's last-row binding after step 3a.
pub fn witness_claim1_anchor_consistent(w: &MvpWitness) -> bool {
    let perm = default_goldilocks_poseidon2_8();
    let want: [Goldilocks; 4] = pack_32b_as_4fe(&w.anchor_bytes);
    for s in &w.spends {
        let derived =
            poseidon2_merkle_path_root_4fe(&perm, &s.leaf, s.pos, &s.merkle_path);
        if derived != want {
            return false;
        }
    }
    true
}

/// Phase 4b-step3-step3a: no-op — the pre-step-3a invariant
/// `anchor_bytes[0..8] == anchor_proxy` is no longer meaningful.
/// `anchor_bytes` is now the 4-fe Merkle walk output (matches the
/// AIR's last-row binding to `PI[PI_ANCHOR + 0..4]`), while
/// `anchor_proxy` is the legacy single-fe walk output kept only for
/// wire-compat. Callers that need the fresh consistency check should
/// use [`witness_claim1_anchor_consistent`], which derives the 4-fe
/// walk off-circuit and compares against `pack_32b_as_4fe(anchor_bytes)`.
///
/// This stub is retained so downstream callers that previously ran
/// the check do not break at the type-signature level; it always
/// returns true. Real soundness lives in `witness_claim1_anchor_consistent`.
pub fn witness_anchor_bytes_consistent(_w: &MvpWitness) -> bool {
    true
}

/// Phase 4b-step3-step1.3-pi: true iff for every output, all 4 LE
/// u64 limbs of `witness.cm_bytes` (reduced mod Goldilocks) equal the
/// 4-fe output of the 15-fe iterated Poseidon2-w=16 sponge over
/// (d, pk_d, ivk_commitment, value, rcm). Post-step-1.3-pi, the AIR
/// binds `PI[pi_cm(j) + k]` to `O_CM_SPONGE_OUT[k]` — so a mismatch
/// here guarantees verify-time rejection. Surfacing the error at the
/// wallet pre-check boundary is friendlier than an opaque FFI
/// `VerifyFailed`.
///
/// Supersedes the Phase 4b-step1 single-limb check that tested
/// `encode_256(cm_bytes)[0] == poseidon2_cm_fe(...)`; the full 32 B
/// are now consensus-bound.
pub fn witness_cm_bytes_consistent(w: &MvpWitness) -> bool {
    let perm16 = default_goldilocks_poseidon2_16();
    for o in &w.outputs {
        let derived = poseidon2_cm_full_sponge(
            &perm16,
            &o.d,
            &o.pk_d,
            &o.ivk_commitment,
            o.value,
            &o.rcm,
        );
        for k in 0..4 {
            let witness_limb =
                u64::from_le_bytes(o.cm_bytes[k * 8..(k + 1) * 8].try_into().unwrap());
            if reduce_to_goldilocks(witness_limb) != derived[k].as_canonical_u64() {
                return false;
            }
        }
    }
    true
}
