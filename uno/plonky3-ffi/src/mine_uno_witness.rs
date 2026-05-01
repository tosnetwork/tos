//! Witness type + trace generation for the MineUno AIR (Phase 3).
//!
//! Provides:
//! - [`MineUnoWitness`] — the private witness struct (nonce, recipient,
//!   rseed, etc.) that feeds the STARK prover
//! - `encode` / `decode` for the FFI wire format
//! - `public_inputs` / `public_inputs_bytes` producing the 12-element
//!   Goldilocks PI vector
//! - `generate_trace` producing the AIR trace matrix (row selectors,
//!   Poseidon2-w16 rows, witness proxies, and carry proxies all populated)
//! - Off-circuit helpers [`compute_pow_hash`], [`poseidon2_mine_pow_hash`],
//!   and [`uno_mine_v1_tag_block`] mirroring the sponge layout the AIR
//!   will enforce in-circuit
//! - [`MineUnoWitness::deterministic_valid`] for test fixtures

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
    default_goldilocks_poseidon2_16, GenericPoseidon2LinearLayersGoldilocks, Goldilocks,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{generate_trace_rows, RoundConstants};
use p3_symmetric::Permutation;

use crate::mine_uno_columns::*;
use crate::transfer_columns::{
    POSEIDON2_HALF_FULL_ROUNDS, POSEIDON2_PARTIAL_ROUNDS_16, POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS, POSEIDON2_WIDTH_16,
};
use crate::transfer_preimage::{
    encode_256_as_4_limbs, pack_32b_as_4fe, pack_diversifier_as_2fe, GOLDILOCKS_P,
};
use crate::transfer_sponge::{poseidon2_cm_full_sponge, uno_cm_v1_tag_block};
use crate::Plonky3Status;

// ---------------------------------------------------------------------------
// Witness struct
// ---------------------------------------------------------------------------

/// Full private witness for a MineUno transaction.
///
/// All `[u8; N]` fields are in native (unspecified) byte order; the wire
/// encoding is fixed by `encode()`.
#[derive(Debug, Clone)]
pub struct MineUnoWitness {
    /// Current mining epoch (public). Maps to `PI[PI_EPOCH]`.
    pub epoch: u32,

    /// PoW nonce found by the miner (private; the AIR binds `pow_hash`
    /// to a function of this nonce + output_cm + epoch).
    pub nonce: [u8; 32],

    /// Recipient diversifier `d` (11 bytes, zero-padded to 32 per the
    /// canonical format; bytes `d[11..32]` MUST be zero, enforced on
    /// decode).
    pub d: [u8; 32],

    /// Recipient `pk_d` (compressed Ristretto255, 32 bytes).
    pub pk_d: [u8; 32],

    /// Recipient `ivk_commitment` (32 bytes, = Poseidon2("uno-ivk-cm-v1",
    /// ivk, d) off-circuit).
    pub ivk_commitment: [u8; 32],

    /// Mint amount in nano-UNO. Must equal
    /// `mine_reward_for_era(epoch / kEraSize)` — off-circuit chain check.
    pub value_nano: u64,

    /// Per-note randomness seed. `rcm = Poseidon2("uno-rcm-v1", rseed)` is
    /// computed off-circuit here; the AIR consumes `rcm` directly.
    pub rseed: [u8; 32],

    /// `remaining_pre` (public input). Must equal `chain_state.mine_remaining`
    /// at proof submission time.
    pub remaining_pre: u64,

    /// `remaining_post` (public input). Must equal `remaining_pre - value_nano`.
    pub remaining_post: u64,
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------
//
// Fixed-size layout (192 bytes total):
//
//   offset  size  field
//   ------  ----  ---------------------------------------------------------
//   0       4     epoch              (u32 LE)
//   4       32    nonce              ([u8; 32])
//   36      32    d                  ([u8; 32], bytes [11..32] MUST be zero)
//   68      32    pk_d               ([u8; 32])
//   100     32    ivk_commitment     ([u8; 32])
//   132     8     value_nano         (u64 LE)
//   140     32    rseed              ([u8; 32])
//   172     8     remaining_pre      (u64 LE)
//   180     8     remaining_post     (u64 LE)
//   188     4     _reserved          (zero; alignment to 192)
//   ------  ----  ---------------------------------------------------------
//   total   192

/// Wire byte length for [`MineUnoWitness`].
pub const MINE_UNO_WITNESS_BYTES: usize = 192;

impl MineUnoWitness {
    /// Serialize to the canonical wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MINE_UNO_WITNESS_BYTES);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.d);
        out.extend_from_slice(&self.pk_d);
        out.extend_from_slice(&self.ivk_commitment);
        out.extend_from_slice(&self.value_nano.to_le_bytes());
        out.extend_from_slice(&self.rseed);
        out.extend_from_slice(&self.remaining_pre.to_le_bytes());
        out.extend_from_slice(&self.remaining_post.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]); // alignment padding
        debug_assert_eq!(out.len(), MINE_UNO_WITNESS_BYTES);
        out
    }

    /// Deserialize from the canonical wire format. Performs basic
    /// sanity checks (length, `d[11..32] == 0`, `remaining_post + value ==
    /// remaining_pre`).
    pub fn decode(bytes: &[u8]) -> Result<Self, Plonky3Status> {
        if bytes.len() != MINE_UNO_WITNESS_BYTES {
            return Err(Plonky3Status::WitnessInvalid);
        }
        let epoch = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let nonce: [u8; 32] = bytes[4..36].try_into().unwrap();
        let d: [u8; 32] = bytes[36..68].try_into().unwrap();
        let pk_d: [u8; 32] = bytes[68..100].try_into().unwrap();
        let ivk_commitment: [u8; 32] = bytes[100..132].try_into().unwrap();
        let value_nano = u64::from_le_bytes(bytes[132..140].try_into().unwrap());
        let rseed: [u8; 32] = bytes[140..172].try_into().unwrap();
        let remaining_pre = u64::from_le_bytes(bytes[172..180].try_into().unwrap());
        let remaining_post = u64::from_le_bytes(bytes[180..188].try_into().unwrap());

        // Canonical diversifier padding: bytes 11..32 must be zero.
        if d[11..32].iter().any(|&b| b != 0) {
            return Err(Plonky3Status::WitnessInvalid);
        }

        // Conservation: remaining_post = remaining_pre - value_nano.
        if remaining_pre < value_nano {
            return Err(Plonky3Status::WitnessInvalid);
        }
        if remaining_post != remaining_pre - value_nano {
            return Err(Plonky3Status::WitnessInvalid);
        }

        // Canonical u64s for PI (values reduced mod Goldilocks p elsewhere).
        // Here we only reject outright non-canonical sentinels.
        if value_nano >= GOLDILOCKS_P || remaining_pre >= GOLDILOCKS_P
            || remaining_post >= GOLDILOCKS_P
        {
            return Err(Plonky3Status::WitnessInvalid);
        }

        Ok(MineUnoWitness {
            epoch,
            nonce,
            d,
            pk_d,
            ivk_commitment,
            value_nano,
            rseed,
            remaining_pre,
            remaining_post,
        })
    }

    // -----------------------------------------------------------------------
    // Off-circuit sponge computation (witness-side)
    // -----------------------------------------------------------------------

    /// Compute `rcm = Poseidon2("uno-rcm-v1", rseed)` off-circuit. In v1 this
    /// is a simple domain-tagged 4-fe → 4-fe compression; the AIR does NOT
    /// enforce this derivation (rcm is a private witness column; rseed is
    /// only needed for the wallet's own recovery, not for consensus).
    pub fn compute_rcm(&self) -> [u8; 32] {
        // Use the wide (width-16) permutation for consistency with cm
        // sponge, even though the input is small. Layout:
        //   state[0..4] = pack_32b_as_4fe(rseed)
        //   state[8..16] = uno_rcm_v1_tag_block()  (capacity pinning)
        let perm16 = default_goldilocks_poseidon2_16();
        let rseed_fes = pack_32b_as_4fe(&self.rseed);
        let mut state = [Goldilocks::ZERO; 16];
        state[0..4].copy_from_slice(&rseed_fes);
        state[8] = Goldilocks::from_u64(TAG_RCM);
        perm16.permute_mut(&mut state);
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8]
                .copy_from_slice(&state[i].as_canonical_u64().to_le_bytes());
        }
        out
    }

    /// Compute `output_cm = Poseidon2_full_sponge_15fe(d, pk_d, ivk_cm, value, rcm)`
    /// off-circuit via the reference implementation. Returns 4 Goldilocks
    /// limbs (= 256-bit commitment).
    pub fn compute_output_cm_fes(&self) -> [Goldilocks; 4] {
        let perm16 = default_goldilocks_poseidon2_16();
        let rcm = self.compute_rcm();
        poseidon2_cm_full_sponge(
            &perm16,
            &self.d,
            &self.pk_d,
            &self.ivk_commitment,
            self.value_nano,
            &rcm,
        )
    }

    /// Compute `output_cm` as 32 LE bytes (`4 × 8`).
    pub fn compute_output_cm_bytes(&self) -> [u8; 32] {
        let fes = self.compute_output_cm_fes();
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8]
                .copy_from_slice(&fes[i].as_canonical_u64().to_le_bytes());
        }
        out
    }

    /// Compute the PoW hash: `Poseidon2("uno-mine-v1", epoch, nonce, output_cm)`
    /// via a 9-fe iterated sponge (width-16, rate-8, 2 permutations), mirroring
    /// the nullifier derivation's layout in `poseidon2_nf_full_wide`.
    pub fn compute_pow_hash_fes(&self) -> [Goldilocks; 4] {
        let perm16 = default_goldilocks_poseidon2_16();
        let output_cm = self.compute_output_cm_bytes();
        poseidon2_mine_pow_hash(&perm16, self.epoch, &self.nonce, &output_cm)
    }

    /// Compute the PoW hash as 32 LE bytes.
    pub fn compute_pow_hash_bytes(&self) -> [u8; 32] {
        let fes = self.compute_pow_hash_fes();
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8]
                .copy_from_slice(&fes[i].as_canonical_u64().to_le_bytes());
        }
        out
    }

    // -----------------------------------------------------------------------
    // Public inputs
    // -----------------------------------------------------------------------

    /// Build the 12-element Goldilocks public-input vector.
    pub fn public_inputs(&self) -> Vec<Goldilocks> {
        let output_cm = self.compute_output_cm_fes();
        let pow_hash = self.compute_pow_hash_fes();
        let mut pi = vec![Goldilocks::ZERO; N_PUBLIC_INPUTS];
        pi[PI_EPOCH] = Goldilocks::from_u64(u64::from(self.epoch));
        pi[PI_VALUE] = Goldilocks::from_u64(self.value_nano);
        pi[PI_OUTPUT_CM_BASE..PI_OUTPUT_CM_BASE + 4].copy_from_slice(&output_cm);
        pi[PI_POW_HASH_BASE..PI_POW_HASH_BASE + 4].copy_from_slice(&pow_hash);
        pi[PI_REMAINING_PRE] = Goldilocks::from_u64(self.remaining_pre);
        pi[PI_REMAINING_POST] = Goldilocks::from_u64(self.remaining_post);
        pi
    }

    /// Wire-encoded public inputs (`N_PUBLIC_INPUTS × 8` LE bytes).
    pub fn public_inputs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_INPUT_BYTES);
        for fe in self.public_inputs() {
            out.extend_from_slice(&fe.as_canonical_u64().to_le_bytes());
        }
        debug_assert_eq!(out.len(), PUBLIC_INPUT_BYTES);
        out
    }

    // -----------------------------------------------------------------------
    // Trace generation
    // -----------------------------------------------------------------------

    /// Generate the AIR trace matrix (`MINE_TRACE_HEIGHT × MINE_AIR_WIDTH`).
    ///
    /// Phase 3b: fills all columns — row selectors, the shared Poseidon2-w16
    /// block (via `p3_poseidon2_air::generate_trace_rows`), the witness
    /// proxies, and the 16-cell carry proxy (rate + capacity) carrying
    /// perm-1 post-state to perm-2's inputs within each chain.
    pub fn generate_trace(&self) -> RowMajorMatrix<Goldilocks> {
        let mut values = vec![Goldilocks::ZERO; MINE_TRACE_HEIGHT * MINE_AIR_WIDTH];

        // Pre-compute all witness proxy values (same on every row).
        let d_fes = pack_diversifier_as_2fe(&self.d);
        let pk_d_fes = pack_32b_as_4fe(&self.pk_d);
        let ivk_cm_fes = pack_32b_as_4fe(&self.ivk_commitment);
        let rcm_bytes = self.compute_rcm();
        let rcm_fes = pack_32b_as_4fe(&rcm_bytes);
        let nonce_fes = pack_32b_as_4fe(&self.nonce);
        let output_cm_fes = self.compute_output_cm_fes();
        let pow_hash_fes = self.compute_pow_hash_fes();

        let epoch_fe = Goldilocks::from_u64(u64::from(self.epoch));
        let value_fe = Goldilocks::from_u64(self.value_nano);

        // --------------------------------------------------------------
        // Phase 3b: build the 4 Poseidon2-w16 permutation witnesses.
        // --------------------------------------------------------------
        let perm16 = default_goldilocks_poseidon2_16();
        let constants_16 = RoundConstants::new(
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_INITIAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_INTERNAL,
            p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_16_EXTERNAL_FINAL,
        );
        let gen_p2_row_16 = |input: [Goldilocks; POSEIDON2_WIDTH_16]| -> Vec<Goldilocks> {
            let mat = generate_trace_rows::<
                Goldilocks,
                GenericPoseidon2LinearLayersGoldilocks,
                POSEIDON2_WIDTH_16,
                POSEIDON2_SBOX_DEGREE,
                POSEIDON2_SBOX_REGISTERS,
                POSEIDON2_HALF_FULL_ROUNDS,
                POSEIDON2_PARTIAL_ROUNDS_16,
            >(vec![input], &constants_16, 0);
            debug_assert_eq!(mat.values.len(), MINE_POSEIDON2_COLS_16);
            mat.values
        };
        let padding_p2_16 = gen_p2_row_16([Goldilocks::ZERO; POSEIDON2_WIDTH_16]);

        let cm_tag = uno_cm_v1_tag_block();
        let mine_tag = uno_mine_v1_tag_block();

        // Row 0 — CM perm-1 input.
        let mut cm_p1_in = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
        cm_p1_in[0] = d_fes[0];
        cm_p1_in[1] = d_fes[1];
        cm_p1_in[2..6].copy_from_slice(&pk_d_fes);
        cm_p1_in[6] = ivk_cm_fes[0];
        cm_p1_in[7] = ivk_cm_fes[1];
        cm_p1_in[8..16].copy_from_slice(&cm_tag);
        let cm_p1_trace = gen_p2_row_16(cm_p1_in);
        // Off-circuit: the bank-1 output state.
        let mut cm_p1_out = cm_p1_in;
        perm16.permute_mut(&mut cm_p1_out);

        // Row 1 — CM perm-2 input (uses bank-1 out + fe-absorb + 10* pad).
        let mut cm_p2_in = cm_p1_out;
        cm_p2_in[0] = cm_p2_in[0] + ivk_cm_fes[2];
        cm_p2_in[1] = cm_p2_in[1] + ivk_cm_fes[3];
        cm_p2_in[2] = cm_p2_in[2] + value_fe;
        cm_p2_in[3] = cm_p2_in[3] + rcm_fes[0];
        cm_p2_in[4] = cm_p2_in[4] + rcm_fes[1];
        cm_p2_in[5] = cm_p2_in[5] + rcm_fes[2];
        cm_p2_in[6] = cm_p2_in[6] + rcm_fes[3];
        cm_p2_in[7] = cm_p2_in[7] + Goldilocks::ONE;
        let cm_p2_trace = gen_p2_row_16(cm_p2_in);

        // Row 2 — PoW perm-1 input.
        let mut pow_p1_in = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
        pow_p1_in[0] = epoch_fe;
        pow_p1_in[1..5].copy_from_slice(&nonce_fes);
        pow_p1_in[5..8].copy_from_slice(&output_cm_fes[0..3]);
        pow_p1_in[8..16].copy_from_slice(&mine_tag);
        let pow_p1_trace = gen_p2_row_16(pow_p1_in);
        let mut pow_p1_out = pow_p1_in;
        perm16.permute_mut(&mut pow_p1_out);

        // Row 3 — PoW perm-2 input.
        let mut pow_p2_in = pow_p1_out;
        pow_p2_in[0] = pow_p2_in[0] + output_cm_fes[3];
        pow_p2_in[1] = pow_p2_in[1] + Goldilocks::ONE;
        // inputs[2..8] stay equal to pow_p1_out[2..8].
        // inputs[8..16] stay equal to pow_p1_out[8..16] (capacity carry).
        let pow_p2_trace = gen_p2_row_16(pow_p2_in);

        // Carry proxies: each chain gets its own 16-cell block (8 rate +
        // 8 cap). Row-constancy transition invariant propagates these
        // across all 8 rows; per-chain selector-gated constraints in the
        // AIR pin the values on the active perm-1 row and read them on
        // the active perm-2 row. See mine_uno_columns.rs §carry-proxy
        // for the design rationale (and deviation from spec §A).
        let cm_carry_rate: [Goldilocks; 8] = {
            let mut out = [Goldilocks::ZERO; 8];
            out.copy_from_slice(&cm_p1_out[0..8]);
            out
        };
        let cm_carry_cap: [Goldilocks; 8] = {
            let mut out = [Goldilocks::ZERO; 8];
            out.copy_from_slice(&cm_p1_out[8..16]);
            out
        };
        let pow_carry_rate: [Goldilocks; 8] = {
            let mut out = [Goldilocks::ZERO; 8];
            out.copy_from_slice(&pow_p1_out[0..8]);
            out
        };
        let pow_carry_cap: [Goldilocks; 8] = {
            let mut out = [Goldilocks::ZERO; 8];
            out.copy_from_slice(&pow_p1_out[8..16]);
            out
        };

        // Fill each row.
        for row in 0..MINE_TRACE_HEIGHT {
            let row_base = row * MINE_AIR_WIDTH;

            // Row selectors (one-hot for rows 0..3, all-zero for rows 4..7).
            if row == 0 {
                values[row_base + COL_SEL_CM_P1] = Goldilocks::ONE;
            } else if row == 1 {
                values[row_base + COL_SEL_CM_P2] = Goldilocks::ONE;
            } else if row == 2 {
                values[row_base + COL_SEL_POW_P1] = Goldilocks::ONE;
            } else if row == 3 {
                values[row_base + COL_SEL_POW_P2] = Goldilocks::ONE;
            }
            // Rows 4..7: all four selector cols remain ZERO (padding).

            // Shared Poseidon2-w16 block.
            let p2_src: &[Goldilocks] = match row {
                0 => &cm_p1_trace,
                1 => &cm_p2_trace,
                2 => &pow_p1_trace,
                3 => &pow_p2_trace,
                _ => &padding_p2_16,
            };
            values[row_base + N_ROW_SELECTORS
                ..row_base + N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16]
                .copy_from_slice(p2_src);

            // Witness proxy columns (same on every row).
            values[row_base + COL_W_EPOCH] = epoch_fe;
            values[row_base + COL_W_VALUE] = value_fe;
            values[row_base + COL_W_D_FE0] = d_fes[0];
            values[row_base + COL_W_D_FE1] = d_fes[1];
            for k in 0..4 {
                values[row_base + COL_W_PK_D_FE0 + k] = pk_d_fes[k];
                values[row_base + COL_W_IVK_CM_FE0 + k] = ivk_cm_fes[k];
                values[row_base + COL_W_RCM_FE0 + k] = rcm_fes[k];
                values[row_base + COL_W_NONCE_FE0 + k] = nonce_fes[k];
                values[row_base + COL_W_OUTPUT_CM_FE0 + k] = output_cm_fes[k];
                values[row_base + COL_W_POW_HASH_FE0 + k] = pow_hash_fes[k];
            }

            // Carry proxies (4 × 8 cells: CM rate, CM cap, PoW rate, PoW
            // cap). Constant across all rows courtesy of the transition-
            // constancy loop in the AIR.
            for k in 0..8 {
                values[row_base + COL_CAP_CARRY_BASE + CARRY_CM_BASE + k] =
                    cm_carry_rate[k];
                values[row_base + COL_CAP_CARRY_BASE + CARRY_CM_BASE + 8 + k] =
                    cm_carry_cap[k];
                values[row_base + COL_CAP_CARRY_BASE + CARRY_POW_BASE + k] =
                    pow_carry_rate[k];
                values[row_base + COL_CAP_CARRY_BASE + CARRY_POW_BASE + 8 + k] =
                    pow_carry_cap[k];
            }
        }

        RowMajorMatrix::new(values, MINE_AIR_WIDTH)
    }

    // -----------------------------------------------------------------------
    // Deterministic test fixture
    // -----------------------------------------------------------------------

    /// Build a deterministic, valid witness for a given `(epoch, seed)`.
    /// Used by unit tests. NOT suitable for production — the nonce is not
    /// actually PoW-solved against any real target.
    pub fn deterministic_valid(epoch: u32, seed: u64) -> Self {
        let expand = |salt: u64| -> [u8; 32] {
            // Simple xorshift expand (not crypto-strong; tests only).
            let mut out = [0u8; 32];
            let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ salt;
            for chunk in out.chunks_mut(8) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                chunk.copy_from_slice(&x.to_le_bytes());
            }
            out
        };
        let mut d_raw = expand(0xD11_D11);
        for byte in d_raw.iter_mut().skip(11) {
            *byte = 0; // canonical padding
        }
        let value_nano = 50u64 * 1_000_000_000u64; // era-0 reward
        let remaining_pre = 21_000_000u64 * 1_000_000_000u64;
        let remaining_post = remaining_pre - value_nano;
        MineUnoWitness {
            epoch,
            nonce: expand(0xA110_CE_00),
            d: d_raw,
            pk_d: expand(0xAF_AF_AF),
            ivk_commitment: expand(0x1_CE_1_CE),
            value_nano,
            rseed: expand(0x5EED_5EED),
            remaining_pre,
            remaining_post,
        }
    }
}

// ---------------------------------------------------------------------------
// Domain-separation tags + PoW sponge (off-circuit reference)
// ---------------------------------------------------------------------------

/// Domain tag for the rcm derivation Poseidon2 (single-perm, 4-fe → 4-fe).
/// ASCII `"uno-rcm-v1"` — version flag prefix + "uno-rcm" + "v1" tail.
/// Stored as the first Goldilocks element of the capacity block.
pub const TAG_RCM: u64 = 0x01_75_6E_6F_72_63_6D_76;

/// Tag block for the PoW sponge, mirroring `uno_nf_v1_tag_block` /
/// `uno_cm_v1_tag_block` in `transfer_sponge.rs`.
///
/// First element = 8-byte ASCII `"uno-mine"` (little-endian); second
/// element = `"v1"` + 6 zero bytes; remaining 6 capacity slots are zero.
#[inline]
pub fn uno_mine_v1_tag_block() -> [Goldilocks; 8] {
    let mut tag = [Goldilocks::ZERO; 8];
    // First 8 bytes of the tag
    let b0 = b"uno-mine";
    tag[0] = Goldilocks::from_u64(u64::from_le_bytes(*b0));
    // "v1" + 6 zero bytes
    let mut b1 = [0u8; 8];
    b1[0] = b'v';
    b1[1] = b'1';
    tag[1] = Goldilocks::from_u64(u64::from_le_bytes(b1));
    tag
}

/// Off-circuit PoW sponge: `Poseidon2("uno-mine-v1", epoch, nonce_4fe, cm_4fe)`.
///
/// Layout (9-fe iterated sponge, width-16, 2 permutations):
///
/// ```text
///   perm 1:
///     state[0..8]   = [epoch, nonce_fe[0..4], cm_fe[0..3]]  ← rate absorb
///     state[8..16]  = uno_mine_v1_tag_block()               ← capacity pin
///     permute → intermediate
///
///   perm 2:
///     state[0]      += cm_fe[3]                             ← last 1 fe
///     state[1]      += ONE                                  ← 10* padding
///     permute → final
///
///   output = state[0..4]  (= 4-limb 256-bit digest)
/// ```
/// Convenience byte-in/byte-out wrapper around `poseidon2_mine_pow_hash`
/// for external callers (e.g. the tosctl miner) who can't link against
/// this crate's `p3_goldilocks` type directly. Returns the 32-byte LE-
/// per-limb encoding of the 4-fe digest — byte-identical to PI bytes
/// 48..80 emitted by `public_inputs_bytes()`, which is what the on-chain
/// `apply_mine_uno` compares to `state.mine_target()`.
pub fn compute_mine_pow_hash_bytes(
    epoch: u32,
    nonce: &[u8; 32],
    output_cm: &[u8; 32],
) -> [u8; 32] {
    let perm16 = default_goldilocks_poseidon2_16();
    let fes = poseidon2_mine_pow_hash(&perm16, epoch, nonce, output_cm);
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8]
            .copy_from_slice(&fes[i].as_canonical_u64().to_le_bytes());
    }
    out
}

pub fn poseidon2_mine_pow_hash(
    perm16: &impl Permutation<[Goldilocks; 16]>,
    epoch: u32,
    nonce: &[u8; 32],
    output_cm: &[u8; 32],
) -> [Goldilocks; 4] {
    let nonce_fes = pack_32b_as_4fe(nonce);
    let cm_fes = pack_32b_as_4fe(output_cm);
    let tag = uno_mine_v1_tag_block();

    // Initial state: rate slots absorb 8 fes, capacity pinned to tag.
    let mut state = [Goldilocks::ZERO; 16];
    state[0] = Goldilocks::from_u64(u64::from(epoch));
    state[1..5].copy_from_slice(&nonce_fes);
    state[5..8].copy_from_slice(&cm_fes[0..3]);
    state[8..16].copy_from_slice(&tag);
    perm16.permute_mut(&mut state);

    // Perm 2: absorb last fe + 10* padding.
    state[0] = state[0] + cm_fes[3];
    state[1] = state[1] + Goldilocks::ONE;
    perm16.permute_mut(&mut state);

    [state[0], state[1], state[2], state[3]]
}

// ---------------------------------------------------------------------------
// Top-level helpers
// ---------------------------------------------------------------------------

/// Decode a MineUno public-input byte string into a Goldilocks vector.
/// Rejects non-canonical limbs (`>= p`). Mirrors
/// `transfer_preimage::decode_public_inputs` for the Transfer PI path.
pub fn decode_mine_public_inputs(bytes: &[u8]) -> Result<Vec<Goldilocks>, Plonky3Status> {
    if bytes.len() != PUBLIC_INPUT_BYTES {
        return Err(Plonky3Status::PublicInputLengthMismatch);
    }
    let mut out = Vec::with_capacity(N_PUBLIC_INPUTS);
    for i in 0..N_PUBLIC_INPUTS {
        let limb = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        if limb >= GOLDILOCKS_P {
            return Err(Plonky3Status::PublicInputDecodeFailed);
        }
        out.push(Goldilocks::from_u64(limb));
    }
    Ok(out)
}

/// Convenience: encode a `[Goldilocks; 4]` as 32 LE bytes (useful for
/// cross-checking PI fields against a raw bytes fixture).
#[allow(dead_code)]
pub(crate) fn fes4_to_32_bytes_le(fes: &[Goldilocks; 4]) -> [u8; 32] {
    encode_256_as_4_limbs(&{
        let mut tmp = [0u8; 32];
        for i in 0..4 {
            tmp[i * 8..(i + 1) * 8]
                .copy_from_slice(&fes[i].as_canonical_u64().to_le_bytes());
        }
        tmp
    });
    // The above call has a side-effect-free round-trip that the compiler
    // may elide; to be explicit, just do the packing directly:
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8]
            .copy_from_slice(&fes[i].as_canonical_u64().to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p3_matrix::Matrix;

    #[test]
    fn witness_encode_decode_roundtrips() {
        let w = MineUnoWitness::deterministic_valid(0, 0xBEEF_1234);
        let bytes = w.encode();
        assert_eq!(bytes.len(), MINE_UNO_WITNESS_BYTES);
        let w2 = MineUnoWitness::decode(&bytes).expect("decode must succeed");
        assert_eq!(w.epoch, w2.epoch);
        assert_eq!(w.nonce, w2.nonce);
        assert_eq!(w.d, w2.d);
        assert_eq!(w.pk_d, w2.pk_d);
        assert_eq!(w.ivk_commitment, w2.ivk_commitment);
        assert_eq!(w.value_nano, w2.value_nano);
        assert_eq!(w.rseed, w2.rseed);
        assert_eq!(w.remaining_pre, w2.remaining_pre);
        assert_eq!(w.remaining_post, w2.remaining_post);
    }

    #[test]
    fn witness_decode_rejects_non_canonical_diversifier_padding() {
        let w = MineUnoWitness::deterministic_valid(0, 0xAB);
        let mut bytes = w.encode();
        // Flip byte 20 (= offset 36 + 15, which is d[15]) to break d[11..32] zero.
        bytes[36 + 15] = 0xFF;
        assert!(matches!(
            MineUnoWitness::decode(&bytes),
            Err(Plonky3Status::WitnessInvalid)
        ));
    }

    #[test]
    fn witness_decode_rejects_broken_conservation() {
        let w = MineUnoWitness::deterministic_valid(0, 0x77);
        let mut bytes = w.encode();
        // Bump remaining_post by 1 (offset 180).
        let bad_post = w.remaining_post + 1;
        bytes[180..188].copy_from_slice(&bad_post.to_le_bytes());
        assert!(matches!(
            MineUnoWitness::decode(&bytes),
            Err(Plonky3Status::WitnessInvalid)
        ));
    }

    #[test]
    fn public_inputs_have_expected_shape() {
        let w = MineUnoWitness::deterministic_valid(0, 0xDEAD);
        let pi = w.public_inputs();
        assert_eq!(pi.len(), N_PUBLIC_INPUTS);
        assert_eq!(pi[PI_EPOCH].as_canonical_u64(), 0);
        assert_eq!(pi[PI_VALUE].as_canonical_u64(), 50u64 * 1_000_000_000);
        // output_cm + pow_hash are deterministic but we don't assert their
        // exact bytes here — that's the golden fixture's job.
        let pi_bytes = w.public_inputs_bytes();
        assert_eq!(pi_bytes.len(), PUBLIC_INPUT_BYTES);
    }

    #[test]
    fn decode_mine_public_inputs_rejects_non_canonical() {
        let mut bytes = vec![0u8; PUBLIC_INPUT_BYTES];
        // Put Goldilocks p itself into PI[0] (non-canonical).
        bytes[0..8].copy_from_slice(&GOLDILOCKS_P.to_le_bytes());
        assert!(matches!(
            decode_mine_public_inputs(&bytes),
            Err(Plonky3Status::PublicInputDecodeFailed)
        ));
    }

    #[test]
    fn decode_mine_public_inputs_rejects_wrong_length() {
        let bytes = vec![0u8; PUBLIC_INPUT_BYTES + 1];
        assert!(matches!(
            decode_mine_public_inputs(&bytes),
            Err(Plonky3Status::PublicInputLengthMismatch)
        ));
    }

    #[test]
    fn trace_dimensions_are_correct() {
        let w = MineUnoWitness::deterministic_valid(0, 0xF00D);
        let trace = w.generate_trace();
        assert_eq!(trace.height(), MINE_TRACE_HEIGHT);
        assert_eq!(trace.width(), MINE_AIR_WIDTH);
    }

    #[test]
    fn trace_row_selectors_are_one_hot_on_active_rows() {
        let w = MineUnoWitness::deterministic_valid(0, 0xCAFE);
        let trace = w.generate_trace();
        let vals = trace.values;
        for row in 0..MINE_TRACE_HEIGHT {
            let base = row * MINE_AIR_WIDTH;
            let sum: u64 = [
                COL_SEL_CM_P1,
                COL_SEL_CM_P2,
                COL_SEL_POW_P1,
                COL_SEL_POW_P2,
            ]
            .iter()
            .map(|&c| vals[base + c].as_canonical_u64())
            .sum();
            if row < 4 {
                assert_eq!(sum, 1, "row {} selectors must sum to 1", row);
            } else {
                assert_eq!(sum, 0, "padding row {} selectors must all be 0", row);
            }
        }
    }

    #[test]
    fn trace_proxy_cols_are_constant_across_rows() {
        let w = MineUnoWitness::deterministic_valid(42, 0x1234_5678);
        let trace = w.generate_trace();
        let vals = &trace.values;
        // Spot-check: COL_W_EPOCH must equal w.epoch on every row.
        let expected = Goldilocks::from_u64(u64::from(w.epoch));
        for row in 0..MINE_TRACE_HEIGHT {
            let v = vals[row * MINE_AIR_WIDTH + COL_W_EPOCH];
            assert_eq!(v, expected, "COL_W_EPOCH not constant at row {}", row);
        }
    }

    #[test]
    fn pow_hash_matches_tosctl_mirror_shape() {
        // Just sanity-check: the function is deterministic and produces
        // 4 Goldilocks elements — doesn't guarantee byte parity with the
        // tosctl-side `compute_mine_pow_hash` (that's a separate golden test).
        let w = MineUnoWitness::deterministic_valid(7, 0xABCD);
        let fes = w.compute_pow_hash_fes();
        assert_eq!(fes.len(), 4);
        // Re-run must give identical output.
        let fes2 = w.compute_pow_hash_fes();
        assert_eq!(fes, fes2);
    }

    // -----------------------------------------------------------------------
    // Phase 3b: off-circuit ↔ in-circuit parity and end-to-end prove/verify.
    // -----------------------------------------------------------------------

    /// Pull the 4-fe digest (post[0..4]) out of the Poseidon2 block of a
    /// given trace row. The P2 block lives at offset `N_ROW_SELECTORS`
    /// and the digest is the final `ending_full_rounds[HALF-1].post[0..4]`.
    fn extract_p2_digest(
        trace_values: &[Goldilocks],
        row: usize,
    ) -> [Goldilocks; 4] {
        use core::borrow::Borrow;
        let row_base = row * MINE_AIR_WIDTH;
        let p2_cells = &trace_values
            [row_base + N_ROW_SELECTORS..row_base + N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16];
        let p2_cols: &MineP2Cols<Goldilocks> =
            <[Goldilocks] as Borrow<MineP2Cols<Goldilocks>>>::borrow(p2_cells);
        let post =
            &p2_cols.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
        [post[0], post[1], post[2], post[3]]
    }

    #[test]
    fn poseidon2_cm_sponge_matches_in_circuit_parity() {
        let w = MineUnoWitness::deterministic_valid(42, 0xDEAD_BEEF);
        let perm16 = default_goldilocks_poseidon2_16();

        // Off-circuit reference.
        let rcm = w.compute_rcm();
        let off_circuit = poseidon2_cm_full_sponge(
            &perm16,
            &w.d,
            &w.pk_d,
            &w.ivk_commitment,
            w.value_nano,
            &rcm,
        );

        // In-circuit (row 1's post[0..4] = CM perm-2 digest).
        let trace = w.generate_trace();
        let in_circuit = extract_p2_digest(&trace.values, 1);

        assert_eq!(
            off_circuit, in_circuit,
            "CM sponge digest mismatch between off-circuit helper and in-trace Poseidon2"
        );
    }

    #[test]
    fn poseidon2_pow_hash_matches_in_circuit_parity() {
        let w = MineUnoWitness::deterministic_valid(7, 0x1234_5678);
        let perm16 = default_goldilocks_poseidon2_16();

        // Off-circuit reference (via the existing helper).
        let cm_bytes = w.compute_output_cm_bytes();
        let off_circuit =
            poseidon2_mine_pow_hash(&perm16, w.epoch, &w.nonce, &cm_bytes);

        // In-circuit (row 3's post[0..4] = PoW perm-2 digest).
        let trace = w.generate_trace();
        let in_circuit = extract_p2_digest(&trace.values, 3);

        assert_eq!(
            off_circuit, in_circuit,
            "PoW sponge digest mismatch between off-circuit helper and in-trace Poseidon2"
        );
    }

    #[test]
    fn mine_uno_air_prove_verify_roundtrip() {
        use p3_uni_stark::{prove, verify};

        use crate::mine_uno_air::MineUnoAir;
        use crate::prover::build_config;

        let w = MineUnoWitness::deterministic_valid(42, 0xC0FF_EE);
        let trace = w.generate_trace();
        let public_inputs = w.public_inputs();
        let cfg = build_config();
        let air = MineUnoAir::new();

        let proof = prove(&cfg, &air, trace, &public_inputs);
        verify(&cfg, &air, &proof, &public_inputs)
            .expect("MineUnoAir prove/verify round-trip must succeed");
    }
}
