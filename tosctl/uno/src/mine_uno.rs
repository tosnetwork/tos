//! MineUno transaction kind data structures — Rust mirror of
//! `uno/core/mine_uno.h`.
//!
//! `MineUno` is the second transaction kind in the wc=2 protocol alongside
//! `Transfer`. A miner searches for a Poseidon2-over-Goldilocks nonce and
//! proves the solution in a Plonky3 STARK circuit.
//!
//! # Phase 1 scope
//!
//! This file provides:
//! - [`MineUnoWitness`]      — private inputs to the STARK prover.
//! - [`MineUnoPublicInputs`] — public on-chain data (bound into proof).
//! - [`MineUno`]             — full decoded transaction envelope (Phase 2 decoder TBD).
//! - Serialization stubs     — `encode_wire` / `decode_wire` return `Err` stubs.
//!
//! **Full Plonky3 AIR wiring is Phase 2**. Phase 2 will add:
//! - `uno/plonky3-ffi/src/mine_uno_air.rs`     — AIR columns + constraint rows.
//! - `uno/plonky3-ffi/src/mine_uno_witness.rs` — witness types + trace gen.
//! - `uno/plonky3-ffi/src/mine_uno_prover.rs`  — prover entry point (FFI).
//! - Wire codec implementation in this file's stubs.
//!
//! **C++ mirror**: `uno/core/mine_uno.h`. Field names, byte widths, and
//! ordering must be kept in sync.

use anyhow::{bail, Result};

use crate::mine_constants::{mine_reward_for_epoch, ERA_SIZE, MINE_SUPPLY_NANO};
use crate::sizes::{DIGEST, DIVERSIFIER, IVK_COMMITMENT, MLKEM768_PK, RISTRETTO_POINT};

// ---------------------------------------------------------------------------
// Tx-kind discriminator (mirrors mine_uno.h kTxKindMineUno)
// ---------------------------------------------------------------------------

/// Discriminator byte for MineUno envelopes (offset 0).
/// `0x01` = Transfer (existing); `0x02` = MineUno (new).
pub const TX_KIND_TRANSFER: u8 = 0x01;
pub const TX_KIND_MINE_UNO: u8 = 0x02;

/// Schema version for MineUno wire envelope. Version 1 is the initial definition.
pub const MINE_UNO_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Address (mirrors GenesisAddress in genesis.h)
// ---------------------------------------------------------------------------

/// Recipient's Uno address (1259 bytes; §2.6 layout).
///
/// Layout:
///   - 11 B diversifier `d`
///   - 32 B compressed Ristretto `pk_d`
///   - 32 B `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)`
///   - 1184 B ML-KEM-768 `pk_mlkem`
///
/// Byte-identical to `GenesisAddress` in `uno/core/genesis.h`.
/// Used in `MineUnoWitness` (private; never transmitted on-chain).
#[derive(Clone, Debug)]
pub struct MineUnoAddress {
    /// Diversifier `d` (11 bytes).
    pub diversifier: [u8; DIVERSIFIER],
    /// Compressed Ristretto255 `pk_d` (32 bytes).
    pub pk_d_compressed: [u8; RISTRETTO_POINT],
    /// `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)` (32 bytes).
    pub ivk_commitment: [u8; IVK_COMMITMENT],
    /// ML-KEM-768 public key `pk_mlkem` (1184 bytes).
    pub pk_mlkem: Vec<u8>,
}

impl MineUnoAddress {
    /// Validate that field sizes match the §2.6 spec.
    /// Returns `Err` if `pk_mlkem` is not exactly 1184 bytes.
    pub fn validate(&self) -> Result<()> {
        if self.pk_mlkem.len() != MLKEM768_PK {
            bail!(
                "MineUnoAddress: pk_mlkem must be {} bytes, got {}",
                MLKEM768_PK,
                self.pk_mlkem.len()
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MineUnoWitness — private inputs to the STARK prover
// ---------------------------------------------------------------------------

/// Witness (private inputs to the Plonky3 prover).
///
/// None of these fields appear on-chain. The prover holds them in local
/// memory and discards them after proof generation.
///
/// **C++ mirror**: `uno_workchain::MineUnoWitness` in `mine_uno.h`.
/// Field names must match exactly.
///
/// AIR constraint mapping:
///   - `nonce`      → Constraint 1 (PoW preimage)
///   - `recipient`  → Constraint 2 (cm derivation), Constraint 6 (addr valid)
///   - `rseed`      → Constraint 2 (rcm = Poseidon2("uno-rcm-v1", rseed))
///   - `epoch`      → Constraint 1 (PoW preimage), Constraint 3 (halving)
///   - `value_nano` → Constraint 3 (halving table), Constraint 4 (conservation)
///
/// See `doc/uno-mine-air-constraints.md` for the full spec.
#[derive(Clone, Debug)]
pub struct MineUnoWitness {
    /// Current mining epoch (= cumulative successful solves before this solve).
    /// Public — appears in [`MineUnoPublicInputs`] and in the AIR.
    /// The era is `mine_constants::era_from_epoch(epoch)`.
    pub epoch: u32,

    /// 32-byte proof-of-work nonce (private). Miner searches for a nonce such
    /// that `Poseidon2("uno-mine-v1" ‖ epoch ‖ nonce ‖ output_cm) < target`.
    /// This is the inner loop of `tosctl uno mine` (Phase 2 tosctl command).
    pub nonce: [u8; DIGEST],

    /// Recipient's Uno address (private, 1259 B). Used to derive `output_cm`
    /// (Constraint 2) and to validate field sizes (Constraint 6).
    pub recipient: MineUnoAddress,

    /// Mint amount in nano-UNO. Must equal `mine_reward_for_epoch(epoch)`.
    /// Checked by AIR Constraint 3 against the baked-in halving table.
    pub value_nano: u64,

    /// 32-byte randomness seed for commitment derivation (private).
    /// `rcm = Poseidon2("uno-rcm-v1", rseed)` (§3.1), then
    /// `output_cm = Poseidon2("uno-cm-v1", d, pk_d, ivk_commitment, value_nano, rcm)`.
    pub rseed: [u8; DIGEST],
    // Note: halving_era is DERIVED — use era_from_epoch(self.epoch).
}

impl MineUnoWitness {
    /// Validate that the witness is internally consistent (off-circuit checks).
    ///
    /// Does NOT invoke the Plonky3 prover. Use this before allocating proof
    /// resources to fail-fast on obviously wrong inputs.
    ///
    /// Checks:
    /// 1. `value_nano == mine_reward_for_epoch(epoch)` (halving table check).
    /// 2. `recipient.pk_mlkem.len() == 1184` (address well-form, field sizes).
    pub fn validate(&self) -> Result<()> {
        let expected = mine_reward_for_epoch(self.epoch);
        if self.value_nano != expected {
            bail!(
                "MineUnoWitness: value_nano {} does not match halving-table \
                 reward {} for epoch {} (era {})",
                self.value_nano,
                expected,
                self.epoch,
                self.epoch as u64 / ERA_SIZE,
            );
        }
        self.recipient.validate()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MineUnoPublicInputs — visible on-chain, bound into proof
// ---------------------------------------------------------------------------

/// Public inputs (visible on-chain, included in proof verification).
///
/// The Fiat-Shamir verifier binds these fields into the proof's transcript so
/// they cannot be modified without invalidating the proof.
///
/// **C++ mirror**: `uno_workchain::MineUnoPublicInputs` in `mine_uno.h`.
/// Field names and ordering must match exactly.
///
/// Wire layout (inline in the MineUno cell header, Phase 2):
///   epoch(u32,BE) target(32B) value_nano(u64,BE) output_cm(32B)
///   remaining_pre(u64,BE) remaining_post(u64,BE)
/// Total: 4 + 32 + 8 + 32 + 8 + 8 = 92 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MineUnoPublicInputs {
    /// Current mining epoch (= cumulative solve count before this solve).
    pub epoch: u32,

    /// 32-byte PoW difficulty target (big-endian). Sourced from chain state
    /// `mine_target` at proof-generation time. PoW constraint:
    /// `Poseidon2("uno-mine-v1" ‖ epoch ‖ nonce ‖ output_cm) < target`.
    pub target: [u8; DIGEST],

    /// Mint amount in nano-UNO. Must equal `mine_reward_for_epoch(epoch)`.
    pub value_nano: u64,

    /// Note commitment for the newly minted output note.
    /// `output_cm = Poseidon2("uno-cm-v1", d, pk_d, ivk_commitment, value, rcm)`.
    /// Appended to the commitment tree on-chain when the tx is applied.
    pub output_cm: [u8; DIGEST],

    /// Chain's `mine_remaining` BEFORE this transaction.
    /// Mismatch with current chain state = race condition (another miner won).
    pub remaining_pre: u64,

    /// Chain's `mine_remaining` AFTER this transaction.
    /// Must satisfy: `remaining_post == remaining_pre - value_nano`.
    pub remaining_post: u64,
}

impl MineUnoPublicInputs {
    /// Serialize to wire bytes (big-endian integers, matching C++ encoder).
    /// Layout: epoch(4) target(32) value_nano(8) output_cm(32)
    ///         remaining_pre(8) remaining_post(8) = 92 bytes total.
    pub fn to_wire_bytes(&self) -> [u8; 92] {
        let mut out = [0u8; 92];
        out[0..4].copy_from_slice(&self.epoch.to_be_bytes());
        out[4..36].copy_from_slice(&self.target);
        out[36..44].copy_from_slice(&self.value_nano.to_be_bytes());
        out[44..76].copy_from_slice(&self.output_cm);
        out[76..84].copy_from_slice(&self.remaining_pre.to_be_bytes());
        out[84..92].copy_from_slice(&self.remaining_post.to_be_bytes());
        out
    }

    /// Deserialize from wire bytes produced by `to_wire_bytes`.
    pub fn from_wire_bytes(b: &[u8; 92]) -> Self {
        let mut target = [0u8; DIGEST];
        let mut output_cm = [0u8; DIGEST];
        target.copy_from_slice(&b[4..36]);
        output_cm.copy_from_slice(&b[44..76]);
        Self {
            epoch:          u32::from_be_bytes(b[0..4].try_into().unwrap()),
            target,
            value_nano:     u64::from_be_bytes(b[36..44].try_into().unwrap()),
            output_cm,
            remaining_pre:  u64::from_be_bytes(b[76..84].try_into().unwrap()),
            remaining_post: u64::from_be_bytes(b[84..92].try_into().unwrap()),
        }
    }

    /// Off-circuit validation (pre-proof fast checks).
    ///
    /// 1. `value_nano == mine_reward_for_epoch(epoch)` (halving table).
    /// 2. `remaining_pre >= value_nano` (no underflow / cap violation).
    /// 3. `remaining_post == remaining_pre - value_nano` (conservation).
    /// 4. `remaining_pre <= MINE_SUPPLY_NANO` (sanity — chain enforces).
    pub fn validate(&self) -> Result<()> {
        let expected = mine_reward_for_epoch(self.epoch);
        if self.value_nano != expected {
            bail!(
                "MineUnoPublicInputs: value_nano {} ≠ halving-table \
                 reward {} for epoch {}",
                self.value_nano,
                expected,
                self.epoch
            );
        }
        if self.remaining_pre < self.value_nano {
            bail!(
                "MineUnoPublicInputs: remaining_pre {} < value_nano {} \
                 (over-mint / cap violation)",
                self.remaining_pre,
                self.value_nano
            );
        }
        let expected_post = self.remaining_pre - self.value_nano;
        if self.remaining_post != expected_post {
            bail!(
                "MineUnoPublicInputs: remaining_post {} ≠ remaining_pre - \
                 value_nano = {}",
                self.remaining_post,
                expected_post
            );
        }
        if self.remaining_pre > MINE_SUPPLY_NANO {
            bail!(
                "MineUnoPublicInputs: remaining_pre {} > total supply {}",
                self.remaining_pre,
                MINE_SUPPLY_NANO
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MineUno — full decoded transaction (Phase 2 codec TBD)
// ---------------------------------------------------------------------------

/// A fully decoded MineUno transaction.
///
/// This is the in-memory representation after `decode_mine_uno()` (Phase 2).
/// The witness fields are absent — they are consumed by the prover and discarded.
///
/// Wire layout (Phase 2 spec):
///   tx_kind(1) version(1) scheme_id(1) chain_id(4) [MineUnoPublicInputs 92B]
///   zk_proof:^Cell  (Plonky3 STARK proof, chunk-tree layout per §4.1a)
/// Total inline: 99 bytes + 1 ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MineUno {
    pub tx_kind: u8,
    pub version: u8,
    pub scheme_id: u8,
    pub chain_id: u32,
    pub public_inputs: MineUnoPublicInputs,
    /// Raw STARK proof bytes. `None` for Phase 1 stubs; populated by Phase 2 decoder.
    pub zk_proof: Option<Vec<u8>>,
}

impl MineUno {
    /// Encode the inline header (no proof cell) to wire bytes for testing.
    /// Phase 2 will replace this with a full BoC encoder (Cell + refs).
    ///
    /// Layout: tx_kind(1) version(1) scheme_id(1) chain_id(4)
    ///         [MineUnoPublicInputs 92 B] = 99 bytes.
    pub fn encode_header(&self) -> [u8; 99] {
        let mut out = [0u8; 99];
        out[0] = self.tx_kind;
        out[1] = self.version;
        out[2] = self.scheme_id;
        out[3..7].copy_from_slice(&self.chain_id.to_be_bytes());
        out[7..99].copy_from_slice(&self.public_inputs.to_wire_bytes());
        out
    }

    /// Decode the inline header from 99 bytes.
    pub fn decode_header(b: &[u8; 99]) -> Result<Self> {
        if b[0] != TX_KIND_MINE_UNO {
            bail!("MineUno::decode_header: tx_kind {} ≠ {}", b[0], TX_KIND_MINE_UNO);
        }
        let mut pi_bytes = [0u8; 92];
        pi_bytes.copy_from_slice(&b[7..99]);
        Ok(Self {
            tx_kind: b[0],
            version: b[1],
            scheme_id: b[2],
            chain_id: u32::from_be_bytes(b[3..7].try_into().unwrap()),
            public_inputs: MineUnoPublicInputs::from_wire_bytes(&pi_bytes),
            zk_proof: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Serialization stubs (Phase 2 will replace with BoC codec)
// ---------------------------------------------------------------------------

/// Encode a MineUno transaction to a flat byte buffer.
///
/// **Phase 1 stub**: returns an error. Phase 2 will implement the full
/// BoC cell-tree encoder (mirror of `encode_transfer_boc` for Transfer).
pub fn encode_mine_uno_wire(_tx: &MineUno) -> Result<Vec<u8>> {
    // TODO(uno-mine-v1, Phase 2): implement full BoC encoder.
    // Must produce a Cell tree byte-identical to what the C++ daemon's
    // `decode_mine_uno_bytes()` accepts.
    bail!("encode_mine_uno_wire: not implemented (Phase 2)")
}

/// Decode a MineUno transaction from a flat byte buffer.
///
/// **Phase 1 stub**: returns an error. Phase 2 will implement the full
/// BoC cell-tree decoder.
pub fn decode_mine_uno_wire(_bytes: &[u8]) -> Result<MineUno> {
    // TODO(uno-mine-v1, Phase 2): implement full BoC decoder.
    bail!("decode_mine_uno_wire: not implemented (Phase 2)")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mine_constants::INIT_MINE_REWARD;

    fn make_address() -> MineUnoAddress {
        MineUnoAddress {
            diversifier: [0x01; 11],
            pk_d_compressed: [0x02; 32],
            ivk_commitment: [0x03; 32],
            pk_mlkem: vec![0x04u8; 1184],
        }
    }

    fn make_public_inputs() -> MineUnoPublicInputs {
        MineUnoPublicInputs {
            epoch: 0,
            target: [0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            value_nano: INIT_MINE_REWARD,
            output_cm: [0xaa; 32],
            remaining_pre: MINE_SUPPLY_NANO,
            remaining_post: MINE_SUPPLY_NANO - INIT_MINE_REWARD,
        }
    }

    #[test]
    fn public_inputs_wire_roundtrip() {
        let pi = make_public_inputs();
        let bytes = pi.to_wire_bytes();
        let pi2 = MineUnoPublicInputs::from_wire_bytes(&bytes);
        assert_eq!(pi, pi2);
    }

    #[test]
    fn public_inputs_validate_ok() {
        make_public_inputs().validate().unwrap();
    }

    #[test]
    fn public_inputs_validate_wrong_value() {
        let mut pi = make_public_inputs();
        pi.value_nano += 1;
        assert!(pi.validate().is_err());
    }

    #[test]
    fn public_inputs_validate_conservation_fail() {
        let mut pi = make_public_inputs();
        pi.remaining_post += 1; // tampered
        assert!(pi.validate().is_err());
    }

    #[test]
    fn public_inputs_validate_overmint() {
        let mut pi = make_public_inputs();
        // Set remaining_pre = 0 but keep value_nano = era-0 reward → underflow.
        pi.remaining_pre = 0;
        pi.remaining_post = 0;
        // value_nano mismatch will be checked first; but set to 0 too:
        pi.value_nano = 0;
        // Now conservation passes (0 - 0 = 0) but epoch-0 reward check fails.
        assert!(pi.validate().is_err());
    }

    #[test]
    fn mine_uno_header_roundtrip() {
        let tx = MineUno {
            tx_kind:   TX_KIND_MINE_UNO,
            version:   MINE_UNO_VERSION,
            scheme_id: 0x01,
            chain_id:  0x554E4F54,
            public_inputs: make_public_inputs(),
            zk_proof: None,
        };
        let header = tx.encode_header();
        let tx2 = MineUno::decode_header(&header).unwrap();
        assert_eq!(tx, tx2);
    }

    #[test]
    fn witness_validate_ok() {
        let w = MineUnoWitness {
            epoch: 0,
            nonce: [0xbb; 32],
            recipient: make_address(),
            value_nano: INIT_MINE_REWARD,
            rseed: [0xcc; 32],
        };
        w.validate().unwrap();
    }

    #[test]
    fn witness_validate_wrong_value() {
        let w = MineUnoWitness {
            epoch: 0,
            nonce: [0xbb; 32],
            recipient: make_address(),
            value_nano: INIT_MINE_REWARD + 1,
            rseed: [0xcc; 32],
        };
        assert!(w.validate().is_err());
    }

    #[test]
    fn witness_validate_wrong_pk_mlkem_len() {
        let mut addr = make_address();
        addr.pk_mlkem = vec![0u8; 512]; // wrong length
        let w = MineUnoWitness {
            epoch: 0,
            nonce: [0xbb; 32],
            recipient: addr,
            value_nano: INIT_MINE_REWARD,
            rseed: [0xcc; 32],
        };
        assert!(w.validate().is_err());
    }

    #[test]
    fn encode_decode_stubs_return_err() {
        let tx = MineUno {
            tx_kind: TX_KIND_MINE_UNO,
            version: MINE_UNO_VERSION,
            scheme_id: 0x01,
            chain_id: 0,
            public_inputs: make_public_inputs(),
            zk_proof: None,
        };
        assert!(encode_mine_uno_wire(&tx).is_err());
        assert!(decode_mine_uno_wire(&[]).is_err());
    }
}
