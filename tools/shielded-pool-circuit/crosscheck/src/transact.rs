/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 12.2's transact message, built from what the circuit proved.
//!
//! A wallet builds this. It is here rather than in a test because two tests
//! need it -- a transfer and a withdrawal -- and a second copy of a wire
//! format is a second thing to keep in step with section 12.2.

use chain_block::{BuilderData, Cell, IBitstring};
use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::public_inputs::PublicInputs;
use shielded_pool_circuit::{groth16, imt, wire};

use crate::imt_probe::encode_witness;
use crate::pool::{be, refs_only, store_coins};
use crate::wire::byte_chain;
use crate::{CrossCheckError, Result};

pub const OP_TRANSACT: u32 = 0x5348_5002;
/// Section 9.4: exactly 28 ASCII bytes, and it never varies.
pub const SIGNATURE_CONTEXT: &[u8] = b"TOS-SHIELDED-POOL-MLDSA44-v1";

/// A one-time ML-DSA-44 key, as section 4.1 requires per note.
pub struct AuthKey {
    pub public: [u8; 1312],
    secret: ml_dsa_44::PrivateKey,
}

impl AuthKey {
    pub fn generate() -> Result<Self> {
        let (public, secret) = ml_dsa_44::try_keygen()
            .map_err(|error| CrossCheckError::Fixture(format!("ML-DSA-44 keygen: {error}")))?;
        Ok(AuthKey { public: public.into_bytes(), secret })
    }

    /// Section 4.1, and public inputs 9 and 10.
    pub fn hash(&self) -> Fr {
        wire::pq_auth_key_hash(&self.public)
    }

    /// Section 9.4: FIPS 204 pure ML-DSA-44 over the digest's 32 big-endian
    /// bytes, under the fixed context.
    pub fn sign(&self, digest: Fr) -> Result<[u8; 2420]> {
        self.secret
            .try_sign(&be(digest), SIGNATURE_CONTEXT)
            .map_err(|error| CrossCheckError::Fixture(format!("ML-DSA-44 signing: {error}")))
    }
}

/// The recipient of a withdrawal, or `None` for a transfer.
#[derive(Clone, Copy)]
pub struct Recipient(pub [u8; 32]);

/// Section 6's three anchor kinds: which root the proof is against.
///
/// The current root needs no id and reads nothing; the other two name a slot
/// in one of the rings, and the contract accepts them only on an exact match
/// of the pair stored there.
#[derive(Clone, Copy, Debug)]
pub enum Anchor {
    Current,
    Recent(u32),
    Epoch(u32),
}

impl Anchor {
    fn kind_and_id(self) -> (u8, u32) {
        match self {
            Anchor::Current => (0, 0),
            Anchor::Recent(id) => (1, id),
            Anchor::Epoch(id) => (2, id),
        }
    }
}

/// Everything section 12.2 puts on the wire that the proof does not carry.
///
/// `keys` is public bytes rather than keypairs on purpose: the signatures are
/// made by whoever holds the secrets -- a wallet derives its own from the
/// mnemonic and never hands them over -- and this only has to write them down.
pub struct Transact<'a> {
    pub public: &'a PublicInputs,
    pub proof: &'a groth16::CanonicalProof,
    pub anchor_root: Fr,
    /// Which of section 6's roots `anchor_root` is, and its id.
    pub anchor: Anchor,
    pub valid_until: u32,
    pub output_payloads: &'a [Vec<u8>; 3],
    pub keys: [&'a [u8; 1312]; 2],
    pub signatures: &'a [[u8; 2420]; 2],
    pub witnesses: &'a [imt::Witness; 2],
    /// A withdrawal's terms. A transfer leaves all three at their zero form.
    pub public_amount_out: u64,
    pub withdrawal_fee: u64,
    pub recipient: Option<Recipient>,
    /// Section 15.1: pre-authorised recovery material, for a withdrawal only.
    pub recovery_owner_commitment: Fr,
    pub recovery_payload: Option<Vec<u8>>,
}

fn cell_of(builder: BuilderData) -> Result<Cell> {
    builder.into_cell().map_err(|error| CrossCheckError::Sandbox(format!("cell: {error}")))
}

impl Transact<'_> {
    pub fn body(&self) -> Result<Cell> {
        let sandbox = |error: chain_block::Error| CrossCheckError::Sandbox(format!("{error}"));

        // Section 12.2's proof bundle: the anchor, the two nullifiers, the
        // three note bodies and the proof.
        let mut proof_bundle = BuilderData::new();
        proof_bundle
            .append_raw(&be(self.anchor_root), 256)
            .and_then(|b| b.append_raw(&be(self.public.nullifier_0), 256))
            .and_then(|b| b.append_raw(&be(self.public.nullifier_1), 256))
            .map_err(sandbox)?;
        let mut bodies = BuilderData::new();
        for body in [self.public.note_body_0, self.public.note_body_1, self.public.note_body_2] {
            bodies.append_raw(&be(body), 256).map_err(sandbox)?;
        }
        proof_bundle.checked_append_reference(cell_of(bodies)?).map_err(sandbox)?;

        // Section 10.1: A and C in the root, B in the reference.
        let mut proof_ac = BuilderData::new();
        proof_ac
            .append_raw(&self.proof.a, 384)
            .and_then(|b| b.append_raw(&self.proof.c, 384))
            .map_err(sandbox)?;
        let mut proof_b = BuilderData::new();
        proof_b.append_raw(&self.proof.b, 768).map_err(sandbox)?;
        proof_ac.checked_append_reference(cell_of(proof_b)?).map_err(sandbox)?;
        proof_bundle.checked_append_reference(cell_of(proof_ac)?).map_err(sandbox)?;

        // The output bundle: the recovery owner commitment, the three
        // payloads, and the recovery payload a withdrawal pre-authorises.
        let mut output = BuilderData::new();
        output.append_raw(&be(self.recovery_owner_commitment), 256).map_err(sandbox)?;
        for bytes in self.output_payloads {
            output.checked_append_reference(byte_chain(bytes)?).map_err(sandbox)?;
        }
        let recovery = match &self.recovery_payload {
            None => Cell::default(),
            Some(bytes) => byte_chain(bytes)?,
        };
        output.checked_append_reference(recovery).map_err(sandbox)?;

        let auth = refs_only(&[
            byte_chain(self.keys[0])?,
            byte_chain(&self.signatures[0])?,
            byte_chain(self.keys[1])?,
            byte_chain(&self.signatures[1])?,
        ])?;
        let witnesses =
            refs_only(&[encode_witness(&self.witnesses[0])?, encode_witness(&self.witnesses[1])?])?;

        let digest = be(self.public.transaction_intent_digest);
        let query_id = u64::from_be_bytes(
            digest[24..]
                .try_into()
                .map_err(|_| CrossCheckError::Fixture("a digest that is not 32 bytes".into()))?,
        );

        let (kind, id) = self.anchor.kind_and_id();
        let mut builder = BuilderData::new();
        builder
            .append_u32(OP_TRANSACT)
            .and_then(|b| b.append_u64(query_id))
            .and_then(|b| b.append_u8(kind))
            .and_then(|b| b.append_u32(id))
            .and_then(|b| b.append_u32(self.valid_until))
            .map_err(sandbox)?;
        store_coins(&mut builder, u128::from(self.public_amount_out))?;
        store_coins(&mut builder, u128::from(self.withdrawal_fee))?;
        match &self.recipient {
            None => {
                builder.append_bits(0, 2).map_err(sandbox)?;
            }
            Some(Recipient(account)) => {
                builder
                    .append_bits(2, 2)
                    .and_then(|b| b.append_bit_zero())
                    .and_then(|b| b.append_i8(0))
                    .and_then(|b| b.append_raw(account, 256))
                    .map_err(sandbox)?;
            }
        }
        builder
            .append_raw(&digest, 256)
            .and_then(|b| b.checked_append_reference(cell_of(proof_bundle)?))
            .and_then(|b| b.checked_append_reference(cell_of(output)?))
            .and_then(|b| b.checked_append_reference(auth))
            .and_then(|b| b.checked_append_reference(witnesses))
            .map_err(sandbox)?;
        cell_of(builder)
    }
}
