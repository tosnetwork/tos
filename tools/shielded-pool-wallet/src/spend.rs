/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! From a plan to what a transact message carries: the sealed payloads, the
//! public inputs and private witness of the proof, and the two ML-DSA
//! signatures over the intent.
//!
//! Everything here is derived from the plan, the instance's keys and the
//! randomness the caller supplies. Proving happens elsewhere (the production
//! prover crate); so does the nullifier tree's witness, which has to be taken
//! against the tree at inclusion and is therefore built last, by the caller,
//! from [`nullifier_witnesses`].

use crate::delivery::{self, Kind, Plaintext, RECOVERY_PAYLOAD_SLOT};
use crate::error::{Error, Result};
use crate::keys::{PoolInstance, MLDSA_PUBLIC_KEY_BYTES, MLDSA_SIGNATURE_BYTES};
use crate::plan::{Plan, PlannedInput, PlannedOutput, MAX_INPUTS, OUTPUT_SLOTS};
use ark_ff::{AdditiveGroup, Zero};
use shielded_pool_circuit::circuit::{
    HeldNote, OutputNote, TransactionBuilder, TransactionWitness,
};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::public_inputs::PublicInputs;
use shielded_pool_circuit::tree::Frontier;
use shielded_pool_circuit::{domains, imt, notes, wire};

/// The terms the proof and the signatures bind that are not the plan's: the
/// root the inputs are proven against, the expiry and the nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    pub anchor_root: Fr,
    pub valid_until: u32,
    /// Non-zero and fresh (section 11.4); the phantom nullifier derives from
    /// it.
    pub intent_nonce: Fr,
}

/// A spend, assembled: everything a transact body carries except the proof
/// and the nullifier witnesses.
pub struct Assembled {
    pub public: PublicInputs,
    pub witness: TransactionWitness,
    /// The three output slots' sealed payloads.
    pub payloads: [Vec<u8>; OUTPUT_SLOTS],
    /// Section 15.1; zero and `None` for a transfer.
    pub recovery_owner_commitment: Fr,
    pub recovery_payload: Option<Vec<u8>>,
    /// The signing keys of the two input slots and their signatures over the
    /// intent digest.
    pub input_keys: [[u8; MLDSA_PUBLIC_KEY_BYTES]; MAX_INPUTS],
    pub signatures: [[u8; MLDSA_SIGNATURE_BYTES]; MAX_INPUTS],
    /// The note-key index each input slot signs with.
    pub input_indices: [u64; MAX_INPUTS],
}

impl Assembled {
    pub fn intent_digest(&self) -> Fr {
        self.public.transaction_intent_digest
    }

    pub fn nullifiers(&self) -> [Fr; MAX_INPUTS] {
        [self.public.nullifier_0, self.public.nullifier_1]
    }
}

fn circuit(error: shielded_pool_circuit::error::Error) -> Error {
    Error::Encoding(format!("circuit: {error}"))
}

fn nonzero(value: Fr, what: &str) -> Result<Fr> {
    if value.is_zero() {
        return Err(Error::Encoding(format!("{what} drawn as zero")));
    }
    Ok(value)
}

/// Seals one plaintext to `encapsulation_key` and returns the payload with
/// the hash the chain will compute over it.
fn seal(
    instance: &PoolInstance,
    encapsulation_key: &[u8; crate::keys::MLKEM_ENCAPSULATION_KEY_BYTES],
    plaintext: &Plaintext,
) -> Result<(Vec<u8>, Fr)> {
    let payload = delivery::seal(encapsulation_key, instance.execution_domain(), plaintext)?;
    let hash = wire::output_data_hash(&payload);
    Ok((payload, hash))
}

/// Everything of a spend but its signatures: the public inputs (and so both
/// nullifiers and the intent digest), the witness, the sealed payloads, the
/// recovery material and the keys of the two input slots. A caller makes
/// the spend durable from this and signs afterwards with [`Prepared::sign`].
pub struct Prepared {
    pub public: PublicInputs,
    pub witness: TransactionWitness,
    pub payloads: [Vec<u8>; OUTPUT_SLOTS],
    pub recovery_owner_commitment: Fr,
    pub recovery_payload: Option<Vec<u8>>,
    pub input_keys: [[u8; MLDSA_PUBLIC_KEY_BYTES]; MAX_INPUTS],
    pub input_indices: [u64; MAX_INPUTS],
}

impl Prepared {
    pub fn intent_digest(&self) -> Fr {
        self.public.transaction_intent_digest
    }

    pub fn nullifiers(&self) -> [Fr; MAX_INPUTS] {
        [self.public.nullifier_0, self.public.nullifier_1]
    }

    /// Section 9.1: two signatures always, each by the key of its slot. The
    /// last step, so that what the signatures commit to can be recorded
    /// before any key signs it.
    pub fn sign(self, instance: &PoolInstance) -> Result<Assembled> {
        let digest = self.public.transaction_intent_digest;
        let signatures = [
            instance.sign_intent(self.input_indices[0], digest)?,
            instance.sign_intent(self.input_indices[1], digest)?,
        ];
        Ok(Assembled {
            public: self.public,
            witness: self.witness,
            payloads: self.payloads,
            recovery_owner_commitment: self.recovery_owner_commitment,
            recovery_payload: self.recovery_payload,
            input_keys: self.input_keys,
            signatures,
            input_indices: self.input_indices,
        })
    }
}

/// Prepares and signs one planned spend in one step.
pub fn assemble(
    instance: &PoolInstance,
    plan: &Plan,
    frontier: &Frontier,
    terms: &Terms,
    fresh: &mut dyn FnMut() -> Result<Fr>,
) -> Result<Assembled> {
    prepare(instance, plan, frontier, terms, fresh)?.sign(instance)
}

/// Builds the public inputs, the witness and the payloads of one planned
/// spend, unsigned. `fresh` supplies note secrets and the phantom input's
/// filler, non-zero and never reused.
pub fn prepare(
    instance: &PoolInstance,
    plan: &Plan,
    frontier: &Frontier,
    terms: &Terms,
    fresh: &mut dyn FnMut() -> Result<Fr>,
) -> Result<Prepared> {
    plan.check_conservation()?;
    nonzero(terms.intent_nonce, "the intent nonce")?;
    let own_encapsulation_key = instance.mlkem_encapsulation_key()?;

    // Inputs. A real note presents the keys of its own index; a phantom
    // presents the keys of the fresh index the plan reserved for it, and a
    // body nobody holds.
    let mut held: Vec<HeldNote> = Vec::with_capacity(MAX_INPUTS);
    let mut input_pq_auth_key_hash: Vec<Fr> = Vec::with_capacity(MAX_INPUTS);
    let mut input_indices: Vec<u64> = Vec::with_capacity(MAX_INPUTS);
    for input in &plan.inputs {
        let (index, note) = match input {
            PlannedInput::Note(candidate) => (
                candidate.note.note_key_index,
                HeldNote {
                    is_phantom: false,
                    owner_nf_key: instance.owner_nf_key(candidate.note.note_key_index)?,
                    note_secret: candidate.note.note_secret,
                    amount: Fr::from(candidate.note.amount),
                    output_data_hash: candidate.note.output_data_hash,
                    leaf_index: candidate.leaf_index,
                },
            ),
            PlannedInput::Phantom { note_key_index } => (
                *note_key_index,
                HeldNote {
                    is_phantom: true,
                    owner_nf_key: instance.owner_nf_key(*note_key_index)?,
                    note_secret: nonzero(fresh()?, "a phantom's note secret")?,
                    amount: Fr::ZERO,
                    output_data_hash: nonzero(fresh()?, "a phantom's data hash")?,
                    leaf_index: 0,
                },
            ),
        };
        input_pq_auth_key_hash.push(instance.pq_auth_key_hash(index)?);
        input_indices.push(index);
        held.push(note);
    }

    // Outputs, sealed first so their data hashes can go into the bodies.
    let mut outputs: Vec<OutputNote> = Vec::with_capacity(OUTPUT_SLOTS);
    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(OUTPUT_SLOTS);
    let mut output_data_hash: Vec<Fr> = Vec::with_capacity(OUTPUT_SLOTS);
    for (slot, output) in plan.outputs.iter().enumerate() {
        let slot_u8 = u8::try_from(slot).map_err(|_| Error::Encoding("slot".into()))?;
        let note_secret = nonzero(fresh()?, "an output's note secret")?;
        let (note, plaintext, encapsulation_key) = match output {
            PlannedOutput::Recipient { to, amount } => (
                OutputNote {
                    is_dummy: false,
                    owner_nf_key_hash: to.owner_nf_key_hash,
                    pq_auth_key_hash: to.pq_auth_key_hash,
                    note_secret,
                    amount: Fr::from(*amount),
                },
                Plaintext {
                    slot: slot_u8,
                    kind: Kind::Ordinary,
                    amount: *amount,
                    note_secret,
                    owner_nf_key_hash: to.owner_nf_key_hash,
                    note_key_index: to.note_key_index,
                    pq_auth_key_hash: to.pq_auth_key_hash,
                },
                to.encapsulation_key,
            ),
            PlannedOutput::Change { note_key_index, amount } => {
                let owner_nf_key_hash = instance.owner_nf_key_hash(*note_key_index)?;
                let pq_auth_key_hash = instance.pq_auth_key_hash(*note_key_index)?;
                (
                    OutputNote {
                        is_dummy: false,
                        owner_nf_key_hash,
                        pq_auth_key_hash,
                        note_secret,
                        amount: Fr::from(*amount),
                    },
                    Plaintext {
                        slot: slot_u8,
                        kind: Kind::Ordinary,
                        amount: *amount,
                        note_secret,
                        owner_nf_key_hash,
                        note_key_index: *note_key_index,
                        pq_auth_key_hash,
                    },
                    own_encapsulation_key,
                )
            }
            // Section 3: the dummy constant as owner, this wallet's throwaway
            // PQ key of a consumed index, sealed to this wallet.
            PlannedOutput::Dummy { note_key_index } => {
                let owner_nf_key_hash = domains::dummy_owner_nf_hash();
                let pq_auth_key_hash = instance.pq_auth_key_hash(*note_key_index)?;
                (
                    OutputNote {
                        is_dummy: true,
                        owner_nf_key_hash,
                        pq_auth_key_hash,
                        note_secret,
                        amount: Fr::ZERO,
                    },
                    Plaintext {
                        slot: slot_u8,
                        kind: Kind::Dummy,
                        amount: 0,
                        note_secret,
                        owner_nf_key_hash,
                        note_key_index: *note_key_index,
                        pq_auth_key_hash,
                    },
                    own_encapsulation_key,
                )
            }
        };
        let (payload, hash) = seal(instance, &encapsulation_key, &plaintext)?;
        outputs.push(note);
        payloads.push(payload);
        output_data_hash.push(hash);
    }

    // Section 15.1: a withdrawal pre-authorises the keys of its recovery note,
    // not an amount.
    let (recovery_owner_commitment, recovery_payload, recovery_template_hash) = match &plan.recovery
    {
        Some(recovery) => {
            let index = recovery.note_key_index;
            let owner_nf_key_hash = instance.owner_nf_key_hash(index)?;
            let pq_auth_key_hash = instance.pq_auth_key_hash(index)?;
            let note_secret = nonzero(fresh()?, "the recovery note secret")?;
            let plaintext = Plaintext {
                slot: RECOVERY_PAYLOAD_SLOT,
                kind: Kind::Recovery,
                amount: 0,
                note_secret,
                owner_nf_key_hash,
                note_key_index: index,
                pq_auth_key_hash,
            };
            let (payload, hash) = seal(instance, &own_encapsulation_key, &plaintext)?;
            let owner = notes::owner_commitment(owner_nf_key_hash, pq_auth_key_hash, note_secret);
            (owner, Some(payload), wire::recovery_template_hash(owner, hash))
        }
        None => (Fr::ZERO, None, Fr::ZERO),
    };
    if plan.is_withdrawal() != recovery_payload.is_some() {
        return Err(Error::Encoding("a withdrawal without a recovery plan, or the reverse".into()));
    }
    let public_recipient_hash = match (&plan.recipient_account, plan.is_withdrawal()) {
        (Some(account), true) => wire::public_recipient_hash(account),
        (None, false) => Fr::ZERO,
        _ => {
            return Err(Error::Encoding("a recipient without a withdrawal, or the reverse".into()))
        }
    };

    let outputs: [OutputNote; OUTPUT_SLOTS] =
        outputs.try_into().map_err(|_| Error::Encoding("three output slots".into()))?;
    let output_data_hash: [Fr; OUTPUT_SLOTS] =
        output_data_hash.try_into().map_err(|_| Error::Encoding("three data hashes".into()))?;
    let payloads: [Vec<u8>; OUTPUT_SLOTS] =
        payloads.try_into().map_err(|_| Error::Encoding("three payloads".into()))?;
    let input_pq_auth_key_hash: [Fr; MAX_INPUTS] =
        input_pq_auth_key_hash.try_into().map_err(|_| Error::Encoding("two inputs".into()))?;
    let held: [HeldNote; MAX_INPUTS] =
        held.try_into().map_err(|_| Error::Encoding("two inputs".into()))?;
    let input_indices: [u64; MAX_INPUTS] =
        input_indices.try_into().map_err(|_| Error::Encoding("two inputs".into()))?;

    let builder = TransactionBuilder {
        execution_domain: instance.execution_domain(),
        valid_until: terms.valid_until,
        intent_nonce: terms.intent_nonce,
        public_amount_out: Fr::from(plan.public_amount_out),
        withdrawal_fee: Fr::from(plan.withdrawal_fee),
        is_withdrawal: Some(plan.is_withdrawal()),
        public_recipient_hash,
        recovery_template_hash,
        input_pq_auth_key_hash,
        outputs,
        output_data_hash,
    };
    let (public, witness) = builder.build(frontier, terms.anchor_root, held).map_err(circuit)?;
    let input_keys = [
        instance.mldsa_public_key(input_indices[0])?,
        instance.mldsa_public_key(input_indices[1])?,
    ];

    Ok(Prepared {
        public,
        witness,
        payloads,
        recovery_owner_commitment,
        recovery_payload,
        input_keys,
        input_indices,
    })
}

/// Section 7.1: the two non-membership and insertion witnesses, the second
/// taken against the tree the first insertion leaves, as the contract
/// inserts them. `state` is the nullifier tree at inclusion; it is not
/// advanced.
pub fn nullifier_witnesses(
    state: &imt::State,
    nullifiers: [Fr; MAX_INPUTS],
) -> Result<[imt::Witness; MAX_INPUTS]> {
    let mut working = state.clone();
    let (first, after_first) = working.witness_for(&nullifiers[0]).map_err(circuit)?;
    working.apply(after_first);
    let (second, _) = working.witness_for(&nullifiers[1]).map_err(circuit)?;
    Ok([first, second])
}
