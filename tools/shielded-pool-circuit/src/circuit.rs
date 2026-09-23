/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Profile section 11: the transaction relations, with the section 10 public
//! input vector.
//!
//! Every relation carries a switch. The switches exist for one reason: the
//! acceptance gate requires each relation to be removed one at a time and the
//! exploit it prevents to become accepted. A relation nobody can turn off is a
//! relation nobody has shown to be load-bearing. [`Relations::ALL`] is the only
//! set a real proof is ever built with, and [`ShieldedTransactionCircuit::new`]
//! is the only constructor that reaches the fixtures.

use ark_ff::AdditiveGroup;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::ops::Not;

use crate::domains;
use crate::error::{Error, Result};
use crate::field::{fr_from_u128, Fr};
use crate::gadgets::notes as note_gadget;
use crate::gadgets::poseidon2::FrVar;
use crate::gadgets::range;
use crate::gadgets::tree as tree_gadget;
use crate::public_inputs::PublicInputs;
use crate::tree::MerklePath;
use crate::{notes, tree};

/// Profile section 11.1 and 11.2: every amount is below this.
pub const AMOUNT_BITS: usize = 120;
/// Profile section 5: leaf indices stay uint32.
pub const LEAF_INDEX_BITS: usize = 32;

/// One spent note, or a phantom input slot.
#[derive(Clone, Debug)]
pub struct InputNote {
    /// Section 11.1: the boolean that selects the phantom branch. The same
    /// boolean removes the amount from conservation; there is no second flag.
    pub is_phantom: bool,
    pub owner_nf_key: Fr,
    pub note_secret: Fr,
    /// The amount as a field element. It is not a `u128`: the circuit's job is
    /// to prove it is one, and a witness type that could not express an
    /// out-of-range amount would make the range relation untestable.
    pub amount: Fr,
    /// The `output_data_hash` the note carried when it was created.
    pub output_data_hash: Fr,
    pub leaf_index: u64,
    pub path: MerklePath,
}

/// One created note, or a dummy output slot.
#[derive(Clone, Debug)]
pub struct OutputNote {
    pub is_dummy: bool,
    pub owner_nf_key_hash: Fr,
    pub pq_auth_key_hash: Fr,
    pub note_secret: Fr,
    pub amount: Fr,
}

/// The private witness of one transaction.
#[derive(Clone, Debug)]
pub struct TransactionWitness {
    pub inputs: [InputNote; 2],
    pub outputs: [OutputNote; 3],
    pub intent_nonce: Fr,
    /// Section 11.3 gives two alternative predicate sets. This selects which
    /// one is enforced; the circuit accepts exactly their union, which is what
    /// the section says. It is not an extra degree of freedom: under either
    /// value the selected set is fully enforced.
    pub is_withdrawal: bool,
}

/// One switch per relation of section 11, for the removal tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relations {
    pub input_amount_range: bool,
    pub input_amount_non_zero_when_real: bool,
    pub phantom_amount_is_zero: bool,
    pub input_membership: bool,
    pub leaf_index_binding: bool,
    pub leaf_index_range: bool,
    pub real_nullifier: bool,
    pub phantom_nullifier: bool,
    pub at_least_one_real_input: bool,
    pub nullifiers_distinct: bool,
    pub nullifiers_non_zero: bool,
    pub output_amount_range: bool,
    pub output_amount_non_zero_when_real: bool,
    pub dummy_output_shape: bool,
    pub output_note_secret_non_zero: bool,
    pub output_note_body_binding: bool,
    pub conservation: bool,
    pub mode_predicates: bool,
    pub public_amount_range: bool,
    /// Section 11.3, ruled in the V1 open-rulings register: the fee is a value
    /// in the same conservation equation as every other amount, so it carries
    /// the same width. Its own switch, so its own removal test.
    pub withdrawal_fee_range: bool,
    pub intent_digest: bool,
    pub intent_nonce_non_zero: bool,
}

impl Relations {
    /// Every relation of section 11 enforced. The only set a real proof uses.
    pub const ALL: Self = Self {
        input_amount_range: true,
        input_amount_non_zero_when_real: true,
        phantom_amount_is_zero: true,
        input_membership: true,
        leaf_index_binding: true,
        leaf_index_range: true,
        real_nullifier: true,
        phantom_nullifier: true,
        at_least_one_real_input: true,
        nullifiers_distinct: true,
        nullifiers_non_zero: true,
        output_amount_range: true,
        output_amount_non_zero_when_real: true,
        dummy_output_shape: true,
        output_note_secret_non_zero: true,
        output_note_body_binding: true,
        conservation: true,
        mode_predicates: true,
        public_amount_range: true,
        withdrawal_fee_range: true,
        intent_digest: true,
        intent_nonce_non_zero: true,
    };
}

impl Default for Relations {
    fn default() -> Self {
        Self::ALL
    }
}

/// The section 11 circuit.
#[derive(Clone, Debug)]
pub struct ShieldedTransactionCircuit {
    public: PublicInputs,
    witness: Option<TransactionWitness>,
    relations: Relations,
}

impl ShieldedTransactionCircuit {
    /// The circuit as the profile defines it, with every relation enforced.
    pub fn new(public: PublicInputs, witness: TransactionWitness) -> Self {
        Self { public, witness: Some(witness), relations: Relations::ALL }
    }

    /// The same shape with no assignments, for key generation.
    pub fn blank(public: PublicInputs) -> Self {
        Self { public, witness: None, relations: Relations::ALL }
    }

    /// A deliberately weakened circuit, for the relation-removal tests only.
    #[doc(hidden)]
    pub fn for_removal_test(
        public: PublicInputs,
        witness: TransactionWitness,
        relations: Relations,
    ) -> Self {
        Self { public, witness: Some(witness), relations }
    }

    pub fn relations(&self) -> Relations {
        self.relations
    }
}

/// Allocates a witness element, or signals the missing assignment during setup.
fn witness_fr(cs: &ConstraintSystemRef<Fr>, value: Option<Fr>) -> Result0<FrVar> {
    FrVar::new_witness(cs.clone(), || value.ok_or(SynthesisError::AssignmentMissing))
}

fn witness_bool(cs: &ConstraintSystemRef<Fr>, value: Option<bool>) -> Result0<Boolean<Fr>> {
    Boolean::new_witness(cs.clone(), || value.ok_or(SynthesisError::AssignmentMissing))
}

type Result0<T> = core::result::Result<T, SynthesisError>;

impl ConstraintSynthesizer<Fr> for ShieldedTransactionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result0<()> {
        let r = self.relations;

        // --- Section 10: the public input vector, in the frozen order. ------
        // Allocation order is the verifying key's IC order, so this block must
        // stay exactly as section 10 lists it.
        let mut public_vars: Vec<FrVar> = Vec::with_capacity(18);
        for value in self.public.to_vec() {
            public_vars.push(public_input(&cs, value)?);
        }
        let anchor_root = public_vars[0].clone();
        let nullifier_public = [public_vars[1].clone(), public_vars[2].clone()];
        let note_body_public =
            [public_vars[3].clone(), public_vars[4].clone(), public_vars[5].clone()];
        let output_data_hash =
            [public_vars[6].clone(), public_vars[7].clone(), public_vars[8].clone()];
        let pq_auth_key_hash = [public_vars[9].clone(), public_vars[10].clone()];
        let public_amount_out = public_vars[11].clone();
        let withdrawal_fee = public_vars[12].clone();
        let public_recipient_hash = public_vars[13].clone();
        let valid_until = public_vars[14].clone();
        let execution_domain = public_vars[15].clone();
        let recovery_template_hash = public_vars[16].clone();
        let transaction_intent_digest = public_vars[17].clone();

        // --- Private witness ------------------------------------------------
        let assignment = self.witness.as_ref();
        let intent_nonce = witness_fr(&cs, assignment.map(|w| w.intent_nonce))?;
        let is_withdrawal = witness_bool(&cs, assignment.map(|w| w.is_withdrawal))?;

        // Section 19 gate 28.
        if r.intent_nonce_non_zero {
            range::enforce_non_zero(&intent_nonce)?;
        }

        // --- Section 11.1: inputs -------------------------------------------
        let mut real_input_sum = FrVar::zero();
        let mut is_real_flags: Vec<Boolean<Fr>> = Vec::with_capacity(2);
        for slot in 0..2usize {
            let note = assignment.map(|w| &w.inputs[slot]);
            let is_phantom = witness_bool(&cs, note.map(|n| n.is_phantom))?;
            let is_real = is_phantom.clone().not();
            let owner_nf_key = witness_fr(&cs, note.map(|n| n.owner_nf_key))?;
            let note_secret = witness_fr(&cs, note.map(|n| n.note_secret))?;
            let amount = witness_fr(&cs, note.map(|n| n.amount))?;
            let note_data_hash = witness_fr(&cs, note.map(|n| n.output_data_hash))?;
            let leaf_index = witness_fr(&cs, note.map(|n| fr_from_u128(u128::from(n.leaf_index))))?;

            if r.input_amount_range {
                range::enforce_bit_width(&amount, AMOUNT_BITS)?;
            }
            if r.input_amount_non_zero_when_real {
                range::conditionally_enforce_non_zero(&amount, &is_real)?;
            }
            if r.phantom_amount_is_zero {
                amount.conditional_enforce_equal(&FrVar::zero(), &is_phantom)?;
            }
            if r.leaf_index_range {
                range::enforce_bit_width(&leaf_index, LEAF_INDEX_BITS)?;
            }

            let key_hash = note_gadget::owner_nf_key_hash(&owner_nf_key)?;
            let owner =
                note_gadget::owner_commitment(&key_hash, &pq_auth_key_hash[slot], &note_secret)?;
            let body = note_gadget::note_body_commitment(&owner, &amount, &note_data_hash)?;
            let commitment = note_gadget::note_commitment(&body, &leaf_index)?;

            let path = match assignment {
                Some(w) => {
                    tree_gadget::MerklePathVar::new_witness(cs.clone(), &w.inputs[slot].path)?
                }
                None => tree_gadget::MerklePathVar::new_witness(cs.clone(), &blank_path())?,
            };
            if r.leaf_index_binding {
                path.leaf_index()?.enforce_equal(&leaf_index)?;
            }
            if r.input_membership {
                path.root(&commitment)?.conditional_enforce_equal(&anchor_root, &is_real)?;
            }

            if r.real_nullifier {
                note_gadget::nullifier(&body, &owner_nf_key)?
                    .conditional_enforce_equal(&nullifier_public[slot], &is_real)?;
            }
            if r.phantom_nullifier {
                let slot_constant = FrVar::Constant(Fr::from(slot as u64));
                note_gadget::phantom_nullifier(
                    &intent_nonce,
                    &slot_constant,
                    &pq_auth_key_hash[slot],
                )?
                .conditional_enforce_equal(&nullifier_public[slot], &is_phantom)?;
            }
            if r.nullifiers_non_zero {
                range::enforce_non_zero(&nullifier_public[slot])?;
            }

            // Section 11.1: the selector that removes a phantom amount from
            // conservation is this same boolean.
            real_input_sum = &real_input_sum + &(&amount * &FrVar::from(is_real.clone()));
            is_real_flags.push(is_real);
        }

        if r.at_least_one_real_input {
            Boolean::kary_or(&is_real_flags)?.enforce_equal(&Boolean::TRUE)?;
        }
        if r.nullifiers_distinct {
            range::enforce_not_equal(&nullifier_public[0], &nullifier_public[1])?;
        }

        // --- Section 11.2: outputs ------------------------------------------
        let dummy_owner = FrVar::Constant(domains::dummy_owner_nf_hash());
        let mut output_sum = FrVar::zero();
        for slot in 0..3usize {
            let note = assignment.map(|w| &w.outputs[slot]);
            let is_dummy = witness_bool(&cs, note.map(|n| n.is_dummy))?;
            let is_real = is_dummy.clone().not();
            let owner_nf_key_hash = witness_fr(&cs, note.map(|n| n.owner_nf_key_hash))?;
            let pq_hash = witness_fr(&cs, note.map(|n| n.pq_auth_key_hash))?;
            let note_secret = witness_fr(&cs, note.map(|n| n.note_secret))?;
            let amount = witness_fr(&cs, note.map(|n| n.amount))?;

            if r.output_amount_range {
                range::enforce_bit_width(&amount, AMOUNT_BITS)?;
            }
            if r.output_amount_non_zero_when_real {
                range::conditionally_enforce_non_zero(&amount, &is_real)?;
            }
            if r.dummy_output_shape {
                amount.conditional_enforce_equal(&FrVar::zero(), &is_dummy)?;
                owner_nf_key_hash.conditional_enforce_equal(&dummy_owner, &is_dummy)?;
            }
            if r.output_note_secret_non_zero {
                range::enforce_non_zero(&note_secret)?;
            }

            let owner = note_gadget::owner_commitment(&owner_nf_key_hash, &pq_hash, &note_secret)?;
            let body = note_gadget::note_body_commitment(&owner, &amount, &output_data_hash[slot])?;
            if r.output_note_body_binding {
                body.enforce_equal(&note_body_public[slot])?;
            }

            output_sum = &output_sum + &amount;
        }

        // --- Section 11.3: conservation and mode ----------------------------
        if r.public_amount_range {
            range::enforce_bit_width(&public_amount_out, AMOUNT_BITS)?;
        }
        if r.withdrawal_fee_range {
            // Conservation is field arithmetic, so a fee left unbounded could
            // be chosen as r - X and wrap the equation back into balance while
            // X walks out. The contract's equality against the immutable config
            // fee is a second line; a relation that depends on it is not a
            // value-conservation relation on its own.
            range::enforce_bit_width(&withdrawal_fee, AMOUNT_BITS)?;
        }
        if r.conservation {
            real_input_sum
                .enforce_equal(&(&output_sum + &(&public_amount_out + &withdrawal_fee)))?;
        }
        if r.mode_predicates {
            let is_transfer = is_withdrawal.clone().not();
            public_amount_out.conditional_enforce_equal(&FrVar::zero(), &is_transfer)?;
            withdrawal_fee.conditional_enforce_equal(&FrVar::zero(), &is_transfer)?;
            public_recipient_hash.conditional_enforce_equal(&FrVar::zero(), &is_transfer)?;
            recovery_template_hash.conditional_enforce_equal(&FrVar::zero(), &is_transfer)?;

            range::conditionally_enforce_non_zero(&public_amount_out, &is_withdrawal)?;
            range::conditionally_enforce_non_zero(&withdrawal_fee, &is_withdrawal)?;
            range::conditionally_enforce_non_zero(&public_recipient_hash, &is_withdrawal)?;
            range::conditionally_enforce_non_zero(&recovery_template_hash, &is_withdrawal)?;
        }

        // --- Section 11.4: the intent ---------------------------------------
        if r.intent_digest {
            let core = note_gadget::intent_core(
                &execution_domain,
                &nullifier_public[0],
                &nullifier_public[1],
                &public_amount_out,
                &withdrawal_fee,
                &public_recipient_hash,
                &recovery_template_hash,
            )?;
            let outputs = note_gadget::intent_outputs(
                &note_body_public[0],
                &note_body_public[1],
                &note_body_public[2],
                &pq_auth_key_hash[0],
                &pq_auth_key_hash[1],
                &intent_nonce,
                &valid_until,
            )?;
            note_gadget::intent_final(&core, &outputs)?
                .enforce_equal(&transaction_intent_digest)?;
        }

        Ok(())
    }
}

/// A structurally valid but meaningless path, used only when the circuit is
/// synthesised without assignments during key generation.
fn blank_path() -> MerklePath {
    MerklePath {
        levels: core::array::from_fn(|_| tree::MerkleLevel {
            siblings: [Fr::ZERO; tree::ARITY - 1],
            position: 0,
        }),
    }
}

/// Allocates one public input. Kept as a named function so the allocation
/// order below reads as the section 10 list and nothing else.
fn public_input(cs: &ConstraintSystemRef<Fr>, value: Fr) -> Result0<FrVar> {
    FrVar::new_input(cs.clone(), || Ok(value))
}

/// Assembles a consistent public/witness pair from a tree and a set of notes.
///
/// This is the only place that derives the public inputs from the witness, so
/// that a test builds a transaction the way a wallet would rather than by
/// writing down eighteen numbers.
pub struct TransactionBuilder {
    pub execution_domain: Fr,
    pub valid_until: u32,
    pub intent_nonce: Fr,
    pub public_amount_out: Fr,
    pub withdrawal_fee: Fr,
    /// Section 11.3's mode. Left unset it is inferred from the public fields,
    /// which is what a wallet would do; the tests set it explicitly when they
    /// need an inconsistent pair.
    pub is_withdrawal: Option<bool>,
    pub public_recipient_hash: Fr,
    pub recovery_template_hash: Fr,
    pub input_pq_auth_key_hash: [Fr; 2],
    pub outputs: [OutputNote; 3],
    pub output_data_hash: [Fr; 3],
}

/// One input note as the wallet holds it, before the path is looked up.
#[derive(Clone, Debug)]
pub struct HeldNote {
    pub is_phantom: bool,
    pub owner_nf_key: Fr,
    pub note_secret: Fr,
    pub amount: Fr,
    pub output_data_hash: Fr,
    pub leaf_index: u64,
}

impl TransactionBuilder {
    /// Builds the public inputs and the witness. Fails rather than producing an
    /// inconsistent pair.
    pub fn build(
        &self,
        frontier: &tree::Frontier,
        anchor_root: Fr,
        held: [HeldNote; 2],
    ) -> Result<(PublicInputs, TransactionWitness)> {
        let is_withdrawal = self.is_withdrawal.unwrap_or(
            self.public_amount_out != Fr::ZERO
                || self.withdrawal_fee != Fr::ZERO
                || self.public_recipient_hash != Fr::ZERO
                || self.recovery_template_hash != Fr::ZERO,
        );

        let mut inputs: Vec<InputNote> = Vec::with_capacity(2);
        let mut nullifiers: Vec<Fr> = Vec::with_capacity(2);
        for (slot, note) in held.iter().enumerate() {
            let path =
                if note.is_phantom { blank_path() } else { frontier.path(note.leaf_index)? };
            let key_hash = notes::owner_nf_key_hash(note.owner_nf_key);
            let owner = notes::owner_commitment(
                key_hash,
                self.input_pq_auth_key_hash[slot],
                note.note_secret,
            );
            let body = notes::note_body_commitment(owner, note.amount, note.output_data_hash);
            nullifiers.push(if note.is_phantom {
                notes::phantom_nullifier(
                    self.intent_nonce,
                    Fr::from(slot as u64),
                    self.input_pq_auth_key_hash[slot],
                )
            } else {
                notes::nullifier(body, note.owner_nf_key)
            });
            inputs.push(InputNote {
                is_phantom: note.is_phantom,
                owner_nf_key: note.owner_nf_key,
                note_secret: note.note_secret,
                amount: note.amount,
                output_data_hash: note.output_data_hash,
                leaf_index: if note.is_phantom { 0 } else { note.leaf_index },
                path,
            });
        }

        let mut note_bodies: Vec<Fr> = Vec::with_capacity(3);
        for (slot, output) in self.outputs.iter().enumerate() {
            let owner = notes::owner_commitment(
                output.owner_nf_key_hash,
                output.pq_auth_key_hash,
                output.note_secret,
            );
            note_bodies.push(notes::note_body_commitment(
                owner,
                output.amount,
                self.output_data_hash[slot],
            ));
        }

        let core = notes::intent_core(
            self.execution_domain,
            nullifiers[0],
            nullifiers[1],
            self.public_amount_out,
            self.withdrawal_fee,
            self.public_recipient_hash,
            self.recovery_template_hash,
        );
        let outputs_hash = notes::intent_outputs(
            note_bodies[0],
            note_bodies[1],
            note_bodies[2],
            self.input_pq_auth_key_hash[0],
            self.input_pq_auth_key_hash[1],
            self.intent_nonce,
            Fr::from(u64::from(self.valid_until)),
        );

        let public = PublicInputs {
            anchor_root,
            nullifier_0: nullifiers[0],
            nullifier_1: nullifiers[1],
            note_body_0: note_bodies[0],
            note_body_1: note_bodies[1],
            note_body_2: note_bodies[2],
            output_data_hash_0: self.output_data_hash[0],
            output_data_hash_1: self.output_data_hash[1],
            output_data_hash_2: self.output_data_hash[2],
            pq_auth_key_hash_0: self.input_pq_auth_key_hash[0],
            pq_auth_key_hash_1: self.input_pq_auth_key_hash[1],
            public_amount_out: self.public_amount_out,
            withdrawal_fee: self.withdrawal_fee,
            public_recipient_hash: self.public_recipient_hash,
            valid_until: Fr::from(u64::from(self.valid_until)),
            execution_domain: self.execution_domain,
            recovery_template_hash: self.recovery_template_hash,
            transaction_intent_digest: notes::intent_final(core, outputs_hash),
        };

        let inputs: [InputNote; 2] =
            inputs.try_into().map_err(|_| Error::Witness("two input slots".to_string()))?;
        let witness = TransactionWitness {
            inputs,
            outputs: self.outputs.clone(),
            intent_nonce: self.intent_nonce,
            is_withdrawal,
        };
        Ok((public, witness))
    }
}
