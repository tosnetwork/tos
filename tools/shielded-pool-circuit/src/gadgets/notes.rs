/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Profile section 4 inside the constraint system, plus the section 9.3 intent
//! digest, which is built from the same `H7` calls.
//!
//! Each function mirrors one formula in the profile and nothing else. The
//! domain separator is a circuit constant in every case, so a proof cannot
//! substitute one relation's hash for another's.

use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::SynthesisError;

use crate::gadgets::poseidon2::{h7, FrVar};

fn zero() -> FrVar {
    FrVar::zero()
}

/// Profile section 2.1.
pub fn owner_nf_key_hash(owner_nf_key: &FrVar) -> Result<FrVar, SynthesisError> {
    h7("OWNER-NF-HASH", &[owner_nf_key.clone(), zero(), zero(), zero(), zero(), zero(), zero()])
}

/// Profile section 4.1.
pub fn owner_commitment(
    owner_nf_key_hash: &FrVar,
    pq_auth_key_hash: &FrVar,
    note_secret: &FrVar,
) -> Result<FrVar, SynthesisError> {
    h7(
        "OWNER-COMMITMENT",
        &[
            owner_nf_key_hash.clone(),
            pq_auth_key_hash.clone(),
            note_secret.clone(),
            zero(),
            zero(),
            zero(),
            zero(),
        ],
    )
}

/// Profile section 4.2.
pub fn note_body_commitment(
    owner_commitment: &FrVar,
    amount: &FrVar,
    output_data_hash: &FrVar,
) -> Result<FrVar, SynthesisError> {
    h7(
        "NOTE-BODY",
        &[
            owner_commitment.clone(),
            amount.clone(),
            output_data_hash.clone(),
            zero(),
            zero(),
            zero(),
            zero(),
        ],
    )
}

/// Profile section 4.3.
pub fn note_commitment(
    note_body_commitment: &FrVar,
    leaf_index: &FrVar,
) -> Result<FrVar, SynthesisError> {
    h7(
        "NOTE-COMMITMENT",
        &[note_body_commitment.clone(), leaf_index.clone(), zero(), zero(), zero(), zero(), zero()],
    )
}

/// Profile section 4.4.
pub fn nullifier(
    note_body_commitment: &FrVar,
    owner_nf_key: &FrVar,
) -> Result<FrVar, SynthesisError> {
    h7(
        "NULLIFIER",
        &[
            note_body_commitment.clone(),
            owner_nf_key.clone(),
            zero(),
            zero(),
            zero(),
            zero(),
            zero(),
        ],
    )
}

/// Profile section 4.5.
pub fn phantom_nullifier(
    intent_nonce: &FrVar,
    input_slot: &FrVar,
    pq_auth_key_hash: &FrVar,
) -> Result<FrVar, SynthesisError> {
    h7(
        "PHANTOM-NULLIFIER",
        &[
            intent_nonce.clone(),
            input_slot.clone(),
            pq_auth_key_hash.clone(),
            zero(),
            zero(),
            zero(),
            zero(),
        ],
    )
}

/// Profile section 9.3, first stage.
#[allow(clippy::too_many_arguments)]
pub fn intent_core(
    execution_domain: &FrVar,
    nf0: &FrVar,
    nf1: &FrVar,
    public_amount_out: &FrVar,
    withdrawal_fee: &FrVar,
    public_recipient_hash: &FrVar,
    recovery_template_hash: &FrVar,
) -> Result<FrVar, SynthesisError> {
    h7(
        "INTENT-CORE",
        &[
            execution_domain.clone(),
            nf0.clone(),
            nf1.clone(),
            public_amount_out.clone(),
            withdrawal_fee.clone(),
            public_recipient_hash.clone(),
            recovery_template_hash.clone(),
        ],
    )
}

/// Profile section 9.3, second stage.
#[allow(clippy::too_many_arguments)]
pub fn intent_outputs(
    note_body_0: &FrVar,
    note_body_1: &FrVar,
    note_body_2: &FrVar,
    pq_auth_key_hash_0: &FrVar,
    pq_auth_key_hash_1: &FrVar,
    intent_nonce: &FrVar,
    valid_until: &FrVar,
) -> Result<FrVar, SynthesisError> {
    h7(
        "INTENT-OUTPUTS",
        &[
            note_body_0.clone(),
            note_body_1.clone(),
            note_body_2.clone(),
            pq_auth_key_hash_0.clone(),
            pq_auth_key_hash_1.clone(),
            intent_nonce.clone(),
            valid_until.clone(),
        ],
    )
}

/// Profile section 9.3, final stage.
pub fn intent_final(intent_core: &FrVar, intent_outputs: &FrVar) -> Result<FrVar, SynthesisError> {
    h7(
        "INTENT-FINAL",
        &[intent_core.clone(), intent_outputs.clone(), zero(), zero(), zero(), zero(), zero()],
    )
}
