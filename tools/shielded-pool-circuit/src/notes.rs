/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Profile section 4: note commitments and nullifiers, outside the constraint
//! system.
//!
//! These functions are written from the profile text alone. They are the third
//! independent reading of section 4, after the FunC library and the sandbox
//! reference, and they exist so that a shared misreading between those two can
//! be seen rather than inherited.

use ark_ff::AdditiveGroup;

use crate::domains::h7;
use crate::field::Fr;

const ZERO: Fr = Fr::ZERO;

/// Profile section 2.1:
/// `owner_nf_key_hash = H7("OWNER-NF-HASH", owner_nf_key, 0,0,0,0,0,0)`.
pub fn owner_nf_key_hash(owner_nf_key: Fr) -> Fr {
    h7("OWNER-NF-HASH", &[owner_nf_key, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO])
}

/// Profile section 4.1:
/// `owner_commitment = H7("OWNER-COMMITMENT", owner_nf_key_hash,
/// pq_auth_key_hash, note_secret, 0, 0, 0, 0)`.
pub fn owner_commitment(owner_nf_key_hash: Fr, pq_auth_key_hash: Fr, note_secret: Fr) -> Fr {
    h7(
        "OWNER-COMMITMENT",
        &[owner_nf_key_hash, pq_auth_key_hash, note_secret, ZERO, ZERO, ZERO, ZERO],
    )
}

/// Profile section 4.2:
/// `note_body_commitment = H7("NOTE-BODY", owner_commitment, amount,
/// output_data_hash, 0, 0, 0, 0)`.
pub fn note_body_commitment(owner_commitment: Fr, amount: Fr, output_data_hash: Fr) -> Fr {
    h7("NOTE-BODY", &[owner_commitment, amount, output_data_hash, ZERO, ZERO, ZERO, ZERO])
}

/// Profile section 4.3:
/// `note_commitment = H7("NOTE-COMMITMENT", note_body_commitment, leaf_index,
/// 0, 0, 0, 0, 0)`.
pub fn note_commitment(note_body_commitment: Fr, leaf_index: Fr) -> Fr {
    h7("NOTE-COMMITMENT", &[note_body_commitment, leaf_index, ZERO, ZERO, ZERO, ZERO, ZERO])
}

/// Profile section 4.4:
/// `nullifier = H7("NULLIFIER", note_body_commitment, owner_nf_key,
/// 0, 0, 0, 0, 0)`.
///
/// The nullifier binds the semantic note body, not the final leaf index, so a
/// note that appears at two leaf indices is still single-spend.
pub fn nullifier(note_body_commitment: Fr, owner_nf_key: Fr) -> Fr {
    h7("NULLIFIER", &[note_body_commitment, owner_nf_key, ZERO, ZERO, ZERO, ZERO, ZERO])
}

/// Profile section 4.5:
/// `phantom_nullifier = H7("PHANTOM-NULLIFIER", intent_nonce, input_slot,
/// pq_auth_key_hash, 0, 0, 0, 0)`.
pub fn phantom_nullifier(intent_nonce: Fr, input_slot: Fr, pq_auth_key_hash: Fr) -> Fr {
    h7("PHANTOM-NULLIFIER", &[intent_nonce, input_slot, pq_auth_key_hash, ZERO, ZERO, ZERO, ZERO])
}

/// Profile section 9.3, first stage.
#[allow(clippy::too_many_arguments)]
pub fn intent_core(
    execution_domain: Fr,
    nf0: Fr,
    nf1: Fr,
    public_amount_out: Fr,
    withdrawal_fee: Fr,
    public_recipient_hash: Fr,
    recovery_template_hash: Fr,
) -> Fr {
    h7(
        "INTENT-CORE",
        &[
            execution_domain,
            nf0,
            nf1,
            public_amount_out,
            withdrawal_fee,
            public_recipient_hash,
            recovery_template_hash,
        ],
    )
}

/// Profile section 9.3, second stage.
#[allow(clippy::too_many_arguments)]
pub fn intent_outputs(
    note_body_0: Fr,
    note_body_1: Fr,
    note_body_2: Fr,
    pq_auth_key_hash_0: Fr,
    pq_auth_key_hash_1: Fr,
    intent_nonce: Fr,
    valid_until: Fr,
) -> Fr {
    h7(
        "INTENT-OUTPUTS",
        &[
            note_body_0,
            note_body_1,
            note_body_2,
            pq_auth_key_hash_0,
            pq_auth_key_hash_1,
            intent_nonce,
            valid_until,
        ],
    )
}

/// Profile section 9.3, final stage.
pub fn intent_final(intent_core: Fr, intent_outputs: Fr) -> Fr {
    h7("INTENT-FINAL", &[intent_core, intent_outputs, ZERO, ZERO, ZERO, ZERO, ZERO])
}
