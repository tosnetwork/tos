/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Profile section 10: the frozen 18-element public input vector.
//!
//! The order is normative. Groth16 indexes `IC[1..]` by allocation order, so
//! the order here is also the verifying key's shape: changing it is a new
//! circuit version, not a refactor.

use crate::field::Fr;

/// The number of public inputs, and therefore `IC.len() - 1`.
pub const PUBLIC_INPUT_COUNT: usize = 18;

/// The public inputs, named as section 10 names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub anchor_root: Fr,
    pub nullifier_0: Fr,
    pub nullifier_1: Fr,
    pub note_body_0: Fr,
    pub note_body_1: Fr,
    pub note_body_2: Fr,
    pub output_data_hash_0: Fr,
    pub output_data_hash_1: Fr,
    pub output_data_hash_2: Fr,
    pub pq_auth_key_hash_0: Fr,
    pub pq_auth_key_hash_1: Fr,
    pub public_amount_out: Fr,
    pub withdrawal_fee: Fr,
    pub public_recipient_hash: Fr,
    pub valid_until: Fr,
    pub execution_domain: Fr,
    pub recovery_template_hash: Fr,
    pub transaction_intent_digest: Fr,
}

/// The section 10 names, in the frozen order. Used to label a mismatch.
pub const ORDER: [&str; PUBLIC_INPUT_COUNT] = [
    "anchor_root",
    "nullifier_0",
    "nullifier_1",
    "note_body_0",
    "note_body_1",
    "note_body_2",
    "output_data_hash_0",
    "output_data_hash_1",
    "output_data_hash_2",
    "pq_auth_key_hash_0",
    "pq_auth_key_hash_1",
    "public_amount_out",
    "withdrawal_fee",
    "public_recipient_hash",
    "valid_until",
    "execution_domain",
    "recovery_template_hash",
    "transaction_intent_digest",
];

impl PublicInputs {
    /// The vector in the frozen section 10 order.
    pub fn to_vec(&self) -> [Fr; PUBLIC_INPUT_COUNT] {
        [
            self.anchor_root,
            self.nullifier_0,
            self.nullifier_1,
            self.note_body_0,
            self.note_body_1,
            self.note_body_2,
            self.output_data_hash_0,
            self.output_data_hash_1,
            self.output_data_hash_2,
            self.pq_auth_key_hash_0,
            self.pq_auth_key_hash_1,
            self.public_amount_out,
            self.withdrawal_fee,
            self.public_recipient_hash,
            self.valid_until,
            self.execution_domain,
            self.recovery_template_hash,
            self.transaction_intent_digest,
        ]
    }

    /// Replaces one entry by its section 10 position. Used to build the
    /// mutated public-input fixture section 10.1 requires.
    pub fn with_mutated(&self, position: usize, value: Fr) -> Option<Self> {
        let mut vector = self.to_vec();
        *vector.get_mut(position)? = value;
        Some(Self {
            anchor_root: vector[0],
            nullifier_0: vector[1],
            nullifier_1: vector[2],
            note_body_0: vector[3],
            note_body_1: vector[4],
            note_body_2: vector[5],
            output_data_hash_0: vector[6],
            output_data_hash_1: vector[7],
            output_data_hash_2: vector[8],
            pq_auth_key_hash_0: vector[9],
            pq_auth_key_hash_1: vector[10],
            public_amount_out: vector[11],
            withdrawal_fee: vector[12],
            public_recipient_hash: vector[13],
            valid_until: vector[14],
            execution_domain: vector[15],
            recovery_template_hash: vector[16],
            transaction_intent_digest: vector[17],
        })
    }
}
