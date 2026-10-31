/* Copyright (C) 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only */
//! BR1 private commission preflight, using an ordinary existing Shield output.
//!
//! This module deliberately does NOT return an `Imported`/spendable note. A
//! successful preflight is neither a valid transaction proof nor evidence of
//! inclusion. The caller must validate the complete exact candidate transaction
//! and later authenticate its final execution before crediting any balance.

use shielded_pool_circuit::{field::Fr, wire};

use crate::delivery::{self, Kind};
use crate::error::{Error, Rejection};
use crate::import::{self, ChainSlot};
use crate::keys::PoolInstance;

/// Terms from the authenticated quote. The caller also verifies the quote's
/// network, worker identity, exact request and expiry outside this module.
#[derive(Clone, Copy, Debug)]
pub struct FeeTerms {
    pub execution_domain: Fr,
    pub slot: u8,
    pub amount: u128,
    pub note_key_index: u64,
}

#[derive(Debug)]
pub enum FeeError {
    InvalidTerms,
    WrongDomain,
    WrongKind,
    WrongAmount,
    WrongIndex,
    Payload(Rejection),
    Wallet(Error),
}

impl std::fmt::Display for FeeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "relayer fee preflight refused: {self:?}")
    }
}
impl std::error::Error for FeeError {}

/// A checked prospective output, NOT a receipt or a credit. No note secret or
/// automatic balance-import method is exposed. The body and payload hash must
/// refer to the same slot in the full transaction being simulated/submitted.
#[derive(Clone, Copy, Debug)]
pub struct FeePreflight {
    note_body: Fr,
    output_data_hash: Fr,
    amount: u128,
    note_key_index: u64,
}

impl FeePreflight {
    pub fn note_body(&self) -> Fr {
        self.note_body
    }
    pub fn output_data_hash(&self) -> Fr {
        self.output_data_hash
    }
    pub fn amount(&self) -> u128 {
        self.amount
    }
    pub fn note_key_index(&self) -> u64 {
        self.note_key_index
    }
}

pub fn preflight_fee_output(
    instance: &PoolInstance,
    terms: &FeeTerms,
    exact_output_data: &[u8],
    candidate_note_body: Fr,
) -> Result<FeePreflight, FeeError> {
    if terms.slot >= 3 || terms.amount == 0 || terms.amount >= (1u128 << 120) {
        return Err(FeeError::InvalidTerms);
    }
    if terms.execution_domain != instance.execution_domain() {
        return Err(FeeError::WrongDomain);
    }
    let plaintext =
        delivery::open(instance, exact_output_data, terms.slot).map_err(FeeError::Payload)?;
    if plaintext.kind != Kind::Ordinary {
        return Err(FeeError::WrongKind);
    }
    if plaintext.amount != terms.amount {
        return Err(FeeError::WrongAmount);
    }
    if plaintext.note_key_index != terms.note_key_index {
        return Err(FeeError::WrongIndex);
    }
    let output_data_hash = wire::output_data_hash(exact_output_data);
    let slot = ChainSlot { output_data_hash, note_body: candidate_note_body, recovered: None };
    let checked = import::import(instance, &plaintext, &slot)
        .map_err(FeeError::Wallet)?
        .map_err(FeeError::Payload)?;
    // `import` authenticates the NF owner, derived one-time PQ key and the
    // note body including this exact encrypted payload's hash. Do not replace
    // those checks with successful decryption alone.
    Ok(FeePreflight {
        note_body: checked.note_body,
        output_data_hash,
        amount: checked.amount,
        note_key_index: checked.note_key_index,
    })
}
