// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! A relay request admitted to this provider: the structural checks shared
//! with the wallet, then this operator's funding bound and the fee output
//! preflight with the operator's own receiving instance.
use crate::{config::Config, identity::Identity};
use anyhow::{ensure, Result};
pub use br1_client::request::{ordinary_boc, Request};
use chain_block::Cell;
use serde_json::Value;
use shielded_pool_circuit::field::Fr;

pub struct Candidate {
    pub request: Request,
    pub identity: String,
    pub body: Cell,
    pub fee_payload: Vec<u8>,
    pub fee_body: Fr,
}
impl Candidate {
    pub fn parse(
        value: &Value,
        config: &Config,
        identity: &Identity,
        terms: &Value,
    ) -> Result<Self> {
        let checked =
            br1_client::request::Candidate::check(value, &config.release.scope()?, terms)?;
        ensure!(checked.request.funding_cap <= config.funding_cap, "request release/budget/slot");
        let fee_terms = shielded_pool_wallet::relayer_fee::FeeTerms {
            execution_domain: identity.recipient().execution_domain(),
            slot: checked.request.fee_slot,
            amount: u128::from(config.fee),
            note_key_index: checked.request.fee_note_index,
        };
        shielded_pool_wallet::relayer_fee::preflight_fee_output(
            identity.recipient(),
            &fee_terms,
            &checked.fee_payload,
            checked.fee_body,
        )?;
        Ok(Self {
            request: checked.request,
            identity: checked.identity,
            body: checked.body,
            fee_payload: checked.fee_payload,
            fee_body: checked.fee_body,
        })
    }
}
