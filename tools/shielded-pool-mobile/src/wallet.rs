// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Complete scan of one finished ledger. This summary establishes neither
//! proof freshness nor durable off-chain reservations; callers enforce both.
use crate::{Error, Result, MAX_OUTPUTS};
use serde::Serialize;
use shielded_pool_circuit::field::Fr;
use shielded_pool_wallet::{
    keys::PoolInstance,
    ledger::{Ledger, Output},
    scan::{self, Recovered},
};
use std::collections::BTreeSet;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Independent entry cap before cloning/decrypting. No cache survives this call.
const MAX_COMPLETE_OUTPUTS: usize = 32768;
const MAX_COMPLETE_PAYLOAD_BYTES: usize =
    MAX_COMPLETE_OUTPUTS * shielded_pool_wallet::delivery::OUTPUT_DATA_BYTES;

// Clear the secret-bearing aggregate on success, failure and unwind. This does
// not promise erasure of upstream import/key-derivation intermediates.
pub(crate) struct CompleteRecovered(pub(crate) Recovered);
impl Drop for CompleteRecovered {
    fn drop(&mut self) {
        for note in &mut self.0.notes {
            note.note_secret.zeroize();
            note.amount.zeroize();
            note.owner_commitment.zeroize();
            note.note_body.zeroize();
            note.output_data_hash.zeroize();
            note.note_key_index.zeroize();
        }
        self.0.leaves.zeroize();
        self.0.next_note_key_index.zeroize();
        #[cfg(test)]
        tests::observe_drop(&self.0);
    }
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
struct Summary {
    version: u8,
    total_outputs: String,
    owned_outputs: String,
    unique_unspent_notes: String,
    duplicate_outputs: String,
    reused_indices_count: String,
    diagnostics_count: String,
    unspent_balance: String,
    // None means u64 exhaustion. This never includes unbroadcast reservations.
    scan_next_index: Option<String>,
}

fn summarize(recovered: &Recovered, total: usize) -> Result<Summary> {
    let balance = recovered
        .spendable_notes()
        .try_fold(0u128, |sum, note| sum.checked_add(note.amount).ok_or(Error::Limit))?;
    let next = match recovered.notes.iter().map(|note| note.note_key_index).max() {
        Some(index) => index.checked_add(1),
        None => Some(0),
    };
    Ok(Summary {
        version: 1,
        total_outputs: total.to_string(),
        owned_outputs: recovered.notes.len().to_string(),
        unique_unspent_notes: recovered.spendable_notes().count().to_string(),
        duplicate_outputs: recovered.duplicates().to_string(),
        reused_indices_count: recovered.reused.len().to_string(),
        diagnostics_count: recovered.diagnostics.len().to_string(),
        unspent_balance: balance.to_string(),
        scan_next_index: next.map(|index| index.to_string()),
    })
}

pub(crate) fn recover_complete(
    outputs: &[Output],
    published: &BTreeSet<Fr>,
    seed: &[u8; 32],
    domain: Fr,
) -> Result<CompleteRecovered> {
    if outputs.len() > MAX_COMPLETE_OUTPUTS {
        return Err(Error::Limit);
    }
    let bytes = outputs.iter().try_fold(0usize, |total, output| {
        total.checked_add(output.observed.output_data.len()).ok_or(Error::Limit)
    })?;
    if bytes > MAX_COMPLETE_PAYLOAD_BYTES {
        return Err(Error::Limit);
    }
    let instance = PoolInstance::new(seed, domain);
    let mut recovered = CompleteRecovered(Recovered::default());
    for page in outputs.chunks(MAX_OUTPUTS) {
        let outputs =
            page.iter().map(|output| (output.observed.clone(), output.leaf)).collect::<Vec<_>>();
        let later = scan::recover_indexed(&instance, &outputs).map_err(|_| Error::Crypto)?;
        recovered.0.merge(later);
    }
    recovered.0.reconcile_spent(&instance, published).map_err(|_| Error::Crypto)?;
    Ok(recovered)
}

pub(crate) fn summary(ledger: &Ledger, seed: &[u8; 32], domain: Fr) -> Result<Zeroizing<Vec<u8>>> {
    let recovered =
        recover_complete(ledger.outputs(), ledger.published_nullifiers(), seed, domain)?;
    let result = summarize(&recovered.0, ledger.outputs().len())?;
    serde_json::to_vec(&result).map(Zeroizing::new).map_err(|_| Error::InvalidInput)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use shielded_pool_wallet::{delivery::Kind, import::Imported};

    thread_local! {
        static EXPECT_WIPE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static CLEANED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    pub(super) fn observe_drop(recovered: &Recovered) {
        if EXPECT_WIPE.get() {
            CLEANED.set(recovered.notes.iter().all(|note| {
                note.note_secret == Fr::from(0u64) && note.amount == 0 && note.note_key_index == 0
            }));
        }
    }
    #[test]
    fn held_secret_aggregate_is_cleared_by_actual_drop() {
        CLEANED.set(false);
        EXPECT_WIPE.set(true);
        let mut recovered = CompleteRecovered(Recovered::default());
        recovered.0.notes.push(note(7, 1, 1000));
        drop(recovered);
        EXPECT_WIPE.set(false);
        assert!(CLEANED.get());
    }
    fn note(index: u64, body: u64, amount: u128) -> Imported {
        Imported {
            kind: Kind::Ordinary,
            note_key_index: index,
            amount,
            note_secret: Fr::from(3u64),
            owner_commitment: Fr::from(body),
            note_body: Fr::from(body),
            output_data_hash: Fr::from(4u64),
            spendable: true,
            spent: false,
        }
    }
    #[test]
    fn checked_balance_never_wraps_or_returns_a_partial_total() {
        let mut recovered = Recovered::default();
        for i in 0..257 {
            recovered.notes.push(note(i, i + 1, (1u128 << 120) - 1));
        }
        assert!(matches!(summarize(&recovered, 257), Err(Error::Limit)));
    }
    #[test]
    fn scan_exhaustion_is_explicit_and_not_an_issuable_maximum() {
        let mut recovered = Recovered::default();
        recovered.notes.push(note(u64::MAX, 1, 1));
        assert!(summarize(&recovered, 1).unwrap().scan_next_index.is_none());
        assert_eq!(
            summarize(&Recovered::default(), 0).unwrap().scan_next_index.as_deref(),
            Some("0")
        );
    }
    #[test]
    fn total_output_budget_is_checked_before_recovery() {
        // Synthetic output-count boundary, not authenticated transaction evidence.
        let output = Output {
            leaf: None,
            observed: scan::ObservedOutput {
                slot: 0,
                output_data: Vec::new(),
                chain: shielded_pool_wallet::import::ChainSlot {
                    output_data_hash: Fr::from(0u64),
                    note_body: Fr::from(0u64),
                    recovered: None,
                },
            },
        };
        let outputs = vec![output; MAX_COMPLETE_OUTPUTS + 1];
        assert!(matches!(
            recover_complete(&outputs, &BTreeSet::new(), &[42; 32], Fr::from(7u64)),
            Err(Error::Limit)
        ));
        assert!(recover_complete(
            &outputs[..MAX_COMPLETE_OUTPUTS],
            &BTreeSet::new(),
            &[42; 32],
            Fr::from(7u64)
        )
        .is_ok());
    }
    #[test]
    fn payload_budget_is_checked_before_cloning_or_decrypting() {
        let output = Output {
            leaf: None,
            observed: scan::ObservedOutput {
                slot: 0,
                output_data: vec![0; MAX_COMPLETE_PAYLOAD_BYTES + 1],
                chain: shielded_pool_wallet::import::ChainSlot {
                    output_data_hash: Fr::from(0u64),
                    note_body: Fr::from(0u64),
                    recovered: None,
                },
            },
        };
        assert!(matches!(
            recover_complete(&[output], &BTreeSet::new(), &[42; 32], Fr::from(7u64)),
            Err(Error::Limit)
        ));
    }
}
