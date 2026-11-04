// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Construction of an encrypted self-deposit for the existing pool wire format.

use crate::{Error, Result};
use rand::{rngs::OsRng, RngCore};
use shielded_pool_circuit::{
    field::{fr_from_be, fr_to_be, Fr},
    notes,
};
use shielded_pool_codec::DepositBody;
use shielded_pool_wallet::{
    delivery::{self, Kind, Plaintext},
    keys::PoolInstance,
};
use zeroize::Zeroizing;

/// Build the body of a self-deposit. The caller supplies a durably reserved
/// note index and must preserve the resulting bytes when retrying a submission.
/// The ordinary wallet attaches value and signs the enclosing message.
pub fn build_self_deposit(
    instance: &PoolInstance,
    note_key_index: u64,
    amount: u64,
    query_id: u64,
) -> Result<Vec<u8>> {
    if amount == 0 {
        return Err(Error::InvalidInput);
    }
    let note_secret = loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        OsRng.try_fill_bytes(bytes.as_mut()).map_err(|_| Error::Crypto)?;
        if let Ok(value) = fr_from_be(&bytes) {
            if value != Fr::from(0u64) {
                break value;
            }
        }
    };
    let owner_nf_key_hash =
        instance.owner_nf_key_hash(note_key_index).map_err(|_| Error::Crypto)?;
    let pq_auth_key_hash = instance.pq_auth_key_hash(note_key_index).map_err(|_| Error::Crypto)?;
    let plaintext = Plaintext {
        slot: 0,
        kind: Kind::Ordinary,
        amount: u128::from(amount),
        note_secret,
        owner_nf_key_hash,
        note_key_index,
        pq_auth_key_hash,
    };
    let key = instance.mlkem_encapsulation_key().map_err(|_| Error::Crypto)?;
    let output_data =
        delivery::seal(&key, instance.execution_domain(), &plaintext).map_err(|_| Error::Crypto)?;
    let owner_commitment =
        notes::owner_commitment(owner_nf_key_hash, pq_auth_key_hash, note_secret);
    let body = DepositBody {
        query_id,
        amount: u128::from(amount),
        owner_commitment: fr_to_be(&owner_commitment),
        output_data,
    }
    .build()
    .map_err(|_| Error::InvalidInput)?;
    chain_block::write_boc(&body).map_err(|_| Error::InvalidInput)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use chain_block::SliceData;
    use shielded_pool_codec::OP_DEPOSIT;

    #[test]
    fn self_deposit_round_trips_and_seals_to_the_wallet() {
        let instance = PoolInstance::new(&[7; 32], Fr::from(9u64));
        let other = PoolInstance::new(&[8; 32], instance.execution_domain());
        assert!(build_self_deposit(&instance, 12, 0, 23).is_err());
        let bytes = build_self_deposit(&instance, 12, 1_000_000_000, 23).unwrap();
        let mut slice = SliceData::load_cell(crate::pool::read_cell(&bytes).unwrap()).unwrap();
        assert_eq!(slice.get_next_u32().unwrap(), OP_DEPOSIT);
        let deposit = DepositBody::parse(&mut slice).unwrap();
        assert_eq!(deposit.query_id, 23);
        assert_eq!(deposit.amount, 1_000_000_000);
        assert!(delivery::open(&other, &deposit.output_data, 0).is_err());
        let note = delivery::open(&instance, &deposit.output_data, 0).unwrap();
        assert_eq!(note.kind, Kind::Ordinary);
        assert_eq!(note.amount, deposit.amount);
        assert_eq!(note.note_key_index, 12);
        assert_ne!(note.note_secret, Fr::from(0u64));
        assert_eq!(
            deposit.owner_commitment,
            fr_to_be(&notes::owner_commitment(
                note.owner_nf_key_hash,
                note.pq_auth_key_hash,
                note.note_secret,
            ))
        );
    }
}
