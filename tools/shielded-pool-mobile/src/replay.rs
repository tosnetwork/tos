// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Provisional oldest-first replay. Nothing is a wallet observation until the
//! final transaction and all ledger checkpoint fields match the proven head.
use chain_block::{CellType, Deserializable, Transaction};
use shielded_pool_circuit::field::{fr_from_be, Fr};
use shielded_pool_codec::{classify, PoolState, PoolTransaction};
use shielded_pool_wallet::ledger::{Checkpoint, Event, Ledger, Payout, Transact};

use crate::{pool::read_cell, Error, Result};

/// Bounds apply across the whole replay, not independently to each transaction.
pub const MAX_HISTORY_TRANSACTIONS: usize = 8192;
pub const MAX_HISTORY_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Head {
    pub account_id: [u8; 32],
    pub last_hash: [u8; 32],
    pub last_lt: u64,
    pub account_root: [u8; 32],
    pub shard_time: u32,
}

struct Link {
    hash: [u8; 32],
    lt: u64,
    new_state: [u8; 32],
    time: u32,
}

/// The owner must free a cancelled replay. No global registry or cache exists.
/// A failed push immediately discards provisional state and poisons this replay.
pub struct Replay {
    head: Head,
    expected: Checkpoint,
    recovery_charge: u128,
    ledger: Option<Ledger>,
    last: Option<Link>,
    count: usize,
    bytes: usize,
}

fn fr(bytes: &[u8; 32]) -> Result<Fr> {
    fr_from_be(bytes).map_err(|_| Error::InvalidInput)
}

fn event(transaction: &Transaction) -> Result<Option<Event>> {
    Ok(match classify(transaction).map_err(|_| Error::InvalidInput)? {
        PoolTransaction::NoStateChange(_) => None,
        PoolTransaction::Deposit(body) => Some(Event::Deposit {
            amount: body.amount,
            owner_commitment: fr(&body.owner_commitment)?,
            output_data: body.output_data,
        }),
        PoolTransaction::Transact { body, payout } => Some(Event::Transact(Box::new(Transact {
            intent_digest: fr(&body.intent_digest)?,
            nullifiers: [fr(&body.nullifiers[0])?, fr(&body.nullifiers[1])?],
            note_bodies: [
                fr(&body.note_bodies[0])?,
                fr(&body.note_bodies[1])?,
                fr(&body.note_bodies[2])?,
            ],
            payloads: body.payloads,
            public_amount_out: body.public_amount_out,
            withdrawal_fee: body.withdrawal_fee,
            recovery_owner_commitment: fr(&body.recovery_owner_commitment)?,
            recovery_payload: body.recovery_payload,
            payout: payout.map(|p| Payout {
                recipient: p.recipient.to_string(),
                value: p.value,
                body_hash: p.body_hash,
            }),
        }))),
        PoolTransaction::Bounce { original_body_hash, sender, value } => {
            Some(Event::Bounce { original_body_hash, sender: sender.to_string(), value })
        }
    })
}

impl Replay {
    /// All head/state inputs must originate in one verified account observation.
    /// Recovery pricing must come from its proven gas configuration. As in the
    /// CLI, earlier gas changes that affect bounces cause a checkpoint refusal.
    pub fn new(head: Head, state: &PoolState, recovery_charge: u128) -> Result<Self> {
        if (head.last_lt == 0) != (head.last_hash == [0; 32]) {
            return Err(Error::InvalidInput);
        }
        let expected = Checkpoint {
            commitment_root: fr(&state.commitment_root)?,
            commitment_next_index: state.commitment_next_index,
            reserved_recovery_leaves: u64::from(state.reserved_recovery_leaves),
            nullifier_root: fr(&state.nullifier_root)?,
            nullifier_next_index: state.nullifier_next_index,
            native_liability: state.native_liability,
        };
        Ok(Self {
            head,
            expected,
            recovery_charge,
            ledger: Some(Ledger::genesis()),
            last: None,
            count: 0,
            bytes: 0,
        })
    }

    pub fn push(&mut self, boc: &[u8]) -> Result<()> {
        // Move provisional funds out before decoding or applying. An unwind
        // drops this local ledger too, leaving the owner unable to finish it.
        let mut ledger = self.ledger.take().ok_or(Error::InvalidInput)?;
        let result = self.push_inner(boc, &mut ledger);
        if result.is_ok() {
            self.ledger = Some(ledger);
        } else {
            self.last = None;
        }
        result
    }

    fn push_inner(&mut self, boc: &[u8], ledger: &mut Ledger) -> Result<()> {
        let count = self.count.checked_add(1).ok_or(Error::Limit)?;
        let bytes = self.bytes.checked_add(boc.len()).ok_or(Error::Limit)?;
        if count > MAX_HISTORY_TRANSACTIONS || bytes > MAX_HISTORY_BYTES {
            return Err(Error::Limit);
        }
        let root = read_cell(boc)?;
        if root.cell_type() != CellType::Ordinary || root.level() != 0 {
            return Err(Error::InvalidInput);
        }
        let hash = *root.repr_hash().as_array();
        let tx = Transaction::construct_from_cell(root).map_err(|_| Error::InvalidInput)?;
        let update = tx.read_state_update().map_err(|_| Error::InvalidInput)?;
        if tx.account_id() != &chain_block::SliceData::from_raw(self.head.account_id.to_vec(), 256)
            || tx.logical_time() == 0
            || tx.logical_time() > self.head.last_lt
            || tx.now() > self.head.shard_time
        {
            return Err(Error::InvalidInput);
        }
        match &self.last {
            None => {
                if tx.prev_trans_lt() != 0 || tx.prev_trans_hash().as_array() != &[0; 32] {
                    return Err(Error::InvalidInput);
                }
            }
            Some(last) => {
                if tx.prev_trans_lt() != last.lt
                    || tx.prev_trans_hash().as_array() != &last.hash
                    || tx.logical_time() <= last.lt
                    || tx.now() < last.time
                    || update.old_hash.as_array() != &last.new_state
                {
                    return Err(Error::InvalidInput);
                }
            }
        }
        if let Some(event) = event(&tx)? {
            ledger.apply(&event, self.recovery_charge).map_err(|_| Error::InvalidInput)?;
        }
        self.last = Some(Link {
            hash,
            lt: tx.logical_time(),
            new_state: *update.new_hash.as_array(),
            time: tx.now(),
        });
        self.count = count;
        self.bytes = bytes;
        Ok(())
    }

    /// Consumes the provisional state. An error returns no usable ledger.
    pub fn finish(mut self) -> Result<Ledger> {
        match &self.last {
            None if self.head.last_lt == 0 => {}
            Some(last)
                if last.hash == self.head.last_hash
                    && last.lt == self.head.last_lt
                    && last.new_state == self.head.account_root => {}
            _ => return Err(Error::InvalidInput),
        }
        let ledger = self.ledger.take().ok_or(Error::InvalidInput)?;
        if ledger.checkpoint() != self.expected {
            return Err(Error::InvalidInput);
        }
        Ok(ledger)
    }
}
