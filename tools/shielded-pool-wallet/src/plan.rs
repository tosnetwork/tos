/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Choosing what a spend moves and where, before anything is sealed, signed
//! or proven.
//!
//! A plan is arithmetic over notes the wallet holds and the pool's immutable
//! terms: which notes go in, what each of the three output slots carries, what
//! leaves the pool and what the pool keeps as its withdrawal fee. It draws no
//! randomness and derives no key; the only thing it asks its caller for is a
//! fresh note-key index for each slot the wallet keeps for itself, and it asks
//! for those last, after every check that could refuse has passed, so a
//! refused plan consumes nothing.
//!
//! The circuit enforces conservation again (profile section 11.3) and the
//! contract enforces the denomination list and the fee (section 11.3, exit
//! codes 202 and 242). The planner enforces them first so a spend the chain
//! would refuse is refused here, before the wallet pays for a proof.

use crate::descriptor::Descriptor;
use crate::error::{Error, Result};
use crate::import::Imported;
use crate::keys::MLKEM_ENCAPSULATION_KEY_BYTES;
use crate::scan::Recovered;
use shielded_pool_circuit::field::Fr;
use std::collections::BTreeSet;

/// Section 11.1: a transaction spends at most two notes.
pub const MAX_INPUTS: usize = 2;
/// Section 11.2: a transaction always carries three output slots.
pub const OUTPUT_SLOTS: usize = 3;
/// Section 11.3: every amount is below 2^120.
pub const MAX_AMOUNT: u128 = (1u128 << 120) - 1;

fn refuse(message: impl Into<String>) -> Error {
    Error::Planning(message.into())
}

/// The pool's immutable terms a plan must honour, as its config cell states
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolTerms {
    /// The amounts the pool pays out in one piece, sorted.
    pub denominations: Vec<u128>,
    /// What every withdrawal leaves in the pool.
    pub withdrawal_fee: u128,
}

/// A note the planner may spend: an imported ordinary note at a known leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub note: Imported,
    pub leaf_index: u64,
}

/// Select recovered notes with known leaves, excluding locally held inputs.
pub fn spendable_candidates(recovered: &Recovered, held: &BTreeSet<u64>) -> Vec<Candidate> {
    recovered
        .notes
        .iter()
        .zip(recovered.leaves.iter())
        .filter_map(|(note, leaf)| {
            leaf.filter(|leaf| !held.contains(leaf))
                .map(|leaf_index| Candidate { note: *note, leaf_index })
        })
        .collect()
}

/// Plan from a complete wallet scan and its locally held inputs.
pub fn plan_recovered(
    terms: &PoolTerms,
    recovered: &Recovered,
    held: &BTreeSet<u64>,
    request: &Request,
    fresh_index: &mut dyn FnMut() -> Result<u64>,
) -> Result<Plan> {
    if !recovered.diagnostics.is_empty() {
        return Err(refuse("the wallet scan reported diagnostics"));
    }
    plan(terms, &spendable_candidates(recovered, held), request, fresh_index)
}

/// Where a recipient's note goes: the parts of a descriptor the sealing needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientKeys {
    pub note_key_index: u64,
    pub owner_nf_key_hash: Fr,
    pub pq_auth_key_hash: Fr,
    pub encapsulation_key: [u8; MLKEM_ENCAPSULATION_KEY_BYTES],
}

impl RecipientKeys {
    pub fn of(descriptor: &Descriptor) -> Self {
        Self {
            note_key_index: descriptor.note_key_index,
            owner_nf_key_hash: descriptor.owner_nf_key_hash,
            pq_auth_key_hash: shielded_pool_circuit::wire::pq_auth_key_hash(
                &descriptor.pq_auth_public_key,
            ),
            encapsulation_key: descriptor.mlkem_encapsulation_key,
        }
    }
}

/// A note paid to a third party inside the same spend: a relayer's fee at
/// the descriptor its quote named. It takes output slot 2, is an ordinary
/// note the relayer recovers like any recipient, and comes out of the notes
/// on top of the amount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fee {
    pub to: Box<RecipientKeys>,
    pub amount: u128,
}

/// What the holder asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// A private transfer of `amount` to the descriptor's holder, with an
    /// optional fee note to a relayer.
    Transfer { to: Box<RecipientKeys>, amount: u128, fee: Option<Fee> },
    /// A withdrawal of `amount` to a public account of workchain 0.
    Withdraw { amount: u128, recipient_account: [u8; 32] },
    /// A withdrawal with a fee note in output slot 2.
    RelayedWithdraw { amount: u128, recipient_account: [u8; 32], fee: Fee },
}

impl Request {
    /// Build a withdrawal that compensates the relayer from the input notes.
    pub fn relayed_withdrawal(
        domain: Fr,
        recipient_account: [u8; 32],
        amount: u128,
        fee_recipient: &Descriptor,
        fee_amount: u128,
    ) -> Result<Self> {
        fee_recipient.validate_recipient(domain)?;
        Ok(Self::RelayedWithdraw {
            amount,
            recipient_account,
            fee: Fee { to: Box::new(RecipientKeys::of(fee_recipient)), amount: fee_amount },
        })
    }

    /// Build a relayed transfer from the recipient and the quoted fee descriptor.
    pub fn relayed_transfer(
        domain: Fr,
        recipient: &Descriptor,
        amount: u128,
        fee_recipient: &Descriptor,
        fee_amount: u128,
    ) -> Result<Self> {
        recipient.validate_recipient(domain)?;
        fee_recipient.validate_recipient(domain)?;
        Ok(Self::Transfer {
            to: Box::new(RecipientKeys::of(recipient)),
            amount,
            fee: Some(Fee { to: Box::new(RecipientKeys::of(fee_recipient)), amount: fee_amount }),
        })
    }
}

/// One input slot of the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlannedInput {
    Note(Candidate),
    /// Section 4.5: a slot with no note. It still signs, with the key of a
    /// fresh index of this wallet.
    Phantom {
        note_key_index: u64,
    },
}

/// One output slot of the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlannedOutput {
    /// To the descriptor's holder, at the descriptor's index.
    Recipient { to: Box<RecipientKeys>, amount: u128 },
    /// Back to this wallet at a fresh index.
    Change { note_key_index: u64, amount: u128 },
    /// No value. Section 3: a fresh index of this wallet is consumed so the
    /// wallet recognises its own dummy, and its owner is the dummy constant.
    Dummy { note_key_index: u64 },
}

impl PlannedOutput {
    pub fn amount(&self) -> u128 {
        match self {
            PlannedOutput::Recipient { amount, .. } | PlannedOutput::Change { amount, .. } => {
                *amount
            }
            PlannedOutput::Dummy { .. } => 0,
        }
    }

    /// The index of this wallet the slot consumes, if any.
    pub fn own_index(&self) -> Option<u64> {
        match self {
            PlannedOutput::Recipient { .. } => None,
            PlannedOutput::Change { note_key_index, .. }
            | PlannedOutput::Dummy { note_key_index } => Some(*note_key_index),
        }
    }
}

/// Section 15.1: the index whose keys a withdrawal's recovery template is
/// built for. Its note, if the payout bounces, is minted to this wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub note_key_index: u64,
}

/// A spend, decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub inputs: [PlannedInput; MAX_INPUTS],
    pub outputs: [PlannedOutput; OUTPUT_SLOTS],
    pub public_amount_out: u128,
    pub withdrawal_fee: u128,
    pub recipient_account: Option<[u8; 32]>,
    pub recovery: Option<RecoveryPlan>,
}

impl Plan {
    pub fn is_withdrawal(&self) -> bool {
        self.public_amount_out > 0
    }

    /// Every index of this wallet the plan consumes: outputs in slot order,
    /// then the recovery index, then the phantom input's.
    pub fn own_indices(&self) -> Vec<u64> {
        let mut indices: Vec<u64> =
            self.outputs.iter().filter_map(PlannedOutput::own_index).collect();
        if let Some(recovery) = &self.recovery {
            indices.push(recovery.note_key_index);
        }
        for input in &self.inputs {
            if let PlannedInput::Phantom { note_key_index } = input {
                indices.push(*note_key_index);
            }
        }
        indices
    }

    /// The leaves the plan spends.
    pub fn input_leaves(&self) -> Vec<u64> {
        self.inputs
            .iter()
            .filter_map(|input| match input {
                PlannedInput::Note(candidate) => Some(candidate.leaf_index),
                PlannedInput::Phantom { .. } => None,
            })
            .collect()
    }

    pub fn input_total(&self) -> Result<u128> {
        self.inputs.iter().try_fold(0u128, |total, input| match input {
            PlannedInput::Note(candidate) => {
                total.checked_add(candidate.note.amount).ok_or_else(|| refuse("inputs overflow"))
            }
            PlannedInput::Phantom { .. } => Ok(total),
        })
    }

    /// Section 11.3: inputs equal outputs plus what leaves the pool plus what
    /// the pool keeps. Checked arithmetic throughout; the circuit proves it
    /// again.
    pub fn check_conservation(&self) -> Result<()> {
        let out = self
            .outputs
            .iter()
            .try_fold(0u128, |total, output| total.checked_add(output.amount()))
            .and_then(|total| total.checked_add(self.public_amount_out))
            .and_then(|total| total.checked_add(self.withdrawal_fee))
            .ok_or_else(|| refuse("outputs overflow"))?;
        if self.input_total()? != out {
            return Err(refuse("the plan does not conserve value"));
        }
        for output in &self.outputs {
            if output.amount() > MAX_AMOUNT {
                return Err(refuse("an output amount is out of range"));
            }
        }
        Ok(())
    }
}

/// Which spendable notes cover `need`, by the fixed rule: the smallest single
/// note that covers it, else the pair with the smallest sum that covers it.
/// Candidates are ordered by amount then leaf, so the choice is a function of
/// the holdings and nothing else.
fn select(candidates: &[Candidate], need: u128) -> Result<Vec<Candidate>> {
    let mut sorted: Vec<&Candidate> = candidates
        .iter()
        // Spendable is the scan's word: an ordinary note, or a recovery note
        // once its bounce has minted it. A template, a dummy and a spent note
        // are not.
        .filter(|candidate| {
            candidate.note.spendable && !candidate.note.spent && candidate.note.amount > 0
        })
        .collect();
    sorted.sort_by_key(|candidate| (candidate.note.amount, candidate.leaf_index));
    if let Some(single) = sorted.iter().find(|candidate| candidate.note.amount >= need) {
        return Ok(vec![(*single).clone()]);
    }
    let mut best: Option<(u128, &Candidate, &Candidate)> = None;
    for (position, first) in sorted.iter().enumerate() {
        for second in sorted.iter().skip(position.saturating_add(1)) {
            if first.leaf_index == second.leaf_index
                || first.note.note_body == second.note.note_body
            {
                continue;
            }
            let Some(sum) = first.note.amount.checked_add(second.note.amount) else { continue };
            if sum >= need && best.is_none_or(|(best_sum, _, _)| sum < best_sum) {
                best = Some((sum, first, second));
            }
        }
    }
    match best {
        Some((_, first, second)) => Ok(vec![first.clone(), second.clone()]),
        None => Err(refuse(format!(
            "no one or two spendable notes cover {need}; consolidate first: send two notes to a fresh \
             descriptor of this instance (`tosctl shield address`)"
        ))),
    }
}

/// Decides a spend. `fresh_index` is asked for one index per slot the wallet
/// keeps for itself, in the order [`Plan::own_indices`] lists them, and only
/// once every check has passed.
pub fn plan(
    terms: &PoolTerms,
    candidates: &[Candidate],
    request: &Request,
    fresh_index: &mut dyn FnMut() -> Result<u64>,
) -> Result<Plan> {
    let (amount, withdrawal) = match request {
        Request::Transfer { amount, .. } => (*amount, false),
        Request::Withdraw { amount, .. } | Request::RelayedWithdraw { amount, .. } => {
            (*amount, true)
        }
    };
    if amount == 0 {
        return Err(refuse("an amount of zero"));
    }
    if amount > MAX_AMOUNT {
        return Err(refuse("an amount out of range"));
    }
    let fee = match request {
        Request::Transfer { to, fee, .. } => {
            if fee.as_ref().is_some_and(|fee| fee.to == *to) {
                return Err(refuse("the relayer's fee descriptor is the recipient's"));
            }
            fee.as_ref()
        }
        Request::RelayedWithdraw { fee, .. } => Some(fee),
        Request::Withdraw { .. } => None,
    };
    let relayer_fee = match fee {
        Some(fee) if fee.amount == 0 => return Err(refuse("a relayer fee of zero")),
        Some(fee) if fee.amount > MAX_AMOUNT => return Err(refuse("a relayer fee out of range")),
        Some(fee) => fee.amount,
        None => 0,
    };
    let withdrawal_fee = if withdrawal {
        if terms.withdrawal_fee == 0 || terms.withdrawal_fee > MAX_AMOUNT {
            return Err(refuse("the pool's withdrawal fee is out of range"));
        }
        if !terms.denominations.contains(&amount) {
            return Err(refuse(format!(
                "{amount} is not one of the pool's denominations; a withdrawal is paid in one piece"
            )));
        }
        terms.withdrawal_fee
    } else {
        0
    };
    let need = amount
        .checked_add(withdrawal_fee)
        .and_then(|need| need.checked_add(relayer_fee))
        .ok_or_else(|| refuse("amount overflow"))?;
    let selected = select(candidates, need)?;
    let total = selected
        .iter()
        .try_fold(0u128, |total, candidate| total.checked_add(candidate.note.amount))
        .ok_or_else(|| refuse("inputs overflow"))?;
    let change = total.checked_sub(need).ok_or_else(|| refuse("inputs below the need"))?;

    // Every check has passed; now the indices. Outputs in slot order, then
    // the recovery index, then the phantom's.
    let own_output =
        |fresh: &mut dyn FnMut() -> Result<u64>, amount: u128| -> Result<PlannedOutput> {
            let note_key_index = fresh()?;
            Ok(if amount == 0 {
                PlannedOutput::Dummy { note_key_index }
            } else {
                PlannedOutput::Change { note_key_index, amount }
            })
        };
    let outputs = match request {
        Request::Transfer { to, fee, .. } => [
            PlannedOutput::Recipient { to: to.clone(), amount },
            own_output(fresh_index, change)?,
            match fee {
                Some(fee) => PlannedOutput::Recipient { to: fee.to.clone(), amount: fee.amount },
                None => PlannedOutput::Dummy { note_key_index: fresh_index()? },
            },
        ],
        Request::Withdraw { .. } | Request::RelayedWithdraw { .. } => [
            own_output(fresh_index, change)?,
            PlannedOutput::Dummy { note_key_index: fresh_index()? },
            match fee {
                Some(fee) => PlannedOutput::Recipient { to: fee.to.clone(), amount: fee.amount },
                None => PlannedOutput::Dummy { note_key_index: fresh_index()? },
            },
        ],
    };
    let recovery =
        if withdrawal { Some(RecoveryPlan { note_key_index: fresh_index()? }) } else { None };
    let mut selected = selected.into_iter();
    let first = selected.next().map(PlannedInput::Note).ok_or_else(|| refuse("no input"))?;
    let second = match selected.next() {
        Some(candidate) => PlannedInput::Note(candidate),
        None => PlannedInput::Phantom { note_key_index: fresh_index()? },
    };
    let plan = Plan {
        inputs: [first, second],
        outputs,
        public_amount_out: if withdrawal { amount } else { 0 },
        withdrawal_fee,
        recipient_account: match request {
            Request::Withdraw { recipient_account, .. }
            | Request::RelayedWithdraw { recipient_account, .. } => Some(*recipient_account),
            Request::Transfer { .. } => None,
        },
        recovery,
    };
    plan.check_conservation()?;
    Ok(plan)
}
