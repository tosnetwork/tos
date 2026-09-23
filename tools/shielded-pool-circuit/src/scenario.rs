/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! A pool with notes in it, so a caller can build a transaction the way a
//! wallet would instead of writing down eighteen numbers.
//!
//! This lives in the library rather than in the tests because the development
//! proof fixture and the relation-removal tests must be built from the same
//! transaction. Two copies of a scenario drift, and the one that drifts is
//! always the one nobody ran.

use ark_ff::AdditiveGroup;

use crate::circuit::{HeldNote, OutputNote, TransactionBuilder, TransactionWitness};
use crate::domains::dummy_owner_nf_hash;
use crate::error::Result;
use crate::field::{fr_from_u128, Fr};
use crate::notes;
use crate::public_inputs::PublicInputs;
use crate::tree::Frontier;

/// An arbitrary but fixed execution domain for the fixtures. The real value is
/// a deployment fact, not a circuit fact.
pub fn execution_domain() -> Fr {
    fr_from_u128(0x5348_4c44_5f54_4553_5400)
}

/// A small amount as a field element.
pub fn amount(value: u128) -> Fr {
    fr_from_u128(value)
}

/// A deterministic element stream, so two runs build the same pool.
pub struct Stream {
    state: Fr,
}

impl Stream {
    pub fn new(seed: u64) -> Self {
        Self { state: fr_from_u128(u128::from(seed)) }
    }

    /// The next element. Named `next` for readability; this is not an
    /// iterator and the sequence never ends.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Fr {
        self.state = notes::owner_nf_key_hash(self.state);
        self.state
    }
}

/// A pool with a commitment tree and the notes appended to it.
pub struct Pool {
    pub frontier: Frontier,
    pub root: Fr,
    stream: Stream,
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl Pool {
    pub fn new() -> Self {
        let frontier = Frontier::new();
        let root = frontier.empty_root();
        Self { frontier, root, stream: Stream::new(0x504f_4f4c) }
    }

    /// Appends a note of `value` owned by a fresh key, and returns it as the
    /// wallet would hold it together with the PQ key hash the spender presents
    /// as a public input.
    pub fn deposit(&mut self, value: Fr) -> Result<(HeldNote, Fr)> {
        let owner_nf_key = self.stream.next();
        let note_secret = self.stream.next();
        let pq_auth_key_hash = self.stream.next();
        let output_data_hash = self.stream.next();

        let key_hash = notes::owner_nf_key_hash(owner_nf_key);
        let owner = notes::owner_commitment(key_hash, pq_auth_key_hash, note_secret);
        let body = notes::note_body_commitment(owner, value, output_data_hash);
        let index = self.frontier.next_index();
        let leaf = notes::note_commitment(body, fr_from_u128(u128::from(index)));
        let (leaf_index, root) = self.frontier.append(leaf)?;
        self.root = root;

        Ok((
            HeldNote {
                is_phantom: false,
                owner_nf_key,
                note_secret,
                amount: value,
                output_data_hash,
                leaf_index,
            },
            pq_auth_key_hash,
        ))
    }

    /// A phantom input slot: no note, no membership.
    pub fn phantom(&mut self) -> (HeldNote, Fr) {
        let pq_auth_key_hash = self.stream.next();
        (
            HeldNote {
                is_phantom: true,
                owner_nf_key: self.stream.next(),
                note_secret: self.stream.next(),
                amount: Fr::ZERO,
                output_data_hash: self.stream.next(),
                leaf_index: 0,
            },
            pq_auth_key_hash,
        )
    }

    /// A note that was never appended to the tree.
    pub fn note_outside_the_tree(&mut self, value: Fr) -> (HeldNote, Fr) {
        let pq_auth_key_hash = self.stream.next();
        (
            HeldNote {
                is_phantom: false,
                owner_nf_key: self.stream.next(),
                note_secret: self.stream.next(),
                amount: value,
                output_data_hash: self.stream.next(),
                leaf_index: 0,
            },
            pq_auth_key_hash,
        )
    }

    pub fn fresh(&mut self) -> Fr {
        self.stream.next()
    }

    /// A spendable output note.
    pub fn real_output(&mut self, value: Fr) -> OutputNote {
        OutputNote {
            is_dummy: false,
            owner_nf_key_hash: self.stream.next(),
            pq_auth_key_hash: self.stream.next(),
            note_secret: self.stream.next(),
            amount: value,
        }
    }

    /// A dummy output note, shaped as section 11.2 requires.
    pub fn dummy_output(&mut self) -> OutputNote {
        OutputNote {
            is_dummy: true,
            owner_nf_key_hash: dummy_owner_nf_hash(),
            pq_auth_key_hash: self.stream.next(),
            note_secret: self.stream.next(),
            amount: Fr::ZERO,
        }
    }
}

/// The public fields of a transaction other than the derived ones.
#[derive(Clone, Copy, Debug)]
pub struct PublicTerms {
    pub public_amount_out: Fr,
    pub withdrawal_fee: Fr,
    pub public_recipient_hash: Fr,
    pub recovery_template_hash: Fr,
}

impl PublicTerms {
    /// A transfer: every public term is zero, as section 11.3 requires.
    pub fn transfer() -> Self {
        Self {
            public_amount_out: Fr::ZERO,
            withdrawal_fee: Fr::ZERO,
            public_recipient_hash: Fr::ZERO,
            recovery_template_hash: Fr::ZERO,
        }
    }
}

/// Builds a two-input, three-output transaction.
pub fn transaction(
    pool: &mut Pool,
    held: [HeldNote; 2],
    input_pq: [Fr; 2],
    outputs: [OutputNote; 3],
    terms: PublicTerms,
) -> Result<(PublicInputs, TransactionWitness)> {
    let output_data_hash = [pool.fresh(), pool.fresh(), pool.fresh()];
    let intent_nonce = pool.fresh();
    let builder = TransactionBuilder {
        execution_domain: execution_domain(),
        valid_until: 1_800_000_000,
        intent_nonce,
        public_amount_out: terms.public_amount_out,
        withdrawal_fee: terms.withdrawal_fee,
        public_recipient_hash: terms.public_recipient_hash,
        recovery_template_hash: terms.recovery_template_hash,
        is_withdrawal: None,
        input_pq_auth_key_hash: input_pq,
        outputs,
        output_data_hash,
    };
    builder.build(&pool.frontier, pool.root, held)
}

/// Recomputes the section 9.3 digest after a public field has been changed, so
/// a tampered transaction stays internally consistent and only the targeted
/// relation is violated.
pub fn reseal(public: &PublicInputs, witness: &TransactionWitness) -> PublicInputs {
    let core = notes::intent_core(
        public.execution_domain,
        public.nullifier_0,
        public.nullifier_1,
        public.public_amount_out,
        public.withdrawal_fee,
        public.public_recipient_hash,
        public.recovery_template_hash,
    );
    let outputs = notes::intent_outputs(
        public.note_body_0,
        public.note_body_1,
        public.note_body_2,
        public.pq_auth_key_hash_0,
        public.pq_auth_key_hash_1,
        witness.intent_nonce,
        public.valid_until,
    );
    let mut resealed = *public;
    resealed.transaction_intent_digest = notes::intent_final(core, outputs);
    resealed
}

/// One real input, one phantom, two real outputs and one dummy.
pub fn valid_transfer() -> Result<(Pool, PublicInputs, TransactionWitness)> {
    let mut pool = Pool::new();
    let (note, pq0) = pool.deposit(amount(5_000))?;
    let (phantom, pq1) = pool.phantom();
    let outputs =
        [pool.real_output(amount(3_000)), pool.real_output(amount(2_000)), pool.dummy_output()];
    let (public, witness) =
        transaction(&mut pool, [note, phantom], [pq0, pq1], outputs, PublicTerms::transfer())?;
    Ok((pool, public, witness))
}

/// Two real inputs, one real change output and two dummies.
pub fn valid_withdrawal() -> Result<(Pool, PublicInputs, TransactionWitness)> {
    let mut pool = Pool::new();
    let (first, pq0) = pool.deposit(amount(5_000))?;
    let (second, pq1) = pool.deposit(amount(1_000))?;
    let outputs = [pool.real_output(amount(2_000)), pool.dummy_output(), pool.dummy_output()];
    let recipient = pool.fresh();
    let recovery = pool.fresh();
    let (public, witness) = transaction(
        &mut pool,
        [first, second],
        [pq0, pq1],
        outputs,
        PublicTerms {
            public_amount_out: amount(3_900),
            withdrawal_fee: amount(100),
            public_recipient_hash: recipient,
            recovery_template_hash: recovery,
        },
    )?;
    Ok((pool, public, witness))
}

/// The transaction the section 10.1 development proof is built over.
pub fn development_transaction() -> Result<(PublicInputs, TransactionWitness)> {
    let (_pool, public, witness) = valid_withdrawal()?;
    Ok((public, witness))
}
