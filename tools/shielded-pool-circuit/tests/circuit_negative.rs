/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Relation removal: profile section 19 gate 3.
//!
//! Each case builds a witness that a correct circuit must reject, shows the
//! full circuit rejecting it, then removes exactly one relation and shows the
//! same witness accepted. A relation that cannot be shown load-bearing this way
//! is reported as such rather than quietly counted as tested.
//!
//! Some checks sit behind another relation: the witness that would exercise
//! them cannot be built while the earlier relation holds. Those cases state
//! their baseline explicitly, and the baseline still has the relation under
//! test switched on, so the removal is what changes the verdict.

mod scenario;

use ark_ff::{AdditiveGroup, Field};

use shielded_pool_circuit::circuit::{OutputNote, Relations, TransactionWitness};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::public_inputs::PublicInputs;

use scenario::{amount, Pool};

/// Runs one removal case and reports what it showed.
fn removal(
    relation: &str,
    exploit: &str,
    baseline: Relations,
    weakened: Relations,
    public: &PublicInputs,
    witness: &TransactionWitness,
) {
    assert_ne!(
        baseline, weakened,
        "{relation}: the baseline and the weakened set are identical, so nothing was removed"
    );
    assert!(
        !scenario::satisfied(public, witness, baseline),
        "{relation}: the full circuit ACCEPTED a witness it must reject ({exploit})"
    );
    assert!(
        scenario::satisfied(public, witness, weakened),
        "{relation}: removing it did not make the witness acceptable, so this case does not \
         demonstrate what the relation is for"
    );
    println!("{relation}: removed -> accepted. Exploit let through: {exploit}");
}

fn two_thousand_twenty_bits() -> Fr {
    // 2^120, the first value the range check must reject.
    let mut value = Fr::ONE;
    for _ in 0..120 {
        value = value.double();
    }
    value
}

/// A transfer whose one real input carries an amount at the range boundary and
/// whose outputs stay inside it. Only the input's range is violated.
#[test]
fn input_amount_range() {
    let mut pool = Pool::new();
    let boundary = two_thousand_twenty_bits();
    let (note, pq0) = scenario::deposit(&mut pool, boundary);
    let (phantom, pq1) = pool.phantom();
    let outputs =
        [pool.real_output(boundary - Fr::ONE), pool.real_output(Fr::ONE), pool.dummy_output()];
    let (public, witness) = scenario::transaction(
        &mut pool,
        [note, phantom],
        [pq0, pq1],
        outputs,
        scenario::PublicTerms::transfer(),
    );

    let mut weakened = Relations::ALL;
    weakened.input_amount_range = false;
    removal(
        "section 11.1 input amount < 2^120",
        "a note holding 2^120 is spent and its full value credited, above the declared bound",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// A withdrawal that balances only because an output amount wraps the field.
#[test]
fn output_amount_range() {
    let mut pool = Pool::new();
    let (note, pq0) = scenario::deposit(&mut pool, amount(1));
    let (phantom, pq1) = pool.phantom();
    let payout = amount(1_000_000);
    let fee = amount(100);
    // out0 = 1 - payout - fee, taken in the field: a negative amount.
    let wrapped = Fr::ONE - payout - fee;
    let outputs = [pool.real_output(wrapped), pool.dummy_output(), pool.dummy_output()];
    let recipient = pool.fresh();
    let recovery = pool.fresh();
    let (public, witness) = scenario::transaction(
        &mut pool,
        [note, phantom],
        [pq0, pq1],
        outputs,
        scenario::PublicTerms {
            public_amount_out: payout,
            withdrawal_fee: fee,
            public_recipient_hash: recipient,
            recovery_template_hash: recovery,
        },
    );

    let mut weakened = Relations::ALL;
    weakened.output_amount_range = false;
    removal(
        "section 11.2 output amount < 2^120",
        "a one-unit note is withdrawn as 1 000 000 because a negative output amount balances \
         conservation in the field",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// Outputs simply exceed inputs.
#[test]
fn conservation() {
    let mut pool = Pool::new();
    let (note, pq0) = scenario::deposit(&mut pool, amount(5_000));
    let (phantom, pq1) = pool.phantom();
    let outputs =
        [pool.real_output(amount(3_000)), pool.real_output(amount(3_000)), pool.dummy_output()];
    let (public, witness) = scenario::transaction(
        &mut pool,
        [note, phantom],
        [pq0, pq1],
        outputs,
        scenario::PublicTerms::transfer(),
    );

    let mut weakened = Relations::ALL;
    weakened.conservation = false;
    removal(
        "section 11.3 conservation",
        "5 000 in, 6 000 out: the pool mints 1 000 from nothing",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// A note that was never in the tree is spent.
#[test]
fn input_membership() {
    let mut pool = Pool::new();
    let (_real, _pq) = scenario::deposit(&mut pool, amount(1));
    let (invented, pq0) = pool.note_outside_the_tree(amount(5_000));
    let (phantom, pq1) = pool.phantom();
    let outputs = [pool.real_output(amount(5_000)), pool.dummy_output(), pool.dummy_output()];
    let (public, witness) = scenario::transaction(
        &mut pool,
        [invented, phantom],
        [pq0, pq1],
        outputs,
        scenario::PublicTerms::transfer(),
    );

    let mut weakened = Relations::ALL;
    weakened.input_membership = false;
    removal(
        "section 11.1 membership under anchor_root",
        "a note the pool never issued is spent for 5 000: value is created out of nothing",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// The published nullifier of a real input is not the one the note derives.
#[test]
fn real_nullifier() {
    let (mut pool, public, witness) = scenario::valid_transfer();
    let mut tampered = public;
    tampered.nullifier_0 = pool.fresh();
    let tampered = scenario::reseal(&tampered, &witness);

    let mut weakened = Relations::ALL;
    weakened.real_nullifier = false;
    removal(
        "section 11.1 / 4.4 real nullifier derivation",
        "a spent note publishes a nullifier of the prover's choosing, so the same note can be \
         spent again and again",
        Relations::ALL,
        weakened,
        &tampered,
        &witness,
    );
}

/// The published nullifier of a phantom slot is not the section 4.5 value.
#[test]
fn phantom_nullifier() {
    let (mut pool, public, witness) = scenario::valid_transfer();
    let mut tampered = public;
    tampered.nullifier_1 = pool.fresh();
    let tampered = scenario::reseal(&tampered, &witness);

    let mut weakened = Relations::ALL;
    weakened.phantom_nullifier = false;
    removal(
        "section 11.1 / 4.5 phantom nullifier derivation",
        "a phantom slot publishes any nullifier it likes, so it can burn another user's unspent \
         note by inserting that note's nullifier",
        Relations::ALL,
        weakened,
        &tampered,
        &witness,
    );
}

/// Both input slots are phantom.
#[test]
fn at_least_one_real_input() {
    let mut pool = Pool::new();
    let (first, pq0) = pool.phantom();
    let (second, pq1) = pool.phantom();
    let outputs = [pool.dummy_output(), pool.dummy_output(), pool.dummy_output()];
    let (public, witness) = scenario::transaction(
        &mut pool,
        [first, second],
        [pq0, pq1],
        outputs,
        scenario::PublicTerms::transfer(),
    );

    let mut weakened = Relations::ALL;
    weakened.at_least_one_real_input = false;
    removal(
        "section 11.1 at least one real input",
        "a transaction that spends no note at all is accepted, appending three commitments and \
         two nullifiers for free",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// The same note occupies both input slots.
#[test]
fn nullifiers_distinct() {
    let mut pool = Pool::new();
    let (note, pq0) = scenario::deposit(&mut pool, amount(5_000));
    let twin = note.clone();
    let outputs = [pool.real_output(amount(10_000)), pool.dummy_output(), pool.dummy_output()];
    let (public, witness) = scenario::transaction(
        &mut pool,
        [note, twin],
        [pq0, pq0],
        outputs,
        scenario::PublicTerms::transfer(),
    );
    assert_eq!(
        public.nullifier_0, public.nullifier_1,
        "the twin spend must produce one nullifier twice"
    );

    let mut weakened = Relations::ALL;
    weakened.nullifiers_distinct = false;
    removal(
        "section 11.1 nf0 != nf1",
        "one 5 000 note fills both input slots and is counted twice, paying out 10 000",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// A real output carrying zero.
#[test]
fn output_amount_non_zero_when_real() {
    let mut pool = Pool::new();
    let (note, pq0) = scenario::deposit(&mut pool, amount(5_000));
    let (phantom, pq1) = pool.phantom();
    let outputs =
        [pool.real_output(amount(5_000)), pool.real_output(Fr::ZERO), pool.dummy_output()];
    let (public, witness) = scenario::transaction(
        &mut pool,
        [note, phantom],
        [pq0, pq1],
        outputs,
        scenario::PublicTerms::transfer(),
    );

    let mut weakened = Relations::ALL;
    weakened.output_amount_non_zero_when_real = false;
    removal(
        "section 11.2 real output amount > 0",
        "a slot that is not marked dummy carries zero value with a real owner, so the dummy and \
         real shapes the payload rules depend on are no longer distinguishable",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// A dummy output with an attacker-chosen owner and a non-zero amount.
#[test]
fn dummy_output_shape() {
    let mut pool = Pool::new();
    let (note, pq0) = scenario::deposit(&mut pool, amount(5_000));
    let (phantom, pq1) = pool.phantom();
    let attacker_owner = pool.fresh();
    let outputs = [
        pool.real_output(amount(4_993)),
        pool.dummy_output(),
        OutputNote {
            is_dummy: true,
            owner_nf_key_hash: attacker_owner,
            pq_auth_key_hash: pool.fresh(),
            note_secret: pool.fresh(),
            amount: amount(7),
        },
    ];
    let (public, witness) = scenario::transaction(
        &mut pool,
        [note, phantom],
        [pq0, pq1],
        outputs,
        scenario::PublicTerms::transfer(),
    );

    let mut weakened = Relations::ALL;
    weakened.dummy_output_shape = false;
    removal(
        "section 11.2 dummy output shape",
        "a slot declared dummy carries a real owner and a non-zero amount, so a spendable note \
         is delivered under the payload rules meant for dummies",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// Section 19 gate 28: an output note secret of zero.
#[test]
fn output_note_secret_non_zero() {
    let mut pool = Pool::new();
    let (note, pq0) = scenario::deposit(&mut pool, amount(5_000));
    let (phantom, pq1) = pool.phantom();
    let mut third = pool.dummy_output();
    third.note_secret = Fr::ZERO;
    let outputs = [pool.real_output(amount(5_000)), pool.dummy_output(), third];
    let (public, witness) = scenario::transaction(
        &mut pool,
        [note, phantom],
        [pq0, pq1],
        outputs,
        scenario::PublicTerms::transfer(),
    );

    let mut weakened = Relations::ALL;
    weakened.output_note_secret_non_zero = false;
    removal(
        "section 11.2 / gate 28 note_secret != 0",
        "an output commits with note_secret = 0, so its owner commitment is a function of two \
         values the payer already knows and no longer hides the note",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// The published note body is not the one the witness builds.
#[test]
fn output_note_body_binding() {
    let (mut pool, public, witness) = scenario::valid_transfer();
    let mut tampered = public;
    tampered.note_body_1 = pool.fresh();
    let tampered = scenario::reseal(&tampered, &witness);

    let mut weakened = Relations::ALL;
    weakened.output_note_body_binding = false;
    removal(
        "section 11.2 published note body equals the computed one",
        "the leaf the pool appends is chosen freely by the prover: any amount, any owner, with \
         no relation to the inputs",
        Relations::ALL,
        weakened,
        &tampered,
        &witness,
    );
}

/// A withdrawal that pays no fee.
#[test]
fn mode_predicates() {
    let mut pool = Pool::new();
    let (first, pq0) = scenario::deposit(&mut pool, amount(5_000));
    let (second, pq1) = scenario::deposit(&mut pool, amount(1_000));
    let outputs = [pool.real_output(amount(2_100)), pool.dummy_output(), pool.dummy_output()];
    let recipient = pool.fresh();
    let recovery = pool.fresh();
    let (public, witness) = scenario::transaction(
        &mut pool,
        [first, second],
        [pq0, pq1],
        outputs,
        scenario::PublicTerms {
            public_amount_out: amount(3_900),
            withdrawal_fee: Fr::ZERO,
            public_recipient_hash: recipient,
            recovery_template_hash: recovery,
        },
    );

    let mut weakened = Relations::ALL;
    weakened.mode_predicates = false;
    removal(
        "section 11.3 withdrawal predicates",
        "a withdrawal pays a fee of zero, so the outbound forward fee and any bounce recovery \
         are funded from the pool's reserve instead of the withdrawer",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// A public payout that is not an amount at all: chosen as `r - 1000` so that
/// conservation wraps and the outputs quietly exceed the inputs. The fee here
/// is an ordinary small number, so this exploit belongs to the payout's width
/// alone and to no other relation.
#[test]
fn public_amount_range() {
    let mut pool = Pool::new();
    let (first, pq0) = scenario::deposit(&mut pool, amount(5_000));
    let (second, pq1) = scenario::deposit(&mut pool, amount(1_000));
    // 6,000 in; 6,990 out plus a 10 fee, balanced only by the payout wrapping.
    let outputs = [pool.real_output(amount(6_990)), pool.dummy_output(), pool.dummy_output()];
    let fee = amount(10);
    let payout = -amount(1_000);
    let recipient = pool.fresh();
    let recovery = pool.fresh();
    let (public, witness) = scenario::transaction(
        &mut pool,
        [first, second],
        [pq0, pq1],
        outputs,
        scenario::PublicTerms {
            public_amount_out: payout,
            withdrawal_fee: fee,
            public_recipient_hash: recipient,
            recovery_template_hash: recovery,
        },
    );

    let mut weakened = Relations::ALL;
    weakened.public_amount_range = false;
    removal(
        "section 11.3 public amount width",
        "the circuit endorses 990 more in notes than were put in, because a payout of r-1000 \
         wraps conservation back into balance",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// The same theft driven by the fee instead of the payout. The profile states
/// only `withdrawal_fee > 0`; this is what the missing upper bound buys, and
/// why the ruling put the fee under the same width as every other amount.
#[test]
fn withdrawal_fee_range() {
    let mut pool = Pool::new();
    let (first, pq0) = scenario::deposit(&mut pool, amount(5_000));
    let (second, pq1) = scenario::deposit(&mut pool, amount(1_000));
    // 6,000 in; 6,500 in notes and 500 paid out, balanced by a fee of r-1000.
    let outputs = [pool.real_output(amount(6_500)), pool.dummy_output(), pool.dummy_output()];
    let payout = amount(500);
    let fee = -amount(1_000);
    let recipient = pool.fresh();
    let recovery = pool.fresh();
    let (public, witness) = scenario::transaction(
        &mut pool,
        [first, second],
        [pq0, pq1],
        outputs,
        scenario::PublicTerms {
            public_amount_out: payout,
            withdrawal_fee: fee,
            public_recipient_hash: recipient,
            recovery_template_hash: recovery,
        },
    );

    let mut weakened = Relations::ALL;
    weakened.withdrawal_fee_range = false;
    removal(
        "section 11.3 withdrawal fee width",
        "a fee of r-1000 wraps conservation, so 1,000 more leaves the pool than entered it \
         while every amount in sight still looks like an amount",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// The digest the two signatures cover is unrelated to the transaction.
#[test]
fn intent_digest() {
    let (mut pool, public, witness) = scenario::valid_transfer();
    let mut tampered = public;
    tampered.transaction_intent_digest = pool.fresh();

    let mut weakened = Relations::ALL;
    weakened.intent_digest = false;
    removal(
        "section 11.4 intent recomputation",
        "the signed digest is not derived from this transaction, so the signatures authorise \
         nothing: output slots, amounts and the fee can all be rewritten after signing",
        Relations::ALL,
        weakened,
        &tampered,
        &witness,
    );
}

/// Section 19 gate 28: a zero intent nonce.
#[test]
fn intent_nonce_non_zero() {
    let mut pool = Pool::new();
    let (note, pq0) = scenario::deposit(&mut pool, amount(5_000));
    let (phantom, pq1) = pool.phantom();
    let outputs = [pool.real_output(amount(5_000)), pool.dummy_output(), pool.dummy_output()];
    let output_data_hash = [pool.fresh(), pool.fresh(), pool.fresh()];
    let zero = Fr::ZERO;
    let builder = shielded_pool_circuit::circuit::TransactionBuilder {
        execution_domain: scenario::execution_domain(),
        valid_until: 1_800_000_000,
        intent_nonce: Fr::ZERO,
        public_amount_out: zero,
        withdrawal_fee: zero,
        public_recipient_hash: zero,
        recovery_template_hash: zero,
        is_withdrawal: None,
        input_pq_auth_key_hash: [pq0, pq1],
        outputs,
        output_data_hash,
    };
    let (public, witness) = match builder.build(&pool.frontier, pool.root, [note, phantom]) {
        Ok(pair) => pair,
        Err(error) => panic!("building the transaction: {error}"),
    };

    let mut weakened = Relations::ALL;
    weakened.intent_nonce_non_zero = false;
    removal(
        "gate 28 intent_nonce != 0",
        "the phantom nullifier collapses to a function of the slot and the public key hash \
         alone, so it repeats across transactions and can be predicted or pre-inserted",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

/// A real input carrying zero, which is only reachable once such a note exists.
#[test]
fn input_amount_non_zero_when_real() {
    let mut pool = Pool::new();
    let (note, pq0) = scenario::deposit(&mut pool, Fr::ZERO);
    let (phantom, pq1) = pool.phantom();
    let outputs = [pool.dummy_output(), pool.dummy_output(), pool.dummy_output()];
    let (public, witness) = scenario::transaction(
        &mut pool,
        [note, phantom],
        [pq0, pq1],
        outputs,
        scenario::PublicTerms::transfer(),
    );

    let mut weakened = Relations::ALL;
    weakened.input_amount_non_zero_when_real = false;
    removal(
        "section 11.1 real input amount > 0",
        "a zero-value note satisfies the real-input requirement, so a transaction that spends \
         nothing still passes as a spend and consumes a nullifier slot",
        Relations::ALL,
        weakened,
        &public,
        &witness,
    );
}

// ---------------------------------------------------------------------------
// Cases whose relation sits behind another one. The baseline states which.

/// A nullifier of zero. The derivation relation has to be off for a witness to
/// reach this check at all, because no preimage of zero is known.
#[test]
fn nullifiers_non_zero_behind_the_derivation() {
    let (_pool, public, witness) = scenario::valid_transfer();
    let mut tampered = public;
    tampered.nullifier_0 = Fr::ZERO;
    let tampered = scenario::reseal(&tampered, &witness);

    let mut baseline = Relations::ALL;
    baseline.real_nullifier = false;
    let mut weakened = baseline;
    weakened.nullifiers_non_zero = false;
    removal(
        "section 11.1 nullifiers non-zero (baseline: real nullifier derivation off)",
        "a published nullifier of zero, which collides with the empty-leaf value the nullifier \
         tree uses",
        baseline,
        weakened,
        &tampered,
        &witness,
    );
}

/// A leaf index that is not the position the path walks. Membership has to be
/// off, because a note at a different index is simply not in the tree.
#[test]
fn leaf_index_binding_behind_membership() {
    let (_pool, public, mut witness) = scenario::valid_transfer();
    witness.inputs[0].leaf_index = 1;

    let mut baseline = Relations::ALL;
    baseline.input_membership = false;
    let mut weakened = baseline;
    weakened.leaf_index_binding = false;
    removal(
        "section 11.1 leaf index matches the path position (baseline: membership off)",
        "the index hashed into the note commitment and the position the path walks are allowed \
         to disagree",
        baseline,
        weakened,
        &public,
        &witness,
    );
}

/// A leaf index above 2^32. Membership and the index binding both have to be
/// off for the same reason.
#[test]
fn leaf_index_range_behind_membership() {
    let (_pool, public, mut witness) = scenario::valid_transfer();
    witness.inputs[0].leaf_index = 1u64 << 32;

    let mut baseline = Relations::ALL;
    baseline.input_membership = false;
    baseline.leaf_index_binding = false;
    let mut weakened = baseline;
    weakened.leaf_index_range = false;
    removal(
        "section 5 leaf index < 2^32 (baseline: membership and index binding off)",
        "a note commitment built at an index the contract can never assign",
        baseline,
        weakened,
        &public,
        &witness,
    );
}

// ---------------------------------------------------------------------------

/// Section 11.1 says the phantom amount is zero, and also that the selector
/// removing it from conservation is the same boolean. With the selector in
/// place the zero check has no effect on any other value, so removing it lets
/// nothing through. That is recorded here rather than dressed up as an
/// exploit: a guard that cannot be tripped is not evidence of anything.
#[test]
fn phantom_amount_zero_is_redundant_given_the_selector() {
    let (_pool, public, mut witness) = scenario::valid_transfer();
    assert!(
        witness.inputs[1].is_phantom,
        "the second slot of the standard transfer is the phantom one"
    );
    witness.inputs[1].amount = amount(7);

    assert!(
        !scenario::satisfied(&public, &witness, Relations::ALL),
        "the full circuit accepted a phantom slot carrying a non-zero amount"
    );
    let mut weakened = Relations::ALL;
    weakened.phantom_amount_is_zero = false;
    assert!(
        scenario::satisfied(&public, &witness, weakened),
        "removing the phantom zero check did not make this witness acceptable"
    );
    println!(
        "section 11.1 phantom amount = 0: removed -> accepted, but the accepted witness gains \
         nothing. The amount enters conservation only through `amount * is_real`, so with the \
         selector in place the value of a phantom amount reaches no other relation. The check \
         is defence in depth, not a load-bearing constraint."
    );
}

/// A witness the tests build has to be a witness the circuit would otherwise
/// accept, or a removal case could pass because of an unrelated mistake in the
/// setup. This is the control.
#[test]
fn the_control_case_is_accepted_by_every_set() {
    let (_pool, public, witness) = scenario::valid_transfer();
    assert!(scenario::satisfied(&public, &witness, Relations::ALL));
    let mut weakened = Relations::ALL;
    weakened.conservation = false;
    assert!(scenario::satisfied(&public, &witness, weakened));
}

/// The relation set a real proof uses is the complete one. Nothing in the
/// fixture path may reach a weakened circuit.
#[test]
fn the_default_relation_set_is_complete() {
    assert_eq!(Relations::default(), Relations::ALL);
    let (_pool, public, witness) = scenario::valid_transfer();
    let circuit = shielded_pool_circuit::circuit::ShieldedTransactionCircuit::new(public, witness);
    assert_eq!(circuit.relations(), Relations::ALL);
}
