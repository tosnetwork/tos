/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The happy paths of section 11, and the shape of the section 10 vector.

mod scenario;

use shielded_pool_circuit::circuit::Relations;
use shielded_pool_circuit::public_inputs::{ORDER, PUBLIC_INPUT_COUNT};

#[test]
fn a_transfer_satisfies_every_relation() {
    let (_pool, public, witness) = scenario::valid_transfer();
    assert!(
        scenario::satisfied(&public, &witness, Relations::ALL),
        "a well-formed transfer does not satisfy the circuit"
    );
    println!("transfer: {} constraints", scenario::constraint_count(&public, &witness));
}

#[test]
fn a_withdrawal_satisfies_every_relation() {
    let (_pool, public, witness) = scenario::valid_withdrawal();
    assert!(
        scenario::satisfied(&public, &witness, Relations::ALL),
        "a well-formed withdrawal does not satisfy the circuit"
    );
    println!("withdrawal: {} constraints", scenario::constraint_count(&public, &witness));
}

#[test]
fn the_public_input_vector_is_eighteen_elements_in_the_frozen_order() {
    let (_pool, public, _witness) = scenario::valid_withdrawal();
    let vector = public.to_vec();
    assert_eq!(vector.len(), PUBLIC_INPUT_COUNT);
    assert_eq!(ORDER.len(), PUBLIC_INPUT_COUNT);
    assert_eq!(ORDER[0], "anchor_root");
    assert_eq!(ORDER[17], "transaction_intent_digest");
    assert_eq!(vector[0], public.anchor_root);
    assert_eq!(vector[17], public.transaction_intent_digest);
    assert_eq!(vector[11], public.public_amount_out);
}

/// The public inputs are allocated in the section 10 order, which is what the
/// verifying key's `IC` order will be. Reading them back from the constraint
/// system is the only way to see that the allocation order is the frozen one
/// and not merely the struct's field order.
#[test]
fn the_constraint_system_allocates_the_public_inputs_in_the_frozen_order() {
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
    use shielded_pool_circuit::field::Fr;

    let (_pool, public, witness) = scenario::valid_withdrawal();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = ShieldedTransactionCircuit::new(public, witness);
    if let Err(error) = circuit.generate_constraints(cs.clone()) {
        panic!("synthesis failed: {error}");
    }
    assert_eq!(
        cs.num_instance_variables(),
        PUBLIC_INPUT_COUNT + 1,
        "the instance vector is not one plus the eighteen public inputs"
    );
    let assignment = match cs.borrow() {
        Some(borrowed) => borrowed.instance_assignment.clone(),
        None => panic!("the constraint system could not be borrowed"),
    };
    assert_eq!(assignment[0], Fr::from(1u64), "the leading one is missing");
    for (index, expected) in public.to_vec().iter().enumerate() {
        assert_eq!(
            assignment[index + 1],
            *expected,
            "public input {index} ({}) is not where section 10 puts it",
            ORDER[index]
        );
    }
}
