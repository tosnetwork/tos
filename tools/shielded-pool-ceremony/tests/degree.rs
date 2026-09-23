/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The one number the whole ceremony is built on.
//!
//! Every byte offset in the phase-1 slice is a function of the circuit's QAP
//! domain. If the circuit grows past 32,768 the domain becomes 2^16, the
//! slice doubles, and the ranges move -- so a slice fetched before the growth
//! is not merely too small, it is the wrong bytes, and nothing downstream
//! would say so. A fetched slice carries the exponent it was taken at and is
//! refused against a circuit that has outgrown it, which is what makes this a
//! gate rather than a note.

use shielded_pool_ceremony::{layout, shape, Shape};
use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
use shielded_pool_circuit::scenario;

/// The exponent the deployment's phase-1 slice is taken at.
///
/// Pinned on purpose: this is the number a fetched artifact is checked
/// against, so it has to be a declaration the circuit is measured against and
/// not a value derived from whatever the circuit happens to be today.
const SLICE_EXPONENT: u32 = 15;

fn measured() -> Shape {
    let (_pool, public, witness) = scenario::valid_withdrawal().expect("a withdrawal");
    shape(ShieldedTransactionCircuit::new(public, witness)).expect("the circuit's shape")
}

#[test]
fn the_circuit_still_fits_the_slice_the_ceremony_is_planned_for() {
    let shape = measured();
    eprintln!(
        "constraints {}, instance {}, witness {} -> QAP degree {} -> 2^{}",
        shape.constraints,
        shape.instance_variables,
        shape.witness_variables,
        shape.qap_degree(),
        shape.domain_exponent(),
    );
    assert_eq!(
        shape.domain_exponent(),
        SLICE_EXPONENT,
        "the circuit's QAP domain is now 2^{} and the ceremony is planned around 2^{SLICE_EXPONENT}. \
         This is not a tuning constant: every byte range in `layout` is derived from the exponent, \
         so a slice already fetched is the wrong bytes rather than too few of them.",
        shape.domain_exponent()
    );
    assert!(
        shape.qap_degree() <= 1 << SLICE_EXPONENT,
        "a QAP degree of {} does not fit a domain of {}",
        shape.qap_degree(),
        1usize << SLICE_EXPONENT
    );
}

/// The headroom, stated rather than left to be discovered. A circuit change
/// that eats it is a change that moves the ceremony.
#[test]
fn how_much_the_circuit_can_grow_before_the_ceremony_changes() {
    let shape = measured();
    let room = (1usize << SLICE_EXPONENT) - shape.qap_degree();
    eprintln!(
        "the circuit uses {} of a {} domain; {room} to spare before the slice doubles",
        shape.qap_degree(),
        1usize << SLICE_EXPONENT
    );
    assert!(room > 0, "the circuit exactly fills its domain, so any addition moves the ceremony");
}

/// A transfer and a withdrawal are the same circuit with different witnesses,
/// so they had better generate the same constraint system. If they did not,
/// "the circuit's degree" would not be a well-defined thing to build a
/// ceremony on.
#[test]
fn both_transaction_kinds_have_the_same_shape() {
    let (_pool, public, witness) = scenario::valid_transfer().expect("a transfer");
    let transfer =
        shape(ShieldedTransactionCircuit::new(public, witness)).expect("the transfer's shape");
    assert_eq!(
        transfer,
        measured(),
        "a transfer and a withdrawal synthesise different constraint systems, so one proving \
         key cannot serve both"
    );
}

#[test]
fn the_slice_the_exponent_implies_is_the_one_the_layout_produces() {
    // Both ceremonies, because the slice's shape depends on the circuit and
    // not on which one a deployment inherits.
    for transcript in layout::ALL {
        let ranges = layout::slice_ranges(transcript, SLICE_EXPONENT).expect("ranges");
        let degree = 1u64 << SLICE_EXPONENT;
        assert_eq!(ranges[0].points, 2 * degree - 1, "tau_g1 must reach degree 2n-2");
        for range in &ranges[1..4] {
            assert_eq!(range.points, degree, "{} must hold n points", range.name);
        }
        assert_eq!(ranges[4].points, 1);
    }
}

/// The domain is the one the setup uses, not the one a formula says.
///
/// `qap_degree` used to be `max(constraints, variables)`, which is a plausible
/// reading of what a QAP needs and is not what `ark-groth16` does: its
/// `instance_map_with_evaluation` gives every instance variable a Lagrange
/// coefficient of its own at index `num_constraints + i`, so the domain is
/// `constraints + instance_variables`. Both formulas round to 2^15 here, so
/// nothing downstream was wrong -- but the headroom was, and headroom is the
/// number somebody adding constraints reads.
///
/// This does not re-read that source. It builds a real key and asks it: the
/// `h` query is one short of the domain, so the key states the domain it was
/// built over.
#[test]
fn the_domain_is_the_one_the_setup_uses() {
    use ark_bls12_381::{Bls12_381, G1Projective, G2Projective};
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use shielded_pool_circuit::field::Fr;

    let (_pool, public, witness) = scenario::valid_withdrawal().expect("a withdrawal");
    let circuit = ShieldedTransactionCircuit::new(public, witness);
    let mut rng = ChaCha20Rng::from_seed(*b"the-domain-a-real-key-was-built!");
    let key = Groth16::<Bls12_381>::generate_parameters_with_qap(
        circuit,
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        G1Projective::rand(&mut rng),
        G2Projective::rand(&mut rng),
        &mut rng,
    )
    .expect("a key");

    let measured = measured();
    let domain_the_key_used = key.h_query.len() + 1;
    assert_eq!(
        domain_the_key_used,
        1usize << measured.domain_exponent(),
        "the setup built over a domain of {domain_the_key_used} and this crate plans the slice \
         for 2^{}",
        measured.domain_exponent()
    );
    assert!(
        measured.qap_degree() <= domain_the_key_used,
        "a QAP degree of {} does not fit the domain the setup chose",
        measured.qap_degree()
    );

    // And the key's other dimensions, so the shapes a phase-2 construction has
    // to produce are written down somewhere that can go red.
    assert_eq!(key.vk.gamma_abc_g1.len(), measured.instance_variables, "IC is one per input");
    assert_eq!(key.l_query.len(), measured.witness_variables, "L is one per witness");
    assert_eq!(
        key.a_query.len(),
        measured.instance_variables + measured.witness_variables,
        "A is one per variable"
    );
    assert_eq!(key.b_g1_query.len(), key.a_query.len());
    assert_eq!(key.b_g2_query.len(), key.a_query.len());
    eprintln!(
        "a real key: domain {domain_the_key_used}, h {}, a {}, l {}, ic {}",
        key.h_query.len(),
        key.a_query.len(),
        key.l_query.len(),
        key.vk.gamma_abc_g1.len()
    );
}

/// The formula itself, on a shape where the two candidates disagree.
///
/// The test above pins the *exponent*, and for this circuit both the old
/// formula and the right one round to 2^15 -- so it would not have caught the
/// error, and saying otherwise would claim coverage that is not there. What
/// catches it is a shape chosen so the two answers differ: `max(9, 8) = 9`
/// rounds to a domain of 16, `9 + 8 = 17` rounds to 32.
#[test]
fn the_degree_is_constraints_plus_inputs_not_the_larger_of_the_two() {
    let shape = Shape { constraints: 9, instance_variables: 8, witness_variables: 0 };
    assert_eq!(shape.qap_degree(), 17, "the QAP reaches past the constraints by one per input");
    assert_eq!(shape.domain_exponent(), 5, "17 needs a domain of 32, not 16");

    // And the shape that let the old formula look right: with no inputs the
    // two agree, which is why a test shaped like this circuit could not tell
    // them apart.
    let inputless = Shape { constraints: 9, instance_variables: 0, witness_variables: 40 };
    assert_eq!(inputless.qap_degree(), 9);
}
