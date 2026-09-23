/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Is the key built from our reference string the key the setup would build?
//!
//! Not "does it verify something" -- that is a much weaker claim, and a key
//! with the input-consistency rows left out of `beta*A` still proves and
//! verifies for a while before it does not. The claim here is **equality**:
//! element for element against `ark-groth16`'s own generator, on the same
//! secrets.
//!
//! That comparison is possible because `generate_parameters_with_qap` draws
//! tau as its *first* call on the generator it is handed. So the same seeded
//! generator, asked once, yields the tau it is about to use -- and a reference
//! string built from that tau is the one that setup is secretly working from.
//!
//! Every secret here is this file's own. A key built this way proves anything;
//! the point is that it is the *same* key, and being the same is checkable
//! where being secret is not.

use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::ConstraintSynthesizer;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use shielded_pool_ceremony::verify::slice_from_known_secrets;
use shielded_pool_ceremony::{lagrange, phase2};
use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
use shielded_pool_circuit::scenario;

/// A circuit small enough that a full setup runs in seconds, with inputs --
/// which matters, because the input-consistency rows are the part of the map
/// most easily left out, and a circuit with no inputs cannot show they are
/// there.
#[derive(Clone)]
struct Tiny {
    witnesses: usize,
}

impl ConstraintSynthesizer<Fr> for Tiny {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        use ark_r1cs_std::alloc::AllocVar;
        use ark_r1cs_std::eq::EqGadget;
        use ark_r1cs_std::fields::fp::FpVar;

        // Three public inputs and a chain of multiplications, so both matrices
        // are non-trivial and several variables appear in several rows.
        let a = FpVar::new_input(cs.clone(), || Ok(Fr::from(3u64)))?;
        let b = FpVar::new_input(cs.clone(), || Ok(Fr::from(5u64)))?;
        let product = FpVar::new_input(cs.clone(), || Ok(Fr::from(15u64)))?;
        (&a * &b).enforce_equal(&product)?;

        let mut running = a;
        for i in 0..self.witnesses {
            let next = FpVar::new_witness(cs.clone(), || Ok(Fr::from(i as u64 + 2)))?;
            running = &running * &next;
        }
        let target = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64)))?;
        (&running * &target).enforce_equal(&running)?;
        Ok(())
    }
}

/// The tau a seeded setup is about to draw, drawn the same way, and a
/// generator still at the state the setup will find it in.
///
/// The second half of that is the whole trick and it is easy to get wrong: the
/// sample has to be taken from a *copy*, because the setup draws tau itself
/// from the generator it is handed. Handing over the used one gives it the
/// second value, and then two correct constructions disagree for a reason that
/// has nothing to do with either.
fn tau_for(domain_size: usize, seed: [u8; 32]) -> (Fr, ChaCha20Rng) {
    let mut peek = ChaCha20Rng::from_seed(seed);
    let domain = Radix2EvaluationDomain::<Fr>::new(domain_size).expect("a domain");
    let tau = domain.sample_element_outside_domain(&mut peek);
    (tau, ChaCha20Rng::from_seed(seed))
}

fn compare(circuit: impl ConstraintSynthesizer<Fr> + Clone, seed: [u8; 32]) {
    let (matrices, instance, _witness) =
        phase2::matrices(circuit.clone()).expect("the circuit's matrices");
    let domain_size = {
        let wanted = matrices.num_constraints + instance;
        Radix2EvaluationDomain::<Fr>::new(wanted).expect("a domain").size()
    };

    // The tau the setup will use, and the generator left where the setup will
    // find it.
    let (tau, mut rng) = tau_for(matrices.num_constraints + instance, seed);

    // Our side: a reference string over that tau, then the initial key.
    let mut secrets = ChaCha20Rng::from_seed([0xa7u8; 32]);
    let alpha = Fr::rand(&mut secrets);
    let beta = Fr::rand(&mut secrets);
    let srs = lagrange::transform(&slice_from_known_secrets(domain_size, tau, alpha, beta))
        .expect("the Lagrange basis");
    let ours = phase2::initial(&srs, circuit.clone()).expect("the initial key");

    // Theirs: the same secrets, gamma and delta one, and the same tau because
    // the generator is at the state we read it from.
    let one = Fr::from(1u64);
    let theirs = Groth16::<Bls12_381>::generate_parameters_with_qap(
        circuit,
        alpha,
        beta,
        one,
        one,
        G1Projective::from(<ark_bls12_381::G1Affine as ark_ec::AffineRepr>::generator()),
        G2Projective::from(<ark_bls12_381::G2Affine as ark_ec::AffineRepr>::generator()),
        &mut rng,
    )
    .expect("arkworks' key");

    assert_eq!(
        phase2::dimensions(&ours),
        phase2::dimensions(&theirs),
        "the two keys are not even the same shape"
    );

    assert_eq!(ours.vk.alpha_g1, theirs.vk.alpha_g1, "alpha_g1");
    assert_eq!(ours.vk.beta_g2, theirs.vk.beta_g2, "beta_g2");
    assert_eq!(ours.vk.gamma_g2, theirs.vk.gamma_g2, "gamma_g2");
    assert_eq!(ours.vk.delta_g2, theirs.vk.delta_g2, "delta_g2");
    assert_eq!(ours.beta_g1, theirs.beta_g1, "beta_g1");
    assert_eq!(ours.delta_g1, theirs.delta_g1, "delta_g1");

    for (i, (a, b)) in ours.vk.gamma_abc_g1.iter().zip(&theirs.vk.gamma_abc_g1).enumerate() {
        assert_eq!(a, b, "IC point {i} -- the input-consistency rows are the usual cause");
    }
    for (i, (a, b)) in ours.a_query.iter().zip(&theirs.a_query).enumerate() {
        assert_eq!(a, b, "a_query[{i}]");
    }
    for (i, (a, b)) in ours.b_g1_query.iter().zip(&theirs.b_g1_query).enumerate() {
        assert_eq!(a, b, "b_g1_query[{i}]");
    }
    for (i, (a, b)) in ours.b_g2_query.iter().zip(&theirs.b_g2_query).enumerate() {
        assert_eq!(a, b, "b_g2_query[{i}]");
    }
    for (i, (a, b)) in ours.l_query.iter().zip(&theirs.l_query).enumerate() {
        assert_eq!(a, b, "l_query[{i}]");
    }
    for (i, (a, b)) in ours.h_query.iter().zip(&theirs.h_query).enumerate() {
        assert_eq!(a, b, "h_query[{i}]");
    }
}

#[test]
fn the_initial_key_is_the_one_the_setup_would_build() {
    compare(Tiny { witnesses: 6 }, *b"phase2-initial-key-equality-0001");
}

/// A second shape, because one circuit can agree by accident -- a different
/// number of witnesses moves the domain and every index in it.
#[test]
fn and_for_a_circuit_of_another_shape() {
    compare(Tiny { witnesses: 21 }, *b"phase2-initial-key-equality-0002");
}

/// Deterministic: the ceremony's starting point has no secrets, so two people
/// running it must get identical bytes or there is nothing to agree on.
#[test]
fn the_starting_point_is_the_same_every_time() {
    let circuit = Tiny { witnesses: 4 };
    let (matrices, instance, _) = phase2::matrices(circuit.clone()).expect("matrices");
    let (tau, _) = tau_for(matrices.num_constraints + instance, [9u8; 32]);
    let domain =
        Radix2EvaluationDomain::<Fr>::new(matrices.num_constraints + instance).expect("d").size();
    let srs = lagrange::transform(&slice_from_known_secrets(
        domain,
        tau,
        Fr::from(7u64),
        Fr::from(11u64),
    ))
    .expect("srs");

    let first = phase2::initial(&srs, circuit.clone()).expect("first");
    let second = phase2::initial(&srs, circuit).expect("second");
    assert_eq!(first.a_query, second.a_query);
    assert_eq!(first.l_query, second.l_query);
    assert_eq!(first.vk.gamma_abc_g1, second.vk.gamma_abc_g1);
}

/// And on the circuit that matters, against its real reference string.
///
/// Slow -- a full setup over 18,107 constraints, twice -- so it is behind
/// `--ignored` and run when the construction changes.
#[test]
#[ignore = "a full setup over the real circuit, twice; run when phase2.rs changes"]
fn the_shielded_circuit_too() {
    let (_pool, public, witness) = scenario::valid_withdrawal().expect("a withdrawal");
    compare(ShieldedTransactionCircuit::new(public, witness), *b"phase2-the-real-circuit-00000001");
}
