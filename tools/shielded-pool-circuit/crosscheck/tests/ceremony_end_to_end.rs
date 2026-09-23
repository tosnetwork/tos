/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The whole pipeline, once, on the real thing.
//!
//! Every other test covers one link. `the_real_slice` says the committed
//! eighteen megabytes are a powers-of-tau string. `phase2_initial` says our
//! starting key is the one `ark-groth16` would build. `phase2_contribution`
//! says a contribution does what it claims and a forged one does not.
//! `ceremony_acceptance` says the gate judges a key it has never seen. Each of
//! those is evidence about a link, and a chain of verified links can still be
//! bolted together wrongly.
//!
//! So this runs the chain end to end and asks the only question that matters:
//!
//! > phase-1 slice -> Lagrange basis -> starting key -> two contributions -> a
//! > beacon -> 1,248 bytes -> **a deployed pool that accepts a real private
//! > transfer**
//!
//! Nothing here is mocked, substituted or shortened. The slice is the one in
//! `artifacts/phase1`, the circuit is the 18,107-constraint shielded
//! transaction, the contributions go through `contribute`, the audit is the
//! one a later auditor would run, and the last step deploys a contract in the
//! VM and sends it a transaction.
//!
//! # This key must never hold money
//!
//! The scalars below come from labelled test seeds, so `delta` is recomputable
//! by anyone reading this file: the key it produces is a **development** key
//! exactly like the one in `groth16.rs`, and it is no more deployable. What
//! the test establishes is that the machinery produces a key the chain
//! accepts, not that this key is safe. A real ceremony changes where the
//! scalars come from and nothing else in this file.
//!
//! Slow -- a full setup over 18,107 constraints, the slice's pairing checks,
//! two contributions and a sandbox deployment -- so it is behind `--ignored`.

use shielded_pool_ceremony::contribution::{
    contribute, finalise, verify_beacon_step, verify_chain, Contribution, Transcript,
};
use shielded_pool_ceremony::entropy::{Entropy, OperatingSystem};
use shielded_pool_ceremony::{committed, phase2, Result as CeremonyResult};
use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
use shielded_pool_circuit::groth16::{self, DevelopmentKeys};
use shielded_pool_circuit::scenario;
use shielded_pool_circuit_crosscheck::acceptance::{self, CANONICAL_VK_BYTES};
use shielded_pool_circuit_crosscheck::pool::development_vk_bytes;

/// A repeatable source, for this test only.
///
/// The library offers no seeded entropy and must not: a ceremony run from a
/// seed has a `delta` anybody holding the seed recomputes. It lives here so a
/// failure is reproducible, and so the key below is unmistakably a
/// development key.
struct TestOnlySeeded(rand_chacha::ChaCha20Rng);

impl Entropy for TestOnlySeeded {
    fn fill(&mut self, out: &mut [u8]) -> CeremonyResult<()> {
        use rand::RngCore;
        self.0.fill_bytes(out);
        Ok(())
    }
}

fn seeded(label: &[u8; 32]) -> TestOnlySeeded {
    use rand::SeedableRng;
    TestOnlySeeded(rand_chacha::ChaCha20Rng::from_seed(*label))
}

/// A beacon output stands in for the published one. A real ceremony names its
/// beacon before it begins; nothing in code can check that, which is why the
/// documentation says it and this test cannot.
const BEACON: &[u8] = b"a stand-in beacon output for this test, thirty-two bytes at least";

#[test]
#[ignore = "the whole pipeline on the real slice and the real circuit; minutes, not seconds"]
fn a_ceremony_produces_a_key_the_chain_accepts() {
    // --- phase 1, as committed -------------------------------------------
    let directory = committed::artifacts_directory();
    let (bytes, record) = committed::load_slice(&directory).expect("a fetched slice");
    eprintln!("slice: the {} ceremony, {} bytes", record.transcript, bytes.len());
    eprintln!("inheriting: {}", record.custody);

    // The structural checks batch against weights the transcript's author
    // could not have known. Drawn, not written down, even here.
    let mut seed = [0u8; 32];
    OperatingSystem.fill(&mut seed).expect("the system generator");
    let srs = committed::reference_string(&bytes, &record, seed).expect("the reference string");

    // --- the starting key -------------------------------------------------
    //
    // `blank` because a setup reads the circuit's shape and never its witness,
    // and because that is the constructor the rest of this repository's setups
    // use. A key built over a different construction of the same circuit would
    // be a different key for no stated reason.
    let (_pool, public, _witness) = scenario::valid_transfer().expect("a transfer");
    let circuit = ShieldedTransactionCircuit::blank(public.clone());

    let initial = phase2::initial(&srs, circuit.clone()).expect("the starting key");
    let mut key = initial.clone();
    eprintln!(
        "starting key: {} IC points, L {}, H {}",
        key.vk.gamma_abc_g1.len(),
        key.l_query.len(),
        key.h_query.len()
    );

    // --- the ceremony -----------------------------------------------------
    let mut transcript = Transcript::begin(&key).expect("a transcript");
    let mut published: Vec<Contribution> = Vec::new();
    for label in [b"test-only-end-to-end-party-one!!", b"test-only-end-to-end-party-two!!"] {
        let contribution =
            contribute(&mut key, &transcript, &mut seeded(label)).expect("a contribution");
        transcript = transcript.extend(&contribution);
        published.push(contribution);
    }

    let before_the_beacon = key.clone();
    let ending = finalise(&mut key, &transcript, BEACON).expect("the beacon step");
    verify_beacon_step(
        before_the_beacon.delta_g1,
        before_the_beacon.vk.delta_g2,
        &transcript,
        BEACON,
        &ending,
    )
    .expect("the ending is not the one this beacon determines");
    published.push(ending);

    // --- the audit a later reader runs ------------------------------------
    //
    // Note what it is given: the starting key, which anyone rebuilds from the
    // committed slice, the published contributions, and the finished key.
    // Nothing else, and in particular none of the intermediate keys.
    verify_chain(&initial, &key, &published, &mut OperatingSystem)
        .expect("the ceremony's own chain did not audit");
    eprintln!(
        "{} contributions, {} bytes of published record, transcript {}",
        published.len(),
        published.len() * 672,
        hex_of(&transcript.extend(&published[published.len() - 1]).digest())
    );

    // The ceremony actually moved something. Without this the rest would pass
    // for a run in which every contribution was a no-op.
    assert_ne!(key.delta_g1, initial.delta_g1, "delta never moved");
    assert_ne!(key.l_query, initial.l_query, "the L query never moved");
    assert_eq!(key.a_query, initial.a_query, "the A query moved, and nothing but delta may");

    // --- 1,248 bytes, and a contract that accepts them --------------------
    let verifying = key.vk.clone();
    let encoded = groth16::canonical_verifying_key(&verifying).expect("the canonical encoding");
    assert_eq!(encoded.bytes.len(), CANONICAL_VK_BYTES);
    assert_eq!(encoded.ic_count, 19, "eighteen public inputs need nineteen IC points");
    assert_ne!(
        encoded.bytes,
        development_vk_bytes().expect("the fixture key"),
        "the ceremony produced the development key, which would mean it did nothing"
    );

    let keys = DevelopmentKeys { proving: key, verifying };
    let outcome = acceptance::run(&keys, &encoded.bytes).expect("the acceptance gate should run");
    assert_eq!(
        outcome.exit, 0,
        "a pool carrying the ceremony's key refused a transfer proved under it (exit {})",
        outcome.exit
    );
    eprintln!(
        "ceremony key {} -> pool {} -> transact exit {} at {} gas",
        &outcome.vk_sha256[..16],
        outcome.address,
        outcome.exit,
        outcome.gas
    );

    // --- and the starting key is not a substitute for it ------------------
    //
    // The sharp end. Everything above would also pass for a pipeline that
    // quietly handed back the key it started from, and that key's `delta` is
    // one -- known to everyone, forgeable by anyone. A pool deployed with the
    // ceremony's key must refuse a proof made under the starting key.
    let starting_pair = DevelopmentKeys { proving: initial.clone(), verifying: initial.vk.clone() };
    let refused =
        acceptance::run(&starting_pair, &encoded.bytes).expect("the gate should still run");
    assert_ne!(
        refused.exit, 0,
        "a pool carrying the ceremony's key accepted a proof made under the pre-ceremony key, \
         so the ceremony changed nothing the contract can tell apart"
    );
    eprintln!("a proof under the pre-ceremony key: exit {}", refused.exit);
}

fn hex_of(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()[..16].to_string()
}
