/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Does the gate that will judge the ceremony's output actually judge it?
//!
//! The gate deploys a pool carrying a candidate verifying key, proves a real
//! transfer under the matching proving key and requires the contract to
//! accept. Three things have to be true of it before it is worth pointing at
//! a ceremony:
//!
//! 1. it accepts the key this repository already ships, or it is broken;
//! 2. it accepts a key it has never seen -- one from a *different* setup --
//!    or it is a test of the fixture rather than a gate for a ceremony;
//! 3. it refuses a proof made under a different key from the one deployed, or
//!    it is checking that some proof verifies and not that this one does.
//!
//! The third is the one that matters and the one an acceptance check is most
//! likely to be missing, because a gate that only ever sees a matching pair
//! passes whether or not it compares them.
//!
//! Every key here is a single-party setup from a seed in this file, so the
//! toxic waste is known and none of them may ever hold money. The ceremony
//! replaces where the keys come from and nothing else about this file.

use shielded_pool_circuit::circuit::ShieldedTransactionCircuit;
use shielded_pool_circuit::groth16;
use shielded_pool_circuit::scenario;
use shielded_pool_circuit_crosscheck::acceptance::{self, CANONICAL_VK_BYTES};
use shielded_pool_circuit_crosscheck::pool::development_vk_bytes;

/// A setup that is not the development one. Stands in for "what a ceremony
/// will hand us": a key pair this repository has never recorded.
const ANOTHER_SETUP: [u8; 32] = *b"a-key-this-repo-has-never-seen!!";

fn keys_from(seed: [u8; 32]) -> groth16::DevelopmentKeys {
    let (_pool, public, _witness) = scenario::valid_transfer().expect("a transfer");
    groth16::keys_from_seed(ShieldedTransactionCircuit::blank(public), seed).expect("setup")
}

fn development() -> groth16::DevelopmentKeys {
    let (_pool, public, _witness) = scenario::valid_transfer().expect("a transfer");
    groth16::development_keys(ShieldedTransactionCircuit::blank(public)).expect("setup")
}

#[test]
fn the_gate_accepts_the_key_this_repository_ships() {
    let keys = development();
    let vk = development_vk_bytes().expect("the fixture verifying key");
    let outcome = acceptance::run(&keys, &vk).expect("the development key must pass its own gate");

    assert_eq!(outcome.ic_count, 19, "eighteen public inputs need nineteen IC points");
    assert_eq!(outcome.vk_bytes, CANONICAL_VK_BYTES);
    assert_eq!(outcome.vk_bytes, 1248, "section 10.1's key is 1,248 bytes");
    assert_eq!(outcome.exit, 0, "the transfer was refused with exit {}", outcome.exit);
    eprintln!(
        "development key {} -> pool {} -> transact exit {} at {} gas",
        &outcome.vk_sha256[..16],
        outcome.address,
        outcome.exit,
        outcome.gas
    );

    // And it is the key the fixture records, so the gate ran against the
    // deployment rather than against something it made up.
    assert_eq!(
        outcome.vk_sha256, "5b760517f330e3914d76fc5baf18cc9e46f6b03d8467eeafb4de10d9681c9251",
        "the development key's digest moved"
    );
}

/// The case the ceremony is actually for.
#[test]
fn the_gate_accepts_a_key_it_has_never_seen() {
    let keys = keys_from(ANOTHER_SETUP);
    let vk = groth16::canonical_verifying_key(&keys.verifying).expect("encode");
    assert_ne!(
        vk.bytes,
        development_vk_bytes().expect("the fixture key"),
        "this setup produced the development key, so it proves nothing about a new one"
    );

    let outcome = acceptance::run(&keys, &vk.bytes).expect("a fresh key pair must pass the gate");
    assert_eq!(outcome.exit, 0, "a pool carrying a fresh key refused a proof made under it");
    assert_eq!(outcome.vk_bytes, 1248);
    eprintln!(
        "a key from another setup {} -> pool {} -> transact exit {} at {} gas",
        &outcome.vk_sha256[..16],
        outcome.address,
        outcome.exit,
        outcome.gas
    );
}

/// The discriminator. Without this the two tests above pass for a gate that
/// never compares the proof to the deployed key at all.
#[test]
fn the_gate_refuses_a_proof_made_under_a_different_key() {
    let mine = keys_from(ANOTHER_SETUP);
    let theirs = development();
    let theirs_vk = groth16::canonical_verifying_key(&theirs.verifying).expect("encode");

    // A perfectly valid proof, of a true statement, made under a key the pool
    // was not deployed with. Nothing about the message is malformed.
    let outcome = acceptance::run(&mine, &theirs_vk.bytes).expect("the gate should run");
    assert_ne!(
        outcome.exit, 0,
        "a pool deployed with one verifying key accepted a proof made under another, so the \
         gate -- and the contract -- are not binding the proof to the key"
    );
    eprintln!("a proof under the wrong key: exit {} at {} gas", outcome.exit, outcome.gas);
}

/// A key of the right length is not a key of the right shape.
#[test]
fn the_gate_refuses_a_key_of_the_wrong_size() {
    let keys = development();
    let mut vk = development_vk_bytes().expect("the fixture key");
    vk.pop();
    let error = acceptance::run(&keys, &vk).expect_err("a short key must be refused");
    assert!(format!("{error}").contains("not 1248"), "refused for the wrong reason: {error}");
}

/// Two different keys are two different pools. Worth asserting rather than
/// remembering, because it is the reason an address cannot be published
/// before the ceremony ends.
#[test]
fn a_different_verifying_key_is_a_different_deployment_address() {
    let development = development();
    let development_vk = development_vk_bytes().expect("the fixture key");
    let other = keys_from(ANOTHER_SETUP);
    let other_vk = groth16::canonical_verifying_key(&other.verifying).expect("encode");

    let first = acceptance::run(&development, &development_vk).expect("the development gate");
    let second = acceptance::run(&other, &other_vk.bytes).expect("the other gate");
    assert_ne!(
        first.address, second.address,
        "two pools carrying different verifying keys landed on the same address, which would \
         mean the key is not part of the genesis state"
    );
    eprintln!("{}\n{}", first.address, second.address);
}
