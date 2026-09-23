/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 2, and gate 30: what the key hierarchy separates.
//!
//! The hierarchy exists to make two things true at once: a wallet stores only
//! a mnemonic, and the same mnemonic on two pools shares no key material. Both
//! are easy to claim and easy to get subtly wrong, so each is a test that
//! would fail if the derivation were flattened by one level.

use shielded_pool_circuit::field::Fr;
use shielded_pool_wallet::keys::PoolInstance;

const SEED: [u8; 32] = [0x11; 32];
const OTHER_SEED: [u8; 32] = [0x12; 32];

fn domain(tag: u64) -> Fr {
    Fr::from(0x5348_0000_0000_0000u64 + tag)
}

/// Gate 30. The same mnemonic and the same index, under two execution
/// domains, must derive different owner-nullifier keys, different ML-DSA
/// public keys and different ML-KEM encapsulation keys.
///
/// This is why the execution domain -- a deployment fact about one pool on one
/// chain -- reaches all the way into the wallet. Without it, a note on a
/// testnet pool and a note on the mainnet pool at the same index would share
/// their spending key.
#[test]
fn two_execution_domains_share_no_key_material() {
    let here = PoolInstance::new(&SEED, domain(1));
    let there = PoolInstance::new(&SEED, domain(2));

    for index in [0u64, 1, 7, 1_000_000] {
        assert_ne!(
            here.owner_nf_key(index).expect("a key"),
            there.owner_nf_key(index).expect("a key"),
            "index {index}: one owner-nullifier key on two domains"
        );
        assert_ne!(
            here.mldsa_public_key(index).expect("a key"),
            there.mldsa_public_key(index).expect("a key"),
            "index {index}: one ML-DSA key on two domains"
        );
        assert_ne!(
            here.pq_auth_key_hash(index).expect("a hash"),
            there.pq_auth_key_hash(index).expect("a hash"),
            "index {index}: one PQ key hash on two domains"
        );
    }
    assert_ne!(
        here.mlkem_encapsulation_key().expect("a key"),
        there.mlkem_encapsulation_key().expect("a key"),
        "one ML-KEM key on two domains"
    );

    // And a different mnemonic on the same domain, which is the other half of
    // the same property.
    let elsewhere = PoolInstance::new(&OTHER_SEED, domain(1));
    assert_ne!(
        here.owner_nf_key(0).expect("a key"),
        elsewhere.owner_nf_key(0).expect("a key"),
        "two mnemonics derive one owner-nullifier key"
    );
    assert_ne!(
        here.mlkem_encapsulation_key().expect("a key"),
        elsewhere.mlkem_encapsulation_key().expect("a key"),
        "two mnemonics derive one ML-KEM key"
    );
}

/// Section 2.1: one key per note, never reused across indices. A wallet that
/// reused one owner-nullifier key would link every note it ever received.
#[test]
fn every_index_derives_its_own_keys() {
    let instance = PoolInstance::new(&SEED, domain(1));
    let mut owners = Vec::new();
    let mut auths = Vec::new();
    for index in 0u64..16 {
        owners.push(instance.owner_nf_key(index).expect("a key"));
        auths.push(instance.pq_auth_key_hash(index).expect("a hash"));
    }
    for i in 0..owners.len() {
        for j in (i + 1)..owners.len() {
            assert_ne!(owners[i], owners[j], "indices {i} and {j} share an owner key");
            assert_ne!(auths[i], auths[j], "indices {i} and {j} share a PQ key");
        }
    }
}

/// The whole point of the hierarchy: nothing is stored. Two wallets built from
/// the same mnemonic are the same wallet, key for key, with no state passed
/// between them.
#[test]
fn a_wallet_rebuilt_from_the_mnemonic_is_the_same_wallet() {
    let first = PoolInstance::new(&SEED, domain(3));
    let second = PoolInstance::new(&SEED, domain(3));
    for index in [0u64, 5, 99] {
        assert_eq!(
            first.owner_nf_key(index).expect("a key"),
            second.owner_nf_key(index).expect("a key")
        );
        assert_eq!(
            first.mldsa_public_key(index).expect("a key"),
            second.mldsa_public_key(index).expect("a key")
        );
    }
    assert_eq!(
        first.mlkem_encapsulation_key().expect("a key"),
        second.mlkem_encapsulation_key().expect("a key")
    );
    assert_eq!(first.mlkem_seed(), second.mlkem_seed());
}

/// Section 2.2's frozen sizes, which the wire format depends on and which a
/// change of library version could move without anything else noticing.
#[test]
fn the_frozen_sizes_are_the_frozen_sizes() {
    use shielded_pool_wallet::keys::{
        MLDSA_PUBLIC_KEY_BYTES, MLDSA_SIGNATURE_BYTES, MLKEM_CIPHERTEXT_BYTES,
        MLKEM_ENCAPSULATION_KEY_BYTES,
    };
    let instance = PoolInstance::new(&SEED, domain(1));
    assert_eq!(instance.mlkem_encapsulation_key().expect("a key").len(), 1184);
    assert_eq!(MLKEM_ENCAPSULATION_KEY_BYTES, 1184);
    assert_eq!(MLKEM_CIPHERTEXT_BYTES, 1088);
    assert_eq!(instance.mldsa_public_key(0).expect("a key").len(), 1312);
    assert_eq!(MLDSA_PUBLIC_KEY_BYTES, 1312);
    assert_eq!(
        instance.sign_intent(0, Fr::from(7u64)).expect("a signature").len(),
        MLDSA_SIGNATURE_BYTES
    );
    assert_eq!(MLDSA_SIGNATURE_BYTES, 2420);

    // And the one the descriptor depends on.
    assert_eq!(
        shielded_pool_wallet::descriptor::Descriptor::issue(&instance, 0)
            .expect("a descriptor")
            .to_bytes()
            .len(),
        shielded_pool_wallet::descriptor::DESCRIPTOR_BYTES
    );
}

/// A descriptor round trips, and refuses to come back from bytes that are not
/// one. It names a domain, and paying it under another is refused rather than
/// producing a note nobody can spend.
#[test]
fn a_descriptor_round_trips_and_names_its_domain() {
    let instance = PoolInstance::new(&SEED, domain(4));
    let descriptor =
        shielded_pool_wallet::descriptor::Descriptor::issue(&instance, 11).expect("a descriptor");
    let bytes = descriptor.to_bytes();
    let back =
        shielded_pool_wallet::descriptor::Descriptor::from_bytes(&bytes).expect("a descriptor");
    assert_eq!(back.note_key_index, 11);
    assert_eq!(back.execution_domain, domain(4));
    assert_eq!(back.owner_nf_key_hash, descriptor.owner_nf_key_hash);
    assert_eq!(back.pq_auth_public_key, descriptor.pq_auth_public_key);
    assert_eq!(back.mlkem_encapsulation_key, descriptor.mlkem_encapsulation_key);
    assert_eq!(back.to_bytes(), bytes);

    assert!(back.require_domain(domain(4)).is_ok());
    assert!(back.require_domain(domain(5)).is_err(), "a descriptor was accepted for another pool");

    let mut wrong_magic = bytes.clone();
    wrong_magic[0] ^= 1;
    assert!(shielded_pool_wallet::descriptor::Descriptor::from_bytes(&wrong_magic).is_err());
    let mut wrong_version = bytes.clone();
    wrong_version[4] = 2;
    assert!(shielded_pool_wallet::descriptor::Descriptor::from_bytes(&wrong_version).is_err());
    assert!(shielded_pool_wallet::descriptor::Descriptor::from_bytes(&bytes[..bytes.len() - 1])
        .is_err());
}
