/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The eight derived public inputs, computed by the prover's library and by
//! the VM, compared value for value.
//!
//! These are the inputs a prover cannot read off the wire: the contract
//! recomputes them from the bytes that arrived. If the prover's version
//! disagrees, every proof it makes is a proof of a transaction the contract
//! will refuse -- and the symptom is "the proof does not verify", which points
//! nowhere. So the agreement is established here, on its own, first.

use ark_ff::{BigInteger, PrimeField};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::wire;
use shielded_pool_circuit_crosscheck::wire::WireProbe;

/// A field element as the decimal string the VM prints.
fn dec(value: Fr) -> String {
    let bytes = value.into_bigint().to_bytes_be();
    let mut digits = vec![0u8];
    for byte in bytes {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let next = u32::from(*digit) * 256 + carry;
            *digit = (next % 10) as u8;
            carry = next / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

fn payload(seed: u8) -> Vec<u8> {
    (0..wire::OUTPUT_DATA_BYTES as u32).map(|i| (i as u8) ^ seed).collect()
}

fn key_bytes(seed: u8) -> Vec<u8> {
    (0..wire::MLDSA44_PUBLIC_KEY_BYTES as u32).map(|i| (i as u8).wrapping_add(seed)).collect()
}

#[test]
fn the_payload_hash_agrees_with_the_vm() {
    let probe = WireProbe::deploy().expect("deploy the wire probe");
    for seed in [0u8, 1, 0x5a, 0xff] {
        let bytes = payload(seed);
        let vm = probe.output_data_hash(&bytes).expect("the vm");
        assert_eq!(dec(wire::output_data_hash(&bytes)), vm, "payload {seed:#04x}");
    }

    // One bit, so the comparison is known to be able to fail.
    let mut flipped = payload(0);
    flipped[700] ^= 1;
    assert_ne!(
        dec(wire::output_data_hash(&flipped)),
        probe.output_data_hash(&payload(0)).expect("the vm"),
        "flipping a payload bit changed nothing"
    );
}

#[test]
fn the_public_key_hash_agrees_with_the_vm() {
    let probe = WireProbe::deploy().expect("deploy the wire probe");
    for seed in [0u8, 7, 0x80, 0xfe] {
        let bytes = key_bytes(seed);
        let vm = probe.pq_auth_key_hash(&bytes).expect("the vm");
        assert_eq!(dec(wire::pq_auth_key_hash(&bytes)), vm, "key {seed:#04x}");
    }

    // The two derivations share a construction and differ only in their
    // domain tag, so a tag mix-up would be invisible without this.
    let bytes = key_bytes(0);
    assert_ne!(
        dec(wire::output_data_hash(&bytes)),
        dec(wire::pq_auth_key_hash(&bytes)),
        "the two byte-chain hashes are not separated by their domain"
    );
}

#[test]
fn the_recipient_hash_agrees_with_the_vm() {
    let probe = WireProbe::deploy().expect("deploy the wire probe");
    for seed in [1u8, 0x42, 0xab] {
        let account = [seed; 32];
        let vm = probe.public_recipient_hash(&account).expect("the vm");
        assert_eq!(dec(wire::public_recipient_hash(&account)), vm, "account {seed:#04x}");
    }
}

/// The execution domain is a deployment fact: it binds this chain's global id
/// and this particular account. The prover has to take both from the pool it
/// is proving against, which is what this checks it can do.
#[test]
fn the_execution_domain_agrees_with_the_vm_for_the_account_that_computed_it() {
    let probe = WireProbe::deploy().expect("deploy the wire probe");
    let (global_id, account) = probe.domain_inputs().expect("the domain inputs");
    let vm = probe.execution_domain().expect("the vm");
    assert_eq!(dec(wire::execution_domain(global_id, &account)), vm);

    // A different account is a different domain, which is the property the
    // whole binding exists for.
    let mut elsewhere = account;
    elsewhere[0] ^= 1;
    assert_ne!(
        dec(wire::execution_domain(global_id, &elsewhere)),
        vm,
        "another account shares this pool's execution domain"
    );
    assert_ne!(
        dec(wire::execution_domain(global_id + 1, &account)),
        vm,
        "another chain shares this pool's execution domain"
    );
}

#[test]
fn the_recovery_template_hash_agrees_with_the_vm() {
    let probe = WireProbe::deploy().expect("deploy the wire probe");
    let owner = Fr::from(0x5eedu64);
    let data_hash = wire::output_data_hash(&payload(9));
    let vm = probe.recovery_template_hash(&dec(owner), &dec(data_hash)).expect("the vm");
    assert_eq!(dec(wire::recovery_template_hash(owner, data_hash)), vm);
}
