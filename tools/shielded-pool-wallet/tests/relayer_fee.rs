/* Copyright (C) 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only */
use shielded_pool_circuit::{field::Fr, notes, wire};
use shielded_pool_wallet::delivery::{self, Kind, Plaintext};
use shielded_pool_wallet::keys::PoolInstance;
use shielded_pool_wallet::relayer_fee::{preflight_fee_output, FeeError, FeeTerms};

fn instance() -> PoolInstance {
    PoolInstance::new(&[0x3b; 32], Fr::from(0x425231u64))
}

fn fixture(kind: Kind, slot: u8) -> (PoolInstance, FeeTerms, Plaintext) {
    let wallet = instance();
    let terms = FeeTerms {
        execution_domain: wallet.execution_domain(),
        slot,
        amount: 1234567,
        note_key_index: 7,
    };
    let p = Plaintext {
        slot,
        kind,
        amount: terms.amount,
        note_secret: Fr::from(99u64),
        owner_nf_key_hash: wallet.owner_nf_key_hash(7).unwrap(),
        note_key_index: 7,
        pq_auth_key_hash: wallet.pq_auth_key_hash(7).unwrap(),
    };
    (wallet, terms, p)
}

fn seal(wallet: &PoolInstance, p: &Plaintext) -> (Vec<u8>, Fr) {
    let encrypted = delivery::seal(
        &wallet.mlkem_encapsulation_key().unwrap(),
        wallet.execution_domain(),
        p,
    )
    .unwrap();
    let owner = notes::owner_commitment(p.owner_nf_key_hash, p.pq_auth_key_hash, p.note_secret);
    let body =
        notes::note_body_commitment(owner, Fr::from(p.amount), wire::output_data_hash(&encrypted));
    (encrypted, body)
}

#[test]
fn all_three_slots_can_hold_an_exact_private_commission() {
    for slot in 0..3 {
        let (wallet, terms, p) = fixture(Kind::Ordinary, slot);
        let (encrypted, body) = seal(&wallet, &p);
        let checked = preflight_fee_output(&wallet, &terms, &encrypted, body).unwrap();
        assert_eq!(checked.amount(), terms.amount);
        assert_eq!(checked.note_key_index(), terms.note_key_index);
        assert_eq!(checked.note_body(), body);
        assert_eq!(checked.output_data_hash(), wire::output_data_hash(&encrypted));
    }
}

#[test]
fn terms_cannot_move_to_another_pool() {
    let (wallet, mut terms, p) = fixture(Kind::Ordinary, 0);
    let (encrypted, body) = seal(&wallet, &p);
    terms.execution_domain = Fr::from(2u64);
    assert!(matches!(
        preflight_fee_output(&wallet, &terms, &encrypted, body),
        Err(FeeError::WrongDomain)
    ));
}

#[test]
fn fee_must_equal_the_quote_not_merely_be_positive() {
    let (wallet, mut terms, p) = fixture(Kind::Ordinary, 0);
    let (encrypted, body) = seal(&wallet, &p);
    terms.amount += 1;
    assert!(matches!(
        preflight_fee_output(&wallet, &terms, &encrypted, body),
        Err(FeeError::WrongAmount)
    ));
}

#[test]
fn descriptor_index_is_bound_to_the_quote() {
    let (wallet, mut terms, p) = fixture(Kind::Ordinary, 0);
    let (encrypted, body) = seal(&wallet, &p);
    terms.note_key_index += 1;
    assert!(matches!(
        preflight_fee_output(&wallet, &terms, &encrypted, body),
        Err(FeeError::WrongIndex)
    ));
}

#[test]
fn dummy_and_recovery_outputs_never_pay_commission() {
    for kind in [Kind::Dummy, Kind::Recovery] {
        let (wallet, terms, p) = fixture(kind, 0);
        let (encrypted, body) = seal(&wallet, &p);
        assert!(matches!(
            preflight_fee_output(&wallet, &terms, &encrypted, body),
            Err(FeeError::WrongKind)
        ));
    }
}

#[test]
fn decrypting_a_payload_does_not_prove_ownership() {
    let (wallet, terms, mut p) = fixture(Kind::Ordinary, 0);
    p.owner_nf_key_hash = Fr::from(123u64);
    let (encrypted, body) = seal(&wallet, &p);
    assert!(matches!(
        preflight_fee_output(&wallet, &terms, &encrypted, body),
        Err(FeeError::Payload(_))
    ));
}

#[test]
fn derived_pq_key_is_checked_even_when_nf_owner_is_correct() {
    let (wallet, terms, mut p) = fixture(Kind::Ordinary, 0);
    p.pq_auth_key_hash = Fr::from(123u64);
    let (encrypted, body) = seal(&wallet, &p);
    assert!(matches!(
        preflight_fee_output(&wallet, &terms, &encrypted, body),
        Err(FeeError::Payload(_))
    ));
}

#[test]
fn body_substitution_cannot_redirect_the_fee() {
    let (wallet, terms, p) = fixture(Kind::Ordinary, 0);
    let (encrypted, body) = seal(&wallet, &p);
    assert!(matches!(
        preflight_fee_output(&wallet, &terms, &encrypted, body + Fr::from(1u64)),
        Err(FeeError::Payload(_))
    ));
}

#[test]
fn ciphertext_length_and_integrity_are_enforced() {
    let (wallet, terms, p) = fixture(Kind::Ordinary, 0);
    let (mut encrypted, body) = seal(&wallet, &p);
    encrypted[1232] ^= 1;
    assert!(matches!(
        preflight_fee_output(&wallet, &terms, &encrypted, body),
        Err(FeeError::Payload(_))
    ));
    encrypted.pop();
    assert!(matches!(
        preflight_fee_output(&wallet, &terms, &encrypted, body),
        Err(FeeError::Payload(_))
    ));
}

#[test]
fn no_zero_oversized_or_fourth_slot_quote() {
    let (wallet, terms, p) = fixture(Kind::Ordinary, 0);
    let (encrypted, body) = seal(&wallet, &p);
    for bad in [
        FeeTerms { amount: 0, ..terms },
        FeeTerms { amount: 1u128 << 120, ..terms },
        FeeTerms { slot: 3, ..terms },
    ] {
        assert!(matches!(
            preflight_fee_output(&wallet, &bad, &encrypted, body),
            Err(FeeError::InvalidTerms)
        ));
    }
}
