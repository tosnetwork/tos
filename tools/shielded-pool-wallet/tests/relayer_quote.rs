// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
use fips204::ml_dsa_44::KG;
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use shielded_pool_wallet::relayer_quote::{self, QuoteError, MAX_TERMS_BYTES};

const TERMS: &[u8] =
    br#"{"amount":7,"note_index":4,"release":"test-only","slot":2,"valid_until":200}"#;

#[test]
fn real_worker_signature_authenticates_exact_terms() -> Result<(), Box<dyn std::error::Error>> {
    // Public disposable test keys, never used by a deployment.
    let (public, private) = KG::keygen_from_seed(&[42; 32]);
    let signature = relayer_quote::sign_terms(&private, TERMS)?;
    assert!(public.verify(TERMS, &signature, b"TOS-BR1-QUOTE-v1"));
    relayer_quote::verify_terms(&public.into_bytes(), TERMS, &signature)?;
    Ok(())
}

#[test]
fn quote_cannot_be_repurposed_as_an_acceptance() -> Result<(), Box<dyn std::error::Error>> {
    let (public, private) = KG::keygen_from_seed(&[42; 32]);
    let signature = relayer_quote::sign_terms(&private, TERMS)?;
    assert!(!public.verify(TERMS, &signature, b"TOS-BONDED-RELAYER-v1"));
    assert!(!public.verify(TERMS, &signature, b"TOS-SHIELDED-POOL-MLDSA44-v1"));
    let wrong_purpose = private.try_sign(TERMS, b"TOS-BONDED-RELAYER-v1")?;
    assert_eq!(
        relayer_quote::verify_terms(&public.into_bytes(), TERMS, &wrong_purpose),
        Err(QuoteError::Signature)
    );
    Ok(())
}

#[test]
fn wrong_worker_and_modified_signature_refuse() -> Result<(), Box<dyn std::error::Error>> {
    let (public, private) = KG::keygen_from_seed(&[42; 32]);
    let (foreign, _) = KG::keygen_from_seed(&[43; 32]);
    let mut signature = relayer_quote::sign_terms(&private, TERMS)?;
    assert_eq!(
        relayer_quote::verify_terms(&foreign.into_bytes(), TERMS, &signature),
        Err(QuoteError::Signature)
    );
    signature[0] ^= 1;
    assert_eq!(
        relayer_quote::verify_terms(&public.into_bytes(), TERMS, &signature),
        Err(QuoteError::Signature)
    );
    Ok(())
}

#[test]
fn every_byte_and_trailing_data_are_authenticated() -> Result<(), Box<dyn std::error::Error>> {
    let (public, private) = KG::keygen_from_seed(&[42; 32]);
    let signature = relayer_quote::sign_terms(&private, TERMS)?;
    let public = public.into_bytes();
    for index in 0..TERMS.len() {
        let mut mutated = TERMS.to_vec();
        mutated[index] ^= 1;
        assert_eq!(
            relayer_quote::verify_terms(&public, &mutated, &signature),
            Err(QuoteError::Signature),
            "byte {index} is not authenticated"
        );
    }
    let mut trailing = TERMS.to_vec();
    trailing.push(b' ');
    assert_eq!(
        relayer_quote::verify_terms(&public, &trailing, &signature),
        Err(QuoteError::Signature)
    );
    Ok(())
}

#[test]
fn byte_bound_is_checked_on_both_sides() -> Result<(), Box<dyn std::error::Error>> {
    let (public, private) = KG::keygen_from_seed(&[42; 32]);
    let maximum = vec![b'x'; MAX_TERMS_BYTES];
    let signature = relayer_quote::sign_terms(&private, &maximum)?;
    let public = public.into_bytes();
    relayer_quote::verify_terms(&public, &maximum, &signature)?;
    for invalid in [vec![], vec![b'x'; MAX_TERMS_BYTES + 1]] {
        assert_eq!(relayer_quote::sign_terms(&private, &invalid), Err(QuoteError::TermsSize));
        assert_eq!(
            relayer_quote::verify_terms(&public, &invalid, &signature),
            Err(QuoteError::TermsSize)
        );
    }
    Ok(())
}
