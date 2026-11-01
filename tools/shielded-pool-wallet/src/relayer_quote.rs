// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Worker signatures on the exact BR1 quote terms, with a separate purpose.
//!
//! This primitive authenticates bytes, not chain eligibility or quote semantics.
//! The caller must check canonical encoding, the full release, descriptor, fee,
//! expiry and the worker key obtained from authenticated Bond state. A quote is
//! not an acceptance and must never use the Bond acceptance signature context.
//! Keys are supplied by the caller's production custody boundary; this module
//! does not load a seed, use a test signer, or make a network request.

use fips204::ml_dsa_44::{PrivateKey, PublicKey};
use fips204::traits::{SerDes as _, Signer as _, Verifier as _};

use crate::keys::{MLDSA_PUBLIC_KEY_BYTES, MLDSA_SIGNATURE_BYTES};

pub const CONTEXT: &[u8] = b"TOS-BR1-QUOTE-v1";
pub const MAX_TERMS_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuoteError {
    TermsSize,
    PublicKey,
    Signature,
    Signing,
}

impl std::fmt::Display for QuoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BR1 quote authentication failed: {self:?}")
    }
}
impl std::error::Error for QuoteError {}

fn bound(terms: &[u8]) -> Result<(), QuoteError> {
    if terms.is_empty() || terms.len() > MAX_TERMS_BYTES {
        return Err(QuoteError::TermsSize);
    }
    Ok(())
}

/// Sign exact, already-validated canonical terms with the immutable worker key.
pub fn sign_terms(
    worker: &PrivateKey,
    terms: &[u8],
) -> Result<[u8; MLDSA_SIGNATURE_BYTES], QuoteError> {
    bound(terms)?;
    worker.try_sign(terms, CONTEXT).map_err(|_| QuoteError::Signing)
}

/// Verify before accepting the descriptor or building the user's transaction.
pub fn verify_terms(
    worker: &[u8; MLDSA_PUBLIC_KEY_BYTES],
    terms: &[u8],
    signature: &[u8; MLDSA_SIGNATURE_BYTES],
) -> Result<(), QuoteError> {
    bound(terms)?;
    let key = PublicKey::try_from_bytes(*worker).map_err(|_| QuoteError::PublicKey)?;
    if !key.verify(terms, signature, CONTEXT) {
        return Err(QuoteError::Signature);
    }
    Ok(())
}
