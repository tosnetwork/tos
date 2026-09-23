/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The scalar field of BLS12-381 and its one canonical encoding.
//!
//! Profile section 1.1: "Field elements on the wire are exactly 32-byte
//! big-endian unsigned integers < r. No implicit reduction is accepted for
//! user-supplied field elements." Every conversion in this module therefore
//! rejects rather than reduces.

use ark_ff::{BigInteger, PrimeField};

use crate::error::{Error, Result};

/// The circuit field: BLS12-381 `Fr`.
pub type Fr = ark_bls12_381::Fr;

/// A canonical field element as it appears on the wire.
pub type FieldBytes = [u8; 32];

/// `r` as 32 big-endian bytes, taken from profile section 1.1.
pub const MODULUS_BE: FieldBytes = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

/// True when `value` is below the modulus, which is the only accepted form.
pub fn is_canonical(value: &FieldBytes) -> bool {
    value[..] < MODULUS_BE[..]
}

/// Parses a wire field element, rejecting anything at or above the modulus.
pub fn fr_from_be(value: &FieldBytes) -> Result<Fr> {
    if !is_canonical(value) {
        return Err(Error::NonCanonicalField { value: hex::encode(value) });
    }
    Ok(Fr::from_be_bytes_mod_order(value))
}

/// Writes a field element back out in the one accepted encoding.
pub fn fr_to_be(value: &Fr) -> FieldBytes {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    // `to_bytes_be` emits exactly ceil(255/8) = 32 bytes for this field, but a
    // shorter run is copied right-aligned rather than assumed away.
    let start = out.len().saturating_sub(bytes.len());
    let skip = bytes.len().saturating_sub(out.len());
    out[start..].copy_from_slice(&bytes[skip..]);
    out
}

/// A 256-bit value rendered as a decimal string, which is how these values are
/// compared against other implementations: never through a 64-bit integer.
pub fn fr_to_decimal(value: &Fr) -> String {
    value.into_bigint().to_string()
}

/// Parses a decimal string produced by [`fr_to_decimal`] or by another
/// implementation, rejecting anything at or above the modulus.
pub fn fr_from_decimal(text: &str) -> Result<Fr> {
    let trimmed = text.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::NonCanonicalField { value: trimmed.to_string() });
    }
    // Horner over the field would silently reduce, so the value is accumulated
    // in a wide big-endian buffer first and then range-checked.
    let mut digits: Vec<u8> = vec![0u8; 40];
    for byte in trimmed.bytes() {
        let digit = u32::from(byte - b'0');
        let mut carry = digit;
        for slot in digits.iter_mut().rev() {
            let wide = u32::from(*slot)
                .checked_mul(10)
                .and_then(|v| v.checked_add(carry))
                .ok_or_else(|| Error::NonCanonicalField { value: trimmed.to_string() })?;
            *slot = (wide & 0xff) as u8;
            carry = wide >> 8;
        }
        if carry != 0 {
            return Err(Error::NonCanonicalField { value: trimmed.to_string() });
        }
    }
    if digits[..8].iter().any(|b| *b != 0) {
        return Err(Error::NonCanonicalField { value: trimmed.to_string() });
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digits[8..]);
    fr_from_be(&bytes)
}

/// Builds a field element from a small unsigned integer. Used for constants
/// such as slot indices and tree positions, never for user-supplied values.
pub fn fr_from_u128(value: u128) -> Fr {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&value.to_be_bytes());
    // A u128 is always far below r, so no rejection path can fire here.
    Fr::from_be_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_itself_is_rejected() {
        assert!(!is_canonical(&MODULUS_BE));
        assert!(fr_from_be(&MODULUS_BE).is_err());
    }

    #[test]
    fn modulus_minus_one_round_trips() {
        let mut bytes = MODULUS_BE;
        bytes[31] -= 1;
        let value = match fr_from_be(&bytes) {
            Ok(value) => value,
            Err(error) => panic!("largest canonical element rejected: {error}"),
        };
        assert_eq!(fr_to_be(&value), bytes);
        let decimal = fr_to_decimal(&value);
        assert_eq!(
            decimal,
            "52435875175126190479447740508185965837690552500527637822603658699938581184512"
        );
        let parsed = match fr_from_decimal(&decimal) {
            Ok(parsed) => parsed,
            Err(error) => panic!("decimal round trip rejected: {error}"),
        };
        assert_eq!(parsed, value);
    }

    #[test]
    fn decimal_at_the_modulus_is_rejected() {
        assert!(fr_from_decimal(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513"
        )
        .is_err());
    }

    #[test]
    fn small_values_round_trip_through_decimal() {
        for value in [0u128, 1, 7, u128::MAX] {
            let element = fr_from_u128(value);
            assert_eq!(fr_to_decimal(&element), value.to_string());
            match fr_from_decimal(&value.to_string()) {
                Ok(parsed) => assert_eq!(parsed, element),
                Err(error) => panic!("u128 {value} rejected: {error}"),
            }
        }
    }
}
