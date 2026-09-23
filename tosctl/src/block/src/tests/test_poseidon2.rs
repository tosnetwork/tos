/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The permutation against the vectors the pinned upstream reference produced,
//! and against the manifest digest that ties this table to the C++ one.

use super::*;
use crate::poseidon2_kat::{DOMAINS, HASH7, PERM8};
use crate::poseidon2_params::{
    MANIFEST_SHA256, MANIFEST_TAG, MODULUS_BE, ROUNDS_TOTAL, STATE_WIDTH,
};
use sha2::{Digest, Sha256};

#[test]
fn the_manifest_rebuilt_here_has_the_pinned_digest() {
    let bytes = manifest_bytes();
    let expected = MANIFEST_TAG.len()
        + 32
        + 4
        + 32 * (STATE_WIDTH + STATE_WIDTH * STATE_WIDTH + ROUNDS_TOTAL * STATE_WIDTH);
    assert_eq!(bytes.len(), expected, "manifest length");
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(
        hex::encode(digest),
        hex::encode(MANIFEST_SHA256),
        "the tables here do not rebuild the frozen manifest"
    );
}

/// Nothing below is believed until this passes: it catches a permutation that
/// is the identity, one that is not deterministic, and one that drops a lane.
#[test]
fn the_instrument_behaves_like_a_permutation_before_any_vector_is_believed() {
    let input = PERM8[0].1;
    let once = permute(&input);
    assert_ne!(once, input, "the permutation returned its input");
    assert_eq!(once, permute(&input), "the permutation is not deterministic");

    for lane in 0..STATE_WIDTH {
        let mut nudged = input;
        nudged[lane][31] ^= 1;
        assert_ne!(permute(&nudged), once, "lane {lane} does not reach the output");
    }
    for value in once.iter() {
        assert!(is_canonical(value), "an output is not below the modulus");
    }
}

#[test]
fn every_pinned_vector_is_reproduced() {
    for (name, input, output) in PERM8 {
        assert_eq!(permute(&input), output, "{name}: permutation differs from the reference");
    }
    for (name, state, output) in HASH7 {
        assert_eq!(permute(&state)[0], output, "{name}: hash differs from the reference");
    }
    assert_eq!(PERM8.len(), 21, "the vector table shrank");
    assert_eq!(HASH7.len(), 28, "the hash vector table shrank");
}

#[test]
fn domain_constants_are_usable_field_elements() {
    for (label, value) in DOMAINS {
        assert!(value.iter().any(|byte| *byte != 0), "{label}: domain constant is zero");
        assert!(is_canonical(&value), "{label}: domain constant is not below the modulus");
    }
    assert_eq!(DOMAINS.len(), 14, "the frozen label list changed");
}

#[test]
fn canonicality_is_a_strict_bound() {
    assert!(!is_canonical(&MODULUS_BE), "the modulus itself is not a field element");
    let mut below = MODULUS_BE;
    below[31] -= 1; // the modulus ends in 0x01, so this cannot borrow
    assert!(is_canonical(&below), "the largest field element was rejected");
    assert!(!is_canonical(&[0xff; 32]), "2^256-1 is not a field element");
    assert!(is_canonical(&[0u8; 32]), "zero is a field element");
}
