/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The last mile: a ceremony's 1,248 bytes into a genesis state.
//!
//! A phase-2 ceremony ends with a verifying key, and until
//! `parameters_with_verifying_key` existed the only route from there to a
//! deployment was editing the development fixture by hand -- a step performed
//! once, under time pressure, by whoever happened to be there.
//!
//! Two things have to be true of that route, and only one is obvious:
//!
//! 1. the default has not moved. Passing no key must produce exactly the
//!    genesis state the frozen manifest names, or this convenience has
//!    quietly changed what the chain deploys;
//! 2. **the key reaches the state hash.** A route that accepted the bytes and
//!    dropped them would pass every test that only checks the default, and
//!    would hand a ceremony's output to a deployment carrying the development
//!    key -- the one whose toxic waste is in the source.

use std::path::PathBuf;

use shielded_pool_genesis::manifest::cell_hash;
use shielded_pool_genesis::{
    build, development_parameters, parameters_with_verifying_key, VK_BYTES,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn state_hash(parameters: shielded_pool_genesis::Parameters) -> [u8; 32] {
    cell_hash(&build(parameters).expect("the genesis state").state)
}

/// The development key, handed back in explicitly, must give the state the
/// default gives. Anything else means the override does more than replace the
/// key.
#[test]
fn passing_the_development_key_back_in_changes_nothing() {
    let root = root();
    let default = development_parameters(&root).expect("the development parameters");
    let explicit = parameters_with_verifying_key(&root, default.verifying_key.clone())
        .expect("the same key, explicitly");
    assert_eq!(
        state_hash(default),
        state_hash(explicit),
        "handing the development key back in produced a different genesis state"
    );
}

/// The one that matters. A different key is a different state, so a different
/// state hash, so a different deployment address -- which is why no address
/// can be published before a ceremony finishes.
#[test]
fn a_different_verifying_key_is_a_different_genesis_state() {
    let root = root();
    let default = development_parameters(&root).expect("the development parameters");

    // Not a random blob: a real key differing from the development one in a
    // single byte is the case a route that hashes the wrong thing would still
    // pass. The genesis state commits to the key's bytes, not to its meaning,
    // so this is the right shape of difference to test with.
    let mut altered = default.verifying_key.clone();
    let last = altered.len() - 1;
    altered[last] ^= 0x01;

    let changed =
        parameters_with_verifying_key(&root, altered.clone()).expect("a key of the right length");
    assert_ne!(
        state_hash(default),
        state_hash(changed),
        "one bit of the verifying key did not reach the genesis state, so the key a ceremony \
         produces would not change what is deployed"
    );
}

#[test]
fn a_key_of_the_wrong_length_is_refused() {
    let root = root();
    for length in [0usize, VK_BYTES - 1, VK_BYTES + 1] {
        let error = parameters_with_verifying_key(&root, vec![0u8; length])
            .expect_err("a key of the wrong length was accepted");
        assert!(
            format!("{error}").contains(&format!("not {VK_BYTES}")),
            "refused for the wrong reason at length {length}: {error}"
        );
    }
}
