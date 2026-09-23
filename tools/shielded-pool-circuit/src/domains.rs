/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Domain separators and the `H7` helper of profile section 1.4.
//!
//! The numeric constants are derived here from the ASCII labels, never written
//! out by hand:
//!
//! ```text
//! domain_fr(label) = uint256_be(SHA256("TOS-SHIELDED-DOMAIN-v1:" || label)) mod r
//! ```
//!
//! The reduction is part of constant generation only. User-supplied field
//! elements stay canonical, which is why [`crate::field::fr_from_be`] rejects
//! rather than reduces.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

use crate::field::Fr;
use crate::poseidon2::hash7;

/// The prefix every domain label is hashed under.
pub const DOMAIN_PREFIX: &[u8] = b"TOS-SHIELDED-DOMAIN-v1:";

/// Every label profile section 1.4 freezes, in the order it lists them.
pub const LABELS: [&str; 14] = [
    "DUMMY-OWNER-NF",
    "OWNER-NF-HASH",
    "OWNER-COMMITMENT",
    "NOTE-BODY",
    "NOTE-COMMITMENT",
    "NULLIFIER",
    "PHANTOM-NULLIFIER",
    "RECOVERY-TEMPLATE",
    "COMMIT-NODE",
    "IMT-LEAF",
    "IMT-NODE",
    "INTENT-CORE",
    "INTENT-OUTPUTS",
    "INTENT-FINAL",
];

/// Derives the domain constant for `label`.
///
/// This is the one place in the crate where a value is reduced rather than
/// rejected, because section 1.4 defines the constant that way.
pub fn derive_domain(label: &str) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_PREFIX);
    hasher.update(label.as_bytes());
    Fr::from_be_bytes_mod_order(&hasher.finalize())
}

fn table() -> &'static BTreeMap<&'static str, Fr> {
    static TABLE: OnceLock<BTreeMap<&'static str, Fr>> = OnceLock::new();
    TABLE.get_or_init(|| LABELS.iter().map(|label| (*label, derive_domain(label))).collect())
}

/// The domain constant for a frozen label.
///
/// Unknown labels are refused: section 1.4 freezes the list, so a label that is
/// not on it is a coding mistake rather than an input.
pub fn domain(label: &str) -> Option<Fr> {
    table().get(label).copied()
}

/// The domain constant for a label known at compile time to be on the frozen
/// list. Used by the gadget code, which only ever names frozen labels.
fn frozen(label: &str) -> Fr {
    match domain(label) {
        Some(value) => value,
        // Unreachable for the constants below; deriving directly keeps the
        // function total without a panic path.
        None => derive_domain(label),
    }
}

/// `H7(label, a0..a6)` of profile section 1.4.
pub fn h7(label: &str, inputs: &[Fr; 7]) -> Fr {
    hash7(frozen(label), inputs)
}

/// `DUMMY_OWNER_NF_HASH = domain_fr("DUMMY-OWNER-NF")`, profile section 1.4.
pub fn dummy_owner_nf_hash() -> Fr {
    frozen("DUMMY-OWNER-NF")
}

/// Section 1.4 requires the generator to fail if any reserved domain constant
/// reduces to zero. This is that check, kept where the constants are derived.
pub fn no_domain_is_zero() -> bool {
    LABELS.iter().all(|label| derive_domain(label) != Fr::from(0u64))
}
