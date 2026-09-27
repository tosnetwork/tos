/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! What a validator controller's post-quantum root authorizes, and the exact bytes it
//! signs.
//!
//! A controller is the root of a validator's authority: it owns the stake, it is the
//! stable validator identity, and it is what replaces an operational consensus key. Its
//! root key signs under a domain of its own, and `test/pq-native/controller-auth-vectors.tsv`
//! holds what this produces so the other implementation is held to the same bytes.

use crate::UInt256;

/// Internal message operation, lowercase; signed-preimage domain, uppercase.
pub const CONTROLLER_AUTH_OP: u32 = 0x5051_6361; // "PQca"
pub const CONTROLLER_AUTH_SIGN_TAG: u32 = 0x5051_4341; // "PQCA"

/// The signature context, distinct from every other authority in this system.
pub const CONTROLLER_AUTH_CONTEXT: &[u8] = b"TOS-VALIDATOR-CONTROLLER-v1";

/// What a controller root signs. Exactly 93 bytes.
///
/// `controller_id` is the controller's own account id, which the contract takes from its
/// own address and never from the request. `payload_hash` is the level-zero commitment to
/// the action being authorized, so an authorization binds the action without carrying it.
pub fn controller_auth_preimage(
    global_id: i32,
    controller_id: &UInt256,
    epoch: u64,
    nonce: u64,
    valid_until: u32,
    kind: u8,
    payload_hash: &UInt256,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(93);
    out.extend_from_slice(&CONTROLLER_AUTH_SIGN_TAG.to_be_bytes());
    out.extend_from_slice(&global_id.to_be_bytes());
    out.extend_from_slice(controller_id.as_slice());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&nonce.to_be_bytes());
    out.extend_from_slice(&valid_until.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(payload_hash.as_slice());
    out
}

#[cfg(test)]
#[path = "tests/test_pq_controller.rs"]
mod tests;
