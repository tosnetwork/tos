/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Work package D: the wallet side of the shielded pool.
//!
//! The profile places this at `sdk/js/packages/crypto/src/shielded/`. It is
//! here first because the acceptance gates it has to close -- 7, 18, 25, 26
//! and 30 -- are all about agreeing with what the chain did, and only an
//! implementation that can be driven against the pool in the sandbox can show
//! that. The TypeScript that ships is then held to this by vectors rather than
//! by reading.

pub mod delivery;
pub mod descriptor;
pub mod error;
pub mod import;
pub mod keys;
pub mod scan;

/// Section 9.4: exactly 28 ASCII bytes, and it never varies.
pub const SIGNATURE_CONTEXT: &[u8] = b"TOS-SHIELDED-POOL-MLDSA44-v1";
