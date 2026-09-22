/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The shielded pool V1 circuit.
//!
//! The implementation profile is normative for everything in this crate: the
//! field, the Poseidon2 instance, the domain separators, the note and tree
//! relations, the public input ordering and the proof encoding. The Groth16
//! backend is an implementation choice; none of the above is.

pub mod circuit;
pub mod domains;
pub mod error;
pub mod field;
pub mod fixture;
pub mod gadgets;
pub mod groth16;
pub mod imt;
pub mod notes;
pub mod params;
pub mod poseidon2;
pub mod public_inputs;
pub mod scenario;
pub mod tree;
pub mod wire;
