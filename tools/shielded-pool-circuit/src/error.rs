/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Errors raised while reading frozen parameters, parsing field elements or
//! assembling a witness. Nothing here is recoverable at run time: every case
//! means an input was not what the profile says it must be.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A 32-byte big-endian value was not below the field modulus. The profile
    /// forbids reducing it; a larger value is a different value.
    NonCanonicalField { value: String },
    /// The parameter manifest did not have the shape the profile freezes.
    Manifest(String),
    /// A witness field was outside the range the circuit relation allows.
    Witness(String),
    /// A proving/verifying operation in the backing library failed.
    Backend(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NonCanonicalField { value } => {
                write!(f, "value 0x{value} is not below the BLS12-381 scalar modulus")
            }
            Error::Manifest(detail) => write!(f, "poseidon2 parameter manifest: {detail}"),
            Error::Witness(detail) => write!(f, "witness: {detail}"),
            Error::Backend(detail) => write!(f, "proof backend: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
