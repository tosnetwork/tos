/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! What can stop a wallet, kept separate from what it means.

/// A wallet failure. `Rejected` is the interesting one: it is not an error in
/// the wallet, it is a payload that belongs to no valid local note, and
/// section 3.1 requires it to be surfaced rather than silently dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    KeyDerivation(String),
    Encoding(String),
    /// The payload decrypted but does not describe a note this wallet owns.
    Rejected(Rejection),
}

/// Exactly which section 3.1 rule a payload broke. A wallet keeps this so a
/// malformed or malicious delivery can be shown to somebody rather than
/// disappearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The AEAD did not open: not ours, or tampered with.
    Undecryptable,
    PlaintextLength,
    Magic,
    Version,
    Slot,
    /// Reserved flag bits set, or a combination section 3 forbids.
    Flags,
    NoteSecretNotCanonical,
    NoteSecretZero,
    /// The amount is outside the range the flags allow.
    Amount,
    /// The plaintext names an owner this index does not derive.
    OwnerNfKeyHash,
    /// The plaintext names a PQ key this index does not derive.
    PqAuthKeyHash,
    /// The note the plaintext describes is not the note the chain published.
    NoteBodyMismatch,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::KeyDerivation(message) => write!(f, "key derivation: {message}"),
            Error::Encoding(message) => write!(f, "encoding: {message}"),
            Error::Rejected(why) => write!(f, "payload rejected: {why:?}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
