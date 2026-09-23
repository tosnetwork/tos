/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// The accumulator layout and the file disagree.
    Layout(String),
    /// A point the transcript carries is not a point this chain accepts.
    Point(String),
    /// The slice on disk is not the shape the provenance record claims.
    Slice(String),
    /// A structural check on the powers-of-tau string failed. This is the one
    /// that means the transcript is not what it says it is.
    Structure(String),
    /// The randomness a secret was to be drawn from is unusable. Never a
    /// reason to retry: every case this covers means the generator is wrong,
    /// not that the draw was unlucky.
    Entropy(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Layout(message) => write!(formatter, "layout: {message}"),
            Error::Point(message) => write!(formatter, "point: {message}"),
            Error::Slice(message) => write!(formatter, "slice: {message}"),
            Error::Structure(message) => write!(formatter, "structure: {message}"),
            Error::Entropy(message) => write!(formatter, "entropy: {message}"),
            Error::Io(error) => write!(formatter, "io: {error}"),
            Error::Json(error) => write!(formatter, "json: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::Json(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
