/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use std::{
    error::Error,
    fmt::{Display, Formatter},
    str::FromStr,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum WalletVersion {
    V1R3,
    V3R2,
    V4R2,
    V5R1,
}

impl Display for WalletVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletVersion::V1R3 => write!(f, "V1R3"),
            WalletVersion::V3R2 => write!(f, "V3R2"),
            WalletVersion::V4R2 => write!(f, "V4R2"),
            WalletVersion::V5R1 => write!(f, "V5R1"),
        }
    }
}

#[derive(Debug)]
pub struct ParseWalletVersionError;

impl Display for ParseWalletVersionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseWalletVersionError => write!(f, "Failed to parse wallet version"),
        }
    }
}

impl FromStr for WalletVersion {
    type Err = ParseWalletVersionError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "V1R3" => Ok(WalletVersion::V1R3),
            "V3R2" => Ok(WalletVersion::V3R2),
            "V4R2" => Ok(WalletVersion::V4R2),
            "V5R1" => Ok(WalletVersion::V5R1),
            _ => Err(ParseWalletVersionError),
        }
    }
}

impl Error for ParseWalletVersionError {}

pub mod version_serde {
    use super::WalletVersion;
    use serde::Deserialize;
    use std::str::FromStr;

    pub fn serialize<S>(
        version: &WalletVersion,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let str = version.to_string();
        serializer.serialize_str(str.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<WalletVersion, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        WalletVersion::from_str(s.as_str()).map_err(serde::de::Error::custom)
    }
}
