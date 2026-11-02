// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! The release pins: what a wallet and a provider must agree on before a
//! quote means anything. Supplied by the operator and by the wallet's own
//! profile, never by a directory or an HTTP peer.
use crate::wire;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCOPE_TAG: &[u8] = b"TOS-BR1-RELEASE\0";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub global_id: i32,
    pub genesis_root: String,
    pub genesis_file: String,
    pub bond: String,
    pub bond_code_hash: String,
    pub policy_hash: String,
    pub worker_key_hash: String,
    pub pool: String,
    pub pool_code_hash: String,
    pub pool_config_hash: String,
}

impl Release {
    /// Shape only: digests are digests, addresses are canonical basechain
    /// addresses, the Bond is not the pool. Which networks are allowed is the
    /// caller's policy.
    pub fn validate(&self) -> Result<()> {
        for s in [
            &self.genesis_root,
            &self.genesis_file,
            &self.bond_code_hash,
            &self.policy_hash,
            &self.worker_key_hash,
            &self.pool_code_hash,
            &self.pool_config_hash,
        ] {
            wire::digest(&Value::String(s.clone()))?;
        }
        for s in [&self.bond, &self.pool] {
            ensure!(s.starts_with("0:") && s.len() == 66, "canonical basechain address");
            wire::digest(&Value::String(s[2..].into()))?;
        }
        ensure!(self.bond != self.pool, "release account collision");
        Ok(())
    }

    /// The identity every quote and request carries.
    pub fn scope(&self) -> Result<String> {
        let mut bytes = SCOPE_TAG.to_vec();
        bytes.extend(wire::canonical(&serde_json::to_value(self)?)?);
        Ok(wire::hash(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> Release {
        Release {
            global_id: 3,
            genesis_root: "01".repeat(32),
            genesis_file: "02".repeat(32),
            bond: format!("0:{}", "03".repeat(32)),
            bond_code_hash: "04".repeat(32),
            policy_hash: "05".repeat(32),
            worker_key_hash: "06".repeat(32),
            pool: format!("0:{}", "07".repeat(32)),
            pool_code_hash: "08".repeat(32),
            pool_config_hash: "09".repeat(32),
        }
    }

    #[test]
    fn scope_is_the_tagged_canonical_hash() -> Result<()> {
        let release = sample();
        release.validate()?;
        let mut bytes = SCOPE_TAG.to_vec();
        bytes.extend(wire::canonical(&serde_json::to_value(&release)?)?);
        assert_eq!(release.scope()?, wire::hash(&bytes));
        // The Python reference encodes the same object the same way: sorted
        // members, compact, the integer bare.
        let text = String::from_utf8(wire::canonical(&serde_json::to_value(&release)?)?)?;
        assert!(text.starts_with(r#"{"bond":"0:"#));
        assert!(text.contains(r#""global_id":3,"#));
        Ok(())
    }

    #[test]
    fn shape_refusals() {
        let mut r = sample();
        r.pool = r.bond.clone();
        assert!(r.validate().is_err());
        let mut r = sample();
        r.bond = "-1:".to_owned() + &"03".repeat(32);
        assert!(r.validate().is_err());
        let mut r = sample();
        r.policy_hash = "00".repeat(32);
        assert!(r.validate().is_err());
        let text = r#"{"global_id":3,"extra":1}"#;
        assert!(serde_json::from_str::<Release>(text).is_err());
    }
}
