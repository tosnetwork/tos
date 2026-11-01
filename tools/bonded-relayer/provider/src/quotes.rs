// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
use crate::{config::Config, identity::Identity, protocol};
use anyhow::{ensure, Result};
use serde_json::Value;

pub fn validate(
    bytes: &[u8],
    config: &Config,
    identity: &Identity,
    now: Option<u64>,
) -> Result<Value> {
    ensure!(bytes.len() <= 16 * 1024, "quote terms bound");
    let t = protocol::parse(bytes)?;
    protocol::fields(
        &t,
        &[
            "schema",
            "release",
            "nonce",
            "note_index",
            "issued_at",
            "valid_until",
            "slot",
            "amount",
            "funding_cap",
            "descriptor_b64",
            "status_hash",
            "success",
        ],
    )?;
    ensure!(protocol::canonical(&t)? == bytes, "quote terms must be canonical");
    ensure!(
        t["schema"] == "tos.br1.quote.terms.v1"
            && t["release"] == config.release.scope()?
            && t["success"] == "pool_execution",
        "quote release/semantics"
    );
    protocol::digest(&t["nonce"])?;
    protocol::digest(&t["status_hash"])?;
    let integer = |key: &str, lo: u64, hi: u64| -> Result<u64> {
        let n = t[key].as_u64().ok_or_else(|| anyhow::anyhow!("quote integer"))?;
        ensure!((lo..=hi).contains(&n), "quote integer bound");
        Ok(n)
    };
    let index = integer("note_index", 0, i64::MAX as u64)?;
    integer("slot", 0, 2)?;
    ensure!(
        integer("amount", 1, i64::MAX as u64)? == config.fee
            && integer("funding_cap", 1, i64::MAX as u64)? == config.funding_cap,
        "operator fee/funding policy"
    );
    let issued = integer("issued_at", 1, u32::MAX as u64)?;
    let maximum = issued
        .checked_add(300)
        .ok_or_else(|| anyhow::anyhow!("quote expiry overflow"))?
        .min(u32::MAX as u64);
    let minimum = issued.checked_add(1).ok_or_else(|| anyhow::anyhow!("quote expiry overflow"))?;
    let expiry = integer("valid_until", minimum, maximum)?;
    if let Some(now) = now {
        ensure!(
            issued <= now.checked_add(5).ok_or_else(|| anyhow::anyhow!("clock overflow"))?
                && expiry > now,
            "quote not currently valid"
        );
    }
    let descriptor =
        t["descriptor_b64"].as_str().ok_or_else(|| anyhow::anyhow!("descriptor string"))?;
    ensure!(
        crate::identity::decode(descriptor, 2573)? == identity.descriptor(index)?,
        "descriptor custody/domain/index mismatch"
    );
    Ok(t)
}
