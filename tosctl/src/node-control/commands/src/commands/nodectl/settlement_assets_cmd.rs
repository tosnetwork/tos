/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! ConfigParam 84 (recognized settlement assets): the proposal value builder
//! and the reader-side check of the adopted value.

use anyhow::Context;
use chain_block::{
    Cell, Deserializable, MsgAddressInt, SETTLEMENT_ASSETS_CONFIG_PARAM, SettlementAssets,
    TokenBridgeParams, UInt256, read_pinned_settlement_assets, read_single_root_boc, write_boc,
};
use chain_block_json::{settlement_assets_from_json, settlement_assets_to_json};
use contracts::settlement_assets::{
    MASTER_WORKCHAIN, MasterEvidence, bridge_config_param, verify_settlement_asset,
};

#[derive(clap::Args, Clone)]
#[command(about = "Build or check ConfigParam 84, the recognized settlement assets")]
pub struct SettlementAssetsCmd {
    #[command(subcommand)]
    action: SettlementAssetsAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum SettlementAssetsAction {
    /// Build a ConfigParam 84 value from its JSON form, for `vote offer create --param 84 --critical`
    Build(SettlementAssetsBuildCmd),
    /// Read ConfigParam 84 at the last masterchain block and verify the pinned masters
    Verify(SettlementAssetsVerifyCmd),
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Build a ConfigParam 84 value",
    long_about = "Build a ConfigParam 84 value from its JSON form, the shape `tosctl config-param 84` \
        prints: {\"assets\": [{\"master\", \"status\", \"decimals\", \"minter_code_hash\", \
        \"wallet_code_hash\", \"max_liability_per_actor\", \"origin\": {\"kind\", \
        \"bridge_address\", \"source_chain_id\", \"source_token\"}}]}. The list is the whole new \
        value. Unknown or missing fields, a repeated master, a zero cap and an undefined status \
        or origin kind are refused; no cap is written as 1329227995784915872903807060280344575 \
        (2^120 - 1). The value is decoded back before it is printed. ConfigParam 84 is critical, \
        so propose it with `vote offer create --param 84 --critical --value-boc-file <out>`."
)]
pub struct SettlementAssetsBuildCmd {
    /// JSON file holding the new value
    #[arg(long)]
    spec: std::path::PathBuf,
    /// Write the value BOC to this file
    #[arg(long)]
    out: Option<std::path::PathBuf>,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Verify pinned ConfigParam 84 entries against finalized state",
    long_about = "Read ConfigParam 84 at the last masterchain block and decode only the pinned \
        masters; every other entry is ignored. For each pinned master that is listed, the \
        master's code and data and the source chain's bridge ConfigParam are read at the same \
        block, and the master's address is re-derived from the record the way the token bridge \
        derives it. Any mismatch is refused with a nonzero exit."
)]
pub struct SettlementAssetsVerifyCmd {
    /// Pinned master account id (64 hex digits, workchain 0); repeat for each pin
    #[arg(long = "pin", required = true)]
    pins: Vec<String>,
}

impl SettlementAssetsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            SettlementAssetsAction::Build(cmd) => cmd.run(),
            SettlementAssetsAction::Verify(cmd) => cmd.run(config_path).await,
        }
    }
}

/// The value and its BOC, decoded back to prove the decoder reproduces it.
pub(crate) fn build_value(spec: &serde_json::Value) -> anyhow::Result<(Cell, Vec<u8>)> {
    let assets = settlement_assets_from_json(spec)?;
    let cell = assets.to_cell()?;
    let decoded = SettlementAssets::construct_from_cell(cell.clone())?;
    anyhow::ensure!(decoded == assets, "the built value does not decode back to the input");
    let boc = write_boc(&cell)?;
    Ok((cell, boc))
}

impl SettlementAssetsBuildCmd {
    fn run(&self) -> anyhow::Result<()> {
        use base64::Engine;
        let text = std::fs::read_to_string(&self.spec)
            .with_context(|| format!("read {}", self.spec.display()))?;
        let spec: serde_json::Value =
            serde_json::from_str(&text).context("the spec is not JSON")?;
        let (cell, boc) = build_value(&spec)?;
        super::vote_cmd::check_value_shape(SETTLEMENT_ASSETS_CONFIG_PARAM as i32, &cell)?;
        if let Some(out) = &self.out {
            std::fs::write(out, &boc).with_context(|| format!("write {}", out.display()))?;
        }
        let decoded = SettlementAssets::construct_from_cell(cell.clone())?;
        let report = serde_json::json!({
            "param": SETTLEMENT_ASSETS_CONFIG_PARAM,
            "critical": true,
            "value_hash": hex::encode(cell.repr_hash().as_slice()),
            "value_boc": base64::engine::general_purpose::STANDARD.encode(&boc),
            "value": settlement_assets_to_json(&decoded),
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(())
    }
}

pub(crate) fn parse_pin(text: &str) -> anyhow::Result<UInt256> {
    let text = text.strip_prefix("0:").unwrap_or(text);
    anyhow::ensure!(
        text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()),
        "a pin is a workchain-0 account id of 64 hex digits"
    );
    let bytes: [u8; 32] =
        hex::decode(text)?.try_into().map_err(|_| anyhow::anyhow!("a pin is 32 bytes"))?;
    Ok(UInt256::from(bytes))
}

fn cell_from(boc: Option<Vec<u8>>, what: &str) -> anyhow::Result<Cell> {
    let boc = boc.ok_or_else(|| anyhow::anyhow!("the master has no {what}"))?;
    read_single_root_boc(boc)
}

impl SettlementAssetsVerifyCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::try_create_rpc_client;
        use common::app_config::AppConfig;

        let pins = self.pins.iter().map(|p| parse_pin(p)).collect::<anyhow::Result<Vec<_>>>()?;
        let config = AppConfig::load(std::path::Path::new(config_path))?;
        let rpc = try_create_rpc_client(&config).await?;
        let seqno = rpc.get_masterchain_info().await?.last.seqno;
        let Some((value, block)) =
            rpc.get_optional_config_param_cell_at(SETTLEMENT_ASSETS_CONFIG_PARAM, seqno).await?
        else {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "seqno": seqno,
                    "present": false,
                    "pins": pins.iter().map(|m| serde_json::json!({"master": hex::encode(m.as_slice()), "listed": false})).collect::<Vec<_>>(),
                }))?
            );
            return Ok(());
        };
        let pinned = read_pinned_settlement_assets(value, &pins)?;
        let mut report = Vec::with_capacity(pinned.len());
        for entry in &pinned {
            let master_hex = hex::encode(entry.master.as_slice());
            let Some(asset) = &entry.asset else {
                report.push(serde_json::json!({"master": master_hex, "listed": false}));
                continue;
            };
            let param = bridge_config_param(asset.origin.source_chain_id).ok_or_else(|| {
                anyhow::anyhow!(
                    "master {master_hex}: source chain {} has no token bridge parameter",
                    asset.origin.source_chain_id
                )
            })?;
            let (bridge_cell, bridge_block) =
                rpc.get_optional_config_param_cell_at(param, seqno).await?.ok_or_else(|| {
                    anyhow::anyhow!("master {master_hex}: ConfigParam {param} is absent")
                })?;
            anyhow::ensure!(
                bridge_block.root_hash == block.root_hash,
                "ConfigParam {param} was read at another block than ConfigParam 84"
            );
            let bridge_params = TokenBridgeParams::construct_from_cell(bridge_cell)
                .with_context(|| format!("ConfigParam {param}"))?;
            let address = MsgAddressInt::with_standart(
                None,
                MASTER_WORKCHAIN as i8,
                entry.master.clone().into(),
            )?;
            let account = rpc.get_address_information_at(&address, seqno).await?;
            let code = cell_from(account.code, "code")?;
            let data = cell_from(account.data, "data")?;
            verify_settlement_asset(
                &entry.master,
                asset,
                &MasterEvidence { code: &code, data: &data, bridge_params: &bridge_params },
            )?;
            report.push(serde_json::json!({
                "master": master_hex,
                "listed": true,
                "verified": true,
                "status": asset.status.name(),
                "decimals": asset.decimals,
                "bridge_param": param,
            }));
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "seqno": seqno,
                "present": true,
                "pins": report,
            }))?
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(cap: &str) -> serde_json::Value {
        serde_json::json!({"assets": [{
            "master": "a1".repeat(32),
            "status": "active",
            "decimals": 6,
            "minter_code_hash": "11".repeat(32),
            "wallet_code_hash": "22".repeat(32),
            "max_liability_per_actor": cap,
            "origin": {
                "kind": "token_bridge",
                "bridge_address": "33".repeat(32),
                "source_chain_id": 1,
                "source_token": "44".repeat(20)
            }
        }]})
    }

    #[test]
    fn the_built_value_is_what_vote_offer_create_accepts() {
        let (cell, boc) = build_value(&spec("1000000000")).expect("built");
        super::super::vote_cmd::check_value_shape(84, &cell).expect("a well-formed ConfigParam 84");
        assert_eq!(read_single_root_boc(boc).expect("boc"), cell);
        let read = read_pinned_settlement_assets(cell, &[parse_pin(&"a1".repeat(32)).unwrap()])
            .expect("pinned");
        assert_eq!(read[0].asset.as_ref().expect("listed").decimals, 6);
    }

    #[test]
    fn the_builder_refuses_a_zero_cap() {
        assert!(build_value(&spec("0")).is_err());
    }

    #[test]
    fn vote_offer_create_refuses_a_malformed_value() {
        use chain_block::IBitstring;
        // settlement_assets_v1 with a trailing bit after the empty dictionary.
        let mut b = chain_block::BuilderData::new();
        b.append_u8(1).unwrap();
        b.append_bit_zero().unwrap();
        b.append_bit_zero().unwrap();
        let cell = b.into_cell().unwrap();
        assert!(super::super::vote_cmd::check_value_shape(84, &cell).is_err());
    }

    #[test]
    fn a_pin_is_a_workchain_zero_account_id() {
        let id = "a1".repeat(32);
        assert_eq!(parse_pin(&id).unwrap(), parse_pin(&format!("0:{id}")).unwrap());
        assert!(parse_pin(&format!("-1:{id}")).is_err());
        assert!(parse_pin("a1").is_err());
        assert!(parse_pin(&"zz".repeat(32)).is_err());
    }
}
