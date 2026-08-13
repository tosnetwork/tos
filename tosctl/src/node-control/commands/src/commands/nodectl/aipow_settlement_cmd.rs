/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! `tosctl agent aipow-settlement` -- deploy and inspect the AIPoW settlement
//! account (the single ConfigParam-93 masterchain account the native mint credits).
//! `address` computes the counterfactual deploy address so governance can register
//! it in ConfigParam 93 BEFORE the account is deployed (the Model B activation
//! order). Masterchain-only.

use super::agent_cmd::{confirm, validate_tos_amount};
use super::output_format::OutputFormat;
use super::utils::{
    get_wallet_config, load_config_vault_rpc_client, make_wallet, try_create_rpc_client,
    wallet_info,
};
use anyhow::Context;
use chain_block::MsgAddressInt;
use chain_rpc_client::v2::data_models::AccountState;
use colored::Colorize;
use contracts::{
    AipowCommitmentContract, AipowDistributorContract, AipowMaturation, AipowSettlementContract,
    AipowSettlementInit,
};
use std::path::Path;

const SETTLEMENT_DEPLOY_GAS: u64 = 2_000_000; // 0.002 TOS

/// `tosctl agent aipow-settlement` -- AIPoW settlement account operations.
#[derive(clap::Args, Clone)]
#[command(about = "AIPoW settlement account operations")]
pub struct AipowSettlementCmd {
    #[command(subcommand)]
    action: AipowSettlementAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum AipowSettlementAction {
    /// Print the counterfactual deploy address (for ConfigParam 93) without deploying
    Address(AipowSettlementParamsCmd),
    /// Deploy the settlement account to its counterfactual address
    Deploy(AipowSettlementDeployCmd),
    /// Show settlement ledger state by address
    Show(AipowSettlementShowCmd),
}

impl AipowSettlementCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            AipowSettlementAction::Address(cmd) => cmd.run(config_path).await,
            AipowSettlementAction::Deploy(cmd) => cmd.run(config_path).await,
            AipowSettlementAction::Show(cmd) => cmd.run(config_path).await,
        }
    }
}

/// The deploy parameters that fix the settlement's StateInit (and thus its
/// address). Shared by `address` and `deploy` so the two compute an identical
/// address.
#[derive(clap::Args, Clone)]
pub struct AipowSettlementParamsCmd {
    #[arg(long, help = "The first epoch the cursor settles")]
    next_epoch: u32,
    #[arg(long, default_value_t = 65536, help = "Epoch length in seconds")]
    epoch_seconds: u32,
    #[arg(long, default_value_t = 3600, help = "Seconds after an epoch ends before it may be skipped")]
    register_grace: u32,
    #[arg(
        long,
        help = "Seconds a candidate's challenge window must be open + elapsed before the native path mints it; MUST be < register_grace"
    )]
    challenge_window: u32,
    #[arg(long, default_value_t = 0, help = "Workchain the per-epoch distributors are deployed on")]
    earner_workchain: i8,
    #[arg(long, default_value_t = 4_500_000_000, help = "AIPoW supply cap in TOS")]
    total_cap_tos: u64,
    #[arg(short = 'w', long = "workchain", default_value = "-1")]
    workchain: i32,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

impl AipowSettlementParamsCmd {
    fn build_init(&self) -> anyhow::Result<AipowSettlementInit> {
        Ok(AipowSettlementInit {
            next_epoch: self.next_epoch,
            epoch_seconds: self.epoch_seconds,
            register_grace: self.register_grace,
            challenge_window: self.challenge_window,
            earner_workchain: self.earner_workchain,
            maturation: AipowMaturation::methodology_v0(),
            total_cap: self
                .total_cap_tos
                .checked_mul(1_000_000_000)
                .context("total_cap_tos overflows nanotos")?,
            // The audited distributor code the settle path deploys per epoch.
            distributor_code: AipowDistributorContract::code()?,
        })
    }

    async fn run(&self, _config_path: &str) -> anyhow::Result<()> {
        // build_data enforces 0 < challenge_window < register_grace and the
        // maturation bounds, so an invalid parameter set fails here.
        let init = self.build_init()?;
        let address = AipowSettlementContract::calculate_address(self.workchain, &init)?;
        // ConfigParam 93 (AipowRegistry) bundles the settlement address with the
        // audited commitment code hash the native settle path pins; emit it here so
        // governance registers a consistent set.
        let commitment_code_hash = AipowCommitmentContract::code()?.repr_hash();
        if self.format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::json!({
                    "address": address.to_string(),
                    "account_id_hex": hex::encode(address.address().get_bytestring(0)),
                    "commitment_code_hash": hex::encode(commitment_code_hash.as_slice()),
                    "next_epoch": self.next_epoch,
                    "challenge_window": self.challenge_window,
                })
            );
        } else {
            println!("{} settlement address: {}", "OK".green().bold(), address);
            println!("  commitment_code_hash: {}", hex::encode(commitment_code_hash.as_slice()));
        }
        Ok(())
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Deploy the settlement account to its counterfactual address")]
pub struct AipowSettlementDeployCmd {
    #[command(flatten)]
    params: AipowSettlementParamsCmd,
    #[arg(long, help = "Funding wallet name or master_wallet")]
    from: String,
    #[arg(long, default_value_t = 2.0, help = "Message value funding the deploy, in TOS")]
    amount: f64,
    #[arg(long)]
    yes: bool,
}

impl AipowSettlementDeployCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("amount", self.amount)?;
        let init = self.params.build_init()?;
        let address = AipowSettlementContract::calculate_address(self.params.workchain, &init)?;
        let state_init = AipowSettlementContract::build_state_init(&init)?;
        let amount_nanotos = common::chain_utils::tos_to_nanotos(self.amount);

        let path = Path::new(config_path);
        let (config, vault, rpc_client) = load_config_vault_rpc_client(path).await?;
        let payer_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (payer_address, payer_info, payer_secret) =
            wallet_info(rpc_client.clone(), payer_cfg, vault).await?;
        if payer_info.account_state != AccountState::Active {
            anyhow::bail!("funding wallet is not active");
        }
        if payer_info.balance < amount_nanotos.saturating_add(SETTLEMENT_DEPLOY_GAS) {
            anyhow::bail!("funding wallet has insufficient balance");
        }
        if !self.yes && !confirm("Confirm AIPoW settlement deployment?")? {
            return Ok(());
        }
        let wallet = make_wallet(rpc_client.clone(), payer_cfg, payer_secret, &self.from).await?;
        let body = chain_block::BuilderData::new().into_cell()?;
        super::agent_cmd::send_wallet_message_with_state_init(
            &wallet,
            rpc_client,
            address.clone(),
            amount_nanotos,
            body,
            payer_info.seqno,
            &payer_address,
            state_init,
        )
        .await?;
        if self.params.format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::json!({
                    "address": address.to_string(),
                    "status": "submitted",
                    "next_epoch": self.params.next_epoch,
                })
            );
        } else {
            println!("{} settlement deployed at {}", "OK".green().bold(), address);
        }
        Ok(())
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Show settlement ledger state by address")]
pub struct AipowSettlementShowCmd {
    #[arg(long, help = "Settlement account address")]
    address: String,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

impl AipowSettlementShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let addr = self.address.parse::<MsgAddressInt>().context("invalid settlement address")?;
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let provider = contracts::contract_provider!(rpc_client.clone());
        let stack = provider
            .get_method(addr.to_string(), "get_aipow_settlement_data", vec![])
            .await?;
        let data = AipowSettlementContract::decode_data(&stack)?;
        if self.format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::json!({
                    "address": addr.to_string(),
                    "version": data.version,
                    "next_epoch": data.next_epoch,
                    "epoch_seconds": data.epoch_seconds,
                    "register_grace": data.register_grace,
                    "challenge_window": data.challenge_window,
                    "earner_workchain": data.earner_workchain,
                    "minted_total": data.minted_total.to_string(),
                    "total_cap": data.total_cap.to_string(),
                })
            );
        } else {
            println!(
                "settlement {} cursor next_epoch={} challenge_window={} minted_total={}",
                addr, data.next_epoch, data.challenge_window, data.minted_total
            );
        }
        Ok(())
    }
}
