/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Validator controller operating authorization (root action kind 4).
//!
//! `status` reads what the controller recorded and what the next relayed stake will
//! cost. `plan` prepares a renewal by deficit for offline root signing. Neither signs
//! nor sends anything: the controller root key is offline.
use super::output_format::OutputFormat;
use anyhow::Context;
use chain_block::MsgAddressInt;
use colored::Colorize;
use contracts::validator_controller::{
    ControllerOperations, OperatingAssessment, OperatingThresholds, RenewalPlan, RenewalRequest,
    authorization_valid_until, funds_for_runway, plan_renewal, read_controller_operations,
};

const NANO: u128 = 1_000_000_000;
const DAY: u64 = 86_400;

#[derive(clap::Args, Clone)]
#[command(about = "Validator controller operations")]
pub struct ControllerCmd {
    #[arg(
        short = 'c',
        long = "config",
        help = "Path to the configuration file",
        default_value = "tosctl-config.json",
        env = "CONFIG_PATH",
        global = true
    )]
    config: String,

    #[command(subcommand)]
    action: ControllerAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum ControllerAction {
    /// Operating authorization (kind 4): status and renewal planning
    Operations(ControllerOperationsCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Operating authorization (kind 4) that pays for relayed stakes")]
pub struct ControllerOperationsCmd {
    #[command(subcommand)]
    action: ControllerOperationsAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum ControllerOperationsAction {
    /// Show funds, allowance, limit, floor, expiry, payer, the live grant and the runway
    Status(ControllerOperationsStatusCmd),
    /// Prepare a renewal by deficit for offline root signing (signs and sends nothing)
    Plan(Box<ControllerOperationsPlanCmd>),
}

#[derive(clap::Args, Clone)]
pub struct ThresholdArgs {
    /// The runway an authorization is sized for, in days
    #[arg(long, default_value_t = 30)]
    target_days: u32,
    /// Warn when the funded runway falls below this percentage of the target
    #[arg(long, default_value_t = 25, value_parser = clap::value_parser!(u8).range(1..=100))]
    warn_percent: u8,
    /// Warn when the authorization expires within this many days
    #[arg(long, default_value_t = 7)]
    expiry_warn_days: u32,
}

impl ThresholdArgs {
    fn thresholds(&self) -> anyhow::Result<OperatingThresholds> {
        let thresholds = OperatingThresholds {
            target_runway_secs: u64::from(self.target_days)
                .checked_mul(DAY)
                .ok_or_else(|| anyhow::anyhow!("--target-days overflows"))?,
            runway_warn_percent: self.warn_percent,
            expiry_warn_secs: u64::from(self.expiry_warn_days)
                .checked_mul(DAY)
                .ok_or_else(|| anyhow::anyhow!("--expiry-warn-days overflows"))?,
        };
        thresholds.validate()?;
        Ok(thresholds)
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Show the controller's operating authorization and its runway")]
pub struct ControllerOperationsStatusCmd {
    /// Validator controller address (-1:<hex>)
    #[arg(long, allow_hyphen_values = true)]
    controller: String,
    #[command(flatten)]
    thresholds: ThresholdArgs,
    /// Exit with an error when any warning is raised (for monitoring)
    #[arg(long)]
    strict: bool,
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Prepare a kind 4 renewal by deficit for offline root signing",
    long_about = "Prepare a kind 4 renewal by deficit for offline root signing.\n\n\
        The contract adds the deposit to the recorded funds and replaces the allowance, \
        per-request limit, storage floor, expiry and payer. The deposit is therefore \
        max(0, funds target - current funds), and a target at or below the current funds \
        is a zero-deposit renewal. The command prints the kind 4 payload, the exact \
        `tos-pq-controller fund-operations` command line to run where the root seed is \
        held, and the value the payer wallet must send. It signs and sends nothing, and \
        refuses while a relay is pending or when the payer would change."
)]
pub struct ControllerOperationsPlanCmd {
    /// Validator controller address (-1:<hex>)
    #[arg(long, allow_hyphen_values = true)]
    controller: String,
    /// Wallet that sends the signed request; the contract requires sender == payer
    #[arg(long, allow_hyphen_values = true)]
    payer: String,
    #[command(flatten)]
    thresholds: ThresholdArgs,
    /// Funds target in nanoTOS (default: the grants for --target-days of elections)
    #[arg(long, conflicts_with = "expiry_only")]
    funds_target_nanotos: Option<u128>,
    /// Allowance in nanoTOS; replaces the stored one (default: the funds target)
    #[arg(long)]
    allowance_nanotos: Option<u128>,
    /// Per-request limit in nanoTOS (default: the current one when it admits the grant,
    /// otherwise twice the grant)
    #[arg(long)]
    limit_nanotos: Option<u128>,
    /// Storage floor in nanoTOS (default: the current one; required for a first
    /// authorization)
    #[arg(long)]
    floor_nanotos: Option<u128>,
    /// Expiry in days from now (default: --target-days)
    #[arg(long, conflicts_with = "expires_at")]
    expires_in_days: Option<u32>,
    /// Absolute expiry as a unix timestamp
    #[arg(long)]
    expires_at: Option<u32>,
    /// Renew only the expiry: zero deposit and the current allowance (limit and floor
    /// default as above)
    #[arg(long)]
    expiry_only: bool,
    /// Seconds the root authorization stays valid after preparation (1..=3600)
    #[arg(long, default_value_t = 1800)]
    valid_for: u32,
    /// Value in nanoTOS sent above the contract's requirement; refunded to the payer
    #[arg(long, default_value_t = 1_000_000_000)]
    margin_nanotos: u128,
    /// Allow the renewal to move sponsorship to a different payer
    #[arg(long)]
    allow_payer_change: bool,
    /// Root seed path printed into the offline command line
    #[arg(long, default_value = "ROOTSEED")]
    root_seed: String,
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

impl ControllerCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            ControllerAction::Operations(cmd) => match &cmd.action {
                ControllerOperationsAction::Status(cmd) => cmd.run(&self.config).await,
                ControllerOperationsAction::Plan(cmd) => cmd.run(&self.config).await,
            },
        }
    }
}

fn parse_controller(text: &str) -> anyhow::Result<MsgAddressInt> {
    let address = text.parse::<MsgAddressInt>().context("invalid controller address")?;
    anyhow::ensure!(
        address.workchain_id() == -1,
        "a validator controller is a masterchain account"
    );
    Ok(address)
}

async fn read(
    config_path: &str,
    controller: &MsgAddressInt,
) -> anyhow::Result<(ControllerOperations, i32)> {
    use super::utils::{network_global_id, try_create_rpc_client};
    use common::app_config::AppConfig;
    use contracts::DefaultChainProvider;

    let config = AppConfig::load(std::path::Path::new(config_path))?;
    let rpc_client = try_create_rpc_client(&config).await?;
    let chain = DefaultChainProvider::new(rpc_client.clone());
    let operations = read_controller_operations(&chain, controller).await?;
    let global_id = network_global_id(&rpc_client).await?;
    Ok((operations, global_id))
}

/// Exact nano-TOS rendered as TOS with all nine decimals.
pub(crate) fn tos(value: u128) -> String {
    let whole = value.checked_div(NANO).unwrap_or_default();
    let fraction = value.checked_rem(NANO).unwrap_or_default();
    format!("{whole}.{fraction:09} TOS")
}

fn days(secs: u64) -> String {
    format!("{:.2} days", secs as f64 / DAY as f64)
}

fn status_json(
    controller: &MsgAddressInt,
    operations: &ControllerOperations,
    assessment: &OperatingAssessment,
    thresholds: &OperatingThresholds,
    now: u64,
) -> serde_json::Value {
    let state = &operations.state;
    serde_json::json!({
        "controller": controller.to_string(),
        "now": now,
        "authorized": !state.is_unset(controller),
        "funds": state.funds.to_string(),
        "allowance": state.allowance.to_string(),
        "per_request_limit": state.limit.to_string(),
        "storage_floor": state.floor.to_string(),
        "expires": state.expires,
        "payer": state.payer.to_string(),
        "balance": operations.balance.to_string(),
        "relay_pending": operations.relay_pending,
        "retry_fees_held": operations.retry_fees_held,
        "root_epoch": operations.authority.epoch,
        "root_nonce": operations.authority.nonce,
        "grant": assessment.grant.to_string(),
        "funding_processing": operations.fees.funding_processing.to_string(),
        "elections_interval_secs": operations.elections_interval_secs,
        "stakes_remaining": assessment.stakes_remaining.to_string(),
        "runway_secs": assessment.runway_secs,
        "expires_in_secs": assessment.expires_in_secs,
        "thresholds": thresholds,
        "blocks_next_stake": assessment.blocks_next_stake(),
        "warnings": assessment.warnings,
    })
}

fn print_status(
    controller: &MsgAddressInt,
    operations: &ControllerOperations,
    assessment: &OperatingAssessment,
    now: u64,
) {
    use common::time_format::format_ts;
    let state = &operations.state;
    println!();
    println!("{}", "Controller operating authorization".bold());
    println!("{}", "\u{2500}".repeat(72));
    println!("  {:<24} {}", "Controller:", controller);
    if state.is_unset(controller) {
        println!("  {:<24} {}", "Authorization:", "none recorded".red().bold());
    }
    println!("  {:<24} {}", "Funds:", tos(state.funds));
    println!("  {:<24} {}", "Allowance:", tos(state.allowance));
    println!("  {:<24} {}", "Per-request limit:", tos(state.limit));
    println!("  {:<24} {}", "Storage floor:", tos(state.floor));
    println!(
        "  {:<24} {} ({}, in {})",
        "Expires:",
        state.expires,
        format_ts(u64::from(state.expires)),
        days(assessment.expires_in_secs)
    );
    println!("  {:<24} {}", "Payer:", state.payer);
    println!("  {:<24} {}", "Balance:", tos(operations.balance));
    println!(
        "  {:<24} epoch {} nonce {}",
        "Root authority:", operations.authority.epoch, operations.authority.nonce
    );
    println!(
        "  {:<24} {}",
        "Relay pending:",
        operations.relay_pending || operations.retry_fees_held
    );
    println!();
    println!("  {:<24} {} (live ConfigParam 20/24)", "Grant per stake:", tos(assessment.grant));
    println!(
        "  {:<24} {} s (ConfigParam 15 validators_elected_for)",
        "Elections interval:", operations.elections_interval_secs
    );
    println!("  {:<24} {}", "Stakes remaining:", assessment.stakes_remaining);
    println!("  {:<24} {}", "Runway:", days(assessment.runway_secs));
    println!("  {:<24} {}", "Checked at:", format_ts(now));
    println!();
    if assessment.warnings.is_empty() {
        println!("  {} no warnings", "OK".green().bold());
    }
    for warning in &assessment.warnings {
        let label = if warning.blocks_next_stake() {
            "[BLOCKING]".red().bold()
        } else {
            "[WARNING]".yellow().bold()
        };
        println!("  {label} {warning}");
    }
    println!();
}

impl ControllerOperationsStatusCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let controller = parse_controller(&self.controller)?;
        let thresholds = self.thresholds.thresholds()?;
        let (operations, _) = read(config_path, &controller).await?;
        let now = common::time_format::now();
        let assessment = operations.assess(&controller, now, &thresholds)?;
        match self.format {
            OutputFormat::Json => println!(
                "{}",
                serde_json::to_string_pretty(&status_json(
                    &controller,
                    &operations,
                    &assessment,
                    &thresholds,
                    now
                ))?
            ),
            OutputFormat::Table => print_status(&controller, &operations, &assessment, now),
        }
        if self.strict && !assessment.warnings.is_empty() {
            anyhow::bail!(
                "{} operating authorization warning(s) for {controller}",
                assessment.warnings.len()
            );
        }
        Ok(())
    }
}

impl ControllerOperationsPlanCmd {
    /// The renewal request from the flags, the live state and the live grant.
    fn request(
        &self,
        controller: &MsgAddressInt,
        operations: &ControllerOperations,
        now: u64,
    ) -> anyhow::Result<RenewalRequest> {
        let state = &operations.state;
        let unset = state.is_unset(controller);
        let grant = operations.fees.grant;
        let payer = self.payer.parse::<MsgAddressInt>().context("invalid payer address")?;
        let target_secs = u64::from(self.thresholds.target_days)
            .checked_mul(DAY)
            .ok_or_else(|| anyhow::anyhow!("--target-days overflows"))?;

        let funds_target = match (self.expiry_only, self.funds_target_nanotos) {
            (true, _) => state.funds,
            (false, Some(target)) => target,
            (false, None) => {
                funds_for_runway(&operations.fees, target_secs, operations.elections_interval_secs)?
            }
        };
        let allowance = match (self.allowance_nanotos, self.expiry_only) {
            (Some(value), _) => value,
            (None, true) => state.allowance,
            (None, false) => funds_target,
        };
        let limit = match self.limit_nanotos {
            Some(value) => value,
            None if !unset && state.limit >= grant => state.limit,
            None => grant.checked_mul(2).ok_or_else(|| anyhow::anyhow!("limit overflows"))?,
        };
        let floor = match self.floor_nanotos {
            Some(value) => value,
            None if !unset => state.floor,
            None => anyhow::bail!(
                "this controller has no operating authorization yet; pass --floor-nanotos"
            ),
        };
        let expires_at = match (self.expires_at, self.expires_in_days) {
            (Some(at), _) => at,
            (None, in_days) => {
                let days = u64::from(in_days.unwrap_or(self.thresholds.target_days));
                let at = days
                    .checked_mul(DAY)
                    .and_then(|secs| now.checked_add(secs))
                    .ok_or_else(|| anyhow::anyhow!("expiry overflows"))?;
                u32::try_from(at).context("expiry exceeds uint32")?
            }
        };
        Ok(RenewalRequest {
            payer,
            funds_target,
            allowance,
            limit,
            floor,
            expires_at,
            margin: self.margin_nanotos,
            allow_payer_change: self.allow_payer_change,
        })
    }

    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let controller = parse_controller(&self.controller)?;
        let thresholds = self.thresholds.thresholds()?;
        let (operations, global_id) = read(config_path, &controller).await?;
        let now = common::time_format::now();
        anyhow::ensure!(
            !operations.retry_fees_held,
            "retry fees are held for an unfinished relay on this controller; wait for it to finish before renewing"
        );
        anyhow::ensure!(
            operations.authority.nonce < u64::MAX,
            "the controller's root nonce is exhausted"
        );
        let request = self.request(&controller, &operations, now)?;
        let plan = plan_renewal(
            &controller,
            &operations.state,
            &operations.fees,
            operations.relay_pending,
            now,
            &request,
        )?;
        let valid_until = authorization_valid_until(now, self.valid_for)?;
        let assessment = operations.assess(&controller, now, &thresholds)?;
        let rendered = render_plan(&PlanOutput {
            controller: &controller,
            operations: &operations,
            plan: &plan,
            global_id,
            valid_until,
            root_seed: &self.root_seed,
        })?;
        match self.format {
            OutputFormat::Json => {
                let mut value = rendered.json;
                value["current"] =
                    status_json(&controller, &operations, &assessment, &thresholds, now);
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
            OutputFormat::Table => {
                print_status(&controller, &operations, &assessment, now);
                println!("{}", rendered.text);
            }
        }
        Ok(())
    }
}

pub(crate) struct PlanOutput<'a> {
    pub controller: &'a MsgAddressInt,
    pub operations: &'a ControllerOperations,
    pub plan: &'a RenewalPlan,
    pub global_id: i32,
    pub valid_until: u32,
    pub root_seed: &'a str,
}

pub(crate) struct RenderedPlan {
    pub json: serde_json::Value,
    pub text: String,
}

/// The offline signing command and what the payer then sends, exactly as printed.
pub(crate) fn render_plan(output: &PlanOutput<'_>) -> anyhow::Result<RenderedPlan> {
    use base64::Engine;
    let plan = output.plan;
    let authority = &output.operations.authority;
    let payload_b64 =
        base64::engine::general_purpose::STANDARD.encode(chain_block::write_boc(&plan.payload)?);
    let controller_hex = hex::encode(output.controller.address().get_bytestring(0));
    let sign_command = format!(
        "tos-pq-controller fund-operations {} {} {} {} {} {} {}",
        output.root_seed,
        output.global_id,
        controller_hex,
        authority.epoch,
        authority.nonce,
        output.valid_until,
        payload_b64
    );
    let send_command = match u64::try_from(plan.message_value) {
        Ok(value) => format!(
            "tosctl wallet send --from <PAYER_WALLET> --to {} --amount-nanotos {} --body-boc <SIGNED_BODY_B64> --bounce",
            output.controller, value
        ),
        Err(_) => "the message value exceeds what a wallet transfer can carry".to_string(),
    };
    let json = serde_json::json!({
        "controller": output.controller.to_string(),
        "payer": plan.payer.to_string(),
        "deposit": plan.deposit.to_string(),
        "funds_after": plan.funds_after.to_string(),
        "allowance": plan.allowance.to_string(),
        "per_request_limit": plan.limit.to_string(),
        "storage_floor": plan.floor.to_string(),
        "expires_at": plan.expires_at,
        "required_value": plan.required_value.to_string(),
        "message_value": plan.message_value.to_string(),
        "global_id": output.global_id,
        "epoch": authority.epoch,
        "nonce": authority.nonce,
        "valid_until": output.valid_until,
        "payload_boc_base64": payload_b64,
        "sign_command": sign_command.clone(),
        "send_command": send_command.clone(),
    });
    let text = format!(
        "Kind 4 renewal (deposit by deficit; every other field replaces the stored one)\n\
         {rule}\n\
         \x20 Payer:               {payer}\n\
         \x20 Deposit:             {deposit}\n\
         \x20 Funds after:         {funds_after}\n\
         \x20 Allowance:           {allowance}\n\
         \x20 Per-request limit:   {limit}\n\
         \x20 Storage floor:       {floor}\n\
         \x20 Expires at:          {expires}\n\
         \x20 Required value:      {required} (deposit + gas_fee(-1, 200000) + control_value)\n\
         \x20 Message value:       {value}\n\
         \x20 Root epoch / nonce:  {epoch} / {nonce}\n\
         \x20 Valid until:         {valid_until}\n\
         \x20 Payload (kind 4):    {payload_b64}\n\n\
         1. Where the controller root seed is held (offline), run:\n\n\
         \x20  {sign_command}\n\n\
         2. Send its output as the body of a bounceable message from the payer wallet\n\
         \x20  ({payer}) to the controller, with exactly the message value, before\n\
         \x20  valid_until. For a wallet configured in tosctl:\n\n\
         \x20  {send_command}\n\n\
         3. Run `tosctl controller operations status --controller {controller}` and check\n\
         \x20  that the nonce advanced and the recorded values are the ones above.\n",
        rule = "\u{2500}".repeat(72),
        payer = plan.payer,
        deposit = tos(plan.deposit),
        funds_after = tos(plan.funds_after),
        allowance = tos(plan.allowance),
        limit = tos(plan.limit),
        floor = tos(plan.floor),
        expires = plan.expires_at,
        required = tos(plan.required_value),
        value = tos(plan.message_value),
        epoch = authority.epoch,
        nonce = authority.nonce,
        valid_until = output.valid_until,
        controller = output.controller,
    );
    Ok(RenderedPlan { json, text })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Args, Command, FromArgMatches};
    use contracts::validator_controller::{
        ControllerAuthority, OperatingState, RelayFees, plan_renewal,
    };

    const NOW: u64 = 1_791_250_000;

    fn controller() -> MsgAddressInt {
        MsgAddressInt::standard(-1, [0xC0; 32])
    }

    fn payer() -> MsgAddressInt {
        MsgAddressInt::standard(-1, [0xAA; 32])
    }

    fn operations(state: OperatingState) -> ControllerOperations {
        ControllerOperations {
            authority: ControllerAuthority { epoch: 2, nonce: 9, algorithm: 1, key_id: [7; 32] },
            state,
            relay_pending: false,
            retry_fees_held: false,
            balance: 1_000 * NANO,
            fees: RelayFees {
                control_value: 1_000_000_000,
                callback_value: 2_000_000_000,
                grant: 6_000_000_000,
                funding_processing: 3_000_000_000,
            },
            elections_interval_secs: 65_536,
        }
    }

    fn plan_cmd(args: &[&str]) -> ControllerOperationsPlanCmd {
        let command = ControllerOperationsPlanCmd::augment_args(Command::new("plan"));
        let mut argv = vec![
            "plan",
            "--controller",
            "-1:c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
            "--payer",
            "-1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        argv.extend_from_slice(args);
        let matches = command.try_get_matches_from(argv).unwrap();
        ControllerOperationsPlanCmd::from_arg_matches(&matches).unwrap()
    }

    fn funded(funds: u128) -> OperatingState {
        OperatingState {
            funds,
            allowance: funds,
            limit: 20 * NANO,
            floor: 10 * NANO,
            expires: (NOW + DAY) as u32,
            payer: payer(),
        }
    }

    #[test]
    fn default_target_is_the_grants_for_the_target_days() {
        let ops = operations(funded(30 * NANO));
        let request = plan_cmd(&[]).request(&controller(), &ops, NOW).unwrap();
        // 30 days at 65 536 s per election is 40 elections (rounded up).
        assert_eq!(request.funds_target, 40 * 6 * NANO);
        assert_eq!(request.allowance, request.funds_target);
        assert_eq!(request.limit, 20 * NANO, "a limit that admits the grant is kept");
        assert_eq!(request.floor, 10 * NANO, "the floor is kept");
        assert_eq!(u64::from(request.expires_at), NOW + 30 * DAY);
        let plan =
            plan_renewal(&controller(), &ops.state, &ops.fees, false, NOW, &request).unwrap();
        assert_eq!(plan.deposit, 240 * NANO - 30 * NANO);
    }

    #[test]
    fn expiry_only_is_a_zero_deposit_renewal() {
        let ops = operations(funded(30 * NANO));
        let request = plan_cmd(&["--expiry-only", "--expires-in-days", "90"])
            .request(&controller(), &ops, NOW)
            .unwrap();
        assert_eq!(request.funds_target, 30 * NANO);
        assert_eq!(request.allowance, 30 * NANO);
        let plan =
            plan_renewal(&controller(), &ops.state, &ops.fees, false, NOW, &request).unwrap();
        assert_eq!(plan.deposit, 0);
        assert_eq!(u64::from(plan.expires_at), NOW + 90 * DAY);
        assert_eq!(plan.message_value, ops.fees.funding_processing + NANO);
    }

    #[test]
    fn a_first_authorization_needs_an_explicit_floor() {
        let unset = OperatingState {
            funds: 0,
            allowance: 0,
            limit: 0,
            floor: 0,
            expires: 0,
            payer: controller(),
        };
        let ops = operations(unset);
        let refused = plan_cmd(&[]).request(&controller(), &ops, NOW);
        assert!(refused.unwrap_err().to_string().contains("--floor-nanotos"));
        let request =
            plan_cmd(&["--floor-nanotos", "5"]).request(&controller(), &ops, NOW).unwrap();
        assert_eq!(request.floor, 5);
        assert_eq!(request.limit, 12 * NANO, "an unset limit defaults to twice the grant");
    }

    #[test]
    fn expiry_only_conflicts_with_a_funds_target() {
        let command = ControllerOperationsPlanCmd::augment_args(Command::new("plan"));
        let error = command
            .try_get_matches_from([
                "plan",
                "--controller",
                "-1:00",
                "--payer",
                "-1:00",
                "--expiry-only",
                "--funds-target-nanotos",
                "1",
            ])
            .err()
            .map(|error| error.kind());
        assert_eq!(error, Some(clap::error::ErrorKind::ArgumentConflict));
    }

    #[test]
    fn the_offline_command_line_carries_the_live_authority() {
        let ops = operations(funded(30 * NANO));
        let request = plan_cmd(&[]).request(&controller(), &ops, NOW).unwrap();
        let plan =
            plan_renewal(&controller(), &ops.state, &ops.fees, false, NOW, &request).unwrap();
        let rendered = render_plan(&PlanOutput {
            controller: &controller(),
            operations: &ops,
            plan: &plan,
            global_id: -217,
            valid_until: (NOW + 1800) as u32,
            root_seed: "/secure/root.seed",
        })
        .unwrap();
        let sign_command = rendered.json["sign_command"].as_str().unwrap().to_string();
        assert!(rendered.text.contains(&sign_command));
        let parts: Vec<&str> = sign_command.split(' ').collect();
        assert_eq!(parts.len(), 9, "{sign_command}");
        assert_eq!(&parts[..3], ["tos-pq-controller", "fund-operations", "/secure/root.seed"]);
        assert_eq!(parts[3], "-217");
        assert_eq!(parts[4], "c0".repeat(32));
        assert_eq!(parts[5], "2");
        assert_eq!(parts[6], "9");
        assert_eq!(parts[7], (NOW + 1800).to_string());
        use base64::Engine;
        let payload = chain_block::read_single_root_boc(
            base64::engine::general_purpose::STANDARD.decode(parts[8]).unwrap(),
        )
        .unwrap();
        assert_eq!(payload.repr_hash(), plan.payload.repr_hash());
        assert_eq!(rendered.json["message_value"], plan.message_value.to_string());
        assert!(rendered.text.contains("--bounce"));
    }

    #[test]
    fn exact_tos_rendering() {
        assert_eq!(tos(0), "0.000000000 TOS");
        assert_eq!(tos(6_441_234_567), "6.441234567 TOS");
    }
}
