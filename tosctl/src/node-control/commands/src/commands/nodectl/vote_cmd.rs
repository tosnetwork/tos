/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

/// Governance voting commands
#[derive(clap::Args, Clone)]
#[command(about = "Manage governance voting")]
pub struct VoteCmd {
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
    action: VoteAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum VoteAction {
    /// Manage config-proposal offers
    Offer(VoteOfferCmd),
    /// Manage complaints
    Complaint(VoteComplaintCmd),
    /// Manage validator elections
    Election(VoteElectionCmd),
}

// ── Offer ────────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Manage config-proposal offers")]
pub struct VoteOfferCmd {
    #[command(subcommand)]
    action: VoteOfferAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum VoteOfferAction {
    /// List active config-proposal offers
    Ls(VoteOfferLsCmd),
    /// Show diff for a config-proposal offer
    Diff(VoteOfferDiffCmd),
    /// Cast vote on one or more offers
    Cast(VoteOfferCastCmd),
    /// Create a configuration proposal
    Create(VoteOfferCreateCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "List active config-proposal offers")]
pub struct VoteOfferLsCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show diff for a config-proposal offer")]
pub struct VoteOfferDiffCmd {
    #[arg(long, help = "Proposal hash (hex)")]
    hash: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Cast vote on one or more offers")]
pub struct VoteOfferCastCmd {
    /// Proposal hash (hex) to vote on. If omitted, lists proposals and prompts.
    #[arg(long)]
    hash: Option<String>,
}

// ── Offer create ─────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(
    about = "Create a configuration proposal",
    long_about = "Create a configuration proposal for the configuration contract.\n\n\
        The proposal sets parameter --param to the given value (or removes it), for the \
        given lifetime. The storage price is computed from live ConfigParam 11 and checked \
        against the contract's own proposal_storage_price. A parameter listed in \
        ConfigParam 10 needs --critical; one listed in ConfigParam 9 must name the value it \
        replaces (--bind-current or --if-hash-equal), or the contract refuses it.\n\n\
        Without --wallet the message body and the value to send are printed for an \
        external masterchain wallet: the contract ignores a proposal from any other \
        workchain and keeps its value."
)]
pub struct VoteOfferCreateCmd {
    /// Configuration parameter index
    #[arg(long, allow_hyphen_values = true)]
    param: i32,
    /// New value as a standard base64 cell BOC
    #[arg(long, group = "new_value")]
    value_boc: Option<String>,
    /// New value as a BOC file
    #[arg(long, group = "new_value")]
    value_boc_file: Option<std::path::PathBuf>,
    /// Propose removing the parameter
    #[arg(long, group = "new_value")]
    remove: bool,
    /// Proposal lifetime in seconds (at least ConfigParam 11 min_store_sec)
    #[arg(long, default_value_t = 30 * 86_400)]
    expires_in: u32,
    /// Mark the proposal critical (required for a parameter in ConfigParam 10)
    #[arg(long)]
    critical: bool,
    /// Bind the proposal to the parameter's current value hash (0 when absent)
    #[arg(long, conflicts_with = "if_hash_equal")]
    bind_current: bool,
    /// Bind the proposal to this current value hash (64 hex characters)
    #[arg(long)]
    if_hash_equal: Option<String>,
    /// Query id echoed in the contract's answer (default: current unix time)
    #[arg(long)]
    query_id: Option<u64>,
    /// Value in nanoTOS sent above price + 2^30; the contract returns the change
    #[arg(long, default_value_t = 1_000_000_000)]
    margin_nanotos: u64,
    /// Masterchain wallet from config that sends the proposal; prints the message otherwise
    #[arg(long)]
    wallet: Option<String>,
    /// Confirm sending non-interactively
    #[arg(long)]
    yes: bool,
    /// Do not require the new value to decode as the parameter's known type
    #[arg(long)]
    skip_value_check: bool,
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

/// A proposal message, priced, ready to send or to hand to an external wallet.
pub(crate) struct PreparedProposal {
    pub body: chain_block::Cell,
    pub proposal_hash: [u8; 32],
    pub critical: bool,
    pub stored_secs: u32,
    pub bits: u64,
    pub refs: u64,
    pub price: u128,
    pub value: u128,
}

/// What the live configuration says about one parameter.
pub(crate) struct ParameterRules {
    pub critical: bool,
    pub mandatory: bool,
    pub setup: chain_block::ConfigProposalSetup,
}

/// Refuses a value that does not decode as the type this tool knows for the parameter.
/// The contract registers any cell; a malformed one would be voted on and then either
/// refused at installation or installed as a parameter the node cannot read.
pub(crate) fn check_value_shape(param_id: i32, value: &chain_block::Cell) -> anyhow::Result<()> {
    let Ok(index) = u32::try_from(param_id) else {
        return Ok(());
    };
    let refuse = |why: String| {
        anyhow::anyhow!(
            "the new value does not decode as ConfigParam {param_id}: {why}; pass \
             --skip-value-check to propose it anyway"
        )
    };
    let parsed = chain_block::ConfigParamEnum::construct_from_cell_and_number(value.clone(), index)
        .map_err(|e| refuse(e.to_string()))?;
    // Decoding stops at the fields it knows; only a value that re-encodes to the same
    // cell carries nothing else.
    let mut builder = chain_block::BuilderData::new();
    parsed.write_to_cell(&mut builder).map_err(|e| refuse(e.to_string()))?;
    let reencoded = builder.into_cell()?.reference(0)?;
    anyhow::ensure!(
        reencoded.repr_hash() == value.repr_hash(),
        refuse(
            "it carries data beyond, or encoded differently from, that parameter's fields".into()
        )
    );
    Ok(())
}

/// The proposal an operator asks for.
pub(crate) struct ProposalRequest {
    pub param_id: i32,
    /// `None` proposes removing the parameter.
    pub value: Option<chain_block::Cell>,
    pub if_hash_equal: Option<[u8; 32]>,
    pub critical: bool,
    pub ttl_secs: u32,
    pub query_id: u64,
    pub margin: u64,
}

/// Builds and prices the proposal, refusing locally what the contract would refuse.
pub(crate) fn prepare_proposal(
    request: ProposalRequest,
    rules: &ParameterRules,
) -> anyhow::Result<PreparedProposal> {
    use contracts::config_contract::messages::proposal;
    let ProposalRequest { param_id, value, if_hash_equal, critical, ttl_secs, query_id, margin } =
        request;
    anyhow::ensure!(
        !rules.critical || critical,
        "parameter {param_id} is critical (ConfigParam 10); pass --critical"
    );
    if rules.mandatory {
        anyhow::ensure!(
            value.is_some(),
            "parameter {param_id} is mandatory (ConfigParam 9) and cannot be removed"
        );
        anyhow::ensure!(
            if_hash_equal.is_some(),
            "parameter {param_id} is mandatory (ConfigParam 9): the contract refuses a \
             proposal for it that does not name the value it replaces; pass --bind-current \
             or --if-hash-equal"
        );
    }
    let (price, stored_secs) = proposal::storage_price(&rules.setup, value.as_ref(), ttl_secs)?;
    let (_, bits, refs) = proposal::value_size(value.as_ref())?;
    let cell = proposal::proposal_cell(param_id, value, if_hash_equal)?;
    let mut proposal_hash = [0u8; 32];
    proposal_hash.copy_from_slice(cell.repr_hash().as_slice());
    let body = proposal::new_proposal_body(query_id, ttl_secs, cell, critical)?;
    let value = price
        .checked_add(proposal::MIN_VALUE_ABOVE_PRICE)
        .and_then(|value| value.checked_add(u128::from(margin)))
        .ok_or_else(|| anyhow::anyhow!("proposal value overflows"))?;
    Ok(PreparedProposal { body, proposal_hash, critical, stored_secs, bits, refs, price, value })
}

impl VoteOfferCreateCmd {
    fn new_value(&self) -> anyhow::Result<Option<chain_block::Cell>> {
        use base64::Engine;
        let bytes = match (&self.value_boc, &self.value_boc_file, self.remove) {
            (Some(encoded), None, false) => base64::engine::general_purpose::STANDARD
                .decode(encoded.trim())
                .map_err(|e| anyhow::anyhow!("--value-boc is not base64: {e}"))?,
            (None, Some(path), false) => {
                std::fs::read(path).map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?
            }
            (None, None, true) => return Ok(None),
            _ => anyhow::bail!(
                "exactly one of --value-boc, --value-boc-file or --remove is required"
            ),
        };
        Ok(Some(chain_block::read_single_root_boc(bytes)?))
    }

    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::{
            SEND_TIMEOUT, get_wallet_config, load_config_vault_rpc_client, make_wallet,
            try_create_rpc_client, wait_for_seqno_change, wallet_info,
        };
        use anyhow::Context;
        use base64::Engine;
        use chain_block::{ConfigParamEnum, MsgAddressInt, write_boc};
        use colored::Colorize;
        use common::app_config::AppConfig;
        use contracts::{ChainProvider, DefaultChainProvider, Wallet};
        use std::path::Path;

        let value = self.new_value()?;
        if let (Some(cell), false) = (&value, self.skip_value_check) {
            check_value_shape(self.param, cell)?;
        }
        let if_hash_equal = match &self.if_hash_equal {
            Some(text) => {
                let bytes = hex::decode(text.trim_start_matches("0x"))
                    .map_err(|e| anyhow::anyhow!("--if-hash-equal is not hex: {e}"))?;
                let hash: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("--if-hash-equal must be 32 bytes"))?;
                Some(hash)
            }
            None => None,
        };

        let config = AppConfig::load(Path::new(config_path))?;
        let rpc_client = try_create_rpc_client(&config).await?;
        let chain = DefaultChainProvider::new(rpc_client.clone());

        let config_address = match chain.get_config_param(0).await? {
            ConfigParamEnum::ConfigParam0(param) => {
                MsgAddressInt::with_standart(None, -1, param.config_addr)?
            }
            other => anyhow::bail!("live ConfigParam 0 has unexpected representation: {other:?}"),
        };
        let contains = |param: ConfigParamEnum| -> anyhow::Result<bool> {
            Ok(match param {
                ConfigParamEnum::ConfigParam9(value) => {
                    value.mandatory_params.get(&self.param)?.is_some()
                }
                ConfigParamEnum::ConfigParam10(value) => {
                    value.critical_params.get(&self.param)?.is_some()
                }
                other => anyhow::bail!("unexpected configuration parameter: {other:?}"),
            })
        };
        let mandatory = contains(chain.get_config_param(9).await?)?;
        let critical_param = contains(chain.get_config_param(10).await?)?;
        let critical = self.critical || critical_param;
        let setup = match chain.get_config_param(11).await? {
            ConfigParamEnum::ConfigParam11(value) => {
                if critical {
                    value.read_critical_params()?
                } else {
                    value.read_normal_params()?
                }
            }
            other => anyhow::bail!("live ConfigParam 11 has unexpected representation: {other:?}"),
        };
        let if_hash_equal = if self.bind_current {
            let index = u32::try_from(self.param).map_err(|_| {
                anyhow::anyhow!(
                    "--bind-current reads only non-negative parameters; pass --if-hash-equal"
                )
            })?;
            match chain.get_optional_config_param(index).await? {
                None => Some([0u8; 32]),
                Some(_) => {
                    let current = chain.get_config_param_cell(index).await?;
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(current.repr_hash().as_slice());
                    Some(hash)
                }
            }
        } else {
            if_hash_equal
        };

        let prepared = prepare_proposal(
            ProposalRequest {
                param_id: self.param,
                value,
                if_hash_equal,
                critical: self.critical,
                ttl_secs: self.expires_in,
                query_id: self.query_id.unwrap_or_else(common::time_format::now),
                margin: self.margin_nanotos,
            },
            &ParameterRules { critical: critical_param, mandatory, setup },
        )?;

        // The contract's own price for the same inputs: a disagreement means this
        // tool and the deployed contract read the configuration differently.
        let quoted = chain
            .run_get_method(
                config_address.to_string(),
                "proposal_storage_price",
                vec![
                    contracts::stack_utils::i64_to_stack_entry(if prepared.critical {
                        -1
                    } else {
                        0
                    }),
                    contracts::stack_utils::i64_to_stack_entry(i64::from(self.expires_in)),
                    contracts::stack_utils::i64_to_stack_entry(i64::try_from(prepared.bits)?),
                    contracts::stack_utils::i64_to_stack_entry(i64::try_from(prepared.refs)?),
                ],
            )
            .await?
            .decimal_string(0)?
            .parse::<u128>()
            .context("proposal_storage_price")?;
        anyhow::ensure!(
            quoted == prepared.price,
            "the configuration contract quotes {quoted} nanoTOS for this proposal and this tool computed {}",
            prepared.price
        );

        let body_b64 = base64::engine::general_purpose::STANDARD.encode(write_boc(&prepared.body)?);
        let value = u64::try_from(prepared.value).context("proposal value exceeds u64")?;
        let summary = ProposalSummary {
            config_contract: config_address.to_string(),
            param_id: self.param,
            prepared: &prepared,
            value,
            body_b64: body_b64.clone(),
        };
        let json = self.format == super::output_format::OutputFormat::Json;
        if !json {
            println!();
            println!("{}", "Configuration proposal".bold());
            println!("{}", "\u{2500}".repeat(72));
            println!("  {:<20} {}", "Config contract:", config_address);
            println!("  {:<20} {}", "Parameter:", self.param);
            println!("  {:<20} {}", "Critical:", prepared.critical);
            println!("  {:<20} {} s", "Stored for:", prepared.stored_secs);
            println!("  {:<20} {} nanoTOS", "Storage price:", prepared.price);
            println!("  {:<20} {} nanoTOS", "Value to send:", value);
            println!("  {:<20} {}", "Proposal hash:", hex::encode(prepared.proposal_hash));
            println!("  {:<20} {}", "Body (base64):", body_b64);
            println!();
        }

        let Some(wallet_name) = &self.wallet else {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary.report(ProposalOutcome::Prepared, None))?
                );
            } else {
                println!(
                    "  Send the body to {} with exactly {} nanoTOS from a masterchain wallet\n  \
                     (bounceable), with enough left over for the wallet's own fees. The contract\n  \
                     answers 0xee565052 when the proposal is registered; confirm with\n  \
                     `tosctl vote offer diff --hash {}`.\n",
                    config_address,
                    value,
                    hex::encode(prepared.proposal_hash)
                );
            }
            return Ok(());
        };

        let (config, vault, rpc_client) =
            load_config_vault_rpc_client(Path::new(config_path)).await?;
        let wallet_cfg =
            get_wallet_config(wallet_name, &config.wallets, config.master_wallet.as_ref())?;
        let (wallet_address, info, secret) =
            wallet_info(rpc_client.clone(), wallet_cfg, vault).await?;
        anyhow::ensure!(
            wallet_address.workchain_id() == -1,
            "wallet '{wallet_name}' is on workchain {}; the configuration contract only hears \
             masterchain senders and would keep the value",
            wallet_address.workchain_id()
        );
        let reserve = sender_fee_reserve(
            &chain.get_config_param(20).await?,
            &chain.get_config_param(24).await?,
            &prepared.body,
        )?;
        sender_can_pay(wallet_name, info.balance, value, reserve)?;
        if !self.yes {
            // The prompt goes to stderr so that stdout carries only the report.
            eprint!("Send {value} nanoTOS from '{wallet_name}' to register this proposal? [y/N] ");
            std::io::Write::flush(&mut std::io::stderr())?;
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim(), "y" | "Y" | "yes" | "Yes") {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &summary.report(ProposalOutcome::Cancelled, None)
                        )?
                    );
                } else {
                    println!("{}", "Cancelled".yellow());
                }
                return Ok(());
            }
        }
        let prior = proposal_expiry(&chain, &config_address, &prepared.proposal_hash).await?;
        let wallet = make_wallet(rpc_client.clone(), wallet_cfg, secret, wallet_name).await?;
        let message = wallet
            .build_message(
                config_address.clone(),
                value,
                prepared.body.clone(),
                true,
                None,
                None,
                None,
            )
            .await?;
        rpc_client.send_boc(&write_boc(&message)?).await?;
        // A seqno change shows only that the wallet accepted the external message: the
        // wallet sends in a mode that ignores action errors, so the proposal itself is
        // confirmed by reading it back from the configuration contract.
        wait_for_seqno_change(
            rpc_client.clone(),
            &wallet_address,
            info.seqno,
            &common::task_cancellation::CancellationCtx::default(),
            SEND_TIMEOUT,
        )
        .await?;
        let mut registered = None;
        for _ in 0..REGISTRATION_POLLS {
            let current = proposal_expiry(&chain, &config_address, &prepared.proposal_hash).await?;
            if registration_confirmed(prior, current) {
                registered = current;
                break;
            }
            tokio::time::sleep(REGISTRATION_POLL_INTERVAL).await;
        }
        let outcome = if registered.is_some() {
            ProposalOutcome::Registered
        } else {
            ProposalOutcome::WalletAcceptedUnconfirmed
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&summary.report(outcome, registered))?);
        } else if let Some(expires) = registered {
            println!(
                "{} Proposal registered (expires {expires}); hash {}",
                "OK".green().bold(),
                hex::encode(prepared.proposal_hash)
            );
        } else {
            println!(
                "{} The wallet accepted the message, but the configuration contract does not show \
                 the proposal yet; check `tosctl vote offer diff --hash {}`",
                "UNCONFIRMED".yellow().bold(),
                hex::encode(prepared.proposal_hash)
            );
        }
        anyhow::ensure!(
            outcome == ProposalOutcome::Registered,
            "the proposal was not seen registered within the wait"
        );
        Ok(())
    }
}

const REGISTRATION_POLLS: usize = 15;
const REGISTRATION_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
/// An upper bound for a wallet's own computation when it sends one message.
const WALLET_SEND_GAS_BOUND: u64 = 20_000;
/// Bits of envelope around a body: the external message (signature and wallet
/// header) and the outbound internal message header, generously.
const ENVELOPE_BITS: u64 = 1_600;

/// What `vote offer create` did, as reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProposalOutcome {
    /// Built and priced; nothing was sent.
    Prepared,
    /// The operator declined to send.
    Cancelled,
    /// The configuration contract holds the proposal.
    Registered,
    /// The wallet's seqno advanced, but the proposal was not seen in the contract.
    WalletAcceptedUnconfirmed,
}

impl ProposalOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Cancelled => "cancelled",
            Self::Registered => "registered",
            Self::WalletAcceptedUnconfirmed => "wallet_accepted_unconfirmed",
        }
    }
}

pub(crate) struct ProposalSummary<'a> {
    pub config_contract: String,
    pub param_id: i32,
    pub prepared: &'a PreparedProposal,
    pub value: u64,
    pub body_b64: String,
}

impl ProposalSummary<'_> {
    /// The one JSON document the command prints, once its outcome is known.
    pub(crate) fn report(
        &self,
        outcome: ProposalOutcome,
        registered_expires: Option<u32>,
    ) -> serde_json::Value {
        serde_json::json!({
            "status": outcome.as_str(),
            "broadcast": matches!(
                outcome,
                ProposalOutcome::Registered | ProposalOutcome::WalletAcceptedUnconfirmed
            ),
            "registered_expires": registered_expires,
            "config_contract": self.config_contract,
            "param_id": self.param_id,
            "critical": self.prepared.critical,
            "stored_secs": self.prepared.stored_secs,
            "value_bits": self.prepared.bits,
            "value_refs": self.prepared.refs,
            "price_nanotos": self.prepared.price.to_string(),
            "value_nanotos": self.value,
            "proposal_hash": hex::encode(self.prepared.proposal_hash),
            "body_boc_base64": self.body_b64,
        })
    }
}

/// What the sending wallet spends besides the value: its own computation and the
/// forwarding of the external and the outbound message, at live masterchain prices.
pub(crate) fn sender_fee_reserve(
    param20: &chain_block::ConfigParamEnum,
    param24: &chain_block::ConfigParamEnum,
    body: &chain_block::Cell,
) -> anyhow::Result<u128> {
    use chain_block::ConfigParamEnum;
    use contracts::validator_controller::{forward_fee, gas_fee};
    let ConfigParamEnum::ConfigParam20(gas) = param20 else {
        anyhow::bail!("live ConfigParam 20 has unexpected representation");
    };
    let ConfigParamEnum::ConfigParam24(forward) = param24 else {
        anyhow::bail!("live ConfigParam 24 has unexpected representation");
    };
    let (cells, bits, _) = contracts::config_contract::messages::proposal::value_size(Some(body))?;
    let message_bits =
        bits.checked_add(ENVELOPE_BITS).ok_or_else(|| anyhow::anyhow!("size overflows"))?;
    let message_cells = cells.checked_add(2).ok_or_else(|| anyhow::anyhow!("size overflows"))?;
    let one_message = forward_fee(forward, message_bits, message_cells)?;
    gas_fee(gas, WALLET_SEND_GAS_BOUND)?
        .checked_add(one_message)
        .and_then(|sum| sum.checked_add(one_message))
        .ok_or_else(|| anyhow::anyhow!("fee reserve overflows"))
}

/// The wallet must hold the value and its own fees.
pub(crate) fn sender_can_pay(
    wallet_name: &str,
    balance: u64,
    value: u64,
    reserve: u128,
) -> anyhow::Result<()> {
    let needed = u128::from(value)
        .checked_add(reserve)
        .ok_or_else(|| anyhow::anyhow!("required balance overflows"))?;
    anyhow::ensure!(
        u128::from(balance) >= needed,
        "wallet '{wallet_name}' holds {balance} nanoTOS; the proposal needs {value} plus about \
         {reserve} in the wallet's own fees ({needed} in all)"
    );
    Ok(())
}

/// The expiry of a proposal the configuration contract holds, or `None`.
async fn proposal_expiry(
    chain: &contracts::DefaultChainProvider,
    config_address: &chain_block::MsgAddressInt,
    proposal_hash: &[u8; 32],
) -> anyhow::Result<Option<u32>> {
    use contracts::ChainProvider;
    let stack = chain
        .run_get_method(
            config_address.to_string(),
            "get_proposal",
            vec![contracts::stack_utils::bytes_to_stack_entry(proposal_hash)],
        )
        .await?;
    if stack.stack.is_empty() || contracts::validator_controller::stack_entry_is_null(&stack, 0)? {
        return Ok(None);
    }
    let expires = stack.tuple(0)?.u64(0)?;
    Ok(Some(u32::try_from(expires)?))
}

/// Registered by this request: present now, and either new or extended beyond the
/// expiry it had before.
pub(crate) fn registration_confirmed(prior: Option<u32>, current: Option<u32>) -> bool {
    match (prior, current) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(before), Some(after)) => after > before,
    }
}

// ── Complaint ────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Manage complaints")]
pub struct VoteComplaintCmd {
    #[command(subcommand)]
    action: VoteComplaintAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum VoteComplaintAction {
    /// List active complaints
    Ls(VoteComplaintLsCmd),
    /// Cast complaint vote
    Cast(VoteComplaintCastCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "List active complaints")]
pub struct VoteComplaintLsCmd {}

#[derive(clap::Args, Clone)]
#[command(about = "Cast complaint vote")]
pub struct VoteComplaintCastCmd {
    /// Election ID of the past election containing the complaint
    #[arg(long)]
    election_id: u32,
    /// Complaint hash (hex, 64 chars / 32 bytes)
    #[arg(long)]
    complaint_hash: String,
}

// ── Election ─────────────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
#[command(about = "Manage validator elections")]
pub struct VoteElectionCmd {
    #[command(subcommand)]
    action: VoteElectionAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum VoteElectionAction {
    /// List election entries
    Ls(VoteElectionLsCmd),
    /// Enter election
    Cast(VoteElectionCastCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "List election entries")]
pub struct VoteElectionLsCmd {
    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: super::output_format::OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Enter election")]
pub struct VoteElectionCastCmd {
    /// Dry-run mode: query election status without actually casting a vote
    #[arg(long, default_value = "false")]
    dry_run: bool,
    /// Max factor for election bid (1.0 to 3.0)
    #[arg(long, default_value = "3.0")]
    max_factor: f32,
    /// Stake amount in TOS (whole units). If omitted, uses the minimum stake from elector.
    #[arg(long)]
    stake: Option<u64>,
    /// Wallet name from config to use for sending the bid. Defaults to first node's wallet.
    #[arg(long)]
    wallet: Option<String>,
}

// ── run() dispatch ───────────────────────────────────────────────────

impl VoteCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        match &self.action {
            VoteAction::Offer(cmd) => cmd.run(&self.config).await,
            VoteAction::Complaint(cmd) => cmd.run(&self.config).await,
            VoteAction::Election(cmd) => cmd.run(&self.config).await,
        }
    }

    /// Shortcut entry point for `tosctl ol` (vote offer ls).
    pub async fn run_offer_ls_shortcut() -> anyhow::Result<()> {
        let config_path =
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "tosctl-config.json".into());
        let cmd = VoteOfferLsCmd { format: super::output_format::OutputFormat::Table };
        cmd.run(&config_path).await
    }

    /// Shortcut entry point for `tosctl el` (vote election ls).
    pub async fn run_election_ls_shortcut() -> anyhow::Result<()> {
        let config_path =
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "tosctl-config.json".into());
        let cmd = VoteElectionLsCmd { format: super::output_format::OutputFormat::Table };
        cmd.run(&config_path).await
    }
}

impl VoteOfferCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            VoteOfferAction::Ls(cmd) => cmd.run(config_path).await,
            VoteOfferAction::Diff(cmd) => cmd.run(config_path).await,
            VoteOfferAction::Cast(cmd) => cmd.run(config_path).await,
            VoteOfferAction::Create(cmd) => cmd.run(config_path).await,
        }
    }
}

impl VoteOfferLsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::try_create_rpc_client;
        use colored::Colorize;
        use common::app_config::AppConfig;
        use common::time_format::format_ts;
        use contracts::{
            ConfigContractImpl, ConfigContractWrapper, DefaultChainProvider, contract_provider_from,
        };
        use std::path::Path;
        use std::sync::Arc;

        let config_path = Path::new(config_path);

        let config = AppConfig::load(config_path)?;
        let rpc_client = try_create_rpc_client(&config).await?;

        if self.format != super::output_format::OutputFormat::Json {
            println!("\n{}", "Querying config contract for proposals...".cyan());
        }

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let wrapper = ConfigContractImpl::new(contract_provider_from(chain_provider));

        let proposals = wrapper.list_proposals().await?;

        if proposals.is_empty() {
            if self.format == super::output_format::OutputFormat::Json {
                println!("[]");
            } else {
                println!("\n{}\n", "No active config proposals.".yellow());
            }
            return Ok(());
        }

        if self.format == super::output_format::OutputFormat::Json {
            let views: Vec<serde_json::Value> = proposals
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "param_id": p.param.id,
                        "is_critical": p.is_critical,
                        "expires": format_ts(p.expires as u64),
                        "voters": p.voters.len(),
                        "weight_remaining": p.weight_remaining,
                        "hash": hex::encode(p.hash),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&views)?);
        } else {
            println!();
            println!("{}", "Config Proposals".bold());
            println!("{}", "\u{2500}".repeat(80));
            println!(
                "  {:<4} {:<8} {:<11} {:<22} {:<9} {}",
                "#".bold(),
                "Param".bold(),
                "Critical".bold(),
                "Expires".bold(),
                "Voters".bold(),
                "Weight Remaining".bold(),
            );
            println!("  {}", "\u{2500}".repeat(76));

            for (i, p) in proposals.iter().enumerate() {
                let critical = if p.is_critical { "Yes" } else { "No" };
                let expires = format_ts(p.expires as u64);
                println!(
                    "  {:<4} {:<8} {:<11} {:<22} {:<9} {}",
                    i + 1,
                    p.param.id,
                    critical,
                    expires,
                    p.voters.len(),
                    p.weight_remaining,
                );
            }

            println!();
        }
        Ok(())
    }
}

impl VoteOfferDiffCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::try_create_rpc_client;
        use colored::Colorize;
        use common::app_config::AppConfig;
        use common::time_format::format_ts;
        use contracts::{
            ConfigContractImpl, ConfigContractWrapper, DefaultChainProvider, contract_provider_from,
        };
        use std::path::Path;
        use std::sync::Arc;

        let config_path = Path::new(config_path);

        let config = AppConfig::load(config_path)?;
        let rpc_client = try_create_rpc_client(&config).await?;

        let hash_bytes_vec = hex::decode(self.hash.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid hex hash: {}", e))?;
        if hash_bytes_vec.len() != 32 {
            anyhow::bail!(
                "Proposal hash must be 32 bytes (64 hex chars), got {}",
                hash_bytes_vec.len()
            );
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash_bytes_vec);

        println!("\n{}", "Querying config contract for proposal...".cyan());

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let wrapper = ConfigContractImpl::new(contract_provider_from(chain_provider));

        let proposal = wrapper.get_proposal(hash_bytes).await?;

        match proposal {
            None => {
                println!("\n{}\n", "Proposal not found.".yellow());
            }
            Some(p) => {
                println!();
                println!("{}", "Proposal Details".bold());
                println!("{}", "\u{2500}".repeat(60));
                println!("  {:<20} {}", "Hash:".bold(), self.hash);
                println!("  {:<20} {}", "Param ID:".bold(), p.param.id);
                println!(
                    "  {:<20} {}",
                    "Critical:".bold(),
                    if p.is_critical { "Yes".red().to_string() } else { "No".green().to_string() }
                );
                println!("  {:<20} {}", "Expires:".bold(), format_ts(p.expires as u64));
                println!("  {:<20} {}", "Voters:".bold(), p.voters.len());
                println!("  {:<20} {}", "Weight remaining:".bold(), p.weight_remaining);
                println!("  {:<20} {}", "Rounds remaining:".bold(), p.rounds_remaining);
                println!("  {:<20} W={} / L={}", "Wins / Losses:".bold(), p.wins, p.losses);
                println!();
                if p.param.cell.is_some() {
                    println!(
                        "  {}",
                        "New cell value: present (param has a proposed value)".green()
                    );
                } else {
                    println!("  {}", "New cell value: none (param deletion or reset)".yellow());
                }
                if let Some(h) = p.param.hash {
                    println!("  {:<20} {}", "Param hash:".bold(), hex::encode(h));
                }
                println!();
            }
        }

        Ok(())
    }
}

impl VoteOfferCastCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::{load_config_vault_rpc_client, make_wallet, wallet_info};
        use anyhow::Context;
        use chain_block::write_boc;
        use colored::Colorize;
        use common::time_format::format_ts;
        use contracts::{
            ConfigContractImpl, ConfigContractWrapper, DefaultChainProvider, SmartContract, Wallet,
            contract_provider_from,
        };
        use control_client::{
            client_adnl::ControlClientAdnl, client_api::ClientAPI,
            config_params::parse_config_param_34,
        };
        use std::path::Path;
        use std::sync::Arc;

        let config_path = Path::new(config_path);

        let (config, vault, rpc_client) = load_config_vault_rpc_client(config_path).await?;

        println!("\n{}", "Querying config contract for proposals...".cyan());

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let wrapper = ConfigContractImpl::new(contract_provider_from(chain_provider));

        let proposals = wrapper.list_proposals().await?;

        if proposals.is_empty() {
            println!("\n{}\n", "No active proposals to vote on.".yellow());
            return Ok(());
        }

        // Determine which proposal to vote on
        let target_hash: Option<[u8; 32]> = if let Some(ref hash_str) = self.hash {
            let hash_bytes_vec = hex::decode(hash_str.trim_start_matches("0x"))
                .map_err(|e| anyhow::anyhow!("Invalid hex hash: {}", e))?;
            if hash_bytes_vec.len() != 32 {
                anyhow::bail!(
                    "Proposal hash must be 32 bytes (64 hex chars), got {}",
                    hash_bytes_vec.len()
                );
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash_bytes_vec);
            Some(arr)
        } else {
            None
        };

        // Display proposals
        println!();
        println!("{}", "Active Config Proposals".bold());
        println!("{}", "\u{2500}".repeat(80));
        println!(
            "  {:<4} {:<8} {:<11} {:<22} {:<9} {}",
            "#".bold(),
            "Param".bold(),
            "Critical".bold(),
            "Expires".bold(),
            "Voters".bold(),
            "Hash (first 16 hex)".bold(),
        );
        println!("  {}", "\u{2500}".repeat(76));

        for (i, p) in proposals.iter().enumerate() {
            let critical = if p.is_critical { "Yes" } else { "No" };
            let expires = format_ts(p.expires as u64);
            let hash_short = hex::encode(&p.hash[..8]);
            println!(
                "  {:<4} {:<8} {:<11} {:<22} {:<9} {}...",
                i + 1,
                p.param.id,
                critical,
                expires,
                p.voters.len(),
                hash_short,
            );
        }
        println!();

        // Find the target proposal
        let proposal = if let Some(ref target) = target_hash {
            proposals.iter().find(|p| p.hash == *target)
        } else {
            // If only one proposal, use it; otherwise require --hash
            if proposals.len() == 1 {
                Some(&proposals[0])
            } else {
                println!(
                    "  {}",
                    "Multiple proposals found. Use --hash to specify which one to vote on."
                        .yellow()
                );
                println!();
                return Ok(());
            }
        };

        let proposal = match proposal {
            Some(p) => p,
            None => {
                println!(
                    "  {}",
                    "Proposal with specified hash not found among active proposals.".yellow()
                );
                println!();
                return Ok(());
            }
        };

        println!(
            "  Target proposal: param {} (hash={})",
            proposal.param.id,
            hex::encode(proposal.hash)
        );

        // --- Connect to node via ADNL control ---
        println!("\n{}", "Connecting to validator node...".cyan());
        let (node_name, node_cfg) =
            config.nodes.iter().next().ok_or_else(|| anyhow::anyhow!("No nodes configured"))?;
        let adnl_config = node_cfg.to_node_adnl_config(None).await?;
        let mut client = ControlClientAdnl::new(adnl_config, 1);
        client.connect().await.context("Failed to connect to validator node via ADNL")?;
        println!("  {} Connected to node '{}'", "OK".green().bold(), node_name);

        // --- Get current validator set (config param 34) ---
        println!("{}", "Fetching current validator set...".cyan());
        let vset_bytes = client.get_config_param(34).await.context("get config param 34")?;
        let vset = parse_config_param_34(&vset_bytes)?;

        // --- Get validator config to find our key ---
        let validator_config =
            client.get_validator_config().await.context("get_validator_config")?;

        // Search through recent validator keys to find one in the current vset
        let mut validators_sorted = validator_config.validators.clone();
        validators_sorted.sort_by_key(|v| v.election_date);

        let mut found_idx: Option<u16> = None;
        let mut found_key_id: Option<Vec<u8>> = None;

        // Check the last 3 election keys (same strategy as voting_task.rs)
        let check_count = validators_sorted.len().min(3);
        for validator in validators_sorted.iter().rev().take(check_count) {
            let public_key = match client.export_key_pub(&validator.id).await {
                Ok(pk) => pk,
                Err(_) => continue,
            };
            let mut key = [0u8; 32];
            if public_key.len() >= 32 {
                key.copy_from_slice(&public_key[..32]);
            } else {
                continue;
            }
            // Search for this public key in the current validator set
            if let Some(idx) = vset
                .list()
                .iter()
                .position(|item| item.public_key().is_ok_and(|pk| pk.as_slice() == &key))
            {
                found_idx = Some(idx as u16);
                found_key_id = Some(validator.id.clone());
                println!(
                    "  {} Found validator at index {} (pubkey={})",
                    "OK".green().bold(),
                    idx,
                    hex::encode(&key)
                );
                break;
            }
        }

        let validator_idx = found_idx.ok_or_else(|| {
            anyhow::anyhow!(
                "This node is not in the current validator set (config param 34). \
                 Only active validators can vote on config proposals."
            )
        })?;
        let key_id = found_key_id.unwrap();

        // Check if we already voted
        if proposal.voters.contains(&validator_idx) {
            println!(
                "\n{} Already voted for this proposal (validator index {}).",
                "OK".green().bold(),
                validator_idx
            );
            println!();
            return Ok(());
        }

        // --- Build and sign the vote ---
        let _ = (&client, &key_id);
        anyhow::bail!(
            "a configuration vote is authorised by the current post-quantum validator set, \
             and producing one needs two things this node cannot yet supply: a signature \
             from its ML-DSA-44 consensus key, and the hash of the stored ConfigParam 34 \
             cell that the vote is bound to. The control protocol carries neither, so the \
             vote is not sent rather than sent in a form the chain refuses"
        );

        #[allow(unreachable_code)]
        let vote_body: chain_block::Cell = unreachable!();

        // --- Send via wallet ---
        println!("{}", "Sending vote transaction...".cyan());
        let wallet_name = node_name;
        let wallet_cfg = config
            .wallets
            .get(wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

        let (_wallet_address, _wallet_info_res, secret) =
            wallet_info(rpc_client.clone(), wallet_cfg, vault.clone()).await?;

        let wallet = make_wallet(rpc_client.clone(), wallet_cfg, secret, wallet_name).await?;

        let config_addr = wrapper.address();
        let send_value = 1_000_000_000u64; // 1 TOS for gas
        let msg_cell = wallet.message(config_addr, send_value, vote_body).await?;
        let boc = write_boc(&msg_cell)?;
        client.send_boc(&boc).await.context("send vote BOC")?;

        println!("\n{} Vote cast successfully!", "OK".green().bold());
        println!("  Proposal hash:    {}", hex::encode(proposal.hash));
        println!("  Param ID:         {}", proposal.param.id);
        println!("  Validator index:  {}", validator_idx);
        println!();
        println!("  {}", "Use 'tosctl vote offer ls' to verify your vote is recorded.".dimmed());
        println!();

        Ok(())
    }
}

impl VoteComplaintCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            VoteComplaintAction::Ls(cmd) => cmd.run(config_path).await,
            VoteComplaintAction::Cast(cmd) => cmd.run(config_path).await,
        }
    }
}

impl VoteComplaintLsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::try_create_rpc_client;
        use colored::Colorize;
        use common::app_config::AppConfig;
        use common::chain_utils::display_tos;
        use common::time_format::format_ts;
        use contracts::{
            DefaultChainProvider, ElectorWrapper, ElectorWrapperImpl, contract_provider_from,
        };
        use std::path::Path;
        use std::sync::Arc;

        let config_path = Path::new(config_path);

        let config = AppConfig::load(config_path)?;
        let rpc_client = try_create_rpc_client(&config).await?;

        println!("\n{}", "Querying elector for past elections (complaint data)...".cyan());

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let elector = ElectorWrapperImpl::new(contract_provider_from(chain_provider));

        let past = elector.past_elections().await?;

        if past.is_empty() {
            println!("\n{}\n", "No past elections found.".yellow());
            return Ok(());
        }

        println!();
        println!("{}", "Past Elections (Complaint Context)".bold());
        println!("{}", "\u{2500}".repeat(80));
        println!(
            "  {:<4} {:<14} {:<22} {:<16} {:<8} {}",
            "#".bold(),
            "Election ID".bold(),
            "Unfreeze At".bold(),
            "Total Stake".bold(),
            "Frozen".bold(),
            "Banned".bold(),
        );
        println!("  {}", "\u{2500}".repeat(76));

        for (i, election) in past.iter().enumerate() {
            let banned_count = election.frozen_map.values().filter(|f| f.banned).count();
            println!(
                "  {:<4} {:<14} {:<22} {:<16} {:<8} {}",
                i + 1,
                election.election_id,
                format_ts(election.unfreeze_at),
                display_tos(election.total_stake),
                election.frozen_map.len(),
                banned_count,
            );
        }

        // Show banned validators if any exist
        let has_banned = past.iter().any(|e| e.frozen_map.values().any(|f| f.banned));
        if has_banned {
            println!();
            println!("  {}", "Banned Validators".bold().red());
            println!("  {}", "\u{2500}".repeat(76));
            for election in &past {
                for (pubkey, frozen) in &election.frozen_map {
                    if frozen.banned {
                        let pubkey_hex: String =
                            pubkey.iter().map(|b| format!("{:02x}", b)).collect();
                        let wallet_hex: String =
                            frozen.wallet_addr.iter().map(|b| format!("{:02x}", b)).collect();
                        println!(
                            "  Election {}: pubkey={}... wallet={}... stake={} TOS",
                            election.election_id,
                            &pubkey_hex[..16],
                            &wallet_hex[..16],
                            display_tos(frozen.stake),
                        );
                    }
                }
            }
        }

        println!();
        println!(
            "  {}",
            "Note: Complaints are submitted against validators in past elections.".dimmed()
        );
        println!("  {}", "Banned validators have already been penalized.".dimmed());
        println!();

        Ok(())
    }
}

impl VoteComplaintCastCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::{load_config_vault_rpc_client, make_wallet, wallet_info};
        use anyhow::Context;
        use chain_block::write_boc;
        use colored::Colorize;
        use contracts::{
            DefaultChainProvider, ElectorWrapper, ElectorWrapperImpl, SmartContract, Wallet,
            contract_provider_from,
        };
        use control_client::{
            client_adnl::ControlClientAdnl, client_api::ClientAPI,
            config_params::parse_config_param_34,
        };
        use std::path::Path;
        use std::sync::Arc;

        let config_path = Path::new(config_path);

        let (config, vault, rpc_client) = load_config_vault_rpc_client(config_path).await?;

        // Parse and validate complaint hash
        let hash_hex = self.complaint_hash.trim().trim_start_matches("0x");
        let hash_bytes_vec = hex::decode(hash_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hex complaint hash: {}", e))?;
        if hash_bytes_vec.len() != 32 {
            anyhow::bail!(
                "Complaint hash must be 32 bytes (64 hex chars), got {}",
                hash_bytes_vec.len()
            );
        }
        let mut complaint_hash = [0u8; 32];
        complaint_hash.copy_from_slice(&hash_bytes_vec);

        println!("\n{}", "Complaint Voting".cyan().bold());
        println!("{}", "\u{2500}".repeat(56).dimmed());
        println!("  Election ID:      {}", self.election_id);
        println!("  Complaint hash:   {}", hex::encode(complaint_hash));

        // Verify the election exists in past elections
        println!("\n{}", "Querying elector for past elections...".cyan());

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let elector = ElectorWrapperImpl::new(contract_provider_from(chain_provider));

        let past = elector.past_elections().await?;
        let target_election = past.iter().find(|e| e.election_id == self.election_id as u64);

        if target_election.is_none() {
            let election_ids: Vec<String> =
                past.iter().map(|e| e.election_id.to_string()).collect();
            anyhow::bail!(
                "Election ID {} not found in past elections. Available: [{}]",
                self.election_id,
                election_ids.join(", ")
            );
        }
        println!("  {} Election {} found in past elections", "OK".green().bold(), self.election_id);

        // --- Connect to node via ADNL control ---
        println!("\n{}", "Connecting to validator node...".cyan());
        let (node_name, node_cfg) =
            config.nodes.iter().next().ok_or_else(|| anyhow::anyhow!("No nodes configured"))?;
        let adnl_config = node_cfg.to_node_adnl_config(None).await?;
        let mut client = ControlClientAdnl::new(adnl_config, 1);
        client.connect().await.context("Failed to connect to validator node via ADNL")?;
        println!("  {} Connected to node '{}'", "OK".green().bold(), node_name);

        // --- Get current validator set (config param 34) ---
        println!("{}", "Fetching current validator set...".cyan());
        let vset_bytes = client.get_config_param(34).await.context("get config param 34")?;
        let vset = parse_config_param_34(&vset_bytes)?;

        // --- Get validator config to find our key ---
        let validator_config =
            client.get_validator_config().await.context("get_validator_config")?;

        // Search through recent validator keys to find one in the current vset
        let mut validators_sorted = validator_config.validators.clone();
        validators_sorted.sort_by_key(|v| v.election_date);

        let mut found_idx: Option<u16> = None;
        let mut found_key_id: Option<Vec<u8>> = None;

        // Check the last 3 election keys (same strategy as offer voting)
        let check_count = validators_sorted.len().min(3);
        for validator in validators_sorted.iter().rev().take(check_count) {
            let public_key = match client.export_key_pub(&validator.id).await {
                Ok(pk) => pk,
                Err(_) => continue,
            };
            let mut key = [0u8; 32];
            if public_key.len() >= 32 {
                key.copy_from_slice(&public_key[..32]);
            } else {
                continue;
            }
            // Search for this public key in the current validator set
            if let Some(idx) = vset
                .list()
                .iter()
                .position(|item| item.public_key().is_ok_and(|pk| pk.as_slice() == &key))
            {
                found_idx = Some(idx as u16);
                found_key_id = Some(validator.id.clone());
                println!(
                    "  {} Found validator at index {} (pubkey={})",
                    "OK".green().bold(),
                    idx,
                    hex::encode(&key)
                );
                break;
            }
        }

        let validator_idx = found_idx.ok_or_else(|| {
            anyhow::anyhow!(
                "This node is not in the current validator set (config param 34). \
                 Only active validators can vote on complaints."
            )
        })?;
        let key_id = found_key_id.unwrap();

        // --- Build and sign the complaint vote ---
        let _ = (&client, &key_id, validator_idx);
        anyhow::bail!(
            "a complaint vote is authorised by the current post-quantum validator set, \
             and producing one needs two things this node cannot yet supply: a signature \
             from its ML-DSA-44 consensus key, and the hash of the stored ConfigParam 34 \
             cell that the vote is bound to. The control protocol carries neither, so the \
             vote is not sent rather than sent in a form the chain refuses"
        );

        #[allow(unreachable_code)]
        let vote_body: chain_block::Cell = unreachable!();

        // --- Send via wallet ---
        println!("{}", "Sending complaint vote transaction...".cyan());
        let wallet_name = node_name;
        let wallet_cfg = config
            .wallets
            .get(wallet_name)
            .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found in config", wallet_name))?;

        let (_wallet_address, _wallet_info_res, secret) =
            wallet_info(rpc_client.clone(), wallet_cfg, vault.clone()).await?;

        let wallet = make_wallet(rpc_client.clone(), wallet_cfg, secret, wallet_name).await?;

        let elector_addr = elector.address();
        let send_value = 1_000_000_000u64; // 1 TOS for gas
        let msg_cell = wallet.message(elector_addr, send_value, vote_body).await?;
        let boc = write_boc(&msg_cell)?;
        client.send_boc(&boc).await.context("send complaint vote BOC")?;

        println!("\n{} Complaint vote cast successfully!", "OK".green().bold());
        println!("  Election ID:      {}", self.election_id);
        println!("  Complaint hash:   {}", hex::encode(complaint_hash));
        println!("  Validator index:  {}", validator_idx);
        println!();
        println!("  {}", "Use 'tosctl vote complaint ls' to verify complaint status.".dimmed());
        println!();

        Ok(())
    }
}

impl VoteElectionCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            VoteElectionAction::Ls(cmd) => cmd.run(config_path).await,
            VoteElectionAction::Cast(cmd) => cmd.run(config_path).await,
        }
    }
}

impl VoteElectionLsCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::try_create_rpc_client;
        use colored::Colorize;
        use common::app_config::AppConfig;
        use common::chain_utils::display_tos;
        use contracts::{
            DefaultChainProvider, ElectorWrapper, ElectorWrapperImpl, contract_provider_from,
        };
        use std::path::Path;
        use std::sync::Arc;

        let config_path = Path::new(config_path);

        let config = AppConfig::load(config_path)?;
        let rpc_client = try_create_rpc_client(&config).await?;

        if self.format != super::output_format::OutputFormat::Json {
            println!("\n{}", "Querying elector for election participants...".cyan());
        }

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let elector = ElectorWrapperImpl::new(contract_provider_from(chain_provider));

        let info = elector.elections_info().await?;

        if info.participants.is_empty() {
            if self.format == super::output_format::OutputFormat::Json {
                let obj = serde_json::json!({
                    "election_id": info.election_id,
                    "participants": [],
                });
                println!("{}", serde_json::to_string_pretty(&obj)?);
            } else {
                println!("\n{}\n", "No election participants found.".yellow());
            }
            return Ok(());
        }

        if self.format == super::output_format::OutputFormat::Json {
            let participants: Vec<serde_json::Value> = info
                .participants
                .iter()
                .map(|p| {
                    let pubkey_hex: String =
                        p.pub_key.iter().map(|b| format!("{:02x}", b)).collect();
                    serde_json::json!({
                        "public_key": pubkey_hex,
                        "stake": display_tos(p.stake),
                        "max_factor": p.max_factor,
                    })
                })
                .collect();
            let obj = serde_json::json!({
                "election_id": info.election_id,
                "elect_close": info.elect_close,
                "total_stake": display_tos(info.total_stake),
                "min_stake": display_tos(info.min_stake),
                "participants": participants,
            });
            println!("{}", serde_json::to_string_pretty(&obj)?);
        } else {
            println!();
            println!("{}", "Election Participants".bold());
            println!("{}", "\u{2500}".repeat(90));
            println!("  {:<8} {}", "Election:".bold(), info.election_id);
            println!("  {:<8} {}", "Closes:".bold(), info.elect_close);
            println!("  {:<8} {} TOS", "Total:".bold(), display_tos(info.total_stake));
            println!("  {:<8} {} TOS", "Min:".bold(), display_tos(info.min_stake));
            println!();
            println!(
                "  {:<4} {:<66} {:<16} {}",
                "#".bold(),
                "Public Key (hex)".bold(),
                "Stake (TOS)".bold(),
                "Max Factor".bold(),
            );
            println!("  {}", "\u{2500}".repeat(96));

            for (i, p) in info.participants.iter().enumerate() {
                let pubkey_hex: String = p.pub_key.iter().map(|b| format!("{:02x}", b)).collect();
                let pubkey_display = if pubkey_hex.len() > 64 {
                    pubkey_hex[..64].to_string()
                } else {
                    format!("{:<64}", pubkey_hex)
                };
                println!(
                    "  {:<4} {:<66} {:<16} {}",
                    i + 1,
                    pubkey_display,
                    display_tos(p.stake),
                    p.max_factor,
                );
            }

            println!();
        }
        Ok(())
    }
}

impl VoteElectionCastCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        use super::utils::load_config_vault_rpc_client;
        use colored::Colorize;
        use common::chain_utils::display_tos;
        use contracts::{
            DefaultChainProvider, ElectorWrapper, ElectorWrapperImpl, contract_provider_from,
        };
        use std::path::Path;
        use std::sync::Arc;

        let config_path = Path::new(config_path);

        let (_config, _vault, rpc_client) = load_config_vault_rpc_client(config_path).await?;

        println!("\n{}", "Querying elector for active election...".cyan());

        let chain_provider = Arc::new(DefaultChainProvider::new(rpc_client.clone()));
        let elector = ElectorWrapperImpl::new(contract_provider_from(chain_provider));

        let election_id = elector.get_active_election_id().await?;

        if election_id == 0 {
            println!("\n{}\n", "No active election".yellow());
            return Ok(());
        }

        println!(
            "\n{} Active election ID: {}",
            "OK".green().bold(),
            election_id.to_string().white().bold()
        );

        let elections_info = elector.elections_info().await?;
        println!("  Total stake:    {} TOS", display_tos(elections_info.total_stake));
        println!("  Participants:   {}", elections_info.participants.len());
        println!("  Min stake:      {} TOS", display_tos(elections_info.min_stake));
        println!("  Closes at:      {}", elections_info.elect_close);

        if self.dry_run {
            println!(
                "\n{}",
                "Dry-run mode: no bid was submitted. Remove --dry-run to participate."
                    .yellow()
                    .italic()
            );
            println!();
            return Ok(());
        }

        anyhow::bail!(
            "a wallet cannot stake directly to the PQ elector: configure a single-nominator pool and an admitted validator controller, then use the pool bid command"
        )
    }
}

#[cfg(test)]
mod offer_create_tests {
    use super::*;
    use chain_block::{BuilderData, ConfigProposalSetup, IBitstring, Serializable, SliceData};

    fn prepared() -> PreparedProposal {
        prepare_proposal(ask(42, Some(value()), None, false, 2_000_000), &rules(false, false))
            .unwrap()
    }

    #[test]
    fn the_report_states_what_actually_happened() {
        let prepared = prepared();
        let summary = ProposalSummary {
            config_contract: "-1:55".into(),
            param_id: 42,
            prepared: &prepared,
            value: 9,
            body_b64: "AA==".into(),
        };
        let only_prepared = summary.report(ProposalOutcome::Prepared, None);
        assert_eq!(only_prepared["status"], "prepared");
        assert_eq!(only_prepared["broadcast"], false);
        assert!(only_prepared.get("sent").is_none());
        assert_eq!(summary.report(ProposalOutcome::Cancelled, None)["broadcast"], false);
        let unconfirmed = summary.report(ProposalOutcome::WalletAcceptedUnconfirmed, None);
        assert_eq!(unconfirmed["status"], "wallet_accepted_unconfirmed");
        assert_eq!(unconfirmed["broadcast"], true);
        let registered = summary.report(ProposalOutcome::Registered, Some(77));
        assert_eq!(registered["status"], "registered");
        assert_eq!(registered["registered_expires"], 77);
    }

    #[test]
    fn a_wallet_must_hold_the_value_and_its_own_fees() {
        let gas = chain_block::GasLimitsPrices {
            gas_price: 10_000 * 65_536,
            flat_gas_limit: 100,
            flat_gas_price: 1_000_000,
            ..Default::default()
        };
        let forward = chain_block::MsgForwardPrices {
            lump_price: 10_000_000,
            bit_price: 655_360_000,
            cell_price: 65_536_000_000,
            ihr_price_factor: 98_304,
            first_frac: 21_845,
            next_frac: 21_845,
        };
        let reserve = sender_fee_reserve(
            &chain_block::ConfigParamEnum::ConfigParam20(gas),
            &chain_block::ConfigParamEnum::ConfigParam24(forward),
            &prepared().body,
        )
        .unwrap();
        // 20 000 gas alone costs 0.199 TOS at these prices.
        assert!(reserve > 199_000_000, "{reserve}");
        let value = 5_000_000_000u64;
        let refused = sender_can_pay("w", value + 1, value, reserve);
        assert!(refused.err().is_some_and(|e| e.to_string().contains("own fees")));
        let exact = value + u64::try_from(reserve).unwrap();
        assert!(sender_can_pay("w", exact, value, reserve).is_ok());
        assert!(sender_can_pay("w", exact - 1, value, reserve).is_err());
    }

    #[test]
    fn only_a_new_or_extended_proposal_counts_as_registered() {
        assert!(!registration_confirmed(None, None));
        assert!(registration_confirmed(None, Some(10)));
        assert!(!registration_confirmed(Some(10), Some(10)), "an existing proposal unchanged");
        assert!(registration_confirmed(Some(10), Some(11)));
        assert!(!registration_confirmed(Some(10), None));
    }

    #[test]
    fn a_value_must_decode_as_the_parameter() {
        let cp15 = chain_block::ConfigParam15 {
            validators_elected_for: 65_536,
            elections_start_before: 32_768,
            elections_end_before: 8_192,
            stake_held_for: 32_768,
        };
        let good = cp15.serialize().unwrap();
        assert!(check_value_shape(15, &good).is_ok());
        let mut bad = BuilderData::new();
        bad.append_u8(1).unwrap();
        let bad = bad.into_cell().unwrap();
        assert!(
            check_value_shape(15, &bad)
                .err()
                .is_some_and(|e| e.to_string().contains("ConfigParam 15"))
        );
        let mut trailing = BuilderData::from_cell(&good).unwrap();
        trailing.append_u8(0xff).unwrap();
        let trailing = trailing.into_cell().unwrap();
        assert!(check_value_shape(15, &trailing).is_err(), "trailing data was accepted");
        // An index this tool has no type for, and a negative one, are not judged.
        assert!(check_value_shape(1000, &bad).is_ok());
        assert!(check_value_shape(-71, &bad).is_ok());
    }

    fn rules(critical: bool, mandatory: bool) -> ParameterRules {
        ParameterRules {
            critical,
            mandatory,
            setup: ConfigProposalSetup {
                min_tot_rounds: 2,
                max_tot_rounds: 6,
                min_wins: 2,
                max_losses: 2,
                min_store_sec: 1_000_000,
                max_store_sec: 10_000_000,
                bit_price: 1,
                cell_price: 500,
            },
        }
    }

    fn ask(
        param_id: i32,
        value: Option<chain_block::Cell>,
        if_hash_equal: Option<[u8; 32]>,
        critical: bool,
        ttl_secs: u32,
    ) -> ProposalRequest {
        ProposalRequest {
            param_id,
            value,
            if_hash_equal,
            critical,
            ttl_secs,
            query_id: 1,
            margin: 0,
        }
    }

    fn value() -> chain_block::Cell {
        let mut b = BuilderData::new();
        b.append_u32(9).unwrap();
        b.into_cell().unwrap()
    }

    #[test]
    fn a_proposal_carries_price_plus_the_contract_surplus_plus_margin() {
        let request = ProposalRequest {
            query_id: 5,
            margin: 7,
            ..ask(42, Some(value()), None, false, 2_000_000)
        };
        let prepared = prepare_proposal(request, &rules(false, false)).unwrap();
        assert_eq!(prepared.price, (32 + 1024 + 500 * 2) * 2_000_000);
        assert_eq!(prepared.value, prepared.price + (1 << 30) + 7);
        let mut cs = SliceData::load_cell(prepared.body).unwrap();
        assert_eq!(cs.get_next_u32().unwrap(), 0x6e56_5052);
        assert_eq!(cs.get_next_u64().unwrap(), 5);
        assert_eq!(cs.get_next_u32().unwrap(), 2_000_000);
        let proposal = cs.checked_drain_reference().unwrap();
        assert_eq!(proposal.repr_hash().as_slice(), &prepared.proposal_hash);
        assert!(!cs.get_next_bit().unwrap());
    }

    #[test]
    fn local_refusals_match_the_contract() {
        let critical =
            prepare_proposal(ask(7, Some(value()), None, false, 2_000_000), &rules(true, false));
        assert!(critical.err().is_some_and(|e| e.to_string().contains("--critical")));
        assert!(
            prepare_proposal(ask(7, Some(value()), None, true, 2_000_000), &rules(true, false))
                .is_ok()
        );

        let unbound =
            prepare_proposal(ask(7, Some(value()), None, true, 2_000_000), &rules(true, true));
        assert!(unbound.err().is_some_and(|e| e.to_string().contains("--bind-current")));
        let removal =
            prepare_proposal(ask(7, None, Some([0; 32]), true, 2_000_000), &rules(true, true));
        assert!(removal.err().is_some_and(|e| e.to_string().contains("cannot be removed")));
        assert!(
            prepare_proposal(
                ask(7, Some(value()), Some([0; 32]), true, 2_000_000),
                &rules(true, true)
            )
            .is_ok()
        );

        let short =
            prepare_proposal(ask(42, Some(value()), None, false, 999_999), &rules(false, false));
        assert!(short.err().is_some_and(|e| e.to_string().contains("at least 1000000")));
    }

    #[test]
    fn exactly_one_new_value_source_is_accepted() {
        use clap::{Args, Command, FromArgMatches};
        let parse = |args: &[&str]| {
            let mut argv = vec!["create", "--param", "-71"];
            argv.extend_from_slice(args);
            VoteOfferCreateCmd::augment_args(Command::new("create"))
                .try_get_matches_from(argv)
                .and_then(|m| VoteOfferCreateCmd::from_arg_matches(&m))
        };
        let removal = parse(&["--remove"]).unwrap();
        assert_eq!(removal.param, -71);
        assert!(removal.new_value().unwrap().is_none());
        assert!(parse(&["--remove", "--value-boc", "AA=="]).is_err());
        assert!(parse(&["--bind-current", "--if-hash-equal", "00"]).is_err());
        assert!(parse(&[]).unwrap().new_value().is_err());
    }
}
