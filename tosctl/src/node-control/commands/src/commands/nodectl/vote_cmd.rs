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
        workchain and keeps its value.\n\n\
        With --wallet the wallet must hold the value plus its own fees: storage accrued and \
        owed (from the storage_stat the node serves with the account), computation and \
        forwarding, all read at one block. A node that does not serve storage_stat makes \
        --wallet refuse, since a mode-3 send that cannot pay its fees sends nothing. \
        The report's status is registered only when the configuration contract is then \
        observed holding the proposal, new or with a later expiry; that is observed state \
        and does not prove this transaction caused it."
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
    /// Masterchain wallet from config that sends the proposal (needs a node that serves
    /// the wallet's storage_stat); prints the message otherwise
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
                    serde_json::to_string_pretty(&summary.report(
                        ProposalOutcome::Prepared,
                        None,
                        None
                    ))?
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
        let (reserve, balance) =
            pinned_wallet_reserve(&chain, &wallet_address, &prepared.body).await?;
        sender_can_pay(wallet_name, balance, value, reserve)?;
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
                        serde_json::to_string_pretty(&summary.report(
                            ProposalOutcome::Cancelled,
                            None,
                            None
                        ))?
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
        let boc = write_boc(&message)?;
        // From the moment the message is handed over it may be on its way, even if the
        // answer is lost: every failure is reported in the final report rather than
        // returned bare. A seqno change shows only that the wallet accepted the external
        // message; the wallet sends in a mode that ignores action errors, so the
        // proposal is looked for in the configuration contract.
        let accepted = send_then_wait(
            rpc_client.send_boc(&boc),
            wait_for_seqno_change(
                rpc_client.clone(),
                &wallet_address,
                info.seqno,
                &common::task_cancellation::CancellationCtx::default(),
                SEND_TIMEOUT,
            ),
        )
        .await;
        let observed = if accepted.is_ok() {
            poll_registration(
                prior,
                || proposal_expiry(&chain, &config_address, &prepared.proposal_hash),
                REGISTRATION_POLLS,
                REGISTRATION_POLL_INTERVAL,
            )
            .await
        } else {
            Ok(None)
        };
        let (outcome, registered, error) = outcome_after_broadcast(prior, accepted, observed);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&summary.report(
                    outcome,
                    registered,
                    error.as_deref()
                ))?
            );
        } else if let Some(expires) = registered {
            println!(
                "{} The configuration contract holds this proposal (expires {expires}); hash {}. \
                 This is observed contract state: another sender may have registered or \
                 extended the same proposal.",
                "OK".green().bold(),
                hex::encode(prepared.proposal_hash)
            );
        } else {
            println!(
                "{} {}; check `tosctl vote offer diff --hash {}`",
                "UNCONFIRMED".yellow().bold(),
                error.as_deref().unwrap_or(
                    "the wallet accepted the message, but the configuration contract does not \
                     show the proposal yet"
                ),
                hex::encode(prepared.proposal_hash)
            );
        }
        anyhow::ensure!(
            outcome == ProposalOutcome::Registered,
            "the proposal was not seen registered: {}",
            outcome.as_str()
        );
        Ok(())
    }
}

/// Hands the message over, then waits for the wallet to accept it. A failed hand-over
/// is not proof the message went nowhere (the node may have forwarded it before the
/// answer was lost), so it is an unconfirmed broadcast, not a plain error.
pub(crate) async fn send_then_wait<S, W>(send: S, wait: W) -> Result<(), String>
where
    S: std::future::Future<Output = anyhow::Result<()>>,
    W: std::future::Future<Output = anyhow::Result<()>>,
{
    send.await.map_err(|e| format!("the node did not confirm it took the message: {e:#}"))?;
    wait.await.map_err(|e| format!("{e:#}"))
}

/// What can be said once the message was handed to the network: the wallet's
/// acceptance (its seqno advanced) and what the configuration contract then showed.
pub(crate) fn outcome_after_broadcast(
    prior: Option<u32>,
    accepted: Result<(), String>,
    observed: Result<Option<u32>, String>,
) -> (ProposalOutcome, Option<u32>, Option<String>) {
    if let Err(error) = accepted {
        return (ProposalOutcome::BroadcastUnconfirmed, None, Some(error));
    }
    match observed {
        Ok(current) if registration_confirmed(prior, current) => {
            (ProposalOutcome::Registered, current, None)
        }
        Ok(_) => (ProposalOutcome::WalletAcceptedUnconfirmed, None, None),
        Err(error) => (ProposalOutcome::WalletAcceptedUnconfirmed, None, Some(error)),
    }
}

const REGISTRATION_POLLS: usize = 15;
const REGISTRATION_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
/// How far ahead the storage the wallet owes is counted: a signed message is valid
/// for a short while after it is built.
const SEND_HORIZON_SECS: u64 = 600;

/// What `vote offer create` did, as reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProposalOutcome {
    /// Built and priced; nothing was sent.
    Prepared,
    /// The operator declined to send.
    Cancelled,
    /// The configuration contract was observed holding the proposal, new or with a
    /// later expiry than before. Observed state only: a concurrent sender of the same
    /// proposal produces the same observation.
    Registered,
    /// The wallet's seqno advanced, but the proposal was not seen in the contract.
    WalletAcceptedUnconfirmed,
    /// The message was handed to the network, but the wallet's acceptance was not seen.
    BroadcastUnconfirmed,
}

impl ProposalOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Cancelled => "cancelled",
            Self::Registered => "registered",
            Self::WalletAcceptedUnconfirmed => "wallet_accepted_unconfirmed",
            Self::BroadcastUnconfirmed => "broadcast_unconfirmed",
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
        error: Option<&str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "status": outcome.as_str(),
            "broadcast": matches!(
                outcome,
                ProposalOutcome::Registered
                    | ProposalOutcome::WalletAcceptedUnconfirmed
                    | ProposalOutcome::BroadcastUnconfirmed
            ),
            "error": error,
            "registered_expires": registered_expires,
            "registration_evidence": "observed configuration contract state: the proposal is \
                present, new or with a later expiry than before the send; this does not prove \
                that this transaction caused it, since another sender may register or extend \
                the same proposal",
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

/// The wallet's own charge for sending `body`, as an upper bound, with the balance it
/// holds: both read at one masterchain block. The storage it owes is counted from its
/// last transaction (when it last paid) to shortly after now.
async fn pinned_wallet_reserve(
    chain: &contracts::DefaultChainProvider,
    wallet: &chain_block::MsgAddressInt,
    body: &chain_block::Cell,
) -> anyhow::Result<(u128, u64)> {
    use chain_block::ConfigParamEnum;
    use contracts::ChainProvider;
    use contracts::wallet::send_fees::{SendFeeInputs, wallet_send_reserve};
    let checkpoint = contracts::validator_controller::latest_checkpoint(chain).await?;
    let account = chain.get_address_info_at_unverified(wallet, &checkpoint).await?;
    let storage = wallet_storage_from_rpc(wallet, &account)?;
    let gas = match chain.get_config_param_at_unverified(20, &checkpoint).await? {
        ConfigParamEnum::ConfigParam20(value) => value,
        other => anyhow::bail!("live ConfigParam 20 has unexpected representation: {other:?}"),
    };
    let forward = match chain.get_config_param_at_unverified(24, &checkpoint).await? {
        ConfigParamEnum::ConfigParam24(value) => value,
        other => anyhow::bail!("live ConfigParam 24 has unexpected representation: {other:?}"),
    };
    let storage_prices = match chain.get_config_param_at_unverified(18, &checkpoint).await? {
        ConfigParamEnum::ConfigParam18(value) => value.prices()?,
        other => anyhow::bail!("live ConfigParam 18 has unexpected representation: {other:?}"),
    };
    let now = u32::try_from(common::time_format::now().saturating_add(SEND_HORIZON_SECS))?;
    let reserve = wallet_send_reserve(&SendFeeInputs {
        gas: &gas,
        forward: &forward,
        storage_prices: &storage_prices,
        storage: &storage,
        now,
        body,
    })?;
    Ok((reserve, account.balance))
}

/// The wallet's storage metadata (used cells and bits, last paid, recorded debt), as
/// the storage phase will charge it, from the `storage_stat` the node serves with the
/// account at the pinned block. Code and data are not a bound (they omit the library
/// dictionary, extra currencies under older global versions, and any debt), so a
/// node that does not serve `storage_stat` makes the send fail closed; the printed
/// body can still be sent from an external wallet.
pub(crate) fn wallet_storage_from_rpc(
    wallet: &chain_block::MsgAddressInt,
    account: &contracts::chain_provider::AddressInfo,
) -> anyhow::Result<contracts::wallet::send_fees::AccountStorage> {
    let Some(stat) = &account.storage_stat else {
        anyhow::bail!(
            "cannot bound the fees of wallet {wallet}: the node did not return its storage \
             metadata (storage_stat: used cells and bits, last paid, storage debt), as a node \
             older than this tool does not, and with mode 3 a wallet that cannot pay sends \
             nothing while still advancing its seqno. Run without --wallet and send the \
             printed body from an external masterchain wallet with value + margin for its fees"
        );
    };
    contracts::wallet::send_fees::AccountStorage::from_rpc(stat)
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

/// The expiry of a proposal the configuration contract holds, or `None`, read
/// through the bounded proposal-read path.
async fn proposal_expiry(
    chain: &contracts::DefaultChainProvider,
    config_address: &chain_block::MsgAddressInt,
    proposal_hash: &[u8; 32],
) -> anyhow::Result<Option<u32>> {
    use contracts::ChainProvider;
    match chain
        .read_proposals(config_address, contracts::ProposalRead::Expiry(*proposal_hash))
        .await?
    {
        contracts::ProposalAnswer::Expiry(expiry) => Ok(expiry),
        _ => anyhow::bail!("the provider answered another proposal read"),
    }
}

/// Decodes a `get_proposal` answer: `None` for the getter's null, the expiry for its
/// proposal tuple, and an error for anything else. Production reads go through the
/// bounded proposal-read path, which applies the same decoder on its worker.
#[cfg(test)]
pub(crate) async fn proposal_expiry_from<F>(answer: F) -> anyhow::Result<Option<u32>>
where
    F: std::future::Future<Output = anyhow::Result<common::tvm_stack_parser::TvmStackParser>>,
{
    contracts::config_contract::decode_proposal_expiry(&answer.await?)
}

/// Reads the proposal back up to `polls` times, `interval` apart, until it is seen
/// registered by this request. A read error ends the polling and is reported, never
/// taken as "not registered yet".
pub(crate) async fn poll_registration<R, F>(
    prior: Option<u32>,
    mut read: R,
    polls: usize,
    interval: std::time::Duration,
) -> Result<Option<u32>, String>
where
    R: FnMut() -> F,
    F: std::future::Future<Output = anyhow::Result<Option<u32>>>,
{
    let mut observed: Result<Option<u32>, String> = Ok(None);
    for poll in 0..polls {
        if poll > 0 {
            tokio::time::sleep(interval).await;
        }
        observed = read().await.map_err(|e| format!("reading the proposal back failed: {e:#}"));
        match &observed {
            Ok(current) if registration_confirmed(prior, *current) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    observed
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
        let json = self.format == super::output_format::OutputFormat::Json;
        print!("{}", render_offer_list(&proposals, json)?);
        Ok(())
    }
}

/// What `vote offer ls` prints for `proposals`, in the getter's order.
fn render_offer_list(
    proposals: &[contracts::ConfigProposal],
    json: bool,
) -> anyhow::Result<String> {
    use colored::Colorize;
    use common::time_format::format_ts;
    use std::fmt::Write;

    let mut out = String::new();
    if proposals.is_empty() {
        if json {
            writeln!(out, "[]")?;
        } else {
            writeln!(out, "\n{}\n", "No active config proposals.".yellow())?;
        }
        return Ok(out);
    }

    if json {
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
        writeln!(out, "{}", serde_json::to_string_pretty(&views)?)?;
    } else {
        writeln!(out)?;
        writeln!(out, "{}", "Config Proposals".bold())?;
        writeln!(out, "{}", "\u{2500}".repeat(80))?;
        writeln!(
            out,
            "  {:<4} {:<8} {:<11} {:<22} {:<9} {}",
            "#".bold(),
            "Param".bold(),
            "Critical".bold(),
            "Expires".bold(),
            "Voters".bold(),
            "Weight Remaining".bold(),
        )?;
        writeln!(out, "  {}", "\u{2500}".repeat(76))?;

        for (i, p) in proposals.iter().enumerate() {
            let critical = if p.is_critical { "Yes" } else { "No" };
            let expires = format_ts(p.expires as u64);
            writeln!(
                out,
                "  {:<4} {:<8} {:<11} {:<22} {:<9} {}",
                i + 1,
                p.param.id,
                critical,
                expires,
                p.voters.len(),
                p.weight_remaining,
            )?;
        }

        writeln!(out)?;
    }
    Ok(out)
}

/// Which listed proposal `vote offer cast` targets.
enum OfferChoice<'a> {
    One(&'a contracts::ConfigProposal),
    /// Several proposals are listed and no hash was given.
    Ambiguous,
    /// The given hash is not among the listed proposals.
    Missing,
}

fn select_offer<'a>(
    proposals: &'a [contracts::ConfigProposal],
    target: Option<&[u8; 32]>,
) -> OfferChoice<'a> {
    match target {
        Some(target) => match proposals.iter().find(|p| p.hash == *target) {
            Some(p) => OfferChoice::One(p),
            None => OfferChoice::Missing,
        },
        None => match proposals {
            [only] => OfferChoice::One(only),
            _ => OfferChoice::Ambiguous,
        },
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
        let proposal = match select_offer(&proposals, target_hash.as_ref()) {
            OfferChoice::One(p) => p,
            OfferChoice::Ambiguous => {
                println!(
                    "  {}",
                    "Multiple proposals found. Use --hash to specify which one to vote on."
                        .yellow()
                );
                println!();
                return Ok(());
            }
            OfferChoice::Missing => {
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
        let only_prepared = summary.report(ProposalOutcome::Prepared, None, None);
        assert_eq!(only_prepared["status"], "prepared");
        assert_eq!(only_prepared["broadcast"], false);
        assert!(only_prepared.get("sent").is_none());
        assert_eq!(summary.report(ProposalOutcome::Cancelled, None, None)["broadcast"], false);
        let unconfirmed = summary.report(ProposalOutcome::WalletAcceptedUnconfirmed, None, None);
        assert_eq!(unconfirmed["status"], "wallet_accepted_unconfirmed");
        assert_eq!(unconfirmed["broadcast"], true);
        let registered = summary.report(ProposalOutcome::Registered, Some(77), None);
        assert_eq!(registered["status"], "registered");
        assert_eq!(registered["registered_expires"], 77);
        assert!(
            registered["registration_evidence"]
                .as_str()
                .is_some_and(|note| note.contains("does not prove that this transaction caused it")),
            "the report must say registration is observed state"
        );
        let failed = summary.report(
            ProposalOutcome::WalletAcceptedUnconfirmed,
            None,
            Some("reading the proposal back failed: timeout"),
        );
        assert_eq!(failed["error"], "reading the proposal back failed: timeout");
    }

    /// After the broadcast, a failed read-back or a missing wallet acceptance is a
    /// reported outcome, not an error that skips the report.
    #[test]
    fn post_broadcast_failures_become_reported_outcomes() {
        let read_failed = outcome_after_broadcast(None, Ok(()), Err("read back: timeout".into()));
        assert_eq!(
            read_failed,
            (ProposalOutcome::WalletAcceptedUnconfirmed, None, Some("read back: timeout".into()))
        );
        let not_accepted =
            outcome_after_broadcast(None, Err("Transaction timeout expired".into()), Ok(None));
        assert_eq!(not_accepted.0, ProposalOutcome::BroadcastUnconfirmed);
        assert_eq!(not_accepted.2.as_deref(), Some("Transaction timeout expired"));
        assert_eq!(
            outcome_after_broadcast(Some(5), Ok(()), Ok(Some(9))),
            (ProposalOutcome::Registered, Some(9), None)
        );
        assert_eq!(
            outcome_after_broadcast(Some(9), Ok(()), Ok(Some(9))).0,
            ProposalOutcome::WalletAcceptedUnconfirmed,
            "an unchanged proposal is not this request's registration"
        );
    }

    /// Without the account's storage metadata the wallet's charge has no bound, so a
    /// send is refused rather than sized from code and data.
    #[test]
    fn a_wallet_send_fails_closed_without_storage_metadata() {
        let info: contracts::chain_provider::AddressInfo =
            serde_json::from_value(serde_json::json!({
                "@type": "raw.fullAccountState",
                "balance": "1000000000000",
                "code": "",
                "data": "",
                "last_transaction_id": {"@type": "internal.transactionId", "lt": "5", "hash": ""},
                "block_id": {
                    "@type": "tos.blockIdExt", "workchain": -1, "shard": "-9223372036854775808",
                    "seqno": 1, "root_hash": "", "file_hash": ""
                },
                "sync_utime": 1,
                "state": "active",
            }))
            .unwrap();
        let wallet = chain_block::MsgAddressInt::standard(-1, [0xAA; 32]);
        let error = wallet_storage_from_rpc(&wallet, &info).unwrap_err().to_string();
        assert!(error.contains("storage metadata"), "{error}");
        assert!(error.contains("without --wallet"), "{error}");
    }

    /// A node that serves storage_stat gives the reserve the account's own figures,
    /// debt included.
    #[test]
    fn a_wallet_send_uses_the_served_storage_stat() {
        let mut account = serde_json::json!({
            "@type": "raw.fullAccountState",
            "balance": "1000000000000",
            "code": "",
            "data": "",
            "last_transaction_id": {"@type": "internal.transactionId", "lt": "5", "hash": ""},
            "block_id": {
                "@type": "tos.blockIdExt", "workchain": -1, "shard": "-9223372036854775808",
                "seqno": 1, "root_hash": "", "file_hash": ""
            },
            "sync_utime": 1,
            "state": "active",
            "storage_stat": {
                "@type": "storage.stat",
                "used_cells": "7",
                "used_bits": "4321",
                "last_paid": 1700000123,
                "due_payment": "2000000000"
            },
        });
        let wallet = chain_block::MsgAddressInt::standard(-1, [0xAA; 32]);
        let info: contracts::chain_provider::AddressInfo =
            serde_json::from_value(account.clone()).unwrap();
        assert_eq!(
            wallet_storage_from_rpc(&wallet, &info).unwrap(),
            contracts::wallet::send_fees::AccountStorage {
                cells: 7,
                bits: 4321,
                last_paid: 1_700_000_123,
                due_payment: 2_000_000_000,
            }
        );
        account["storage_stat"]["due_payment"] = serde_json::Value::Null;
        let info: contracts::chain_provider::AddressInfo = serde_json::from_value(account).unwrap();
        assert_eq!(wallet_storage_from_rpc(&wallet, &info).unwrap().due_payment, 0);
    }

    /// A lost answer to the send itself still yields the final report, as an
    /// unconfirmed broadcast, and the wallet is not waited for.
    #[tokio::test]
    async fn a_lost_send_answer_is_an_unconfirmed_broadcast() {
        let waited = std::sync::atomic::AtomicBool::new(false);
        let accepted = send_then_wait(async { Err(anyhow::anyhow!("connection reset")) }, async {
            waited.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await;
        assert!(!waited.load(std::sync::atomic::Ordering::SeqCst));
        let (outcome, registered, error) = outcome_after_broadcast(None, accepted, Ok(None));
        assert_eq!(outcome, ProposalOutcome::BroadcastUnconfirmed);
        assert_eq!(registered, None);
        assert!(error.is_some_and(|e| e.contains("connection reset")));
        assert_eq!(send_then_wait(async { Ok(()) }, async { Ok(()) }).await, Ok(()));
    }

    #[test]
    fn a_wallet_must_hold_the_value_and_its_own_fees() {
        let reserve = 700_000_000u128;
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

#[cfg(test)]
mod proposal_read_back_tests {
    use super::*;

    /// `runGetMethodStd` for `get_proposal` of an absent hash, as a running node
    /// answered it (see the README beside the file for the request and block).
    const ABSENT_LIVE: &str =
        include_str!("../../../../contracts/tests/fixtures/get_proposal/absent-live.json");
    /// The same call for a proposal registered on that network by `vote offer create`.
    const PRESENT_LIVE: &str =
        include_str!("../../../../contracts/tests/fixtures/get_proposal/present-live.json");

    /// The stack of a JSON-RPC answer, through the same conversion the chain provider
    /// applies to every get-method result.
    fn served(response: &str) -> common::tvm_stack_parser::TvmStackParser {
        let value: serde_json::Value = serde_json::from_str(response).expect("JSON");
        let result: chain_rpc_client::v2::data_models::RunGetMethodRes =
            serde_json::from_value(value["result"].clone()).expect("a runResult");
        assert_eq!(result.exit_code, 0);
        contracts::chain_provider::stack_from_rpc(result.stack)
    }

    /// A present proposal with two voters, written by hand in the shape the node's
    /// serializer produces (tuple tested before list, so the cons chain is nested
    /// pairs ending in an empty list). This is not independent evidence of that
    /// shape; `PRESENT_LIVE` is.
    fn present_with_voters(expires: u32) -> String {
        let num = |n: &str| {
            format!(
                r#"{{"@type":"tvm.stackEntryNumber","number":{{"@type":"tvm.numberDecimal","number":"{n}"}}}}"#
            )
        };
        let null = r#"{"@type":"tvm.stackEntryList","list":{"@type":"tvm.list","elements":[]}}"#;
        let tuple = |items: Vec<String>| {
            format!(
                r#"{{"@type":"tvm.stackEntryTuple","tuple":{{"@type":"tvm.tuple","elements":[{}]}}}}"#,
                items.join(",")
            )
        };
        let voters = tuple(vec![num("1"), tuple(vec![num("3"), null.to_string()])]);
        let proposal = tuple(vec![
            num(&expires.to_string()),
            num("0"),
            tuple(vec![num("42"), null.to_string(), num("-1")]),
            num("77"),
            voters,
            num("100"),
            num("3"),
            num("0"),
            num("0"),
        ]);
        format!(
            r#"{{"ok":true,"jsonrpc":"2.0","id":1,"result":{{"@type":"smc.runResult","gas_used":0,"stack":[{proposal}],"exit_code":0,"last_transaction_id":null,"block_id":null}}}}"#
        )
    }

    /// The expiry the registration reported, which the live answer must carry.
    fn live_present_expiry() -> u32 {
        1_792_321_804
    }

    /// The pre-send read: an existing proposal must read as its expiry, not fail, or
    /// extending it can never be broadcast.
    #[tokio::test]
    async fn the_prior_read_decodes_both_live_answers() {
        let absent = proposal_expiry_from(async { Ok(served(ABSENT_LIVE)) }).await.unwrap();
        assert_eq!(absent, None);
        let present = proposal_expiry_from(async { Ok(served(PRESENT_LIVE)) }).await.unwrap();
        assert_eq!(present, Some(live_present_expiry()));
        let voted = present_with_voters(1_793_250_000);
        let voted = proposal_expiry_from(async { Ok(served(&voted)) }).await.unwrap();
        assert_eq!(voted, Some(1_793_250_000));
        let failed = proposal_expiry_from(async { Err(anyhow::anyhow!("timeout")) }).await;
        assert!(failed.is_err());
    }

    /// Serves scripted answers to successive reads, through the decoder.
    fn script(
        answers: Vec<anyhow::Result<String>>,
    ) -> (
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        impl FnMut()
            -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Option<u32>>>>>,
    ) {
        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = reads.clone();
        let answers = std::sync::Arc::new(std::sync::Mutex::new(
            answers.into_iter().collect::<std::collections::VecDeque<_>>(),
        ));
        let read = move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let next = answers.lock().expect("script").pop_front();
            Box::pin(async move {
                let response = next.unwrap_or_else(|| Err(anyhow::anyhow!("script exhausted")))?;
                proposal_expiry_from(async { Ok(served(&response)) }).await
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = _>>>
        };
        (reads, read)
    }

    const NO_WAIT: std::time::Duration = std::time::Duration::ZERO;

    #[tokio::test]
    async fn polling_sees_the_live_registration() {
        let expires = live_present_expiry();
        let (reads, read) = script(vec![
            Ok(ABSENT_LIVE.to_string()),
            Ok(ABSENT_LIVE.to_string()),
            Ok(PRESENT_LIVE.to_string()),
            Ok(ABSENT_LIVE.to_string()),
        ]);
        let observed = poll_registration(None, read, 15, NO_WAIT).await;
        assert_eq!(observed, Ok(Some(expires)));
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 3, "stops when seen");
        let (outcome, registered, error) = outcome_after_broadcast(None, Ok(()), observed);
        assert_eq!(
            (outcome, registered, error),
            (ProposalOutcome::Registered, Some(expires), None)
        );
    }

    #[tokio::test]
    async fn polling_sees_an_extension_with_voters() {
        let (_, read) = script(vec![Ok(present_with_voters(100)), Ok(present_with_voters(200))]);
        let observed = poll_registration(Some(100), read, 15, NO_WAIT).await;
        assert_eq!(observed, Ok(Some(200)));
        assert_eq!(
            outcome_after_broadcast(Some(100), Ok(()), observed).0,
            ProposalOutcome::Registered
        );
    }

    /// An unchanged or shortened expiry is not this request's registration: polling
    /// runs out and reports an unconfirmed acceptance without inventing an error.
    #[tokio::test]
    async fn an_unchanged_or_lower_expiry_is_not_a_registration() {
        for current in [100, 99] {
            let (reads, read) = script((0..4).map(|_| Ok(present_with_voters(current))).collect());
            let observed = poll_registration(Some(100), read, 4, NO_WAIT).await;
            assert_eq!(observed, Ok(Some(current)));
            assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 4);
            let (outcome, registered, error) = outcome_after_broadcast(Some(100), Ok(()), observed);
            assert_eq!(outcome, ProposalOutcome::WalletAcceptedUnconfirmed);
            assert_eq!((registered, error), (None, None));
        }
    }

    /// A read error stops polling at once and is reported as such.
    #[tokio::test]
    async fn a_read_error_ends_polling_and_is_reported() {
        let (reads, read) = script(vec![
            Ok(ABSENT_LIVE.to_string()),
            Err(anyhow::anyhow!("connection refused")),
            Ok(PRESENT_LIVE.to_string()),
        ]);
        let observed = poll_registration(None, read, 15, NO_WAIT).await;
        assert!(observed.as_ref().is_err_and(|e| e.contains("connection refused")), "{observed:?}");
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 2);
        let (outcome, _, error) = outcome_after_broadcast(None, Ok(()), observed);
        assert_eq!(outcome, ProposalOutcome::WalletAcceptedUnconfirmed);
        assert!(error.is_some_and(|e| e.contains("reading the proposal back failed")));

        // A malformed answer is a read error too, not "absent": a non-empty list, and
        // a numeric zero in place of the null (how some getters' nil has been seen).
        let null = r#"{"@type":"tvm.stackEntryList","list":{"@type":"tvm.list","elements":[]}}"#;
        let zero = r#"{"@type":"tvm.stackEntryNumber","number":{"@type":"tvm.numberDecimal","number":"0"}}"#;
        for malformed in [
            ABSENT_LIVE.replace(r#""elements":[]"#, &format!(r#""elements":[{zero}]"#)),
            ABSENT_LIVE.replace(null, zero),
        ] {
            assert_ne!(malformed, ABSENT_LIVE);
            // One poll: an exhausted script must not be what makes this an error.
            let (_, read) = script(vec![Ok(malformed)]);
            let observed = poll_registration(None, read, 1, NO_WAIT).await;
            assert!(observed.is_err_and(|e| !e.contains("script exhausted")));
        }
    }

    #[tokio::test]
    async fn zero_polls_read_nothing() {
        let (reads, read) = script(vec![Ok(PRESENT_LIVE.to_string())]);
        let observed = poll_registration(None, read, 0, NO_WAIT).await;
        assert_eq!(observed, Ok(None));
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            outcome_after_broadcast(None, Ok(()), observed).0,
            ProposalOutcome::WalletAcceptedUnconfirmed
        );
    }
}

#[cfg(test)]
mod offer_list_tests {
    use super::*;

    /// The node's real `list_proposals` answer with two proposals, decoded as the
    /// wrapper decodes it.
    fn live_proposals() -> Vec<contracts::ConfigProposal> {
        let response =
            include_str!("../../../../contracts/tests/fixtures/list_proposals/two-live.json");
        let value: serde_json::Value = serde_json::from_str(response).unwrap();
        let result: chain_rpc_client::v2::data_models::RunGetMethodRes =
            serde_json::from_value(value["result"].clone()).unwrap();
        let stack = contracts::chain_provider::stack_from_rpc(result.stack);
        contracts::config_contract::decode_proposal_list(&stack).unwrap()
    }

    const FIRST: &str = "472b34cc4214f8c3d028bc1f47dcc7d8c2e040b093a9b32f4afe2485be597cc9";
    const SECOND: &str = "caf342eb8fdd9adc97379f44c7740735097dd210430f79dc410a3690639888f0";

    #[test]
    fn the_json_listing_of_the_live_answer() {
        let rendered = render_offer_list(&live_proposals(), true).unwrap();
        let expected = serde_json::json!([
            {
                "param_id": 1000,
                "is_critical": false,
                "expires": common::time_format::format_ts(1_792_326_266),
                "voters": 0,
                "weight_remaining": 864_691_128_455_135_232i64,
                "hash": FIRST,
            },
            {
                "param_id": 1001,
                "is_critical": false,
                "expires": common::time_format::format_ts(1_792_326_268),
                "voters": 0,
                "weight_remaining": 864_691_128_455_135_232i64,
                "hash": SECOND,
            }
        ]);
        assert_eq!(rendered, format!("{}\n", serde_json::to_string_pretty(&expected).unwrap()));
        assert_eq!(render_offer_list(&[], true).unwrap(), "[]\n");
    }

    #[test]
    fn the_text_listing_of_the_live_answer() {
        colored::control::set_override(false);
        let rendered = render_offer_list(&live_proposals(), false).unwrap();
        let rows: Vec<&str> = rendered.lines().collect();
        assert_eq!(rows[1], "Config Proposals");
        assert_eq!(
            rows[3],
            "  #    Param    Critical    Expires                Voters    Weight Remaining"
        );
        let first = common::time_format::format_ts(1_792_326_266);
        let second = common::time_format::format_ts(1_792_326_268);
        assert_eq!(
            rows[5],
            format!("  1    1000     No          {first:<22} 0         864691128455135232")
        );
        assert_eq!(
            rows[6],
            format!("  2    1001     No          {second:<22} 0         864691128455135232")
        );
        assert_eq!(rows.len(), 8);
        assert_eq!(render_offer_list(&[], false).unwrap(), "\nNo active config proposals.\n\n");
    }

    #[test]
    fn cast_selects_by_hash_or_the_only_proposal() {
        let proposals = live_proposals();
        let mut second = [0u8; 32];
        hex::decode_to_slice(SECOND, &mut second).unwrap();
        match select_offer(&proposals, Some(&second)) {
            OfferChoice::One(p) => assert_eq!((p.hash, p.param.id), (second, 1001)),
            _ => panic!("the listed hash is selected"),
        }
        assert!(matches!(select_offer(&proposals, Some(&[0x11; 32])), OfferChoice::Missing));
        assert!(matches!(select_offer(&proposals, None), OfferChoice::Ambiguous));
        match select_offer(&proposals[..1], None) {
            OfferChoice::One(p) => assert_eq!(hex::encode(p.hash), FIRST),
            _ => panic!("a single proposal is selected without a hash"),
        }
    }
}
