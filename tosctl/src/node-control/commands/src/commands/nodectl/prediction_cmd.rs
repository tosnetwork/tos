/*
 * Copyright (C) 2025-2026 TOS Network.
 * Licensed under the GNU General Public License v3.0.
 */

//! `tosctl agent prediction`: fail-closed PredictionMarket V1 tooling.
//!
//! A prepared file is the complete, signed external-message BOC. It is made
//! durable before any optional broadcast so the same bytes can be retried
//! after a crash without rebuilding against a different wallet seqno.

use super::agent_cmd::{build_wallet_message_boc, confirm, open_economic_controller_journal};
use super::utils::{get_wallet_config, load_config_vault_rpc_client, make_wallet, wallet_info};
use anyhow::Context;
use base64::Engine;
use chain_block::{
    Cell, ConfigParamEnum, MsgAddressInt, Serializable, read_single_root_boc, write_boc,
};
use chain_rpc_client::v2::{client_json_rpc::ClientJsonRpc, data_models::AccountState};
use common::app_config::AppConfig;
use common::time_format;
use contracts::{
    AgentAccountContract, AgentCheckedContractCallV2, ChainProvider, ControllerActionClaim,
    ControllerActionStatus, DefaultChainProvider, EconomicEffectAuthorization,
    MasterchainCheckpoint, PREDICTION_MARKET_CODE_VERSION, PREDICTION_PRICE_SCALE,
    PredictionLiquidityRoleV1, PredictionMarketContractV1, PredictionMarketInitV1,
    PredictionOraclePolicyV1, PredictionOrderActionV1, PredictionOrderOutcomeV1, PredictionOrderV1,
    PredictionRelayRecoveryBoundary, PredictionResolutionContextsV1, Wallet,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
};

const OPERATION_BUDGET: u64 = 1_000_000_000;
const AUDITED_GLOBAL_VERSIONS: [u32; 2] = [14, 15];

#[derive(clap::Args, Clone)]
#[command(about = "PredictionMarket V1 operations")]
pub struct PredictionCmd {
    #[command(subcommand)]
    action: PredictionAction,
}

#[derive(clap::Subcommand, Clone)]
enum PredictionAction {
    /// Report the frozen CLI/contract capability profile
    Capabilities,
    /// Deterministically build a market StateInit and address
    BuildState(PredictionBuildStateCmd),
    /// Build a canonical order authorization or signed-order cell
    BuildOrder(PredictionBuildOrderCmd),
    /// Build one canonical operation body without signing or chain access
    BuildOperation(PredictionBuildOperationCmd),
    /// Verify and display deployed market state
    Show(PredictionShowCmd),
    /// Build and durably persist a signed deploy+activate external BOC
    PrepareDeploy(PredictionPrepareDeployCmd),
    /// Build and durably persist a signed operation external BOC
    Prepare(PredictionPrepareCmd),
    /// Prepare a custody-authorized Agent Account checked-contract-call v2
    PrepareAgent(PredictionPrepareAgentCmd),
}

#[derive(clap::Args, Clone)]
struct PredictionBuildStateCmd {
    #[arg(long)]
    definition: PathBuf,
    #[arg(long, help = "Optional raw StateInit BOC output path")]
    output_boc: Option<PathBuf>,
}

#[derive(clap::Args, Clone)]
struct PredictionBuildOrderCmd {
    #[arg(long)]
    definition: PathBuf,
    #[arg(long)]
    order: PathBuf,
    #[arg(long, requires = "signature", help = "32-byte Ed25519 public key")]
    public_key: Option<String>,
    #[arg(long, requires = "public_key", help = "64-byte Ed25519 signature over the digest")]
    signature: Option<String>,
    #[arg(long, help = "Optional raw order/signed-order BOC output path")]
    output_boc: Option<PathBuf>,
}

#[derive(clap::Args, Clone)]
struct PredictionBuildOperationCmd {
    #[arg(long)]
    definition: PathBuf,
    #[arg(long, help = "Strict tagged JSON operation request")]
    operation: PathBuf,
    #[arg(long, help = "Optional raw operation-body BOC output path")]
    output_boc: Option<PathBuf>,
}

#[derive(clap::Args, Clone)]
struct PredictionShowCmd {
    #[arg(long)]
    definition: PathBuf,
}

#[derive(clap::Args, Clone)]
struct PredictionPrepareDeployCmd {
    #[arg(long)]
    definition: PathBuf,
    #[arg(long, help = "Signing wallet name or master_wallet")]
    from: String,
    #[arg(long, help = "Exact deploy value in nanoTOS")]
    amount_nanotos: u64,
    #[arg(long, help = "New or byte-identical raw external-message BOC path")]
    output_boc: PathBuf,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
}

#[derive(clap::Args, Clone)]
struct PredictionPrepareCmd {
    #[arg(long)]
    definition: PathBuf,
    #[arg(long, help = "Strict tagged JSON operation request")]
    operation: PathBuf,
    #[arg(long, help = "Signing wallet name or master_wallet")]
    from: String,
    #[arg(long, help = "Exact message value in nanoTOS")]
    amount_nanotos: u64,
    #[arg(long, help = "New or byte-identical raw external-message BOC path")]
    output_boc: PathBuf,
}

#[derive(clap::Args, Clone)]
struct PredictionPrepareAgentCmd {
    #[arg(long)]
    definition: PathBuf,
    #[arg(long)]
    operation: PathBuf,
    #[arg(short = 'n', long = "wallet", help = "Agent Wallet profile name")]
    wallet: String,
    #[arg(long, help = "Exact message value in nanoTOS")]
    amount_nanotos: u64,
    #[arg(long, help = "Conservative Agent Account source fee reserve")]
    fee_reserve_nanotos: u64,
    #[arg(long)]
    valid_until: u32,
    #[arg(long = "authorization-file", help = "Absolute Prediction custody authorization JSON")]
    authorization_file: PathBuf,
    #[arg(long, help = "New or byte-identical raw external-message BOC path")]
    output_boc: PathBuf,
    #[arg(long)]
    yes: bool,
    #[arg(long, help = "Optional explicit owner-private custody journal directory")]
    journal_directory: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct OraclePolicyJson {
    threshold: u8,
    reporters: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarketDefinitionJson {
    global_id: i32,
    workchain_id: i8,
    deployment_salt: String,
    rules_hash: String,
    metadata_hash: String,
    reserve_recipient: String,
    trade_close: u64,
    resolve_not_before: u64,
    oracle_vote_deadline: u64,
    challenge_period: u64,
    appeal_review_delay: u64,
    appeal_period: u64,
    claim_deadline: u64,
    lot_value: u64,
    min_price_tick: u16,
    min_fill_lots: u64,
    max_order_lots: u64,
    max_locked_collateral: u64,
    max_account_free_balance: u64,
    max_total_free_balance: u64,
    max_total_liability: u64,
    max_participants: u32,
    max_orders_per_participant: u32,
    max_live_order_records: u32,
    participant_entry_fee: u64,
    account_cleanup_bounty: u64,
    order_entry_fee: u64,
    order_cleanup_bounty: u64,
    operating_reserve_floor: u64,
    terminal_tombstone_reserve: u64,
    challenge_bond: u64,
    challenge_processing_fee: u64,
    normal_oracle_policy: OraclePolicyJson,
    appellate_oracle_policy: OraclePolicyJson,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrderJson {
    global_id: i32,
    workchain_id: i8,
    market_address: String,
    market_config_hash: String,
    owner_address: String,
    key_epoch: u32,
    nonce: u64,
    salt: String,
    action: OrderActionJson,
    outcome: OrderOutcomeJson,
    liquidity_role: LiquidityRoleJson,
    quantity_lots: u64,
    min_fill_lots: u64,
    allow_partial: bool,
    limit_price_tick: u16,
    valid_after: u64,
    valid_until: u64,
    optional_counterparty: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OrderActionJson {
    Buy,
    Sell,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OrderOutcomeJson {
    Yes,
    No,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LiquidityRoleJson {
    Maker,
    Taker,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum OperationJson {
    RegisterAndDeposit {
        query_id: u64,
        credited_amount: u64,
        trading_pubkey: String,
    },
    Deposit {
        query_id: u64,
        credited_amount: u64,
    },
    SetTradingKey {
        query_id: u64,
        new_pubkey: String,
    },
    RaiseNonceFloor {
        query_id: u64,
        new_floor: u64,
    },
    CancelExact {
        query_id: u64,
        order: OrderJson,
    },
    Split {
        query_id: u64,
        quantity_lots: u64,
    },
    Merge {
        query_id: u64,
        quantity_lots: u64,
    },
    MatchPair {
        query_id: u64,
        quantity_lots: u64,
        left_signed_order_boc: String,
        right_signed_order_boc: String,
    },
    ReportResult {
        query_id: u64,
        round: u8,
        expected_round_context_hash: String,
        outcome: u8,
        evidence_root: String,
        statement_created_at: u64,
        statement_expiry: u64,
    },
    ChallengeResult {
        query_id: u64,
        expected_proposed_statement_hash: String,
        counter_outcome: u8,
        counter_evidence_root: String,
    },
    AdvancePhase {
        query_id: u64,
    },
    FinalizeUncontested {
        query_id: u64,
    },
    FinalizeReviewTimeout {
        query_id: u64,
        expected_review_base_context_hash: String,
    },
    Claim {
        query_id: u64,
        owner: String,
    },
    Withdraw {
        query_id: u64,
        amount: u64,
    },
    WithdrawChallengeBond {
        query_id: u64,
    },
    ForceRefundChallengeBond {
        query_id: u64,
        challenger: String,
    },
    PruneOrder {
        query_id: u64,
        owner: String,
        epoch: u32,
        nonce: u64,
        accept_reward: bool,
    },
    PruneOwnerOrders {
        query_id: u64,
        owner: String,
        accept_reward: bool,
    },
    CloseEmptyAccount {
        query_id: u64,
        owner: String,
        accept_reward: bool,
    },
    ForceCloseAccount {
        query_id: u64,
        owner: String,
        accept_reward: bool,
    },
    CompactTerminal {
        query_id: u64,
    },
    WithdrawTerminalSurplus {
        query_id: u64,
        amount: u64,
    },
    TopUpReserve {
        query_id: u64,
    },
}

struct BuiltOperation {
    body: Cell,
    operation: &'static str,
    risk_increasing: bool,
    credited_amount: u64,
    state_contribution: u64,
    minimum_value: u64,
}

impl PredictionCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            PredictionAction::Capabilities => capabilities(),
            PredictionAction::BuildState(cmd) => cmd.run(),
            PredictionAction::BuildOrder(cmd) => cmd.run(),
            PredictionAction::BuildOperation(cmd) => cmd.run(),
            PredictionAction::Show(cmd) => cmd.run(config_path).await,
            PredictionAction::PrepareDeploy(cmd) => cmd.run(config_path).await,
            PredictionAction::Prepare(cmd) => cmd.run(config_path).await,
            PredictionAction::PrepareAgent(cmd) => cmd.run(config_path).await,
        }
    }
}

fn capabilities() -> anyhow::Result<()> {
    let code = PredictionMarketContractV1::code()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "tos.prediction-market-cli-capabilities.v1",
            "contract_version": PREDICTION_MARKET_CODE_VERSION,
            "code_hash": format!("tvm-cell-sha256:{}", hex::encode(code.repr_hash().as_slice())),
            "minimum_global_version": 14,
            "full_risk_global_versions": AUDITED_GLOBAL_VERSIONS,
            "prepared_artifact": "exact-signed-external-message-boc",
            "agent_relay_preparation": {
                "schema": "tosctl.prediction-agent-effect-prepared.v1",
                "pre_broadcast_recovery_boundary": "pinned-rpc"
            },
            "get_methods": [
                "get_prediction_state", "get_prediction_accounting",
                "get_prediction_account", "get_prediction_order", "get_market_phase",
                "get_resolution_contexts"
            ]
        }))?
    );
    Ok(())
}

impl PredictionBuildStateCmd {
    fn run(&self) -> anyhow::Result<()> {
        let init = load_definition(&self.definition)?;
        let state_init = PredictionMarketContractV1::build_state_init(&init)?;
        let state_cell = state_init.write_to_new_cell()?.into_cell()?;
        let boc = write_boc(&state_cell)?;
        if let Some(path) = &self.output_boc {
            persist_exact(path, &boc)?;
        }
        print_state_artifact(&init, &boc, self.output_boc.as_deref())
    }
}

impl PredictionBuildOrderCmd {
    fn run(&self) -> anyhow::Result<()> {
        let init = load_definition(&self.definition)?;
        let order: OrderJson = load_json(&self.order)?;
        let order = convert_order(order)?;
        validate_order_for_market(&init, &order)?;
        let digest = PredictionMarketContractV1::order_digest(&order)?;
        let (kind, cell) = match (&self.public_key, &self.signature) {
            (Some(public_key), Some(signature)) => (
                "signed_order",
                PredictionMarketContractV1::build_signed_order(
                    &order,
                    parse_fixed_hex::<32>("public_key", public_key)?,
                    parse_fixed_hex::<64>("signature", signature)?,
                )?,
            ),
            (None, None) => ("order", PredictionMarketContractV1::build_order(&order)?),
            _ => anyhow::bail!("--public-key and --signature must be supplied together"),
        };
        let boc = write_boc(&cell)?;
        if let Some(path) = &self.output_boc {
            persist_exact(path, &boc)?;
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "tos.prediction-order-artifact.v1",
                "kind": kind,
                "digest": format!("tvm-cell-sha256:{}", hex::encode(digest)),
                "cell_hash": format!("tvm-cell-sha256:{}", hex::encode(cell.repr_hash().as_slice())),
                "boc_base64": base64::engine::general_purpose::STANDARD.encode(&boc),
                "output_boc": self.output_boc,
            }))?
        );
        Ok(())
    }
}

impl PredictionBuildOperationCmd {
    fn run(&self) -> anyhow::Result<()> {
        let init = load_definition(&self.definition)?;
        let operation: OperationJson = load_json(&self.operation)?;
        let built = build_operation(&init, operation)?;
        let address = PredictionMarketContractV1::calculate_address(&init)?;
        let market_id = PredictionMarketContractV1::market_id(&init)?;
        let market_config_hash = PredictionMarketContractV1::market_config_hash(&init)?;
        let market_code_hash = PredictionMarketContractV1::code()?.repr_hash();
        let source_agent_account_code_hash = AgentAccountContract::code()?.repr_hash();
        let boc = write_boc(&built.body)?;
        if let Some(path) = &self.output_boc {
            persist_exact(path, &boc)?;
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "tos.prediction-operation-artifact.v1",
                "operation": built.operation,
                "custody_action_kind": prediction_semantic_effect_kind(built.operation),
                "global_id": init.global_id,
                "workchain_id": init.workchain_id,
                "market_address": address.to_string(),
                "market_id": format!("sha256:{}", hex::encode(market_id)),
                "market_config_hash": format!("tvm-cell-sha256:{}", hex::encode(market_config_hash)),
                "market_code_hash": format!("tvm-cell-sha256:{}", hex::encode(market_code_hash.as_slice())),
                "source_agent_account_code_hash": format!("tvm-cell-sha256:{}", hex::encode(source_agent_account_code_hash.as_slice())),
                "risk_increasing": built.risk_increasing,
                "credited_amount": built.credited_amount,
                "state_contribution": built.state_contribution,
                "minimum_value": built.minimum_value,
                "body_hash": format!("tvm-cell-sha256:{}", hex::encode(built.body.repr_hash().as_slice())),
                "body_boc_base64": base64::engine::general_purpose::STANDARD.encode(&boc),
                "output_boc": self.output_boc,
            }))?
        );
        Ok(())
    }
}

impl PredictionShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let init = load_definition(&self.definition)?;
        // A market view is a read-only RPC projection. Loading a Vault here
        // would make an observer disclose a signing capability merely to
        // inspect public chain state, and breaks confined verifier processes
        // that intentionally inherit no ambient secret configuration.
        let config = AppConfig::load(Path::new(config_path))?;
        let rpc = Arc::new(ClientJsonRpc::connect_many(
            config.chain_rpc.resolved_endpoints(),
            config.chain_rpc.api_key.clone(),
        )?);
        let (address, global_version, checkpoint) = preflight_market(&rpc, &init, false).await?;
        let provider = DefaultChainProvider::new(rpc.clone());
        let state = PredictionMarketContractV1::decode_state(
            &provider
                .run_get_method_at(address.to_string(), "get_prediction_state", vec![], &checkpoint)
                .await?,
        )?;
        let accounting = PredictionMarketContractV1::decode_accounting(
            &provider
                .run_get_method_at(
                    address.to_string(),
                    "get_prediction_accounting",
                    vec![],
                    &checkpoint,
                )
                .await?,
        )?;
        let phase = PredictionMarketContractV1::decode_phase(
            &provider
                .run_get_method_at(address.to_string(), "get_market_phase", vec![], &checkpoint)
                .await?,
        )?;
        let contexts = PredictionMarketContractV1::decode_resolution_contexts(
            &provider
                .run_get_method_at(
                    address.to_string(),
                    "get_resolution_contexts",
                    vec![],
                    &checkpoint,
                )
                .await?,
        )?;
        let (current_context_boc_base64, review_base_context_boc_base64) =
            verified_resolution_context_bocs(&phase, &contexts)?;
        let normal_oracle_policy_hash =
            PredictionMarketContractV1::oracle_policy_hash(&init.normal_oracle_policy)?;
        let appellate_oracle_policy_hash =
            PredictionMarketContractV1::oracle_policy_hash(&init.appellate_oracle_policy)?;
        let final_outcome = matches!(
            state.status,
            contracts::PredictionMarketStatusV1::Finalized
                | contracts::PredictionMarketStatusV1::Terminal
        )
        .then(|| format!("{:?}", state.final_outcome).to_lowercase());
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "tos.prediction-market-chain-view.v1",
                "address": address.to_string(),
                "global_version": global_version,
                "checkpoint": {
                    "seqno": checkpoint.seqno,
                    "root_hash": checkpoint.root_hash,
                    "file_hash": checkpoint.file_hash,
                },
                "code_hash_verified": true,
                "config_hash_verified": true,
                "activated": state.activated,
                "activated_at": state.activated_at,
                "status": format!("{:?}", state.status).to_lowercase(),
                "review_reason": state.review_reason,
                "final_outcome": final_outcome,
                "market_id": hex::encode(state.market_id),
                "market_config_hash": hex::encode(state.market_config_hash),
                "normal_oracle_policy_hash": hex::encode(normal_oracle_policy_hash),
                "appellate_oracle_policy_hash": hex::encode(appellate_oracle_policy_hash),
                "participants": accounting.participants,
                "live_orders": accounting.live_orders,
                "fill_count": accounting.fill_count,
                "complete_sets": accounting.complete_sets,
                "total_free": accounting.total_free,
                "locked": accounting.locked,
                "final_backing": accounting.final_backing,
                "remaining_payout": accounting.remaining_payout,
                "claimed": accounting.claimed,
                "challenge_bond": accounting.challenge_bond,
                "cleanup_liability": accounting.cleanup_liability,
                "current_context_hash": hex::encode(phase.current_context_hash),
                "current_context_boc_base64": current_context_boc_base64,
                "review_base_context_hash": hex::encode(phase.review_base_context_hash),
                "review_base_context_boc_base64": review_base_context_boc_base64,
                "proposed_statement_hash": hex::encode(phase.proposed_statement_hash),
                "next_deadline": phase.next_deadline,
            }))?
        );
        Ok(())
    }
}

fn verified_resolution_context_bocs(
    phase: &contracts::PredictionMarketPhaseV1,
    contexts: &PredictionResolutionContextsV1,
) -> anyhow::Result<(Option<String>, Option<String>)> {
    let current_hash =
        contexts.current.as_ref().map(|value| *value.repr_hash().as_array()).unwrap_or([0; 32]);
    let review_base_hash =
        contexts.review_base.as_ref().map(|value| *value.repr_hash().as_array()).unwrap_or([0; 32]);
    anyhow::ensure!(
        current_hash == phase.current_context_hash,
        "resolution context cell conflicts with get_market_phase at the pinned checkpoint"
    );
    anyhow::ensure!(
        review_base_hash == phase.review_base_context_hash,
        "review base context cell conflicts with get_market_phase at the pinned checkpoint"
    );
    let encode = |value: &Cell| -> anyhow::Result<String> {
        Ok(base64::engine::general_purpose::STANDARD.encode(write_boc(value)?))
    };
    Ok((
        contexts.current.as_ref().map(encode).transpose()?,
        contexts.review_base.as_ref().map(encode).transpose()?,
    ))
}

impl PredictionPrepareDeployCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let init = load_definition(&self.definition)?;
        let (config, vault, rpc) = load_config_vault_rpc_client(Path::new(config_path)).await?;
        preflight_network_version(&rpc, &init, true).await?;
        let address = PredictionMarketContractV1::calculate_address(&init)?;
        let info = rpc.get_address_information(&address).await?;
        anyhow::ensure!(
            info.state == AccountState::Uninitialized,
            "refusing to deploy: market {address} is not uninitialized (state is {})",
            info.state
        );
        let minimum_value = init
            .operating_reserve_floor
            .checked_add(OPERATION_BUDGET)
            .context("deploy minimum value overflow")?;
        anyhow::ensure!(
            self.amount_nanotos >= minimum_value,
            "deploy value {} is below reserve + operation budget {}",
            self.amount_nanotos,
            minimum_value
        );
        let wallet_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?.clone();
        let (owner, wallet_info, secret) = wallet_info(rpc.clone(), &wallet_cfg, vault).await?;
        let wallet = make_wallet(rpc, &wallet_cfg, secret, &self.from).await?;
        let message = wallet
            .build_message(
                address.clone(),
                self.amount_nanotos,
                PredictionMarketContractV1::activate(self.query_id)?,
                true,
                wallet_info.seqno,
                None,
                Some(PredictionMarketContractV1::build_state_init(&init)?),
            )
            .await?;
        let boc = write_boc(&message)?;
        persist_exact(&self.output_boc, &boc)?;
        print_prepared(
            "deploy_activate",
            &address,
            &owner,
            self.amount_nanotos,
            minimum_value,
            0,
            0,
            &boc,
            &self.output_boc,
        )
    }
}

impl PredictionPrepareCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let init = load_definition(&self.definition)?;
        let operation: OperationJson = load_json(&self.operation)?;
        let built = build_operation(&init, operation)?;
        anyhow::ensure!(
            self.amount_nanotos >= built.minimum_value,
            "message value {} is below {} minimum {}",
            self.amount_nanotos,
            built.operation,
            built.minimum_value
        );
        let (config, vault, rpc) = load_config_vault_rpc_client(Path::new(config_path)).await?;
        let (address, _, _) = preflight_market(&rpc, &init, built.risk_increasing).await?;
        let wallet_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?.clone();
        let (owner, wallet_info, secret) = wallet_info(rpc.clone(), &wallet_cfg, vault).await?;
        let wallet = make_wallet(rpc, &wallet_cfg, secret, &self.from).await?;
        let boc = build_wallet_message_boc(
            &wallet,
            address.clone(),
            self.amount_nanotos,
            built.body,
            true,
            wallet_info.seqno,
        )
        .await?;
        persist_exact(&self.output_boc, &boc)?;
        print_prepared(
            built.operation,
            &address,
            &owner,
            self.amount_nanotos,
            built.minimum_value,
            built.credited_amount,
            built.state_contribution,
            &boc,
            &self.output_boc,
        )
    }
}

impl PredictionPrepareAgentCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let now = time_format::now();
        anyhow::ensure!(
            now <= u64::from(u32::MAX),
            "current chain-operation time cannot be represented by Agent Account"
        );
        anyhow::ensure!(
            self.valid_until > now as u32,
            "valid_until must be a future Unix timestamp"
        );
        anyhow::ensure!(
            self.authorization_file.is_absolute(),
            "authorization-file must be absolute"
        );
        let metadata = fs::symlink_metadata(&self.authorization_file)
            .context("inspect Prediction custody authorization file")?;
        anyhow::ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() > 0
                && metadata.len() <= 64 << 10,
            "Prediction custody authorization must be a bounded regular file"
        );
        let authorization: EconomicEffectAuthorization =
            serde_json::from_slice(&fs::read(&self.authorization_file)?)
                .context("decode PredictionCustodyEffectAuthorizationV1")?;

        let init = load_definition(&self.definition)?;
        let operation: OperationJson = load_json(&self.operation)?;
        let built = build_operation(&init, operation.clone())?;
        let semantic_kind =
            prediction_semantic_effect_kind(built.operation).with_context(|| {
                format!("{} has no reviewed Prediction custody action", built.operation)
            })?;
        anyhow::ensure!(
            self.amount_nanotos >= built.minimum_value,
            "message value {} is below {} minimum {}",
            self.amount_nanotos,
            built.operation,
            built.minimum_value
        );
        let body_hash =
            format!("tvm-cell-sha256:{}", hex::encode(built.body.repr_hash().as_slice()));
        let path = Path::new(config_path);
        let (config, vault, rpc) = load_config_vault_rpc_client(path).await?;
        let (market, _, checkpoint) = preflight_market(&rpc, &init, built.risk_increasing).await?;
        let market_code_hash = format!(
            "tvm-cell-sha256:{}",
            hex::encode(PredictionMarketContractV1::code()?.repr_hash().as_slice())
        );
        let market_config_hash = format!(
            "tvm-cell-sha256:{}",
            hex::encode(PredictionMarketContractV1::market_config_hash(&init)?)
        );
        let market_id =
            format!("sha256:{}", hex::encode(PredictionMarketContractV1::market_id(&init)?));

        let agent_wallet = config
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let runtime = agent_wallet
            .runtime
            .as_ref()
            .context("Agent Wallet has no owner-pinned runtime authority")?;
        let expected_authority_id = runtime
            .economic_authority_id
            .as_deref()
            .context("runtime has no economic_authority_id")?;
        let expected_key: [u8; 32] = hex::decode(
            runtime
                .economic_authority_public_key_hex
                .as_deref()
                .context("runtime has no economic_authority_public_key")?,
        )?
        .try_into()
        .map_err(|_| anyhow::anyhow!("pinned economic authority key must be 32 bytes"))?;
        let account = agent_wallet
            .agent_account_address
            .as_ref()
            .context("Agent Account is not deployed for this wallet")?
            .parse::<MsgAddressInt>()?;
        validate_autonomous_operation_at_checkpoint(
            &rpc,
            &market,
            &account,
            &init,
            &operation,
            &checkpoint,
            now,
        )
        .await?;
        let provider = contracts::contract_provider!(rpc.clone());
        let data = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
        anyhow::ensure!(
            u128::from(self.valid_until)
                <= u128::from(now) + u128::from(data.default_task_timeout_secs),
            "valid_until exceeds the Agent Account default_task_timeout"
        );
        let spent_after = data
            .spent_today
            .checked_add(self.amount_nanotos)
            .context("Agent Account daily spend would overflow")?;
        anyhow::ensure!(
            self.amount_nanotos <= data.max_per_tx && spent_after <= data.daily_limit,
            "Prediction effect exceeds Agent Account policy limits"
        );
        let required_source_balance = self
            .amount_nanotos
            .checked_add(self.fee_reserve_nanotos)
            .context("Prediction effect source balance requirement overflows")?;
        let account_info = rpc.get_address_information(&account).await?;
        anyhow::ensure!(
            account_info.state == AccountState::Active
                && account_info.balance >= required_source_balance,
            "Agent Account is inactive or lacks effect value plus fee reserve"
        );
        let deployed_source_code =
            account_info.code.as_ref().context("Agent Account has no deployed code")?;
        let source_code = read_single_root_boc(deployed_source_code)?;
        let expected_source_code = AgentAccountContract::code()?;
        anyhow::ensure!(
            source_code.repr_hash() == expected_source_code.repr_hash(),
            "Prediction custody requires the audited Agent Account code"
        );
        let source_code_hash =
            format!("tvm-cell-sha256:{}", hex::encode(expected_source_code.repr_hash().as_slice()));
        let global_id = match rpc.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => value as i32,
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        };
        let network = authorization
            .network_domain
            .as_ref()
            .context("Prediction custody authorization has no network-domain pin")?;
        anyhow::ensure!(
            network.global_id == global_id
                && network.workchain_id == account.workchain_id()
                && market.workchain_id() == network.workchain_id,
            "Prediction custody network domain conflicts with source or market"
        );
        rpc.verify_pinned_primary_network(network).await?;
        anyhow::ensure!(
            authorization.profile == "tos.prediction.checked-call.v1"
                && authorization.authority_id == expected_authority_id
                && authorization.public_key == format!("ed25519:{}", hex::encode(expected_key))
                && authorization.source_account == account.to_string()
                && authorization.source_agent_account_code_hash == source_code_hash
                && authorization.action_kind == semantic_kind
                && authorization.effect_kind == semantic_kind
                && authorization.destination == market.to_string()
                && authorization.market_address == market.to_string()
                && authorization.market_id == market_id
                && authorization.market_config_hash == market_config_hash
                && authorization.market_code_hash == market_code_hash
                && authorization.amount_nanotos == self.amount_nanotos
                && authorization.body_hash == body_hash
                && authorization.expires_at_unix >= u64::from(self.valid_until),
            "command effect differs from the owner-pinned Prediction authorization"
        );

        let secret = agent_wallet.controller_key.read_secret(Some(vault)).await?;
        let keypair = secret.as_keypair()?;
        let controller_pubkey: [u8; 32] = keypair
            .public_key()
            .await?
            .context("controller secret has no public key")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("controller public key must be 32 bytes"))?;
        anyhow::ensure!(
            controller_pubkey == data.controller_pubkey,
            "configured controller key does not match the Agent Account"
        );
        let stable_hex = authorization
            .stable_action_id
            .strip_prefix("sha256:")
            .context("Prediction stable action ID is not canonical")?;
        parse_fixed_hex::<32>("stable_action_id", stable_hex)?;
        if !self.yes
            && !confirm(&format!(
                "Authorize Prediction effect {} ({}) from {} to {}?",
                authorization.stable_action_id, semantic_kind, account, market
            ))?
        {
            anyhow::bail!("owner declined Prediction effect authorization");
        }
        // The recovery boundary is an observation made by the same pinned RPC
        // which prepares the exact external BOC. It must not be supplied by
        // an OpenFox caller: that would let an untrusted caller choose where a
        // later authenticated history walk stops.
        //
        // Keep this immediately before the durable claim/signing boundary.
        // Everything after it is local journal and signing work until the BOC
        // is returned; no network write occurs here.
        let pre_broadcast_source = rpc.get_address_information(&account).await?;
        anyhow::ensure!(
            pre_broadcast_source.state == AccountState::Active,
            "Agent Account became inactive before Prediction effect preparation"
        );
        let pre_broadcast_master = rpc.get_masterchain_info().await?;
        let (pre_broadcast_source_cursor, pre_broadcast_masterchain_checkpoint) =
            prediction_pre_broadcast_boundary(
                &account.to_string(),
                pre_broadcast_source.last_transaction_id.lt,
                &pre_broadcast_source.last_transaction_id.hash,
                pre_broadcast_master.last.shard,
                pre_broadcast_master.last.seqno,
                &pre_broadcast_master.last.root_hash,
                &pre_broadcast_master.last.file_hash,
            )?;
        let journal = open_economic_controller_journal(
            path,
            self.journal_directory.as_deref(),
            runtime.economic_custody_journal_directory.as_deref(),
        )?;
        let deployment_id = hex::encode(data.deployment_id);
        journal.reconcile_finalized_state(
            &account.to_string(),
            global_id,
            &deployment_id,
            data.controller_epoch,
            data.seqno,
            now,
        )?;
        let claim = ControllerActionClaim {
            account: account.to_string(),
            network_global_id: global_id,
            network_domain: Some(network.clone()),
            deployment_id,
            controller_epoch: data.controller_epoch,
            seqno: data.seqno,
            target: market.to_string(),
            value_atomic: self.amount_nanotos,
            body_hash: Some(body_hash.clone()),
            state_init_hash: None,
            action_kind: "agent-checked-contract-call-v2".into(),
            idempotency_key: stable_hex.to_owned(),
            action_identity: authorization.stable_action_id.clone(),
            valid_until: self.valid_until,
        };
        let (record, _) = journal.claim_prediction_effect(
            claim.clone(),
            authorization.clone(),
            expected_authority_id,
            expected_key,
            now,
        )?;
        // Reuse the owner-private boundary already fixed for an idempotent
        // retry. A freshly observed boundary after the first preparation is
        // necessarily later and must never replace the history-walk anchor.
        let recovery_boundary =
            if let Some(boundary) = record.prediction_relay_recovery_boundary.clone() {
                boundary
            } else {
                let boundary: PredictionRelayRecoveryBoundary = serde_json::from_value(json!({
                    "source_cursor": pre_broadcast_source_cursor,
                    "masterchain_checkpoint": pre_broadcast_masterchain_checkpoint,
                }))
                .context("serialize Prediction relay recovery boundary")?;
                journal
                    .attach_prediction_relay_recovery_boundary(&claim, boundary, now)?
                    .prediction_relay_recovery_boundary
                    .context("custody did not retain Prediction relay recovery boundary")?
            };
        let pre_broadcast_source_cursor = serde_json::to_value(&recovery_boundary.source_cursor)?;
        let pre_broadcast_masterchain_checkpoint =
            serde_json::to_value(&recovery_boundary.masterchain_checkpoint)?;
        anyhow::ensure!(
            record.status != ControllerActionStatus::Resolved,
            "Prediction effect sequence was consumed; resolve before retry"
        );
        let boc = if let Some(encoded) = record.exact_signed_boc_base64 {
            base64::engine::general_purpose::STANDARD.decode(encoded)?
        } else {
            let payload = AgentAccountContract::build_checked_contract_call_v2_payload(
                global_id,
                data.controller_epoch,
                data.seqno,
                self.valid_until,
                &AgentCheckedContractCallV2 {
                    target: market.clone(),
                    value: self.amount_nanotos,
                    body: built.body,
                },
            )?;
            let hash =
                AgentAccountContract::controller_hash_to_sign(&account, global_id, &payload)?;
            let signature: [u8; 64] = keypair
                .sign(&hash)
                .await?
                .try_into()
                .map_err(|_| anyhow::anyhow!("controller signature must be 64 bytes"))?;
            let signed =
                AgentAccountContract::build_signed_controller_message(payload, &signature)?;
            let message =
                AgentAccountContract::build_external_controller_message(account.clone(), signed)?;
            let boc = write_boc(&message)?;
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&boc)));
            journal.attach_signed_boc(
                &claim,
                &base64::engine::general_purpose::STANDARD.encode(&boc),
                &digest,
                now,
            )?;
            boc
        };
        persist_exact(&self.output_boc, &boc)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "tosctl.prediction-agent-effect-prepared.v1",
                "stable_action_id": authorization.stable_action_id,
                "action_kind": authorization.action_kind,
                "source": account.to_string(),
                "source_agent_account_code_hash": source_code_hash,
                "destination": market.to_string(),
                "market_id": market_id,
                "market_config_hash": market_config_hash,
                "market_code_hash": market_code_hash,
                "amount_nanotos": self.amount_nanotos,
                "body_hash": body_hash,
                "controller_epoch": data.controller_epoch,
                "seqno": data.seqno,
                "valid_until": self.valid_until,
                "network_domain": network,
                "pre_broadcast_source_cursor": pre_broadcast_source_cursor,
                "pre_broadcast_masterchain_checkpoint": pre_broadcast_masterchain_checkpoint,
                "exact_signed_boc": base64::engine::general_purpose::STANDARD.encode(&boc),
                "exact_signed_boc_digest": format!("sha256:{}", hex::encode(Sha256::digest(&boc))),
                "output_boc": self.output_boc,
                "broadcast": false,
            }))?
        );
        Ok(())
    }
}

// Serialize the only pre-broadcast recovery boundary accepted by OpenFox.
// Keeping this conversion pure makes its zero-cursor and canonical-hash
// contract regression-testable without an RPC fixture.
fn prediction_pre_broadcast_boundary(
    account: &str,
    source_lt: u64,
    source_hash: &[u8],
    masterchain_shard: i64,
    masterchain_seqno: u32,
    masterchain_root_hash: &[u8],
    masterchain_file_hash: &[u8],
) -> anyhow::Result<(serde_json::Value, serde_json::Value)> {
    anyhow::ensure!(!account.is_empty(), "Agent Account source address is empty");
    let source_hash = if source_lt == 0 {
        anyhow::ensure!(
            source_hash.is_empty(),
            "zero Agent Account source cursor carries a transaction hash"
        );
        String::new()
    } else {
        anyhow::ensure!(source_hash.len() == 32, "Agent Account source cursor hash is malformed");
        format!("sha256:{}", hex::encode(source_hash))
    };
    anyhow::ensure!(
        masterchain_seqno > 0
            && masterchain_root_hash.len() == 32
            && masterchain_file_hash.len() == 32,
        "pre-broadcast masterchain checkpoint is malformed"
    );
    Ok((
        json!({
            "account_address": account,
            "last_logical_time": source_lt,
            "last_transaction_hash": source_hash,
        }),
        json!({
            "workchain_id": -1,
            "shard": masterchain_shard,
            "sequence_number": masterchain_seqno,
            "root_hash": format!("sha256:{}", hex::encode(masterchain_root_hash)),
            "file_hash": format!("sha256:{}", hex::encode(masterchain_file_hash)),
            // This is the strict field name consumed by
            // `prediction-relay-source-resolve`. The prepared artifact is a
            // direct resolver input, so an abbreviated local spelling would
            // make a valid preparation unrecoverable.
            "masterchain_sequence_number": masterchain_seqno,
        }),
    ))
}

fn prediction_semantic_effect_kind(operation: &str) -> Option<&'static str> {
    match operation {
        "register_and_deposit" | "deposit" => Some("prediction.collateral.deposit"),
        "set_trading_key" => Some("prediction.trading-key.rotate"),
        "raise_nonce_floor" => Some("prediction.order.nonce-floor.raise"),
        "cancel_exact" => Some("prediction.order.cancel-exact"),
        "split" => Some("prediction.position.split"),
        "merge" => Some("prediction.position.merge"),
        "match_pair" => Some("prediction.match.submit"),
        "report_result" => Some("prediction.resolution.report"),
        "challenge_result" => Some("prediction.resolution.challenge"),
        "advance_phase" => Some("prediction.market.advance-phase"),
        "finalize_uncontested" | "finalize_review_timeout" => {
            Some("prediction.resolution.finalize")
        }
        "claim" => Some("prediction.position.claim"),
        "withdraw" => Some("prediction.collateral.withdraw"),
        "withdraw_challenge_bond" | "force_refund_challenge_bond" => {
            Some("prediction.challenge-bond.withdraw")
        }
        "compact_terminal" => Some("prediction.market.compact"),
        "withdraw_terminal_surplus" => Some("prediction.terminal-surplus.withdraw"),
        "top_up_reserve" => Some("prediction.reserve.top-up"),
        _ => None,
    }
}

async fn preflight_network_version(
    rpc: &Arc<ClientJsonRpc>,
    init: &PredictionMarketInitV1,
    risk_increasing: bool,
) -> anyhow::Result<u32> {
    let chain_global_id = rpc.get_global_id().await.context("read chain global_id")?;
    anyhow::ensure!(
        chain_global_id == init.global_id,
        "market global_id {} does not match connected chain {}",
        init.global_id,
        chain_global_id
    );
    let ConfigParamEnum::ConfigParam8(param) = rpc.get_config_param(8).await? else {
        anyhow::bail!("chain ConfigParam 8 is missing or has the wrong type");
    };
    let version = param.global_version.version;
    validate_global_version(version, risk_increasing)?;
    Ok(version)
}

fn validate_global_version(version: u32, risk_increasing: bool) -> anyhow::Result<()> {
    anyhow::ensure!(version >= 14, "TOS global version {version} is below required version 14");
    if risk_increasing {
        anyhow::ensure!(
            AUDITED_GLOBAL_VERSIONS.contains(&version),
            "risk-increasing PredictionMarket operations are not audited for global version {version}"
        );
    }
    Ok(())
}

async fn preflight_market(
    rpc: &Arc<ClientJsonRpc>,
    init: &PredictionMarketInitV1,
    risk_increasing: bool,
) -> anyhow::Result<(MsgAddressInt, u32, MasterchainCheckpoint)> {
    let version = preflight_network_version(rpc, init, risk_increasing).await?;
    let address = PredictionMarketContractV1::calculate_address(init)?;
    let info = rpc.get_address_information(&address).await?;
    anyhow::ensure!(info.state == AccountState::Active, "market {address} is not active");
    let deployed_code = info.code.as_ref().context("active market omitted code")?;
    let deployed_code = read_single_root_boc(deployed_code).context("invalid deployed code BOC")?;
    anyhow::ensure!(
        deployed_code.repr_hash() == PredictionMarketContractV1::code()?.repr_hash(),
        "market {address} code hash does not match PredictionMarket V1"
    );
    let provider = DefaultChainProvider::new(rpc.clone());
    let master = provider.get_masterchain_info().await?;
    anyhow::ensure!(master.last.seqno > 0, "masterchain checkpoint is not initialized");
    anyhow::ensure!(
        master.last.root_hash.len() == 32 && master.last.file_hash.len() == 32,
        "masterchain checkpoint hashes are malformed"
    );
    let checkpoint = MasterchainCheckpoint {
        seqno: master.last.seqno,
        root_hash: hex::encode(master.last.root_hash),
        file_hash: hex::encode(master.last.file_hash),
    };
    let state = PredictionMarketContractV1::decode_state(
        &provider
            .run_get_method_at(address.to_string(), "get_prediction_state", vec![], &checkpoint)
            .await?,
    )?;
    anyhow::ensure!(
        state.market_config_hash == PredictionMarketContractV1::market_config_hash(init)?,
        "deployed market config hash does not match --definition"
    );
    anyhow::ensure!(
        state.market_id == PredictionMarketContractV1::market_id(init)?,
        "deployed market id does not match --definition"
    );
    Ok((address, version, checkpoint))
}

async fn validate_autonomous_operation_at_checkpoint(
    rpc: &Arc<ClientJsonRpc>,
    market: &MsgAddressInt,
    source: &MsgAddressInt,
    init: &PredictionMarketInitV1,
    operation: &OperationJson,
    checkpoint: &MasterchainCheckpoint,
    now: u64,
) -> anyhow::Result<()> {
    if !matches!(
        operation,
        OperationJson::ReportResult { .. }
            | OperationJson::ChallengeResult { .. }
            | OperationJson::FinalizeUncontested { .. }
            | OperationJson::FinalizeReviewTimeout { .. }
    ) {
        return Ok(());
    }
    let provider = DefaultChainProvider::new(rpc.clone());
    let phase = PredictionMarketContractV1::decode_phase(
        &provider
            .run_get_method_at(market.to_string(), "get_market_phase", vec![], checkpoint)
            .await?,
    )?;
    validate_autonomous_operation_phase(source, init, operation, &phase, now)
}

fn validate_autonomous_operation_phase(
    source: &MsgAddressInt,
    init: &PredictionMarketInitV1,
    operation: &OperationJson,
    phase: &contracts::PredictionMarketPhaseV1,
    now: u64,
) -> anyhow::Result<()> {
    match operation {
        OperationJson::ReportResult {
            round,
            expected_round_context_hash,
            statement_created_at,
            statement_expiry,
            ..
        } => {
            let expected = parse_hash("expected_round_context_hash", expected_round_context_hash)?;
            anyhow::ensure!(
                phase.current_context_hash != [0; 32] && phase.current_context_hash == expected,
                "report authorization requires the exact opened round context"
            );
            let (wanted_status, reporters) = match round {
                0 => (
                    contracts::PredictionMarketStatusV1::Reporting,
                    &init.normal_oracle_policy.reporters,
                ),
                1 => (
                    contracts::PredictionMarketStatusV1::Reviewing,
                    &init.appellate_oracle_policy.reporters,
                ),
                _ => anyhow::bail!("report round must be NORMAL=0 or APPEAL=1"),
            };
            anyhow::ensure!(
                phase.status == wanted_status && reporters.iter().any(|value| value == source),
                "source Agent Account is not an admitted reporter for the current round"
            );
            anyhow::ensure!(
                *statement_created_at <= now
                    && now < *statement_expiry
                    && *statement_expiry <= phase.next_deadline,
                "report statement time is outside the opened round"
            );
        }
        OperationJson::ChallengeResult { expected_proposed_statement_hash, .. } => {
            anyhow::ensure!(
                phase.status == contracts::PredictionMarketStatusV1::Proposed
                    && phase.proposed_statement_hash != [0; 32]
                    && phase.proposed_statement_hash
                        == parse_hash(
                            "expected_proposed_statement_hash",
                            expected_proposed_statement_hash,
                        )?
                    && now < phase.next_deadline,
                "challenge authorization requires the exact live proposal"
            );
        }
        OperationJson::FinalizeUncontested { .. } => {
            anyhow::ensure!(
                phase.status == contracts::PredictionMarketStatusV1::Proposed
                    && now >= phase.next_deadline,
                "uncontested finalize authorization is not yet executable"
            );
        }
        OperationJson::FinalizeReviewTimeout { expected_review_base_context_hash, .. } => {
            anyhow::ensure!(
                phase.status == contracts::PredictionMarketStatusV1::Reviewing
                    && phase.review_base_context_hash != [0; 32]
                    && phase.review_base_context_hash
                        == parse_hash(
                            "expected_review_base_context_hash",
                            expected_review_base_context_hash,
                        )?
                    && now >= phase.next_deadline,
                "review-timeout finalize authorization requires the exact expired review"
            );
        }
        _ => {}
    }
    Ok(())
}

fn build_operation(
    init: &PredictionMarketInitV1,
    operation: OperationJson,
) -> anyhow::Result<BuiltOperation> {
    let mut credited = 0;
    let mut contribution = 0;
    let (name, risk, minimum, body) = match operation {
        OperationJson::RegisterAndDeposit { query_id, credited_amount, trading_pubkey } => {
            anyhow::ensure!(
                credited_amount >= 1_000_000,
                "initial credited_amount must be at least 1000000 nanoTOS"
            );
            credited = credited_amount;
            contribution = init
                .participant_entry_fee
                .checked_add(init.account_cleanup_bounty)
                .context("participant contribution overflow")?;
            (
                "register_and_deposit",
                true,
                credited
                    .checked_add(contribution)
                    .and_then(|value| value.checked_add(OPERATION_BUDGET))
                    .context("register minimum overflow")?,
                PredictionMarketContractV1::register_and_deposit(
                    query_id,
                    credited,
                    parse_fixed_hex::<32>("trading_pubkey", &trading_pubkey)?,
                )?,
            )
        }
        OperationJson::Deposit { query_id, credited_amount } => {
            anyhow::ensure!(credited_amount > 0, "credited_amount must be nonzero");
            credited = credited_amount;
            (
                "deposit",
                true,
                credited.checked_add(OPERATION_BUDGET).context("deposit minimum overflow")?,
                PredictionMarketContractV1::deposit(query_id, credited)?,
            )
        }
        OperationJson::SetTradingKey { query_id, new_pubkey } => (
            "set_trading_key",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::set_trading_key(
                query_id,
                parse_fixed_hex::<32>("new_pubkey", &new_pubkey)?,
            )?,
        ),
        OperationJson::RaiseNonceFloor { query_id, new_floor } => (
            "raise_nonce_floor",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::raise_nonce_floor(query_id, new_floor)?,
        ),
        OperationJson::CancelExact { query_id, order } => {
            let order = convert_order(order)?;
            validate_order_for_market(init, &order)?;
            contribution = init
                .order_entry_fee
                .checked_add(init.order_cleanup_bounty)
                .context("cancel state contribution overflow")?;
            (
                "cancel_exact",
                false,
                contribution.checked_add(OPERATION_BUDGET).context("cancel minimum overflow")?,
                PredictionMarketContractV1::cancel_exact(query_id, &order)?,
            )
        }
        OperationJson::Split { query_id, quantity_lots } => (
            "split",
            true,
            OPERATION_BUDGET,
            PredictionMarketContractV1::split(query_id, quantity_lots)?,
        ),
        OperationJson::Merge { query_id, quantity_lots } => (
            "merge",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::merge(query_id, quantity_lots)?,
        ),
        OperationJson::MatchPair {
            query_id,
            quantity_lots,
            left_signed_order_boc,
            right_signed_order_boc,
        } => {
            contribution = init
                .order_entry_fee
                .checked_add(init.order_cleanup_bounty)
                .and_then(|value| value.checked_mul(2))
                .context("match state contribution overflow")?;
            (
                "match_pair",
                true,
                contribution.checked_add(OPERATION_BUDGET).context("match minimum overflow")?,
                PredictionMarketContractV1::match_pair(
                    query_id,
                    quantity_lots,
                    decode_cell_boc("left_signed_order_boc", &left_signed_order_boc)?,
                    decode_cell_boc("right_signed_order_boc", &right_signed_order_boc)?,
                )?,
            )
        }
        OperationJson::ReportResult {
            query_id,
            round,
            expected_round_context_hash,
            outcome,
            evidence_root,
            statement_created_at,
            statement_expiry,
        } => (
            "report_result",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::report_result(
                query_id,
                round,
                parse_hash("expected_round_context_hash", &expected_round_context_hash)?,
                outcome,
                parse_hash("evidence_root", &evidence_root)?,
                statement_created_at,
                statement_expiry,
            )?,
        ),
        OperationJson::ChallengeResult {
            query_id,
            expected_proposed_statement_hash,
            counter_outcome,
            counter_evidence_root,
        } => (
            "challenge_result",
            false,
            init.challenge_bond
                .checked_add(init.challenge_processing_fee)
                .and_then(|value| value.checked_add(OPERATION_BUDGET))
                .context("challenge minimum overflow")?,
            PredictionMarketContractV1::challenge_result(
                query_id,
                parse_hash("expected_proposed_statement_hash", &expected_proposed_statement_hash)?,
                counter_outcome,
                parse_hash("counter_evidence_root", &counter_evidence_root)?,
            )?,
        ),
        OperationJson::AdvancePhase { query_id } => (
            "advance_phase",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::advance_phase(query_id)?,
        ),
        OperationJson::FinalizeUncontested { query_id } => (
            "finalize_uncontested",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::finalize_uncontested(query_id)?,
        ),
        OperationJson::FinalizeReviewTimeout { query_id, expected_review_base_context_hash } => (
            "finalize_review_timeout",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::finalize_review_timeout(
                query_id,
                parse_hash(
                    "expected_review_base_context_hash",
                    &expected_review_base_context_hash,
                )?,
            )?,
        ),
        OperationJson::Claim { query_id, owner } => (
            "claim",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::claim(query_id, &parse_address("owner", &owner)?)?,
        ),
        OperationJson::Withdraw { query_id, amount } => (
            "withdraw",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::withdraw(query_id, amount)?,
        ),
        OperationJson::WithdrawChallengeBond { query_id } => (
            "withdraw_challenge_bond",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::withdraw_challenge_bond(query_id)?,
        ),
        OperationJson::ForceRefundChallengeBond { query_id, challenger } => (
            "force_refund_challenge_bond",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::force_refund_challenge_bond(
                query_id,
                &parse_address("challenger", &challenger)?,
            )?,
        ),
        OperationJson::PruneOrder { query_id, owner, epoch, nonce, accept_reward } => (
            "prune_order",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::prune_order(
                query_id,
                &parse_address("owner", &owner)?,
                epoch,
                nonce,
                accept_reward,
            )?,
        ),
        OperationJson::PruneOwnerOrders { query_id, owner, accept_reward } => (
            "prune_owner_orders",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::prune_owner_orders(
                query_id,
                &parse_address("owner", &owner)?,
                accept_reward,
            )?,
        ),
        OperationJson::CloseEmptyAccount { query_id, owner, accept_reward } => (
            "close_empty_account",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::close_empty_account(
                query_id,
                &parse_address("owner", &owner)?,
                accept_reward,
            )?,
        ),
        OperationJson::ForceCloseAccount { query_id, owner, accept_reward } => (
            "force_close_account",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::force_close_account(
                query_id,
                &parse_address("owner", &owner)?,
                accept_reward,
            )?,
        ),
        OperationJson::CompactTerminal { query_id } => (
            "compact_terminal",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::compact_terminal(query_id)?,
        ),
        OperationJson::WithdrawTerminalSurplus { query_id, amount } => (
            "withdraw_terminal_surplus",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::withdraw_terminal_surplus(query_id, amount)?,
        ),
        OperationJson::TopUpReserve { query_id } => (
            "top_up_reserve",
            false,
            OPERATION_BUDGET,
            PredictionMarketContractV1::top_up_reserve(query_id)?,
        ),
    };
    Ok(BuiltOperation {
        body,
        operation: name,
        risk_increasing: risk,
        credited_amount: credited,
        state_contribution: contribution,
        minimum_value: minimum,
    })
}

fn load_definition(path: &Path) -> anyhow::Result<PredictionMarketInitV1> {
    let value: MarketDefinitionJson = load_json(path)?;
    Ok(PredictionMarketInitV1 {
        global_id: value.global_id,
        workchain_id: value.workchain_id,
        deployment_salt: parse_hash("deployment_salt", &value.deployment_salt)?,
        rules_hash: parse_hash("rules_hash", &value.rules_hash)?,
        metadata_hash: parse_hash("metadata_hash", &value.metadata_hash)?,
        reserve_recipient: parse_address("reserve_recipient", &value.reserve_recipient)?,
        trade_close: value.trade_close,
        resolve_not_before: value.resolve_not_before,
        oracle_vote_deadline: value.oracle_vote_deadline,
        challenge_period: value.challenge_period,
        appeal_review_delay: value.appeal_review_delay,
        appeal_period: value.appeal_period,
        claim_deadline: value.claim_deadline,
        lot_value: value.lot_value,
        min_price_tick: value.min_price_tick,
        min_fill_lots: value.min_fill_lots,
        max_order_lots: value.max_order_lots,
        max_locked_collateral: value.max_locked_collateral,
        max_account_free_balance: value.max_account_free_balance,
        max_total_free_balance: value.max_total_free_balance,
        max_total_liability: value.max_total_liability,
        max_participants: value.max_participants,
        max_orders_per_participant: value.max_orders_per_participant,
        max_live_order_records: value.max_live_order_records,
        participant_entry_fee: value.participant_entry_fee,
        account_cleanup_bounty: value.account_cleanup_bounty,
        order_entry_fee: value.order_entry_fee,
        order_cleanup_bounty: value.order_cleanup_bounty,
        operating_reserve_floor: value.operating_reserve_floor,
        terminal_tombstone_reserve: value.terminal_tombstone_reserve,
        challenge_bond: value.challenge_bond,
        challenge_processing_fee: value.challenge_processing_fee,
        normal_oracle_policy: convert_policy(value.normal_oracle_policy)?,
        appellate_oracle_policy: convert_policy(value.appellate_oracle_policy)?,
    })
}

fn convert_policy(value: OraclePolicyJson) -> anyhow::Result<PredictionOraclePolicyV1> {
    Ok(PredictionOraclePolicyV1 {
        threshold: value.threshold,
        reporters: value
            .reporters
            .iter()
            .map(|address| parse_address("reporter", address))
            .collect::<anyhow::Result<_>>()?,
    })
}

fn convert_order(value: OrderJson) -> anyhow::Result<PredictionOrderV1> {
    Ok(PredictionOrderV1 {
        global_id: value.global_id,
        workchain_id: value.workchain_id,
        market_address: parse_address("market_address", &value.market_address)?,
        market_config_hash: parse_tvm_hash("market_config_hash", &value.market_config_hash)?,
        owner_address: parse_address("owner_address", &value.owner_address)?,
        key_epoch: value.key_epoch,
        nonce: value.nonce,
        salt: parse_hash("salt", &value.salt)?,
        action: match value.action {
            OrderActionJson::Buy => PredictionOrderActionV1::Buy,
            OrderActionJson::Sell => PredictionOrderActionV1::Sell,
        },
        outcome: match value.outcome {
            OrderOutcomeJson::Yes => PredictionOrderOutcomeV1::Yes,
            OrderOutcomeJson::No => PredictionOrderOutcomeV1::No,
        },
        liquidity_role: match value.liquidity_role {
            LiquidityRoleJson::Maker => PredictionLiquidityRoleV1::Maker,
            LiquidityRoleJson::Taker => PredictionLiquidityRoleV1::Taker,
        },
        quantity_lots: value.quantity_lots,
        min_fill_lots: value.min_fill_lots,
        allow_partial: value.allow_partial,
        limit_price_tick: value.limit_price_tick,
        valid_after: value.valid_after,
        valid_until: value.valid_until,
        optional_counterparty: value
            .optional_counterparty
            .as_deref()
            .map(|address| parse_address("optional_counterparty", address))
            .transpose()?,
    })
}

fn validate_order_for_market(
    init: &PredictionMarketInitV1,
    order: &PredictionOrderV1,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        order.global_id == init.global_id && order.workchain_id == init.workchain_id,
        "order network domain does not match market definition"
    );
    anyhow::ensure!(
        order.market_address == PredictionMarketContractV1::calculate_address(init)?,
        "order market address does not match deterministic market definition"
    );
    anyhow::ensure!(
        order.market_config_hash == PredictionMarketContractV1::market_config_hash(init)?,
        "order market config hash does not match market definition"
    );
    anyhow::ensure!(
        order.valid_until <= init.trade_close,
        "order expiry exceeds the immutable market trade close"
    );
    anyhow::ensure!(
        order.quantity_lots <= init.max_order_lots
            && order.min_fill_lots >= init.min_fill_lots
            && order.limit_price_tick >= init.min_price_tick
            && order.limit_price_tick <= PREDICTION_PRICE_SCALE - init.min_price_tick,
        "order quantity, fill or price violates immutable market limits"
    );
    Ok(())
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> anyhow::Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse strict JSON {}", path.display()))
}

fn parse_address(label: &str, value: &str) -> anyhow::Result<MsgAddressInt> {
    value.parse().with_context(|| format!("invalid {label} address"))
}

fn parse_hash(label: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    parse_fixed_hex(label, value)
}

fn parse_tvm_hash(label: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    let value = value.strip_prefix("tvm-cell-sha256:").unwrap_or(value);
    parse_fixed_hex(label, value)
}

fn parse_fixed_hex<const N: usize>(label: &str, value: &str) -> anyhow::Result<[u8; N]> {
    anyhow::ensure!(
        value.len() == N * 2
            && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} must be exactly {} lowercase hex characters",
        N * 2
    );
    hex::decode(value)?.try_into().map_err(|_| anyhow::anyhow!("{label} must decode to {N} bytes"))
}

fn decode_cell_boc(label: &str, value: &str) -> anyhow::Result<Cell> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .with_context(|| format!("decode {label} base64"))?;
    read_single_root_boc(&bytes).with_context(|| format!("decode {label} single-root BOC"))
}

fn persist_exact(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let existing = fs::read(path)?;
            anyhow::ensure!(
                existing == bytes,
                "refusing to overwrite non-identical exact BOC {}",
                path.display()
            );
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("create {}", path.display())),
    }
}

fn print_state_artifact(
    init: &PredictionMarketInitV1,
    boc: &[u8],
    output: Option<&Path>,
) -> anyhow::Result<()> {
    let code = PredictionMarketContractV1::code()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "tos.prediction-market-state-init.v1",
            "address": PredictionMarketContractV1::calculate_address(init)?.to_string(),
            "code_hash": format!("tvm-cell-sha256:{}", hex::encode(code.repr_hash().as_slice())),
            "market_config_hash": format!("tvm-cell-sha256:{}", hex::encode(PredictionMarketContractV1::market_config_hash(init)?)),
            "market_id": format!("sha256:{}", hex::encode(PredictionMarketContractV1::market_id(init)?)),
            "rules_hash": format!("sha256:{}", hex::encode(init.rules_hash)),
            "state_init_boc_base64": base64::engine::general_purpose::STANDARD.encode(boc),
            "output_boc": output,
        }))?
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn print_prepared(
    operation: &str,
    address: &MsgAddressInt,
    source: &MsgAddressInt,
    value: u64,
    minimum_value: u64,
    credited_amount: u64,
    state_contribution: u64,
    boc: &[u8],
    output: &Path,
) -> anyhow::Result<()> {
    let root = read_single_root_boc(boc)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "tos.prediction-prepared-exact-boc.v1",
            "operation": operation,
            "source": source.to_string(),
            "destination": address.to_string(),
            "message_value": value,
            "minimum_value": minimum_value,
            "credited_amount": credited_amount,
            "state_contribution": state_contribution,
            "operation_budget": OPERATION_BUDGET,
            "reserve_donation": value.saturating_sub(minimum_value),
            "message_hash": format!("tvm-cell-sha256:{}", hex::encode(root.repr_hash().as_slice())),
            "message_boc_base64": base64::engine::general_purpose::STANDARD.encode(boc),
            "output_boc": output,
            "broadcast": false,
        }))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_init() -> PredictionMarketInitV1 {
        PredictionMarketInitV1 {
            global_id: 42,
            workchain_id: -1,
            deployment_salt: [0x11; 32],
            rules_hash: [0x22; 32],
            metadata_hash: [0x33; 32],
            reserve_recipient:
                "-1:1111111111111111111111111111111111111111111111111111111111111111"
                    .parse()
                    .unwrap(),
            trade_close: 1_800_000_000,
            resolve_not_before: 1_800_000_100,
            oracle_vote_deadline: 1_800_000_300,
            challenge_period: 120,
            appeal_review_delay: 60,
            appeal_period: 180,
            claim_deadline: 1_800_001_000,
            lot_value: 1_000_000_000,
            min_price_tick: 100,
            min_fill_lots: 1,
            max_order_lots: 100,
            max_locked_collateral: 100_000_000_000,
            max_account_free_balance: 50_000_000_000,
            max_total_free_balance: 100_000_000_000,
            max_total_liability: 300_000_000_000,
            max_participants: 8,
            max_orders_per_participant: 8,
            max_live_order_records: 16,
            participant_entry_fee: 1_000_000,
            account_cleanup_bounty: 1_000_000,
            order_entry_fee: 1_000_000,
            order_cleanup_bounty: 1_000_000,
            operating_reserve_floor: 1_000_000_000,
            terminal_tombstone_reserve: 100_000_000,
            challenge_bond: 100_000_000,
            challenge_processing_fee: 10_000_000,
            normal_oracle_policy: PredictionOraclePolicyV1 {
                threshold: 1,
                reporters: vec![
                    "-1:2222222222222222222222222222222222222222222222222222222222222222"
                        .parse()
                        .unwrap(),
                ],
            },
            appellate_oracle_policy: PredictionOraclePolicyV1 {
                threshold: 1,
                reporters: vec![
                    "-1:3333333333333333333333333333333333333333333333333333333333333333"
                        .parse()
                        .unwrap(),
                ],
            },
        }
    }

    #[test]
    fn computes_exact_value_breakdown_for_funding_operations() {
        let init = test_init();
        let register = build_operation(
            &init,
            OperationJson::RegisterAndDeposit {
                query_id: 1,
                credited_amount: 5_000_000_000,
                trading_pubkey: "8b237d788e8eaaef550c6d125823fa45f1fd5fc29b2c88bdf871119471fc1312"
                    .into(),
            },
        )
        .unwrap();
        assert_eq!(register.credited_amount, 5_000_000_000);
        assert_eq!(register.state_contribution, 2_000_000);
        assert_eq!(register.minimum_value, 6_002_000_000);
        assert!(register.risk_increasing);

        let challenge = build_operation(
            &init,
            OperationJson::ChallengeResult {
                query_id: 2,
                expected_proposed_statement_hash: "44".repeat(32),
                counter_outcome: 1,
                counter_evidence_root: "55".repeat(32),
            },
        )
        .unwrap();
        assert_eq!(challenge.minimum_value, 1_110_000_000);
        assert!(!challenge.risk_increasing);

        let top_up = build_operation(&init, OperationJson::TopUpReserve { query_id: 3 }).unwrap();
        assert_eq!(top_up.minimum_value, OPERATION_BUDGET);
        assert_eq!(top_up.body, PredictionMarketContractV1::top_up_reserve(3).unwrap());
        assert_eq!(top_up.body.references_count(), 0);
        assert!(!top_up.risk_increasing);
    }

    fn test_phase(
        status: contracts::PredictionMarketStatusV1,
    ) -> contracts::PredictionMarketPhaseV1 {
        contracts::PredictionMarketPhaseV1 {
            status,
            review_reason: 0,
            final_outcome: contracts::PredictionResolutionOutcomeV1::Invalid,
            current_context_hash: [0x44; 32],
            review_base_context_hash: [0x55; 32],
            proposed_statement_hash: [0x66; 32],
            next_deadline: 200,
        }
    }

    #[test]
    fn resolution_context_bocs_are_hash_cross_checked_before_export() {
        let current = PredictionMarketContractV1::top_up_reserve(7).unwrap();
        let mut phase = test_phase(contracts::PredictionMarketStatusV1::Reporting);
        phase.current_context_hash = *current.repr_hash().as_array();
        phase.review_base_context_hash = [0; 32];
        let contexts =
            PredictionResolutionContextsV1 { current: Some(current.clone()), review_base: None };
        let (encoded, review) = verified_resolution_context_bocs(&phase, &contexts).unwrap();
        assert!(review.is_none());
        let decoded = read_single_root_boc(
            &base64::engine::general_purpose::STANDARD.decode(encoded.unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(decoded, current);

        phase.current_context_hash = [0x99; 32];
        assert!(verified_resolution_context_bocs(&phase, &contexts).is_err());
    }

    fn report_operation(round: u8, context: [u8; 32]) -> OperationJson {
        OperationJson::ReportResult {
            query_id: 1,
            round,
            expected_round_context_hash: hex::encode(context),
            outcome: 0,
            evidence_root: "77".repeat(32),
            statement_created_at: 140,
            statement_expiry: 190,
        }
    }

    #[test]
    fn autonomous_report_authorization_is_bound_to_open_round_and_reporter() {
        let init = test_init();
        let normal = &init.normal_oracle_policy.reporters[0];
        let appellate = &init.appellate_oracle_policy.reporters[0];
        let reporting = test_phase(contracts::PredictionMarketStatusV1::Reporting);
        let report = report_operation(0, [0x44; 32]);

        validate_autonomous_operation_phase(normal, &init, &report, &reporting, 150).unwrap();
        assert!(
            validate_autonomous_operation_phase(appellate, &init, &report, &reporting, 150)
                .is_err()
        );
        assert!(
            validate_autonomous_operation_phase(
                normal,
                &init,
                &report_operation(0, [0x45; 32]),
                &reporting,
                150
            )
            .is_err()
        );

        let mut unopened = reporting.clone();
        unopened.current_context_hash = [0; 32];
        assert!(
            validate_autonomous_operation_phase(normal, &init, &report, &unopened, 150).is_err()
        );

        let mut bad_time = report_operation(0, [0x44; 32]);
        if let OperationJson::ReportResult { statement_created_at, .. } = &mut bad_time {
            *statement_created_at = 151;
        }
        assert!(
            validate_autonomous_operation_phase(normal, &init, &bad_time, &reporting, 150).is_err()
        );
        let mut bad_expiry = report_operation(0, [0x44; 32]);
        if let OperationJson::ReportResult { statement_expiry, .. } = &mut bad_expiry {
            *statement_expiry = 201;
        }
        assert!(
            validate_autonomous_operation_phase(normal, &init, &bad_expiry, &reporting, 150)
                .is_err()
        );

        let reviewing = test_phase(contracts::PredictionMarketStatusV1::Reviewing);
        validate_autonomous_operation_phase(
            appellate,
            &init,
            &report_operation(1, [0x44; 32]),
            &reviewing,
            150,
        )
        .unwrap();
        assert!(
            validate_autonomous_operation_phase(
                normal,
                &init,
                &report_operation(1, [0x44; 32]),
                &reviewing,
                150,
            )
            .is_err()
        );
    }

    #[test]
    fn autonomous_resolution_authorization_enforces_time_and_hash_boundaries() {
        let init = test_init();
        let source = &init.normal_oracle_policy.reporters[0];
        let proposed = test_phase(contracts::PredictionMarketStatusV1::Proposed);
        let challenge = OperationJson::ChallengeResult {
            query_id: 2,
            expected_proposed_statement_hash: "66".repeat(32),
            counter_outcome: 1,
            counter_evidence_root: "77".repeat(32),
        };
        validate_autonomous_operation_phase(source, &init, &challenge, &proposed, 199).unwrap();
        assert!(
            validate_autonomous_operation_phase(source, &init, &challenge, &proposed, 200).is_err()
        );

        let finalize = OperationJson::FinalizeUncontested { query_id: 3 };
        assert!(
            validate_autonomous_operation_phase(source, &init, &finalize, &proposed, 199).is_err()
        );
        validate_autonomous_operation_phase(source, &init, &finalize, &proposed, 200).unwrap();

        let reviewing = test_phase(contracts::PredictionMarketStatusV1::Reviewing);
        let review_timeout = OperationJson::FinalizeReviewTimeout {
            query_id: 4,
            expected_review_base_context_hash: "55".repeat(32),
        };
        assert!(
            validate_autonomous_operation_phase(source, &init, &review_timeout, &reviewing, 199,)
                .is_err()
        );
        validate_autonomous_operation_phase(source, &init, &review_timeout, &reviewing, 200)
            .unwrap();
        let wrong_review = OperationJson::FinalizeReviewTimeout {
            query_id: 5,
            expected_review_base_context_hash: "56".repeat(32),
        };
        assert!(
            validate_autonomous_operation_phase(source, &init, &wrong_review, &reviewing, 200,)
                .is_err()
        );
    }

    #[test]
    fn exact_boc_persistence_is_idempotent_but_never_overwrites() {
        let dir = std::env::temp_dir().join(format!(
            "tos-prediction-cli-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("message.boc");
        persist_exact(&path, b"one").unwrap();
        persist_exact(&path, b"one").unwrap();
        assert!(persist_exact(&path, b"two").is_err());
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn hash_parser_rejects_uppercase_and_noncanonical_lengths() {
        assert!(parse_hash("hash", &"aa".repeat(32)).is_ok());
        assert!(parse_hash("hash", &"AA".repeat(32)).is_err());
        assert!(parse_hash("hash", &"aa".repeat(31)).is_err());
    }

    #[test]
    fn global_version_gate_is_fail_closed_but_preserves_exit_operations() {
        assert!(validate_global_version(13, false).is_err());
        assert!(validate_global_version(14, true).is_ok());
        assert!(validate_global_version(15, true).is_ok());
        assert!(validate_global_version(16, true).is_err());
        assert!(validate_global_version(16, false).is_ok());
    }

    #[test]
    fn custody_action_dispatch_is_closed_and_never_prefix_based() {
        assert_eq!(prediction_semantic_effect_kind("match_pair"), Some("prediction.match.submit"));
        assert_eq!(
            prediction_semantic_effect_kind("register_and_deposit"),
            Some("prediction.collateral.deposit")
        );
        assert_eq!(
            prediction_semantic_effect_kind("finalize_review_timeout"),
            Some("prediction.resolution.finalize")
        );
        assert_eq!(prediction_semantic_effect_kind("prune_order"), None);
        assert_eq!(prediction_semantic_effect_kind("prediction.future.action"), None);
    }

    #[test]
    fn pre_broadcast_boundary_is_canonical_and_rejects_malformed_observations() {
        let (cursor, checkpoint) = prediction_pre_broadcast_boundary(
            "0:source",
            7,
            &[0x11; 32],
            i64::MIN,
            9,
            &[0x22; 32],
            &[0x33; 32],
        )
        .unwrap();
        assert_eq!(cursor["account_address"], "0:source");
        assert_eq!(cursor["last_logical_time"], 7);
        assert_eq!(cursor["last_transaction_hash"], format!("sha256:{}", "11".repeat(32)));
        assert_eq!(checkpoint["workchain_id"], -1);
        assert_eq!(checkpoint["shard"], i64::MIN);
        assert_eq!(checkpoint["masterchain_sequence_number"], 9);
        assert_eq!(checkpoint["root_hash"], format!("sha256:{}", "22".repeat(32)));

        let (zero_cursor, _) = prediction_pre_broadcast_boundary(
            "0:source",
            0,
            &[],
            i64::MIN,
            9,
            &[0x22; 32],
            &[0x33; 32],
        )
        .unwrap();
        assert_eq!(zero_cursor["last_transaction_hash"], "");
        assert!(
            prediction_pre_broadcast_boundary(
                "0:source",
                0,
                &[0x11; 32],
                i64::MIN,
                9,
                &[0x22; 32],
                &[0x33; 32],
            )
            .is_err()
        );
        assert!(
            prediction_pre_broadcast_boundary(
                "0:source",
                7,
                &[0x11; 31],
                i64::MIN,
                9,
                &[0x22; 32],
                &[0x33; 32],
            )
            .is_err()
        );
    }

    #[test]
    fn order_builder_binds_every_immutable_market_domain() {
        let init = test_init();
        let mut order = PredictionOrderV1 {
            global_id: init.global_id,
            workchain_id: init.workchain_id,
            market_address: PredictionMarketContractV1::calculate_address(&init).unwrap(),
            market_config_hash: PredictionMarketContractV1::market_config_hash(&init).unwrap(),
            owner_address: "-1:4444444444444444444444444444444444444444444444444444444444444444"
                .parse()
                .unwrap(),
            key_epoch: 0,
            nonce: 1,
            salt: [0x55; 32],
            action: PredictionOrderActionV1::Buy,
            outcome: PredictionOrderOutcomeV1::Yes,
            liquidity_role: PredictionLiquidityRoleV1::Maker,
            quantity_lots: 10,
            min_fill_lots: 1,
            allow_partial: true,
            limit_price_tick: 5_000,
            valid_after: init.trade_close - 100,
            valid_until: init.trade_close,
            optional_counterparty: None,
        };
        validate_order_for_market(&init, &order).unwrap();
        order.market_config_hash[0] ^= 1;
        assert!(validate_order_for_market(&init, &order).is_err());
        order.market_config_hash = PredictionMarketContractV1::market_config_hash(&init).unwrap();
        order.valid_until = init.trade_close + 1;
        assert!(validate_order_for_market(&init, &order).is_err());
    }
}
