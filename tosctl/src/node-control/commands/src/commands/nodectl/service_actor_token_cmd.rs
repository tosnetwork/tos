/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! `tosctl agent service-token`: the token-rail Service Actor
//! (`service-actor-token-code.fc`, release `tos-service-actor-token-v1`).
//!
//! Every command reads the actor at one masterchain block, the last one the
//! endpoint reports, and binds every further read to that block's id. It
//! refuses, before anything is signed, each message the actor would refuse
//! for a reason visible in that state, and builds every body through
//! `contracts::service_actor_token`.
//!
//! `--build-only` prints the internal message a wallet sends (destination,
//! value, bounce flag and body BOC) as the versioned JSON document
//! `tosctl.service-actor-token.prepared-message.v1`, described in
//! `tosctl/src/node-control/docs/service-actor-token-cli.md`, and signs
//! nothing. The document is a
//! function of the arguments and of the state read: the same arguments at the
//! same block give the same bytes. `wallet send --to <destination>
//! --amount-nanotos <value_nanotos> --body-boc <body_boc> --bounce` sends it.
//! Without `--build-only` the command signs the same message with `--from`
//! and broadcasts it.

use super::agent_cmd::{confirm, parse_required_hash};
use super::native_registry_cmd::read_controller_seed;
use super::output_format::OutputFormat;
use super::service_actor_cmd::send_announced_wallet_message;
use super::utils::{
    get_wallet_config, load_config_vault_rpc_client, make_wallet, try_create_rpc_client,
    wallet_info,
};
use anyhow::Context;
use base64::Engine;
use chain_block::{
    BuilderData, Cell, Deserializable, MsgAddressInt, SETTLEMENT_ASSETS_CONFIG_PARAM,
    SettlementAssetStatus, TokenBridgeParams, UInt256, read_pinned_settlement_assets,
    read_single_root_boc, write_boc,
};
use chain_rpc_client::v2::{
    client_json_rpc::ClientJsonRpc,
    data_models::{AccountState, BlockIdExt, RunGetMethodParams},
    stack::RPCStackEntry,
};
use common::tvm_stack_parser::TvmStackParser;
use contracts::service_actor_token::{
    FundingQuote, NativeLedger, PayoutData, ReturnedData, SERVICE_ACTOR_TOKEN_RAIL,
    ServiceActorTokenCodeProfile, ServiceActorTokenContract as Actor, ServiceActorTokenData,
    TokenLedger, TokenPendingRequest, err, kind, protocol_constants, token_wallet_state_init,
};
use std::{collections::BTreeMap, path::Path, sync::Arc};

/// The `--build-only` document's version.
pub(crate) const PREPARED_MESSAGE_VERSION: &str = "tosctl.service-actor-token.prepared-message.v1";
/// Value of an op that creates no payout, when none is given.
const DEFAULT_NON_PAYOUT_VALUE: u64 = 10_000_000; // 0.01 TOS
/// A funded value defaults to this multiple of its minimum at the state read,
/// so a price rise before execution does not leave it short. The actor returns
/// what it does not use to the sender.
const FUNDING_HEADROOM: u128 = 2;
/// Allowance per forwarding the bridge wallet's transfer check counts.
const FORWARD_FEE_ALLOWANCE: u128 = 50_000_000; // 0.05 TOS
/// What the signing wallet pays for its own message, beyond the value.
const WALLET_ACTION_GAS: u64 = 1_000_000; // 0.001 TOS

/// `tosctl agent service-token` -- token-rail Service Actor operations.
#[derive(clap::Args, Clone)]
#[command(about = "Token-rail Service Actor operations")]
pub struct ServiceActorTokenCmd {
    #[command(subcommand)]
    action: TokenAction,
}

#[derive(clap::Subcommand, Clone)]
enum TokenAction {
    /// Show the actor's policy, ledgers and funding prices at one block
    Show(TokenShowCmd),
    /// Show a pending request (`get_request`)
    RequestShow(TokenRequestShowCmd),
    /// Show a payout in flight (`get_payout`)
    PayoutShow(TokenPayoutShowCmd),
    /// Show a returned entry (`get_returned`)
    ReturnedShow(TokenReturnedShowCmd),
    /// Fund a call: a token transfer to the actor carrying `token_call`
    Call(Box<TokenCallCmd>),
    /// Send an owner or permissionless actor operation
    Send(Box<TokenSendCmd>),
    /// Top up the actor's TOS balance, or its token wallet's
    TopUp(TokenTopUpCmd),
}

impl ServiceActorTokenCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            TokenAction::Show(cmd) => cmd.run(config_path).await,
            TokenAction::RequestShow(cmd) => cmd.run(config_path).await,
            TokenAction::PayoutShow(cmd) => cmd.run(config_path).await,
            TokenAction::ReturnedShow(cmd) => cmd.run(config_path).await,
            TokenAction::Call(cmd) => cmd.run(config_path).await,
            TokenAction::Send(cmd) => cmd.run(config_path).await,
            TokenAction::TopUp(cmd) => cmd.run(config_path).await,
        }
    }
}

/// Which token-actor build the address must run.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenCodeProfileArg {
    /// The released token-rail actor.
    Release,
    /// TEST NETWORKS ONLY: minimum windows of 600 seconds.
    Test,
}

impl From<TokenCodeProfileArg> for ServiceActorTokenCodeProfile {
    fn from(value: TokenCodeProfileArg) -> Self {
        match value {
            TokenCodeProfileArg::Release => Self::Release,
            TokenCodeProfileArg::Test => Self::TestProfile,
        }
    }
}

const CODE_PROFILE_HELP: &str = "The build the actor must run: `release` (the default) or \
    `test` (TEST NETWORKS ONLY, 600-second minimum windows). An actor running other code is \
    refused";

#[derive(clap::Args, Clone)]
struct ActorArgs {
    #[arg(
        allow_hyphen_values = true,
        value_parser = super::utils::address_arg,
        long,
        help = "Token-rail Service Actor address"
    )]
    address: String,
    #[arg(long, value_enum, default_value_t = TokenCodeProfileArg::Release, help = CODE_PROFILE_HELP)]
    code_profile: TokenCodeProfileArg,
}

impl ActorArgs {
    fn actor(&self) -> anyhow::Result<MsgAddressInt> {
        self.address.parse::<MsgAddressInt>().context("invalid Service Actor address")
    }
}

#[derive(clap::Args, Clone)]
struct SignerArgs {
    #[arg(
        long,
        conflicts_with = "sender",
        required_unless_present = "sender",
        help = "Signing wallet name or master_wallet"
    )]
    from: Option<String>,
    #[arg(
        allow_hyphen_values = true,
        value_parser = super::utils::address_arg,
        long,
        requires = "build_only",
        help = "The wallet that will send the message, for --build-only without a local wallet"
    )]
    sender: Option<String>,
    #[arg(
        long,
        help = "Print the prepared message as versioned JSON and sign nothing \
                (docs/service-actor-token-cli.md)"
    )]
    build_only: bool,
    #[arg(long, help = "Confirm non-interactively")]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show the actor's policy, ledgers and funding prices at one block")]
pub(crate) struct TokenShowCmd {
    #[command(flatten)]
    actor: ActorArgs,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show a pending request")]
pub(crate) struct TokenRequestShowCmd {
    #[command(flatten)]
    actor: ActorArgs,
    #[arg(long, help = "Request ID")]
    request_id: u64,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show a payout in flight")]
pub(crate) struct TokenPayoutShowCmd {
    #[command(flatten)]
    actor: ActorArgs,
    #[arg(long, help = "Payout ID")]
    id: u64,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(about = "Show a returned entry")]
pub(crate) struct TokenReturnedShowCmd {
    #[command(flatten)]
    actor: ActorArgs,
    #[arg(long, help = "Returned entry ID (the payout ID whose refusal created it)")]
    id: u64,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Fund a call with a token transfer",
    long_about = "Fund a call: an ordinary token transfer of exactly the actor's price from the \
        sender's token wallet to the actor, whose forward payload is the `token_call` naming the \
        request and the terms it accepts. Refused before signing: an inactive actor, a sender \
        the actor does not admit or not canonical on workchain 0, terms that changed, an asset \
        ConfigParam 84 does not list as active with the route's wallet code, a call past the \
        exposure caps, a token balance below the price, an actor not accepting tokens, and a \
        forward below the call's budget (storage fee plus `min_funding_value`). A transfer \
        below that budget would make its tokens the provider's surplus."
)]
pub(crate) struct TokenCallCmd {
    #[command(flatten)]
    actor: ActorArgs,
    #[command(flatten)]
    signer: SignerArgs,
    #[arg(long, default_value_t = 0, help = "query_id of the token transfer")]
    query_id: u64,
    #[arg(long, help = "Request hash the call commits to (32 bytes, hex)")]
    request_hash: String,
    #[arg(
        long,
        help = "Terms hash of the accepted quote (32 bytes, hex); refused when the actor's \
                current terms differ"
    )]
    expected_terms_hash: String,
    #[arg(
        long,
        help = "forward_tos_amount in nanoTOS; defaults to twice the call's budget at the state \
                read (the actor returns the change); a value below the budget is refused"
    )]
    forward_tos_nanotos: Option<u128>,
    #[arg(
        long,
        help = "Value of the message to the sender's token wallet in nanoTOS; defaults to the \
                forward plus the bridge wallet's transfer cost read from its bridge ConfigParam"
    )]
    wallet_value_nanotos: Option<u64>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenOperation {
    Respond,
    Expire,
    ClaimRefund,
    SweepExpiredRequest,
    UpdatePolicy,
    RotateAttestorKey,
    RevokeAttestor,
    WithdrawRevenue,
    ClaimReturned,
    SweepReturned,
    RecoverSurplus,
    AbandonPayout,
    RecheckPayout,
}

impl TokenOperation {
    fn name(self) -> &'static str {
        match self {
            Self::Respond => "respond",
            Self::Expire => "expire",
            Self::ClaimRefund => "claim-refund",
            Self::SweepExpiredRequest => "sweep-expired-request",
            Self::UpdatePolicy => "update-policy",
            Self::RotateAttestorKey => "rotate-attestor-key",
            Self::RevokeAttestor => "revoke-attestor",
            Self::WithdrawRevenue => "withdraw-revenue",
            Self::ClaimReturned => "claim-returned",
            Self::SweepReturned => "sweep-returned",
            Self::RecoverSurplus => "recover-surplus",
            Self::AbandonPayout => "abandon-payout",
            Self::RecheckPayout => "recheck-payout",
        }
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Send an owner or permissionless token-rail Service Actor operation")]
pub(crate) struct TokenSendCmd {
    #[arg(long, value_enum)]
    operation: TokenOperation,
    #[command(flatten)]
    actor: ActorArgs,
    #[command(flatten)]
    signer: SignerArgs,
    #[arg(long, default_value_t = 0)]
    query_id: u64,
    #[arg(long, help = "Request ID for respond, expire, claim-refund and sweep-expired-request")]
    request_id: Option<u64>,
    #[arg(
        long,
        help = "Payout or returned-entry ID for claim-returned, sweep-returned, abandon-payout \
                and recheck-payout"
    )]
    id: Option<u64>,
    #[arg(long, help = "Response hash for respond (32 bytes, hex)")]
    response_hash: Option<String>,
    #[arg(
        long,
        conflicts_with = "attestor_controller",
        help = "2,420-byte ML-DSA-44 signature (hex) for respond to a request with an attestor"
    )]
    attestation_signature: Option<String>,
    #[arg(
        long,
        conflicts_with = "attestation_signature",
        help = "ML-DSA-44 controller in the vault: signs respond's response domain, or names \
                the new key for rotate-attestor-key"
    )]
    attestor_controller: Option<String>,
    #[arg(
        long,
        conflicts_with = "attestor_controller",
        help = "New ML-DSA-44 attestor public key (1,312 bytes, hex) for rotate-attestor-key"
    )]
    new_attestor_pubkey: Option<String>,
    #[arg(
        allow_hyphen_values = true,
        value_parser = super::utils::address_arg,
        long,
        help = "Destination for claim-refund and claim-returned: canonical, workchain 0, not \
                the actor"
    )]
    destination: Option<String>,
    #[arg(
        long,
        help = "Token amount in atomic units: withdraw-revenue's token part, recover-surplus's \
                amount"
    )]
    token_amount: Option<u128>,
    #[arg(long, help = "withdraw-revenue's TOS part, in nanoTOS")]
    tos_amount_nanotos: Option<u64>,
    #[arg(long, help = "update-policy: price per call in atomic token units")]
    price_per_call_units: Option<u128>,
    #[arg(long, help = "update-policy: storage fee in nanoTOS")]
    storage_fee_nanotos: Option<u64>,
    #[arg(long, help = "update-policy: cleanup bounty in nanoTOS")]
    cleanup_bounty_nanotos: Option<u64>,
    #[arg(long, help = "update-policy: response SLA in seconds")]
    response_sla: Option<u32>,
    #[arg(long, help = "update-policy: refund claim window in seconds")]
    refund_claim_window: Option<u32>,
    #[arg(long, help = "update-policy: the active flag")]
    active: Option<bool>,
    #[arg(long, help = "update-policy: max calls per day; 0 means unlimited")]
    rate_limit_per_day: Option<u32>,
    #[arg(long, conflicts_with = "authorized_caller", help = "update-policy: open access")]
    open_access: bool,
    #[arg(
        allow_hyphen_values = true,
        value_parser = super::utils::address_arg,
        long,
        conflicts_with = "open_access",
        help = "update-policy: the single authorized caller"
    )]
    authorized_caller: Option<String>,
    #[arg(
        long,
        help = "update-policy: the owner's token liability cap in atomic units \
                (1329227995784915872903807060280344575 for none)"
    )]
    max_token_liability: Option<u128>,
    #[arg(long, help = "update-policy: metadata hash (32 bytes, hex)")]
    metadata_hash: Option<String>,
    #[arg(long, help = "update-policy: proof scheme hash (32 bytes, hex)")]
    proof_scheme_hash: Option<String>,
    #[arg(
        long,
        help = "Message value in nanoTOS; defaults to twice the op's minimum at the state read \
                (the actor returns the change), or 0.01 TOS for an op without a payout"
    )]
    amount_nanotos: Option<u64>,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TopUpTarget {
    /// The actor's own TOS balance (backing, locks and operating reserve)
    Actor,
    /// The actor's token wallet, which holds every customer's principal
    Wallet,
}

#[derive(clap::Args, Clone)]
#[command(about = "Top up the actor or its token wallet with a plain TOS transfer")]
pub(crate) struct TokenTopUpCmd {
    #[arg(long, value_enum)]
    target: TopUpTarget,
    #[command(flatten)]
    actor: ActorArgs,
    #[command(flatten)]
    signer: SignerArgs,
    #[arg(long, help = "Amount in nanoTOS")]
    amount_nanotos: u64,
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

// ---- The state read ------------------------------------------------------------

/// The masterchain block every read of one command is bound to.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ReadAt {
    pub seqno: u32,
    /// The block's root hash, hex.
    pub root_hash: String,
}

/// The token actor at one block, as its getters report it.
#[derive(Clone, Debug)]
pub(crate) struct ActorView {
    pub read_at: ReadAt,
    pub actor: MsgAddressInt,
    pub profile: ServiceActorTokenCodeProfile,
    /// The actor's TOS balance, nanoTOS.
    pub balance: u64,
    pub data: ServiceActorTokenData,
    pub terms_hash: [u8; 32],
    pub token: TokenLedger,
    pub native: NativeLedger,
    pub quote: FundingQuote,
    pub accepting_tokens: bool,
    pub attestor_key_count: u32,
    pub master: MsgAddressInt,
    pub wallet_code: Cell,
    pub own_wallet: MsgAddressInt,
}

/// The ConfigParam 84 record of the actor's master, at the same block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecognizedAsset {
    pub status: u8,
    pub decimals: u8,
    pub wallet_code_hash: [u8; 32],
    pub max_liability_per_actor: u128,
    pub bridge_config_param: Option<u32>,
}

/// What a call reads beyond the actor, at the same block.
#[derive(Clone, Debug, Default)]
pub(crate) struct CallReads {
    /// `None` when ConfigParam 84 is absent or does not list the master.
    pub asset: Option<RecognizedAsset>,
    /// The bridge wallet's `wallet_gas_consumption` and
    /// `wallet_min_tos_for_storage`; `None` when the bridge parameter is absent.
    pub wallet_prices: Option<(u128, u128)>,
    /// The sender's token balance; `None` when its wallet is not deployed.
    pub sender_token_balance: Option<u128>,
}

/// What an operation reads beyond the actor, at the same block.
#[derive(Clone, Debug, Default)]
pub(crate) struct OpReads {
    pub request: Option<TokenPendingRequest>,
    pub payout: Option<PayoutData>,
    pub returned: Option<ReturnedData>,
    /// The actor's token wallet balance.
    pub own_wallet_balance: Option<u128>,
}

/// Reads bound to the last masterchain block the endpoint reports.
struct Reader {
    rpc: Arc<ClientJsonRpc>,
    block: BlockIdExt,
}

impl Reader {
    async fn at_last(rpc: Arc<ClientJsonRpc>) -> anyhow::Result<Self> {
        let block = rpc.get_masterchain_info().await?.last;
        anyhow::ensure!(
            block.workchain == -1,
            "the endpoint's last block is not a masterchain block"
        );
        Ok(Self { rpc, block })
    }

    fn read_at(&self) -> ReadAt {
        ReadAt { seqno: self.block.seqno, root_hash: hex::encode(&self.block.root_hash) }
    }

    fn same_block(&self, what: &str, read: &BlockIdExt) -> anyhow::Result<()> {
        anyhow::ensure!(
            read.workchain == -1
                && read.seqno == self.block.seqno
                && read.root_hash == self.block.root_hash,
            "{what} was read at masterchain block {} instead of block {}",
            read.seqno,
            self.block.seqno
        );
        Ok(())
    }

    async fn get(
        &self,
        address: &MsgAddressInt,
        method: &str,
        args: Vec<RPCStackEntry>,
    ) -> anyhow::Result<TvmStackParser> {
        let result = self
            .rpc
            .run_get_method(&RunGetMethodParams {
                address: address.to_string(),
                method_id: method.to_owned(),
                stack: Some(args),
                seqno: Some(self.block.seqno),
            })
            .await
            .with_context(|| format!("{method} on {address}"))?;
        anyhow::ensure!(
            result.exit_code == 0,
            "{method} on {address}: exit code {}",
            result.exit_code
        );
        let block = result
            .block_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("{method}: the endpoint did not report its block"))?;
        self.same_block(method, block)?;
        // The endpoint serializes the stack top first; decoders index in
        // get-method return order.
        Ok(TvmStackParser::new(result.stack.into_iter().rev().map(Into::into).collect()))
    }

    async fn account(
        &self,
        address: &MsgAddressInt,
    ) -> anyhow::Result<chain_rpc_client::v2::data_models::GetAddressInformationRes> {
        let info = self.rpc.get_address_information_at(address, self.block.seqno).await?;
        self.same_block("the account", &info.block_id)?;
        Ok(info)
    }

    async fn config_cell(&self, id: u32) -> anyhow::Result<Option<Cell>> {
        match self.rpc.get_optional_config_param_cell_at(id, self.block.seqno).await? {
            Some((cell, block)) => {
                self.same_block(&format!("ConfigParam {id}"), &block)?;
                Ok(Some(cell))
            }
            None => Ok(None),
        }
    }

    async fn actor(
        &self,
        actor: &MsgAddressInt,
        profile: ServiceActorTokenCodeProfile,
    ) -> anyhow::Result<ActorView> {
        let account = self.account(actor).await?;
        anyhow::ensure!(
            account.state == AccountState::Active,
            "{actor} is not an active account at block {}",
            self.block.seqno
        );
        let code = read_single_root_boc(
            account.code.clone().ok_or_else(|| anyhow::anyhow!("{actor} has no code"))?,
        )?;
        anyhow::ensure!(
            code.repr_hash() == Actor::code_for(profile)?.repr_hash(),
            "{actor} does not run the {} token-rail Service Actor build",
            profile_name(profile)
        );
        let data = Actor::decode_service_data(&self.get(actor, "get_service_data", vec![]).await?)?;
        let terms = self.get(actor, "get_terms_hash", vec![]).await?;
        let terms_hash = hash_at(&terms, 0)?;
        let token =
            Actor::decode_token_ledger(&self.get(actor, "get_token_ledger", vec![]).await?)?;
        let native =
            Actor::decode_native_ledger(&self.get(actor, "get_native_ledger", vec![]).await?)?;
        let quote =
            Actor::decode_funding_quote(&self.get(actor, "get_funding_prices", vec![]).await?)?;
        let accepting_tokens = Actor::decode_accepting_tokens(
            &self.get(actor, "get_accepting_tokens", vec![]).await?,
        )?;
        let keys = self.get(actor, "get_attestor_key_count", vec![]).await?;
        let attestor_key_count = u32::try_from(keys.u64(0)?)
            .map_err(|_| anyhow::anyhow!("get_attestor_key_count exceeds 32 bits"))?;
        let route = self.get(actor, "get_asset_route", vec![]).await?;
        let mut master_slice = route.slice(0)?;
        let master = MsgAddressInt::construct_from(&mut master_slice)?;
        let wallet_code = route.cell(2)?;
        anyhow::ensure!(
            wallet_code.repr_hash().inner() == hash_at(&route, 1)?,
            "get_asset_route: the wallet code does not hash to the route's wallet code hash"
        );
        let own = self.get(actor, "get_own_wallet", vec![]).await?;
        let mut own_slice = own.slice(0)?;
        let own_wallet = MsgAddressInt::construct_from(&mut own_slice)?;
        anyhow::ensure!(
            own_wallet == wallet_of(actor, &master, &wallet_code)?,
            "get_own_wallet is not the wallet the route derives"
        );
        Ok(ActorView {
            read_at: self.read_at(),
            actor: actor.clone(),
            profile,
            balance: account.balance,
            data,
            terms_hash,
            token,
            native,
            quote,
            accepting_tokens,
            attestor_key_count,
            master,
            wallet_code,
            own_wallet,
        })
    }

    /// A bridge token wallet's balance (`get_wallet_data`), or `None` when the
    /// wallet is not deployed.
    async fn token_balance(&self, wallet: &MsgAddressInt) -> anyhow::Result<Option<u128>> {
        let account = self.account(wallet).await?;
        if account.state != AccountState::Active {
            return Ok(None);
        }
        let stack = self.get(wallet, "get_wallet_data", vec![]).await?;
        Ok(Some(u128_at(&stack, 0)?))
    }

    async fn call_reads(
        &self,
        view: &ActorView,
        sender: &MsgAddressInt,
    ) -> anyhow::Result<CallReads> {
        let asset = match self.config_cell(SETTLEMENT_ASSETS_CONFIG_PARAM).await? {
            None => None,
            Some(value) => {
                let pin = UInt256::from(master_account_id(&view.master)?);
                let pinned = read_pinned_settlement_assets(value, &[pin])?;
                match pinned.into_iter().next().and_then(|entry| entry.asset) {
                    None => None,
                    Some(asset) => Some(RecognizedAsset {
                        status: asset.status.code(),
                        decimals: asset.decimals,
                        wallet_code_hash: *asset.wallet_code_hash.as_slice(),
                        max_liability_per_actor: asset.max_liability_per_actor.as_u128(),
                        bridge_config_param: contracts::settlement_assets::bridge_config_param(
                            asset.origin.source_chain_id,
                        ),
                    }),
                }
            }
        };
        let wallet_prices = match asset.as_ref().and_then(|a| a.bridge_config_param) {
            None => None,
            Some(param) => match self.config_cell(param).await? {
                None => None,
                Some(cell) => {
                    let params = TokenBridgeParams::construct_from_cell(cell)
                        .with_context(|| format!("ConfigParam {param}"))?;
                    Some((
                        params.prices.wallet_gas_consumption.as_u128(),
                        params.prices.wallet_min_tos_for_storage.as_u128(),
                    ))
                }
            },
        };
        let sender_wallet = wallet_of(sender, &view.master, &view.wallet_code)?;
        let sender_token_balance = self.token_balance(&sender_wallet).await?;
        Ok(CallReads { asset, wallet_prices, sender_token_balance })
    }

    async fn op_reads(&self, view: &ActorView, op: &OpArgs) -> anyhow::Result<OpReads> {
        let actor = &view.actor;
        let id_entry = |id: u64| vec![id_stack(id)];
        let mut reads = OpReads::default();
        match op {
            OpArgs::Respond { request_id, .. } | OpArgs::Expire { request_id } => {
                reads.request = Actor::decode_request(
                    &self.get(actor, "get_request", id_entry(*request_id)).await?,
                )?;
            }
            OpArgs::ClaimReturned { id, .. } | OpArgs::SweepReturned { id } => {
                reads.returned =
                    Actor::decode_returned(&self.get(actor, "get_returned", id_entry(*id)).await?)?;
            }
            OpArgs::AbandonPayout { id } | OpArgs::RecheckPayout { id } => {
                reads.payout =
                    Actor::decode_payout(&self.get(actor, "get_payout", id_entry(*id)).await?)?;
            }
            OpArgs::RecoverSurplus { .. } => {
                reads.own_wallet_balance = self.token_balance(&view.own_wallet).await?;
            }
            OpArgs::ClaimRefund { .. }
            | OpArgs::SweepExpiredRequest { .. }
            | OpArgs::UpdatePolicy(_)
            | OpArgs::RotateAttestorKey { .. }
            | OpArgs::RevokeAttestor
            | OpArgs::WithdrawRevenue { .. } => {}
        }
        Ok(reads)
    }
}

/// The bridge token wallet of `owner` for `master` and `wallet_code`.
fn wallet_of(
    owner: &MsgAddressInt,
    master: &MsgAddressInt,
    wallet_code: &Cell,
) -> anyhow::Result<MsgAddressInt> {
    use chain_block::Serializable;
    let init = token_wallet_state_init(owner, master, wallet_code)?;
    MsgAddressInt::with_params(0, init.serialize()?.repr_hash())
}

fn master_account_id(master: &MsgAddressInt) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(
        Actor::is_canonical_basechain(master),
        "the asset master is not on workchain 0"
    );
    master
        .address()
        .get_bytestring(0)
        .try_into()
        .map_err(|_| anyhow::anyhow!("the asset master is not a 256-bit account id"))
}

fn hash_at(stack: &TvmStackParser, index: usize) -> anyhow::Result<[u8; 32]> {
    stack
        .number_bytes(index, 32)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stack entry {index} is not a 256-bit value"))
}

fn u128_at(stack: &TvmStackParser, index: usize) -> anyhow::Result<u128> {
    stack
        .decimal_string(index)?
        .parse::<u128>()
        .map_err(|e| anyhow::anyhow!("stack entry {index} is not an unsigned amount: {e}"))
}

fn profile_name(profile: ServiceActorTokenCodeProfile) -> &'static str {
    match profile {
        ServiceActorTokenCodeProfile::Release => "release",
        ServiceActorTokenCodeProfile::TestProfile => "test",
    }
}

// ---- The prepared message ----------------------------------------------------------

/// The `--build-only` document: one internal message, its context and the
/// operation's own fields. Every amount is a decimal string; `details` is
/// sorted by key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct PreparedView {
    pub version: &'static str,
    pub operation: &'static str,
    pub rail: &'static str,
    pub code_profile: &'static str,
    pub actor: String,
    pub read_at: ReadAt,
    pub sender: String,
    pub destination: String,
    pub value_nanotos: String,
    pub bounce: bool,
    pub body_boc: String,
    pub body_hash: String,
    pub details: BTreeMap<&'static str, String>,
}

/// A planned message: the document and the parts a wallet signs.
#[derive(Clone, Debug)]
pub(crate) struct Prepared {
    pub view: PreparedView,
    pub destination: MsgAddressInt,
    pub value: u64,
    pub body: Cell,
}

impl Prepared {
    fn new(
        actor: &ActorView,
        operation: &'static str,
        sender: &MsgAddressInt,
        destination: MsgAddressInt,
        value: u64,
        body: Cell,
        details: BTreeMap<&'static str, String>,
    ) -> anyhow::Result<Self> {
        let view = PreparedView {
            version: PREPARED_MESSAGE_VERSION,
            operation,
            rail: SERVICE_ACTOR_TOKEN_RAIL,
            code_profile: profile_name(actor.profile),
            actor: actor.actor.to_string(),
            read_at: actor.read_at.clone(),
            sender: sender.to_string(),
            destination: destination.to_string(),
            value_nanotos: value.to_string(),
            bounce: true,
            body_boc: base64::engine::general_purpose::STANDARD.encode(write_boc(&body)?),
            body_hash: hex::encode(body.repr_hash().as_slice()),
            details,
        };
        Ok(Self { view, destination, value, body })
    }
}

/// The document exactly as `--build-only` prints it, without the final newline.
pub(crate) fn render(view: &PreparedView) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(view)?)
}

fn to_u64(what: &str, value: u128) -> anyhow::Result<u64> {
    u64::try_from(value).map_err(|_| anyhow::anyhow!("{what} ({value} nanoTOS) exceeds 64 bits"))
}

/// The value a funded message carries: the explicit one, which must reach the
/// minimum, or `FUNDING_HEADROOM` times the minimum.
fn funded_value(what: &str, minimum: u128, explicit: Option<u64>) -> anyhow::Result<u64> {
    match explicit {
        Some(value) => {
            anyhow::ensure!(
                u128::from(value) >= minimum,
                "{what} carries {value} nanoTOS, below its minimum of {minimum} at the state read \
                 (the actor refuses it with {})",
                err::INSUFFICIENT_EXECUTION_PAYMENT
            );
            Ok(value)
        }
        None => to_u64(
            what,
            minimum
                .checked_mul(FUNDING_HEADROOM)
                .ok_or_else(|| anyhow::anyhow!("{what}: the default value overflows"))?,
        ),
    }
}

// ---- Call ------------------------------------------------------------------------

/// The arguments of a funded call.
#[derive(Clone, Debug)]
pub(crate) struct CallArgs {
    pub sender: MsgAddressInt,
    pub query_id: u64,
    pub request_hash: [u8; 32],
    pub expected_terms_hash: [u8; 32],
    pub forward_tos_amount: Option<u128>,
    pub wallet_value: Option<u64>,
}

/// Plans a funded call against one state read, refusing each transfer the
/// actor would answer with a funding return or that would leave the tokens
/// as surplus. The transfer body comes from the SDK's `funding_transfer`,
/// which itself refuses a forward below the budget and an actor not
/// accepting tokens.
pub(crate) fn plan_call(
    view: &ActorView,
    reads: &CallReads,
    args: &CallArgs,
) -> anyhow::Result<Prepared> {
    let data = &view.data;
    let sender = &args.sender;
    anyhow::ensure!(
        Actor::is_canonical_basechain(sender),
        "the sender {sender} is not canonical on workchain 0 (refused with {})",
        err::INVALID_DESTINATION
    );
    anyhow::ensure!(data.active, "the actor is inactive (refused with {})", err::INACTIVE);
    anyhow::ensure!(
        data.open_access || data.authorized_caller.as_ref() == Some(sender),
        "the actor admits only its authorized caller (refused with {})",
        err::NOT_AUTHORIZED
    );
    anyhow::ensure!(
        args.expected_terms_hash == view.terms_hash,
        "the actor's terms changed: the quote commits to {}, the actor now offers {} (refused \
         with {})",
        hex::encode(args.expected_terms_hash),
        hex::encode(view.terms_hash),
        err::TERMS_MISMATCH
    );
    let asset = reads.asset.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "ConfigParam 84 does not list the actor's master {} (refused with {})",
            view.master,
            err::ASSET_NOT_RECOGNIZED
        )
    })?;
    anyhow::ensure!(
        asset.status == SettlementAssetStatus::Active.code(),
        "ConfigParam 84 lists the master with status {}, not 1 (refused with {})",
        asset.status,
        err::ASSET_NOT_RECOGNIZED
    );
    anyhow::ensure!(
        asset.wallet_code_hash == view.wallet_code.repr_hash().inner(),
        "ConfigParam 84 names another wallet code than the actor's route (refused with {})",
        err::ASSET_NOT_RECOGNIZED
    );
    let price = data.price_per_call;
    let cap = data.max_token_liability.min(asset.max_liability_per_actor);
    let exposure = view
        .token
        .liability()
        .and_then(|liability| liability.checked_add(price))
        .ok_or_else(|| anyhow::anyhow!("the actor's token liability overflows"))?;
    anyhow::ensure!(
        exposure <= cap,
        "the call would raise the actor's token liability to {exposure}, above its cap {cap} \
         (refused with {})",
        err::EXPOSURE_CAP
    );
    let balance = reads.sender_token_balance.ok_or_else(|| {
        anyhow::anyhow!("the sender has no token wallet for this asset at the state read")
    })?;
    anyhow::ensure!(
        balance >= price,
        "the sender's token balance {balance} is below the price {price}"
    );

    let prices = view.quote.prices(data.storage_fee, view.accepting_tokens);
    let minimum_forward = prices.minimum_forward()?;
    let forward = match args.forward_tos_amount {
        Some(forward) => forward,
        None => minimum_forward
            .checked_mul(FUNDING_HEADROOM)
            .ok_or_else(|| anyhow::anyhow!("the default forward overflows"))?,
    };
    let body = Actor::funding_transfer(
        args.query_id,
        price,
        &view.actor,
        sender,
        forward,
        &prices,
        args.request_hash,
        args.expected_terms_hash,
    )?;

    let (wallet_value, transfer_cost) = match args.wallet_value {
        Some(value) => {
            anyhow::ensure!(
                u128::from(value) > forward,
                "the wallet value {value} does not exceed the forward {forward}"
            );
            (value, None)
        }
        None => {
            let (gas, reserve) = reads.wallet_prices.ok_or_else(|| {
                anyhow::anyhow!(
                    "the asset's bridge ConfigParam is absent at the state read; pass \
                     --wallet-value-nanotos"
                )
            })?;
            let cost = gas
                .checked_mul(2)
                .and_then(|g| g.checked_add(reserve))
                .and_then(|c| c.checked_add(FORWARD_FEE_ALLOWANCE.checked_mul(2)?))
                .ok_or_else(|| anyhow::anyhow!("the transfer cost overflows"))?;
            let value = forward
                .checked_add(cost)
                .ok_or_else(|| anyhow::anyhow!("the wallet value overflows"))?;
            (to_u64("the wallet value", value)?, Some(cost))
        }
    };

    let mut details = BTreeMap::new();
    details.insert("token_amount", price.to_string());
    details.insert("forward_tos_amount", forward.to_string());
    details.insert("minimum_forward", minimum_forward.to_string());
    details.insert("storage_fee", data.storage_fee.to_string());
    details.insert("min_funding_value", view.quote.min_funding_value.to_string());
    details.insert("accepting_tokens", view.accepting_tokens.to_string());
    details.insert("query_id", args.query_id.to_string());
    details.insert("request_hash", hex::encode(args.request_hash));
    details.insert("expected_terms_hash", hex::encode(args.expected_terms_hash));
    details.insert("asset_master", view.master.to_string());
    details.insert("asset_decimals", asset.decimals.to_string());
    details.insert("token_wallet", wallet_of(sender, &view.master, &view.wallet_code)?.to_string());
    if let Some(cost) = transfer_cost {
        details.insert("wallet_transfer_cost", cost.to_string());
    }
    let destination = wallet_of(sender, &view.master, &view.wallet_code)?;
    Prepared::new(view, "call", sender, destination, wallet_value, body, details)
}

// ---- Operations ---------------------------------------------------------------------

/// The new policy of `update-policy`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyArgs {
    pub price_per_call: u128,
    pub storage_fee: u64,
    pub cleanup_bounty: u64,
    pub response_sla: u32,
    pub refund_claim_window: u32,
    pub active: bool,
    pub open_access: bool,
    pub authorized_caller: Option<MsgAddressInt>,
    pub rate_limit_per_day: u32,
    pub max_token_liability: u128,
    pub metadata_hash: [u8; 32],
    pub proof_scheme_hash: [u8; 32],
}

/// One operation and its arguments.
#[derive(Clone, Debug)]
pub(crate) enum OpArgs {
    Respond { request_id: u64, response_hash: [u8; 32], signature: Option<Vec<u8>> },
    Expire { request_id: u64 },
    ClaimRefund { request_id: u64, destination: MsgAddressInt },
    SweepExpiredRequest { request_id: u64 },
    UpdatePolicy(Box<PolicyArgs>),
    RotateAttestorKey { public_key: Vec<u8> },
    RevokeAttestor,
    WithdrawRevenue { token_amount: u128, tos_amount: u64 },
    ClaimReturned { id: u64, destination: MsgAddressInt },
    SweepReturned { id: u64 },
    RecoverSurplus { amount: u128 },
    AbandonPayout { id: u64 },
    RecheckPayout { id: u64 },
}

impl OpArgs {
    fn operation(&self) -> TokenOperation {
        match self {
            Self::Respond { .. } => TokenOperation::Respond,
            Self::Expire { .. } => TokenOperation::Expire,
            Self::ClaimRefund { .. } => TokenOperation::ClaimRefund,
            Self::SweepExpiredRequest { .. } => TokenOperation::SweepExpiredRequest,
            Self::UpdatePolicy(_) => TokenOperation::UpdatePolicy,
            Self::RotateAttestorKey { .. } => TokenOperation::RotateAttestorKey,
            Self::RevokeAttestor => TokenOperation::RevokeAttestor,
            Self::WithdrawRevenue { .. } => TokenOperation::WithdrawRevenue,
            Self::ClaimReturned { .. } => TokenOperation::ClaimReturned,
            Self::SweepReturned { .. } => TokenOperation::SweepReturned,
            Self::RecoverSurplus { .. } => TokenOperation::RecoverSurplus,
            Self::AbandonPayout { .. } => TokenOperation::AbandonPayout,
            Self::RecheckPayout { .. } => TokenOperation::RecheckPayout,
        }
    }

    fn owner_only(&self) -> bool {
        matches!(
            self,
            Self::Respond { .. }
                | Self::UpdatePolicy(_)
                | Self::RotateAttestorKey { .. }
                | Self::RevokeAttestor
                | Self::WithdrawRevenue { .. }
                | Self::RecoverSurplus { .. }
                | Self::AbandonPayout { .. }
        )
    }
}

fn owner_basechain(view: &ActorView) -> anyhow::Result<()> {
    anyhow::ensure!(
        Actor::is_canonical_basechain(&view.data.owner),
        "the owner is not canonical on workchain 0, so no token payout can reach it (refused \
         with {})",
        err::INVALID_DESTINATION
    );
    Ok(())
}

fn claimant_basechain(sender: &MsgAddressInt) -> anyhow::Result<()> {
    anyhow::ensure!(
        Actor::is_canonical_basechain(sender),
        "the sender {sender} is not canonical on workchain 0 (refused with {})",
        err::INVALID_DESTINATION
    );
    Ok(())
}

fn require_payout(reads: &OpReads, id: u64) -> anyhow::Result<&PayoutData> {
    reads.payout.as_ref().ok_or_else(|| {
        anyhow::anyhow!("payout {id} is not in flight (refused with {})", err::PAYOUT_NOT_FOUND)
    })
}

fn require_returned(reads: &OpReads, id: u64) -> anyhow::Result<&ReturnedData> {
    let entry = reads.returned.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "returned entry {id} does not exist (refused with {})",
            err::RETURNED_NOT_FOUND
        )
    })?;
    anyhow::ensure!(
        entry.paying == 0,
        "returned entry {id} already has payout {} in flight (refused with {})",
        entry.paying,
        err::PAYOUT_IN_FLIGHT
    );
    Ok(entry)
}

fn require_pending(reads: &OpReads, request_id: u64) -> anyhow::Result<&TokenPendingRequest> {
    reads.request.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "request {request_id} is not pending (refused with {})",
            err::REQUEST_NOT_PENDING
        )
    })
}

/// The new policy, checked as `update_policy` checks it.
fn check_policy(view: &ActorView, policy: &PolicyArgs) -> anyhow::Result<()> {
    use protocol_constants::*;
    let min_window = view.profile.min_window_secs();
    anyhow::ensure!(
        (min_window..=MAX_RESPONSE_SLA_SECS).contains(&policy.response_sla),
        "the response SLA must be within {min_window}..={MAX_RESPONSE_SLA_SECS} seconds \
         (refused with {})",
        err::INVALID_RESPONSE_SLA
    );
    anyhow::ensure!(
        (min_window..=MAX_REFUND_CLAIM_WINDOW_SECS).contains(&policy.refund_claim_window),
        "the refund claim window must be within {min_window}..={MAX_REFUND_CLAIM_WINDOW_SECS} \
         seconds (refused with {})",
        err::INVALID_REFUND_CLAIM_WINDOW
    );
    anyhow::ensure!(
        (MINIMUM_CLEANUP_BOUNTY..=MAXIMUM_CLEANUP_BOUNTY).contains(&policy.cleanup_bounty),
        "the cleanup bounty must be within {MINIMUM_CLEANUP_BOUNTY}..={MAXIMUM_CLEANUP_BOUNTY} \
         nanoTOS (refused with {})",
        err::INVALID_CLEANUP_BOUNTY
    );
    let least_fee = MINIMUM_STORAGE_FEE
        .checked_add(policy.cleanup_bounty)
        .ok_or_else(|| anyhow::anyhow!("the storage fee floor overflows"))?;
    anyhow::ensure!(
        policy.storage_fee >= least_fee,
        "the storage fee must be at least {least_fee} nanoTOS (refused with {})",
        err::INSUFFICIENT_STORAGE_FEE
    );
    anyhow::ensure!(
        policy.price_per_call > 0,
        "the price must be positive (refused with {})",
        err::INSUFFICIENT_PAYMENT
    );
    anyhow::ensure!(
        policy.max_token_liability > 0 && policy.max_token_liability <= NO_TOKEN_CAP,
        "the liability cap must be within 1..={NO_TOKEN_CAP} (refused with {})",
        err::EXPOSURE_CAP
    );
    anyhow::ensure!(policy.price_per_call <= NO_TOKEN_CAP, "the price does not fit a Coins field");
    anyhow::ensure!(
        policy.open_access || policy.authorized_caller.is_some(),
        "update-policy needs --open-access or --authorized-caller"
    );
    Ok(())
}

/// Plans one operation against one state read. Each refusal names the exit
/// code the actor would answer with.
pub(crate) fn plan_op(
    view: &ActorView,
    reads: &OpReads,
    sender: &MsgAddressInt,
    query_id: u64,
    op: &OpArgs,
    explicit_value: Option<u64>,
) -> anyhow::Result<Prepared> {
    let operation = op.operation();
    if op.owner_only() {
        anyhow::ensure!(
            sender == &view.data.owner,
            "{} is owner-only and the sender is not the owner {} (refused with {})",
            operation.name(),
            view.data.owner,
            err::NOT_OWNER
        );
    }
    if let Some(value) = explicit_value {
        anyhow::ensure!(value > 0, "the message value must be positive");
    }
    let payout_funding = view.quote.payout_funding;
    let unfunded =
        || -> anyhow::Result<u64> { Ok(explicit_value.unwrap_or(DEFAULT_NON_PAYOUT_VALUE)) };
    let mut details = BTreeMap::new();
    details.insert("query_id", query_id.to_string());
    let (body, value) = match op {
        OpArgs::Respond { request_id, response_hash, signature } => {
            let request = require_pending(reads, *request_id)?;
            details.insert("request_id", request_id.to_string());
            details.insert("response_hash", hex::encode(response_hash));
            let body = match (request.attestor_key_id.is_some(), signature) {
                (true, Some(signature)) => {
                    Actor::respond_signed(query_id, *request_id, *response_hash, signature)?
                }
                (false, None) => Actor::respond(query_id, *request_id, *response_hash)?,
                (true, None) => anyhow::bail!(
                    "request {request_id} snapshotted an attestor key: respond needs its \
                     signature (refused with {})",
                    err::BAD_RESPONSE_SIGNATURE
                ),
                (false, Some(_)) => anyhow::bail!(
                    "request {request_id} has no attestor: respond carries no signature"
                ),
            };
            (body, unfunded()?)
        }
        OpArgs::Expire { request_id } => {
            require_pending(reads, *request_id)?;
            details.insert("request_id", request_id.to_string());
            (Actor::expire(query_id, *request_id)?, unfunded()?)
        }
        OpArgs::ClaimRefund { request_id, destination } => {
            claimant_basechain(sender)?;
            Actor::check_destination(destination, &view.actor)?;
            details.insert("request_id", request_id.to_string());
            details.insert("destination", destination.to_string());
            details.insert("payout_funding", payout_funding.to_string());
            (
                Actor::claim_refund(query_id, *request_id, destination)?,
                funded_value("claim-refund", payout_funding, explicit_value)?,
            )
        }
        OpArgs::SweepExpiredRequest { request_id } => {
            details.insert("request_id", request_id.to_string());
            details.insert("payout_funding", payout_funding.to_string());
            (
                Actor::sweep_expired_request(query_id, *request_id)?,
                funded_value("sweep-expired-request", payout_funding, explicit_value)?,
            )
        }
        OpArgs::UpdatePolicy(policy) => {
            check_policy(view, policy)?;
            details.insert("price_per_call", policy.price_per_call.to_string());
            details.insert("max_token_liability", policy.max_token_liability.to_string());
            details.insert("active", policy.active.to_string());
            (
                Actor::update_policy(
                    query_id,
                    policy.price_per_call,
                    policy.storage_fee,
                    policy.cleanup_bounty,
                    policy.response_sla,
                    policy.refund_claim_window,
                    policy.active,
                    policy.open_access,
                    policy.authorized_caller.as_ref(),
                    // Read only when the caller is cleared: the owner is a
                    // valid address of the right form.
                    &view.data.owner,
                    policy.rate_limit_per_day,
                    policy.max_token_liability,
                    policy.metadata_hash,
                    policy.proof_scheme_hash,
                )?,
                unfunded()?,
            )
        }
        OpArgs::RotateAttestorKey { public_key } => {
            anyhow::ensure!(
                view.attestor_key_count < protocol_constants::MAX_LIVE_ATTESTOR_KEYS,
                "pending requests already name {} attestor keys, the most (refused with {})",
                view.attestor_key_count,
                err::ATTESTOR_KEYS_FULL
            );
            let key_id = contracts::native_registry::controller_key_id(public_key)?;
            details.insert("attestor_key_id", format!("mldsa44:{}", hex::encode(key_id)));
            (Actor::rotate_attestor_key(query_id, public_key)?, unfunded()?)
        }
        OpArgs::RevokeAttestor => (Actor::revoke_attestor(query_id)?, unfunded()?),
        OpArgs::WithdrawRevenue { token_amount, tos_amount } => {
            anyhow::ensure!(
                *token_amount > 0 || *tos_amount > 0,
                "withdraw-revenue needs a positive token or TOS amount"
            );
            anyhow::ensure!(
                *token_amount <= view.token.withdrawable_revenue,
                "token revenue {} is below the {token_amount} asked (refused with {})",
                view.token.withdrawable_revenue,
                err::INSUFFICIENT_REVENUE
            );
            let free = view
                .balance
                .checked_sub(view.native.locked_storage_fees)
                .and_then(|r| r.checked_sub(view.native.locked_outcome_fees))
                .and_then(|r| r.checked_sub(protocol_constants::MINIMUM_OPERATING_RESERVE))
                .unwrap_or(0);
            let tos_available = free.min(view.native.withdrawable_revenue);
            anyhow::ensure!(
                *tos_amount <= tos_available,
                "{tos_available} nanoTOS of TOS revenue is withdrawable without touching the \
                 locks and the operating reserve, below the {tos_amount} asked (refused with {})",
                err::INSUFFICIENT_REVENUE
            );
            let minimum = if *token_amount > 0 {
                anyhow::ensure!(
                    view.native.revenue_payouts_in_flight < protocol_constants::MAX_REVENUE_PAYOUTS,
                    "{} revenue payouts are in flight, the most (refused with {})",
                    view.native.revenue_payouts_in_flight,
                    err::PAYOUT_IN_FLIGHT
                );
                owner_basechain(view)?;
                payout_funding
            } else {
                u128::from(protocol_constants::PAYOUT_GAS_ALLOWANCE)
            };
            details.insert("token_amount", token_amount.to_string());
            details.insert("tos_amount", tos_amount.to_string());
            details.insert("minimum_value", minimum.to_string());
            (
                Actor::withdraw_revenue(query_id, *token_amount, *tos_amount)?,
                funded_value("withdraw-revenue", minimum, explicit_value)?,
            )
        }
        OpArgs::ClaimReturned { id, destination } => {
            claimant_basechain(sender)?;
            let entry = require_returned(reads, *id)?;
            anyhow::ensure!(
                &entry.caller == sender,
                "returned entry {id} belongs to {}, not the sender (refused with {})",
                entry.caller,
                err::NOT_REFUND_CALLER
            );
            Actor::check_destination(destination, &view.actor)?;
            details.insert("id", id.to_string());
            details.insert("destination", destination.to_string());
            details.insert("token_amount", entry.amount.to_string());
            details.insert("payout_funding", payout_funding.to_string());
            (
                Actor::claim_returned(query_id, *id, destination)?,
                funded_value("claim-returned", payout_funding, explicit_value)?,
            )
        }
        OpArgs::SweepReturned { id } => {
            let entry = require_returned(reads, *id)?;
            details.insert("id", id.to_string());
            details.insert("recipient", entry.caller.to_string());
            details.insert("token_amount", entry.amount.to_string());
            details.insert("return_deadline", entry.return_deadline.to_string());
            details.insert("payout_funding", payout_funding.to_string());
            (
                Actor::sweep_returned(query_id, *id)?,
                funded_value("sweep-returned", payout_funding, explicit_value)?,
            )
        }
        OpArgs::RecoverSurplus { amount } => {
            anyhow::ensure!(
                view.native.surplus_payouts_in_flight < protocol_constants::MAX_SURPLUS_PAYOUTS,
                "{} surplus payouts are in flight, the most (refused with {})",
                view.native.surplus_payouts_in_flight,
                err::PAYOUT_IN_FLIGHT
            );
            owner_basechain(view)?;
            let attributed = view
                .token
                .attributed()
                .ok_or_else(|| anyhow::anyhow!("the actor's token ledger overflows"))?;
            let held = reads.own_wallet_balance.ok_or_else(|| {
                anyhow::anyhow!("the actor's token wallet is not deployed at the state read")
            })?;
            let surplus = held.saturating_sub(attributed);
            anyhow::ensure!(
                *amount <= surplus,
                "the actor's wallet holds {surplus} unattributed at the state read, below the \
                 {amount} asked (the answer would be {})",
                err::SURPLUS_INSUFFICIENT
            );
            let minimum = u128::from(protocol_constants::PAYOUT_GAS_ALLOWANCE)
                .checked_add(payout_funding)
                .ok_or_else(|| anyhow::anyhow!("the recovery funding overflows"))?;
            details.insert("token_amount", amount.to_string());
            details.insert("surplus_at_read", surplus.to_string());
            details.insert("minimum_value", minimum.to_string());
            (
                Actor::recover_surplus(query_id, *amount)?,
                funded_value("recover-surplus", minimum, explicit_value)?,
            )
        }
        OpArgs::AbandonPayout { id } => {
            let payout = require_payout(reads, *id)?;
            anyhow::ensure!(
                payout.kind == kind::REVENUE || payout.kind == kind::SURPLUS,
                "payout {id} is of kind {}; only revenue (3) and surplus (6) payouts are \
                 abandoned (refused with {})",
                payout.kind,
                err::RECHECK_NOT_ALLOWED
            );
            details.insert("id", id.to_string());
            details.insert("kind", payout.kind.to_string());
            details.insert("created_at", payout.created_at.to_string());
            (Actor::abandon_payout(query_id, *id)?, unfunded()?)
        }
        OpArgs::RecheckPayout { id } => {
            let payout = require_payout(reads, *id)?;
            anyhow::ensure!(
                payout.kind != kind::REVENUE && payout.kind != kind::SURPLUS,
                "payout {id} is of kind {}; revenue and surplus payouts are abandoned, not \
                 rechecked (refused with {})",
                payout.kind,
                err::RECHECK_NOT_ALLOWED
            );
            let minimum = u128::from(protocol_constants::PAYOUT_GAS_ALLOWANCE);
            details.insert("id", id.to_string());
            details.insert("kind", payout.kind.to_string());
            details.insert("created_at", payout.created_at.to_string());
            details.insert("minimum_value", minimum.to_string());
            (
                Actor::recheck_payout(query_id, *id)?,
                funded_value("recheck-payout", minimum, explicit_value)?,
            )
        }
    };
    Prepared::new(view, operation.name(), sender, view.actor.clone(), value, body, details)
}

// ---- Top-ups --------------------------------------------------------------------------

/// A plain TOS transfer, bounceable, to the actor or to its token wallet. A
/// wallet that is not deployed yet would bounce it; it is refused instead.
pub(crate) fn plan_top_up(
    view: &ActorView,
    sender: &MsgAddressInt,
    target: TopUpTarget,
    amount: u64,
    own_wallet_deployed: bool,
) -> anyhow::Result<Prepared> {
    anyhow::ensure!(amount > 0, "a top-up moves a positive amount");
    let (operation, destination) = match target {
        TopUpTarget::Actor => ("top-up-actor", view.actor.clone()),
        TopUpTarget::Wallet => {
            anyhow::ensure!(
                own_wallet_deployed,
                "the actor's token wallet {} is not deployed yet: its first funding deploys it",
                view.own_wallet
            );
            ("top-up-wallet", view.own_wallet.clone())
        }
    };
    let mut details = BTreeMap::new();
    details.insert("actor_balance", view.balance.to_string());
    Prepared::new(
        view,
        operation,
        sender,
        destination,
        amount,
        BuilderData::new().into_cell()?,
        details,
    )
}

// ---- Running -----------------------------------------------------------------------------

/// The sender: the given address for `--build-only`, else the `--from` wallet.
struct Signer {
    address: MsgAddressInt,
    wallet: Option<(String, Arc<secrets_vault::vault::SecretVault>)>,
}

async fn open(
    config_path: &str,
    signer: &SignerArgs,
) -> anyhow::Result<(Arc<ClientJsonRpc>, Signer, Option<common::app_config::AppConfig>)> {
    let path = Path::new(config_path);
    match (&signer.from, &signer.sender) {
        (None, Some(sender)) => {
            let config = common::app_config::AppConfig::load(path)?;
            let rpc = try_create_rpc_client(&config).await?;
            let address = sender.parse::<MsgAddressInt>().context("invalid --sender")?;
            Ok((rpc, Signer { address, wallet: None }, None))
        }
        (Some(from), None) => {
            let (config, vault, rpc) = load_config_vault_rpc_client(path).await?;
            let wallet_config =
                get_wallet_config(from, &config.wallets, config.master_wallet.as_ref())?;
            let (address, _, _) = wallet_info(rpc.clone(), wallet_config, vault.clone()).await?;
            Ok((rpc, Signer { address, wallet: Some((from.clone(), vault)) }, Some(config)))
        }
        _ => anyhow::bail!("provide exactly one of --from or --sender"),
    }
}

/// Prints the document for `--build-only`, else signs and broadcasts the
/// message after showing it.
async fn emit(
    prepared: Prepared,
    signer: &SignerArgs,
    rpc: Arc<ClientJsonRpc>,
    opened: Signer,
    config: Option<common::app_config::AppConfig>,
    format: &OutputFormat,
) -> anyhow::Result<()> {
    if signer.build_only {
        println!("{}", render(&prepared.view)?);
        return Ok(());
    }
    print_prepared(&prepared.view, format)?;
    let (from, vault) = opened.wallet.ok_or_else(|| anyhow::anyhow!("sending needs --from"))?;
    let config = config.ok_or_else(|| anyhow::anyhow!("sending needs a loaded configuration"))?;
    let wallet_config = get_wallet_config(&from, &config.wallets, config.master_wallet.as_ref())?;
    let (address, info, secret) = wallet_info(rpc.clone(), wallet_config, vault).await?;
    anyhow::ensure!(address == opened.address, "the signing wallet changed while planning");
    anyhow::ensure!(info.account_state == AccountState::Active, "the signing wallet is not active");
    let needed = prepared
        .value
        .checked_add(WALLET_ACTION_GAS)
        .ok_or_else(|| anyhow::anyhow!("the message value overflows"))?;
    anyhow::ensure!(info.balance >= needed, "the signing wallet holds less than {needed} nanoTOS");
    if !signer.yes && !confirm("Send this token-rail Service Actor message?")? {
        return Ok(());
    }
    let wallet = make_wallet(rpc.clone(), wallet_config, secret, &from).await?;
    send_announced_wallet_message(
        &wallet,
        rpc,
        prepared.destination.clone(),
        prepared.value,
        prepared.body,
        info.seqno,
        &address,
    )
    .await?;
    println!("OK {} submitted to {}", prepared.view.operation, prepared.destination);
    Ok(())
}

fn print_prepared(view: &PreparedView, format: &OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => println!("{}", render(view)?),
        OutputFormat::Table => {
            println!("Operation: {}", view.operation);
            println!("Actor: {}  (read at block {})", view.actor, view.read_at.seqno);
            println!("Sender: {}", view.sender);
            println!("Destination: {}", view.destination);
            println!("Value: {} nanoTOS", view.value_nanotos);
            for (key, value) in &view.details {
                println!("  {key}: {value}");
            }
            println!("Body hash: {}", view.body_hash);
        }
    }
    Ok(())
}

impl TokenCallCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let actor = self.actor.actor()?;
        let request_hash = parse_required_hash("request-hash", &Some(self.request_hash.clone()))?;
        let expected_terms_hash =
            parse_required_hash("expected-terms-hash", &Some(self.expected_terms_hash.clone()))?;
        let (rpc, opened, config) = open(config_path, &self.signer).await?;
        let reader = Reader::at_last(rpc.clone()).await?;
        let view = reader.actor(&actor, self.actor.code_profile.into()).await?;
        let reads = reader.call_reads(&view, &opened.address).await?;
        let prepared = plan_call(
            &view,
            &reads,
            &CallArgs {
                sender: opened.address.clone(),
                query_id: self.query_id,
                request_hash,
                expected_terms_hash,
                forward_tos_amount: self.forward_tos_nanotos,
                wallet_value: self.wallet_value_nanotos,
            },
        )?;
        emit(prepared, &self.signer, rpc, opened, config, &self.format).await
    }
}

fn parse_hex_bytes(name: &str, value: &str) -> anyhow::Result<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("{name} must be hex"))
}

impl TokenSendCmd {
    fn request_id(&self) -> anyhow::Result<u64> {
        self.request_id.ok_or_else(|| anyhow::anyhow!("--request-id is required"))
    }

    fn id(&self) -> anyhow::Result<u64> {
        self.id.ok_or_else(|| anyhow::anyhow!("--id is required"))
    }

    fn destination(&self) -> anyhow::Result<MsgAddressInt> {
        self.destination
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--destination is required"))?
            .parse::<MsgAddressInt>()
            .context("invalid --destination")
    }

    fn required<T: Copy>(name: &str, value: Option<T>) -> anyhow::Result<T> {
        value.ok_or_else(|| anyhow::anyhow!("--{name} is required for update-policy"))
    }

    /// The operation's arguments that need no chain read. respond's signature
    /// from a vault controller is added after the request is read.
    async fn args(
        &self,
        vault: Option<&secrets_vault::vault::SecretVault>,
    ) -> anyhow::Result<OpArgs> {
        Ok(match self.operation {
            TokenOperation::Respond => {
                let signature = match &self.attestation_signature {
                    Some(text) => {
                        let bytes = parse_hex_bytes("attestation-signature", text)?;
                        anyhow::ensure!(
                            bytes.len()
                                == contracts::native_registry::NATIVE_REGISTRY_SIGNATURE_BYTES,
                            "attestation-signature must be {} bytes, not {}",
                            contracts::native_registry::NATIVE_REGISTRY_SIGNATURE_BYTES,
                            bytes.len()
                        );
                        Some(bytes)
                    }
                    None => None,
                };
                OpArgs::Respond {
                    request_id: self.request_id()?,
                    response_hash: parse_required_hash("response-hash", &self.response_hash)?,
                    signature,
                }
            }
            TokenOperation::Expire => OpArgs::Expire { request_id: self.request_id()? },
            TokenOperation::ClaimRefund => OpArgs::ClaimRefund {
                request_id: self.request_id()?,
                destination: self.destination()?,
            },
            TokenOperation::SweepExpiredRequest => {
                OpArgs::SweepExpiredRequest { request_id: self.request_id()? }
            }
            TokenOperation::UpdatePolicy => OpArgs::UpdatePolicy(Box::new(PolicyArgs {
                price_per_call: Self::required("price-per-call-units", self.price_per_call_units)?,
                storage_fee: Self::required("storage-fee-nanotos", self.storage_fee_nanotos)?,
                cleanup_bounty: Self::required(
                    "cleanup-bounty-nanotos",
                    self.cleanup_bounty_nanotos,
                )?,
                response_sla: Self::required("response-sla", self.response_sla)?,
                refund_claim_window: Self::required(
                    "refund-claim-window",
                    self.refund_claim_window,
                )?,
                active: Self::required("active", self.active)?,
                open_access: self.open_access,
                authorized_caller: self
                    .authorized_caller
                    .as_deref()
                    .map(str::parse::<MsgAddressInt>)
                    .transpose()
                    .context("invalid --authorized-caller")?,
                rate_limit_per_day: Self::required("rate-limit-per-day", self.rate_limit_per_day)?,
                max_token_liability: Self::required(
                    "max-token-liability",
                    self.max_token_liability,
                )?,
                metadata_hash: parse_required_hash("metadata-hash", &self.metadata_hash)?,
                proof_scheme_hash: parse_required_hash(
                    "proof-scheme-hash",
                    &self.proof_scheme_hash,
                )?,
            })),
            TokenOperation::RotateAttestorKey => {
                let public_key = match (&self.new_attestor_pubkey, &self.attestor_controller) {
                    (Some(text), None) => parse_hex_bytes("new-attestor-pubkey", text)?,
                    (None, Some(name)) => {
                        let vault = vault.ok_or_else(|| {
                            anyhow::anyhow!("--attestor-controller needs --from and its vault")
                        })?;
                        let seed = read_controller_seed(vault, name).await?;
                        contracts::native_registry::native_public_key_from_seed(&seed)
                    }
                    _ => anyhow::bail!(
                        "rotate-attestor-key needs one of --new-attestor-pubkey or \
                         --attestor-controller"
                    ),
                };
                contracts::native_registry::controller_key_id(&public_key)?;
                OpArgs::RotateAttestorKey { public_key }
            }
            TokenOperation::RevokeAttestor => OpArgs::RevokeAttestor,
            TokenOperation::WithdrawRevenue => OpArgs::WithdrawRevenue {
                token_amount: self.token_amount.unwrap_or(0),
                tos_amount: self.tos_amount_nanotos.unwrap_or(0),
            },
            TokenOperation::ClaimReturned => {
                OpArgs::ClaimReturned { id: self.id()?, destination: self.destination()? }
            }
            TokenOperation::SweepReturned => OpArgs::SweepReturned { id: self.id()? },
            TokenOperation::RecoverSurplus => OpArgs::RecoverSurplus {
                amount: self
                    .token_amount
                    .ok_or_else(|| anyhow::anyhow!("--token-amount is required"))?,
            },
            TokenOperation::AbandonPayout => OpArgs::AbandonPayout { id: self.id()? },
            TokenOperation::RecheckPayout => OpArgs::RecheckPayout { id: self.id()? },
        })
    }

    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let actor = self.actor.actor()?;
        if let Some(value) = self.amount_nanotos {
            anyhow::ensure!(value > 0, "--amount-nanotos must be positive");
        }
        let (rpc, opened, config) = open(config_path, &self.signer).await?;
        let vault = opened.wallet.as_ref().map(|(_, vault)| vault.clone());
        let mut op = self.args(vault.as_deref()).await?;
        let reader = Reader::at_last(rpc.clone()).await?;
        let view = reader.actor(&actor, self.actor.code_profile.into()).await?;
        let reads = reader.op_reads(&view, &op).await?;
        if let (OpArgs::Respond { request_id, response_hash, signature }, Some(name)) =
            (&mut op, &self.attestor_controller)
        {
            let request = require_pending(&reads, *request_id)?;
            let key_id = request.attestor_key_id.ok_or_else(|| {
                anyhow::anyhow!("request {request_id} has no attestor; drop --attestor-controller")
            })?;
            let vault = vault.as_deref().ok_or_else(|| {
                anyhow::anyhow!("--attestor-controller needs --from and its vault")
            })?;
            let domain = Actor::respond_domain_hash(
                super::utils::network_global_id(&rpc).await?,
                &actor,
                *request_id,
                request,
                *response_hash,
            )?;
            let seed = read_controller_seed(vault, name).await?;
            let (public_key, signed) =
                contracts::service_actor::sign_service_response(&seed, &domain)?;
            anyhow::ensure!(
                contracts::native_registry::controller_key_id(&public_key)? == key_id,
                "controller {name} is not the attestor request {request_id} snapshotted"
            );
            contracts::service_actor::verify_service_response(&public_key, &signed, &domain)?;
            *signature = Some(signed);
        }
        let prepared =
            plan_op(&view, &reads, &opened.address, self.query_id, &op, self.amount_nanotos)?;
        emit(prepared, &self.signer, rpc, opened, config, &self.format).await
    }
}

impl TokenTopUpCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let actor = self.actor.actor()?;
        anyhow::ensure!(self.amount_nanotos > 0, "--amount-nanotos must be positive");
        let (rpc, opened, config) = open(config_path, &self.signer).await?;
        let reader = Reader::at_last(rpc.clone()).await?;
        let view = reader.actor(&actor, self.actor.code_profile.into()).await?;
        let deployed = match self.target {
            TopUpTarget::Actor => true,
            TopUpTarget::Wallet => {
                reader.account(&view.own_wallet).await?.state == AccountState::Active
            }
        };
        let prepared =
            plan_top_up(&view, &opened.address, self.target, self.amount_nanotos, deployed)?;
        emit(prepared, &self.signer, rpc, opened, config, &self.format).await
    }
}

// ---- Reads -------------------------------------------------------------------------------

async fn reader(config_path: &str) -> anyhow::Result<Reader> {
    let config = common::app_config::AppConfig::load(Path::new(config_path))?;
    Reader::at_last(try_create_rpc_client(&config).await?).await
}

fn print_json_or_lines(value: &serde_json::Value, format: &OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value)?),
        OutputFormat::Table => {
            if let Some(map) = value.as_object() {
                for (key, value) in map {
                    println!(
                        "{key}: {}",
                        value.as_str().map(str::to_owned).unwrap_or(value.to_string())
                    );
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn show_json(view: &ActorView) -> serde_json::Value {
    let data = &view.data;
    let mut value = serde_json::json!({
        "actor": view.actor.to_string(),
        "code_profile": profile_name(view.profile),
        "read_at": view.read_at,
        "balance_nanotos": view.balance.to_string(),
        "owner": data.owner.to_string(),
        "active": data.active,
        "policy_version": data.policy_version,
        "terms_hash": hex::encode(view.terms_hash),
        "open_access": data.open_access,
        "authorized_caller": data.authorized_caller.as_ref().map(|a| a.to_string()),
        "price_per_call_units": data.price_per_call.to_string(),
        "storage_fee_nanotos": data.storage_fee.to_string(),
        "cleanup_bounty_nanotos": data.cleanup_bounty.to_string(),
        "response_sla": data.response_sla,
        "refund_claim_window": data.refund_claim_window,
        "rate_limit_per_day": data.rate_limit_per_day,
        "max_token_liability": data.max_token_liability.to_string(),
        "attestor_key_id": data.attestor_key_id.map(|k| format!("mldsa44:{}", hex::encode(k))),
        "attestor_key_count": view.attestor_key_count,
        "next_request_id": data.next_request_id,
        "pending_count": data.pending_count,
        "live_count": data.live_count,
        "next_payout_id": data.next_payout_id,
    });
    let ledgers = serde_json::json!({
        "asset_master": view.master.to_string(),
        "asset_wallet_code_hash": hex::encode(view.wallet_code.repr_hash().as_slice()),
        "own_wallet": view.own_wallet.to_string(),
        "token_pending": view.token.pending.to_string(),
        "token_refundable": view.token.refundable.to_string(),
        "token_returned": view.token.returned.to_string(),
        "token_in_flight": view.token.in_flight.to_string(),
        "token_withdrawable_revenue": view.token.withdrawable_revenue.to_string(),
        "tos_withdrawable_revenue": view.native.withdrawable_revenue.to_string(),
        "locked_storage_fees": view.native.locked_storage_fees.to_string(),
        "locked_outcome_fees": view.native.locked_outcome_fees.to_string(),
        "returned_count": view.native.returned_count,
        "returns_in_flight": view.native.returns_in_flight,
        "revenue_payouts_in_flight": view.native.revenue_payouts_in_flight,
        "surplus_payouts_in_flight": view.native.surplus_payouts_in_flight,
        "accepting_tokens": view.accepting_tokens,
        "min_funding_value": view.quote.min_funding_value.to_string(),
        "payout_funding": view.quote.payout_funding.to_string(),
        "outcome_fee_lock": view.quote.outcome_fee_lock.to_string(),
    });
    if let (Some(map), serde_json::Value::Object(more)) = (value.as_object_mut(), ledgers) {
        map.extend(more);
    }
    value
}

impl TokenShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let reader = reader(config_path).await?;
        let view = reader.actor(&self.actor.actor()?, self.actor.code_profile.into()).await?;
        print_json_or_lines(&show_json(&view), &self.format)
    }
}

impl TokenRequestShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let reader = reader(config_path).await?;
        let actor = self.actor.actor()?;
        let view = reader.actor(&actor, self.actor.code_profile.into()).await?;
        let stack = reader.get(&actor, "get_request", vec![id_stack(self.request_id)]).await?;
        let value = match Actor::decode_request(&stack)? {
            None => {
                serde_json::json!({"request_id": self.request_id, "found": false, "read_at": view.read_at})
            }
            Some(r) => serde_json::json!({
                "request_id": self.request_id,
                "found": true,
                "read_at": view.read_at,
                "caller": r.caller.to_string(),
                "price_units": r.price.to_string(),
                "storage_fee_nanotos": r.storage_fee.to_string(),
                "cleanup_bounty_nanotos": r.cleanup_bounty.to_string(),
                "response_deadline": r.response_deadline,
                "refund_claim_deadline": r.refund_claim_deadline,
                "policy_version": r.policy_version,
                "request_hash": hex::encode(r.request_hash),
                "terms_hash": hex::encode(r.terms_hash),
                "attestor_key_id": r.attestor_key_id.map(|k| format!("mldsa44:{}", hex::encode(k))),
            }),
        };
        print_json_or_lines(&value, &self.format)
    }
}

impl TokenPayoutShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let reader = reader(config_path).await?;
        let actor = self.actor.actor()?;
        let view = reader.actor(&actor, self.actor.code_profile.into()).await?;
        let stack = reader.get(&actor, "get_payout", vec![id_stack(self.id)]).await?;
        let value = match Actor::decode_payout(&stack)? {
            None => serde_json::json!({"id": self.id, "found": false, "read_at": view.read_at}),
            Some(p) => serde_json::json!({
                "id": self.id,
                "found": true,
                "read_at": view.read_at,
                "kind": p.kind,
                "request_id": p.request_id,
                "recipient": p.recipient.to_string(),
                "requester": p.requester.to_string(),
                "token_amount": p.amount.to_string(),
                "created_at": p.created_at,
                "recipient_wallet": p.recipient_wallet.to_string(),
                "own_wallet": p.own_wallet.to_string(),
                "outcome_fee_lock": p.outcome_fee_lock.to_string(),
            }),
        };
        print_json_or_lines(&value, &self.format)
    }
}

impl TokenReturnedShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let reader = reader(config_path).await?;
        let actor = self.actor.actor()?;
        let view = reader.actor(&actor, self.actor.code_profile.into()).await?;
        let stack = reader.get(&actor, "get_returned", vec![id_stack(self.id)]).await?;
        let value = match Actor::decode_returned(&stack)? {
            None => serde_json::json!({"id": self.id, "found": false, "read_at": view.read_at}),
            Some(r) => serde_json::json!({
                "id": self.id,
                "found": true,
                "read_at": view.read_at,
                "caller": r.caller.to_string(),
                "token_amount": r.amount.to_string(),
                "paying": r.paying,
                "return_deadline": r.return_deadline,
            }),
        };
        print_json_or_lines(&value, &self.format)
    }
}

#[cfg(test)]
#[path = "service_actor_token_cmd_tests.rs"]
mod tests;

fn id_stack(id: u64) -> RPCStackEntry {
    RPCStackEntry::from(contracts::stack_utils::u64_to_stack_entry(id))
}
