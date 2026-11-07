/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

//! The Agent Account's ML-DSA-44 route: install the module (deploy, verify,
//! stage) and send one ML-DSA-44-authorized native transfer, journaled in the
//! controller custody journal and resolved from three RPC views.
//!
//! Any wallet may relay a signed submission (`--relayer`, by default the
//! Agent Wallet's owner wallet). The relayer carries no authority: every
//! authorizing field is inside the ML-DSA-44-signed request, the relay
//! resends exactly the journaled bytes, and the worst a relayer can do is
//! withhold them until they expire, which another relayer remedies. The
//! relaying wallet signs and pays for its own message and attaches the relay
//! value.
//!
//! The relay value pays the module's verification of the 2,420-byte signature
//! it receives, the forwarding of the AUTH envelope (the module does not
//! forward the signature) and the account's execution. Outcomes of a relayed
//! submission, as each command reports them:
//! - module compute failure (bad signature, too little funding): nothing is
//!   forwarded; the bounceable relay message returns what verification left
//!   to the relaying wallet (nothing when the funding ran out during it);
//! - module action failure (verified, forward failed): the value stays in the
//!   immutable module; nothing reaches the account;
//! - account abort before commit (stale nonce, consumed seqno, expiry): the
//!   forwarded value bounces to the module, which ignores bounces, so it stays
//!   there;
//! - committed account refusal (a throw after the account committed its
//!   counters): the seqno and auth nonce are consumed, no transfer is made and
//!   the forwarded value stays in the Agent Account (resolved as
//!   `committed-refusal`);
//! - success: exactly the signed transfer (resolved as `transferred`).

use super::super::native_registry_cmd::read_controller_seed;
use super::*;
use contracts::agent_account_auth::{
    AUTH_KIND_EXECUTE, AUTH_MODE_MODULE_ONLY, AUTH_MODE_STAGED, AgentAccountState, AgentAuthState,
    AuthRequest, Mldsa44AuthConfig, Mldsa44AuthModule, build_auth_envelope,
    build_mldsa44_relay_wallet_message, build_mldsa44_submit, build_stage_auth_message,
    check_auth_window, mldsa44_relay_body, parse_mldsa44_submit, request_superseded,
    require_staged_module, sign_auth_request,
};
use contracts::agent_account_custody::MLDSA44_NATIVE_SEND_ACTION_KIND;
use contracts::native_registry::{NATIVE_REGISTRY_SIGNATURE_BYTES, native_public_key_from_seed};
use contracts::{DefaultChainProvider, Mldsa44RelayAttempt};
use std::collections::HashMap;

const MLDSA44_FINALIZED_SCHEMA: &str = "tos.agent-account.mldsa44-native-send-finalized.v1";
const MLDSA44_EXPIRED_SCHEMA: &str = "tos.agent-account.mldsa44-native-send-expired.v1";
const MLDSA44_SUPERSEDED_SCHEMA: &str = "tos.agent-account.mldsa44-native-send-superseded.v1";

mod strict;
pub use strict::{AgentAccountMldsa44CutoverCmd, AgentAccountMldsa44RotateCmd};

#[derive(clap::Args, Clone)]
#[command(
    about = "Deploy and verify this controller's ML-DSA-44 authentication module and stage it on the Agent Account (legacy authentication stays enabled)"
)]
pub struct AgentAccountMldsa44InstallCmd {
    #[arg(short = 'n', long = "wallet", help = "Agent Wallet profile name")]
    wallet: String,
    #[arg(
        long,
        help = "ML-DSA-44 controller name in the vault (agent native-registry new-controller)"
    )]
    controller: String,
    #[arg(long, help = "TOS sent with the module StateInit if it is not deployed yet")]
    deploy_amount: f64,
    #[arg(long, help = "TOS carried by the owner's stage_auth message")]
    amount: f64,
    #[arg(
        long,
        help = "Lift the custody fence of an earlier install that did not finish; use only when its stage message was never sent or its wallet message has expired"
    )]
    recover_interrupted: bool,
    #[arg(long, help = "Skip confirmation prompts")]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Sign one native transfer with the ML-DSA-44 controller, journal it, and relay it through the account's module from any relaying wallet (default: the owner wallet); resolve it with mldsa44-resolve"
)]
pub struct AgentAccountMldsa44SendCmd {
    #[arg(short = 'n', long = "wallet", help = "Agent Wallet profile name")]
    wallet: String,
    #[arg(long, help = "ML-DSA-44 controller name in the vault")]
    controller: String,
    #[arg(allow_hyphen_values = true, value_parser = super::super::utils::address_arg, long, help = "Destination address")]
    target: String,
    #[arg(long, help = "Transfer amount in TOS")]
    value: f64,
    #[arg(
        long,
        help = "Unix time after which the request is invalid; at most 3600 s after the chain time"
    )]
    valid_until: u32,
    #[arg(long, help = "Stable 64-lowercase-hex idempotency ID")]
    action_id: String,
    #[arg(
        long,
        help = "TOS the relaying wallet attaches: it pays the module's verification of the 2,420-byte signature, the forwarding of the envelope and the account's execution; if the module refuses the submission what verification left bounces to the relaying wallet, after an account abort it stays in the module, after success or a committed refusal in the Agent Account"
    )]
    relay_amount: f64,
    #[arg(
        long,
        help = "Wallet profile (or master_wallet) that relays the signed submission and pays its own fees and the relay amount; default: the Agent Wallet's owner wallet. It carries no authority and may differ between a send and its rebroadcast"
    )]
    relayer: Option<String>,
    #[arg(
        long,
        help = "Relay the journaled submission again although it was already broadcast, byte for byte, through --relayer; it can never pay twice, the account refuses a consumed nonce"
    )]
    rebroadcast: bool,
    #[arg(long, help = "Skip confirmation prompt")]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Resolve an ML-DSA-44 native send from three distinct RPC process views: transferred, committed refusal, or expired without consuming the sequence"
)]
pub struct AgentAccountMldsa44ResolveCmd {
    #[arg(short = 'n', long = "wallet")]
    wallet: String,
    #[arg(long, help = "Stable 64-lowercase-hex action ID")]
    action_id: String,
    #[arg(
        long = "quorum-config",
        required = true,
        num_args = 2..,
        help = "Two additional absolute single-endpoint configs; with --config these form three distinct RPC process views"
    )]
    quorum_configs: Vec<String>,
    #[arg(long, default_value_t = 1000, help = "Maximum account transactions inspected per view")]
    max_transactions: u32,
}

/// Everything the commands read before acting.
struct Mldsa44Context {
    rpc_client: Arc<ClientJsonRpc>,
    /// Wallet profiles a relayer may be chosen from.
    wallets: HashMap<String, WalletConfig>,
    master_wallet: Option<WalletConfig>,
    agent_wallet: AgentWalletConfig,
    vault: Arc<SecretVault>,
    account: MsgAddressInt,
    data: AgentAccountData,
    auth: AgentAuthState,
    global_id: i32,
    seed: zeroize::Zeroizing<[u8; 32]>,
    public_key: Vec<u8>,
    module: MsgAddressInt,
    chain_now: u32,
    /// The account's raw data as one proven snapshot, and the time of the
    /// state it was read at: what fence recovery is judged against.
    snapshot: AgentAccountState,
    state_time: u32,
}

/// One proven account snapshot: the parsed raw data and its state time.
async fn account_snapshot(
    rpc_client: &ClientJsonRpc,
    account: &MsgAddressInt,
) -> anyhow::Result<(AgentAccountState, u32)> {
    let info = rpc_client.get_address_information(account).await?;
    anyhow::ensure!(info.state == AccountState::Active, "Agent Account is not active");
    let data = read_single_root_boc(info.data.as_ref().context("account state has no data")?)?;
    let state_time = u32::try_from(info.sync_utime).context("account state time exceeds uint32")?;
    Ok((AgentAccountState::parse(&data)?, state_time))
}

async fn chain_now(rpc_client: &ClientJsonRpc) -> anyhow::Result<u32> {
    let master = rpc_client.get_masterchain_info().await?;
    let header = rpc_client
        .get_block_header(master.last.workchain, &master.last.shard.to_string(), master.last.seqno)
        .await?;
    anyhow::ensure!(header.gen_utime != 0, "latest masterchain block has no generation time");
    Ok(header.gen_utime)
}

async fn load_context(
    config_path: &str,
    wallet_name: &str,
    controller: &str,
) -> anyhow::Result<Mldsa44Context> {
    let (config, vault, rpc_client) = load_config_vault_rpc_client(Path::new(config_path)).await?;
    let agent_wallet = config
        .agent_wallets
        .get(wallet_name)
        .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", wallet_name))?
        .clone();
    let account = agent_wallet
        .agent_account_address
        .as_ref()
        .context("Agent Account is not deployed for this wallet")?
        .parse::<MsgAddressInt>()
        .context("Invalid persisted Agent Account address")?;
    let info = rpc_client.get_address_information(&account).await?;
    anyhow::ensure!(info.state == AccountState::Active, "Agent Account is not active");
    let code = info.code.as_ref().context("Agent Account has no deployed code")?;
    anyhow::ensure!(
        read_single_root_boc(code)?.hash(0) == AgentAccountContract::code()?.hash(0),
        "Agent Account code does not match the supported template"
    );
    let provider = contracts::contract_provider!(rpc_client.clone());
    let data = AgentAccountContract::get_data(provider.as_ref(), &account).await?;
    let auth = AgentAuthState::get(provider.as_ref(), &account).await?;
    let global_id = match rpc_client.get_config_param(19).await? {
        ConfigParamEnum::ConfigParam19(value) => value as i32,
        _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
    };
    let seed = read_controller_seed(&vault, controller).await?;
    let public_key = native_public_key_from_seed(&seed);
    let module =
        Mldsa44AuthModule::calculate_address(account.workchain_id(), global_id, &public_key)?;
    let chain_now = chain_now(&rpc_client).await?;
    let (snapshot, state_time) = account_snapshot(&rpc_client, &account).await?;
    Ok(Mldsa44Context {
        rpc_client,
        wallets: config.wallets.clone(),
        master_wallet: config.master_wallet.clone(),
        agent_wallet,
        vault,
        account,
        data,
        auth,
        global_id,
        seed,
        public_key,
        module,
        chain_now,
        snapshot,
        state_time,
    })
}

/// What a deployed module must be: this code, this network, this key.
fn verify_module_view(
    active: bool,
    code_hash: Option<chain_block::UInt256>,
    config: Option<&Mldsa44AuthConfig>,
    global_id: i32,
    public_key: &[u8],
) -> anyhow::Result<()> {
    anyhow::ensure!(active, "the ML-DSA-44 module is not active");
    anyhow::ensure!(
        code_hash == Some(Mldsa44AuthModule::code()?.hash(0)),
        "the deployed module does not run the supported ML-DSA-44 module code"
    );
    let config = config.context("the module reported no configuration")?;
    anyhow::ensure!(config.global_id == global_id, "the module serves another network");
    anyhow::ensure!(config.public_key == public_key, "the module holds another ML-DSA-44 key");
    Ok(())
}

async fn verify_module(ctx: &Mldsa44Context) -> anyhow::Result<()> {
    let info = ctx.rpc_client.get_address_information(&ctx.module).await?;
    let active = info.state == AccountState::Active;
    let code_hash = info
        .code
        .as_ref()
        .map(|code| read_single_root_boc(code).map(|cell| cell.hash(0)))
        .transpose()?;
    let config = if active {
        let provider = contracts::contract_provider!(ctx.rpc_client.clone());
        Some(Mldsa44AuthModule::get_config(provider.as_ref(), &ctx.module).await?)
    } else {
        None
    };
    verify_module_view(active, code_hash, config.as_ref(), ctx.global_id, &ctx.public_key)
}

#[derive(Debug, PartialEq, Eq)]
enum StageDecision {
    Stage,
    AlreadyStaged,
}

/// Whether staging `module` is the next step, refused when the account is
/// already strict or a counter the stage advances is exhausted.
fn stage_decision(
    auth: &AgentAuthState,
    data: &AgentAccountData,
    account: &MsgAddressInt,
    module: &MsgAddressInt,
) -> anyhow::Result<StageDecision> {
    anyhow::ensure!(
        auth.mode < AUTH_MODE_MODULE_ONLY,
        "the Agent Account is already in strict authentication mode {}; this route only stages",
        auth.mode
    );
    if auth.mode == AUTH_MODE_STAGED
        && auth.module_address(account.workchain_id())?.as_ref() == Some(module)
    {
        return Ok(StageDecision::AlreadyStaged);
    }
    anyhow::ensure!(auth.epoch < u64::MAX, "the auth epoch is exhausted");
    anyhow::ensure!(data.controller_epoch < u64::MAX, "the controller epoch is exhausted");
    anyhow::ensure!(data.seqno < u32::MAX, "the controller seqno is exhausted");
    Ok(StageDecision::Stage)
}

/// The custody claim of one ML-DSA-44 native send. Its identity binds the
/// action ID, account, target, module, network, value and expiry.
#[allow(clippy::too_many_arguments)]
fn mldsa44_claim(
    action_id: &str,
    account: &MsgAddressInt,
    target: &MsgAddressInt,
    module: &MsgAddressInt,
    global_id: i32,
    network_domain: RelayNetworkDomainPin,
    data: &AgentAccountData,
    value: u64,
    valid_until: u32,
) -> ControllerActionClaim {
    let mut identity = Sha256::new();
    identity.update(b"tos.agent-account.mldsa44-native-send.v1\0");
    let account_text = account.to_string();
    let target_text = target.to_string();
    let module_text = module.to_string();
    for part in [
        action_id.as_bytes(),
        account_text.as_bytes(),
        target_text.as_bytes(),
        module_text.as_bytes(),
        global_id.to_be_bytes().as_slice(),
        value.to_be_bytes().as_slice(),
        valid_until.to_be_bytes().as_slice(),
    ] {
        identity.update((part.len() as u64).to_be_bytes());
        identity.update(part);
    }
    ControllerActionClaim {
        account: account_text,
        network_global_id: global_id,
        network_domain: Some(network_domain),
        deployment_id: hex::encode(data.deployment_id),
        controller_epoch: data.controller_epoch,
        seqno: data.seqno,
        target: target_text,
        value_atomic: value,
        body_hash: None,
        state_init_hash: None,
        action_kind: MLDSA44_NATIVE_SEND_ACTION_KIND.to_owned(),
        idempotency_key: action_id.to_owned(),
        action_identity: format!("sha256:{}", hex::encode(identity.finalize())),
        valid_until,
        auth_module: Some(module_text),
    }
}

/// The exact submission for `claim`, signed under the current auth counters.
fn sign_submission(
    seed: &[u8; 32],
    claim: &ControllerActionClaim,
    account: &MsgAddressInt,
    target: &MsgAddressInt,
    auth: &AgentAuthState,
    query_id: u64,
) -> anyhow::Result<Cell> {
    let request = submission_request(claim, account, target, auth)?;
    let signature = sign_auth_request(seed, &request)?;
    build_mldsa44_submit(query_id, &build_auth_envelope(&request)?, &signature)
}

/// A submission of exactly the size `sign_submission` produces for `claim`,
/// with an all-zero signature: what the relayer's fees are bounded over
/// before anything is claimed or signed.
fn placeholder_submission(
    claim: &ControllerActionClaim,
    account: &MsgAddressInt,
    target: &MsgAddressInt,
    auth: &AgentAuthState,
) -> anyhow::Result<Cell> {
    let request = submission_request(claim, account, target, auth)?;
    build_mldsa44_submit(
        u64::MAX,
        &build_auth_envelope(&request)?,
        &[0u8; NATIVE_REGISTRY_SIGNATURE_BYTES],
    )
}

/// The kind-0 AUTH request for `claim` under the current auth counters.
fn submission_request(
    claim: &ControllerActionClaim,
    account: &MsgAddressInt,
    target: &MsgAddressInt,
    auth: &AgentAuthState,
) -> anyhow::Result<Cell> {
    let payload = AgentAccountContract::build_native_send_payload(
        claim.network_global_id,
        claim.controller_epoch,
        claim.seqno,
        claim.valid_until,
        target,
        claim.value_atomic,
    )?;
    AuthRequest {
        global_id: claim.network_global_id,
        account: account.clone(),
        epoch: auth.epoch,
        nonce: auth.nonce,
        valid_until: claim.valid_until,
        kind: AUTH_KIND_EXECUTE,
        payload,
    }
    .to_cell()
}

impl AgentAccountMldsa44InstallCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_tos_amount("deploy-amount", self.deploy_amount)?;
        validate_tos_amount("amount", self.amount)?;
        anyhow::ensure!(
            self.deploy_amount > 0.0 && self.amount > 0.0,
            "deploy-amount and amount must be greater than zero"
        );
        let ctx = load_context(config_path, &self.wallet, &self.controller).await?;
        let (owner_address, owner_info, owner_secret) =
            wallet_info(ctx.rpc_client.clone(), &ctx.agent_wallet.wallet, ctx.vault.clone())
                .await?;
        anyhow::ensure!(
            owner_address == ctx.data.owner,
            "Agent Wallet '{}' is not the deployed Agent Account owner",
            self.wallet
        );
        anyhow::ensure!(
            owner_info.account_state == AccountState::Active,
            "the owner wallet is not active"
        );
        let decision = stage_decision(&ctx.auth, &ctx.data, &ctx.account, &ctx.module)?;
        println!(
            "\n{}\n  Account:  {}\n  Module:   {}\n  Network:  {}\n  Stage:    {:?}\n",
            "Agent Account ML-DSA-44 install".cyan().bold(),
            ctx.account,
            ctx.module,
            ctx.global_id,
            decision
        );
        let module_info = ctx.rpc_client.get_address_information(&ctx.module).await?;
        if module_info.state != AccountState::Active {
            if !self.yes && !confirm("Deploy the ML-DSA-44 module from the owner wallet?")? {
                println!("{}", "Install cancelled".yellow());
                return Ok(());
            }
            let wallet = make_wallet(
                ctx.rpc_client.clone(),
                &ctx.agent_wallet.wallet,
                owner_secret,
                &self.wallet,
            )
            .await?;
            send_wallet_message_with_state_init(
                &wallet,
                ctx.rpc_client.clone(),
                ctx.module.clone(),
                tos_to_nanotos(self.deploy_amount),
                Cell::default(),
                owner_info.seqno,
                &owner_address,
                Mldsa44AuthModule::build_state_init(ctx.global_id, &ctx.public_key)?,
            )
            .await
            .context("deploy the ML-DSA-44 module")?;
            wait_until(DEPLOY_TIMEOUT, || async {
                Ok(ctx.rpc_client.get_address_information(&ctx.module).await?.state
                    == AccountState::Active)
            })
            .await
            .context("the ML-DSA-44 module did not become active")?;
        }
        // Verified on every run, whether just deployed or already there.
        verify_module(&ctx).await?;
        let journal = open_controller_journal(Path::new(config_path))?;
        let deployment_id = hex::encode(ctx.data.deployment_id);
        let account_text = ctx.account.to_string();
        // A fence is finished only when the account shows its own stage
        // landed: staged, at the auth epoch after the one it expected, with
        // the module it staged; whichever module this run installs. Moved
        // controller counters alone (an owner rotate-controller) never lift it.
        journal.finish_landed_controller_epoch_change(
            &account_text,
            ctx.global_id,
            &deployment_id,
            ctx.data.controller_epoch,
            ctx.data.seqno,
            &ctx.auth,
        )?;
        let interrupted = recover_interrupted_fence(
            &journal,
            &account_text,
            ctx.global_id,
            &deployment_id,
            &ctx.snapshot,
            ctx.state_time,
            self.recover_interrupted,
        )?;
        if decision == StageDecision::AlreadyStaged {
            if interrupted.is_some() {
                println!(
                    "{} another authentication change of this account is still fenced in the custody journal; it is left held (lift it with --recover-interrupted once its stage cannot arrive)",
                    "NOTE".yellow().bold()
                );
            }
            println!("{} module already staged on {}", "OK".green().bold(), ctx.account);
            return Ok(());
        }
        if let Some(start) = interrupted {
            // An earlier run fenced the account and did not see its stage
            // land. Its stage message may still arrive; only the operator can
            // say it was never sent or can no longer be accepted.
            anyhow::bail!(
                "an earlier mldsa44-install of this account did not finish (fenced at controller epoch {}, seqno {}); if its stage message was never sent or its wallet message has expired, run again with --recover-interrupted",
                start.0,
                start.1
            );
        }
        journal.reconcile_finalized_state(
            &account_text,
            ctx.global_id,
            &deployment_id,
            ctx.data.controller_epoch,
            ctx.data.seqno,
            time_format::now(),
        )?;
        if !self.yes
            && !confirm(&format!(
                "Stage module {} on {} (auth epoch {} -> {})?",
                ctx.module,
                ctx.account,
                ctx.auth.epoch,
                ctx.auth.epoch.saturating_add(1)
            ))?
        {
            println!("{}", "Install cancelled".yellow());
            return Ok(());
        }
        // Staging advances the controller epoch. Fence the account first: the
        // journal refuses this while any action is unresolved or another
        // install holds a fence, and admits no claim from now until this
        // invocation sees its stage land, so none can be stranded.
        let mut token_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);
        journal.begin_controller_epoch_change(
            &account_text,
            ctx.global_id,
            &deployment_id,
            ctx.data.controller_epoch,
            ctx.data.seqno,
            ctx.auth.epoch,
            &module_hash_of(&ctx.module)?,
            &token,
        )?;
        let provider = contracts::contract_provider!(ctx.rpc_client.clone());
        let fresh = AgentAccountContract::get_data(provider.as_ref(), &ctx.account).await?;
        let fresh_auth = AgentAuthState::get(provider.as_ref(), &ctx.account).await?;
        if (fresh.controller_epoch, fresh.seqno) != (ctx.data.controller_epoch, ctx.data.seqno)
            || fresh_auth != ctx.auth
        {
            // Nothing was sent by this invocation.
            journal.end_controller_epoch_change(
                &account_text,
                ctx.global_id,
                &deployment_id,
                fresh.controller_epoch,
                fresh.seqno,
                Some(&token),
            )?;
            anyhow::bail!("the Agent Account changed while installing; run mldsa44-install again");
        }
        let (_, owner_info, owner_secret) =
            wallet_info(ctx.rpc_client.clone(), &ctx.agent_wallet.wallet, ctx.vault.clone())
                .await?;
        let query_id = (time_format::now() << 32) | u64::from(owner_info.seqno.unwrap_or_default());
        let body = build_stage_auth_message(query_id, ctx.global_id, ctx.auth.epoch, &ctx.module)?;
        let wallet = make_wallet(
            ctx.rpc_client.clone(),
            &ctx.agent_wallet.wallet,
            owner_secret,
            &self.wallet,
        )
        .await?;
        let boc = build_wallet_message_boc(
            &wallet,
            ctx.account.clone(),
            tos_to_nanotos(self.amount),
            body,
            true,
            owner_info.seqno,
        )
        .await?;
        confirm_prepared_wallet_message(
            ctx.rpc_client.clone(),
            &boc,
            &owner_address,
            &ctx.account,
            DEPLOY_TIMEOUT,
        )
        .await?;
        let expected_epoch = ctx.auth.epoch.checked_add(1).context("auth epoch overflow")?;
        let expected_counters = (
            ctx.data.controller_epoch.checked_add(1).context("controller epoch overflow")?,
            ctx.data.seqno.checked_add(1).context("seqno overflow")?,
        );
        wait_until(DEPLOY_TIMEOUT, || async {
            let provider = contracts::contract_provider!(ctx.rpc_client.clone());
            let auth = AgentAuthState::get(provider.as_ref(), &ctx.account).await?;
            let data = AgentAccountContract::get_data(provider.as_ref(), &ctx.account).await?;
            Ok(auth.mode == AUTH_MODE_STAGED
                && auth.epoch == expected_epoch
                && auth.nonce == 0
                && auth.module_address(ctx.account.workchain_id())?.as_ref() == Some(&ctx.module)
                && (data.controller_epoch, data.seqno) == expected_counters)
        })
        .await
        .context(
            "the Agent Account did not reach the staged state; the account stays fenced in the custody journal until mldsa44-install is run again and sees the outcome",
        )?;
        journal.end_controller_epoch_change(
            &account_text,
            ctx.global_id,
            &deployment_id,
            expected_counters.0,
            expected_counters.1,
            Some(&token),
        )?;
        println!(
            "{} module {} staged on {} (auth epoch {}, controller epoch {}, seqno {})",
            "OK".green().bold(),
            ctx.module,
            ctx.account,
            expected_epoch,
            expected_counters.0,
            expected_counters.1
        );
        Ok(())
    }
}

async fn wait_until<F, Fut>(deadline: tokio::time::Duration, mut observe: F) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<bool>>,
{
    let mut last_error = None;
    let result = tokio::time::timeout(deadline, async {
        loop {
            match observe().await {
                Ok(true) => return,
                Ok(false) => {}
                Err(error) => last_error = Some(error.to_string()),
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    })
    .await;
    result.map_err(|_| {
        anyhow::anyhow!(
            "timed out; last read error: {}",
            last_error.unwrap_or_else(|| "none".into())
        )
    })
}

impl AgentAccountMldsa44SendCmd {
    /// The wallet this invocation relays from: `--relayer`, or the owner
    /// wallet when it is omitted. The one selection both the first relay and
    /// `--rebroadcast` use.
    fn relayer_selection(
        &self,
        wallets: &HashMap<String, WalletConfig>,
        master_wallet: Option<&WalletConfig>,
        owner: &WalletConfig,
    ) -> anyhow::Result<RelayerSelection> {
        resolve_relayer(self.relayer.as_deref(), wallets, master_wallet, owner)
    }

    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_controller_action_id(&self.action_id)?;
        validate_tos_amount("value", self.value)?;
        validate_tos_amount("relay-amount", self.relay_amount)?;
        anyhow::ensure!(
            self.value > 0.0 && self.relay_amount > 0.0,
            "value and relay-amount must be greater than zero"
        );
        let target = self.target.parse::<MsgAddressInt>().context("invalid target address")?;
        let value = tos_to_nanotos(self.value);
        let ctx = load_context(config_path, &self.wallet, &self.controller).await?;
        let master = ctx.rpc_client.get_masterchain_info().await?;
        let zero_state = master.init.context("primary RPC omitted the zero-state identity")?;
        let network_domain = RelayNetworkDomainPin {
            network_id: format!("tos:global-id:{}", ctx.global_id),
            global_id: ctx.global_id,
            zero_state_root_hash: format!("sha256:{}", hex::encode(&zero_state.root_hash)),
            zero_state_file_hash: format!("sha256:{}", hex::encode(&zero_state.file_hash)),
            workchain_id: ctx.account.workchain_id(),
        };

        let journal = open_controller_journal(Path::new(config_path))?;
        let existing = journal.find_action_by_idempotency_key(&self.action_id)?;
        let step = send_step(
            existing.as_ref(),
            &SendTerms {
                account: &ctx.account,
                target: &target,
                module: &ctx.module,
                value,
                valid_until: self.valid_until,
                network: &network_domain,
            },
            &CurrentAccount {
                controller_epoch: ctx.data.controller_epoch,
                seqno: ctx.data.seqno,
                chain_now: ctx.chain_now,
                default_task_timeout_secs: ctx.data.default_task_timeout_secs,
                max_per_tx: ctx.data.max_per_tx,
            },
        )?;
        if let SendStep::ReleaseUnsigned(reason) = step {
            let record = existing.as_ref().context("released claim has no record")?;
            journal.release_unsigned_mldsa44_claim(&record.claim, reason, time_format::now())?;
            anyhow::bail!(
                "the unsigned claim of this action ID was released ({reason}); send again with a new action ID"
            );
        }
        verify_module(&ctx).await?;
        let relayer = self.relayer_selection(
            &ctx.wallets,
            ctx.master_wallet.as_ref(),
            &ctx.agent_wallet.wallet,
        )?;
        let environment =
            ChainRelayEnvironment { rpc_client: ctx.rpc_client.clone(), vault: ctx.vault.clone() };
        let relay_amount = tos_to_nanotos(self.relay_amount);
        if step == SendStep::Relay {
            let record = existing.as_ref().context("relayed action has no record")?;
            if record.exact_signed_boc_base64.is_some() {
                if record.status == ControllerActionStatus::Broadcasting && !self.rebroadcast {
                    anyhow::bail!(
                        "this ML-DSA-44 action was already broadcast; resolve it with mldsa44-resolve, or pass --rebroadcast to relay the same submission again"
                    );
                }
                let relaying = check_relayer(
                    &environment,
                    &relayer,
                    &ctx.module,
                    &journaled_relay_body(record)?,
                    relay_amount,
                )
                .await?;
                if !self.yes
                    && !confirm(&format!(
                        "Relay the journaled ML-DSA-44 submission {} (seqno {}, valid_until {}) from wallet '{}' ({relaying})?",
                        self.action_id, record.claim.seqno, record.claim.valid_until, relayer.label
                    ))?
                {
                    println!("{}", "ML-DSA-44 send cancelled".yellow());
                    return Ok(());
                }
                let relayed = relay_submission(
                    &environment,
                    &journal,
                    record,
                    &relayer,
                    relay_amount,
                    time_format::now(),
                )
                .await?;
                print_relayed(&self.action_id, &record.claim, &relayed);
                return Ok(());
            }
        }
        // A resumable unsigned claim of this action ID, released if the
        // operator declines below.
        let unsigned = existing.filter(|_| step == SendStep::ResumeUnsigned);
        // Every check and the confirmation come before anything is claimed:
        // a refused or declined request leaves no reservation behind.
        require_staged_module(&ctx.auth, &ctx.account, &ctx.module)?;
        check_auth_window(self.valid_until, ctx.chain_now, ctx.data.default_task_timeout_secs)?;
        let claim = mldsa44_claim(
            &self.action_id,
            &ctx.account,
            &target,
            &ctx.module,
            ctx.global_id,
            network_domain,
            &ctx.data,
            value,
            self.valid_until,
        );
        let relaying = check_relayer(
            &environment,
            &relayer,
            &ctx.module,
            &placeholder_submission(&claim, &ctx.account, &target, &ctx.auth)?,
            relay_amount,
        )
        .await?;
        if !self.yes
            && !confirm(&format!(
                "Authorize {} from {} to {} with ML-DSA-44 controller '{}', seqno {}, valid_until {}, relayed by wallet '{}' ({relaying})?",
                display_tos(value),
                ctx.account,
                target,
                self.controller,
                ctx.data.seqno,
                self.valid_until,
                relayer.label
            ))?
        {
            if let Some(record) = &unsigned {
                journal.release_unsigned_mldsa44_claim(
                    &record.claim,
                    "declined before signing",
                    time_format::now(),
                )?;
            }
            println!("{}", "ML-DSA-44 send cancelled".yellow());
            return Ok(());
        }
        let deployment_id = hex::encode(ctx.data.deployment_id);
        journal.reconcile_finalized_state(
            &ctx.account.to_string(),
            ctx.global_id,
            &deployment_id,
            ctx.data.controller_epoch,
            ctx.data.seqno,
            time_format::now(),
        )?;
        let (record, _) = journal.claim_primary(claim.clone(), time_format::now())?;
        let signed = match (record.exact_signed_boc_base64.clone(), record.status) {
            (None, ControllerActionStatus::Claimed) => {
                let submission = sign_submission(
                    &ctx.seed,
                    &claim,
                    &ctx.account,
                    &target,
                    &ctx.auth,
                    (time_format::now() << 32) | u64::from(ctx.data.seqno),
                )?;
                let bytes = write_boc(&submission)?;
                let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
                let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
                journal.attach_signed_boc(&claim, &encoded, &digest, time_format::now())?
            }
            (_, status) => {
                // claim_primary returned a record this run did not sign; it
                // was created concurrently. Leave it to its own invocation.
                anyhow::bail!("custody record in state {status:?} was not created by this run")
            }
        };
        let relayed = relay_submission(
            &environment,
            &journal,
            &signed,
            &relayer,
            relay_amount,
            time_format::now(),
        )
        .await?;
        print_relayed(&self.action_id, &claim, &relayed);
        Ok(())
    }
}

/// The wallet that relays: a named wallet profile (or `master_wallet`), or
/// the Agent Wallet's owner wallet when none is named.
#[derive(Clone)]
struct RelayerSelection {
    label: String,
    wallet: WalletConfig,
}

fn resolve_relayer(
    relayer: Option<&str>,
    wallets: &HashMap<String, WalletConfig>,
    master_wallet: Option<&WalletConfig>,
    owner: &WalletConfig,
) -> anyhow::Result<RelayerSelection> {
    match relayer {
        None => Ok(RelayerSelection { label: "owner".to_owned(), wallet: owner.clone() }),
        Some(name) => {
            anyhow::ensure!(!name.is_empty(), "--relayer names a wallet profile");
            let wallet = get_wallet_config(name, wallets, master_wallet)
                .context("--relayer names no configured wallet profile")?;
            Ok(RelayerSelection { label: name.to_owned(), wallet: wallet.clone() })
        }
    }
}

/// A relaying wallet as the chain shows it, with a signer.
struct LoadedRelayer {
    address: MsgAddressInt,
    active: bool,
    seqno: Option<u32>,
    wallet: Box<dyn Wallet>,
}

/// What a relay reads from the chain and the vault and where it sends, so
/// the relay orchestration itself is what the tests run.
trait RelayEnvironment {
    async fn load_relayer(&self, relayer: &RelayerSelection) -> anyhow::Result<LoadedRelayer>;
    /// The wallet's own fee bound for sending `body` as one message to
    /// `destination`, and the balance it holds, read at one block. The
    /// outbound message is priced as the action phase prices it, by both
    /// endpoints' workchains.
    async fn wallet_reserve(
        &self,
        wallet: &MsgAddressInt,
        destination: &MsgAddressInt,
        body: &Cell,
    ) -> anyhow::Result<(u128, u64)>;
    /// Sends the wallet message and confirms its exact transaction.
    async fn broadcast(
        &self,
        wallet_message: &[u8],
        wallet: &MsgAddressInt,
        module: &MsgAddressInt,
    ) -> anyhow::Result<()>;
}

struct ChainRelayEnvironment {
    rpc_client: Arc<ClientJsonRpc>,
    vault: Arc<SecretVault>,
}

impl RelayEnvironment for ChainRelayEnvironment {
    async fn load_relayer(&self, relayer: &RelayerSelection) -> anyhow::Result<LoadedRelayer> {
        let (address, info, secret) =
            wallet_info(self.rpc_client.clone(), &relayer.wallet, self.vault.clone()).await?;
        let wallet =
            make_wallet(self.rpc_client.clone(), &relayer.wallet, secret, &relayer.label).await?;
        Ok(LoadedRelayer {
            address,
            active: info.account_state == AccountState::Active,
            seqno: info.seqno,
            wallet: Box::new(wallet),
        })
    }

    async fn wallet_reserve(
        &self,
        wallet: &MsgAddressInt,
        destination: &MsgAddressInt,
        body: &Cell,
    ) -> anyhow::Result<(u128, u64)> {
        let chain = DefaultChainProvider::new(self.rpc_client.clone());
        super::super::vote_cmd::pinned_wallet_reserve_to(
            &chain,
            wallet,
            destination.workchain_id(),
            body,
        )
        .await
    }

    async fn broadcast(
        &self,
        wallet_message: &[u8],
        wallet: &MsgAddressInt,
        module: &MsgAddressInt,
    ) -> anyhow::Result<()> {
        confirm_prepared_wallet_message(
            self.rpc_client.clone(),
            &wallet_message.to_vec(),
            wallet,
            module,
            DEPLOY_TIMEOUT,
        )
        .await
    }
}

/// The relaying wallet must be active and hold the relay amount plus its own
/// fees for sending `body`.
fn relayer_can_pay(
    label: &str,
    active: bool,
    balance: u64,
    relay_amount: u64,
    reserve: u128,
) -> anyhow::Result<()> {
    anyhow::ensure!(active, "the relaying wallet '{label}' is not active");
    let needed = u128::from(relay_amount)
        .checked_add(reserve)
        .context("the relay amount plus fees overflows")?;
    anyhow::ensure!(
        u128::from(balance) >= needed,
        "the relaying wallet '{label}' holds {balance} nanoTOS; the relay needs {relay_amount} plus about {reserve} in the wallet's own fees ({needed} in all)"
    );
    Ok(())
}

/// Checks the relayer can pay for relaying `body` to `module`; returns its address.
async fn check_relayer<E: RelayEnvironment>(
    environment: &E,
    relayer: &RelayerSelection,
    module: &MsgAddressInt,
    body: &Cell,
    relay_amount: u64,
) -> anyhow::Result<MsgAddressInt> {
    let loaded = environment.load_relayer(relayer).await?;
    let (reserve, balance) = environment.wallet_reserve(&loaded.address, module, body).await?;
    relayer_can_pay(&relayer.label, loaded.active, balance, relay_amount, reserve)?;
    Ok(loaded.address)
}

/// The exact journaled submission of a signed record, as its relay body.
fn journaled_relay_body(record: &ControllerActionRecord) -> anyhow::Result<Cell> {
    let encoded = record
        .exact_signed_boc_base64
        .as_deref()
        .context("the ML-DSA-44 action has no journaled submission")?;
    let digest = record
        .exact_signed_boc_digest
        .as_deref()
        .context("the ML-DSA-44 action has no submission digest")?;
    mldsa44_relay_body(&base64::engine::general_purpose::STANDARD.decode(encoded)?, digest)
}

/// What one relay sent.
#[derive(Debug)]
struct RelayedSubmission {
    relayer: MsgAddressInt,
    module: MsgAddressInt,
    submission_digest: String,
    wallet_message_digest: String,
}

/// Relays the exact journaled submission of `record` from the `relayer`
/// wallet. The body is the journaled bytes, read back and checked against
/// their digest, never rebuilt. The relayer is checked, a Signed record
/// moves to Broadcasting (so an interrupted run is never mistaken for an
/// unsent one), and the relay is journaled with its wallet message before
/// anything is sent.
async fn relay_submission<E: RelayEnvironment>(
    environment: &E,
    journal: &AgentAccountCustodyJournal,
    record: &ControllerActionRecord,
    relayer: &RelayerSelection,
    relay_amount: u64,
    now: u64,
) -> anyhow::Result<RelayedSubmission> {
    let body = journaled_relay_body(record)?;
    let submission_digest = record
        .exact_signed_boc_digest
        .clone()
        .context("the ML-DSA-44 action has no submission digest")?;
    let module = record
        .claim
        .auth_module
        .as_ref()
        .context("ML-DSA-44 claim has no pinned module")?
        .parse::<MsgAddressInt>()?;
    let loaded = environment.load_relayer(relayer).await?;
    let (reserve, balance) = environment.wallet_reserve(&loaded.address, &module, &body).await?;
    relayer_can_pay(&relayer.label, loaded.active, balance, relay_amount, reserve)?;
    if record.status == ControllerActionStatus::Signed {
        journal.begin_broadcast(&record.claim, now)?;
    }
    let message = build_mldsa44_relay_wallet_message(
        loaded.wallet.as_ref(),
        &module,
        relay_amount,
        body,
        loaded.seqno,
    )
    .await?;
    let wallet_message_digest = format!("sha256:{}", hex::encode(Sha256::digest(&message)));
    journal.record_mldsa44_relay(
        &record.claim,
        &submission_digest,
        Mldsa44RelayAttempt {
            relayer: loaded.address.to_string(),
            wallet_message_digest: wallet_message_digest.clone(),
            relay_amount_atomic: relay_amount,
            at_unix: now,
        },
    )?;
    environment.broadcast(&message, &loaded.address, &module).await?;
    Ok(RelayedSubmission {
        relayer: loaded.address,
        module,
        submission_digest,
        wallet_message_digest,
    })
}

fn print_relayed(action_id: &str, claim: &ControllerActionClaim, relayed: &RelayedSubmission) {
    println!(
        "{}",
        serde_json::json!({
            "schema": "tosctl.agent-account.mldsa44-send.v1",
            "action_id": action_id,
            "account": claim.account,
            "module": relayed.module.to_string(),
            "relayer": relayed.relayer.to_string(),
            "controller_epoch": claim.controller_epoch,
            "seqno": claim.seqno,
            "valid_until": claim.valid_until,
            "exact_submission_digest": relayed.submission_digest,
            "wallet_message_digest": relayed.wallet_message_digest,
            "state": "broadcasting",
            "next": "tosctl agent account mldsa44-resolve --action-id <id> --quorum-config <a> <b>",
        })
    );
}

/// The fence an interrupted install left, after explicit recovery if the
/// operator asked for it. The operator states the fenced stage was never sent
/// or can no longer be accepted; it is handled before any other install
/// decision, so a fence stays recoverable whichever module is staged now and
/// after an owner rotation moved the counters (the journal still refuses
/// counters older than the fence's start). The recovery is the journal's,
/// judged against the account snapshot: a signed reconfiguration's fence is
/// refused until the snapshot is past its expiry. Returns the fence still held.
#[allow(clippy::too_many_arguments)]
fn recover_interrupted_fence(
    journal: &AgentAccountCustodyJournal,
    account: &str,
    global_id: i32,
    deployment_id: &str,
    snapshot: &AgentAccountState,
    state_time: u32,
    recover: bool,
) -> anyhow::Result<Option<(u64, u32)>> {
    let interrupted = journal.controller_epoch_change(account, global_id, deployment_id)?;
    let Some(start) = interrupted else {
        return Ok(None);
    };
    if !recover {
        return Ok(Some(start));
    }
    let recovery = journal.recover_controller_epoch_change(
        account,
        global_id,
        deployment_id,
        snapshot,
        state_time,
    )?;
    println!(
        "{} {:?} the fence of an interrupted authentication change started at controller epoch {}, seqno {}",
        "NOTE".yellow().bold(),
        recovery,
        start.0,
        start.1
    );
    Ok(None)
}

/// The 256-bit account hash of a standard module address, as the account
/// stores it in its auth state.
fn module_hash_of(module: &MsgAddressInt) -> anyhow::Result<[u8; 32]> {
    module
        .address()
        .get_bytestring(0)
        .try_into()
        .map_err(|_| anyhow::anyhow!("a module address carries a 256-bit account hash"))
}

/// The terms a send is invoked with.
struct SendTerms<'a> {
    account: &'a MsgAddressInt,
    target: &'a MsgAddressInt,
    module: &'a MsgAddressInt,
    value: u64,
    valid_until: u32,
    network: &'a RelayNetworkDomainPin,
}

/// The account's current counters, chain time and policy.
struct CurrentAccount {
    controller_epoch: u64,
    seqno: u32,
    chain_now: u32,
    default_task_timeout_secs: u64,
    max_per_tx: u64,
}

/// What a send does with its action ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendStep {
    /// No record: a new claim, admitted under the current policy.
    Fresh,
    /// A signed record: relay its exact bytes.
    Relay,
    /// An unsigned record that can no longer be signed as claimed.
    ReleaseUnsigned(&'static str),
    /// An unsigned record that can still be signed as claimed.
    ResumeUnsigned,
}

/// Decides a send's step. An existing record of the action ID is recovered
/// or released first, judged only against its own journaled terms: a policy
/// change after the claim (a lower max_per_tx) must not strand it. The
/// current policy is applied to terms only when they are about to be signed.
fn send_step(
    record: Option<&ControllerActionRecord>,
    terms: &SendTerms,
    current: &CurrentAccount,
) -> anyhow::Result<SendStep> {
    if let Some(record) = record {
        require_same_terms(
            &record.claim,
            terms.account,
            terms.target,
            terms.module,
            terms.value,
            terms.valid_until,
            terms.network,
        )?;
        match (record.status.clone(), record.exact_signed_boc_base64.is_some()) {
            (ControllerActionStatus::Resolved, _) => {
                anyhow::bail!("this ML-DSA-44 action is already resolved; nothing to send")
            }
            (ControllerActionStatus::Signed | ControllerActionStatus::Broadcasting, true) => {
                return Ok(SendStep::Relay);
            }
            (ControllerActionStatus::Claimed, false) => {
                if (record.claim.controller_epoch, record.claim.seqno)
                    != (current.controller_epoch, current.seqno)
                {
                    return Ok(SendStep::ReleaseUnsigned("counters moved before signing"));
                }
                if check_auth_window(
                    terms.valid_until,
                    current.chain_now,
                    current.default_task_timeout_secs,
                )
                .is_err()
                {
                    return Ok(SendStep::ReleaseUnsigned("expired before signing"));
                }
                if terms.value > current.max_per_tx {
                    return Ok(SendStep::ReleaseUnsigned("the current policy refuses its value"));
                }
                return Ok(SendStep::ResumeUnsigned);
            }
            (status, signed) => anyhow::bail!(
                "custody record in state {status:?} is inconsistent (exact submission present: {signed})"
            ),
        }
    }
    anyhow::ensure!(
        terms.value <= current.max_per_tx,
        "value {} exceeds Agent Account max_per_tx {}",
        display_tos(terms.value),
        display_tos(current.max_per_tx)
    );
    Ok(SendStep::Fresh)
}

/// A journaled action's immutable terms must be the ones supplied again.
fn require_same_terms(
    claim: &ControllerActionClaim,
    account: &MsgAddressInt,
    target: &MsgAddressInt,
    module: &MsgAddressInt,
    value: u64,
    valid_until: u32,
    network: &RelayNetworkDomainPin,
) -> anyhow::Result<()> {
    // The journaled bytes are relayed only to the chain they were signed
    // for: the same global id over another zero state is another chain.
    anyhow::ensure!(
        claim.network_domain.as_ref() == Some(network),
        "the configured RPC serves another chain than the one this action was journaled for"
    );
    anyhow::ensure!(
        claim.action_kind == MLDSA44_NATIVE_SEND_ACTION_KIND
            && claim.account == account.to_string()
            && claim.target == target.to_string()
            && claim.auth_module.as_deref() == Some(module.to_string().as_str())
            && claim.value_atomic == value
            && claim.valid_until == valid_until,
        "action ID already names a different custody action; reuse it only with its original terms"
    );
    Ok(())
}

/// What one account transaction says about an ML-DSA-44 submission.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Mldsa44AccountOutcome {
    /// Not from the pinned module, or another envelope.
    Unrelated,
    /// The envelope arrived and the account refused it before committing
    /// anything (replay, consumed seqno, expiry): nothing was consumed.
    Aborted,
    /// Accepted and consumed the counters, with exactly the signed transfer.
    Transferred,
    /// Accepted and consumed the counters without the transfer.
    CommittedRefusal,
}

fn classify_account_transaction(
    transaction: &Transaction,
    module: &MsgAddressInt,
    envelope_hash: &chain_block::UInt256,
    target: &MsgAddressInt,
    value: u64,
) -> anyhow::Result<Mldsa44AccountOutcome> {
    let Some(inbound) = transaction.in_msg_cell() else {
        return Ok(Mldsa44AccountOutcome::Unrelated);
    };
    let inbound = Message::construct_from_cell(inbound)?;
    let Some(header) = inbound.int_header() else {
        return Ok(Mldsa44AccountOutcome::Unrelated);
    };
    if header.bounced || header.src_ref() != Some(module) {
        return Ok(Mldsa44AccountOutcome::Unrelated);
    }
    let Some(body) = inbound.body().cloned() else {
        return Ok(Mldsa44AccountOutcome::Unrelated);
    };
    if body.into_cell()?.repr_hash() != *envelope_hash {
        return Ok(Mldsa44AccountOutcome::Unrelated);
    }
    let TransactionDescr::Ordinary(description) = transaction.read_description()? else {
        return Ok(Mldsa44AccountOutcome::Unrelated);
    };
    // A refusal thrown after commit() leaves a successful compute phase (the
    // committed state) and an empty, successful action phase, so the
    // transaction is not aborted. A failed action phase rolls the state back
    // and aborts the transaction even after a successful compute phase.
    let committed = !description.aborted
        && matches!(&description.compute_ph, chain_block::TrComputePhase::Vm(vm) if vm.success);
    if !committed {
        return Ok(Mldsa44AccountOutcome::Aborted);
    }
    let mut outputs = Vec::new();
    transaction.iterate_out_msgs(|message| {
        outputs.push(message);
        Ok(true)
    })?;
    let expected = chain_block::CurrencyCollection::with_coins(value);
    Ok(match select_exact_finalized_output(&outputs, target, &expected, None, None) {
        Ok(_) => Mldsa44AccountOutcome::Transferred,
        Err(_) => Mldsa44AccountOutcome::CommittedRefusal,
    })
}

/// One RPC view's answer.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
struct Mldsa44Observation {
    outcome: String,
    transaction: Option<FinalizedEconomicPaymentObservation>,
    aborted_deliveries: u32,
    finalized_controller_epoch: u64,
    finalized_seqno: u32,
    chain_now: u32,
    /// The chain time this view read is past the action's valid_until.
    expired: bool,
    /// The account's auth epoch and nonce in the same snapshot.
    auth_epoch: u64,
    auth_nonce: u64,
    /// The snapshot proves the request superseded: counters past it, its
    /// auth nonce never consumed (`request_superseded`).
    superseded: bool,
}

impl Mldsa44Observation {
    /// Views agree only on the same outcome, transaction, counters, auth
    /// state and expiry maturity, so an unexpired view never supports an
    /// expiry verdict and a view without the supersession proof never
    /// supports a superseded one.
    fn quorum_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            self.outcome,
            self.transaction.as_ref().map(|t| t.quorum_key()).unwrap_or_default(),
            self.finalized_controller_epoch,
            self.finalized_seqno,
            self.expired,
            self.auth_epoch,
            self.auth_nonce,
            self.superseded
        )
    }
}

/// Scans the whole bounded history: a replay after success also carries the
/// envelope, so the first matching transaction is not necessarily the one
/// that counts. At most one delivery can commit, since it consumes the nonce.
async fn observe_mldsa44_action(
    config: &AppConfig,
    endpoint: String,
    locator_identity_digest: String,
    expected_network: &RelayNetworkDomainPin,
    account: &MsgAddressInt,
    record: &ControllerActionRecord,
    max_transactions: u32,
) -> anyhow::Result<Mldsa44Observation> {
    let rpc_client = try_create_rpc_client(config).await?;
    rpc_client.verify_pinned_primary_network(expected_network).await?;
    let encoded = record.exact_signed_boc_base64.as_ref().context("record has no submission")?;
    let submission = parse_mldsa44_submit(&read_single_root_boc(
        base64::engine::general_purpose::STANDARD.decode(encoded)?,
    )?)?;
    let envelope_hash = submission.envelope.repr_hash();
    let module = record
        .claim
        .auth_module
        .as_ref()
        .context("ML-DSA-44 record has no pinned module")?
        .parse::<MsgAddressInt>()?;
    let target = record.claim.target.parse::<MsgAddressInt>()?;
    // One proven account snapshot supplies the counters, the time of the
    // account-shard state they belong to, and the start of the history:
    // "unconsumed after expiry" then speaks of one state, never of an old
    // shard state paired with a later masterchain clock.
    let info = rpc_client.get_address_information(account).await?;
    let now = u32::try_from(info.sync_utime).context("account state time exceeds uint32")?;
    let state = read_single_root_boc(info.data.as_ref().context("account state has no data")?)?;
    let data = AgentAccountState::parse(&state)?;
    let superseded = request_superseded(
        &data,
        record.claim.controller_epoch,
        record.claim.seqno,
        submission.request.epoch,
        submission.request.nonce,
    );
    anyhow::ensure!(
        hex::encode(data.deployment_id) == record.claim.deployment_id,
        "the account's deployment differs from the custody claim"
    );

    let mut cursor_lt = info.last_transaction_id.lt;
    let mut cursor_hash =
        base64::engine::general_purpose::STANDARD.encode(&info.last_transaction_id.hash);
    let mut inspected = 0u32;
    let mut aborted = 0u32;
    let mut committed = Vec::new();
    // A page starts at its cursor transaction, which ended the previous page:
    // each transaction is classified once, by its hash.
    let mut seen = BTreeSet::new();
    let bounded = max_transactions.clamp(1, 10_000);
    while cursor_lt != 0 && inspected < bounded {
        let page = rpc_client
            .get_transactions(account, cursor_lt, &cursor_hash, (bounded - inspected).min(100))
            .await?;
        if page.transactions.is_empty() {
            break;
        }
        let mut next_cursor = None;
        for raw in page.transactions {
            inspected = inspected.saturating_add(1);
            next_cursor = Some((raw.lt, raw.hash.clone()));
            if raw.data.is_empty() {
                continue;
            }
            let transaction_boc = base64::engine::general_purpose::STANDARD.decode(&raw.data)?;
            let transaction_root = read_single_root_boc(&transaction_boc)?;
            if !seen.insert(transaction_root.repr_hash()) {
                continue;
            }
            let transaction = Transaction::construct_from_cell(transaction_root.clone())?;
            let outcome = classify_account_transaction(
                &transaction,
                &module,
                &envelope_hash,
                &target,
                record.claim.value_atomic,
            )?;
            match outcome {
                Mldsa44AccountOutcome::Unrelated => {}
                Mldsa44AccountOutcome::Aborted => aborted = aborted.saturating_add(1),
                Mldsa44AccountOutcome::Transferred | Mldsa44AccountOutcome::CommittedRefusal => {
                    let block = raw.block_id.context("transaction has no block identity")?;
                    let master = rpc_client.get_masterchain_info().await?;
                    committed.push((
                        outcome,
                        FinalizedEconomicPaymentObservation {
                            endpoint: endpoint.clone(),
                            locator_identity_digest: locator_identity_digest.clone(),
                            transaction_hash: format!(
                                "sha256:{}",
                                hex::encode(transaction_root.hash(0))
                            ),
                            transaction_lt: transaction.logical_time(),
                            transaction_utime: exact_transaction_utime(
                                transaction.now(),
                                raw.utime,
                            )?,
                            transaction_boc_digest: format!(
                                "sha256:{}",
                                hex::encode(Sha256::digest(&transaction_boc))
                            ),
                            block_workchain: block.workchain,
                            block_shard: block.shard,
                            block_seqno: block.seqno,
                            block_root_hash: format!("sha256:{}", hex::encode(block.root_hash)),
                            block_file_hash: format!("sha256:{}", hex::encode(block.file_hash)),
                            observed_masterchain_seqno: master.last.seqno,
                        },
                    ));
                }
            }
        }
        let Some((next_lt, next_hash)) = next_cursor else { break };
        if next_lt == cursor_lt && next_hash == cursor_hash {
            break;
        }
        cursor_lt = next_lt;
        cursor_hash = next_hash;
    }
    let (outcome, transaction) = settle_history(committed)?;
    Ok(Mldsa44Observation {
        outcome: outcome.to_owned(),
        transaction,
        aborted_deliveries: aborted,
        finalized_controller_epoch: data.controller_epoch,
        finalized_seqno: data.seqno,
        chain_now: now,
        expired: now > record.claim.valid_until,
        auth_epoch: data.auth.epoch,
        auth_nonce: data.auth.nonce,
        superseded,
    })
}

/// The whole bounded history's verdict from its committing deliveries:
/// aborted ones (replays, refusals before commit) were already left out.
fn settle_history<T>(
    mut committed: Vec<(Mldsa44AccountOutcome, T)>,
) -> anyhow::Result<(&'static str, Option<T>)> {
    anyhow::ensure!(
        committed.len() <= 1,
        "more than one account transaction committed this envelope"
    );
    Ok(match committed.pop() {
        Some((Mldsa44AccountOutcome::Transferred, observation)) => {
            ("transferred", Some(observation))
        }
        Some((Mldsa44AccountOutcome::CommittedRefusal, observation)) => {
            ("committed-refusal", Some(observation))
        }
        Some((other, _)) => anyhow::bail!("a {other:?} delivery cannot settle the action"),
        None => ("not-committed", None),
    })
}

/// How a strict-majority observation terminalizes the record, if it can.
#[derive(Debug, PartialEq, Eq)]
enum Mldsa44Resolution {
    /// The exact action consumed the sequence (with or without the transfer).
    Winner,
    /// Expired with the sequence still unconsumed: it can never execute.
    Expired,
    /// Superseded: another action or an owner rotation moved the controller
    /// counters past it while its auth nonce stayed unconsumed, so it was
    /// never applied and never can be.
    Superseded,
}

fn mldsa44_resolution(
    claim: &ControllerActionClaim,
    observation: &Mldsa44Observation,
) -> anyhow::Result<Mldsa44Resolution> {
    let finalized = (observation.finalized_controller_epoch, observation.finalized_seqno);
    let claimed = (claim.controller_epoch, claim.seqno);
    match observation.outcome.as_str() {
        "transferred" | "committed-refusal" => {
            anyhow::ensure!(
                finalized > claimed,
                "finalized Agent Account state has not consumed the claimed sequence"
            );
            Ok(Mldsa44Resolution::Winner)
        }
        "not-committed" if finalized > claimed => {
            // A bounded search finding nothing proves nothing by itself; the
            // snapshot's unconsumed auth nonce with moved counters does.
            anyhow::ensure!(
                observation.superseded,
                "the claimed sequence was consumed but no committing transaction was found in the bounded history and the account state does not prove the request was superseded; widen --max-transactions"
            );
            Ok(Mldsa44Resolution::Superseded)
        }
        "not-committed" => {
            anyhow::ensure!(
                observation.expired && observation.chain_now > claim.valid_until,
                "no account transaction committed this envelope yet and it has not expired; it may still arrive"
            );
            // A bounded search finding nothing is not proof of absence; an
            // unconsumed sequence after expiry is: the account refuses the
            // request from now on.
            anyhow::ensure!(
                finalized == claimed,
                "the claimed sequence was consumed but no committing transaction was found in the bounded history; widen --max-transactions"
            );
            Ok(Mldsa44Resolution::Expired)
        }
        other => anyhow::bail!("unknown ML-DSA-44 observation outcome {other}"),
    }
}

impl AgentAccountMldsa44ResolveCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        validate_controller_action_id(&self.action_id)?;
        anyhow::ensure!(
            self.quorum_configs.len() >= 2
                && self.max_transactions > 0
                && self.max_transactions <= 10_000,
            "resolution requires two additional RPC configs and a bounded transaction history"
        );
        let primary_path = Path::new(config_path);
        anyhow::ensure!(primary_path.is_absolute(), "primary config must be an absolute path");
        let primary_bytes = fs::read(primary_path).context("read primary RPC config")?;
        let primary = AppConfig::load_bytes(
            &primary_bytes,
            config_format_from_path(primary_path)?,
            "primary RPC config",
        )?;
        let agent_wallet = primary
            .agent_wallets
            .get(&self.wallet)
            .ok_or_else(|| anyhow::anyhow!("Agent wallet '{}' not found", self.wallet))?;
        let account = agent_wallet
            .agent_account_address
            .as_ref()
            .context("Agent Account is not deployed for this wallet")?
            .parse::<MsgAddressInt>()?;
        let journal = open_controller_journal(primary_path)?;
        let record = journal.action_by_idempotency_key(&self.action_id)?;
        anyhow::ensure!(
            record.claim.action_kind == MLDSA44_NATIVE_SEND_ACTION_KIND
                && record.claim.account == account.to_string(),
            "action ID does not name an ML-DSA-44 native send of this Agent Account"
        );
        if record.status == ControllerActionStatus::Resolved {
            let resolution = record
                .exact_winner_resolution
                .as_ref()
                .context("resolved record has no evidence")?;
            println!("{}", resolution.evidence);
            return Ok(());
        }
        anyhow::ensure!(
            matches!(
                record.status,
                ControllerActionStatus::Signed | ControllerActionStatus::Broadcasting
            ),
            "the action has no exact submission to resolve"
        );
        let expected_network =
            record.claim.network_domain.clone().context("record has no network pin")?;

        let mut paths = vec![primary_path.to_path_buf()];
        paths.extend(self.quorum_configs.iter().map(PathBuf::from));
        let mut endpoints = BTreeSet::new();
        let mut members = Vec::with_capacity(paths.len());
        for path in paths {
            anyhow::ensure!(path.is_absolute(), "every quorum config must be absolute");
            let bytes = fs::read(&path).context("read quorum config")?;
            let config =
                AppConfig::load_bytes(&bytes, config_format_from_path(&path)?, "quorum config")?;
            let configured = config.chain_rpc.endpoints();
            anyhow::ensure!(
                configured.len() == 1,
                "every quorum config must name one RPC endpoint"
            );
            let (endpoint, display_origin) = canonicalize_chain_rpc_endpoint(&configured[0])?;
            anyhow::ensure!(
                endpoints.insert(endpoint.clone()),
                "quorum RPC endpoints must be distinct"
            );
            members.push((config, display_origin, rpc_locator_identity_digest(&endpoint)?));
        }
        let threshold = members.len() / 2 + 1;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        let mut last_refusal = None;
        loop {
            let mut votes: BTreeMap<String, Vec<Mldsa44Observation>> = BTreeMap::new();
            for (config, display_origin, locator) in &members {
                match observe_mldsa44_action(
                    config,
                    display_origin.clone(),
                    locator.clone(),
                    &expected_network,
                    &account,
                    &record,
                    self.max_transactions,
                )
                .await
                {
                    Ok(observation) => {
                        votes.entry(observation.quorum_key()).or_default().push(observation)
                    }
                    Err(error) => last_refusal = Some(error.to_string()),
                }
            }
            if let Some(winner) = votes.values().find(|group| group.len() >= threshold) {
                let observation = &winner[0];
                match mldsa44_resolution(&record.claim, observation) {
                    Ok(kind) => {
                        let schema = match kind {
                            Mldsa44Resolution::Winner => MLDSA44_FINALIZED_SCHEMA,
                            Mldsa44Resolution::Expired => MLDSA44_EXPIRED_SCHEMA,
                            Mldsa44Resolution::Superseded => MLDSA44_SUPERSEDED_SCHEMA,
                        };
                        let state = match kind {
                            Mldsa44Resolution::Superseded => "superseded",
                            Mldsa44Resolution::Winner | Mldsa44Resolution::Expired => {
                                observation.outcome.as_str()
                            }
                        };
                        let output = serde_json::json!({
                            "schema": schema,
                            "wallet": self.wallet,
                            "action_id": self.action_id,
                            "source_account": account.to_string(),
                            "auth_module": record.claim.auth_module,
                            "destination": record.claim.target,
                            "amount_nanotos": record.claim.value_atomic,
                            "exact_submission_digest": record.exact_signed_boc_digest,
                            "network_domain": expected_network,
                            "quorum": {"members": members.len(), "threshold": threshold, "agreeing": winner.len()},
                            "observation": observation,
                            "state": state,
                        });
                        let resolution = ControllerActionResolutionEvidence {
                            evidence_kind: schema.to_owned(),
                            evidence_digest: controller_resolution_evidence_digest(
                                schema, &output,
                            )?,
                            evidence: output.clone(),
                        };
                        let digest = record
                            .exact_signed_boc_digest
                            .as_deref()
                            .context("record has no exact submission digest")?;
                        if record.status == ControllerActionStatus::Signed
                            && kind == Mldsa44Resolution::Winner
                        {
                            journal.begin_broadcast(&record.claim, time_format::now())?;
                        }
                        match kind {
                            Mldsa44Resolution::Winner => journal.resolve_exact_winner(
                                &record.claim,
                                digest,
                                observation.finalized_controller_epoch,
                                observation.finalized_seqno,
                                resolution,
                                time_format::now(),
                            )?,
                            Mldsa44Resolution::Expired => journal.resolve_exact_absence(
                                &record.claim,
                                digest,
                                record.claim.controller_epoch,
                                record.claim.seqno,
                                resolution,
                                time_format::now(),
                            )?,
                            // Never applied: an absence at the observed,
                            // advanced counters, which become the high-water.
                            Mldsa44Resolution::Superseded => journal.resolve_exact_absence(
                                &record.claim,
                                digest,
                                observation.finalized_controller_epoch,
                                observation.finalized_seqno,
                                resolution,
                                time_format::now(),
                            )?,
                        };
                        println!("{output}");
                        return Ok(());
                    }
                    Err(error) => last_refusal = Some(error.to_string()),
                }
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "the ML-DSA-44 action could not be resolved by a strict majority: {}",
                    last_refusal.unwrap_or_else(|| "views disagree".to_owned())
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::{
        CurrencyCollection, InternalMessageHeader, SliceData, TransactionDescrOrdinary,
    };
    use contracts::SmartContract;

    fn address(workchain: i32, byte: u8) -> MsgAddressInt {
        MsgAddressInt::with_standart(None, workchain as i8, [byte; 32].into()).unwrap()
    }

    fn data() -> AgentAccountData {
        AgentAccountData {
            owner: address(0, 0x01),
            controller_pubkey: [0x02; 32],
            deployment_id: [0x03; 32],
            controller_epoch: 2,
            seqno: 7,
            spend_day: 0,
            spent_today: 0,
            max_per_tx: 5_000_000_000,
            daily_limit: 50_000_000_000,
            default_task_timeout_secs: 3_600,
            metadata_hash: None,
            service_endpoint_hash: None,
        }
    }

    fn pin() -> RelayNetworkDomainPin {
        RelayNetworkDomainPin {
            network_id: "tos:global-id:42".into(),
            global_id: 42,
            zero_state_root_hash: format!("sha256:{}", "a".repeat(64)),
            zero_state_file_hash: format!("sha256:{}", "b".repeat(64)),
            workchain_id: 0,
        }
    }

    fn auth(mode: u8, module: &MsgAddressInt) -> AgentAuthState {
        let MsgAddressInt::AddrStd(std) = module else { unreachable!("standard test address") };
        let module_hash: [u8; 32] = std.address.clone().get_bytestring(0).try_into().unwrap();
        AgentAuthState { mode, epoch: 4, nonce: 0, module_hash }
    }

    #[test]
    fn staging_is_refused_once_strict_and_skipped_when_already_staged() {
        let account = address(0, 0x10);
        let module = address(0, 0x20);
        let other = address(0, 0x21);
        assert_eq!(
            stage_decision(&auth(0, &module), &data(), &account, &module).unwrap(),
            StageDecision::Stage
        );
        assert_eq!(
            stage_decision(&auth(AUTH_MODE_STAGED, &module), &data(), &account, &module).unwrap(),
            StageDecision::AlreadyStaged
        );
        assert_eq!(
            stage_decision(&auth(AUTH_MODE_STAGED, &other), &data(), &account, &module).unwrap(),
            StageDecision::Stage
        );
        for strict in [AUTH_MODE_MODULE_ONLY, 3] {
            assert!(stage_decision(&auth(strict, &module), &data(), &account, &module).is_err());
        }
        let exhausted = AgentAccountData { seqno: u32::MAX, ..data() };
        assert!(stage_decision(&auth(0, &module), &exhausted, &account, &module).is_err());
        let exhausted = AgentAccountData { controller_epoch: u64::MAX, ..data() };
        assert!(stage_decision(&auth(0, &module), &exhausted, &account, &module).is_err());
    }

    #[test]
    fn the_claim_pins_the_module_and_its_identity_binds_every_term() {
        let account = address(0, 0x10);
        let target = address(0, 0x30);
        let module = address(0, 0x20);
        let claim = mldsa44_claim(
            &"a".repeat(64),
            &account,
            &target,
            &module,
            42,
            pin(),
            &data(),
            9,
            1_000,
        );
        assert_eq!(claim.action_kind, MLDSA44_NATIVE_SEND_ACTION_KIND);
        assert_eq!(claim.auth_module, Some(module.to_string()));
        assert_eq!((claim.controller_epoch, claim.seqno), (2, 7));
        let other_module = address(0, 0x22);
        for changed in [
            mldsa44_claim(
                &"a".repeat(64),
                &account,
                &target,
                &other_module,
                42,
                pin(),
                &data(),
                9,
                1_000,
            ),
            mldsa44_claim(
                &"a".repeat(64),
                &account,
                &target,
                &module,
                42,
                pin(),
                &data(),
                10,
                1_000,
            ),
            mldsa44_claim(
                &"a".repeat(64),
                &account,
                &target,
                &module,
                42,
                pin(),
                &data(),
                9,
                1_001,
            ),
            mldsa44_claim(
                &"b".repeat(64),
                &account,
                &target,
                &module,
                42,
                pin(),
                &data(),
                9,
                1_000,
            ),
        ] {
            assert_ne!(changed.action_identity, claim.action_identity);
        }
    }

    #[test]
    fn a_signed_submission_is_what_the_custody_journal_accepts() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let account = address(0, 0x10);
        let target = address(0, 0x30);
        let module = address(0, 0x20);
        let claim = mldsa44_claim(
            &"a".repeat(64),
            &account,
            &target,
            &module,
            42,
            pin(),
            &data(),
            9,
            1_000,
        );
        journal.claim_primary(claim.clone(), 10).unwrap();
        let submission =
            sign_submission(&[0x44; 32], &claim, &account, &target, &auth(1, &module), 3).unwrap();
        let bytes = write_boc(&submission).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        journal.attach_signed_boc(&claim, &encoded, &digest, 11).unwrap();
        // A submission signed for other counters is refused for this claim.
        let moved = ControllerActionClaim { seqno: 8, ..claim.clone() };
        let other = write_boc(
            &sign_submission(&[0x44; 32], &moved, &account, &target, &auth(1, &module), 3).unwrap(),
        )
        .unwrap();
        let other_digest = format!("sha256:{}", hex::encode(Sha256::digest(&other)));
        assert!(
            journal
                .attach_signed_boc(
                    &claim,
                    &base64::engine::general_purpose::STANDARD.encode(&other),
                    &other_digest,
                    12
                )
                .is_err()
        );
    }

    /// An account transaction delivering `body` from `source`.
    fn delivery(
        source: &MsgAddressInt,
        account: &MsgAddressInt,
        body: Cell,
        aborted: bool,
        success: bool,
        outputs: &[Message],
    ) -> Transaction {
        let mut header = InternalMessageHeader::with_addresses(
            source.clone(),
            account.clone(),
            CurrencyCollection::with_coins(1_000_000_000),
        );
        header.bounce = true;
        let mut inbound = Message::with_int_header(header);
        inbound.set_body(SliceData::load_cell(body).unwrap());
        let mut transaction = Transaction::with_address_and_status(
            account.address().clone(),
            chain_block::AccountStatus::AccStateActive,
        );
        transaction.set_in_msg_cell(inbound.serialize().unwrap());
        for output in outputs {
            transaction.add_out_message(output).unwrap();
        }
        let mut description = TransactionDescrOrdinary { aborted, ..Default::default() };
        description.compute_ph = chain_block::TrComputePhase::Vm(chain_block::TrComputePhaseVm {
            success,
            ..Default::default()
        });
        transaction.write_description(&TransactionDescr::Ordinary(description)).unwrap();
        transaction
    }

    fn transfer(account: &MsgAddressInt, target: &MsgAddressInt, value: u64) -> Message {
        Message::with_int_header(InternalMessageHeader::with_addresses(
            account.clone(),
            target.clone(),
            CurrencyCollection::with_coins(value),
        ))
    }

    #[test]
    fn account_transactions_are_classified_by_module_envelope_commit_and_transfer() {
        let account = address(0, 0x10);
        let target = address(0, 0x30);
        let module = address(0, 0x20);
        let envelope = {
            let mut b = BuilderData::new();
            b.append_u32(0x4155_5448).unwrap();
            b.into_cell().unwrap()
        };
        let hash = envelope.repr_hash();
        let classify = |tx: &Transaction| {
            classify_account_transaction(tx, &module, &hash, &target, 9).unwrap()
        };
        let sent = [transfer(&account, &target, 9)];
        assert_eq!(
            classify(&delivery(&module, &account, envelope.clone(), false, true, &sent)),
            Mldsa44AccountOutcome::Transferred
        );
        assert_eq!(
            classify(&delivery(&module, &account, envelope.clone(), false, true, &[])),
            Mldsa44AccountOutcome::CommittedRefusal
        );
        // A successful compute phase whose action phase failed rolled back:
        // nothing was consumed, even if the counters later move for another reason.
        assert_eq!(
            classify(&delivery(&module, &account, envelope.clone(), true, true, &[])),
            Mldsa44AccountOutcome::Aborted
        );
        // A replay after success: aborted before any commit.
        assert_eq!(
            classify(&delivery(&module, &account, envelope.clone(), true, false, &[])),
            Mldsa44AccountOutcome::Aborted
        );
        // Another sender or another envelope is not this action.
        assert_eq!(
            classify(&delivery(&address(0, 0x21), &account, envelope.clone(), false, true, &sent)),
            Mldsa44AccountOutcome::Unrelated
        );
        assert_eq!(
            classify(&delivery(&module, &account, Cell::default(), false, true, &sent)),
            Mldsa44AccountOutcome::Unrelated
        );
        // A transfer of another value is not the signed one.
        assert_eq!(
            classify(&delivery(
                &module,
                &account,
                envelope,
                false,
                true,
                &[transfer(&account, &target, 8)]
            )),
            Mldsa44AccountOutcome::CommittedRefusal
        );
    }

    fn observation(outcome: &str, epoch: u64, seqno: u32, now: u32) -> Mldsa44Observation {
        Mldsa44Observation {
            outcome: outcome.into(),
            transaction: None,
            aborted_deliveries: 0,
            finalized_controller_epoch: epoch,
            finalized_seqno: seqno,
            chain_now: now,
            expired: now > 1_000,
            auth_epoch: 1,
            auth_nonce: 0,
            superseded: false,
        }
    }

    #[test]
    fn a_request_whose_sequence_another_action_took_settles_as_superseded() {
        let claim = mldsa44_claim(
            &"a".repeat(64),
            &address(0, 0x10),
            &address(0, 0x30),
            &address(0, 0x20),
            42,
            pin(),
            &data(),
            9,
            1_000,
        );
        // The verdict follows the snapshot proof, before or after expiry.
        for now in [900, 1_001] {
            let proven =
                Mldsa44Observation { superseded: true, ..observation("not-committed", 2, 8, now) };
            assert_eq!(mldsa44_resolution(&claim, &proven).unwrap(), Mldsa44Resolution::Superseded);
            // Moved counters without the proof stay unresolved.
            assert!(mldsa44_resolution(&claim, &observation("not-committed", 2, 8, now)).is_err());
        }
        // The proof itself: counters moved, auth nonce unconsumed, same auth epoch.
        let state = |epoch, seqno, auth_epoch, nonce| AgentAccountState {
            deployment_id: [0x03; 32],
            controller_epoch: epoch,
            seqno,
            auth: AgentAuthState {
                mode: AUTH_MODE_STAGED,
                epoch: auth_epoch,
                nonce,
                module_hash: [0; 32],
            },
        };
        assert!(request_superseded(&state(2, 8, 1, 0), 2, 7, 1, 0)); // controller took the seqno
        assert!(request_superseded(&state(3, 8, 1, 0), 2, 7, 1, 0)); // owner rotation
        assert!(!request_superseded(&state(2, 8, 1, 1), 2, 7, 1, 0)); // this request committed
        assert!(!request_superseded(&state(3, 8, 2, 0), 2, 7, 1, 0)); // auth epoch moved
        assert!(!request_superseded(&state(2, 7, 1, 0), 2, 7, 1, 0)); // counters unchanged
        // A view without the proof never votes with one that has it.
        assert_ne!(
            observation("not-committed", 2, 8, 900).quorum_key(),
            Mldsa44Observation { superseded: true, ..observation("not-committed", 2, 8, 900) }
                .quorum_key()
        );
    }

    #[test]
    fn a_superseded_action_releases_custody_for_the_next_send() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let account = address(0, 0x10);
        let target = address(0, 0x30);
        let module = address(0, 0x20);
        let claim = mldsa44_claim(
            &"a".repeat(64),
            &account,
            &target,
            &module,
            42,
            pin(),
            &data(),
            9,
            1_000,
        );
        journal.claim_primary(claim.clone(), 10).unwrap();
        let signed = |claim: &ControllerActionClaim| {
            let bytes = write_boc(
                &sign_submission(&[0x44; 32], claim, &account, &target, &auth(1, &module), 3)
                    .unwrap(),
            )
            .unwrap();
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            (base64::engine::general_purpose::STANDARD.encode(&bytes), digest)
        };
        let (boc, digest) = signed(&claim);
        journal.attach_signed_boc(&claim, &boc, &digest, 11).unwrap();
        journal.begin_broadcast(&claim, 12).unwrap();
        let deployment = hex::encode(data().deployment_id);
        // A controller action took seqno 7: the record blocks the next claim.
        let moved = AgentAccountData { seqno: 8, ..data() };
        assert!(
            journal
                .reconcile_finalized_state(&account.to_string(), 42, &deployment, 2, 8, 13)
                .is_err()
        );
        let evidence = serde_json::json!({"state": "superseded"});
        let resolution = ControllerActionResolutionEvidence {
            evidence_kind: MLDSA44_SUPERSEDED_SCHEMA.to_owned(),
            evidence_digest: controller_resolution_evidence_digest(
                MLDSA44_SUPERSEDED_SCHEMA,
                &evidence,
            )
            .unwrap(),
            evidence,
        };
        journal.resolve_exact_absence(&claim, &digest, 2, 8, resolution, 14).unwrap();
        // The next operation is claimed, signed and journaled at the new counters.
        journal.reconcile_finalized_state(&account.to_string(), 42, &deployment, 2, 8, 15).unwrap();
        let next =
            mldsa44_claim(&"b".repeat(64), &account, &target, &module, 42, pin(), &moved, 9, 1_000);
        assert!(journal.claim_primary(next.clone(), 16).unwrap().1);
        let (boc, digest) = signed(&next);
        journal.attach_signed_boc(&next, &boc, &digest, 17).unwrap();
        journal.begin_broadcast(&next, 18).unwrap();
    }

    #[test]
    fn resolution_needs_a_consumed_sequence_or_an_unconsumed_expired_one() {
        let claim = mldsa44_claim(
            &"a".repeat(64),
            &address(0, 0x10),
            &address(0, 0x30),
            &address(0, 0x20),
            42,
            pin(),
            &data(),
            9,
            1_000,
        );
        for outcome in ["transferred", "committed-refusal"] {
            assert_eq!(
                mldsa44_resolution(&claim, &observation(outcome, 2, 8, 900)).unwrap(),
                Mldsa44Resolution::Winner
            );
            assert!(mldsa44_resolution(&claim, &observation(outcome, 2, 7, 900)).is_err());
        }
        assert_eq!(
            mldsa44_resolution(&claim, &observation("not-committed", 2, 7, 1_001)).unwrap(),
            Mldsa44Resolution::Expired
        );
        // Not yet expired: it may still arrive.
        assert!(mldsa44_resolution(&claim, &observation("not-committed", 2, 7, 1_000)).is_err());
        // Expired but the sequence moved and nothing committing was found:
        // a bounded search is not absence proof.
        assert!(mldsa44_resolution(&claim, &observation("not-committed", 2, 8, 1_001)).is_err());
        // An unexpired view never votes with an expired one.
        assert_ne!(
            observation("not-committed", 2, 7, 1_000).quorum_key(),
            observation("not-committed", 2, 7, 1_001).quorum_key()
        );
    }

    #[test]
    fn the_counters_come_from_the_raw_account_data() {
        let init = AgentAccountInit {
            owner: address(0, 0x01),
            controller_pubkey: ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
                .verifying_key()
                .to_bytes(),
            deployment_id: [0x03; 32],
            max_per_tx: 5_000_000_000,
            daily_limit: 50_000_000_000,
            default_task_timeout_secs: 3_600,
            metadata_hash: None,
            service_endpoint_hash: None,
        };
        let data = AgentAccountContract::build_data(&init).unwrap();
        let state = AgentAccountState::parse(&data).unwrap();
        assert_eq!(
            (state.deployment_id, state.controller_epoch, state.seqno, state.auth.mode),
            ([0x03; 32], 0, 0, 0)
        );
        assert!(AgentAccountState::parse(&Cell::default()).is_err());
    }

    #[test]
    fn an_interrupted_install_is_recovered_after_a_rotation_and_the_next_send_claims() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let account = address(0, 0x10);
        let target = address(0, 0x30);
        let module = address(0, 0x20);
        let text = account.to_string();
        let deployment = hex::encode(data().deployment_id);
        // Install B fenced (2, 7) to stage another module and was interrupted;
        // an owner rotation moved the counters to (3, 8). Module A is still
        // staged, so a run of A's install takes the already-staged path.
        journal
            .begin_controller_epoch_change(
                &text,
                42,
                &deployment,
                2,
                7,
                4,
                &[0x21; 32],
                &"c".repeat(64),
            )
            .unwrap();
        assert_eq!(
            stage_decision(&auth(AUTH_MODE_STAGED, &module), &data(), &account, &module).unwrap(),
            StageDecision::AlreadyStaged
        );
        let snapshot = AgentAccountState {
            deployment_id: data().deployment_id,
            controller_epoch: 3,
            seqno: 8,
            auth: auth(AUTH_MODE_STAGED, &module),
        };
        // Without the operator's statement the fence stays.
        assert_eq!(
            recover_interrupted_fence(&journal, &text, 42, &deployment, &snapshot, 900, false)
                .unwrap(),
            Some((2, 7))
        );
        // With it the fence is lifted at the advanced counters.
        assert_eq!(
            recover_interrupted_fence(&journal, &text, 42, &deployment, &snapshot, 900, true)
                .unwrap(),
            None
        );
        let rotated = AgentAccountData { controller_epoch: 3, seqno: 8, ..data() };
        let next = mldsa44_claim(
            &"a".repeat(64),
            &account,
            &target,
            &module,
            42,
            pin(),
            &rotated,
            9,
            1_000,
        );
        assert!(journal.claim_primary(next, 10).unwrap().1);
    }

    #[test]
    fn a_lowered_policy_never_strands_a_journaled_claim() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let account = address(0, 0x10);
        let target = address(0, 0x30);
        let module = address(0, 0x20);
        let here = pin();
        let terms = |value, valid_until| SendTerms {
            account: &account,
            target: &target,
            module: &module,
            value,
            valid_until,
            network: &here,
        };
        let current = |chain_now, max_per_tx| CurrentAccount {
            controller_epoch: 2,
            seqno: 7,
            chain_now,
            default_task_timeout_secs: 3_600,
            max_per_tx,
        };
        let sign = |claim: &ControllerActionClaim| {
            let bytes = write_boc(
                &sign_submission(&[0x44; 32], claim, &account, &target, &auth(1, &module), 3)
                    .unwrap(),
            )
            .unwrap();
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            (base64::engine::general_purpose::STANDARD.encode(&bytes), digest)
        };
        // A send of 9 claims under max_per_tx 5e9 and is interrupted before
        // signing; the owner then lowers max_per_tx to 5.
        let claim = mldsa44_claim(
            &"a".repeat(64),
            &account,
            &target,
            &module,
            42,
            pin(),
            &data(),
            9,
            1_000,
        );
        assert_eq!(
            send_step(None, &terms(9, 1_000), &current(900, 5_000_000_000)).unwrap(),
            SendStep::Fresh
        );
        journal.claim_primary(claim.clone(), 10).unwrap();
        let record = journal.action_by_idempotency_key(&claim.idempotency_key).unwrap();
        // The retry reaches release, before or after expiry, instead of being
        // refused by the current policy.
        assert_eq!(
            send_step(Some(&record), &terms(9, 1_000), &current(900, 5)).unwrap(),
            SendStep::ReleaseUnsigned("the current policy refuses its value")
        );
        assert_eq!(
            send_step(Some(&record), &terms(9, 1_000), &current(1_001, 5)).unwrap(),
            SendStep::ReleaseUnsigned("expired before signing")
        );
        journal.release_unsigned_mldsa44_claim(&claim, "expired before signing", 11).unwrap();
        // A fresh send under the new policy then claims, signs and journals.
        assert!(send_step(None, &terms(9, 1_000), &current(1_001, 5)).is_err());
        assert_eq!(send_step(None, &terms(4, 2_000), &current(1_001, 5)).unwrap(), SendStep::Fresh);
        let fresh = mldsa44_claim(
            &"b".repeat(64),
            &account,
            &target,
            &module,
            42,
            pin(),
            &data(),
            4,
            2_000,
        );
        assert!(journal.claim_primary(fresh.clone(), 12).unwrap().1);
        let (boc, digest) = sign(&fresh);
        journal.attach_signed_boc(&fresh, &boc, &digest, 13).unwrap();
        // A claim signed before the policy change is re-sent, not refused.
        let signed = journal.action_by_idempotency_key(&fresh.idempotency_key).unwrap();
        assert_eq!(
            send_step(Some(&signed), &terms(4, 2_000), &current(1_001, 1)).unwrap(),
            SendStep::Relay
        );
    }

    #[test]
    fn a_retry_must_repeat_the_journaled_terms() {
        let account = address(0, 0x10);
        let target = address(0, 0x30);
        let module = address(0, 0x20);
        let claim = mldsa44_claim(
            &"a".repeat(64),
            &account,
            &target,
            &module,
            42,
            pin(),
            &data(),
            9,
            1_000,
        );
        let here = pin();
        require_same_terms(&claim, &account, &target, &module, 9, 1_000, &here).unwrap();
        // Counters are not terms: a consumed sequence does not block recovery.
        let consumed = ControllerActionClaim { seqno: 8, ..claim.clone() };
        require_same_terms(&consumed, &account, &target, &module, 9, 1_000, &here).unwrap();
        for (target, module, value, valid_until) in [
            (address(0, 0x31), module.clone(), 9, 1_000),
            (target.clone(), address(0, 0x21), 9, 1_000),
            (target.clone(), module.clone(), 10, 1_000),
            (target.clone(), module.clone(), 9, 1_001),
        ] {
            assert!(
                require_same_terms(&claim, &account, &target, &module, value, valid_until, &here)
                    .is_err()
            );
        }
        let ed25519 = ControllerActionClaim {
            action_kind: "agent-native-send".into(),
            auth_module: None,
            ..claim.clone()
        };
        assert!(require_same_terms(&ed25519, &account, &target, &module, 9, 1_000, &here).is_err());
    }

    #[test]
    fn a_retry_is_never_relayed_to_another_chain_with_the_same_global_id() {
        let account = address(0, 0x10);
        let target = address(0, 0x30);
        let module = address(0, 0x20);
        let claim = mldsa44_claim(
            &"a".repeat(64),
            &account,
            &target,
            &module,
            42,
            pin(),
            &data(),
            9,
            1_000,
        );
        for other in [
            RelayNetworkDomainPin {
                zero_state_root_hash: format!("sha256:{}", "c".repeat(64)),
                ..pin()
            },
            RelayNetworkDomainPin {
                zero_state_file_hash: format!("sha256:{}", "d".repeat(64)),
                ..pin()
            },
        ] {
            assert_eq!(other.global_id, claim.network_global_id);
            assert!(
                require_same_terms(&claim, &account, &target, &module, 9, 1_000, &other).is_err()
            );
        }
        let unpinned = ControllerActionClaim { network_domain: None, ..claim };
        assert!(
            require_same_terms(&unpinned, &account, &target, &module, 9, 1_000, &pin()).is_err()
        );
    }

    #[test]
    fn replays_after_success_do_not_hide_it() {
        use Mldsa44AccountOutcome::*;
        // The scan keeps only committing deliveries; replays abort and are
        // counted elsewhere, wherever they fall in the history pages.
        assert_eq!(settle_history(vec![(Transferred, 1)]).unwrap(), ("transferred", Some(1)));
        assert_eq!(
            settle_history(vec![(CommittedRefusal, 2)]).unwrap(),
            ("committed-refusal", Some(2))
        );
        assert_eq!(settle_history::<u8>(vec![]).unwrap(), ("not-committed", None));
        assert!(settle_history(vec![(Transferred, 1), (Transferred, 2)]).is_err());
        assert!(settle_history(vec![(Aborted, 1)]).is_err());
    }

    fn profile(name: &str, subwallet_id: u32) -> WalletConfig {
        WalletConfig {
            key: KeyConfig::VaultKey { name: name.to_owned() },
            version: WalletVersion::V5R1,
            subwallet_id,
            workchain: 0,
        }
    }

    fn profile_seed(wallet: &WalletConfig) -> [u8; 32] {
        let KeyConfig::VaultKey { name } = &wallet.key else { panic!("test profiles are named") };
        let mut seed = [0u8; 32];
        for (slot, byte) in seed.iter_mut().zip(name.bytes().cycle()) {
            *slot = byte;
        }
        seed
    }

    struct TestSigner(ed25519_dalek::SigningKey);

    #[async_trait::async_trait]
    impl common::signer::Signer for TestSigner {
        async fn public_key(&self) -> anyhow::Result<Vec<u8>> {
            Ok(self.0.verifying_key().to_bytes().to_vec())
        }

        async fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
            use ed25519_dalek::Signer as _;
            Ok(self.0.sign(message).to_bytes().to_vec())
        }
    }

    /// Every query is refused: the relay passes the seqno it read.
    struct NoProvider;

    #[async_trait::async_trait]
    impl contracts::ContractProvider for NoProvider {
        async fn get_method(
            &self,
            _address: String,
            method: &str,
            _stack: Vec<tl_api::tos::tvm::StackEntry>,
        ) -> anyhow::Result<common::tvm_stack_parser::TvmStackParser> {
            anyhow::bail!("the relay must not query get-method {method}")
        }

        async fn balance(&self, _address: &MsgAddressInt) -> anyhow::Result<u64> {
            anyhow::bail!("the relay must not query a balance")
        }
    }

    /// Real wallets over in-process signers; broadcasts are captured.
    struct CapturingEnvironment {
        balance: u64,
        reserve: u128,
        sent: std::sync::Mutex<Vec<(MsgAddressInt, MsgAddressInt, Vec<u8>)>>,
        /// The destination each fee bound was computed for.
        reserved_for: std::sync::Mutex<Vec<MsgAddressInt>>,
    }

    impl CapturingEnvironment {
        fn new(balance: u64) -> Self {
            Self {
                balance,
                reserve: 50_000_000,
                sent: std::sync::Mutex::new(Vec::new()),
                reserved_for: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<(MsgAddressInt, MsgAddressInt, Vec<u8>)> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl RelayEnvironment for CapturingEnvironment {
        async fn load_relayer(&self, relayer: &RelayerSelection) -> anyhow::Result<LoadedRelayer> {
            let signer =
                TestSigner(ed25519_dalek::SigningKey::from_bytes(&profile_seed(&relayer.wallet)));
            let wallet = contracts::WalletContract::new(
                Box::new(signer),
                relayer.wallet.version,
                relayer.wallet.subwallet_id,
                relayer.wallet.workchain,
                42,
                Arc::new(NoProvider),
            )
            .await?;
            Ok(LoadedRelayer {
                address: wallet.address(),
                active: true,
                seqno: Some(3),
                wallet: Box::new(wallet),
            })
        }

        async fn wallet_reserve(
            &self,
            _wallet: &MsgAddressInt,
            destination: &MsgAddressInt,
            _body: &Cell,
        ) -> anyhow::Result<(u128, u64)> {
            self.reserved_for.lock().unwrap().push(destination.clone());
            Ok((self.reserve, self.balance))
        }

        async fn broadcast(
            &self,
            wallet_message: &[u8],
            wallet: &MsgAddressInt,
            module: &MsgAddressInt,
        ) -> anyhow::Result<()> {
            self.sent.lock().unwrap().push((
                wallet.clone(),
                module.clone(),
                wallet_message.to_vec(),
            ));
            Ok(())
        }
    }

    /// The external wallet message's destination wallet and the body of the
    /// one internal message it carries to `module`.
    fn decode_relay(wallet_message: &[u8], module: &MsgAddressInt) -> (MsgAddressInt, Vec<u8>) {
        let root = read_single_root_boc(wallet_message).unwrap();
        let external = Message::construct_from_cell(root.clone()).unwrap();
        let wallet = external.ext_in_header().unwrap().dst.clone();
        let mut bodies = Vec::new();
        let mut stack = vec![root];
        while let Some(cell) = stack.pop() {
            for index in 0..cell.references_count() {
                stack.push(cell.reference(index).unwrap());
            }
            let Ok(message) = Message::construct_from_cell(cell) else { continue };
            let Some(header) = message.int_header() else { continue };
            if header.dst != *module {
                continue;
            }
            assert!(header.bounce, "a relay is bounceable, so a module refusal returns to it");
            let body = message.body().cloned().unwrap().into_cell().unwrap();
            bodies.push(write_boc(&body).unwrap());
        }
        assert_eq!(bodies.len(), 1, "the wallet message carries exactly one relay");
        (wallet, bodies.pop().unwrap())
    }

    /// A journal holding one signed ML-DSA-44 action, and its exact bytes.
    fn signed_record()
    -> (tempfile::TempDir, AgentAccountCustodyJournal, ControllerActionRecord, Vec<u8>) {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let account = address(0, 0x10);
        let target = address(0, 0x30);
        let module = address(0, 0x20);
        let claim = mldsa44_claim(
            &"a".repeat(64),
            &account,
            &target,
            &module,
            42,
            pin(),
            &data(),
            9,
            1_000,
        );
        journal.claim_primary(claim.clone(), 10).unwrap();
        let bytes = write_boc(
            &sign_submission(&[0x44; 32], &claim, &account, &target, &auth(1, &module), 3).unwrap(),
        )
        .unwrap();
        let record = journal
            .attach_signed_boc(
                &claim,
                &base64::engine::general_purpose::STANDARD.encode(&bytes),
                &format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
                11,
            )
            .unwrap();
        (directory, journal, record, bytes)
    }

    #[test]
    fn the_relayer_is_the_named_profile_or_the_owner() {
        let owner = profile("owner-key", 1);
        let wallets = HashMap::from([("relay-a".to_owned(), profile("relay-a-key", 2))]);
        let master = profile("master-key", 3);
        let picked = |selection: RelayerSelection| (selection.label, selection.wallet.subwallet_id);
        assert_eq!(
            picked(resolve_relayer(None, &wallets, Some(&master), &owner).unwrap()),
            ("owner".to_owned(), 1)
        );
        assert_eq!(
            picked(resolve_relayer(Some("relay-a"), &wallets, Some(&master), &owner).unwrap()),
            ("relay-a".to_owned(), 2)
        );
        assert_eq!(
            picked(
                resolve_relayer(Some("master_wallet"), &wallets, Some(&master), &owner).unwrap()
            ),
            ("master_wallet".to_owned(), 3)
        );
        assert!(resolve_relayer(Some("unknown"), &wallets, Some(&master), &owner).is_err());
        assert!(resolve_relayer(Some(""), &wallets, Some(&master), &owner).is_err());
        assert!(resolve_relayer(Some("master_wallet"), &wallets, None, &owner).is_err());
    }

    #[test]
    fn the_relay_fee_bound_reads_the_outbound_tariff_of_both_endpoints() {
        use super::super::super::vote_cmd::reserve_price_params;
        // (gas, import, outbound): the sender's gas and import, the outbound
        // forwarding by both endpoints.
        assert_eq!(reserve_price_params(0, -1), (21, 25, 24));
        assert_eq!(reserve_price_params(-1, 0), (20, 24, 24));
        assert_eq!(reserve_price_params(-1, -1), (20, 24, 24));
        assert_eq!(reserve_price_params(0, 0), (21, 25, 25));
    }

    #[test]
    fn a_relayer_pays_the_relay_amount_and_its_own_fees() {
        relayer_can_pay("r", true, 1_050, 1_000, 50).unwrap();
        assert!(relayer_can_pay("r", true, 1_049, 1_000, 50).is_err(), "fees count");
        assert!(relayer_can_pay("r", true, 999, 1_000, 0).is_err(), "the amount counts");
        assert!(relayer_can_pay("r", false, u64::MAX, 1, 0).is_err(), "inactive");
        assert!(relayer_can_pay("r", true, u64::MAX, u64::MAX, u128::MAX).is_err(), "overflow");
    }

    #[derive(clap::Parser)]
    struct SendCli {
        #[command(flatten)]
        send: AgentAccountMldsa44SendCmd,
    }

    /// An `mldsa44-send` invocation as clap parses it, with `extra` arguments.
    fn send_command(extra: &[&str]) -> AgentAccountMldsa44SendCmd {
        use clap::Parser as _;
        let target = address(0, 0x30).to_string();
        let action_id = "a".repeat(64);
        let mut args = vec![
            "mldsa44-send",
            "-n",
            "agent",
            "--controller",
            "c1",
            "--target",
            target.as_str(),
            "--value",
            "1",
            "--valid-until",
            "1000",
            "--action-id",
            action_id.as_str(),
            "--relay-amount",
            "2",
        ];
        args.extend_from_slice(extra);
        SendCli::try_parse_from(args).unwrap().send
    }

    #[tokio::test]
    async fn a_send_and_its_rebroadcast_relay_the_journaled_bytes_from_the_chosen_wallets() {
        let (_directory, journal, record, bytes) = signed_record();
        let module = address(0, 0x20);
        let owner = profile("owner-key", 1);
        let wallets = HashMap::from([
            ("relay-a".to_owned(), profile("relay-a-key", 2)),
            ("relay-b".to_owned(), profile("relay-b-key", 7)),
        ]);
        let environment = CapturingEnvironment::new(10_000_000_000);
        let owner_wallet = environment
            .load_relayer(&resolve_relayer(None, &wallets, None, &owner).unwrap())
            .await
            .unwrap()
            .address;
        // What each profile's wallet is, independently of the command.
        let wallet_of = |name: &str| resolve_relayer(Some(name), &wallets, None, &owner).unwrap();
        let first_wallet = environment.load_relayer(&wallet_of("relay-a")).await.unwrap().address;
        // The selection is the command's own, from its parsed arguments.
        let first = send_command(&["--relayer", "relay-a"])
            .relayer_selection(&wallets, None, &owner)
            .unwrap();
        let defaulted = send_command(&[]).relayer_selection(&wallets, None, &owner).unwrap();
        assert_eq!(environment.load_relayer(&defaulted).await.unwrap().address, owner_wallet);
        let relayed = relay_submission(&environment, &journal, &record, &first, 2_000_000_000, 20)
            .await
            .unwrap();
        assert_eq!(relayed.relayer, first_wallet);
        let record = journal.action_by_idempotency_key(&record.claim.idempotency_key).unwrap();
        assert_eq!(record.status, ControllerActionStatus::Broadcasting);

        // The rebroadcast goes through another relayer.
        let second = send_command(&["--rebroadcast", "--relayer", "relay-b"])
            .relayer_selection(&wallets, None, &owner)
            .unwrap();
        let second_wallet = environment.load_relayer(&wallet_of("relay-b")).await.unwrap().address;
        assert_ne!(first_wallet, second_wallet);
        relay_submission(&environment, &journal, &record, &second, 3_000_000_000, 21)
            .await
            .unwrap();

        let sent = environment.sent();
        assert_eq!(sent.len(), 2);
        // Each relay's fee bound was computed for the module it sends to.
        assert_eq!(*environment.reserved_for.lock().unwrap(), vec![module.clone(), module.clone()]);
        for ((wallet, destination, message), expected) in
            sent.iter().zip([&first_wallet, &second_wallet])
        {
            assert_eq!(wallet, expected, "sent from the selected relayer");
            assert_ne!(wallet, &owner_wallet, "never from the owner unless chosen");
            assert_eq!(destination, &module);
            let (signed_by, body) = decode_relay(message, &module);
            assert_eq!(&signed_by, expected, "the selected relayer's wallet signed it");
            assert_eq!(body, bytes, "exactly the journaled submission");
        }
        assert_ne!(sent[0].2, sent[1].2, "two different wallet messages");
        let record = journal.action_by_idempotency_key(&record.claim.idempotency_key).unwrap();
        let journaled: Vec<_> =
            record.mldsa44_relays.iter().map(|attempt| attempt.relayer.clone()).collect();
        assert_eq!(journaled, vec![first_wallet.to_string(), second_wallet.to_string()]);
        for (attempt, (_, _, message)) in record.mldsa44_relays.iter().zip(&sent) {
            assert_eq!(
                attempt.wallet_message_digest,
                format!("sha256:{}", hex::encode(Sha256::digest(message)))
            );
        }
        assert_eq!(record.mldsa44_relays[1].relay_amount_atomic, 3_000_000_000);
    }

    #[tokio::test]
    async fn a_relayer_that_cannot_pay_sends_and_journals_nothing() {
        let (_directory, journal, record, _) = signed_record();
        let owner = profile("owner-key", 1);
        // Holds the amount but not its own fees on top.
        let environment = CapturingEnvironment::new(2_000_000_000);
        let relayer = resolve_relayer(None, &HashMap::new(), None, &owner).unwrap();
        assert!(
            relay_submission(&environment, &journal, &record, &relayer, 2_000_000_000, 20)
                .await
                .is_err()
        );
        assert!(environment.sent().is_empty());
        let record = journal.action_by_idempotency_key(&record.claim.idempotency_key).unwrap();
        assert_eq!(record.status, ControllerActionStatus::Signed, "nothing moved to broadcasting");
        assert!(record.mldsa44_relays.is_empty());
    }

    #[tokio::test]
    async fn a_relay_never_sends_bytes_other_than_the_journaled_ones() {
        let (_directory, journal, mut record, _) = signed_record();
        let owner = profile("owner-key", 1);
        let environment = CapturingEnvironment::new(10_000_000_000);
        let relayer = resolve_relayer(None, &HashMap::new(), None, &owner).unwrap();
        // Another valid submission of the same action, under its own digest,
        // is not the journaled one: the journal refuses to relay it.
        let account = address(0, 0x10);
        let target = address(0, 0x30);
        let module = address(0, 0x20);
        let other = write_boc(
            &sign_submission(&[0x44; 32], &record.claim, &account, &target, &auth(1, &module), 4)
                .unwrap(),
        )
        .unwrap();
        record.exact_signed_boc_base64 =
            Some(base64::engine::general_purpose::STANDARD.encode(&other));
        record.exact_signed_boc_digest =
            Some(format!("sha256:{}", hex::encode(Sha256::digest(&other))));
        assert!(
            relay_submission(&environment, &journal, &record, &relayer, 2_000_000_000, 20)
                .await
                .is_err()
        );
        assert!(environment.sent().is_empty());
    }

    #[test]
    fn the_fee_placeholder_has_the_signed_submission_size() {
        let account = address(0, 0x10);
        let target = address(0, 0x30);
        let module = address(0, 0x20);
        let claim = mldsa44_claim(
            &"a".repeat(64),
            &account,
            &target,
            &module,
            42,
            pin(),
            &data(),
            9,
            1_000,
        );
        let signed =
            sign_submission(&[0x44; 32], &claim, &account, &target, &auth(1, &module), 3).unwrap();
        let placeholder =
            placeholder_submission(&claim, &account, &target, &auth(1, &module)).unwrap();
        assert_eq!(
            contracts::wallet::send_fees::tree_size(&[&placeholder]).unwrap(),
            contracts::wallet::send_fees::tree_size(&[&signed]).unwrap()
        );
    }

    #[test]
    fn staging_is_refused_while_a_journaled_action_is_unresolved() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal =
            AgentAccountCustodyJournal::open(directory.path().canonicalize().unwrap()).unwrap();
        let account = address(0, 0x10);
        let text = account.to_string();
        let deployment = hex::encode(data().deployment_id);
        let claim = mldsa44_claim(
            &"a".repeat(64),
            &account,
            &address(0, 0x30),
            &address(0, 0x20),
            42,
            pin(),
            &data(),
            9,
            1_000,
        );
        journal.claim_primary(claim.clone(), 10).unwrap();
        // Install's fence is refused while the claimed action is unresolved.
        assert!(
            journal
                .begin_controller_epoch_change(
                    &text,
                    42,
                    &deployment,
                    2,
                    7,
                    4,
                    &[0x20; 32],
                    &"c".repeat(64)
                )
                .is_err()
        );
        // And a fence taken first keeps a later send from claiming the sequence.
        let other = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(other.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let fenced =
            AgentAccountCustodyJournal::open(other.path().canonicalize().unwrap()).unwrap();
        fenced
            .begin_controller_epoch_change(
                &text,
                42,
                &deployment,
                2,
                7,
                4,
                &[0x20; 32],
                &"c".repeat(64),
            )
            .unwrap();
        assert!(fenced.claim_primary(claim, 11).is_err());
    }
}
