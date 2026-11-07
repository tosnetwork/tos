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
//! The relay value pays the module's verification of the 2,420-byte signature
//! it receives, the forwarding of the AUTH envelope (the module does not
//! forward the signature) and the account's execution. Outcomes of a relayed
//! submission, as each command reports them:
//! - module compute failure (bad signature, too little funding): nothing is
//!   forwarded; the bounceable relay message returns its remainder;
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
    AuthRequest, Mldsa44AuthConfig, Mldsa44AuthModule, build_auth_envelope, build_mldsa44_submit,
    build_stage_auth_message, check_auth_window, parse_mldsa44_submit, request_superseded,
    require_staged_module, sign_auth_request,
};
use contracts::agent_account_custody::MLDSA44_NATIVE_SEND_ACTION_KIND;
use contracts::native_registry::native_public_key_from_seed;

const MLDSA44_FINALIZED_SCHEMA: &str = "tos.agent-account.mldsa44-native-send-finalized.v1";
const MLDSA44_EXPIRED_SCHEMA: &str = "tos.agent-account.mldsa44-native-send-expired.v1";
const MLDSA44_SUPERSEDED_SCHEMA: &str = "tos.agent-account.mldsa44-native-send-superseded.v1";

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
    about = "Sign one native transfer with the ML-DSA-44 controller, journal it, and relay it through the staged module from the owner wallet; resolve it with mldsa44-resolve"
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
        help = "TOS the owner wallet attaches: it pays the module's verification of the 2,420-byte signature, the forwarding of the envelope and the account's execution; after an account abort the remainder stays in the module, after a committed refusal in the Agent Account"
    )]
    relay_amount: f64,
    #[arg(
        long,
        help = "Relay the journaled submission again although it was already broadcast; it can never pay twice, the account refuses a consumed nonce"
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
    Ok(Mldsa44Context {
        rpc_client,
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
    let payload = AgentAccountContract::build_native_send_payload(
        claim.network_global_id,
        claim.controller_epoch,
        claim.seqno,
        claim.valid_until,
        target,
        claim.value_atomic,
    )?;
    let request = AuthRequest {
        global_id: claim.network_global_id,
        account: account.clone(),
        epoch: auth.epoch,
        nonce: auth.nonce,
        valid_until: claim.valid_until,
        kind: AUTH_KIND_EXECUTE,
        payload,
    }
    .to_cell()?;
    let signature = sign_auth_request(seed, &request)?;
    build_mldsa44_submit(query_id, &build_auth_envelope(&request)?, &signature)
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
        let mut interrupted =
            journal.controller_epoch_change(&account_text, ctx.global_id, &deployment_id)?;
        if let Some(start) = interrupted
            && self.recover_interrupted
        {
            // The operator states the fenced stage was never sent or can no
            // longer be accepted. Handled before any other decision, so a
            // fence stays recoverable whichever module is staged now and
            // after an owner rotation moved the counters (the journal still
            // refuses counters older than the fence's start).
            journal.end_controller_epoch_change(
                &account_text,
                ctx.global_id,
                &deployment_id,
                ctx.data.controller_epoch,
                ctx.data.seqno,
                None,
            )?;
            println!(
                "{} lifted the fence of an interrupted install started at controller epoch {}, seqno {}",
                "NOTE".yellow().bold(),
                start.0,
                start.1
            );
            interrupted = None;
        }
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
        anyhow::ensure!(
            value <= ctx.data.max_per_tx,
            "value {} exceeds Agent Account max_per_tx {}",
            display_tos(value),
            display_tos(ctx.data.max_per_tx)
        );
        require_staged_module(&ctx.auth, &ctx.account, &ctx.module)?;
        verify_module(&ctx).await?;
        let (owner_address, owner_info, owner_secret) =
            wallet_info(ctx.rpc_client.clone(), &ctx.agent_wallet.wallet, ctx.vault.clone())
                .await?;
        anyhow::ensure!(
            owner_info.account_state == AccountState::Active,
            "the relaying owner wallet is not active"
        );
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
        // An action signed before is recovered from the journal before any
        // admission check: its counters may since have been consumed by this
        // very submission, and it is never signed again.
        if let Some(record) = journal.find_action_by_idempotency_key(&self.action_id)? {
            require_same_terms(
                &record.claim,
                &ctx.account,
                &target,
                &ctx.module,
                value,
                self.valid_until,
                &network_domain,
            )?;
            if record.status == ControllerActionStatus::Resolved {
                anyhow::bail!("this ML-DSA-44 action is already resolved; nothing to send");
            }
            if let Some(existing) = record.exact_signed_boc_base64.clone() {
                if record.status == ControllerActionStatus::Broadcasting && !self.rebroadcast {
                    anyhow::bail!(
                        "this ML-DSA-44 action was already broadcast; resolve it with mldsa44-resolve, or pass --rebroadcast to relay the same submission again"
                    );
                }
                if !self.yes
                    && !confirm(&format!(
                        "Relay the journaled ML-DSA-44 submission {} (seqno {}, valid_until {}) from the owner wallet?",
                        self.action_id, record.claim.seqno, record.claim.valid_until
                    ))?
                {
                    println!("{}", "ML-DSA-44 send cancelled".yellow());
                    return Ok(());
                }
                return relay_submission(
                    &ctx,
                    &journal,
                    &record.claim,
                    &existing,
                    record.status,
                    self.relay_amount,
                    &self.wallet,
                    owner_address,
                    owner_info.seqno,
                    owner_secret,
                    &self.action_id,
                )
                .await;
            }
        }
        // An unsigned claim left by an interrupted run can never execute: it
        // is released, not kept, when it can no longer be signed as claimed.
        let unsigned = journal
            .find_action_by_idempotency_key(&self.action_id)?
            .filter(|record| record.status == ControllerActionStatus::Claimed);
        if let Some(record) = &unsigned {
            let stale = (record.claim.controller_epoch, record.claim.seqno)
                != (ctx.data.controller_epoch, ctx.data.seqno);
            let expired = check_auth_window(
                self.valid_until,
                ctx.chain_now,
                ctx.data.default_task_timeout_secs,
            )
            .is_err();
            if stale || expired {
                journal.release_unsigned_mldsa44_claim(
                    &record.claim,
                    if stale { "counters moved before signing" } else { "expired before signing" },
                    time_format::now(),
                )?;
                anyhow::bail!(
                    "the unsigned claim of this action ID was released ({}); send again with a new action ID",
                    if stale { "the controller sequence moved" } else { "its window closed" }
                );
            }
        }
        // Every check and the confirmation come before anything is claimed:
        // a refused or declined request leaves no reservation behind.
        require_staged_module(&ctx.auth, &ctx.account, &ctx.module)?;
        check_auth_window(self.valid_until, ctx.chain_now, ctx.data.default_task_timeout_secs)?;
        if !self.yes
            && !confirm(&format!(
                "Authorize {} from {} to {} with ML-DSA-44 controller '{}', seqno {}, valid_until {}?",
                display_tos(value),
                ctx.account,
                target,
                self.controller,
                ctx.data.seqno,
                self.valid_until
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
        let (record, _) = journal.claim_primary(claim.clone(), time_format::now())?;
        let (boc_base64, status) = match (record.exact_signed_boc_base64.clone(), record.status) {
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
                journal.attach_signed_boc(&claim, &encoded, &digest, time_format::now())?;
                (encoded, ControllerActionStatus::Signed)
            }
            (_, status) => {
                // claim_primary returned a record this run did not sign; it
                // was created concurrently. Leave it to its own invocation.
                anyhow::bail!("custody record in state {status:?} was not created by this run")
            }
        };
        relay_submission(
            &ctx,
            &journal,
            &claim,
            &boc_base64,
            status,
            self.relay_amount,
            &self.wallet,
            owner_address,
            owner_info.seqno,
            owner_secret,
            &self.action_id,
        )
        .await
    }
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

/// Relays the exact journaled submission from the owner wallet: Signed moves
/// to Broadcasting first, so an interrupted run is never mistaken for an
/// unsent one.
#[allow(clippy::too_many_arguments)]
async fn relay_submission(
    ctx: &Mldsa44Context,
    journal: &AgentAccountCustodyJournal,
    claim: &ControllerActionClaim,
    boc_base64: &str,
    status: ControllerActionStatus,
    relay_amount: f64,
    wallet_name: &str,
    owner_address: MsgAddressInt,
    owner_seqno: Option<u32>,
    owner_secret: Secret,
    action_id: &str,
) -> anyhow::Result<()> {
    let submission_bytes = base64::engine::general_purpose::STANDARD.decode(boc_base64)?;
    let submission_digest = format!("sha256:{}", hex::encode(Sha256::digest(&submission_bytes)));
    let submission = read_single_root_boc(&submission_bytes)?;
    // The journaled bytes are re-read, never rebuilt.
    parse_mldsa44_submit(&submission)?;
    if status == ControllerActionStatus::Signed {
        journal.begin_broadcast(claim, time_format::now())?;
    }
    let module = claim
        .auth_module
        .as_ref()
        .context("ML-DSA-44 claim has no pinned module")?
        .parse::<MsgAddressInt>()?;
    let wallet =
        make_wallet(ctx.rpc_client.clone(), &ctx.agent_wallet.wallet, owner_secret, wallet_name)
            .await?;
    let boc = build_wallet_message_boc(
        &wallet,
        module.clone(),
        tos_to_nanotos(relay_amount),
        submission,
        true,
        owner_seqno,
    )
    .await?;
    confirm_prepared_wallet_message(
        ctx.rpc_client.clone(),
        &boc,
        &owner_address,
        &module,
        DEPLOY_TIMEOUT,
    )
    .await?;
    println!(
        "{}",
        serde_json::json!({
            "schema": "tosctl.agent-account.mldsa44-send.v1",
            "action_id": action_id,
            "account": claim.account,
            "module": module.to_string(),
            "controller_epoch": claim.controller_epoch,
            "seqno": claim.seqno,
            "valid_until": claim.valid_until,
            "exact_submission_digest": submission_digest,
            "state": "broadcasting",
            "next": "tosctl agent account mldsa44-resolve --action-id <id> --quorum-config <a> <b>",
        })
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
