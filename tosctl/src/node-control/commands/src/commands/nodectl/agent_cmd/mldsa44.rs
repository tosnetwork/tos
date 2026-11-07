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
//! Outcomes of a relayed submission, as each command reports them:
//! - module compute failure (bad signature, too little funding): nothing is
//!   forwarded; the bounceable relay message returns its remainder;
//! - module action failure (verified, forward failed): the value stays in the
//!   immutable module; nothing reaches the account;
//! - account abort (stale nonce, consumed seqno, expiry): the forwarded value
//!   bounces to the module, which ignores bounces, so it stays there;
//! - committed account refusal: the seqno and auth nonce are consumed and no
//!   value moves (resolved as `committed-refusal`);
//! - success: exactly the signed transfer (resolved as `transferred`).

use super::super::native_registry_cmd::read_controller_seed;
use super::*;
use contracts::agent_account_auth::{
    AUTH_KIND_EXECUTE, AUTH_MODE_MODULE_ONLY, AUTH_MODE_STAGED, AgentAuthState, AuthRequest,
    Mldsa44AuthConfig, Mldsa44AuthModule, build_auth_envelope, build_mldsa44_submit,
    build_stage_auth_message, check_auth_window, parse_mldsa44_submit, require_staged_module,
    sign_auth_request,
};
use contracts::agent_account_custody::MLDSA44_NATIVE_SEND_ACTION_KIND;
use contracts::native_registry::native_public_key_from_seed;

const MLDSA44_FINALIZED_SCHEMA: &str = "tos.agent-account.mldsa44-native-send-finalized.v1";
const MLDSA44_EXPIRED_SCHEMA: &str = "tos.agent-account.mldsa44-native-send-expired.v1";

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
        help = "TOS the owner wallet attaches for the module's verification, the 2,420-byte forwarding and the account's execution; value left after an account refusal stays in the module"
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
        if decision == StageDecision::AlreadyStaged {
            println!("{} module already staged on {}", "OK".green().bold(), ctx.account);
            return Ok(());
        }
        // Staging advances the controller epoch: refuse while any journaled
        // action of this account would be stranded by it.
        let journal = open_controller_journal(Path::new(config_path))?;
        let deployment_id = hex::encode(ctx.data.deployment_id);
        journal.reconcile_finalized_state(
            &ctx.account.to_string(),
            ctx.global_id,
            &deployment_id,
            ctx.data.controller_epoch,
            ctx.data.seqno,
            time_format::now(),
        )?;
        require_no_unresolved_actions(&journal, &ctx.account, ctx.global_id, &deployment_id)?;
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
        .context("the Agent Account did not reach the staged state")?;
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
            (_, ControllerActionStatus::Resolved) => {
                anyhow::bail!("this ML-DSA-44 action is already resolved; nothing to send")
            }
            (Some(_), ControllerActionStatus::Broadcasting) if !self.rebroadcast => anyhow::bail!(
                "this ML-DSA-44 action was already broadcast; resolve it with mldsa44-resolve, or pass --rebroadcast to relay the same submission again"
            ),
            (Some(existing), status) => {
                if !self.yes
                    && !confirm(&format!(
                        "Relay the journaled ML-DSA-44 submission {} (seqno {}, valid_until {}) again from the owner wallet?",
                        self.action_id, claim.seqno, claim.valid_until
                    ))?
                {
                    println!("{}", "ML-DSA-44 send cancelled".yellow());
                    return Ok(());
                }
                (existing, status)
            }
            (None, ControllerActionStatus::Claimed) => {
                // Only a fresh signature checks the window: journaled bytes
                // are relayed as they are and the chain judges their expiry.
                check_auth_window(
                    self.valid_until,
                    ctx.chain_now,
                    ctx.data.default_task_timeout_secs,
                )?;
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
                    println!("{}", "ML-DSA-44 send cancelled".yellow());
                    return Ok(());
                }
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
            (None, status) => {
                anyhow::bail!("custody record in state {status:?} has no exact submission")
            }
        };
        let submission_bytes = base64::engine::general_purpose::STANDARD.decode(&boc_base64)?;
        let submission_digest =
            format!("sha256:{}", hex::encode(Sha256::digest(&submission_bytes)));
        let submission = read_single_root_boc(&submission_bytes)?;
        // The journaled bytes are re-read, never rebuilt.
        parse_mldsa44_submit(&submission)?;
        if status == ControllerActionStatus::Signed {
            journal.begin_broadcast(&claim, time_format::now())?;
        }
        let wallet = make_wallet(
            ctx.rpc_client.clone(),
            &ctx.agent_wallet.wallet,
            owner_secret,
            &self.wallet,
        )
        .await?;
        let boc = build_wallet_message_boc(
            &wallet,
            ctx.module.clone(),
            tos_to_nanotos(self.relay_amount),
            submission,
            true,
            owner_info.seqno,
        )
        .await?;
        confirm_prepared_wallet_message(
            ctx.rpc_client.clone(),
            &boc,
            &owner_address,
            &ctx.module,
            DEPLOY_TIMEOUT,
        )
        .await?;
        println!(
            "{}",
            serde_json::json!({
                "schema": "tosctl.agent-account.mldsa44-send.v1",
                "action_id": self.action_id,
                "account": ctx.account.to_string(),
                "module": ctx.module.to_string(),
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
    // The executor marks the compute phase successful when the contract
    // committed its state, including a refusal thrown after commit().
    let committed =
        matches!(&description.compute_ph, chain_block::TrComputePhase::Vm(vm) if vm.success);
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
}

impl Mldsa44Observation {
    fn quorum_key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.outcome,
            self.transaction.as_ref().map(|t| t.quorum_key()).unwrap_or_default(),
            self.finalized_controller_epoch,
            self.finalized_seqno
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
    let provider = contracts::contract_provider!(rpc_client.clone());
    let data = AgentAccountContract::get_data(provider.as_ref(), account).await?;
    let now = chain_now(&rpc_client).await?;

    let info = rpc_client.get_address_information(account).await?;
    let mut cursor_lt = info.last_transaction_id.lt;
    let mut cursor_hash =
        base64::engine::general_purpose::STANDARD.encode(&info.last_transaction_id.hash);
    let mut inspected = 0u32;
    let mut aborted = 0u32;
    let mut committed = Vec::new();
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

/// Refuses an operation that advances the controller epoch while journaled
/// actions of the account would be stranded by it.
fn require_no_unresolved_actions(
    journal: &AgentAccountCustodyJournal,
    account: &MsgAddressInt,
    global_id: i32,
    deployment_id: &str,
) -> anyhow::Result<()> {
    let unresolved = journal.unresolved_count(&account.to_string(), global_id, deployment_id)?;
    anyhow::ensure!(
        unresolved == 0,
        "{unresolved} custody action(s) of this Agent Account are unresolved; resolve them before staging, which advances the controller epoch"
    );
    Ok(())
}

/// How a strict-majority observation terminalizes the record, if it can.
#[derive(Debug, PartialEq, Eq)]
enum Mldsa44Resolution {
    /// The exact action consumed the sequence (with or without the transfer).
    Winner,
    /// Expired with the sequence still unconsumed: it can never execute.
    Expired,
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
        "not-committed" => {
            anyhow::ensure!(
                observation.chain_now > claim.valid_until,
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
                            "state": observation.outcome,
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
        }
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
        let deployment = hex::encode(data().deployment_id);
        require_no_unresolved_actions(&journal, &account, 42, &deployment).unwrap();
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
        journal.claim_primary(claim, 10).unwrap();
        assert!(require_no_unresolved_actions(&journal, &account, 42, &deployment).is_err());
    }
}
