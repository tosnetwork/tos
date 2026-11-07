/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

//! `mldsa44-cutover` and `mldsa44-rotate`: the gated, irreversible strict
//! reconfigurations of the Agent Account's ML-DSA-44 root. The orchestration
//! and every gate are `contracts::agent_account_reconfigure`; this module
//! reaches the chain, the vault and the relaying wallet for it.

use super::*;
use contracts::agent_account_auth::sign_auth_request;
use contracts::agent_account_reconfigure::{
    AccountSnapshot, ModuleView, PreparedRelay, Reconfiguration, ReconfigureChain,
    ReconfigureOutcome, ReconfigureRequest, reconfigure,
};

const RECONFIGURE_SCHEMA: &str = "tosctl.agent-account.mldsa44-reconfigure.v1";
/// Landing observations, two seconds apart.
const LANDING_POLLS: u32 = 90;

#[derive(clap::Args, Clone)]
struct StrictArgs {
    #[arg(short = 'n', long = "wallet", help = "Agent Wallet profile name")]
    wallet: String,
    #[arg(long, help = "ML-DSA-44 controller name of the account's current root")]
    controller: String,
    #[arg(
        long,
        help = "Target authentication mode; only 2 (ML-DSA-44 only) is accepted, and the change is irreversible"
    )]
    mode: u8,
    #[arg(
        long,
        help = "The Agent Account address, typed exactly as tosctl prints it, to confirm the irreversible change"
    )]
    confirm_account: String,
    #[arg(
        long,
        help = "Unix time after which the request is invalid; at most 3600 s after the account state time"
    )]
    valid_until: u32,
    #[arg(long, help = "TOS the relaying wallet attaches to the module message")]
    relay_amount: f64,
    #[arg(
        long,
        help = "Wallet profile (or master_wallet) that relays and pays; default: the Agent Wallet's owner wallet"
    )]
    relayer: Option<String>,
    #[arg(
        long,
        help = "Settle an earlier interrupted change first: finished if it landed, lifted only once the account state is past its expiry"
    )]
    recover_interrupted: bool,
    #[arg(
        long,
        help = "Skip the final yes/no prompt; the typed --confirm-account is still required"
    )]
    yes: bool,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "IRREVERSIBLE: switch a staged Agent Account to ML-DSA-44-only mode 2 with its staged module; the owner and the Ed25519 controller lose every authority. Never a default"
)]
pub struct AgentAccountMldsa44CutoverCmd {
    #[command(flatten)]
    args: StrictArgs,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "IRREVERSIBLE: in strict mode 2, replace the account's ML-DSA-44 root with another controller's module, authorized by the current root. Never a default"
)]
pub struct AgentAccountMldsa44RotateCmd {
    #[command(flatten)]
    args: StrictArgs,
    #[arg(long, help = "ML-DSA-44 controller name of the new root")]
    new_controller: String,
    #[arg(long, help = "TOS sent with the new module's StateInit if it is not deployed yet")]
    deploy_amount: f64,
}

/// The chain, the vault seed of the current root and the relaying wallet.
struct CliReconfigureChain<'a> {
    ctx: &'a Mldsa44Context,
    relayer: RelayerSelection,
    environment: ChainRelayEnvironment,
}

impl ReconfigureChain for CliReconfigureChain<'_> {
    async fn account(&self, account: &MsgAddressInt) -> anyhow::Result<AccountSnapshot> {
        let (state, state_time) = account_snapshot(&self.ctx.rpc_client, account).await?;
        let provider = contracts::contract_provider!(self.ctx.rpc_client.clone());
        let data = AgentAccountContract::get_data(provider.as_ref(), account).await?;
        Ok(AccountSnapshot {
            state,
            state_time,
            default_task_timeout_secs: data.default_task_timeout_secs,
        })
    }

    async fn module(&self, module: &MsgAddressInt) -> anyhow::Result<ModuleView> {
        let info = self.ctx.rpc_client.get_address_information(module).await?;
        let active = info.state == AccountState::Active;
        let code_hash = info
            .code
            .as_ref()
            .map(|code| read_single_root_boc(code).map(|cell| cell.repr_hash()))
            .transpose()?;
        let config = if active {
            let provider = contracts::contract_provider!(self.ctx.rpc_client.clone());
            Some(Mldsa44AuthModule::get_config(provider.as_ref(), module).await?)
        } else {
            None
        };
        Ok(ModuleView { active, code_hash, config })
    }

    async fn check_relayer(
        &self,
        module: &MsgAddressInt,
        body: &Cell,
        amount: u64,
    ) -> anyhow::Result<MsgAddressInt> {
        check_relayer(&self.environment, &self.relayer, module, body, amount).await
    }

    async fn sign(&self, request: &Cell) -> anyhow::Result<Vec<u8>> {
        sign_auth_request(&self.ctx.seed, request)
    }

    async fn prepare_relay(
        &self,
        module: &MsgAddressInt,
        amount: u64,
        body: Cell,
    ) -> anyhow::Result<PreparedRelay> {
        let loaded = self.environment.load_relayer(&self.relayer).await?;
        let (reserve, balance) =
            self.environment.wallet_reserve(&loaded.address, module, &body).await?;
        relayer_can_pay(&self.relayer.label, loaded.active, balance, amount, reserve)?;
        let wallet_message = build_mldsa44_relay_wallet_message(
            loaded.wallet.as_ref(),
            module,
            amount,
            body,
            loaded.seqno,
        )
        .await?;
        Ok(PreparedRelay { relayer: loaded.address, wallet_message })
    }

    async fn broadcast(&self, relay: &PreparedRelay, module: &MsgAddressInt) -> anyhow::Result<()> {
        self.environment.broadcast(&relay.wallet_message, &relay.relayer, module).await
    }

    async fn pause(&self, attempt: u32) -> bool {
        if attempt > LANDING_POLLS {
            return false;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        true
    }
}

fn owner_token() -> String {
    let mut token = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);
    hex::encode(token)
}

/// Runs one gated reconfiguration and prints its result.
async fn run_strict(
    args: &StrictArgs,
    config_path: &str,
    // A rotation names the new root's controller and the module deploy amount.
    rotate_to: Option<(&str, f64)>,
) -> anyhow::Result<()> {
    validate_tos_amount("relay-amount", args.relay_amount)?;
    anyhow::ensure!(args.relay_amount > 0.0, "relay-amount must be greater than zero");
    let ctx = load_context(config_path, &args.wallet, &args.controller).await?;
    let relayer = resolve_relayer(
        args.relayer.as_deref(),
        &ctx.wallets,
        ctx.master_wallet.as_ref(),
        &ctx.agent_wallet.wallet,
    )?;
    let environment =
        ChainRelayEnvironment { rpc_client: ctx.rpc_client.clone(), vault: ctx.vault.clone() };
    // The new root's key is read through the vault this run already holds open.
    let change = match rotate_to {
        None => Reconfiguration::Cutover,
        Some((new_controller, _)) => {
            let seed = read_controller_seed(&ctx.vault, new_controller).await?;
            let public_key = native_public_key_from_seed(&seed);
            let module = Mldsa44AuthModule::calculate_address(
                ctx.account.workchain_id(),
                ctx.global_id,
                &public_key,
            )?;
            Reconfiguration::Rotate { module, public_key }
        }
    };
    let deploy_amount = rotate_to.map(|(_, amount)| amount);
    let request = ReconfigureRequest {
        change: change.clone(),
        mode: args.mode,
        confirm_account: args.confirm_account.clone(),
        account: ctx.account.clone(),
        global_id: ctx.global_id,
        module: ctx.module.clone(),
        public_key: ctx.public_key.clone(),
        valid_until: args.valid_until,
        relay_amount: tos_to_nanotos(args.relay_amount),
        recover_interrupted: args.recover_interrupted,
        query_id: (time_format::now() << 32) | u64::from(ctx.snapshot.seqno),
        owner_token: owner_token(),
    };
    // A held fence is settled by the orchestration first (an interrupted
    // change that landed is finished, not refused as already strict), so the
    // state gates wait for it; the orchestration runs every gate again
    // against the snapshot it fences from.
    let journal = open_controller_journal(Path::new(config_path))?;
    let fenced = journal
        .controller_epoch_change(
            &ctx.account.to_string(),
            ctx.global_id,
            &hex::encode(ctx.snapshot.deployment_id),
        )?
        .is_some();
    let snapshot = AccountSnapshot {
        state: ctx.snapshot,
        state_time: ctx.state_time,
        default_task_timeout_secs: ctx.data.default_task_timeout_secs,
    };
    let target = match &change {
        Reconfiguration::Cutover => ctx.module.clone(),
        Reconfiguration::Rotate { module, .. } => module.clone(),
    };
    let summary = format!(
        "IRREVERSIBLE: set {} to ML-DSA-44-only mode 2 with root {} (current auth mode {}, epoch {}, nonce {}), relayed by wallet '{}'?",
        ctx.account,
        target,
        ctx.snapshot.auth.mode,
        ctx.snapshot.auth.epoch,
        ctx.snapshot.auth.nonce,
        relayer.label
    );
    let steps = CliStrictSteps { ctx: &ctx, environment: &environment, relayer: &relayer };
    let proceed = gate_confirm_deploy(
        &steps,
        &request,
        (!fenced).then_some(&snapshot),
        args.yes,
        deploy_amount,
        &summary,
        &relayer.label,
    )
    .await?;
    if !proceed {
        println!("{}", "Reconfiguration cancelled".yellow());
        return Ok(());
    }
    let chain = CliReconfigureChain { ctx: &ctx, relayer, environment };
    let outcome = reconfigure(&chain, &journal, &request).await?;
    let output = match outcome {
        ReconfigureOutcome::Landed {
            before,
            after,
            relayer,
            submission_digest,
            wallet_message_digest,
        } => serde_json::json!({
            "schema": RECONFIGURE_SCHEMA,
            "state": "landed",
            "account": ctx.account.to_string(),
            "root": target.to_string(),
            "relayer": relayer.to_string(),
            "exact_submission_digest": submission_digest,
            "wallet_message_digest": wallet_message_digest,
            "before": auth_json(&before),
            "after": auth_json(&after),
        }),
        ReconfigureOutcome::EarlierLanded { after } => serde_json::json!({
            "schema": RECONFIGURE_SCHEMA,
            "state": "earlier-landed",
            "account": ctx.account.to_string(),
            "root": target.to_string(),
            "after": auth_json(&after),
        }),
    };
    println!("{output}");
    Ok(())
}

fn auth_json(state: &AgentAccountState) -> serde_json::Value {
    serde_json::json!({
        "auth_mode": state.auth.mode,
        "auth_epoch": state.auth.epoch,
        "auth_nonce": state.auth.nonce,
        "auth_module_hash": hex::encode(state.auth.module_hash),
        "controller_epoch": state.controller_epoch,
        "seqno": state.seqno,
    })
}

/// What the steps before a reconfiguration need from the operator and the chain.
#[allow(async_fn_in_trait)]
trait StrictSteps {
    fn confirm(&self, question: &str) -> anyhow::Result<bool>;
    async fn module_active(&self, module: &MsgAddressInt) -> anyhow::Result<bool>;
    /// Deploys the new root's module from the relaying wallet and waits for it.
    async fn deploy(
        &self,
        module: &MsgAddressInt,
        public_key: &[u8],
        deploy_amount: f64,
    ) -> anyhow::Result<()>;
}

/// Everything that precedes the reconfiguration, in the only safe order: the
/// gates, then the operator's confirmation, then (a rotation to an undeployed
/// module only) a separate confirmation of the deployment and the deployment
/// itself. No value moves before every gate and confirmation has passed.
/// Returns whether to proceed; `false` when the operator declines.
async fn gate_confirm_deploy<S: StrictSteps>(
    steps: &S,
    request: &ReconfigureRequest,
    snapshot: Option<&AccountSnapshot>,
    yes: bool,
    deploy_amount: Option<f64>,
    summary: &str,
    relayer_label: &str,
) -> anyhow::Result<bool> {
    contracts::agent_account_reconfigure::check_request(request)?;
    if let Some(snapshot) = snapshot {
        contracts::agent_account_reconfigure::check_state(request, snapshot)?;
    }
    if !yes && !steps.confirm(summary)? {
        return Ok(false);
    }
    if let Reconfiguration::Rotate { module, public_key } = &request.change
        && !steps.module_active(module).await?
    {
        let amount = deploy_amount.context("a rotation names --deploy-amount")?;
        validate_tos_amount("deploy-amount", amount)?;
        anyhow::ensure!(amount > 0.0, "deploy-amount must be greater than zero");
        if !yes
            && !steps.confirm(&format!(
                "Deploy the new root's ML-DSA-44 module {module} with {amount} TOS from wallet '{relayer_label}'?"
            ))?
        {
            return Ok(false);
        }
        steps.deploy(module, public_key, amount).await?;
    }
    Ok(true)
}

struct CliStrictSteps<'a> {
    ctx: &'a Mldsa44Context,
    environment: &'a ChainRelayEnvironment,
    relayer: &'a RelayerSelection,
}

impl StrictSteps for CliStrictSteps<'_> {
    fn confirm(&self, question: &str) -> anyhow::Result<bool> {
        confirm(question)
    }

    async fn module_active(&self, module: &MsgAddressInt) -> anyhow::Result<bool> {
        Ok(self.ctx.rpc_client.get_address_information(module).await?.state == AccountState::Active)
    }

    /// Deploying an immutable module grants nothing; the reconfiguration
    /// then verifies its code, network and key before anything is signed.
    async fn deploy(
        &self,
        module: &MsgAddressInt,
        public_key: &[u8],
        deploy_amount: f64,
    ) -> anyhow::Result<()> {
        let loaded = self.environment.load_relayer(self.relayer).await?;
        anyhow::ensure!(
            loaded.active,
            "the relaying wallet '{}' is not active",
            self.relayer.label
        );
        send_wallet_message_with_state_init(
            loaded.wallet.as_ref(),
            self.ctx.rpc_client.clone(),
            module.clone(),
            tos_to_nanotos(deploy_amount),
            Cell::default(),
            loaded.seqno,
            &loaded.address,
            Mldsa44AuthModule::build_state_init(self.ctx.global_id, public_key)?,
        )
        .await
        .context("deploy the new root's ML-DSA-44 module")?;
        wait_until(DEPLOY_TIMEOUT, || async {
            Ok(self.ctx.rpc_client.get_address_information(module).await?.state
                == AccountState::Active)
        })
        .await
        .context("the new ML-DSA-44 module did not become active")
    }
}

impl AgentAccountMldsa44CutoverCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        run_strict(&self.args, config_path, None).await
    }
}

impl AgentAccountMldsa44RotateCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        run_strict(&self.args, config_path, Some((&self.new_controller, self.deploy_amount))).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contracts::agent_account_auth::{AUTH_MODE_MODULE_ONLY, AUTH_MODE_STAGED, AgentAuthState};
    use std::cell::RefCell;

    fn address(byte: u8) -> MsgAddressInt {
        MsgAddressInt::with_standart(None, 0, [byte; 32].into()).unwrap()
    }

    /// Answers prompts from a script and records every step in order.
    struct Recorder {
        answers: RefCell<Vec<bool>>,
        deployed: bool,
        steps: RefCell<Vec<String>>,
    }

    impl Recorder {
        fn new(answers: &[bool], deployed: bool) -> Self {
            Self {
                answers: RefCell::new(answers.iter().rev().copied().collect()),
                deployed,
                steps: RefCell::new(Vec::new()),
            }
        }

        fn steps(&self) -> Vec<String> {
            self.steps.borrow().clone()
        }
    }

    impl StrictSteps for Recorder {
        fn confirm(&self, question: &str) -> anyhow::Result<bool> {
            let kind = if question.starts_with("Deploy") { "deploy-prompt" } else { "prompt" };
            self.steps.borrow_mut().push(kind.to_owned());
            self.answers.borrow_mut().pop().context("an unexpected prompt")
        }

        async fn module_active(&self, _module: &MsgAddressInt) -> anyhow::Result<bool> {
            Ok(self.deployed)
        }

        async fn deploy(
            &self,
            _module: &MsgAddressInt,
            _public_key: &[u8],
            _deploy_amount: f64,
        ) -> anyhow::Result<()> {
            self.steps.borrow_mut().push("deploy".to_owned());
            Ok(())
        }
    }

    fn request(change: Reconfiguration) -> ReconfigureRequest {
        ReconfigureRequest {
            change,
            mode: AUTH_MODE_MODULE_ONLY,
            confirm_account: address(0x10).to_string(),
            account: address(0x10),
            global_id: 42,
            module: address(0x20),
            public_key: vec![1; 1312],
            valid_until: 1_600,
            relay_amount: 2_000_000_000,
            recover_interrupted: false,
            query_id: 1,
            owner_token: "a".repeat(64),
        }
    }

    fn rotation() -> ReconfigureRequest {
        request(Reconfiguration::Rotate { module: address(0x21), public_key: vec![2; 1312] })
    }

    fn snapshot(mode: u8) -> AccountSnapshot {
        AccountSnapshot {
            state: AgentAccountState {
                deployment_id: [3; 32],
                controller_epoch: 2,
                seqno: 5,
                auth: AgentAuthState { mode, epoch: 4, nonce: 1, module_hash: [0x20; 32] },
            },
            state_time: 1_000,
            default_task_timeout_secs: 3_600,
        }
    }

    async fn run(
        recorder: &Recorder,
        request: &ReconfigureRequest,
        mode: u8,
        yes: bool,
    ) -> anyhow::Result<bool> {
        gate_confirm_deploy(recorder, request, Some(&snapshot(mode)), yes, Some(1.0), "?", "r1")
            .await
    }

    #[tokio::test]
    async fn no_value_moves_before_every_gate_and_confirmation() {
        let strict = AUTH_MODE_MODULE_ONLY;
        // Declining the irreversible prompt: no deploy prompt, no deploy.
        let r = Recorder::new(&[false], false);
        assert!(!run(&r, &rotation(), strict, false).await.unwrap());
        assert_eq!(r.steps(), vec!["prompt"]);
        // Accepting it but declining the deployment: no deploy.
        let r = Recorder::new(&[true, false], false);
        assert!(!run(&r, &rotation(), strict, false).await.unwrap());
        assert_eq!(r.steps(), vec!["prompt", "deploy-prompt"]);
        // Both accepted: one deploy, after both prompts.
        let r = Recorder::new(&[true, true], false);
        assert!(run(&r, &rotation(), strict, false).await.unwrap());
        assert_eq!(r.steps(), vec!["prompt", "deploy-prompt", "deploy"]);
        // --yes: no prompt, one deploy.
        let r = Recorder::new(&[], false);
        assert!(run(&r, &rotation(), strict, true).await.unwrap());
        assert_eq!(r.steps(), vec!["deploy"]);
        // An already deployed module: no deploy prompt and no deploy.
        let r = Recorder::new(&[true], true);
        assert!(run(&r, &rotation(), strict, false).await.unwrap());
        assert_eq!(r.steps(), vec!["prompt"]);
        // A cutover never deploys.
        let r = Recorder::new(&[true], false);
        assert!(
            run(&r, &request(Reconfiguration::Cutover), AUTH_MODE_STAGED, false).await.unwrap()
        );
        assert_eq!(r.steps(), vec!["prompt"]);
    }

    #[tokio::test]
    async fn a_refused_gate_asks_nothing_and_deploys_nothing() {
        let strict = AUTH_MODE_MODULE_ONLY;
        let mistyped =
            ReconfigureRequest { confirm_account: address(0x11).to_string(), ..rotation() };
        let hybrid = ReconfigureRequest { mode: 3, ..rotation() };
        for refused in [mistyped, hybrid] {
            for yes in [false, true] {
                let r = Recorder::new(&[true, true], false);
                assert!(run(&r, &refused, strict, yes).await.is_err());
                assert!(r.steps().is_empty(), "{:?}", r.steps());
            }
        }
        // A state gate (a rotation from staged mode) refuses before any prompt too.
        let r = Recorder::new(&[true, true], false);
        assert!(run(&r, &rotation(), AUTH_MODE_STAGED, true).await.is_err());
        assert!(r.steps().is_empty());
        // A bad deploy amount is refused before the deploy.
        let r = Recorder::new(&[true, true], false);
        assert!(
            gate_confirm_deploy(
                &r,
                &rotation(),
                Some(&snapshot(strict)),
                false,
                Some(0.0),
                "?",
                "r1"
            )
            .await
            .is_err()
        );
        assert!(!r.steps().contains(&"deploy".to_owned()));
    }
}
