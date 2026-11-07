/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Strict reconfiguration of an Agent Account's ML-DSA-44 authentication
//! root (`crypto/smartcont/auth-extension.md`, kind 1): the cutover from
//! staged mode 1 to module-only mode 2 with the staged module, and the
//! rotation of a mode-2 root to another ML-DSA-44 module.
//!
//! Both are irreversible in the way that matters: once strict, the owner and
//! the Ed25519 controller can no longer stage, spend or recover, and only the
//! installed root can install its successor. Every gate is checked before the
//! account is fenced, anything is signed or anything is relayed:
//! - the target mode is 2 (mode 1 is a downgrade the account refuses; mode 3
//!   adds a classical cosigner, a second key that can lock the account out);
//! - the operator typed the account address exactly;
//! - a cutover starts from staged mode with this controller's module, which
//!   has already authenticated a real request in the staged epoch (auth nonce
//!   at least 1 in a finalized snapshot); a rotation starts from mode 2 with
//!   this controller's module and installs a different, verified module;
//! - counters can advance, the expiry is inside both windows, the relayer can
//!   pay, and no custody action or other fence of the account is open.
//!
//! The chain, the signing key and the relaying wallet are reached through
//! [`ReconfigureChain`], so the orchestration the CLI runs is the one the
//! sandbox suite drives against real bytecode.

use anyhow::{Context, bail, ensure};
use chain_block::{Cell, MsgAddressInt, UInt256, write_boc};
use sha2::Digest as _;

use crate::agent_account_auth::{
    AUTH_MODE_HYBRID, AUTH_MODE_LEGACY, AUTH_MODE_MODULE_ONLY, AUTH_MODE_STAGED, AgentAccountState,
    ConfigureRequest, Mldsa44AuthConfig, Mldsa44AuthModule, build_auth_envelope,
    build_mldsa44_submit, check_auth_window, check_module_address, parse_mldsa44_configure_submit,
    reconfiguration_landed,
};
use crate::agent_account_custody::{AgentAccountCustodyJournal, Mldsa44RelayAttempt};
use crate::native_registry::NATIVE_REGISTRY_SIGNATURE_BYTES;

/// The only target mode this route builds.
pub const STRICT_TARGET_MODE: u8 = AUTH_MODE_MODULE_ONLY;

/// Which reconfiguration is asked for.
// One value per command run; its size does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reconfiguration {
    /// Staged mode 1 -> mode 2 with the staged module as root.
    Cutover,
    /// Mode 2 -> mode 2 with `module`, the module of `public_key`.
    Rotate { module: MsgAddressInt, public_key: Vec<u8> },
}

/// What the operator asked for.
#[derive(Clone, Debug)]
pub struct ReconfigureRequest {
    pub change: Reconfiguration,
    /// The mode the operator typed; only [`STRICT_TARGET_MODE`] is accepted.
    pub mode: u8,
    /// The account address the operator typed; must equal `account` exactly.
    pub confirm_account: String,
    pub account: MsgAddressInt,
    pub global_id: i32,
    /// The current root: this controller's module and public key.
    pub module: MsgAddressInt,
    pub public_key: Vec<u8>,
    pub valid_until: u32,
    pub relay_amount: u64,
    /// Lift an interrupted reconfiguration's fence when the snapshot shows it
    /// can no longer land.
    pub recover_interrupted: bool,
    pub query_id: u64,
    /// A fresh 64-lowercase-hex token for the fence this run takes.
    pub owner_token: String,
}

/// One finalized account snapshot and the time of the state it was read at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountSnapshot {
    pub state: AgentAccountState,
    pub state_time: u32,
    pub default_task_timeout_secs: u64,
}

/// A module as the chain shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleView {
    pub active: bool,
    pub code_hash: Option<UInt256>,
    pub config: Option<Mldsa44AuthConfig>,
}

/// What a relay sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRelay {
    pub relayer: MsgAddressInt,
    pub wallet_message: Vec<u8>,
}

/// The chain, the current root's signing key and the relaying wallet.
#[allow(async_fn_in_trait)]
pub trait ReconfigureChain {
    /// A finalized account snapshot (data and the time of its state).
    async fn account(&self, account: &MsgAddressInt) -> anyhow::Result<AccountSnapshot>;
    async fn module(&self, module: &MsgAddressInt) -> anyhow::Result<ModuleView>;
    /// Refuses unless the relaying wallet can pay `amount` plus its own fees
    /// for relaying `body` to `module`; returns its address.
    async fn check_relayer(
        &self,
        module: &MsgAddressInt,
        body: &Cell,
        amount: u64,
    ) -> anyhow::Result<MsgAddressInt>;
    /// Signs `request` with the current root's ML-DSA-44 key.
    async fn sign(&self, request: &Cell) -> anyhow::Result<Vec<u8>>;
    /// Builds, without sending, the relaying wallet's message of `body`.
    async fn prepare_relay(
        &self,
        module: &MsgAddressInt,
        amount: u64,
        body: Cell,
    ) -> anyhow::Result<PreparedRelay>;
    async fn broadcast(&self, relay: &PreparedRelay, module: &MsgAddressInt) -> anyhow::Result<()>;
    /// Waits before the next landing observation; `false` ends the wait.
    async fn pause(&self, attempt: u32) -> bool;
}

/// How a reconfiguration ended.
// One value per command run; its size does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconfigureOutcome {
    /// This run fenced, signed, relayed and saw it land.
    Landed {
        before: AgentAccountState,
        after: AgentAccountState,
        relayer: MsgAddressInt,
        submission_digest: String,
        wallet_message_digest: String,
    },
    /// An earlier run's reconfiguration had landed; its fence was finished.
    EarlierLanded { after: AgentAccountState },
}

/// The checks that need nothing from the chain.
pub fn check_request(request: &ReconfigureRequest) -> anyhow::Result<()> {
    ensure!(
        request.mode == STRICT_TARGET_MODE,
        "only strict mode {STRICT_TARGET_MODE} (ML-DSA-44 only) is supported; mode {} is refused",
        request.mode
    );
    ensure!(
        request.confirm_account == request.account.to_string(),
        "--confirm-account must be exactly {}",
        request.account
    );
    check_module_address(&request.module, &request.account)?;
    if let Reconfiguration::Rotate { module, .. } = &request.change {
        check_module_address(module, &request.account)?;
        ensure!(module != &request.module, "the rotation installs the root already installed");
    }
    ensure!(request.relay_amount > 0, "the relay amount must be greater than zero");
    Ok(())
}

fn module_hash(module: &MsgAddressInt) -> anyhow::Result<[u8; 32]> {
    module
        .address()
        .get_bytestring(0)
        .try_into()
        .map_err(|_| anyhow::anyhow!("a module address carries a 256-bit account hash"))
}

/// The checks against one finalized snapshot.
pub fn check_state(request: &ReconfigureRequest, snapshot: &AccountSnapshot) -> anyhow::Result<()> {
    let auth = &snapshot.state.auth;
    let root = auth.module_address(request.account.workchain_id())?;
    match &request.change {
        Reconfiguration::Cutover => {
            match auth.mode {
                AUTH_MODE_LEGACY => {
                    bail!("the Agent Account has no staged module; run mldsa44-install first")
                }
                AUTH_MODE_STAGED => {}
                strict => {
                    bail!("the Agent Account is already in strict authentication mode {strict}")
                }
            }
            ensure!(
                root.as_ref() == Some(&request.module),
                "the staged module is not this controller's ML-DSA-44 module"
            );
            ensure!(
                auth.nonce >= 1,
                "the staged module has not authenticated a request in this auth epoch; send one with mldsa44-send and resolve it before the cutover"
            );
        }
        Reconfiguration::Rotate { .. } => {
            match auth.mode {
                AUTH_MODE_MODULE_ONLY => {}
                AUTH_MODE_HYBRID => bail!("this route does not rotate a hybrid (mode 3) root"),
                other => bail!(
                    "the Agent Account is in auth mode {other}, not strict mode 2; a staged account is cut over first"
                ),
            }
            ensure!(
                root.as_ref() == Some(&request.module),
                "the account's root is not this controller's ML-DSA-44 module"
            );
        }
    }
    ensure!(auth.epoch < u64::MAX, "the auth epoch is exhausted");
    ensure!(auth.nonce < u64::MAX, "the auth nonce is exhausted");
    ensure!(snapshot.state.controller_epoch < u64::MAX, "the controller epoch is exhausted");
    ensure!(snapshot.state.seqno < u32::MAX, "the controller seqno is exhausted");
    check_auth_window(request.valid_until, snapshot.state_time, snapshot.default_task_timeout_secs)
}

/// What a module must be: active, this code, this network, this key.
pub fn check_module(view: &ModuleView, global_id: i32, public_key: &[u8]) -> anyhow::Result<()> {
    ensure!(view.active, "the ML-DSA-44 module is not active");
    ensure!(
        view.code_hash == Some(Mldsa44AuthModule::code()?.repr_hash()),
        "the module does not run the supported ML-DSA-44 module code"
    );
    let config = view.config.as_ref().context("the module reported no configuration")?;
    ensure!(config.global_id == global_id, "the module serves another network");
    ensure!(config.public_key == public_key, "the module holds another ML-DSA-44 key");
    Ok(())
}

/// The kind-1 request this reconfiguration signs, under `snapshot`'s counters.
fn configure_request(
    request: &ReconfigureRequest,
    snapshot: &AccountSnapshot,
    target: &MsgAddressInt,
) -> ConfigureRequest {
    ConfigureRequest {
        global_id: request.global_id,
        account: request.account.clone(),
        epoch: snapshot.state.auth.epoch,
        nonce: snapshot.state.auth.nonce,
        valid_until: request.valid_until,
        mode: STRICT_TARGET_MODE,
        module: target.clone(),
    }
}

/// Runs one reconfiguration end to end.
pub async fn reconfigure<C: ReconfigureChain>(
    chain: &C,
    journal: &AgentAccountCustodyJournal,
    request: &ReconfigureRequest,
) -> anyhow::Result<ReconfigureOutcome> {
    check_request(request)?;
    let account_text = request.account.to_string();
    let target = match &request.change {
        Reconfiguration::Cutover => request.module.clone(),
        Reconfiguration::Rotate { module, .. } => module.clone(),
    };
    let target_hash = module_hash(&target)?;
    let snapshot = chain.account(&request.account).await?;
    let deployment_id = hex::encode(snapshot.state.deployment_id);

    // A fence left by an earlier run is settled first, from this snapshot.
    if journal.controller_epoch_change(&account_text, request.global_id, &deployment_id)?.is_some()
    {
        let landed = journal.finish_landed_controller_epoch_change(
            &account_text,
            request.global_id,
            &deployment_id,
            snapshot.state.controller_epoch,
            snapshot.state.seqno,
            &snapshot.state.auth,
        )?;
        if !landed {
            ensure!(
                request.recover_interrupted,
                "an earlier authentication change of this account is still fenced; run again with --recover-interrupted once it can no longer land"
            );
            journal.recover_controller_epoch_change(
                &account_text,
                request.global_id,
                &deployment_id,
                &snapshot.state,
                snapshot.state_time,
            )?;
        }
        // The very change asked for may be the one that landed.
        if snapshot.state.auth.mode == STRICT_TARGET_MODE
            && snapshot.state.auth.module_hash == target_hash
        {
            return Ok(ReconfigureOutcome::EarlierLanded { after: snapshot.state });
        }
    }

    check_state(request, &snapshot)?;
    check_module(&chain.module(&request.module).await?, request.global_id, &request.public_key)?;
    if let Reconfiguration::Rotate { module, public_key } = &request.change {
        check_module(&chain.module(module).await?, request.global_id, public_key)?;
    }
    let configure = configure_request(request, &snapshot, &target);
    let request_cell = configure.to_cell()?;
    let envelope = build_auth_envelope(&request_cell)?;
    let placeholder =
        build_mldsa44_submit(request.query_id, &envelope, &[0u8; NATIVE_REGISTRY_SIGNATURE_BYTES])?;
    chain.check_relayer(&request.module, &placeholder, request.relay_amount).await?;

    journal.begin_auth_reconfiguration(
        &account_text,
        request.global_id,
        &deployment_id,
        snapshot.state.controller_epoch,
        snapshot.state.seqno,
        snapshot.state.auth.epoch,
        &target_hash,
        STRICT_TARGET_MODE,
        &request.owner_token,
    )?;
    // Until the submission is bound nothing authenticated exists: any
    // failure releases the fence this run took.
    let release = |finalized: (u64, u32)| {
        journal.end_controller_epoch_change(
            &account_text,
            request.global_id,
            &deployment_id,
            finalized.0,
            finalized.1,
            Some(&request.owner_token),
        )
    };
    let signed = async {
        let fresh = chain.account(&request.account).await?;
        ensure!(
            fresh.state == snapshot.state,
            "the Agent Account changed while reconfiguring; run again"
        );
        let signature = chain.sign(&request_cell).await?;
        let submission = build_mldsa44_submit(request.query_id, &envelope, &signature)?;
        let parsed = parse_mldsa44_configure_submit(&submission)?;
        ensure!(parsed.request == configure, "the signed submission is not the planned request");
        let bytes = write_boc(&submission)?;
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&bytes)));
        Ok::<_, anyhow::Error>((submission, digest))
    }
    .await;
    let (submission, submission_digest) = match signed {
        Ok(signed) => signed,
        Err(error) => {
            release((snapshot.state.controller_epoch, snapshot.state.seqno))?;
            return Err(error);
        }
    };
    if let Err(error) = journal.bind_epoch_change_submission(
        &account_text,
        request.global_id,
        &deployment_id,
        &request.owner_token,
        &submission_digest,
        request.valid_until,
    ) {
        release((snapshot.state.controller_epoch, snapshot.state.seqno))?;
        return Err(error);
    }

    // Bound: from here the fence is held until the change lands or expires.
    let relay = chain.prepare_relay(&request.module, request.relay_amount, submission).await?;
    let wallet_message_digest =
        format!("sha256:{}", hex::encode(sha2::Sha256::digest(&relay.wallet_message)));
    journal.record_epoch_change_relay(
        &account_text,
        request.global_id,
        &deployment_id,
        &request.owner_token,
        &submission_digest,
        Mldsa44RelayAttempt {
            relayer: relay.relayer.to_string(),
            wallet_message_digest: wallet_message_digest.clone(),
            relay_amount_atomic: request.relay_amount,
            at_unix: u64::from(snapshot.state_time).max(1),
        },
    )?;
    chain.broadcast(&relay, &request.module).await?;

    let mut attempt = 0u32;
    let after = loop {
        let observed = chain.account(&request.account).await?;
        if reconfiguration_landed(
            &snapshot.state,
            &observed.state,
            STRICT_TARGET_MODE,
            &target_hash,
        ) {
            break observed.state;
        }
        ensure!(
            observed.state_time <= request.valid_until,
            "the reconfiguration expired without landing; the account stays fenced until mldsa44 recovery (--recover-interrupted) sees the expired snapshot"
        );
        attempt = attempt.saturating_add(1);
        if !chain.pause(attempt).await {
            bail!(
                "the reconfiguration has not landed yet; the account stays fenced until a later run sees it land or expire"
            );
        }
    };
    journal.end_controller_epoch_change(
        &account_text,
        request.global_id,
        &deployment_id,
        after.controller_epoch,
        after.seqno,
        Some(&request.owner_token),
    )?;
    Ok(ReconfigureOutcome::Landed {
        before: snapshot.state,
        after,
        relayer: relay.relayer,
        submission_digest,
        wallet_message_digest,
    })
}
