/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! `tosctl agent native-registry`: build, sign and read for the TOS Native
//! Service Registry (`crypto/smartcont/native-registry-code.fc`).
//!
//! No command here sends anything. `register-agent` and `action` read the chain,
//! refuse before signing every action the contract would refuse for a reason
//! visible in finalized state, sign with controller keys read from the vault
//! into this process, and print the exact message parts: destination, value-less
//! body BOC and, for a registration, the StateInit BOC. The message itself is
//! sent through the Agent Account custody path (`agent account task-send` /
//! `deploy-send`), which journals the exact signed bytes before any broadcast.
//! `show` reads and decodes one registry object.
//!
//! The identity domain is never implied: genesis anchors come from the given
//! global config, the network label is given explicitly, and both are checked
//! against the chain the RPC serves (zero state, and the label against
//! `tos:global-id:<ConfigParam 19>`) before anything is signed.

use super::agent_cmd::{parse_required_hash, sign_hash_with_vault_key};
use super::output_format::OutputFormat;
use super::utils::{load_config_vault_rpc_client, try_create_rpc_client};
use anyhow::Context;
use base64::Engine;
use chain_block::{
    Cell, ConfigParamEnum, MsgAddressInt, Serializable, read_single_root_boc, write_boc,
};
use chain_rpc_client::v2::{client_json_rpc::ClientJsonRpc, data_models::AccountState};
use common::app_config::KeyConfig;
use contracts::native_registry::*;
use secrets_vault::vault::SecretVault;
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Largest global config this command reads.
const MAX_GLOBAL_CONFIG_BYTES: u64 = 16 << 20;
/// Largest policy file this command reads.
const MAX_POLICY_BYTES: u64 = 64 << 10;

/// `tosctl agent native-registry` -- Native Registry build, sign and read.
#[derive(clap::Args, Clone)]
#[command(about = "Native Registry: build, sign and read (never sends)")]
pub struct NativeRegistryCmd {
    #[command(subcommand)]
    action: NativeRegistrySubcommand,
}

#[derive(clap::Subcommand, Clone)]
enum NativeRegistrySubcommand {
    /// Print the identity domain for a global config and network label
    Domain(DomainCmd),
    /// Build and sign an Agent registration: StateInit, body and address
    RegisterAgent(RegisterAgentCmd),
    /// Build and sign an action on a registered Agent or Capability
    Action(ActionCmd),
    /// Read and decode one registry object
    Show(ShowCmd),
}

impl NativeRegistryCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            NativeRegistrySubcommand::Domain(cmd) => cmd.run(),
            NativeRegistrySubcommand::RegisterAgent(cmd) => cmd.run(config_path).await,
            NativeRegistrySubcommand::Action(cmd) => cmd.run(config_path).await,
            NativeRegistrySubcommand::Show(cmd) => cmd.run(config_path).await,
        }
    }
}

#[derive(clap::Args, Clone)]
struct DomainArgs {
    #[arg(long, help = "Global config of the chain (genesis anchors are read from it)")]
    global_config: PathBuf,
    #[arg(long, help = "Network label of the identity domain, for example tos:global-id:2")]
    network_label: String,
}

#[derive(clap::Args, Clone)]
struct DomainCmd {
    #[command(flatten)]
    domain: DomainArgs,
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
struct RegisterAgentCmd {
    #[command(flatten)]
    domain: DomainArgs,
    #[arg(long, help = "Policy JSON file of the new Agent")]
    policy: PathBuf,
    #[arg(long, help = "32-byte hex object nonce (also the action nonce)")]
    nonce: String,
    #[arg(
        long = "signer",
        required = true,
        help = "Vault key of a controller; every one must sign"
    )]
    signers: Vec<String>,
    #[arg(short = 'w', long = "workchain", allow_negative_numbers = true, default_value_t = 0)]
    workchain: i8,
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

/// Action kinds after registration, as named on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ActionKind {
    UpdatePolicy,
    Delegate,
    InitiateRecovery,
    CompleteRecovery,
    RevokeAgent,
    RegisterCapability,
    AddVersion,
    TransferCapability,
    RevokeCapability,
}

impl ActionKind {
    fn code(self) -> u8 {
        match self {
            ActionKind::UpdatePolicy => NATIVE_KIND_UPDATE_AGENT_POLICY,
            ActionKind::Delegate => NATIVE_KIND_DELEGATE_AGENT,
            ActionKind::InitiateRecovery => NATIVE_KIND_INITIATE_RECOVERY,
            ActionKind::CompleteRecovery => NATIVE_KIND_COMPLETE_RECOVERY,
            ActionKind::RevokeAgent => NATIVE_KIND_REVOKE_AGENT,
            ActionKind::RegisterCapability => NATIVE_KIND_REGISTER_CAPABILITY,
            ActionKind::AddVersion => NATIVE_KIND_ADD_CAPABILITY_VERSION,
            ActionKind::TransferCapability => NATIVE_KIND_TRANSFER_CAPABILITY,
            ActionKind::RevokeCapability => NATIVE_KIND_REVOKE_CAPABILITY,
        }
    }
}

#[derive(clap::Args, Clone)]
struct ActionCmd {
    #[command(flatten)]
    domain: DomainArgs,
    #[arg(long, value_enum)]
    kind: ActionKind,
    #[arg(allow_hyphen_values = true, value_parser = super::utils::address_arg, long, help = "Agent the action is sent to (the owner for Capability actions)")]
    agent: String,
    #[arg(allow_hyphen_values = true, value_parser = super::utils::address_arg, long, help = "Capability address for add-version, transfer-capability and revoke-capability")]
    capability: Option<String>,
    #[arg(allow_hyphen_values = true, value_parser = super::utils::address_arg, long, help = "Receiving Agent for transfer-capability")]
    new_owner: Option<String>,
    #[arg(long, help = "32-byte hex action nonce")]
    nonce: String,
    #[arg(
        long,
        help = "Policy JSON file: next policy (update-policy) or recovery policy (initiate-recovery)"
    )]
    policy: Option<PathBuf>,
    #[arg(long, help = "32-byte hex delegation id for delegate")]
    delegation: Option<String>,
    #[arg(long, help = "Unix time after which the recovery may complete (initiate-recovery)")]
    execute_after: Option<u64>,
    #[arg(long, help = "32-byte hex object nonce of a new Capability (register-capability)")]
    object_nonce: Option<String>,
    #[arg(
        long,
        help = "Version name (register-capability, add-version, revoke-capability of one version)"
    )]
    version: Option<String>,
    #[arg(long, help = "32-byte hex manifest digest (register-capability, add-version)")]
    manifest: Option<String>,
    #[arg(long = "signer", required = true, help = "Vault key of an authority signer")]
    signers: Vec<String>,
    #[arg(long = "counter-signer", help = "Vault key of a counterparty signer")]
    counter_signers: Vec<String>,
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

#[derive(clap::Args, Clone)]
struct ShowCmd {
    #[command(flatten)]
    domain: DomainArgs,
    #[arg(allow_hyphen_values = true, value_parser = super::utils::address_arg, long)]
    address: String,
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

/// A loaded identity domain with its label and the release code.
struct LoadedDomain {
    domain: NativeRegistryDomain,
    label: Vec<u8>,
    code: Cell,
}

fn read_bounded(path: &Path, limit: u64, what: &str) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::File::open(path).with_context(|| format!("open {what}"))?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= limit,
        "{what} exceeds {limit} bytes"
    );
    Ok(bytes)
}

fn anchor(value: &serde_json::Value, what: &str) -> anyhow::Result<[u8; 32]> {
    let text = value.as_str().with_context(|| format!("global config has no {what}"))?;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .with_context(|| format!("{what} is not base64"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} is not 32 bytes"))
}

/// The identity domain from a global config's zero state and an explicit label.
fn domain_from_global_config(config: &[u8], label: &str) -> anyhow::Result<LoadedDomain> {
    let value: serde_json::Value = serde_json::from_slice(config).context("global config JSON")?;
    let zero = &value["validator"]["zero_state"];
    let code = native_registry_release_code()?;
    let domain = NativeRegistryDomain::for_label(
        anchor(&zero["root_hash"], "zero_state.root_hash")?,
        anchor(&zero["file_hash"], "zero_state.file_hash")?,
        label.as_bytes(),
        *code.repr_hash().as_array(),
    )?;
    Ok(LoadedDomain { domain, label: label.as_bytes().to_vec(), code })
}

impl DomainArgs {
    fn load(&self) -> anyhow::Result<LoadedDomain> {
        let bytes = read_bounded(&self.global_config, MAX_GLOBAL_CONFIG_BYTES, "global config")?;
        domain_from_global_config(&bytes, &self.network_label)
    }
}

/// Refuse unless the RPC serves the chain the domain names: the same zero
/// state, and a network label equal to `tos:global-id:<ConfigParam 19>`.
async fn check_chain(rpc: &ClientJsonRpc, loaded: &LoadedDomain) -> anyhow::Result<()> {
    let master = rpc.get_masterchain_info().await?;
    let zero = master.init.context("RPC omitted the zero-state identity")?;
    anyhow::ensure!(
        zero.root_hash.as_slice() == loaded.domain.genesis_root
            && zero.file_hash.as_slice() == loaded.domain.genesis_file,
        "the RPC serves another chain than the global config's zero state"
    );
    let global_id = match rpc.get_config_param(19).await? {
        ConfigParamEnum::ConfigParam19(value) => value,
        _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
    };
    anyhow::ensure!(
        loaded.label == format!("tos:global-id:{global_id}").into_bytes(),
        "network label does not match this chain (global id {global_id})"
    );
    Ok(())
}

/// The verified registry object at `address`, `None` when no account exists.
async fn read_object(
    rpc: &ClientJsonRpc,
    loaded: &LoadedDomain,
    address: &MsgAddressInt,
) -> anyhow::Result<Option<NativeRegistryObject>> {
    let info = rpc.get_address_information(address).await?;
    match info.state {
        AccountState::Uninitialized => return Ok(None),
        AccountState::Frozen => anyhow::bail!("registry account {address} is frozen"),
        AccountState::Active => {}
    }
    let code = read_single_root_boc(info.code.context("active account without code")?)?;
    let data = read_single_root_boc(info.data.context("active account without data")?)?;
    Ok(Some(verify_native_registry_account(
        &loaded.domain,
        &loaded.label,
        &loaded.code,
        address,
        &code,
        &data,
    )?))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    threshold: u32,
    recovery_threshold: u32,
    recovery_timelock: u64,
    controllers: Vec<PolicyFileController>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFileController {
    public_key: String,
    weight: u32,
    purposes: u16,
}

fn parse_policy(bytes: &[u8]) -> anyhow::Result<NativePolicy> {
    let file: PolicyFile = serde_json::from_slice(bytes).context("policy JSON")?;
    let controllers = file
        .controllers
        .iter()
        .map(|c| {
            Ok(NativePolicyController {
                public_key: parse_required_hash("public_key", &Some(c.public_key.clone()))?,
                weight: c.weight,
                purposes: c.purposes,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let policy = NativePolicy {
        threshold: file.threshold,
        recovery_threshold: file.recovery_threshold,
        recovery_timelock: file.recovery_timelock,
        controllers,
    };
    build_policy(&policy)?;
    Ok(policy)
}

fn read_policy(path: &Path) -> anyhow::Result<NativePolicy> {
    parse_policy(&read_bounded(path, MAX_POLICY_BYTES, "policy file")?)
}

fn agent_state(object: &NativeRegistryObject) -> anyhow::Result<&NativeRegistryState> {
    anyhow::ensure!(object.object_kind == 1, "not an Agent");
    let state = object.state.as_ref().context("Agent is not registered")?;
    anyhow::ensure!(!state.tombstone, "Agent is revoked");
    Ok(state)
}

fn agent_policy(state: &NativeRegistryState) -> anyhow::Result<NativePolicy> {
    match &state.detail {
        NativeRegistryStateDetail::Agent { policy, .. } => decode_native_policy(policy),
        NativeRegistryStateDetail::Capability { .. } => anyhow::bail!("not an Agent state"),
    }
}

/// Inputs of an action besides the objects it reads.
#[derive(Clone, Debug)]
enum ActionInput {
    UpdatePolicy(NativePolicy),
    Delegate([u8; 32]),
    InitiateRecovery { execute_after: u64, policy: NativePolicy },
    CompleteRecovery,
    RevokeAgent,
    RegisterCapability { object_nonce: [u8; 32], version: Vec<u8>, manifest: [u8; 32] },
    AddVersion { version: Vec<u8>, manifest: [u8; 32] },
    TransferCapability,
    RevokeCapability { version: Option<Vec<u8>> },
}

/// The registry objects an action reads, already verified against the domain.
struct ActionObjects<'a> {
    agent: (&'a MsgAddressInt, &'a NativeRegistryObject),
    capability: Option<(&'a MsgAddressInt, Option<&'a NativeRegistryObject>)>,
    new_owner: Option<(&'a MsgAddressInt, &'a NativeRegistryObject)>,
}

/// An unsigned action, refused before signing for every reason the contract
/// would refuse it that finalized state shows.
#[derive(Debug)]
struct PlannedAction {
    kind: u8,
    action: Cell,
    destination: MsgAddressInt,
    final_target: MsgAddressInt,
    target_id: [u8; 32],
    generation: u64,
    sequence: u64,
    predecessor: [u8; 32],
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

#[allow(clippy::too_many_arguments)]
fn plan_action(
    loaded: &LoadedDomain,
    kind: ActionKind,
    input: &ActionInput,
    objects: &ActionObjects<'_>,
    signers: &[[u8; 32]],
    counter: &[[u8; 32]],
    nonce: [u8; 32],
    now: u64,
) -> anyhow::Result<PlannedAction> {
    use anyhow::{bail, ensure};
    let code = kind.code();
    let (agent_address, agent) = objects.agent;
    let current = agent_state(agent)?;
    let policy = agent_policy(current)?;
    check_native_threshold(&policy, signers, code)?;
    if native_kind_takes_counterparty(code) {
        ensure!(!counter.is_empty(), "this action kind needs --counter-signer");
    } else {
        ensure!(counter.is_empty(), "this action kind takes no --counter-signer");
    }
    let capability_kind = code >= NATIVE_KIND_REGISTER_CAPABILITY;
    let (payload, target, final_target) = match (kind, input) {
        (ActionKind::UpdatePolicy, ActionInput::UpdatePolicy(next)) => {
            check_native_possession(next, counter)?;
            (build_native_update_policy_payload(next)?, agent, agent_address.clone())
        }
        (ActionKind::Delegate, ActionInput::Delegate(delegation)) => {
            let NativeRegistryStateDetail::Agent { delegations, delegation_root, .. } =
                &current.detail
            else {
                bail!("not an Agent state")
            };
            ensure!(
                *delegations < NATIVE_REGISTRY_MAX_DELEGATIONS,
                "Agent delegation capacity reached"
            );
            ensure!(
                !native_dict_contains(delegation_root, delegation)?,
                "delegation already exists"
            );
            (build_native_delegate_payload(*delegation)?, agent, agent_address.clone())
        }
        (
            ActionKind::InitiateRecovery,
            ActionInput::InitiateRecovery { execute_after, policy: next },
        ) => {
            check_native_possession(next, counter)?;
            let earliest =
                now.checked_add(policy.recovery_timelock).context("recovery time overflows")?;
            ensure!(
                *execute_after >= earliest,
                "--execute-after must be at least now + the current recovery timelock ({earliest})"
            );
            (
                build_native_initiate_recovery_payload(*execute_after, next)?,
                agent,
                agent_address.clone(),
            )
        }
        (ActionKind::CompleteRecovery, ActionInput::CompleteRecovery) => {
            let NativeRegistryStateDetail::Agent { recovery, policy: stored, .. } = &current.detail
            else {
                bail!("not an Agent state")
            };
            let pending = recovery.as_ref().context("no recovery is pending")?;
            ensure!(
                pending.old_policy_hash == *stored.repr_hash().as_array(),
                "the pending recovery was initiated under another policy"
            );
            ensure!(now >= pending.execute_after, "the recovery timelock has not passed");
            (
                build_native_complete_recovery_payload(pending.initiation)?,
                agent,
                agent_address.clone(),
            )
        }
        (ActionKind::RevokeAgent, ActionInput::RevokeAgent) => {
            (build_native_revoke_agent_payload()?, agent, agent_address.clone())
        }
        (
            ActionKind::RegisterCapability,
            ActionInput::RegisterCapability { object_nonce, version, manifest },
        ) => {
            let registration = build_native_capability_registration(
                &loaded.domain,
                *object_nonce,
                agent.object_id,
                version,
                *manifest,
            )?;
            let workchain = i8::try_from(agent_address.workchain_id())?;
            let (_, address) = build_native_registry_deployment(
                &loaded.domain,
                2,
                registration.object_id,
                workchain,
                &loaded.label,
                &loaded.code,
            )?;
            if let Some((given, existing)) = objects.capability {
                ensure!(
                    given == &address,
                    "--capability is not the address this registration derives"
                );
                ensure!(existing.is_none(), "the Capability is already registered");
            }
            let action = build_native_action(
                &loaded.domain,
                &NativeRegistryAction {
                    kind: code,
                    generation: 1,
                    sequence: 1,
                    object_id: registration.object_id,
                    predecessor: [0; 32],
                    nonce,
                    payload: registration.payload,
                },
            )?;
            return Ok(PlannedAction {
                kind: code,
                action,
                destination: agent_address.clone(),
                final_target: address,
                target_id: registration.object_id,
                generation: 1,
                sequence: 1,
                predecessor: [0; 32],
            });
        }
        (_, _) if capability_kind => {
            let (cap_address, cap) = objects.capability.context("--capability is required")?;
            let cap = cap.context("the Capability is not registered")?;
            ensure!(cap.object_kind == 2, "--capability is not a Capability");
            let cap_state = cap.state.as_ref().context("the Capability is not registered")?;
            ensure!(!cap_state.tombstone, "the Capability is revoked");
            let NativeRegistryStateDetail::Capability { owner, versions, version_root } =
                &cap_state.detail
            else {
                bail!("not a Capability state")
            };
            ensure!(*owner == agent.object_id, "--agent is not the Capability's current owner");
            let payload = match (kind, input) {
                (ActionKind::AddVersion, ActionInput::AddVersion { version, manifest }) => {
                    ensure!(
                        *versions < NATIVE_REGISTRY_MAX_VERSIONS,
                        "Capability version capacity reached"
                    );
                    ensure!(
                        native_capability_version(version_root, &sha256(version))?.is_none(),
                        "this version already exists"
                    );
                    build_native_add_version_payload(agent.object_id, version, *manifest)?
                }
                (ActionKind::TransferCapability, ActionInput::TransferCapability) => {
                    let (_, receiver) = objects.new_owner.context("--new-owner is required")?;
                    let receiver_state = agent_state(receiver)?;
                    ensure!(receiver.object_id != agent.object_id, "transfer to the same owner");
                    check_native_threshold(&agent_policy(receiver_state)?, counter, code)
                        .context("the receiving Agent's consent")?;
                    build_native_transfer_payload(agent.object_id, receiver.object_id)?
                }
                (ActionKind::RevokeCapability, ActionInput::RevokeCapability { version }) => {
                    if let Some(version) = version {
                        let stored = native_capability_version(version_root, &sha256(version))?
                            .context("this version does not exist")?;
                        ensure!(!stored.revoked, "this version is already revoked");
                    }
                    build_native_revoke_capability_payload(agent.object_id, version.as_deref())?
                }
                _ => bail!("action inputs do not match --kind"),
            };
            (payload, cap, cap_address.clone())
        }
        _ => bail!("action inputs do not match --kind"),
    };
    let (generation, sequence, predecessor) = next_native_position(target.state.as_ref(), code)?;
    let action = build_native_action(
        &loaded.domain,
        &NativeRegistryAction {
            kind: code,
            generation,
            sequence,
            object_id: target.object_id,
            predecessor,
            nonce,
            payload,
        },
    )?;
    Ok(PlannedAction {
        kind: code,
        action,
        destination: agent_address.clone(),
        final_target,
        target_id: target.object_id,
        generation,
        sequence,
        predecessor,
    })
}

async fn vault_public_key(name: &str, vault: Arc<SecretVault>) -> anyhow::Result<[u8; 32]> {
    let secret = KeyConfig::VaultKey { name: name.to_owned() }.read_secret(Some(vault)).await?;
    let raw = secret
        .as_keypair()?
        .public_key()
        .await?
        .ok_or_else(|| anyhow::anyhow!("vault key '{name}' has no public key"))?;
    raw.try_into().map_err(|_| anyhow::anyhow!("vault key '{name}' is not an Ed25519 key"))
}

async fn public_keys(names: &[String], vault: Arc<SecretVault>) -> anyhow::Result<Vec<[u8; 32]>> {
    let mut keys = Vec::with_capacity(names.len());
    for name in names {
        keys.push(vault_public_key(name, vault.clone()).await?);
    }
    Ok(keys)
}

async fn sign_all(
    names: &[String],
    keys: &[[u8; 32]],
    action: &Cell,
    vault: Arc<SecretVault>,
) -> anyhow::Result<Vec<NativeControllerSignature>> {
    let hash = *action.repr_hash().as_array();
    let mut out = Vec::with_capacity(names.len());
    for (name, public_key) in names.iter().zip(keys) {
        let signature = sign_hash_with_vault_key(name, &hash, vault.clone()).await?;
        out.push(NativeControllerSignature { public_key: *public_key, signature });
    }
    Ok(out)
}

fn b64(cell: &Cell) -> anyhow::Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(write_boc(cell)?))
}

fn print_view(view: &serde_json::Value, format: &OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(view)?),
        OutputFormat::Table => {
            if let Some(map) = view.as_object() {
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

fn nonce_arg(name: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    let nonce = parse_required_hash(name, &Some(value.to_owned()))?;
    anyhow::ensure!(nonce != [0; 32], "--{name} must be nonzero");
    Ok(nonce)
}

impl DomainCmd {
    fn run(&self) -> anyhow::Result<()> {
        let loaded = self.domain.load()?;
        print_view(
            &serde_json::json!({
                "network_label": self.domain.network_label,
                "genesis_root": hex::encode(loaded.domain.genesis_root),
                "genesis_file": hex::encode(loaded.domain.genesis_file),
                "network_hash": hex::encode(loaded.domain.network_tag),
                "code_hash": hex::encode(loaded.domain.runtime_code_hash),
            }),
            &self.format,
        )
    }
}

impl RegisterAgentCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let loaded = self.domain.load()?;
        let policy = read_policy(&self.policy)?;
        let nonce = nonce_arg("nonce", &self.nonce)?;
        let (_, vault, rpc) = load_config_vault_rpc_client(Path::new(config_path)).await?;
        check_chain(&rpc, &loaded).await?;
        let registration = build_native_agent_registration(&loaded.domain, nonce, &policy)?;
        let (init, address) = build_native_registry_deployment(
            &loaded.domain,
            1,
            registration.object_id,
            self.workchain,
            &loaded.label,
            &loaded.code,
        )?;
        anyhow::ensure!(
            read_object(&rpc, &loaded, &address).await?.is_none(),
            "an account already exists at {address}"
        );
        let keys = public_keys(&self.signers, vault.clone()).await?;
        check_native_possession(&policy, &keys)?;
        let (generation, sequence, predecessor) =
            next_native_position(None, NATIVE_KIND_REGISTER_AGENT)?;
        let action = build_native_action(
            &loaded.domain,
            &NativeRegistryAction {
                kind: NATIVE_KIND_REGISTER_AGENT,
                generation,
                sequence,
                object_id: registration.object_id,
                predecessor,
                nonce,
                payload: registration.payload,
            },
        )?;
        let signatures = sign_all(&self.signers, &keys, &action, vault).await?;
        let body = build_native_submission(&loaded.domain, &action, 1, &signatures, &[])?;
        let state_init = init.write_to_new_cell()?.into_cell()?;
        print_view(
            &serde_json::json!({
                "kind": "register-agent",
                "object_id": hex::encode(registration.object_id),
                "destination": address.to_string(),
                "final_target": address.to_string(),
                "action_hash": hex::encode(action.repr_hash().as_slice()),
                "generation": generation,
                "sequence": sequence,
                "state_init_boc": b64(&state_init)?,
                "body_boc": b64(&body)?,
            }),
            &self.format,
        )
    }
}

impl ActionCmd {
    fn input(&self) -> anyhow::Result<ActionInput> {
        let hash = |name: &str, value: &Option<String>| parse_required_hash(name, value);
        let version = || {
            self.version.as_ref().map(|v| v.as_bytes().to_vec()).context("--version is required")
        };
        let policy = || read_policy(self.policy.as_deref().context("--policy is required")?);
        Ok(match self.kind {
            ActionKind::UpdatePolicy => ActionInput::UpdatePolicy(policy()?),
            ActionKind::Delegate => ActionInput::Delegate(hash("delegation", &self.delegation)?),
            ActionKind::InitiateRecovery => ActionInput::InitiateRecovery {
                execute_after: self.execute_after.context("--execute-after is required")?,
                policy: policy()?,
            },
            ActionKind::CompleteRecovery => ActionInput::CompleteRecovery,
            ActionKind::RevokeAgent => ActionInput::RevokeAgent,
            ActionKind::RegisterCapability => ActionInput::RegisterCapability {
                object_nonce: nonce_arg(
                    "object-nonce",
                    self.object_nonce.as_deref().context("--object-nonce is required")?,
                )?,
                version: version()?,
                manifest: hash("manifest", &self.manifest)?,
            },
            ActionKind::AddVersion => ActionInput::AddVersion {
                version: version()?,
                manifest: hash("manifest", &self.manifest)?,
            },
            ActionKind::TransferCapability => ActionInput::TransferCapability,
            ActionKind::RevokeCapability => ActionInput::RevokeCapability {
                version: self.version.as_ref().map(|v| v.as_bytes().to_vec()),
            },
        })
    }

    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let loaded = self.domain.load()?;
        let input = self.input()?;
        let nonce = nonce_arg("nonce", &self.nonce)?;
        let (_, vault, rpc) = load_config_vault_rpc_client(Path::new(config_path)).await?;
        check_chain(&rpc, &loaded).await?;
        let agent_address: MsgAddressInt = self.agent.parse().context("invalid --agent")?;
        let agent = read_object(&rpc, &loaded, &agent_address)
            .await?
            .context("no registry account at --agent")?;
        let capability_address = self
            .capability
            .as_deref()
            .map(str::parse::<MsgAddressInt>)
            .transpose()
            .context("invalid --capability")?;
        let capability = match &capability_address {
            Some(address) => Some(read_object(&rpc, &loaded, address).await?),
            None => None,
        };
        let new_owner_address = self
            .new_owner
            .as_deref()
            .map(str::parse::<MsgAddressInt>)
            .transpose()
            .context("invalid --new-owner")?;
        let new_owner = match &new_owner_address {
            Some(address) => Some(
                read_object(&rpc, &loaded, address)
                    .await?
                    .context("no registry account at --new-owner")?,
            ),
            None => None,
        };
        let objects = ActionObjects {
            agent: (&agent_address, &agent),
            capability: capability_address
                .as_ref()
                .zip(capability.as_ref())
                .map(|(address, object)| (address, object.as_ref())),
            new_owner: new_owner_address.as_ref().zip(new_owner.as_ref()),
        };
        let signer_keys = public_keys(&self.signers, vault.clone()).await?;
        let counter_keys = public_keys(&self.counter_signers, vault.clone()).await?;
        let now = common::time_format::now();
        let planned = plan_action(
            &loaded,
            self.kind,
            &input,
            &objects,
            &signer_keys,
            &counter_keys,
            nonce,
            now,
        )?;
        let authority =
            sign_all(&self.signers, &signer_keys, &planned.action, vault.clone()).await?;
        let counterparty =
            sign_all(&self.counter_signers, &counter_keys, &planned.action, vault).await?;
        let body =
            build_native_submission(&loaded.domain, &planned.action, 1, &authority, &counterparty)?;
        print_view(
            &serde_json::json!({
                "kind": self.kind.to_possible_value_name(),
                "kind_code": planned.kind,
                "target_id": hex::encode(planned.target_id),
                "destination": planned.destination.to_string(),
                "final_target": planned.final_target.to_string(),
                "action_hash": hex::encode(planned.action.repr_hash().as_slice()),
                "generation": planned.generation,
                "sequence": planned.sequence,
                "predecessor": hex::encode(planned.predecessor),
                "body_boc": b64(&body)?,
            }),
            &self.format,
        )
    }
}

impl ActionKind {
    fn to_possible_value_name(self) -> String {
        use clap::ValueEnum;
        self.to_possible_value().map(|v| v.get_name().to_owned()).unwrap_or_default()
    }
}

fn object_view(address: &MsgAddressInt, object: &NativeRegistryObject) -> serde_json::Value {
    let mut view = serde_json::json!({
        "address": address.to_string(),
        "object_kind": if object.object_kind == 1 { "agent" } else { "capability" },
        "object_id": hex::encode(object.object_id),
        "registered": object.state.is_some(),
    });
    if let (Some(state), Some(map)) = (&object.state, view.as_object_mut()) {
        map.insert("tombstone".into(), state.tombstone.into());
        map.insert("generation".into(), state.generation.into());
        map.insert("sequence".into(), state.sequence.into());
        map.insert("last_action".into(), hex::encode(state.last_action).into());
        map.insert("state_hash".into(), hex::encode(state.state_hash).into());
        match &state.detail {
            NativeRegistryStateDetail::Agent { policy, delegations, recovery, .. } => {
                map.insert("policy_hash".into(), hex::encode(policy.repr_hash().as_slice()).into());
                map.insert("delegations".into(), (*delegations).into());
                map.insert(
                    "recovery_execute_after".into(),
                    recovery.as_ref().map(|r| r.execute_after).into(),
                );
            }
            NativeRegistryStateDetail::Capability { owner, versions, .. } => {
                map.insert("owner".into(), hex::encode(owner).into());
                map.insert("versions".into(), (*versions).into());
            }
        }
    }
    view
}

impl ShowCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let loaded = self.domain.load()?;
        let config = common::app_config::AppConfig::load(Path::new(config_path))?;
        let rpc = try_create_rpc_client(&config).await?;
        check_chain(&rpc, &loaded).await?;
        let address: MsgAddressInt = self.address.parse().context("invalid --address")?;
        let object = read_object(&rpc, &loaded, &address)
            .await?
            .context("no registry account at --address")?;
        print_view(&object_view(&address, &object), &self.format)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TESTNET_GLOBAL_CONFIG: &str = r#"{"validator":{"zero_state":{"workchain":-1,"shard":-9223372036854775808,"seqno":0,
        "root_hash":"/2BFnLilFwhUgpCvoW/U34DRZ3W/PBM5IUam0bVmLVc=","file_hash":"OzdN9evRg2jUvw6zdHBHcdr42s2FF1YF87/Rx6kioDk="}}}"#;

    fn loaded() -> LoadedDomain {
        domain_from_global_config(TESTNET_GLOBAL_CONFIG.as_bytes(), "tos:global-id:2")
            .expect("domain")
    }

    fn key(seed: u8) -> [u8; 32] {
        // Deliberately public deterministic test fixture, never an operational key.
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()
    }

    fn one_key_policy(seed: u8, timelock: u64) -> NativePolicy {
        NativePolicy {
            threshold: 1,
            recovery_threshold: 1,
            recovery_timelock: timelock,
            controllers: vec![NativePolicyController {
                public_key: key(seed),
                weight: 1,
                purposes: 15,
            }],
        }
    }

    fn address(byte: u8) -> MsgAddressInt {
        format!("0:{}", hex::encode([byte; 32])).parse().expect("address")
    }

    fn agent(seed: u8, tombstone: bool, delegations: u16) -> NativeRegistryObject {
        agent_with(seed, tombstone, delegations, None)
    }

    fn agent_with(
        seed: u8,
        tombstone: bool,
        delegations: u16,
        recovery: Option<NativePendingRecovery>,
    ) -> NativeRegistryObject {
        NativeRegistryObject {
            object_kind: 1,
            object_id: [seed; 32],
            config: Cell::default(),
            state: Some(NativeRegistryState {
                object_kind: 1,
                tombstone,
                generation: 1,
                sequence: 3,
                last_action: [0x0a; 32],
                state_hash: [seed ^ 0x55; 32],
                detail: NativeRegistryStateDetail::Agent {
                    policy: build_policy(&one_key_policy(seed, 60)).expect("policy"),
                    delegations,
                    delegation_root: None,
                    recovery,
                },
            }),
        }
    }

    fn capability(owner: u8, tombstone: bool, versions: u16) -> NativeRegistryObject {
        NativeRegistryObject {
            object_kind: 2,
            object_id: [0xc0; 32],
            config: Cell::default(),
            state: Some(NativeRegistryState {
                object_kind: 2,
                tombstone,
                generation: 1,
                sequence: 2,
                last_action: [0x0b; 32],
                state_hash: [0xcc; 32],
                detail: NativeRegistryStateDetail::Capability {
                    owner: [owner; 32],
                    versions,
                    version_root: None,
                },
            }),
        }
    }

    fn plan(
        kind: ActionKind,
        input: ActionInput,
        objects: &ActionObjects<'_>,
        signers: &[u8],
        counter: &[u8],
        now: u64,
    ) -> anyhow::Result<PlannedAction> {
        let signers: Vec<_> = signers.iter().map(|&s| key(s)).collect();
        let counter: Vec<_> = counter.iter().map(|&s| key(s)).collect();
        plan_action(&loaded(), kind, &input, objects, &signers, &counter, [0x77; 32], now)
    }

    #[test]
    fn domain_comes_from_the_global_config_and_an_explicit_label() {
        let d = loaded();
        assert_eq!(
            hex::encode(d.domain.network_tag),
            "867b460108f617ef4508e406addf30db563dbabf44f7e90e58cff93ddeacf4a9"
        );
        assert_eq!(
            d.domain.runtime_code_hash,
            *native_registry_release_code().expect("code").repr_hash().as_array()
        );
        assert!(domain_from_global_config(b"{}", "tos:global-id:2").is_err());
        assert!(domain_from_global_config(TESTNET_GLOBAL_CONFIG.as_bytes(), "").is_err());
        assert!(domain_from_global_config(TESTNET_GLOBAL_CONFIG.as_bytes(), "two words").is_err());
    }

    #[test]
    fn policy_files_are_strict() {
        let good = format!(
            r#"{{"threshold":1,"recovery_threshold":1,"recovery_timelock":60,
                "controllers":[{{"public_key":"{}","weight":1,"purposes":15}}]}}"#,
            hex::encode(key(1))
        );
        assert_eq!(parse_policy(good.as_bytes()).expect("policy"), one_key_policy(1, 60));
        let extra = good.replacen("\"threshold\"", "\"extra\":1,\"threshold\"", 1);
        assert!(parse_policy(extra.as_bytes()).is_err());
        let unreachable = good.replacen("\"threshold\":1", "\"threshold\":2", 1);
        assert!(parse_policy(unreachable.as_bytes()).is_err());
    }

    #[test]
    fn agent_actions_are_positioned_on_the_current_state() {
        let a = agent(1, false, 0);
        let aa = address(1);
        let objects = ActionObjects { agent: (&aa, &a), capability: None, new_owner: None };
        let p =
            plan(ActionKind::Delegate, ActionInput::Delegate([0x71; 32]), &objects, &[1], &[], 0)
                .expect("plan");
        assert_eq!((p.generation, p.sequence, p.predecessor), (1, 4, [1 ^ 0x55; 32]));
        assert_eq!((p.destination.clone(), p.final_target.clone()), (aa.clone(), aa));
        assert_eq!(p.kind, NATIVE_KIND_DELEGATE_AGENT);
    }

    #[test]
    fn agent_actions_are_refused_before_signing() {
        let aa = address(1);
        let a = agent(1, false, 0);
        let objects = ActionObjects { agent: (&aa, &a), capability: None, new_owner: None };
        let delegate = || ActionInput::Delegate([0x71; 32]);
        // Not a controller; a counterparty where none is taken.
        assert!(plan(ActionKind::Delegate, delegate(), &objects, &[2], &[], 0).is_err());
        assert!(plan(ActionKind::Delegate, delegate(), &objects, &[1], &[1], 0).is_err());
        // Inputs of another kind.
        assert!(
            plan(ActionKind::Delegate, ActionInput::RevokeAgent, &objects, &[1], &[], 0).is_err()
        );
        // Revoked Agent; full delegation set.
        let dead = agent(1, true, 0);
        let objects_dead = ActionObjects { agent: (&aa, &dead), capability: None, new_owner: None };
        assert!(plan(ActionKind::Delegate, delegate(), &objects_dead, &[1], &[], 0).is_err());
        let full = agent(1, false, NATIVE_REGISTRY_MAX_DELEGATIONS);
        let objects_full = ActionObjects { agent: (&aa, &full), capability: None, new_owner: None };
        assert!(plan(ActionKind::Delegate, delegate(), &objects_full, &[1], &[], 0).is_err());
        // Policy update: the next policy's controllers must all consent.
        let next = || ActionInput::UpdatePolicy(one_key_policy(3, 60));
        assert!(plan(ActionKind::UpdatePolicy, next(), &objects, &[1], &[], 0).is_err());
        assert!(plan(ActionKind::UpdatePolicy, next(), &objects, &[1], &[1], 0).is_err());
        plan(ActionKind::UpdatePolicy, next(), &objects, &[1], &[3], 0).expect("update");
        // Recovery initiation must respect the current timelock.
        let initiate =
            |at| ActionInput::InitiateRecovery { execute_after: at, policy: one_key_policy(4, 60) };
        assert!(
            plan(ActionKind::InitiateRecovery, initiate(1_059), &objects, &[1], &[4], 1_000)
                .is_err()
        );
        plan(ActionKind::InitiateRecovery, initiate(1_060), &objects, &[1], &[4], 1_000)
            .expect("initiate");
        // Completion needs a pending recovery under the current policy, after its time.
        assert!(
            plan(
                ActionKind::CompleteRecovery,
                ActionInput::CompleteRecovery,
                &objects,
                &[1],
                &[],
                0
            )
            .is_err()
        );
        let stored = build_policy(&one_key_policy(1, 60)).expect("policy");
        let pending = NativePendingRecovery {
            initiation: [0x99; 32],
            old_policy_hash: *stored.repr_hash().as_array(),
            execute_after: 2_000,
            policy: build_policy(&one_key_policy(4, 60)).expect("policy"),
        };
        let waiting = agent_with(1, false, 0, Some(pending.clone()));
        let objects_waiting =
            ActionObjects { agent: (&aa, &waiting), capability: None, new_owner: None };
        let complete = || ActionInput::CompleteRecovery;
        assert!(
            plan(ActionKind::CompleteRecovery, complete(), &objects_waiting, &[1], &[], 1_999)
                .is_err()
        );
        let done =
            plan(ActionKind::CompleteRecovery, complete(), &objects_waiting, &[1], &[], 2_000)
                .expect("complete");
        assert_eq!((done.generation, done.sequence), (2, 1));
        let superseded = agent_with(
            1,
            false,
            0,
            Some(NativePendingRecovery { old_policy_hash: [0x01; 32], ..pending }),
        );
        let objects_superseded =
            ActionObjects { agent: (&aa, &superseded), capability: None, new_owner: None };
        assert!(
            plan(ActionKind::CompleteRecovery, complete(), &objects_superseded, &[1], &[], 2_000)
                .is_err()
        );
    }

    #[test]
    fn capability_actions_check_owner_state_and_consent() {
        let (aa, ba, ca) = (address(1), address(2), address(0xc0));
        let (a, b) = (agent(1, false, 0), agent(2, false, 0));
        let cap = capability(1, false, 1);
        let add = || ActionInput::AddVersion { version: b"1.1.0".to_vec(), manifest: [0x5f; 32] };
        let objects = ActionObjects {
            agent: (&aa, &a),
            capability: Some((&ca, Some(&cap))),
            new_owner: Some((&ba, &b)),
        };
        let p = plan(ActionKind::AddVersion, add(), &objects, &[1], &[], 0).expect("add version");
        assert_eq!((p.destination.clone(), p.final_target.clone()), (aa.clone(), ca.clone()));
        assert_eq!((p.generation, p.sequence, p.predecessor), (1, 3, [0xcc; 32]));
        // Another Agent is not the owner; a revoked or missing Capability is refused.
        let not_owner = ActionObjects {
            agent: (&ba, &b),
            capability: Some((&ca, Some(&cap))),
            new_owner: None,
        };
        assert!(plan(ActionKind::AddVersion, add(), &not_owner, &[2], &[], 0).is_err());
        let dead = capability(1, true, 1);
        let objects_dead = ActionObjects {
            agent: (&aa, &a),
            capability: Some((&ca, Some(&dead))),
            new_owner: None,
        };
        assert!(plan(ActionKind::AddVersion, add(), &objects_dead, &[1], &[], 0).is_err());
        let missing =
            ActionObjects { agent: (&aa, &a), capability: Some((&ca, None)), new_owner: None };
        assert!(plan(ActionKind::AddVersion, add(), &missing, &[1], &[], 0).is_err());
        let full = capability(1, false, NATIVE_REGISTRY_MAX_VERSIONS);
        let objects_full = ActionObjects {
            agent: (&aa, &a),
            capability: Some((&ca, Some(&full))),
            new_owner: None,
        };
        assert!(plan(ActionKind::AddVersion, add(), &objects_full, &[1], &[], 0).is_err());
        // Transfer needs the receiving Agent's consent and starts a new generation.
        let transfer = || ActionInput::TransferCapability;
        assert!(plan(ActionKind::TransferCapability, transfer(), &objects, &[1], &[], 0).is_err());
        assert!(plan(ActionKind::TransferCapability, transfer(), &objects, &[1], &[1], 0).is_err());
        let t = plan(ActionKind::TransferCapability, transfer(), &objects, &[1], &[2], 0)
            .expect("transfer");
        assert_eq!((t.generation, t.sequence, t.final_target), (2, 1, ca.clone()));
        let to_self = ActionObjects {
            agent: (&aa, &a),
            capability: Some((&ca, Some(&cap))),
            new_owner: Some((&aa, &a)),
        };
        assert!(plan(ActionKind::TransferCapability, transfer(), &to_self, &[1], &[1], 0).is_err());
        // Revoking an unknown version is refused; revoking the Capability is not.
        let revoke =
            |v: Option<&[u8]>| ActionInput::RevokeCapability { version: v.map(<[u8]>::to_vec) };
        assert!(
            plan(ActionKind::RevokeCapability, revoke(Some(b"9.9.9")), &objects, &[1], &[], 0)
                .is_err()
        );
        plan(ActionKind::RevokeCapability, revoke(None), &objects, &[1], &[], 0).expect("revoke");
    }

    #[test]
    fn capability_registration_targets_the_derived_address() {
        let aa = address(1);
        let a = agent(1, false, 0);
        let input = || ActionInput::RegisterCapability {
            object_nonce: [0x81; 32],
            version: b"1.0.0".to_vec(),
            manifest: [0x5e; 32],
        };
        let objects = ActionObjects { agent: (&aa, &a), capability: None, new_owner: None };
        let p = plan(ActionKind::RegisterCapability, input(), &objects, &[1], &[], 0)
            .expect("register");
        assert_eq!((p.generation, p.sequence, p.predecessor), (1, 1, [0; 32]));
        assert_eq!(p.destination, aa);
        assert_ne!(p.final_target, aa);
        let wrong = address(0xee);
        let objects_wrong =
            ActionObjects { agent: (&aa, &a), capability: Some((&wrong, None)), new_owner: None };
        assert!(
            plan(ActionKind::RegisterCapability, input(), &objects_wrong, &[1], &[], 0).is_err()
        );
        let cap = capability(1, false, 1);
        let derived = p.final_target.clone();
        let objects_taken = ActionObjects {
            agent: (&aa, &a),
            capability: Some((&derived, Some(&cap))),
            new_owner: None,
        };
        assert!(
            plan(ActionKind::RegisterCapability, input(), &objects_taken, &[1], &[], 0).is_err()
        );
    }
}
