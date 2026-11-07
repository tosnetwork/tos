/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! `tosctl agent native-registry`: build, sign and read for the TOS Native
//! Service Registry (`crypto/smartcont/native-registry-code.fc`).
//!
//! Controllers are ML-DSA-44 keys. Each is held in the vault as its 32-byte
//! key-generation seed under the secret id `native-registry-<name>`, created by
//! `new-controller`; `controller` prints its public key and key id for a policy
//! file. The seed is read into this process to sign and wiped afterwards.
//!
//! No command here sends anything. `register-agent` and `action` read the chain,
//! refuse before signing every action the contract would refuse for a reason
//! visible in the state they read (judged at that view's chain time), sign with
//! controller keys read from the vault into this process, and print the exact
//! message parts: destination, body BOC and, for a registration, the StateInit
//! BOC. A caller sends them as one wallet message: `wallet send --build-only
//! --body-boc ... [--state-init-boc ...]` produces the exact signed external
//! message, which the caller journals before broadcasting those bytes only
//! (the wallet seqno makes it apply at most once). A bounceable message
//! refunds a refusal by the first Agent only: registry objects forward without
//! bounce, so value attached to a refused forwarded action stays with the
//! registry object. `show` reads and decodes one registry object.
//!
//! The identity domain is never implied: genesis anchors come from the given
//! global config, the network label is given explicitly, and both are checked
//! against the chain the RPC serves (zero state, and the label against
//! `tos:global-id:<ConfigParam 19>`) before anything is signed.

use super::agent_cmd::parse_required_hash;
use super::output_format::OutputFormat;
use super::utils::{load_config_vault_rpc_client, try_create_rpc_client};
use anyhow::Context;
use base64::Engine;
use chain_block::{
    Cell, ConfigParamEnum, MsgAddressInt, Serializable, read_single_root_boc, write_boc,
};
use chain_rpc_client::v2::{client_json_rpc::ClientJsonRpc, data_models::AccountState};
use contracts::native_registry::*;
use secrets_vault::types::secret_id::SecretId;
use secrets_vault::vault::SecretVault;
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

/// Largest global config this command reads.
const MAX_GLOBAL_CONFIG_BYTES: u64 = 16 << 20;
/// Largest policy file this command reads.
const MAX_POLICY_BYTES: u64 = 64 << 10;
/// Headroom between the chain time an action is planned at and the time it
/// can execute: a recovery initiation must leave the contract's timelock
/// satisfied when it runs, not only when it was read.
const RECOVERY_SUBMISSION_MARGIN_SECS: u64 = 300;

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
    Action(Box<ActionCmd>),
    /// Read and decode one registry object
    Show(ShowCmd),
    /// Create an ML-DSA-44 registry controller in the vault
    NewController(NewControllerCmd),
    /// Print a registry controller's public key and key id
    Controller(ControllerCmd),
}

impl NativeRegistryCmd {
    pub async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        match &self.action {
            NativeRegistrySubcommand::Domain(cmd) => cmd.run(),
            NativeRegistrySubcommand::RegisterAgent(cmd) => cmd.run(config_path).await,
            NativeRegistrySubcommand::Action(cmd) => cmd.run(config_path).await,
            NativeRegistrySubcommand::Show(cmd) => cmd.run(config_path).await,
            NativeRegistrySubcommand::NewController(cmd) => cmd.run(config_path).await,
            NativeRegistrySubcommand::Controller(cmd) => cmd.run(config_path).await,
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
    #[arg(long = "signer", required = true, help = "Registry controller of an authority signer")]
    signers: Vec<String>,
    #[arg(long = "counter-signer", help = "Registry controller of a counterparty signer")]
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

/// The read-only chain view the commands act on. It has no method that sends.
trait RegistryChain {
    /// Refuse unless the view serves the domain's chain.
    async fn check_chain(&self, loaded: &LoadedDomain) -> anyhow::Result<()>;
    /// The verified registry object at `address` (`None` when no account
    /// exists) and the unix time of the view it was read from.
    async fn read_object(
        &self,
        loaded: &LoadedDomain,
        address: &MsgAddressInt,
    ) -> anyhow::Result<(Option<NativeRegistryObject>, u64)>;
}

/// Registry controllers by name: their key ids and their signatures over an
/// action.
trait ControllerSigner {
    async fn key_id(&self, name: &str) -> anyhow::Result<[u8; 32]>;
    async fn sign(&self, name: &str, action: &Cell) -> anyhow::Result<NativeControllerSignature>;
}

/// One account as the RPC returns it: state, raw code and data BOCs, and the
/// unix time of the block the view was read at.
struct AccountSnapshot {
    state: AccountState,
    code: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
    sync_utime: u64,
}

/// The raw RPC reads `RpcChain` needs; nothing here verifies or sends.
trait ChainSource {
    async fn zero_state(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)>;
    async fn global_id(&self) -> anyhow::Result<u32>;
    async fn account(&self, address: &MsgAddressInt) -> anyhow::Result<AccountSnapshot>;
}

impl ChainSource for ClientJsonRpc {
    async fn zero_state(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let master = self.get_masterchain_info().await?;
        let zero = master.init.context("RPC omitted the zero-state identity")?;
        Ok((zero.root_hash, zero.file_hash))
    }

    async fn global_id(&self) -> anyhow::Result<u32> {
        match self.get_config_param(19).await? {
            ConfigParamEnum::ConfigParam19(value) => Ok(value),
            _ => anyhow::bail!("chain config parameter 19 is not a global ID"),
        }
    }

    async fn account(&self, address: &MsgAddressInt) -> anyhow::Result<AccountSnapshot> {
        let info = self.get_address_information(address).await?;
        Ok(AccountSnapshot {
            state: info.state,
            code: info.code,
            data: info.data,
            sync_utime: info.sync_utime,
        })
    }
}

/// The production chain view: raw reads from a source, every account verified
/// against the domain before it is used.
struct RpcChain<'a, T: ChainSource>(&'a T);

impl<T: ChainSource> RegistryChain for RpcChain<'_, T> {
    /// The same zero state as the global config, and a network label equal to
    /// `tos:global-id:<ConfigParam 19>`.
    async fn check_chain(&self, loaded: &LoadedDomain) -> anyhow::Result<()> {
        let (root, file) = self.0.zero_state().await?;
        anyhow::ensure!(
            root.as_slice() == loaded.domain.genesis_root
                && file.as_slice() == loaded.domain.genesis_file,
            "the RPC serves another chain than the global config's zero state"
        );
        let global_id = self.0.global_id().await?;
        anyhow::ensure!(
            loaded.label == format!("tos:global-id:{global_id}").into_bytes(),
            "network label does not match this chain (global id {global_id})"
        );
        Ok(())
    }

    async fn read_object(
        &self,
        loaded: &LoadedDomain,
        address: &MsgAddressInt,
    ) -> anyhow::Result<(Option<NativeRegistryObject>, u64)> {
        let info = self.0.account(address).await?;
        let now = info.sync_utime;
        match info.state {
            AccountState::Uninitialized => return Ok((None, now)),
            AccountState::Frozen => anyhow::bail!("registry account {address} is frozen"),
            AccountState::Active => {}
        }
        let code = read_single_root_boc(info.code.context("active account without code")?)?;
        let data = read_single_root_boc(info.data.context("active account without data")?)?;
        let object = verify_native_registry_account(
            &loaded.domain,
            &loaded.label,
            &loaded.code,
            address,
            &code,
            &data,
        )?;
        Ok((Some(object), now))
    }
}

/// Length of an ML-DSA-44 key-generation seed.
const CONTROLLER_SEED_BYTES: usize = 32;

/// The tag a stored controller begins with: the record kind and the suite. A
/// vault blob without it is not a registry controller, whatever its length.
const CONTROLLER_RECORD_TAG: &[u8] = b"TOS-NATIVE-REGISTRY-CONTROLLER-SEED-v1\0ML-DSA-44\0";

/// A stored controller: the tag, then the seed.
fn controller_record(seed: &[u8; CONTROLLER_SEED_BYTES]) -> Zeroizing<Vec<u8>> {
    let mut record = Zeroizing::new(Vec::with_capacity(CONTROLLER_RECORD_TAG.len() + seed.len()));
    record.extend_from_slice(CONTROLLER_RECORD_TAG);
    record.extend_from_slice(seed);
    record
}

/// The vault secret holding registry controller `name`.
fn controller_secret_id(name: &str) -> anyhow::Result<SecretId> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "a registry controller name is 1..=64 characters of [A-Za-z0-9_-]"
    );
    Ok(SecretId::from(format!("native-registry-{name}")))
}

/// Reads registry controller `name`'s seed from the vault.
pub(crate) async fn read_controller_seed(
    vault: &SecretVault,
    name: &str,
) -> anyhow::Result<Zeroizing<[u8; CONTROLLER_SEED_BYTES]>> {
    let id = controller_secret_id(name)?;
    let secret = vault
        .get(&id)
        .await
        .with_context(|| format!("read the registry controller native-registry-{name}"))?;
    let blob = secret
        .as_blob()
        .with_context(|| format!("native-registry-{name} is not a registry controller"))?;
    anyhow::ensure!(
        blob.metadata().algorithm == secrets_vault::types::algorithm::Algorithm::None,
        "native-registry-{name} is not a registry controller"
    );
    let data = blob.data().await?;
    let guard = data.lock().await?;
    let seed_bytes = guard
        .strip_prefix(CONTROLLER_RECORD_TAG)
        .filter(|rest| rest.len() == CONTROLLER_SEED_BYTES)
        .ok_or_else(|| {
            anyhow::anyhow!("native-registry-{name} is not an ML-DSA-44 registry controller")
        })?;
    let mut seed = Zeroizing::new([0u8; CONTROLLER_SEED_BYTES]);
    seed.copy_from_slice(seed_bytes);
    // An all-zero seed is a key anyone can derive; refuse it however it was stored.
    anyhow::ensure!(
        seed.iter().any(|b| *b != 0),
        "native-registry-{name} holds an all-zero seed and is refused"
    );
    Ok(seed)
}

struct VaultSigner(Arc<SecretVault>);

impl ControllerSigner for VaultSigner {
    async fn key_id(&self, name: &str) -> anyhow::Result<[u8; 32]> {
        let seed = read_controller_seed(&self.0, name).await?;
        controller_key_id(&native_public_key_from_seed(&seed))
    }

    async fn sign(&self, name: &str, action: &Cell) -> anyhow::Result<NativeControllerSignature> {
        let seed = read_controller_seed(&self.0, name).await?;
        sign_native_action(&seed, action)
    }
}

/// `new-controller`: a fresh ML-DSA-44 controller seed from the operating
/// system's CSPRNG, stored only if no controller of that name exists.
#[derive(clap::Args, Clone)]
struct NewControllerCmd {
    #[arg(long, help = "Controller name; stored as vault secret native-registry-<name>")]
    name: String,
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

impl NewControllerCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        controller_secret_id(&self.name)?;
        let (_, vault) = super::utils::load_config_vault(Path::new(config_path)).await?;
        print_view(&store_new_controller(&vault, &self.name).await?, &self.format)
    }
}

/// Generates and stores a new controller, refusing a name already in use, and
/// returns its public view.
async fn store_new_controller(
    vault: &SecretVault,
    name: &str,
) -> anyhow::Result<serde_json::Value> {
    use rand::RngCore;
    use secrets_vault::crypto::factory::{AutoCryptoFactory, CryptoFactory};
    let id = controller_secret_id(name)?;
    {
        let mut seed = Zeroizing::new([0u8; CONTROLLER_SEED_BYTES]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut());
        anyhow::ensure!(seed.iter().any(|b| *b != 0), "the CSPRNG returned an all-zero seed");
        let metadata = secrets_vault::types::metadata::Metadata::new(
            Some(&id),
            secrets_vault::types::algorithm::Algorithm::None,
            true,
        );
        let record = controller_record(&seed);
        let secret = secrets_vault::types::secret::Secret::from_raw_data(
            record.as_ref(),
            metadata,
            AutoCryptoFactory {}.new_crypto()?,
        )
        .await?;
        vault
            .put(&secret, secrets_vault::types::store_mode::StoreMode::NewOnly)
            .await
            .with_context(|| format!("store the registry controller native-registry-{name}"))?;
        vault.flush().await?;
        controller_view(name, &seed)
    }
}

/// `controller`: the public key and key id of an existing controller, as a
/// policy file names it.
#[derive(clap::Args, Clone)]
struct ControllerCmd {
    #[arg(long, help = "Controller name (vault secret native-registry-<name>)")]
    name: String,
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

impl ControllerCmd {
    async fn run(&self, config_path: &str) -> anyhow::Result<()> {
        let (_, vault) = super::utils::load_config_vault(Path::new(config_path)).await?;
        let seed = read_controller_seed(&vault, &self.name).await?;
        print_view(&controller_view(&self.name, &seed)?, &self.format)
    }
}

fn controller_view(
    name: &str,
    seed: &[u8; CONTROLLER_SEED_BYTES],
) -> anyhow::Result<serde_json::Value> {
    let public_key = native_public_key_from_seed(seed);
    Ok(serde_json::json!({
        "name": name,
        "suite": "ML-DSA-44",
        "key_id": hex::encode(controller_key_id(&public_key)?),
        "public_key": hex::encode(&public_key),
    }))
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
            let text = c.public_key.strip_prefix("0x").unwrap_or(&c.public_key);
            let public_key = hex::decode(text).context("controller public_key hex")?;
            anyhow::ensure!(
                public_key.len() == NATIVE_REGISTRY_PUBLIC_KEY_BYTES,
                "controller public_key is an ML-DSA-44 key of {NATIVE_REGISTRY_PUBLIC_KEY_BYTES} \
                 bytes, not {}",
                public_key.len()
            );
            Ok(NativePolicyController { public_key, weight: c.weight, purposes: c.purposes })
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
            // The contract compares with the time it executes the message, which
            // is later than the view `now` was read from.
            let earliest = now
                .checked_add(policy.recovery_timelock)
                .and_then(|t| t.checked_add(RECOVERY_SUBMISSION_MARGIN_SECS))
                .context("recovery time overflows")?;
            ensure!(
                *execute_after >= earliest,
                "--execute-after must be at least chain time + the current recovery timelock + \
                 {RECOVERY_SUBMISSION_MARGIN_SECS} s ({earliest})"
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
            // The owner Agent forwards to an address it derives in its own
            // workchain; a Capability elsewhere would never receive the action.
            ensure!(
                cap_address.workchain_id() == agent_address.workchain_id(),
                "--capability is in another workchain than its owner Agent"
            );
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
                    let (receiver_address, receiver) =
                        objects.new_owner.context("--new-owner is required")?;
                    ensure!(
                        receiver_address.workchain_id() == agent_address.workchain_id(),
                        "--new-owner is in another workchain than the current owner"
                    );
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

/// The key ids of the named controllers, for the threshold and possession
/// checks that run before anything is signed.
async fn public_keys<S: ControllerSigner>(
    signer: &S,
    names: &[String],
) -> anyhow::Result<Vec<[u8; 32]>> {
    let mut keys = Vec::with_capacity(names.len());
    for name in names {
        keys.push(signer.key_id(name).await?);
    }
    Ok(keys)
}

/// One signature per named controller, each from the key whose id the checks
/// were run against.
async fn sign_all<S: ControllerSigner>(
    signer: &S,
    names: &[String],
    keys: &[[u8; 32]],
    action: &Cell,
) -> anyhow::Result<Vec<NativeControllerSignature>> {
    let mut out = Vec::with_capacity(names.len());
    for (name, key_id) in names.iter().zip(keys) {
        let signature = signer.sign(name, action).await?;
        anyhow::ensure!(
            signature.key_id()? == *key_id,
            "controller {name} signed with a key other than the one checked"
        );
        out.push(signature);
    }
    Ok(out)
}

/// Build and sign an Agent registration. Every read and refusal happens before
/// the first signature; nothing is sent.
async fn prepare_register<C: RegistryChain, S: ControllerSigner>(
    chain: &C,
    signer: &S,
    loaded: &LoadedDomain,
    policy: &NativePolicy,
    nonce: [u8; 32],
    workchain: i8,
    signer_names: &[String],
) -> anyhow::Result<serde_json::Value> {
    chain.check_chain(loaded).await?;
    let registration = build_native_agent_registration(&loaded.domain, nonce, policy)?;
    let (init, address) = build_native_registry_deployment(
        &loaded.domain,
        1,
        registration.object_id,
        workchain,
        &loaded.label,
        &loaded.code,
    )?;
    let (existing, _) = chain.read_object(loaded, &address).await?;
    anyhow::ensure!(existing.is_none(), "an account already exists at {address}");
    let keys = public_keys(signer, signer_names).await?;
    check_native_possession(policy, &keys)?;
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
    let signatures = sign_all(signer, signer_names, &keys, &action).await?;
    let body = build_native_submission(&loaded.domain, &action, 1, &signatures, &[])?;
    let state_init = init.write_to_new_cell()?.into_cell()?;
    Ok(serde_json::json!({
        "kind": "register-agent",
        "object_id": hex::encode(registration.object_id),
        "destination": address.to_string(),
        "final_target": address.to_string(),
        "action_hash": hex::encode(action.repr_hash().as_slice()),
        "generation": generation,
        "sequence": sequence,
        "state_init_boc": b64(&state_init)?,
        "body_boc": b64(&body)?,
    }))
}

/// The address a Capability registration under `agent` deploys.
fn registration_address(
    loaded: &LoadedDomain,
    agent_address: &MsgAddressInt,
    agent_id: [u8; 32],
    input: &ActionInput,
) -> anyhow::Result<Option<MsgAddressInt>> {
    let ActionInput::RegisterCapability { object_nonce, version, manifest } = input else {
        return Ok(None);
    };
    let registration = build_native_capability_registration(
        &loaded.domain,
        *object_nonce,
        agent_id,
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
    Ok(Some(address))
}

/// Read every object an action touches, refuse before signing, then sign.
/// Nothing is sent.
#[allow(clippy::too_many_arguments)]
async fn prepare_action<C: RegistryChain, S: ControllerSigner>(
    chain: &C,
    signer: &S,
    loaded: &LoadedDomain,
    kind: ActionKind,
    input: &ActionInput,
    nonce: [u8; 32],
    agent_address: &MsgAddressInt,
    capability_address: Option<&MsgAddressInt>,
    new_owner_address: Option<&MsgAddressInt>,
    signer_names: &[String],
    counter_names: &[String],
) -> anyhow::Result<serde_json::Value> {
    chain.check_chain(loaded).await?;
    let (agent, now) = chain.read_object(loaded, agent_address).await?;
    let agent = agent.context("no registry account at --agent")?;
    // A registration always reads the address it derives, whether or not
    // --capability names it.
    let derived = registration_address(loaded, agent_address, agent.object_id, input)?;
    let capability_address = match (&derived, capability_address) {
        (Some(derived), Some(given)) => {
            anyhow::ensure!(
                given == derived,
                "--capability is not the address this registration derives"
            );
            Some(derived.clone())
        }
        (Some(derived), None) => Some(derived.clone()),
        (None, given) => given.cloned(),
    };
    let capability = match &capability_address {
        Some(address) => Some(chain.read_object(loaded, address).await?.0),
        None => None,
    };
    let new_owner = match new_owner_address {
        Some(address) => Some(
            chain
                .read_object(loaded, address)
                .await?
                .0
                .context("no registry account at --new-owner")?,
        ),
        None => None,
    };
    let objects = ActionObjects {
        agent: (agent_address, &agent),
        capability: capability_address
            .as_ref()
            .zip(capability.as_ref())
            .map(|(address, object)| (address, object.as_ref())),
        new_owner: new_owner_address.zip(new_owner.as_ref()),
    };
    let signer_keys = public_keys(signer, signer_names).await?;
    let counter_keys = public_keys(signer, counter_names).await?;
    let planned =
        plan_action(loaded, kind, input, &objects, &signer_keys, &counter_keys, nonce, now)?;
    let authority = sign_all(signer, signer_names, &signer_keys, &planned.action).await?;
    let counterparty = sign_all(signer, counter_names, &counter_keys, &planned.action).await?;
    let body =
        build_native_submission(&loaded.domain, &planned.action, 1, &authority, &counterparty)?;
    Ok(serde_json::json!({
        "kind": kind.to_possible_value_name(),
        "kind_code": planned.kind,
        "target_id": hex::encode(planned.target_id),
        "destination": planned.destination.to_string(),
        "final_target": planned.final_target.to_string(),
        "action_hash": hex::encode(planned.action.repr_hash().as_slice()),
        "generation": planned.generation,
        "sequence": planned.sequence,
        "predecessor": hex::encode(planned.predecessor),
        "chain_time": now,
        "body_boc": b64(&body)?,
    }))
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
        let view = prepare_register(
            &RpcChain(rpc.as_ref()),
            &VaultSigner(vault),
            &loaded,
            &policy,
            nonce,
            self.workchain,
            &self.signers,
        )
        .await?;
        print_view(&view, &self.format)
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
        let parse = |value: &Option<String>, what: &str| {
            value
                .as_deref()
                .map(str::parse::<MsgAddressInt>)
                .transpose()
                .with_context(|| format!("invalid {what}"))
        };
        let agent_address: MsgAddressInt = self.agent.parse().context("invalid --agent")?;
        let capability_address = parse(&self.capability, "--capability")?;
        let new_owner_address = parse(&self.new_owner, "--new-owner")?;
        let (_, vault, rpc) = load_config_vault_rpc_client(Path::new(config_path)).await?;
        let view = prepare_action(
            &RpcChain(rpc.as_ref()),
            &VaultSigner(vault),
            &loaded,
            self.kind,
            &input,
            nonce,
            &agent_address,
            capability_address.as_ref(),
            new_owner_address.as_ref(),
            &self.signers,
            &self.counter_signers,
        )
        .await?;
        print_view(&view, &self.format)
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
        let chain = RpcChain(rpc.as_ref());
        chain.check_chain(&loaded).await?;
        let address: MsgAddressInt = self.address.parse().context("invalid --address")?;
        let (object, now) = chain.read_object(&loaded, &address).await?;
        let object = object.context("no registry account at --address")?;
        let mut view = object_view(&address, &object);
        if let Some(map) = view.as_object_mut() {
            map.insert("chain_time".into(), now.into());
        }
        print_view(&view, &self.format)
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

    /// The public key of a deliberately public deterministic test fixture,
    /// never an operational key.
    fn public(seed: u8) -> Vec<u8> {
        native_public_key_from_seed(&[seed; 32])
    }

    /// The key id of fixture controller `seed`.
    fn key(seed: u8) -> [u8; 32] {
        controller_key_id(&public(seed)).expect("fixture key id")
    }

    fn one_key_policy(seed: u8, timelock: u64) -> NativePolicy {
        NativePolicy {
            threshold: 1,
            recovery_threshold: 1,
            recovery_timelock: timelock,
            controllers: vec![NativePolicyController {
                public_key: public(seed),
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

    /// A controller created in a real file vault reads back as the same key,
    /// signs a verifiable registry signature, and cannot be overwritten; a
    /// secret that is not a controller seed, and a malformed name, are refused.
    #[tokio::test]
    async fn controllers_live_in_the_vault_as_ml_dsa_44_seeds() {
        let vault = super::super::utils::test_vault::with_ed25519_keys(&[(
            "native-registry-ed25519",
            true,
        )])
        .await;
        let vault = vault.open().await;
        let view = store_new_controller(&vault, "alice").await.expect("create controller");
        let public_key =
            hex::decode(view["public_key"].as_str().expect("public key")).expect("hex");
        assert_eq!(public_key.len(), NATIVE_REGISTRY_PUBLIC_KEY_BYTES);
        let signer = VaultSigner(vault.clone());
        let key_id = signer.key_id("alice").await.expect("key id");
        assert_eq!(hex::encode(key_id), view["key_id"].as_str().expect("key id"));
        assert_eq!(controller_key_id(&public_key).expect("derived id"), key_id);

        let action = Cell::default();
        let signature = signer.sign("alice", &action).await.expect("sign");
        assert_eq!(signature.public_key, public_key);
        verify_native_signature(&public_key, &signature.signature, action.repr_hash().as_array())
            .expect("a registry signature");

        let again = store_new_controller(&vault, "alice").await;
        assert!(again.is_err(), "an existing controller was overwritten");
        assert_eq!(signer.key_id("alice").await.expect("key id"), key_id);

        let refused = signer.key_id("ed25519").await.err().map(|e| e.to_string());
        assert!(
            refused.as_deref().is_some_and(|e| e.contains("not a registry controller")),
            "an Ed25519 key was read as a controller: {refused:?}"
        );
        assert!(signer.key_id("missing").await.is_err());

        // A blob of the seed's length without the controller tag, a tagged
        // all-zero seed, and a tagged seed of the wrong length are refused.
        use secrets_vault::crypto::factory::{AutoCryptoFactory, CryptoFactory};
        let put_blob = |name: &'static str, bytes: Vec<u8>| {
            let vault = vault.clone();
            async move {
                let id = controller_secret_id(name).expect("name");
                let metadata = secrets_vault::types::metadata::Metadata::new(
                    Some(&id),
                    secrets_vault::types::algorithm::Algorithm::None,
                    true,
                );
                let secret = secrets_vault::types::secret::Secret::from_raw_data(
                    &bytes,
                    metadata,
                    AutoCryptoFactory {}.new_crypto().expect("crypto"),
                )
                .await
                .expect("secret");
                vault
                    .put(&secret, secrets_vault::types::store_mode::StoreMode::NewOnly)
                    .await
                    .expect("store blob");
            }
        };
        put_blob("plain", vec![7u8; CONTROLLER_SEED_BYTES]).await;
        put_blob("zero", controller_record(&[0u8; CONTROLLER_SEED_BYTES]).to_vec()).await;
        let mut short = controller_record(&[7u8; CONTROLLER_SEED_BYTES]).to_vec();
        short.pop();
        put_blob("short", short).await;
        for (name, reason) in [
            ("plain", "not an ML-DSA-44 registry controller"),
            ("zero", "all-zero seed"),
            ("short", "not an ML-DSA-44 registry controller"),
        ] {
            let refused = signer.key_id(name).await.err().map(|e| format!("{e:#}"));
            assert!(
                refused.as_deref().is_some_and(|e| e.contains(reason)),
                "{name} was read as a controller: {refused:?}"
            );
            assert!(signer.sign(name, &action).await.is_err(), "{name} signed");
        }
        for name in ["", "with space", "../escape", &"x".repeat(65)] {
            assert!(controller_secret_id(name).is_err(), "name {name:?} accepted");
        }
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
            hex::encode(public(1))
        );
        assert_eq!(parse_policy(good.as_bytes()).expect("policy"), one_key_policy(1, 60));
        // A key of any other length, an Ed25519-sized one among them, is refused.
        let ed25519_sized = good.replacen(&hex::encode(public(1)), &hex::encode([7u8; 32]), 1);
        assert!(
            parse_policy(ed25519_sized.as_bytes())
                .err()
                .is_some_and(|e| e.to_string().contains("ML-DSA-44"))
        );
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
        // Chain time 1000 + timelock 60 + submission margin 300.
        assert!(
            plan(ActionKind::InitiateRecovery, initiate(1_359), &objects, &[1], &[4], 1_000)
                .is_err()
        );
        plan(ActionKind::InitiateRecovery, initiate(1_360), &objects, &[1], &[4], 1_000)
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

    #[test]
    fn capability_and_receiver_must_share_the_owner_workchain() {
        let (aa, ba) = (address(1), address(2));
        let ca_elsewhere: MsgAddressInt =
            format!("-1:{}", hex::encode([0xc0; 32])).parse().expect("address");
        let b_elsewhere: MsgAddressInt =
            format!("-1:{}", hex::encode([2; 32])).parse().expect("address");
        let (a, b) = (agent(1, false, 0), agent(2, false, 0));
        let cap = capability(1, false, 1);
        let add = || ActionInput::AddVersion { version: b"1.1.0".to_vec(), manifest: [0x5f; 32] };
        let foreign_cap = ActionObjects {
            agent: (&aa, &a),
            capability: Some((&ca_elsewhere, Some(&cap))),
            new_owner: None,
        };
        assert!(plan(ActionKind::AddVersion, add(), &foreign_cap, &[1], &[], 0).is_err());
        let ca = address(0xc0);
        let foreign_receiver = ActionObjects {
            agent: (&aa, &a),
            capability: Some((&ca, Some(&cap))),
            new_owner: Some((&b_elsewhere, &b)),
        };
        assert!(
            plan(
                ActionKind::TransferCapability,
                ActionInput::TransferCapability,
                &foreign_receiver,
                &[1],
                &[2],
                0
            )
            .is_err()
        );
        let same = ActionObjects {
            agent: (&aa, &a),
            capability: Some((&ca, Some(&cap))),
            new_owner: Some((&ba, &b)),
        };
        plan(ActionKind::TransferCapability, ActionInput::TransferCapability, &same, &[1], &[2], 0)
            .expect("same workchain");
    }

    /// A chain view with fixed answers that records nothing it is not asked.
    struct FakeChain {
        serves_domain: bool,
        objects: std::collections::HashMap<String, NativeRegistryObject>,
        now: u64,
    }

    impl RegistryChain for FakeChain {
        async fn check_chain(&self, _: &LoadedDomain) -> anyhow::Result<()> {
            anyhow::ensure!(self.serves_domain, "another chain");
            Ok(())
        }
        async fn read_object(
            &self,
            _: &LoadedDomain,
            address: &MsgAddressInt,
        ) -> anyhow::Result<(Option<NativeRegistryObject>, u64)> {
            Ok((self.objects.get(&address.to_string()).cloned(), self.now))
        }
    }

    /// Deterministic fixture keys by name, counting every signature produced.
    struct CountingSigner {
        signatures: std::sync::atomic::AtomicUsize,
    }

    impl CountingSigner {
        fn new() -> Self {
            Self { signatures: std::sync::atomic::AtomicUsize::new(0) }
        }
        fn count(&self) -> usize {
            self.signatures.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn seed(name: &str) -> anyhow::Result<u8> {
            name.strip_prefix("key-").context("fixture key name")?.parse().context("seed")
        }
    }

    impl ControllerSigner for CountingSigner {
        async fn key_id(&self, name: &str) -> anyhow::Result<[u8; 32]> {
            Ok(key(Self::seed(name)?))
        }
        async fn sign(
            &self,
            name: &str,
            action: &Cell,
        ) -> anyhow::Result<NativeControllerSignature> {
            self.signatures.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            sign_native_action(&[Self::seed(name)?; 32], action)
        }
    }

    fn names(seeds: &[u8]) -> Vec<String> {
        seeds.iter().map(|s| format!("key-{s}")).collect()
    }

    fn chain_with(objects: &[(&MsgAddressInt, NativeRegistryObject)], now: u64) -> FakeChain {
        FakeChain {
            serves_domain: true,
            objects: objects.iter().map(|(a, o)| (a.to_string(), o.clone())).collect(),
            now,
        }
    }

    async fn action(
        chain: &FakeChain,
        signer: &CountingSigner,
        kind: ActionKind,
        input: ActionInput,
        capability: Option<&MsgAddressInt>,
        counter: &[u8],
    ) -> anyhow::Result<serde_json::Value> {
        prepare_action(
            chain,
            signer,
            &loaded(),
            kind,
            &input,
            [0x77; 32],
            &address(1),
            capability,
            None,
            &names(&[1]),
            &names(counter),
        )
        .await
    }

    #[tokio::test]
    async fn every_refusal_happens_before_any_signature() {
        let aa = address(1);
        let delegate = || ActionInput::Delegate([0x71; 32]);
        // Another chain.
        let signer = CountingSigner::new();
        let mut chain = chain_with(&[(&aa, agent(1, false, 0))], 0);
        chain.serves_domain = false;
        assert!(
            action(&chain, &signer, ActionKind::Delegate, delegate(), None, &[]).await.is_err()
        );
        // No account at --agent.
        let empty = chain_with(&[], 0);
        assert!(
            action(&empty, &signer, ActionKind::Delegate, delegate(), None, &[]).await.is_err()
        );
        // Revoked Agent; early recovery completion by chain time.
        let dead = chain_with(&[(&aa, agent(1, true, 0))], 0);
        assert!(action(&dead, &signer, ActionKind::Delegate, delegate(), None, &[]).await.is_err());
        let stored = build_policy(&one_key_policy(1, 60)).expect("policy");
        let pending = NativePendingRecovery {
            initiation: [0x99; 32],
            old_policy_hash: *stored.repr_hash().as_array(),
            execute_after: 2_000,
            policy: build_policy(&one_key_policy(4, 60)).expect("policy"),
        };
        let early = chain_with(&[(&aa, agent_with(1, false, 0, Some(pending)))], 1_999);
        assert!(
            action(
                &early,
                &signer,
                ActionKind::CompleteRecovery,
                ActionInput::CompleteRecovery,
                None,
                &[]
            )
            .await
            .is_err()
        );
        assert_eq!(signer.count(), 0, "nothing was signed for a refused action");
        // The same completion at chain time 2000 signs exactly once.
        let ready = FakeChain { now: 2_000, ..early };
        let view = action(
            &ready,
            &signer,
            ActionKind::CompleteRecovery,
            ActionInput::CompleteRecovery,
            None,
            &[],
        )
        .await
        .expect("complete");
        assert_eq!(signer.count(), 1);
        assert_eq!(view["chain_time"], 2_000);
        assert_eq!(view["generation"], 2);
    }

    #[tokio::test]
    async fn registration_reads_the_derived_address_even_without_capability() {
        let aa = address(1);
        let a = agent(1, false, 0);
        let input = || ActionInput::RegisterCapability {
            object_nonce: [0x81; 32],
            version: b"1.0.0".to_vec(),
            manifest: [0x5e; 32],
        };
        let derived = registration_address(&loaded(), &aa, a.object_id, &input())
            .expect("derive")
            .expect("address");
        let signer = CountingSigner::new();
        let occupied = chain_with(&[(&aa, a.clone()), (&derived, capability(1, false, 1))], 0);
        assert!(
            action(&occupied, &signer, ActionKind::RegisterCapability, input(), None, &[])
                .await
                .is_err()
        );
        let other = address(0xee);
        let free = chain_with(&[(&aa, a)], 0);
        assert!(
            action(&free, &signer, ActionKind::RegisterCapability, input(), Some(&other), &[])
                .await
                .is_err()
        );
        assert_eq!(signer.count(), 0);
        let view = action(&free, &signer, ActionKind::RegisterCapability, input(), None, &[])
            .await
            .expect("register");
        assert_eq!(view["final_target"], derived.to_string());
        assert_eq!(view["destination"], aa.to_string());
        assert_eq!(signer.count(), 1);
    }

    #[tokio::test]
    async fn agent_registration_refuses_an_occupied_address_before_signing() {
        let policy = one_key_policy(1, 60);
        let registration =
            build_native_agent_registration(&loaded().domain, [0x61; 32], &policy).expect("reg");
        let l = loaded();
        let (_, address) = build_native_registry_deployment(
            &l.domain,
            1,
            registration.object_id,
            0,
            &l.label,
            &l.code,
        )
        .expect("address");
        let signer = CountingSigner::new();
        let occupied = chain_with(&[(&address, agent(1, false, 0))], 0);
        assert!(
            prepare_register(&occupied, &signer, &l, &policy, [0x61; 32], 0, &names(&[1]))
                .await
                .is_err()
        );
        // A signer set that is not exactly the policy's controllers.
        let free = chain_with(&[], 0);
        assert!(
            prepare_register(&free, &signer, &l, &policy, [0x61; 32], 0, &names(&[2]))
                .await
                .is_err()
        );
        assert_eq!(signer.count(), 0);
        let view = prepare_register(&free, &signer, &l, &policy, [0x61; 32], 0, &names(&[1]))
            .await
            .expect("register");
        assert_eq!(view["destination"], address.to_string());
        assert_eq!(signer.count(), 1);
    }

    /// Raw RPC answers for the production `RpcChain`: zero state, global id and
    /// account snapshots by address.
    struct FakeSource {
        zero: (Vec<u8>, Vec<u8>),
        global_id: u32,
        accounts: std::collections::HashMap<String, (Cell, Cell)>,
        now: u64,
    }

    impl ChainSource for FakeSource {
        async fn zero_state(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
            Ok(self.zero.clone())
        }
        async fn global_id(&self) -> anyhow::Result<u32> {
            Ok(self.global_id)
        }
        async fn account(&self, address: &MsgAddressInt) -> anyhow::Result<AccountSnapshot> {
            Ok(match self.accounts.get(&address.to_string()) {
                None => AccountSnapshot {
                    state: AccountState::Uninitialized,
                    code: None,
                    data: None,
                    sync_utime: self.now,
                },
                Some((code, data)) => AccountSnapshot {
                    state: AccountState::Active,
                    code: Some(write_boc(code)?),
                    data: Some(write_boc(data)?),
                    sync_utime: self.now,
                },
            })
        }
    }

    /// A registered Agent account exactly as the contract stores it: the
    /// deployment data with its state flag set and an NVS1 state attached.
    fn registered_agent_account(l: &LoadedDomain, seed: u8) -> (MsgAddressInt, [u8; 32], Cell) {
        use chain_block::{BuilderData, IBitstring, SliceData};
        let policy = one_key_policy(seed, 60);
        let registration =
            build_native_agent_registration(&l.domain, [seed; 32], &policy).expect("reg");
        let (init, address) = build_native_registry_deployment(
            &l.domain,
            1,
            registration.object_id,
            0,
            &l.label,
            &l.code,
        )
        .expect("deployment");
        let initial = init.data.expect("data");
        let mut s = SliceData::load_cell(initial).expect("slice");
        let header = s.get_next_bits(32 + 16 + 8 + 256).expect("header");
        let config = s.checked_drain_reference().expect("config");
        let mut delegations = BuilderData::new();
        delegations.append_u16(0).expect("count").append_bit_zero().expect("dict");
        let mut recovery = BuilderData::new();
        recovery.append_bit_zero().expect("recovery");
        let mut state = BuilderData::new();
        state
            .append_u32(0x4e56_5331)
            .expect("magic")
            .append_u16(1)
            .expect("schema")
            .append_u8(1)
            .expect("kind")
            .append_bit_zero()
            .expect("tombstone")
            .append_u64(1)
            .expect("generation")
            .append_u64(1)
            .expect("sequence")
            .append_raw(&[0x0a; 32], 256)
            .expect("action");
        state.checked_append_reference(build_policy(&policy).expect("policy")).expect("ref");
        state.checked_append_reference(delegations.into_cell().expect("cell")).expect("ref");
        state.checked_append_reference(recovery.into_cell().expect("cell")).expect("ref");
        let mut data = BuilderData::new();
        data.append_raw(&header, 32 + 16 + 8 + 256).expect("header");
        data.checked_append_reference(config).expect("config");
        data.append_bit_one().expect("has state");
        data.checked_append_reference(state.into_cell().expect("state")).expect("state ref");
        (address, registration.object_id, data.into_cell().expect("data"))
    }

    fn source(l: &LoadedDomain, accounts: &[(&MsgAddressInt, Cell, Cell)]) -> FakeSource {
        FakeSource {
            zero: (l.domain.genesis_root.to_vec(), l.domain.genesis_file.to_vec()),
            global_id: 2,
            accounts: accounts
                .iter()
                .map(|(a, code, data)| (a.to_string(), (code.clone(), data.clone())))
                .collect(),
            now: 1_000,
        }
    }

    async fn delegate_through(
        source: &FakeSource,
        signer: &CountingSigner,
        agent: &MsgAddressInt,
        seed: u8,
    ) -> anyhow::Result<serde_json::Value> {
        prepare_action(
            &RpcChain(source),
            signer,
            &loaded(),
            ActionKind::Delegate,
            &ActionInput::Delegate([0x71; 32]),
            [0x77; 32],
            agent,
            None,
            None,
            &names(&[seed]),
            &[],
        )
        .await
    }

    #[tokio::test]
    async fn production_reads_verify_every_account_before_signing() {
        let l = loaded();
        let (a_address, a_id, a_data) = registered_agent_account(&l, 1);
        let (b_address, _, b_data) = registered_agent_account(&l, 2);
        let signer = CountingSigner::new();

        // The real account, read and verified through the production adapter.
        let good = source(&l, &[(&a_address, l.code.clone(), a_data.clone())]);
        let view = delegate_through(&good, &signer, &a_address, 1).await.expect("delegate");
        assert_eq!(view["target_id"], hex::encode(a_id));
        assert_eq!(view["chain_time"], 1_000);
        assert_eq!(signer.count(), 1);

        // Foreign code at the address.
        let foreign = source(&l, &[(&a_address, Cell::default(), a_data.clone())]);
        let error = delegate_through(&foreign, &signer, &a_address, 1).await.expect_err("code");
        assert!(error.to_string().contains("release code"), "{error:#}");
        // Another object's data at the address.
        let swapped = source(&l, &[(&a_address, l.code.clone(), b_data)]);
        let error = delegate_through(&swapped, &signer, &a_address, 1).await.expect_err("address");
        assert!(error.to_string().contains("does not derive"), "{error:#}");
        // Another zero state, and another global id.
        let mut other_chain = source(&l, &[(&a_address, l.code.clone(), a_data.clone())]);
        other_chain.zero.1[0] ^= 1;
        let error = delegate_through(&other_chain, &signer, &a_address, 1).await.expect_err("zero");
        assert!(error.to_string().contains("another chain"), "{error:#}");
        let mut other_id = source(&l, &[(&a_address, l.code.clone(), a_data)]);
        other_id.global_id = 1;
        let error = delegate_through(&other_id, &signer, &a_address, 1).await.expect_err("label");
        assert!(error.to_string().contains("network label"), "{error:#}");
        // No account at all.
        let empty = source(&l, &[]);
        assert!(delegate_through(&empty, &signer, &b_address, 2).await.is_err());
        assert_eq!(signer.count(), 1, "no refused read produced a signature");
    }
}
