/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! `tosctl shield`: a client for the shielded pool.
//!
//! The pool publishes no events and keeps no index, so a client is its own
//! indexer: it replays the pool's history into a local ledger, scans the
//! outputs for payloads it can open, and keeps what it found under a key
//! only the pool master derives. This release initialises an instance,
//! synchronises it, shows its balance, issues receiving descriptors and
//! deposits. Spending comes later and will require verified state.
//!
//! The pool master is a separate Vault secret derived from the mnemonic. It
//! derives every shielded key and cannot sign an ordinary transaction, so a
//! shielded instance never needs the wallet's signing key and the wallet
//! never needs to give it up.

mod chain;
mod profile;
mod spend;
mod store;

use anyhow::Context;
use base64::Engine;
use chain_block::{MsgAddressInt, write_boc};
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use chain_rpc_client::v2::data_models::AccountState;
use colored::Colorize;
use common::app_config::AppConfig;
use common::task_cancellation::CancellationCtx;
use contracts::shielded_pool::{DepositBody, OUTPUT_DATA_BYTES};
use contracts::wallet::send_fees;
use contracts::{DefaultChainProvider, Wallet};
use rand::RngCore;
use secrets_vault::crypto::factory::{AutoCryptoFactory, CryptoFactory};
use secrets_vault::types::secret_id::SecretId;
use secrets_vault::vault::SecretVault;
use shielded_pool_circuit::field::{Fr, fr_from_be, fr_to_be, is_canonical};
use shielded_pool_circuit::{imt, notes, wire};
use shielded_pool_wallet::delivery::{self, Kind, Plaintext};
use shielded_pool_wallet::descriptor::Descriptor;
use shielded_pool_wallet::import::Imported;
use shielded_pool_wallet::keys::{PoolInstance, fr_be32, pool_master};
use shielded_pool_wallet::ledger::{Ledger, Payout, PendingRecovery, Snapshot};
use shielded_pool_wallet::scan::{self, Recovered};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

use super::utils::{
    SEND_TIMEOUT, get_wallet_config, load_config_vault_rpc_client, make_wallet,
    wait_for_seqno_change, wallet_info,
};
use super::vote_cmd::{pinned_wallet_reserve, sender_can_pay};
use chain::Head;
use profile::{Network, ObservedPool, Profile};
use store::{
    Binding, ChainIdentity, Cursor, JournalRecord, Keys, PersistedDiagnostic, PersistedLedger,
    PersistedNote, PersistedNullifierLeaf, PersistedPayout, PersistedPendingRecovery,
    PersistedPoolConfig, PersistedState, Pointer, STATE_FORMAT_VERSION, Store, coins, coins_value,
};

const EXPERIMENTAL: &str = "EXPERIMENTAL: the shielded client has not passed its end-to-end gate; use it on an isolated \
     network or at your own risk";
const NANOTOS_PER_TOS: u128 = 1_000_000_000;
/// Diagnostics kept in the state, newest last.
const MAX_DIAGNOSTICS: usize = 256;
/// What a deposit leaves in the paying wallet for its own fees.

#[derive(clap::Args, Clone)]
#[command(about = "Shielded pool: private balances and transfers (experimental)")]
pub struct ShieldCmd {
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
    action: ShieldAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum ShieldAction {
    /// Create a shielded instance for one pool from a mnemonic
    Init(InitCmd),
    /// Replay the pool's history and scan it for this instance's notes
    Sync(SyncCmd),
    /// Show the balance and the state of pending deposits
    Balance(BalanceCmd),
    /// Issue a receiving descriptor at the next unused index
    Address(AddressCmd),
    /// Deposit from an ordinary wallet into a new shielded note
    Deposit(DepositCmd),
    /// Withdraw a denomination from the pool to an ordinary address
    Withdraw(spend::WithdrawCmd),
    /// Send to another shielded descriptor
    Send(spend::SendCmd),
}

impl ShieldCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let config_path = Path::new(&self.config);
        match &self.action {
            ShieldAction::Init(cmd) => cmd.run(config_path).await,
            ShieldAction::Sync(cmd) => cmd.run(config_path).await,
            ShieldAction::Balance(cmd) => cmd.run(config_path).await,
            ShieldAction::Address(cmd) => cmd.run(config_path).await,
            ShieldAction::Deposit(cmd) => cmd.run(config_path).await,
            ShieldAction::Withdraw(cmd) => cmd.run(config_path).await,
            ShieldAction::Send(cmd) => cmd.run(config_path).await,
        }
    }
}

/// How the pool is read: through the local proof verifier, or from an RPC
/// endpoint without proof.
#[derive(clap::Args, Clone)]
pub struct ReadMode {
    /// Read the pool from the RPC endpoint without proof. For isolated local
    /// testing only: the state is marked UNVERIFIED and spends will refuse it.
    #[arg(long)]
    unverified_rpc: bool,
}

impl ReadMode {
    async fn head(
        &self,
        config: &AppConfig,
        rpc: &ClientJsonRpc,
        pool: &MsgAddressInt,
    ) -> anyhow::Result<Head> {
        if self.unverified_rpc {
            eprintln!(
                "{} the pool is read from the RPC endpoint without proof; the result is UNVERIFIED",
                "warning:".yellow().bold()
            );
            return chain::read_head_unverified(rpc, pool).await;
        }
        let verifier = config.proof_verifier.as_ref().context(
            "proof_verifier is not configured; configure the local proof verifier, or pass \
             --unverified-rpc for isolated local testing",
        )?;
        chain::read_head_verified(verifier, pool).await
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Create a shielded instance for one pool from a mnemonic")]
pub struct InitCmd {
    /// Name of the instance; also names the Vault secret `shield-<name>`
    #[arg(short = 'n', long)]
    name: String,
    /// Profile file naming the network, the pool and its code hash
    #[arg(long)]
    profile: PathBuf,
    /// Read the mnemonic from a file you own with mode 0600
    #[arg(long)]
    mnemonic_file: Option<PathBuf>,
    /// Read the mnemonic from an inherited descriptor (0 for standard input)
    #[arg(long)]
    mnemonic_fd: Option<i32>,
    /// Allow a pool on the public testnet (global id 2)
    #[arg(long)]
    allow_testnet_pool: bool,
    #[command(flatten)]
    read: ReadMode,
}

impl InitCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        eprintln!("{}", EXPERIMENTAL.yellow());
        let profile = Profile::load(&self.profile)?;
        let network = Network::of(profile.global_id)?;
        network.gate(self.allow_testnet_pool)?;
        if network == Network::Testnet {
            eprintln!(
                "{} the testnet pool is gated and may be reset without notice",
                "note:".bold()
            );
        }
        let pool = profile.address()?;
        let root = store::shield_root(config_path);
        let pointer_path = store::pointer_path(&root, &self.name)?;
        // Held until the pointer is written: two initialisations of one name
        // may be on different pools and so hold different instance locks.
        let _name_lock = store::NameLock::take(&root, &self.name)?;
        anyhow::ensure!(
            !pointer_path.exists(),
            "an instance named {:?} already exists ({})",
            self.name,
            pointer_path.display()
        );

        let (config, vault, rpc) = load_config_vault_rpc_client(config_path).await?;
        let head = self.read.head(&config, &rpc, &pool).await?;
        anyhow::ensure!(
            head.global_id == profile.global_id,
            "the chain reports global id {} but the profile names {}",
            head.global_id,
            profile.global_id
        );
        profile::check_pins(
            &profile,
            network,
            &ObservedPool { code_hash: head.code_hash, state: &head.state },
        )?;

        let master = read_pool_master(self.mnemonic_file.as_deref(), self.mnemonic_fd)?;
        let domain = wire::execution_domain(profile.global_id, &profile.account_id()?);
        let keys = Keys::derive(&master, &fr_be32(domain));
        let binding = Binding { global_id: profile.global_id, pool_address: pool.to_string() };
        let store = Store::open(&root, &keys, binding.clone())?;
        if let Some(other) = store::other_pointer_naming(&root, &keys.directory_name(), &self.name)?
        {
            anyhow::bail!(
                "this mnemonic already has an instance on this pool, named {other:?}; one \
                 instance per mnemonic and pool, whatever it is named"
            );
        }

        // Three durable writes, each idempotent for the same mnemonic, name and
        // profile, so an initialisation that stopped after any of them resumes
        // on the next run: the Vault secret, the sealed state, the pointer. The
        // pointer is last; its absence is what makes a retry a resume.
        let secret_resumed = ensure_pool_master(&vault, &self.name, &master).await?;
        drop(master);
        let (state, state_resumed) = resume_or_create_state(
            &store,
            &keys,
            &binding,
            head.chain.clone(),
            pool_config_of(&head),
            &profile,
        )?;
        let resumed = secret_resumed || state_resumed;
        // The pointer is a cache of the sealed state, so it names the chain the
        // state was built against, which on a resume may not be this run's head.
        Pointer {
            schema: store::POINTER_SCHEMA.to_owned(),
            profile,
            binding,
            chain: state.chain.clone(),
            directory: keys.directory_name(),
        }
        .save(&pointer_path)?;
        if resumed {
            eprintln!(
                "{} resumed an initialisation of {:?} that had stopped before its pointer was \
                 written",
                "note:".bold(),
                self.name
            );
        }
        println!(
            "{} shielded instance {:?} created for pool {} on {} (global id {}); state in {}",
            "OK".green().bold(),
            self.name,
            pool,
            network.label(),
            head.global_id,
            store.directory().display()
        );
        println!("Run `tosctl shield sync --name {}` to replay the pool's history.", self.name);
        Ok(())
    }
}

/// Reads the mnemonic through a protected channel and derives the pool
/// master. Nothing of the mnemonic or the seed survives the call.
fn read_pool_master(file: Option<&Path>, fd: Option<i32>) -> anyhow::Result<Zeroizing<[u8; 64]>> {
    let source = secrets_vault::secret_input::select_source(
        file,
        fd,
        "--mnemonic-file",
        "--mnemonic-fd",
        "Mnemonic (hidden): ",
    )?;
    let text = secrets_vault::secret_input::read_secret(&source)?;
    let trimmed = secrets_vault::secret_input::trim_ascii(&text);
    let phrase =
        std::str::from_utf8(trimmed).map_err(|_| anyhow::anyhow!("mnemonic is not valid UTF-8"))?;
    let mut seed = Zeroizing::new(super::tos_mnemonic::private_seed(phrase, "")?);
    let master = Zeroizing::new(pool_master(&seed));
    seed.zeroize();
    Ok(master)
}

fn secret_id(name: &str) -> SecretId {
    SecretId::from(format!("shield-{name}"))
}

/// Equality of two secrets without an early exit on the first differing byte.
fn same_secret(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Stores the pool master as `shield-<name>` unless the Vault already holds it
/// (an earlier run stopped after this write); returns whether it did. A secret
/// of that name holding something else refuses, and a Vault that cannot be
/// read is never taken as permission to create.
async fn ensure_pool_master(
    vault: &SecretVault,
    name: &str,
    master: &[u8; 64],
) -> anyhow::Result<bool> {
    if vault.exists(&secret_id(name)).await? {
        let existing = load_pool_master(vault, name).await?;
        anyhow::ensure!(
            same_secret(&existing[..], &master[..]),
            "shield-{name} holds another mnemonic's pool master; choose another name"
        );
        return Ok(true);
    }
    store_pool_master(vault, name, master).await?;
    Ok(false)
}

/// The instance's sealed state: the one an earlier run left (it must have been
/// initialised for the same profile document), or a fresh genesis state written
/// now; returns whether it was resumed.
fn resume_or_create_state(
    store: &Store,
    keys: &Keys,
    binding: &Binding,
    chain: ChainIdentity,
    pool_config: PersistedPoolConfig,
    profile: &Profile,
) -> anyhow::Result<(PersistedState, bool)> {
    if let Some(existing) = store.load_state()? {
        anyhow::ensure!(
            existing.profile == *profile,
            "the state this mnemonic already holds on this pool was initialised for another \
             profile document"
        );
        return Ok((existing, true));
    }
    let state = PersistedState {
        version: STATE_FORMAT_VERSION,
        binding: binding.clone(),
        chain,
        instance_id: *keys.instance_id(),
        profile: profile.clone(),
        pool_config,
        cursor: None,
        ledger: persist_ledger(&Ledger::genesis()),
        notes: Vec::new(),
        diagnostics: Vec::new(),
        scan_next_index: 0,
        reused_indices: Vec::new(),
        issued_high_water: 0,
        journal_records: 0,
    };
    store.save_state(&state)?;
    Ok((state, false))
}

/// A deposit body of exactly the real body's shape, for bounding the paying
/// wallet's fees before the index the real one depends on is reserved: the
/// same amount, a zero owner commitment and a zero payload of the fixed size.
fn fee_placeholder_body(amount: u128) -> anyhow::Result<chain_block::Cell> {
    DepositBody {
        query_id: 0,
        amount,
        owner_commitment: [0; 32],
        output_data: vec![0; OUTPUT_DATA_BYTES],
    }
    .build()
}

async fn store_pool_master(
    vault: &SecretVault,
    name: &str,
    master: &[u8; 64],
) -> anyhow::Result<()> {
    let id = secret_id(name);
    let metadata = secrets_vault::types::metadata::Metadata::new(
        Some(&id),
        secrets_vault::types::algorithm::Algorithm::None,
        true,
    );
    let secret = secrets_vault::types::secret::Secret::from_raw_data(
        master,
        metadata,
        AutoCryptoFactory {}.new_crypto()?,
    )
    .await?;
    vault
        .put(&secret, secrets_vault::types::store_mode::StoreMode::NewOnly)
        .await
        .with_context(|| format!("store the shield secret shield-{name}"))?;
    vault.flush().await?;
    Ok(())
}

async fn load_pool_master(vault: &SecretVault, name: &str) -> anyhow::Result<Zeroizing<[u8; 64]>> {
    let id = secret_id(name);
    let secret =
        vault.get(&id).await.with_context(|| format!("read the shield secret shield-{name}"))?;
    let blob = secret.as_blob()?;
    anyhow::ensure!(
        blob.metadata().algorithm == secrets_vault::types::algorithm::Algorithm::None,
        "shield-{name} is not a shield secret"
    );
    let data = blob.data().await?;
    let guard = data.lock().await?;
    anyhow::ensure!(guard.len() == 64, "shield-{name} is not a pool master");
    let mut master = Zeroizing::new([0u8; 64]);
    master.copy_from_slice(&guard[..]);
    Ok(master)
}

/// An opened instance: its public pointer, its keys and its locked store.
struct Opened {
    pointer: Pointer,
    pointer_path: PathBuf,
    instance: PoolInstance,
    domain: Fr,
    store: Store,
    state: PersistedState,
    journal: Vec<JournalRecord>,
}

async fn open_instance(
    config_path: &Path,
    name: &str,
    vault: &SecretVault,
) -> anyhow::Result<Opened> {
    let root = store::shield_root(config_path);
    let pointer_path = store::pointer_path(&root, name)?;
    let pointer = Pointer::load(&pointer_path)?;
    let master = load_pool_master(vault, name).await?;
    let domain = wire::execution_domain(pointer.profile.global_id, &pointer.profile.account_id()?);
    let keys = Keys::derive(&master, &fr_be32(domain));
    let instance = PoolInstance::from_pool_master(&master, domain);
    drop(master);
    anyhow::ensure!(
        keys.directory_name() == pointer.directory,
        "the pointer for {name:?} names another instance directory"
    );
    let store = Store::open(&root, &keys, pointer.binding.clone())?;
    let state = store.load_state()?.with_context(|| format!("instance {name:?} has no state"))?;
    anyhow::ensure!(
        state.instance_id == *keys.instance_id(),
        "the state belongs to another instance"
    );
    anyhow::ensure!(state.profile == pointer.profile, "the state was written for another profile");
    let mut pointer = pointer;
    if repair_pointer(&mut pointer, &pointer_path, &state)? {
        eprintln!(
            "{} the pointer for {name:?} was behind the sealed state and has been rewritten",
            "note:".bold()
        );
    }
    let journal = store.read_journal()?;
    anyhow::ensure!(
        u64::try_from(journal.len()).unwrap_or(u64::MAX) >= state.journal_records,
        "the journal holds {} records but the state remembers {}: restore both files from the same \
         backup",
        journal.len(),
        state.journal_records
    );
    Ok(Opened { pointer, pointer_path, instance, domain, store, state, journal })
}

/// The pointer is a public cache of what the sealed state says about the
/// chain. When the two disagree -- a migration that stopped between its two
/// writes -- the pointer is rewritten from the state. The state is the
/// authority: a pointer cannot move an instance to another chain. Returns
/// whether anything was rewritten.
fn repair_pointer(
    pointer: &mut Pointer,
    path: &Path,
    state: &PersistedState,
) -> anyhow::Result<bool> {
    if pointer.chain == state.chain {
        return Ok(false);
    }
    pointer.chain = state.chain.clone();
    pointer.save(path).context("rewrite the pointer from the sealed state")?;
    Ok(true)
}

/// How the chain a head came from relates to the chain the state was built
/// against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadRelation {
    /// The same identity from the same source: the state continues.
    Same,
    /// The state was built on an RPC endpoint's word and the head is the proof
    /// verifier's: the history is rebuilt from the start against the verified
    /// chain and the state then records that chain. Reservations and the
    /// journal are kept.
    Migrate,
}

/// The two identities come from different authorities and are not comparable,
/// so the only move allowed is up: from the endpoint's word to the verifier's.
/// A state built through the verifier never falls back to an endpoint, and two
/// identities from the same source must be equal.
fn relate_chains(stored: &ChainIdentity, head: &ChainIdentity) -> anyhow::Result<HeadRelation> {
    if stored.source == head.source {
        anyhow::ensure!(
            stored == head,
            "the chain identity ({} {}) is not the one this instance was built against ({} {})",
            head.source,
            hex::encode(head.root_hash),
            stored.source,
            hex::encode(stored.root_hash)
        );
        return Ok(HeadRelation::Same);
    }
    match (stored.source.as_str(), head.source.as_str()) {
        (chain::RPC_INIT_BLOCK, chain::PROOF_ANCHOR) => Ok(HeadRelation::Migrate),
        (chain::PROOF_ANCHOR, chain::RPC_INIT_BLOCK) => anyhow::bail!(
            "this instance was built through the proof verifier; it does not take an RPC \
             endpoint's word about the chain, so drop --unverified-rpc"
        ),
        (stored, head) => anyhow::bail!(
            "the chain identity source {head:?} cannot be related to the stored {stored:?}"
        ),
    }
}

impl Opened {
    fn network(&self) -> anyhow::Result<Network> {
        Network::of(self.pointer.profile.global_id)
    }

    /// Requires the head to be the pool this instance was initialised on,
    /// still matching the pins, and relates its chain identity to the one
    /// the state was built against.
    fn check_head(&self, head: &Head) -> anyhow::Result<HeadRelation> {
        anyhow::ensure!(
            head.global_id == self.pointer.profile.global_id,
            "the chain reports global id {} but this instance is on {}",
            head.global_id,
            self.pointer.profile.global_id
        );
        let relation = relate_chains(&self.state.chain, &head.chain)?;
        profile::check_pins(
            &self.pointer.profile,
            self.network()?,
            &ObservedPool { code_hash: head.code_hash, state: &head.state },
        )?;
        Ok(relation)
    }

    /// Writes the state, then brings the public pointer up to date with what
    /// the state now says. The order matters: the state is the authority, so
    /// a stop between the two writes leaves a pointer behind the state, which
    /// the next open repairs, and a refused state write leaves both files as
    /// they were.
    fn save_state_and_pointer(&mut self) -> anyhow::Result<()> {
        self.save_state()?;
        repair_pointer(&mut self.pointer, &self.pointer_path, &self.state)?;
        Ok(())
    }

    fn append_journal(&mut self, record: &JournalRecord) -> anyhow::Result<()> {
        let sequence = u64::try_from(self.journal.len()).context("journal length")?;
        self.store.append_journal(sequence, record)?;
        self.journal.push(record.clone());
        self.state.journal_records = sequence.checked_add(1).context("journal count overflow")?;
        Ok(())
    }

    fn save_state(&self) -> anyhow::Result<()> {
        self.store.save_state(&self.state)
    }

    /// Reserves the next index: journalled, then recorded in the state, both
    /// on disk before the index is used for anything.
    fn reserve_index(&mut self, purpose: &str) -> anyhow::Result<u64> {
        let index = store::next_issuable_index(&self.state, &self.journal)?;
        self.append_journal(&JournalRecord::IndexReserved { index, purpose: purpose.to_owned() })?;
        self.state.issued_high_water = self
            .state
            .issued_high_water
            .max(index.checked_add(1).context("note key index exhausted")?);
        self.save_state()?;
        Ok(index)
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Replay the pool's history and scan it for this instance's notes")]
pub struct SyncCmd {
    #[arg(short = 'n', long)]
    name: String,
    #[command(flatten)]
    read: ReadMode,
}

impl SyncCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        let (config, vault, rpc) = load_config_vault_rpc_client(config_path).await?;
        let mut opened = open_instance(config_path, &self.name, &vault).await?;
        let pool = opened.pointer.profile.address()?;
        let head = self.read.head(&config, &rpc, &pool).await?;
        let report = sync_instance(&mut opened, &head, &rpc).await?;
        println!(
            "{} {} at masterchain {} ({}): {} transactions replayed ({} applied, {} without state \
             change), {} new notes, {} notes in all",
            "OK".green().bold(),
            if report.verified {
                "verified".green().to_string()
            } else {
                "UNVERIFIED".yellow().bold().to_string()
            },
            report.checkpoint_seqno,
            utc(head.block_gen_utime),
            report.steps,
            report.applied,
            report.skipped,
            report.new_notes,
            report.recovered.notes.len(),
        );
        let ledger = restore_ledger(&opened.state.ledger)?;
        let pending = spend::pending_spends(
            &opened.journal,
            &ledger,
            Some(head.shard_gen_utime),
            report.verified,
        );
        print_balance(&report.recovered, &spend::held_leaves(&pending), report.verified);
        spend::print_pending_spends(&pending);
        Ok(())
    }
}

/// What one sync did.
struct SyncReport {
    verified: bool,
    checkpoint_seqno: u32,
    steps: u64,
    applied: u64,
    skipped: u64,
    new_notes: usize,
    recovered: Recovered,
}

/// Replays the pool's history from where the stored state stopped (or from
/// the start, when the stored state cannot be continued), scans it for this
/// instance's notes and writes the state. `head` has already been checked
/// against the instance.
async fn sync_instance(
    opened: &mut Opened,
    head: &Head,
    rpc: &ClientJsonRpc,
) -> anyhow::Result<SyncReport> {
    let pool = opened.pointer.profile.address()?;
    let relation = opened.check_head(head)?;

    // An unverified prefix is never promoted by an authenticated suffix:
    // when the verifier is available the history is rebuilt from the start.
    let base = match (&opened.state.cursor, head.verified, relation) {
        (Some(_), _, HeadRelation::Migrate) | (Some(Cursor { verified: false, .. }), true, _) => {
            eprintln!(
                "{} the stored state was built on an RPC endpoint's word; rebuilding it from \
                     the pool's first transaction through the proof verifier",
                "note:".bold()
            );
            None
        }
        (Some(cursor), _, _) => Some(cursor.clone()),
        (None, _, _) => None,
    };
    let (ledger, mut recovered, cursor) = match &base {
        Some(cursor) => (
            restore_ledger(&opened.state.ledger)?,
            restore_recovered(&opened.state)?,
            Some((cursor.lt, cursor.hash)),
        ),
        None => (Ledger::genesis(), Recovered::default(), None),
    };
    let replayed_before = base.as_ref().map_or(0, |cursor| cursor.transactions_replayed);

    let history = chain::fetch_history(rpc, &pool, head, cursor).await?;
    let steps = u64::try_from(history.steps.len()).context("history length")?;
    let mut replay = chain::replay(ledger, &history, head)?;

    let outputs = replay.ledger.take_outputs();
    let found = scan::recover_indexed(&opened.instance, &outputs)
        .map_err(|error| anyhow::anyhow!("scan: {error}"))?;
    let new_notes = found.notes.len();
    recovered.merge(found);
    recovered
        .reconcile_spent(&opened.instance, replay.ledger.published_nullifiers())
        .map_err(|error| anyhow::anyhow!("reconcile: {error}"))?;

    let verified = head.verified && base.as_ref().is_none_or(|cursor| cursor.verified);
    let (seqno, root_hash, file_hash) = match &head.checkpoint {
        Some(checkpoint) => {
            (checkpoint.seqno, checkpoint.root_hash.clone(), checkpoint.file_hash.clone())
        }
        None => (0, String::new(), String::new()),
    };
    let state = &mut opened.state;
    state.cursor = Some(Cursor {
        lt: head.last_lt,
        hash: head.last_hash,
        verified,
        checkpoint_seqno: seqno,
        checkpoint_root_hash: root_hash,
        checkpoint_file_hash: file_hash,
        block_gen_utime: head.block_gen_utime,
        shard_gen_utime: head.shard_gen_utime,
        transactions_replayed: replayed_before.saturating_add(steps),
    });
    state.ledger = persist_ledger(&replay.ledger);
    state.pool_config = pool_config_of(head);
    // A rebuild starts the diagnostics afresh; a continuation keeps the
    // retained ones and appends what this sync observed.
    let previous = if base.is_some() { std::mem::take(&mut state.diagnostics) } else { Vec::new() };
    persist_recovered(state, &recovered, previous);
    if relation == HeadRelation::Migrate {
        state.chain = head.chain.clone();
    }
    opened.save_state_and_pointer()?;
    Ok(SyncReport {
        verified,
        checkpoint_seqno: seqno,
        steps,
        applied: replay.applied,
        skipped: replay.skipped,
        new_notes,
        recovered,
    })
}

#[derive(clap::Args, Clone)]
#[command(about = "Show the balance and the state of pending deposits")]
pub struct BalanceCmd {
    #[arg(short = 'n', long)]
    name: String,
    /// List each note: amount, leaf, kind and whether it is spent
    #[arg(long)]
    notes: bool,
}

impl BalanceCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        let (_, vault) = super::utils::load_config_vault(config_path).await?;
        let opened = open_instance(config_path, &self.name, &vault).await?;
        let recovered = restore_recovered(&opened.state)?;
        println!(
            "Instance {:?}: pool {} on {} (global id {})",
            self.name,
            opened.pointer.profile.pool_address,
            opened.network()?.label(),
            opened.pointer.profile.global_id
        );
        match &opened.state.cursor {
            Some(cursor) => println!(
                "Synced: {} to lt {} at masterchain {} ({}), {} transactions replayed",
                if cursor.verified {
                    "verified".green().to_string()
                } else {
                    "UNVERIFIED".yellow().bold().to_string()
                },
                cursor.lt,
                cursor.checkpoint_seqno,
                utc(cursor.block_gen_utime),
                cursor.transactions_replayed
            ),
            None => println!("Synced: never; run `tosctl shield sync --name {}`", self.name),
        }
        let verified = opened.state.cursor.as_ref().is_some_and(|cursor| cursor.verified);
        let ledger = restore_ledger(&opened.state.ledger)?;
        let pending = spend::pending_spends(
            &opened.journal,
            &ledger,
            opened.state.cursor.as_ref().map(|cursor| cursor.shard_gen_utime),
            verified,
        );
        print_balance(&recovered, &spend::held_leaves(&pending), verified);
        println!(
            "Indices: next {}, {} reused; diagnostics: {}",
            store::next_issuable_index(&opened.state, &opened.journal)?,
            opened.state.reused_indices.len(),
            opened.state.diagnostics.len()
        );
        print_pending(&opened.journal, &opened.state.notes, verified);
        spend::print_pending_spends(&pending);
        if self.notes {
            let leaves = recovered.leaves.iter().copied().chain(std::iter::repeat(None));
            let mut seen = BTreeSet::new();
            for (note, leaf) in recovered.notes.iter().zip(leaves) {
                let duplicate = !seen.insert(fr_to_be(&note.note_body));
                println!(
                    "  index {:>6}  leaf {:>10}  {:<9} {:>22} TOS{}{}",
                    note.note_key_index,
                    leaf.map_or_else(|| "-".to_owned(), |leaf| leaf.to_string()),
                    kind_label(note.kind),
                    tos(note.amount),
                    if note.spent { "  spent" } else { "" },
                    if duplicate { "  duplicate body" } else { "" },
                );
            }
        }
        Ok(())
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Issue a receiving descriptor at the next unused index")]
pub struct AddressCmd {
    #[arg(short = 'n', long)]
    name: String,
}

impl AddressCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        let (_, vault) = super::utils::load_config_vault(config_path).await?;
        let mut opened = open_instance(config_path, &self.name, &vault).await?;
        let index = opened.reserve_index("address")?;
        let descriptor = Descriptor::issue(&opened.instance, index)
            .map_err(|error| anyhow::anyhow!("issue a descriptor: {error}"))?;
        println!(
            "Descriptor for index {index} (valid only for this pool on this network; give it to \
             the payer):"
        );
        println!("{}", base64::engine::general_purpose::STANDARD.encode(descriptor.to_bytes()));
        Ok(())
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Deposit from an ordinary wallet into a new shielded note")]
pub struct DepositCmd {
    #[arg(short = 'n', long)]
    name: String,
    /// Amount in TOS, exactly a pool denomination (for example 10 or 100)
    #[arg(long, conflicts_with = "amount_nanotos")]
    amount: Option<String>,
    /// Amount in nanotos, exactly a pool denomination
    #[arg(long)]
    amount_nanotos: Option<u128>,
    /// The configured wallet that pays
    #[arg(long)]
    from: String,
    /// Do not ask for confirmation
    #[arg(short = 'y', long)]
    yes: bool,
    #[command(flatten)]
    read: ReadMode,
}

impl DepositCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        eprintln!("{}", EXPERIMENTAL.yellow());
        let amount = match (&self.amount, self.amount_nanotos) {
            (Some(text), None) => parse_tos(text)?,
            (None, Some(value)) => value,
            _ => anyhow::bail!("give exactly one of --amount and --amount-nanotos"),
        };
        anyhow::ensure!(amount > 0, "a deposit of zero");

        let (config, vault, rpc) = load_config_vault_rpc_client(config_path).await?;
        let mut opened = open_instance(config_path, &self.name, &vault).await?;
        let pool = opened.pointer.profile.address()?;
        let head = self.read.head(&config, &rpc, &pool).await?;
        anyhow::ensure!(
            opened.check_head(&head)? == HeadRelation::Same,
            "the state was built on an RPC endpoint's word and the verifier now answers; run \
             `tosctl shield sync --name {}` first",
            self.name
        );
        anyhow::ensure!(
            head.state.config.has_denomination(amount),
            "{} TOS is not a pool denomination; the pool accepts {}",
            tos(amount),
            head.state.config.denominations.iter().map(|d| tos(*d)).collect::<Vec<_>>().join(", ")
        );
        let fee = head.deposit_fee()?;
        let value = amount.checked_add(fee).context("deposit value overflow")?;
        let value_u64 = u64::try_from(value).context("deposit value exceeds the message limit")?;

        let wallet_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (payer, payer_info, payer_secret) =
            wallet_info(rpc.clone(), wallet_cfg, vault.clone()).await?;
        anyhow::ensure!(
            payer_info.account_state == AccountState::Active,
            "wallet {:?} is not active",
            self.from
        );
        // The wallet's own fees, bounded from its storage metadata and the live
        // prices of its chain over a body of the real body's size (the real one
        // depends on the index, which is reserved only after the confirmation).
        // With send mode 3 a wallet short of its fees sends nothing and still
        // advances its seqno, so this is checked before signing, and again over
        // the real body once the prompt has been answered.
        let chain = DefaultChainProvider::new(rpc.clone());
        let placeholder = fee_placeholder_body(amount)?;
        let (reserve, balance) = pinned_wallet_reserve(&chain, &payer, &placeholder).await?;
        sender_can_pay(&self.from, balance, value_u64, reserve)?;
        let wallet = make_wallet(rpc.clone(), wallet_cfg, payer_secret, &self.from).await?;

        println!(
            "\n{}\n  From:        {} ({})\n  Pool:        {}\n  Note amount: {} TOS\n  Pool fee:    {} TOS \
             (deposit gas at current prices)\n  Message:     {} TOS\n  Wallet fees: {} TOS (upper \
             bound, paid by the wallet on top)\n",
            "Deposit summary:".cyan().bold(),
            self.from,
            payer,
            pool,
            tos(amount),
            tos(fee),
            tos(value),
            tos(reserve),
        );
        println!(
            "{} a deposit is a public transaction: the paying wallet, the amount and the time are \
             visible on chain and link that wallet to this pool.",
            "note:".bold()
        );
        if !self.yes && !confirm("Confirm deposit?")? {
            println!("{}", "Deposit cancelled".yellow());
            return Ok(());
        }

        // The index is reserved and on disk before anything is derived from it.
        let index = opened.reserve_index("deposit")?;
        let instance = &opened.instance;
        let note_secret = random_field_element()?;
        let owner_nf_key_hash = instance
            .owner_nf_key_hash(index)
            .map_err(|error| anyhow::anyhow!("owner key: {error}"))?;
        let pq_auth_key_hash = instance
            .pq_auth_key_hash(index)
            .map_err(|error| anyhow::anyhow!("auth key: {error}"))?;
        let plaintext = Plaintext {
            slot: 0,
            kind: Kind::Ordinary,
            amount,
            note_secret,
            owner_nf_key_hash,
            note_key_index: index,
            pq_auth_key_hash,
        };
        let owner_commitment =
            notes::owner_commitment(owner_nf_key_hash, pq_auth_key_hash, note_secret);
        let encapsulation_key = instance
            .mlkem_encapsulation_key()
            .map_err(|error| anyhow::anyhow!("encapsulation key: {error}"))?;
        let output_data = delivery::seal(&encapsulation_key, opened.domain, &plaintext)
            .map_err(|error| anyhow::anyhow!("seal the payload: {error}"))?;
        anyhow::ensure!(
            output_data.len() == OUTPUT_DATA_BYTES,
            "a sealed payload of the wrong size"
        );
        let body = DepositBody {
            query_id: unix_now(),
            amount,
            owner_commitment: fr_to_be(&owner_commitment),
            output_data,
        }
        .build()?;
        let body_hash = *body.repr_hash().as_array();
        anyhow::ensure!(
            send_fees::tree_size(&[&body])? == send_fees::tree_size(&[&placeholder])?,
            "the deposit body is not the size its fee bound was taken over"
        );
        // The prompt may have outlived the bound's storage horizon.
        let (reserve, balance) = pinned_wallet_reserve(&chain, &payer, &body).await?;
        sender_can_pay(&self.from, balance, value_u64, reserve)?;

        // Build once, journal the exact bytes, send those bytes.
        let message =
            wallet.build_message(pool.clone(), value_u64, body, true, None, None, None).await?;
        let boc = write_boc(&message)?;
        let message_hash = *message.repr_hash().as_array();
        opened.append_journal(&JournalRecord::DepositPrepared {
            index,
            amount: coins(amount),
            value: coins(value),
            payer: payer.to_string(),
            owner_commitment: fr_to_be(&owner_commitment),
            body_hash,
            message_hash,
            boc: boc.clone(),
        })?;
        opened.save_state()?;

        match rpc.send_boc(&boc).await {
            Ok(()) => {
                opened.append_journal(&JournalRecord::DepositBroadcast { message_hash })?;
                opened.save_state()?;
            }
            Err(error) => {
                opened.append_journal(&JournalRecord::DepositUnknown {
                    message_hash,
                    error: error.to_string(),
                })?;
                opened.save_state()?;
                anyhow::bail!(
                    "the broadcast of message {} failed: {error}. Whether it reached the network \
                     is unknown; it is journalled and will not be rebuilt. Run `tosctl shield \
                     sync` later to see whether the pool minted the note at index {index}.",
                    hex::encode(message_hash)
                );
            }
        }
        let seqno_moved = wait_for_seqno_change(
            rpc.clone(),
            &payer,
            payer_info.seqno,
            &CancellationCtx::default(),
            SEND_TIMEOUT,
        )
        .await
        .is_ok();
        println!(
            "{} deposit message {} submitted{}",
            "OK".green().bold(),
            hex::encode(message_hash),
            if seqno_moved {
                "; the wallet's seqno advanced"
            } else {
                "; the wallet's seqno has not advanced yet"
            }
        );
        println!(
            "Submission is not pool execution: run `tosctl shield sync --name {}` to see whether \
             the pool minted the note at index {index}.",
            self.name
        );
        Ok(())
    }
}

fn confirm(prompt: &str) -> anyhow::Result<bool> {
    print!("{prompt} [y/N]: ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn utc(seconds: u32) -> String {
    // Civil time from days since the epoch, Howard Hinnant's algorithm.
    let days = i64::from(seconds) / 86_400;
    let rem = i64::from(seconds) % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3_600, (rem % 3_600) / 60, rem % 60)
}

/// A uniformly random non-zero field element, by rejection on canonical
/// 32-byte strings.
fn random_field_element() -> anyhow::Result<Fr> {
    for _ in 0..1_000 {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(bytes.as_mut());
        if *bytes == [0u8; 32] || !is_canonical(&bytes) {
            continue;
        }
        return fr_from_be(&bytes).map_err(|error| anyhow::anyhow!("field element: {error:?}"));
    }
    anyhow::bail!("the random source never produced a canonical field element")
}

/// Exact decimal TOS to nanotos: digits, an optional point, at most nine
/// fractional digits.
pub(crate) fn parse_tos(text: &str) -> anyhow::Result<u128> {
    let text = text.trim();
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    anyhow::ensure!(
        !(whole.is_empty() && fraction.is_empty())
            && whole.bytes().all(|b| b.is_ascii_digit())
            && fraction.bytes().all(|b| b.is_ascii_digit())
            && fraction.len() <= 9,
        "{text:?} is not an amount in TOS (digits, optionally a point and up to nine decimals)"
    );
    let whole: u128 =
        if whole.is_empty() { 0 } else { whole.parse().context("amount too large")? };
    let mut nanos: u128 =
        if fraction.is_empty() { 0 } else { fraction.parse().context("amount")? };
    for _ in fraction.len()..9 {
        nanos = nanos.checked_mul(10).context("amount")?;
    }
    whole
        .checked_mul(NANOTOS_PER_TOS)
        .and_then(|v| v.checked_add(nanos))
        .context("amount too large")
}

pub(crate) fn tos(nanotos: u128) -> String {
    let whole = nanotos / NANOTOS_PER_TOS;
    let fraction = nanotos % NANOTOS_PER_TOS;
    if fraction == 0 {
        return whole.to_string();
    }
    let digits = format!("{fraction:09}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Ordinary => "ordinary",
        Kind::Dummy => "dummy",
        Kind::Recovery => "recovery",
    }
}

fn kind_code(kind: Kind) -> u8 {
    match kind {
        Kind::Ordinary => 0,
        Kind::Dummy => 1,
        Kind::Recovery => 2,
    }
}

fn kind_of(code: u8) -> anyhow::Result<Kind> {
    match code {
        0 => Ok(Kind::Ordinary),
        1 => Ok(Kind::Dummy),
        2 => Ok(Kind::Recovery),
        other => anyhow::bail!("a note of kind {other}"),
    }
}

/// The balance, with the notes a pending spend holds shown apart: they are
/// this wallet's until the chain says otherwise, but no other spend may take
/// them.
fn print_balance(recovered: &Recovered, held: &BTreeSet<u64>, verified: bool) {
    let spendable = recovered.spendable_notes().count();
    let (held_amount, held_count) = recovered
        .notes
        .iter()
        .zip(recovered.leaves.iter())
        .filter(|(note, leaf)| {
            note.spendable && !note.spent && leaf.is_some_and(|leaf| held.contains(&leaf))
        })
        .fold((0u128, 0usize), |(amount, count), (note, _)| {
            (amount.saturating_add(note.amount), count.saturating_add(1))
        });
    println!(
        "Balance: {} TOS in {} spendable notes{}{}{}",
        tos(recovered.balance().saturating_sub(held_amount)).bold(),
        spendable.saturating_sub(held_count),
        if held_count > 0 {
            format!(" ({} TOS in {held_count} notes held by a pending spend)", tos(held_amount))
        } else {
            String::new()
        },
        if recovered.duplicates() > 0 {
            format!(" ({} duplicate bodies not counted)", recovered.duplicates())
        } else {
            String::new()
        },
        if verified { "" } else { "  [UNVERIFIED]" }
    );
}

/// A prepared deposit the verified state does not yet show.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingDeposit {
    index: u64,
    amount: u128,
    outcome: &'static str,
}

/// What the journal says about deposits the state has not shown yet.
///
/// A deposit is settled only when the state is verified and holds a note at
/// the reserved index with the same owner commitment and amount; a note at
/// the same index alone, or any note from an unverified sync, proves nothing
/// about the prepared message. A `DepositPrepared` record with no later record
/// means the command stopped between journalling and recording the broadcast
/// result; the message may or may not have been sent, so its outcome is
/// unknown rather than "never broadcast".
fn pending_deposits(
    journal: &[JournalRecord],
    notes: &[PersistedNote],
    verified: bool,
) -> Vec<PendingDeposit> {
    let mut pending = Vec::new();
    for record in journal {
        let JournalRecord::DepositPrepared {
            index, amount, owner_commitment, message_hash, ..
        } = record
        else {
            continue;
        };
        let outcome = journal
            .iter()
            .rev()
            .find_map(|later| match later {
                JournalRecord::DepositBroadcast { message_hash: hash } if hash == message_hash => {
                    Some("submitted")
                }
                JournalRecord::DepositUnknown { message_hash: hash, .. }
                    if hash == message_hash =>
                {
                    Some("broadcast failed, outcome unknown")
                }
                _ => None,
            })
            .unwrap_or("prepared; outcome unknown (the command may have stopped after sending)");
        let settled = verified
            && notes.iter().any(|note| {
                note.note_key_index == *index
                    && note.owner_commitment == *owner_commitment
                    && note.amount == *amount
            });
        if !settled {
            pending.push(PendingDeposit { index: *index, amount: coins_value(amount), outcome });
        }
    }
    pending
}

fn print_pending(journal: &[JournalRecord], notes: &[PersistedNote], verified: bool) {
    let pending = pending_deposits(journal, notes, verified);
    if pending.is_empty() {
        println!("Pending deposits: none");
        return;
    }
    for deposit in &pending {
        println!(
            "  deposit of {} TOS at index {} ({}): not shown by the {} state yet; sync to check",
            tos(deposit.amount),
            deposit.index,
            deposit.outcome,
            if verified { "verified" } else { "UNVERIFIED" }
        );
    }
}

fn pool_config_of(head: &Head) -> PersistedPoolConfig {
    PersistedPoolConfig {
        withdrawal_fee: coins(head.state.config.withdrawal_fee),
        denominations: head.state.config.denominations.iter().map(|d| coins(*d)).collect(),
    }
}

fn persist_ledger(ledger: &Ledger) -> PersistedLedger {
    let snapshot = ledger.snapshot();
    PersistedLedger {
        leaves: snapshot.leaves.iter().map(fr_to_be).collect(),
        nullifiers: snapshot.nullifiers.iter().map(fr_to_be).collect(),
        intents: snapshot.intents.iter().map(fr_to_be).collect(),
        nullifier_tree: snapshot
            .nullifier_tree
            .iter()
            .map(|(index, leaf)| PersistedNullifierLeaf {
                index: *index,
                value: fr_to_be(&leaf.value),
                next_index: leaf.next_index,
                next_value: fr_to_be(&leaf.next_value),
            })
            .collect(),
        nullifier_next_index: snapshot.nullifier_next_index,
        native_liability: coins(snapshot.native_liability),
        reserved_recovery_leaves: snapshot.reserved_recovery_leaves,
        pending: snapshot
            .pending
            .iter()
            .map(|pending| PersistedPendingRecovery {
                payout: PersistedPayout {
                    recipient: pending.payout.recipient.clone(),
                    value: coins(pending.payout.value),
                    body_hash: pending.payout.body_hash,
                },
                owner_commitment: fr_to_be(&pending.owner_commitment),
                payload: pending.payload.clone(),
                consumed: pending.consumed,
            })
            .collect(),
    }
}

fn restore_ledger(persisted: &PersistedLedger) -> anyhow::Result<Ledger> {
    let fr = |word: &[u8; 32]| {
        fr_from_be(word).map_err(|error| anyhow::anyhow!("stored field element: {error:?}"))
    };
    let snapshot = Snapshot {
        leaves: persisted.leaves.iter().map(fr).collect::<anyhow::Result<_>>()?,
        nullifiers: persisted.nullifiers.iter().map(fr).collect::<anyhow::Result<_>>()?,
        intents: persisted.intents.iter().map(fr).collect::<anyhow::Result<_>>()?,
        nullifier_tree: persisted
            .nullifier_tree
            .iter()
            .map(|leaf| {
                Ok((
                    leaf.index,
                    imt::Leaf {
                        value: fr(&leaf.value)?,
                        next_index: leaf.next_index,
                        next_value: fr(&leaf.next_value)?,
                    },
                ))
            })
            .collect::<anyhow::Result<_>>()?,
        nullifier_next_index: persisted.nullifier_next_index,
        native_liability: coins_value(&persisted.native_liability),
        reserved_recovery_leaves: persisted.reserved_recovery_leaves,
        pending: persisted
            .pending
            .iter()
            .map(|pending| {
                Ok(PendingRecovery {
                    payout: Payout {
                        recipient: pending.payout.recipient.clone(),
                        value: coins_value(&pending.payout.value),
                        body_hash: pending.payout.body_hash,
                    },
                    owner_commitment: fr(&pending.owner_commitment)?,
                    payload: pending.payload.clone(),
                    consumed: pending.consumed,
                })
            })
            .collect::<anyhow::Result<_>>()?,
    };
    Ledger::restore(snapshot).map_err(|error| anyhow::anyhow!("restore the ledger: {error}"))
}

/// The retained diagnostics after a sync: the previous ones, then the new ones,
/// the newest `max` of them.
fn retain_diagnostics(
    mut previous: Vec<PersistedDiagnostic>,
    new: impl IntoIterator<Item = PersistedDiagnostic>,
    max: usize,
) -> Vec<PersistedDiagnostic> {
    previous.extend(new);
    if previous.len() > max {
        previous.drain(..previous.len().saturating_sub(max));
    }
    previous
}

fn persist_recovered(
    state: &mut PersistedState,
    recovered: &Recovered,
    previous: Vec<PersistedDiagnostic>,
) {
    let leaves = recovered.leaves.iter().copied().chain(std::iter::repeat(None));
    state.notes = recovered
        .notes
        .iter()
        .zip(leaves)
        .map(|(note, leaf)| PersistedNote {
            kind: kind_code(note.kind),
            note_key_index: note.note_key_index,
            amount: coins(note.amount),
            note_secret: fr_to_be(&note.note_secret),
            owner_commitment: fr_to_be(&note.owner_commitment),
            note_body: fr_to_be(&note.note_body),
            output_data_hash: fr_to_be(&note.output_data_hash),
            spendable: note.spendable,
            spent: note.spent,
            leaf,
        })
        .collect();
    let observed = recovered.diagnostics.iter().map(|diagnostic| PersistedDiagnostic {
        slot: diagnostic.slot,
        why: format!("{:?}", diagnostic.why),
    });
    state.diagnostics = retain_diagnostics(previous, observed, MAX_DIAGNOSTICS);
    state.scan_next_index = recovered.next_note_key_index;
    state.reused_indices = recovered.reused.iter().copied().collect();
    state.issued_high_water = state.issued_high_water.max(recovered.next_note_key_index);
}

fn restore_recovered(state: &PersistedState) -> anyhow::Result<Recovered> {
    let fr = |word: &[u8; 32]| {
        fr_from_be(word).map_err(|error| anyhow::anyhow!("stored field element: {error:?}"))
    };
    let mut notes = Vec::with_capacity(state.notes.len());
    let mut leaves = Vec::with_capacity(state.notes.len());
    for note in &state.notes {
        notes.push(Imported {
            kind: kind_of(note.kind)?,
            note_key_index: note.note_key_index,
            amount: coins_value(&note.amount),
            note_secret: fr(&note.note_secret)?,
            owner_commitment: fr(&note.owner_commitment)?,
            note_body: fr(&note.note_body)?,
            output_data_hash: fr(&note.output_data_hash)?,
            spendable: note.spendable,
            spent: note.spent,
        });
        leaves.push(note.leaf);
    }
    let mut recovered = Recovered::default();
    recovered.merge(Recovered { notes, leaves, ..Recovered::default() });
    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_parse_exactly_and_print_back() {
        assert_eq!(parse_tos("10").expect("10"), 10 * NANOTOS_PER_TOS);
        assert_eq!(parse_tos("0.5").expect("0.5"), 500_000_000);
        assert_eq!(parse_tos("1.000000001").expect("nine decimals"), 1_000_000_001);
        assert_eq!(parse_tos(".25").expect("leading point"), 250_000_000);
        assert!(parse_tos("1.0000000001").is_err(), "ten decimals");
        assert!(parse_tos("-1").is_err());
        assert!(parse_tos("1e9").is_err());
        assert!(parse_tos("").is_err());
        assert!(parse_tos(".").is_err());
        assert_eq!(tos(10 * NANOTOS_PER_TOS), "10");
        assert_eq!(tos(1_000_000_001), "1.000000001");
        assert_eq!(tos(500_000_000), "0.5");
    }

    fn identity(source: &str, root: u8) -> ChainIdentity {
        ChainIdentity { source: source.into(), root_hash: [root; 32], file_hash: [root; 32] }
    }

    #[test]
    fn a_state_moves_up_from_the_endpoint_to_the_verifier_and_never_back() {
        let anchor = identity(chain::PROOF_ANCHOR, 1);
        let endpoint = identity(chain::RPC_INIT_BLOCK, 2);
        assert_eq!(relate_chains(&anchor, &anchor).expect("same"), HeadRelation::Same);
        assert_eq!(relate_chains(&endpoint, &endpoint).expect("same"), HeadRelation::Same);
        assert_eq!(relate_chains(&endpoint, &anchor).expect("up"), HeadRelation::Migrate);
        let down = relate_chains(&anchor, &endpoint).expect_err("never down");
        assert!(down.to_string().contains("--unverified-rpc"), "{down}");
        let other = relate_chains(&anchor, &identity(chain::PROOF_ANCHOR, 3)).expect_err("other");
        assert!(other.to_string().contains("not the one"), "{other}");
        assert!(relate_chains(&endpoint, &identity(chain::RPC_INIT_BLOCK, 3)).is_err());
        assert!(relate_chains(&endpoint, &identity("something-else", 2)).is_err());
    }

    fn prepared(index: u64, owner: u8, message: u8) -> JournalRecord {
        JournalRecord::DepositPrepared {
            index,
            amount: coins(NANOTOS_PER_TOS),
            value: coins(NANOTOS_PER_TOS + 1),
            payer: "w".into(),
            owner_commitment: [owner; 32],
            body_hash: [0; 32],
            message_hash: [message; 32],
            boc: vec![],
        }
    }

    fn note(index: u64, owner: u8, amount: u128) -> PersistedNote {
        PersistedNote {
            kind: kind_code(Kind::Ordinary),
            note_key_index: index,
            amount: coins(amount),
            note_secret: [0; 32],
            owner_commitment: [owner; 32],
            note_body: [0; 32],
            output_data_hash: [0; 32],
            spendable: true,
            spent: false,
            leaf: Some(index),
        }
    }

    #[test]
    fn a_deposit_stays_pending_until_the_verified_state_shows_its_note() {
        let journal = vec![
            prepared(0, 10, 1),
            JournalRecord::DepositBroadcast { message_hash: [1; 32] },
            prepared(1, 11, 2),
            JournalRecord::DepositUnknown { message_hash: [2; 32], error: "down".into() },
            prepared(2, 12, 3),
        ];
        let notes =
            vec![note(0, 10, NANOTOS_PER_TOS), note(1, 99, NANOTOS_PER_TOS), note(2, 12, 7)];

        // Verified state: index 0 matches by index, owner commitment and
        // amount, and is settled. Index 1 has a note with another owner and
        // index 2 one with another amount; both stay pending.
        let pending = pending_deposits(&journal, &notes, true);
        assert_eq!(pending.len(), 2, "{pending:?}");
        assert_eq!(pending[0].index, 1);
        assert_eq!(pending[0].outcome, "broadcast failed, outcome unknown");
        assert_eq!(pending[1].index, 2);
        assert!(pending[1].outcome.contains("outcome unknown"), "{}", pending[1].outcome);
        assert!(!pending[1].outcome.contains("never"), "{}", pending[1].outcome);

        // An unverified state settles nothing, whatever notes it holds.
        let pending = pending_deposits(&journal, &notes, false);
        assert_eq!(pending.iter().map(|p| p.index).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert_eq!(pending[0].outcome, "submitted");

        // The crash window: a prepared record with nothing after it is the
        // state the command leaves when it stops right after sendBoc.
        let crash = vec![prepared(5, 1, 9)];
        let pending = pending_deposits(&crash, &[], true);
        assert_eq!(pending.len(), 1);
        assert!(pending[0].outcome.contains("may have stopped after sending"));
    }

    fn test_root() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("tempdir")
    }

    fn test_state(binding: &Binding, keys: &Keys, chain: ChainIdentity) -> PersistedState {
        PersistedState {
            version: STATE_FORMAT_VERSION,
            binding: binding.clone(),
            chain,
            instance_id: *keys.instance_id(),
            profile: Profile {
                schema: profile::PROFILE_SCHEMA.into(),
                global_id: 3,
                pool_address: binding.pool_address.clone(),
                pool_code_hash: "5528ff26426e36b948bbd6ab3bd6615c82c98c87dd774e4fb456f3965722c466"
                    .into(),
            },
            pool_config: PersistedPoolConfig { withdrawal_fee: coins(0), denominations: vec![] },
            cursor: None,
            ledger: persist_ledger(&Ledger::genesis()),
            notes: vec![],
            diagnostics: vec![],
            scan_next_index: 0,
            reused_indices: vec![],
            issued_high_water: 3,
            journal_records: 1,
        }
    }

    #[test]
    fn a_migration_that_stopped_between_its_writes_is_repaired_and_keeps_the_journal() {
        let root = test_root();
        let keys = Keys::derive(&[7u8; 64], &[3u8; 32]);
        let binding = Binding {
            global_id: 3,
            pool_address: "0:aa76950cf26cb74c1d1b1a977d17bd3c96c6c9f28cb259fca297cdc8d33429fe"
                .into(),
        };
        let endpoint = identity(chain::RPC_INIT_BLOCK, 2);
        let anchor = identity(chain::PROOF_ANCHOR, 1);
        let store = Store::open(root.path(), &keys, binding.clone()).expect("open");
        let mut state = test_state(&binding, &keys, endpoint.clone());
        store.save_state(&state).expect("the initial state");
        store.append_journal(0, &prepared(2, 1, 1)).expect("a reservation");
        let pointer_path = store::pointer_path(root.path(), "w").expect("a pointer path");
        let pointer = Pointer {
            schema: store::POINTER_SCHEMA.to_owned(),
            profile: state.profile.clone(),
            binding: binding.clone(),
            chain: endpoint.clone(),
            directory: keys.directory_name(),
        };
        pointer.save(&pointer_path).expect("the pointer");

        // The migration writes the state and stops before the pointer.
        state.chain = anchor.clone();
        store.save_state(&state).expect("the migrated state");

        // The next open finds the pointer behind the state and rewrites it;
        // nothing else moves.
        let mut loaded = Pointer::load(&pointer_path).expect("load the pointer");
        assert_eq!(loaded.chain, endpoint);
        let on_disk = store.load_state().expect("load").expect("a state");
        assert_eq!(on_disk.chain, anchor);
        assert!(repair_pointer(&mut loaded, &pointer_path, &on_disk).expect("repair"));
        assert_eq!(Pointer::load(&pointer_path).expect("reload").chain, anchor);
        assert!(!repair_pointer(&mut loaded, &pointer_path, &on_disk).expect("already right"));
        let journal = store.read_journal().expect("the journal survives");
        assert_eq!(journal.len(), 1);
        assert_eq!(store::next_issuable_index(&on_disk, &journal).expect("next"), 3);

        // A refused state write leaves both files as they were, so there is
        // nothing to repair and the migration can be retried.
        drop(store);
        let small =
            Store::open(root.path(), &keys, binding.clone()).expect("reopen").with_limit(1_500);
        let mut too_large = on_disk.clone();
        too_large.chain = identity(chain::PROOF_ANCHOR, 9);
        too_large.ledger.leaves = vec![[7; 32]; 100];
        assert!(small.save_state(&too_large).is_err(), "refused");
        let kept = small.load_state().expect("load").expect("a state");
        assert_eq!(kept.chain, anchor);
        assert!(!repair_pointer(&mut loaded, &pointer_path, &kept).expect("nothing to repair"));
    }

    #[test]
    fn the_fee_placeholder_has_the_real_bodys_size() {
        let mut payload = vec![0u8; OUTPUT_DATA_BYTES];
        rand::thread_rng().fill_bytes(&mut payload);
        for amount in [1u128, NANOTOS_PER_TOS, 1_000_000 * NANOTOS_PER_TOS] {
            let real = DepositBody {
                query_id: unix_now(),
                amount,
                owner_commitment: fr_to_be(&Fr::from(0x5eed_u64)),
                output_data: payload.clone(),
            }
            .build()
            .expect("a real body");
            let placeholder = fee_placeholder_body(amount).expect("a placeholder");
            assert_eq!(
                send_fees::tree_size(&[&real]).expect("size"),
                send_fees::tree_size(&[&placeholder]).expect("size"),
                "amount {amount}"
            );
        }
    }

    #[test]
    fn an_initialisation_resumes_its_state_and_refuses_another_profile() {
        let root = test_root();
        let keys = Keys::derive(&[7u8; 64], &[3u8; 32]);
        let binding = Binding {
            global_id: 3,
            pool_address: "0:aa76950cf26cb74c1d1b1a977d17bd3c96c6c9f28cb259fca297cdc8d33429fe"
                .into(),
        };
        let template = test_state(&binding, &keys, identity(chain::PROOF_ANCHOR, 1));
        let store = Store::open(root.path(), &keys, binding.clone()).expect("open");
        let (created, resumed) = resume_or_create_state(
            &store,
            &keys,
            &binding,
            identity(chain::PROOF_ANCHOR, 1),
            template.pool_config.clone(),
            &template.profile,
        )
        .expect("a fresh state");
        assert!(!resumed);
        assert_eq!(created.ledger, persist_ledger(&Ledger::genesis()));

        // The run stopped before its pointer; the next one finds the state and
        // keeps it, whatever the head it sees now.
        let later = ChainIdentity {
            source: chain::PROOF_ANCHOR.into(),
            root_hash: [5; 32],
            file_hash: [6; 32],
        };
        let (kept, resumed) = resume_or_create_state(
            &store,
            &keys,
            &binding,
            later,
            template.pool_config.clone(),
            &template.profile,
        )
        .expect("a resumed state");
        assert!(resumed);
        assert_eq!(kept, created);

        let mut other = template.profile.clone();
        other.pool_code_hash = "11".repeat(32);
        let refused = resume_or_create_state(
            &store,
            &keys,
            &binding,
            identity(chain::PROOF_ANCHOR, 1),
            template.pool_config.clone(),
            &other,
        )
        .expect_err("another profile");
        assert!(refused.to_string().contains("another profile document"), "{refused}");
    }

    async fn test_vault(dir: &std::path::Path) -> SecretVault {
        use secrets_vault::crypto::{key_material::KeyMaterial, master_key::MasterKey};
        use secrets_vault::events::null_handler::NullEventHandler;
        use secrets_vault::memory::protected_memory::ProtectedMemory;
        use secrets_vault::storage::file_json::FileJsonStorage;
        let key = ProtectedMemory::from_slice(&[4u8; 32]).await.expect("key");
        let key = MasterKey::from_key_material(
            KeyMaterial::new_symmetric_key(key).await.expect("material"),
        )
        .await
        .expect("master key");
        let storage = FileJsonStorage::new(
            key,
            &dir.join("vault.json"),
            Box::new(AutoCryptoFactory {}),
            false,
        )
        .await
        .expect("storage");
        SecretVault::new(std::sync::Arc::new(storage), std::sync::Arc::new(NullEventHandler {}))
    }

    #[tokio::test]
    async fn the_pool_master_is_stored_once_and_another_mnemonics_is_refused() {
        let root = test_root();
        let vault = test_vault(root.path()).await;
        let master = [9u8; 64];
        assert!(!ensure_pool_master(&vault, "main", &master).await.expect("stored"));
        assert_eq!(&load_pool_master(&vault, "main").await.expect("read")[..], &master[..]);
        // The run stopped after the Vault write; the next one finds its own master.
        assert!(ensure_pool_master(&vault, "main", &master).await.expect("resumed"));
        let other = [10u8; 64];
        let refused = ensure_pool_master(&vault, "main", &other).await.expect_err("another");
        assert!(refused.to_string().contains("another mnemonic"), "{refused}");
        assert_eq!(&load_pool_master(&vault, "main").await.expect("unchanged")[..], &master[..]);
        // Another name is another secret.
        assert!(!ensure_pool_master(&vault, "second", &other).await.expect("stored"));
    }

    #[test]
    fn secrets_compare_by_every_byte() {
        assert!(same_secret(&[1, 2, 3], &[1, 2, 3]));
        assert!(!same_secret(&[1, 2, 3], &[1, 2, 4]));
        assert!(!same_secret(&[1, 2, 3], &[1, 2]));
        assert!(same_secret(&[], &[]));
    }

    fn diagnostic(slot: u8) -> PersistedDiagnostic {
        PersistedDiagnostic { slot, why: "test".into() }
    }

    #[test]
    fn diagnostics_are_retained_across_syncs_and_capped_at_the_newest() {
        let previous = vec![diagnostic(1), diagnostic(2)];
        // A sync that observed nothing keeps the history.
        assert_eq!(retain_diagnostics(previous.clone(), Vec::new(), 4), previous);
        // One that observed something appends it.
        let appended = retain_diagnostics(previous.clone(), vec![diagnostic(3)], 4);
        assert_eq!(appended.iter().map(|d| d.slot).collect::<Vec<_>>(), vec![1, 2, 3]);
        // The cap keeps the newest.
        let capped = retain_diagnostics(previous, vec![diagnostic(3), diagnostic(4)], 3);
        assert_eq!(capped.iter().map(|d| d.slot).collect::<Vec<_>>(), vec![2, 3, 4]);
        // A rebuild passes no history.
        let rebuilt = retain_diagnostics(Vec::new(), vec![diagnostic(9)], 3);
        assert_eq!(rebuilt.iter().map(|d| d.slot).collect::<Vec<_>>(), vec![9]);
    }

    #[test]
    fn a_ledger_survives_persistence() {
        let mut ledger = Ledger::genesis();
        let instance = PoolInstance::from_pool_master(&[1u8; 64], Fr::from(7u64));
        let owner = instance.owner_nf_key_hash(0).expect("owner");
        let auth = instance.pq_auth_key_hash(0).expect("auth");
        let commitment = notes::owner_commitment(owner, auth, Fr::from(9u64));
        ledger
            .apply(
                &shielded_pool_wallet::ledger::Event::Deposit {
                    amount: NANOTOS_PER_TOS,
                    owner_commitment: commitment,
                    output_data: vec![0x5a; OUTPUT_DATA_BYTES],
                },
                1,
            )
            .expect("deposit");
        let persisted = persist_ledger(&ledger);
        let restored = restore_ledger(&persisted).expect("restore");
        assert_eq!(restored.checkpoint(), ledger.checkpoint());
        assert_eq!(persist_ledger(&restored), persisted);
    }

    #[test]
    fn notes_survive_persistence_and_the_scan_counters_follow() {
        let note = Imported {
            kind: Kind::Ordinary,
            note_key_index: 4,
            amount: 3,
            note_secret: Fr::from(1u64),
            owner_commitment: Fr::from(2u64),
            note_body: Fr::from(3u64),
            output_data_hash: Fr::from(4u64),
            spendable: true,
            spent: false,
        };
        let mut recovered = Recovered::default();
        recovered.merge(Recovered {
            notes: vec![note, note],
            leaves: vec![Some(8), None],
            ..Default::default()
        });
        let mut state = PersistedState {
            version: STATE_FORMAT_VERSION,
            binding: Binding { global_id: 3, pool_address: String::new() },
            chain: ChainIdentity { source: String::new(), root_hash: [0; 32], file_hash: [0; 32] },
            instance_id: [0; 32],
            profile: Profile {
                schema: profile::PROFILE_SCHEMA.into(),
                global_id: 3,
                pool_address: String::new(),
                pool_code_hash: String::new(),
            },
            pool_config: PersistedPoolConfig { withdrawal_fee: coins(0), denominations: vec![] },
            cursor: None,
            ledger: persist_ledger(&Ledger::genesis()),
            notes: vec![],
            diagnostics: vec![],
            scan_next_index: 0,
            reused_indices: vec![],
            issued_high_water: 2,
            journal_records: 0,
        };
        persist_recovered(&mut state, &recovered, Vec::new());
        assert_eq!(state.notes.len(), 2);
        assert_eq!(state.notes[0].leaf, Some(8));
        assert_eq!(state.scan_next_index, 5);
        assert_eq!(state.issued_high_water, 5, "issuing never falls below the scan");
        assert!(state.reused_indices.is_empty(), "two copies of one body are one use");
        let back = restore_recovered(&state).expect("restore");
        assert_eq!(back.notes, recovered.notes);
        assert_eq!(back.leaves, vec![Some(8), None]);
        assert_eq!(back.balance(), 3, "a duplicate body is counted once");
    }

    #[test]
    fn random_field_elements_are_canonical_and_distinct() {
        let a = random_field_element().expect("a");
        let b = random_field_element().expect("b");
        assert_ne!(a, b);
        assert!(is_canonical(&fr_to_be(&a)));
    }

    #[test]
    fn the_command_line_is_consistent() {
        use clap::Args;
        ShieldCmd::augment_args(clap::Command::new("shield")).debug_assert();
    }

    #[test]
    fn times_print_as_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_793_534_400), "2026-11-01 12:00:00 UTC");
    }
}
